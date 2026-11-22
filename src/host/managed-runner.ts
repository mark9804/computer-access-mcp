import { dirname } from 'node:path';
import { finished } from 'node:stream/promises';
import { minimalChildEnv } from '../shared/child-env.ts';
import { spawnLocal } from './collectors/local-process.ts';
import type { ManagedProcess, SpawnManaged } from './collectors/process.ts';

export type ManagedRunnerErrorCode =
  | 'closed'
  | 'busy'
  | 'cancelled'
  | 'cancelled-after-dispatch'
  | 'spawn-failed'
  | 'input-failed'
  | 'timeout'
  | 'output-limit'
  | 'response-invalid'
  | 'exit-failed'
  | 'exit-unconfirmed';

export class ManagedRunnerError extends Error {
  readonly code: ManagedRunnerErrorCode;
  readonly dispatched: boolean;

  constructor(code: ManagedRunnerErrorCode, dispatched = false) {
    super(`Managed runner: ${code}`);
    this.name = 'ManagedRunnerError';
    this.code = code;
    this.dispatched = dispatched;
  }
}

export interface SubprocessRunRequest {
  executable: string;
  args: readonly string[];
  cwd?: string;
  stdin?: Uint8Array | string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  maxStderrBytes?: number;
  graceMs?: number;
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
}

export interface SubprocessRunResult {
  stdout: Buffer;
  exitCode: number;
}

export type SubprocessRunner = (request: SubprocessRunRequest) => Promise<SubprocessRunResult>;

export interface ManagedRunnerController {
  readonly run: SubprocessRunner;
  readonly poisoned: boolean;
  cancel(): void;
  close(): Promise<void>;
}

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_OUTPUT_BYTES = 4_096;
const DEFAULT_MAX_STDERR_BYTES = 4_096;
const REAP_TIMEOUT_MS = 1_500;

async function reapBounded(child: ManagedProcess, timeoutMs: number): Promise<boolean> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<boolean>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve(false);
    }, timeoutMs);
  });
  try {
    return await Promise.race([
      Promise.resolve()
        .then(() => child.waitForExit(controller.signal))
        .then(
          (ok) => ok === true,
          () => false,
        ),
      deadline,
    ]);
  } finally {
    if (timer) clearTimeout(timer);
    controller.abort();
  }
}

export function createManagedRunner(options: { spawn?: SpawnManaged; cwd?: string } = {}): ManagedRunnerController {
  const spawn = options.spawn ?? spawnLocal;
  let closed = false;
  let poisoned = false;
  let running = false;
  let activeChild: ManagedProcess | undefined;
  let cancelCurrent: (() => void) | undefined;

  const run: SubprocessRunner = async (request) => {
    if (poisoned) throw new ManagedRunnerError('exit-unconfirmed', false);
    if (closed) throw new ManagedRunnerError('closed', false);
    if (running) throw new ManagedRunnerError('busy', false);
    if (request.signal?.aborted) throw new ManagedRunnerError('cancelled', false);

    const timeoutMs = request.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxOutputBytes = request.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
    const maxStderrBytes = request.maxStderrBytes ?? DEFAULT_MAX_STDERR_BYTES;
    const graceMs = request.graceMs ?? 300;
    const cwd = request.cwd ?? options.cwd ?? dirname(request.executable);

    running = true;
    let child: ManagedProcess;
    try {
      child = spawn({
        argv: [request.executable, ...request.args],
        cwd,
        stdio: { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' },
        env: request.env ?? minimalChildEnv(),
        graceMs,
      });
    } catch {
      running = false;
      throw new ManagedRunnerError('spawn-failed', false);
    }

    activeChild = child;
    let failure: ManagedRunnerErrorCode | undefined;
    let notifyFailure!: () => void;
    const failed = new Promise<void>((resolve) => {
      notifyFailure = resolve;
    });
    const fail = (code: ManagedRunnerErrorCode) => {
      if (!failure) {
        failure = code;
        notifyFailure();
      }
    };

    const chunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const onAbort = () => fail('cancelled-after-dispatch');
    cancelCurrent = onAbort;
    request.signal?.addEventListener('abort', onAbort, { once: true });

    const exitPromise = child.done.then(
      (res) => res,
      () => {
        fail('spawn-failed');
        return undefined;
      },
    );

    const stopAndReap = async (): Promise<boolean> => {
      try {
        child.terminate();
      } catch {
        // Proceed to stream teardown and bounded wait.
      }
      for (const stream of [child.stdin, child.stdout, child.stderr]) {
        try {
          stream?.destroy();
        } catch {
          // Ignore stream teardown errors while reaping.
        }
      }
      return reapBounded(child, REAP_TIMEOUT_MS);
    };

    try {
      if (!child.stdin || !child.stdout || !child.stderr) {
        fail('spawn-failed');
      } else {
        const drained = Promise.all([
          finished(child.stdout, { cleanup: true }).catch(() => fail('response-invalid')),
          finished(child.stderr, { cleanup: true }).catch(() => fail('response-invalid')),
        ]);

        child.stdout.on('data', (chunk: Buffer) => {
          stdoutBytes += chunk.length;
          if (failure) return;
          if (stdoutBytes > maxOutputBytes) {
            fail('output-limit');
            return;
          }
          chunks.push(Buffer.from(chunk));
        });

        child.stderr.on('data', (chunk: Buffer) => {
          stderrBytes += chunk.length;
          chunk.fill(0);
          if (stderrBytes > maxStderrBytes) {
            fail('output-limit');
          }
        });

        child.stdin.on('error', () => fail('input-failed'));
        timer = setTimeout(() => fail('timeout'), timeoutMs);

        if (closed || request.signal?.aborted) {
          fail('cancelled-after-dispatch');
        } else {
          try {
            child.stdin.end(request.stdin ?? '');
          } catch {
            fail('input-failed');
          }
        }

        const completed = await Promise.race([
          Promise.all([exitPromise, drained]).then(([res]) => ({ res })),
          failed.then(() => undefined),
        ]);

        if (!failure && completed) {
          if (timer) clearTimeout(timer);
          const exited = await stopAndReap();
          if (!exited) {
            poisoned = true;
            throw new ManagedRunnerError('exit-unconfirmed', true);
          }
          if (closed || request.signal?.aborted || failure === 'cancelled-after-dispatch') {
            throw new ManagedRunnerError('cancelled-after-dispatch', true);
          }
          if (!completed.res || completed.res.exitCode === null) {
            throw new ManagedRunnerError('exit-failed', true);
          }
          return {
            stdout: Buffer.concat(chunks),
            exitCode: completed.res.exitCode,
          };
        }
      }

      if (timer) clearTimeout(timer);
      const exited = await stopAndReap();
      if (!exited) {
        poisoned = true;
        throw new ManagedRunnerError('exit-unconfirmed', true);
      }
      throw new ManagedRunnerError(failure ?? 'spawn-failed', true);
    } catch (error) {
      if (error instanceof ManagedRunnerError) throw error;
      throw new ManagedRunnerError('input-failed', true);
    } finally {
      if (timer) clearTimeout(timer);
      request.signal?.removeEventListener('abort', onAbort);
      cancelCurrent = undefined;
      activeChild = undefined;
      for (const chunk of chunks) {
        chunk.fill(0);
      }
      chunks.length = 0;
      running = false;
    }
  };

  return {
    run,
    get poisoned() {
      return poisoned;
    },
    cancel() {
      cancelCurrent?.();
    },
    async close() {
      closed = true;
      cancelCurrent?.();
      const child = activeChild;
      if (child) {
        try {
          child.terminate();
        } catch {
          poisoned = true;
        }
        const exited = await reapBounded(child, REAP_TIMEOUT_MS);
        if (!exited) {
          poisoned = true;
        }
      }
      if (poisoned) {
        throw new ManagedRunnerError('exit-unconfirmed', true);
      }
    },
  };
}

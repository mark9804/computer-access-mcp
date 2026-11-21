#!/usr/bin/env node
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants, realpathSync } from 'node:fs';
import { chmod, lstat, mkdir, open, rename, rm, unlink, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import type { Readable, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import type { HistoryServiceContract, NormalizedCaptureStartOptions } from '../shared/api-types.ts';
import { validateCaptureStartOptions } from '../shared/app-policy.ts';
import { createHistoryService } from '../host/service/history-service.ts';
import { defaultDataRoot } from '../storage/platform-paths.ts';
import { DEFAULT_HTTP_HOST, DEFAULT_HTTP_PORT, startHttpServer } from './http-server.ts';
import type { RunningHttpServer } from './http-server.ts';
import { MCP_SERVER_INFO } from './mcp-handler.ts';
import { DEFAULT_STDIO_MCP_URL, runStdioProxy } from './stdio-proxy.ts';

const CLI_SCRIPT_PATH = fileURLToPath(import.meta.url);
const PKG_ROOT = resolve(dirname(CLI_SCRIPT_PATH), '..', '..');

export const RESTART_EXIT_CODE = 75;
export const RESTART_RESUME_FILENAME = 'restart-resume.json';
export const RESTART_RESUME_TTL_MS = 30_000;

export interface ServeResolvedConfig {
  dataDir: string;
  port: number;
  host: string;
  debugTrace: boolean;
  pkgRoot: string;
}

export interface CliRuntimeOptions {
  env?: NodeJS.ProcessEnv;
  stdin?: Readable;
  stdout?: Writable;
  stderr?: Writable;
  signal?: AbortSignal;
  createService?: (config: ServeResolvedConfig) => HistoryServiceContract | Promise<HistoryServiceContract>;
}

export function resolveDefaultDataDir(
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
  home: string = homedir(),
): string {
  const override = env.COMPUTER_ACCESS_DATA_DIR?.trim();
  if (override) {
    return resolve(override);
  }
  return defaultDataRoot(platform, env, home);
}

function formatUsage(): string {
  return [
    `${MCP_SERVER_INFO.name} v${MCP_SERVER_INFO.version}`,
    '',
    'Usage:',
    '  computer-access-mcp serve [--port 43180] [--data-dir <dir>] [--debug-trace] [--no-supervisor]',
    '  computer-access-mcp stdio [--url http://127.0.0.1:43180/mcp]',
    '',
    'Environment:',
    '  COMPUTER_ACCESS_DATA_DIR   Default data directory override for serve',
    '  COMPUTER_ACCESS_TOKEN      Client lease bearer token for stdio',
    '  COMPUTER_ACCESS_URL        Target MCP HTTP endpoint for stdio',
  ].join('\n');
}

function createDefaultHistoryService(config: ServeResolvedConfig): HistoryServiceContract {
  const exeSuffix = process.platform === 'win32' ? '.exe' : '';
  const collectorPath = join(config.pkgRoot, 'native-bin', `computer-access-collector${exeSuffix}`);
  const keyStorePath = join(config.pkgRoot, 'native-bin', `computer-access-key-store${exeSuffix}`);

  return createHistoryService({
    dataRoot: config.dataDir,
    collectorPath,
    keyStorePath,
    debugTrace: config.debugTrace,
  });
}

function parsePort(rawPort: string | undefined): number {
  if (rawPort === undefined) {
    return DEFAULT_HTTP_PORT;
  }
  const parsed = Number(rawPort);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 65535) {
    throw new Error(`Invalid --port value: ${rawPort}`);
  }
  return parsed;
}

export async function writeRestartResume(
  dataDir: string,
  activeScope: NormalizedCaptureStartOptions,
  nowMs: number = Date.now(),
): Promise<void> {
  const dir = resolve(dataDir);
  try {
    const dirInfo = await lstat(dir);
    if (dirInfo.isSymbolicLink() || !dirInfo.isDirectory()) {
      throw new Error('unsafe-restart-resume-dir');
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw err;
    }
    await mkdir(dir, { recursive: true, mode: 0o700 });
  }
  if (process.platform !== 'win32') {
    await chmod(dir, 0o700);
  }

  const targetPath = join(dir, RESTART_RESUME_FILENAME);
  try {
    const existing = await lstat(targetPath);
    if (existing.isSymbolicLink() || !existing.isFile()) {
      throw new Error('unsafe-restart-resume-file');
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw err;
    }
  }

  const normalized = validateCaptureStartOptions(activeScope);
  const payload = JSON.stringify({
    activeScope: normalized,
    expiresAtMs: nowMs + RESTART_RESUME_TTL_MS,
  });

  const tmpPath = `${targetPath}.tmp.${process.pid}.${randomBytes(4).toString('hex')}`;
  try {
    await writeFile(tmpPath, `${payload}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    if (process.platform !== 'win32') {
      await chmod(tmpPath, 0o600);
    }
    await rename(tmpPath, targetPath);
    if (process.platform !== 'win32') {
      await chmod(targetPath, 0o600);
    }
  } catch (err) {
    await rm(tmpPath, { force: true }).catch(() => {});
    throw err;
  }
}

export async function consumeRestartResume(
  dataDir: string,
  nowMs: number = Date.now(),
): Promise<NormalizedCaptureStartOptions | null> {
  const resumePath = join(resolve(dataDir), RESTART_RESUME_FILENAME);
  try {
    const info = await lstat(resumePath);
    if (info.isSymbolicLink() || !info.isFile()) {
      return null;
    }
  } catch {
    return null;
  }

  const openFlags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  let raw: string | null = null;
  let fh: Awaited<ReturnType<typeof open>> | null = null;
  try {
    fh = await open(resumePath, openFlags);
    const info = await fh.stat();
    if (info.isFile()) {
      raw = await fh.readFile('utf8');
    }
  } catch {
    return null;
  } finally {
    if (fh) {
      await fh.close().catch(() => {});
      // Always unlink immediately so one-shot handoff never persists across reboots.
      await unlink(resumePath).catch(() => {});
    }
  }

  if (raw === null) {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return null;
  }
  const rec = parsed as Record<string, unknown>;
  if (typeof rec.expiresAtMs !== 'number' || !Number.isFinite(rec.expiresAtMs) || rec.expiresAtMs <= nowMs) {
    return null;
  }

  try {
    return validateCaptureStartOptions(rec.activeScope);
  } catch {
    return null;
  }
}

async function runServeSupervisor(
  argv: string[],
  env: NodeJS.ProcessEnv,
  stderr: Writable,
  signal?: AbortSignal,
): Promise<number> {
  const childArgs = [...process.execArgv, CLI_SCRIPT_PATH, ...argv, '--worker'];
  let shuttingDown = false;
  let currentChild: ChildProcess | null = null;

  const forwardSignal = (sig: NodeJS.Signals) => {
    shuttingDown = true;
    if (currentChild && currentChild.exitCode === null && currentChild.signalCode === null) {
      try {
        currentChild.kill(sig);
      } catch {
        // Child already exited.
      }
    }
  };
  const onSigInt = () => forwardSignal('SIGINT');
  const onSigTerm = () => forwardSignal('SIGTERM');
  const onAbort = () => forwardSignal('SIGTERM');

  process.on('SIGINT', onSigInt);
  process.on('SIGTERM', onSigTerm);
  if (signal) {
    if (signal.aborted) {
      shuttingDown = true;
    } else {
      signal.addEventListener('abort', onAbort, { once: true });
    }
  }

  try {
    while (!shuttingDown) {
      const child = spawn(process.execPath, childArgs, {
        stdio: 'inherit',
        env,
      });
      currentChild = child;

      const result = await new Promise<{ code: number | null; sig: NodeJS.Signals | null; err?: Error }>(
        (resolveExit) => {
          child.once('error', (err) => resolveExit({ code: 1, sig: null, err }));
          child.once('exit', (code, sig) => resolveExit({ code, sig }));
        },
      );
      currentChild = null;

      if (result.err) {
        stderr.write(`computer-access-mcp supervisor failed to spawn worker: ${result.err.message}\n`);
        return 1;
      }

      if (shuttingDown) {
        return 0;
      }

      if (result.code === RESTART_EXIT_CODE) {
        continue;
      }

      return result.code ?? 0;
    }
    return 0;
  } finally {
    process.off('SIGINT', onSigInt);
    process.off('SIGTERM', onSigTerm);
    signal?.removeEventListener('abort', onAbort);
  }
}

export async function runCli(argv: string[], runtime: CliRuntimeOptions = {}): Promise<number> {
  const env = runtime.env ?? process.env;
  const stdout = runtime.stdout ?? process.stdout;
  const stderr = runtime.stderr ?? process.stderr;
  const stdin = runtime.stdin ?? process.stdin;

  const first = argv[0];
  if (!first || first === '--help' || first === '-h' || first === 'help') {
    stdout.write(`${formatUsage()}\n`);
    return 0;
  }
  if (first === '--version' || first === '-v') {
    stdout.write(`${MCP_SERVER_INFO.version}\n`);
    return 0;
  }

  if (first === 'serve') {
    const { values } = parseArgs({
      args: argv.slice(1),
      options: {
        port: { type: 'string', short: 'p' },
        'data-dir': { type: 'string', short: 'd' },
        'debug-trace': { type: 'boolean', default: false },
        worker: { type: 'boolean', default: false },
        'no-supervisor': { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
      },
      strict: true,
    });

    if (values.help) {
      stdout.write(`${formatUsage()}\n`);
      return 0;
    }

    const port = parsePort(values.port);
    const dataDir = values['data-dir'] ? resolve(values['data-dir']) : resolveDefaultDataDir(process.platform, env);
    const debugTrace = Boolean(values['debug-trace']);
    const isWorker = Boolean(values.worker);
    const noSupervisor = Boolean(values['no-supervisor']);

    // Default `serve` runs under a lightweight supervisor that respawns on RESTART_EXIT_CODE (75).
    if (!isWorker && !noSupervisor && runtime.createService === undefined) {
      return runServeSupervisor(argv, env, stderr, runtime.signal);
    }

    const resolvedConfig: ServeResolvedConfig = {
      dataDir,
      port,
      host: DEFAULT_HTTP_HOST,
      debugTrace,
      pkgRoot: PKG_ROOT,
    };

    const serviceFactory = runtime.createService ?? createDefaultHistoryService;
    const service = await serviceFactory(resolvedConfig);

    // Consume one-shot restart handoff (immediately unlinked; never auto-starts without an unexpired file).
    const resumedScope = await consumeRestartResume(dataDir);
    if (resumedScope) {
      try {
        await service.start(resumedScope);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        stderr.write(`computer-access-mcp warning: failed to resume capture after restart: ${msg}\n`);
      }
    }

    let exitCode = 0;
    let stopping = false;
    let resolveStop!: () => void;
    const stopPromise = new Promise<void>((resolveDone) => {
      resolveStop = resolveDone;
    });
    let running: RunningHttpServer | null = null;

    const shutdown = (code: number) => {
      if (stopping) return;
      stopping = true;
      exitCode = code;
      process.off('SIGINT', onSignal);
      process.off('SIGTERM', onSignal);
      runtime.signal?.removeEventListener('abort', onAbort);
      void (running ? running.close() : Promise.resolve()).finally(() => resolveStop());
    };
    const onSignal = () => {
      stdout.write('\nShutting down computer-access-mcp...\n');
      shutdown(0);
    };
    const onAbort = () => {
      shutdown(0);
    };

    const onRequestServerRestart = isWorker
      ? async (): Promise<void> => {
          try {
            const current = await service.status();
            if (current.state === 'running' && current.activeScope) {
              await writeRestartResume(dataDir, current.activeScope);
            }
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            stderr.write(`computer-access-mcp warning: failed to write restart-resume state: ${msg}\n`);
          }
          stdout.write('\nRestarting computer-access-mcp worker...\n');
          shutdown(RESTART_EXIT_CODE);
        }
      : undefined;

    running = await startHttpServer({
      dataDir,
      host: DEFAULT_HTTP_HOST,
      port,
      pkgRoot: PKG_ROOT,
      webDistDir: join(PKG_ROOT, 'dist', 'web'),
      service,
      ...(onRequestServerRestart ? { onRequestServerRestart } : {}),
    });

    stdout.write(
      [
        `${MCP_SERVER_INFO.name} v${MCP_SERVER_INFO.version} listening on ${running.baseUrl}`,
        `Data Dir: ${dataDir}`,
        `Web UI: ${running.baseUrl}/#token=${running.adminToken}`,
        `MCP HTTP: ${running.mcpUrl}`,
      ].join('\n') + '\n',
    );

    if (runtime.signal) {
      if (runtime.signal.aborted) {
        shutdown(0);
      } else {
        runtime.signal.addEventListener('abort', onAbort, { once: true });
      }
    }
    if (!stopping) {
      process.on('SIGINT', onSignal);
      process.on('SIGTERM', onSignal);
    }

    await stopPromise;
    return exitCode;
  }

  if (first === 'stdio') {
    const { values } = parseArgs({
      args: argv.slice(1),
      options: {
        url: { type: 'string', short: 'u' },
        help: { type: 'boolean', short: 'h', default: false },
      },
      strict: true,
    });

    if (values.help) {
      stdout.write(`${formatUsage()}\n`);
      return 0;
    }

    await runStdioProxy({
      url: values.url ?? env.COMPUTER_ACCESS_URL ?? DEFAULT_STDIO_MCP_URL,
      env,
      input: stdin,
      output: stdout,
      errorOutput: stderr,
    });
    return 0;
  }

  stderr.write(`Unknown command: ${first}\n\n${formatUsage()}\n`);
  return 1;
}

function isDirectEntrypoint(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(CLI_SCRIPT_PATH);
  } catch {
    return resolve(entry) === resolve(CLI_SCRIPT_PATH);
  }
}

if (isDirectEntrypoint()) {
  runCli(process.argv.slice(2)).then(
    (code) => {
      if (code === RESTART_EXIT_CODE) {
        process.exit(code);
      }
      if (code !== 0) {
        process.exitCode = code;
      }
    },
    (err) => {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`computer-access-mcp error: ${msg}\n`);
      process.exitCode = 1;
    },
  );
}

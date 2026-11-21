import { spawn } from 'node:child_process';
import type { ManagedProcess, SpawnManaged } from './process.ts';

export const spawnLocal: SpawnManaged = (spec) => {
  const [file, ...args] = spec.argv;
  if (!file) {
    throw new Error('empty-process-command');
  }
  const child = spawn(file, args, {
    cwd: spec.cwd,
    env: spec.env ?? process.env,
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: false,
    windowsHide: true,
  });

  let exited = false;
  const done = new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once('error', (error) => {
      exited = true;
      reject(error);
    });
    child.once('close', (exitCode, signal) => {
      exited = true;
      resolve({ exitCode, signal });
    });
  });

  let killTimer: ReturnType<typeof setTimeout> | undefined;
  const cleanup = () => {
    if (killTimer) clearTimeout(killTimer);
    killTimer = undefined;
  };
  void done.then(cleanup, cleanup);

  const handle: ManagedProcess = {
    stdin: child.stdin,
    stdout: child.stdout,
    stderr: child.stderr,
    done,
    terminate() {
      if (exited) return;
      child.kill('SIGTERM');
      killTimer ??= setTimeout(() => {
        if (!exited) child.kill('SIGKILL');
      }, spec.graceMs);
    },
    async waitForExit(signal) {
      if (exited) return true;
      if (signal?.aborted) return false;
      return new Promise<boolean>((resolve) => {
        const onAbort = () => {
          signal?.removeEventListener('abort', onAbort);
          resolve(false);
        };
        signal?.addEventListener('abort', onAbort, { once: true });
        void done.then(
          () => {
            signal?.removeEventListener('abort', onAbort);
            resolve(true);
          },
          () => {
            signal?.removeEventListener('abort', onAbort);
            resolve(true);
          },
        );
      });
    },
  };
  return handle;
};

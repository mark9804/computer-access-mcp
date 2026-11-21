import type { Readable, Writable } from 'node:stream';

export interface ManagedProcess {
  readonly stdin: Writable | undefined;
  readonly stdout: Readable | undefined;
  readonly stderr: Readable | undefined;
  readonly done: Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>;
  terminate(): void;
  waitForExit(signal?: AbortSignal): Promise<boolean>;
}

export interface SpawnSpec {
  argv: readonly string[];
  cwd: string;
  stdio: { stdin: 'pipe'; stdout: 'pipe'; stderr: 'pipe' };
  graceMs: number;
  env?: NodeJS.ProcessEnv;
}

export type SpawnManaged = (spec: SpawnSpec) => ManagedProcess;

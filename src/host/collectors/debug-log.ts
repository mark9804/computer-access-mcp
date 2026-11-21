import { constants } from 'node:fs';
import { mkdir, open } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { join } from 'node:path';
import type { DebugLogEntry } from '../../shared/ipc-types.ts';

const MAX_FILE_BYTES = 1_048_576;
const MAX_FILES = 4;
const MAX_QUEUE = 128;
const MAX_QUEUE_BYTES = 512 * 1024;
const MAX_LINE_BYTES = 8_192;

function sanitizeEntry(entry: DebugLogEntry): DebugLogEntry | null {
  if (
    !entry ||
    typeof entry !== 'object' ||
    typeof entry.timeMs !== 'number' ||
    !Number.isFinite(entry.timeMs) ||
    typeof entry.event !== 'string' ||
    entry.event.length === 0 ||
    entry.event.length > 128
  ) {
    return null;
  }
  const clean: DebugLogEntry = {
    timeMs: Math.trunc(entry.timeMs),
    event: entry.event,
    ...(typeof entry.runId === 'string' && entry.runId.length > 0 && entry.runId.length <= 128
      ? { runId: entry.runId }
      : {}),
  };
  if (entry.detail && typeof entry.detail === 'object' && !Array.isArray(entry.detail)) {
    const detail: Record<string, string | number | boolean | null> = {};
    const keys = Object.keys(entry.detail).slice(0, 24);
    for (const key of keys) {
      if (key.length === 0 || key.length > 64) continue;
      const val = entry.detail[key];
      if (val === null || typeof val === 'boolean') {
        detail[key] = val;
      } else if (typeof val === 'number' && Number.isFinite(val)) {
        detail[key] = val;
      } else if (typeof val === 'string' && val.length <= 256 && val.isWellFormed()) {
        detail[key] = val;
      }
    }
    if (Object.keys(detail).length > 0) {
      clean.detail = detail;
    }
  }
  return clean;
}

export class CollectorDebugLog {
  readonly directory: string;
  readonly enabled: boolean;

  #handle: FileHandle | undefined;
  #slot = 0;
  #currentBytes = 0;
  #pending = 0;
  #queuedBytes = 0;
  #opened = false;
  #closed = false;
  #failed = false;
  #work: Promise<void> = Promise.resolve();

  constructor(directory: string, enabled = false) {
    this.directory = directory;
    this.enabled = enabled === true;
  }

  async prepare(): Promise<void> {
    if (!this.enabled || this.#opened || this.#closed || this.#failed) {
      return;
    }
    const init = this.#work.then(async () => {
      if (this.#opened || this.#closed || this.#failed) return;
      try {
        await mkdir(this.directory, { recursive: true, mode: 0o700 });
        const filePath = join(this.directory, `trace-${this.#slot}.jsonl`);
        this.#handle = await open(filePath, constants.O_CREAT | constants.O_APPEND | constants.O_WRONLY, 0o600);
        const st = await this.#handle.stat();
        this.#currentBytes = st.size;
        this.#opened = true;
      } catch {
        this.#failed = true;
        await this.#releaseHandle();
      }
    });
    this.#work = init;
    await init;
  }

  append(entry: DebugLogEntry): void {
    if (!this.enabled || !this.#opened || this.#closed || this.#failed) {
      return;
    }
    const sanitized = sanitizeEntry(entry);
    if (!sanitized) return;

    const line = Buffer.from(JSON.stringify(sanitized) + '\n', 'utf8');
    if (
      line.length > MAX_LINE_BYTES ||
      this.#pending >= MAX_QUEUE ||
      this.#queuedBytes + line.length > MAX_QUEUE_BYTES
    ) {
      return;
    }

    this.#pending++;
    this.#queuedBytes += line.length;
    this.#work = this.#work
      .then(async () => {
        if (!this.#opened || this.#closed || this.#failed || !this.#handle) return;
        if (this.#currentBytes + line.length > MAX_FILE_BYTES) {
          await this.#rotate();
        }
        if (!this.#handle) return;
        await this.#handle.write(line);
        this.#currentBytes += line.length;
      })
      .catch(async () => {
        this.#failed = true;
        await this.#releaseHandle();
      })
      .finally(() => {
        this.#pending--;
        this.#queuedBytes -= line.length;
      });
  }

  async flush(): Promise<void> {
    if (!this.enabled) return;
    const drain = this.#work.then(async () => {
      try {
        await this.#handle?.datasync();
      } catch {
        // Ignore datasync failure on optional debug log.
      }
    });
    this.#work = drain;
    await drain;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    if (!this.enabled) return;
    const shutdown = this.#work.then(async () => {
      try {
        await this.#handle?.datasync();
      } catch {
        // Ignore datasync failure on close.
      } finally {
        await this.#releaseHandle();
      }
    });
    this.#work = shutdown;
    await shutdown;
  }

  async #rotate(): Promise<void> {
    await this.#releaseHandle();
    this.#slot = (this.#slot + 1) % MAX_FILES;
    const filePath = join(this.directory, `trace-${this.#slot}.jsonl`);
    this.#handle = await open(filePath, constants.O_CREAT | constants.O_TRUNC | constants.O_WRONLY, 0o600);
    this.#currentBytes = 0;
  }

  async #releaseHandle(): Promise<void> {
    const h = this.#handle;
    this.#handle = undefined;
    if (h) {
      await h.close().catch(() => {});
    }
  }
}

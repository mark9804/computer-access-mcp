import type { DebugLogEntry } from '../../shared/ipc-types.ts';

const SAFE_TOP_LEVEL_KEYS = new Set([
  'pid',
  'monotonicMs',
  'file',
  'line',
  'stage',
  'reason',
  'status',
  'phase',
  'outcome',
  'exitCode',
  'signal',
  'imageBase',
]);

const FORBIDDEN_STRING_KEYS = new Set(['text', 'value', 'url', 'title', 'description', 'secret']);

function addScalarDetail(
  detail: Record<string, string | number | boolean | null>,
  key: string,
  val: unknown,
): void {
  if (
    key.length === 0 ||
    key.length > 64 ||
    FORBIDDEN_STRING_KEYS.has(key) ||
    Object.keys(detail).length >= 24
  ) {
    return;
  }
  if (val === null || typeof val === 'boolean') detail[key] = val;
  else if (typeof val === 'number' && Number.isFinite(val)) detail[key] = val;
  else if (typeof val === 'string' && val.length <= 256 && val.isWellFormed()) detail[key] = val;
}

function parseStderrTrace(raw: unknown, runId?: string): DebugLogEntry | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = raw as Record<string, unknown>;
  const event =
    typeof obj.event === 'string'
      ? obj.event
      : typeof obj.code === 'string'
        ? obj.code
        : typeof obj.stage === 'string'
          ? obj.stage
          : null;
  if (!event || event.length === 0 || event.length > 128) return null;
  const timeMs =
    typeof obj.timeMs === 'number' && Number.isFinite(obj.timeMs) ? Math.trunc(obj.timeMs) : Date.now();
  const detail: Record<string, string | number | boolean | null> = {};

  for (const [key, val] of Object.entries(obj)) {
    if (key === 'event' || key === 'code' || key === 'timeMs' || key === 'version') continue;
    if (key === 'numbers' && val && typeof val === 'object' && !Array.isArray(val)) {
      for (const [nKey, nVal] of Object.entries(val as Record<string, unknown>)) {
        if (typeof nVal === 'number' && Number.isFinite(nVal)) {
          addScalarDetail(detail, nKey, nVal);
        }
      }
      continue;
    }
    if (key === 'flags' && val && typeof val === 'object' && !Array.isArray(val)) {
      for (const [fKey, fVal] of Object.entries(val as Record<string, unknown>)) {
        if (typeof fVal === 'boolean') {
          addScalarDetail(detail, fKey, fVal);
        }
      }
      continue;
    }
    if ((key === 'strings' || key === 'detail') && val && typeof val === 'object' && !Array.isArray(val)) {
      for (const [sKey, sVal] of Object.entries(val as Record<string, unknown>)) {
        addScalarDetail(detail, sKey, sVal);
      }
      continue;
    }
    if (SAFE_TOP_LEVEL_KEYS.has(key)) {
      addScalarDetail(detail, key, val);
    }
  }

  return {
    timeMs,
    ...(runId ? { runId } : {}),
    event,
    ...(Object.keys(detail).length > 0 ? { detail } : {}),
  };
}

export class CollectorDebugTrace {
  readonly enabled: boolean;
  #partial: Buffer = Buffer.alloc(0);
  #overflowing = false;
  readonly #runId: string | undefined;
  readonly #onEntry: ((entry: DebugLogEntry) => void) | undefined;

  constructor(enabled: boolean, options: { runId?: string; onEntry?: (entry: DebugLogEntry) => void } = {}) {
    this.enabled = enabled === true;
    this.#runId = options.runId;
    this.#onEntry = options.onEntry;
  }

  push(chunk: Buffer): void {
    if (!this.enabled) return;
    let offset = 0;
    while (offset < chunk.length) {
      const newline = chunk.indexOf(10, offset);
      const end = newline < 0 ? chunk.length : newline;
      if (!this.#overflowing) {
        if (this.#partial.length + (end - offset) > 4096) {
          this.#partial = Buffer.alloc(0);
          this.#overflowing = true;
        } else {
          this.#partial = Buffer.concat([this.#partial, chunk.subarray(offset, end)]);
        }
      }
      if (newline < 0) return;
      if (!this.#overflowing && this.#partial.length > 0) {
        try {
          const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(this.#partial));
          const entry = parseStderrTrace(parsed, this.#runId);
          if (entry) {
            this.#onEntry?.(entry);
          }
        } catch {
          // Ignore malformed stderr lines.
        }
      }
      this.#partial = Buffer.alloc(0);
      this.#overflowing = false;
      offset = newline + 1;
    }
  }

  reset(): void {
    this.#partial = Buffer.alloc(0);
    this.#overflowing = false;
  }
}

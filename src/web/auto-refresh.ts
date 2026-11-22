import type { StorageStatusSummary } from '../shared/api-types.ts';

export type AutoRefreshIntervalMs = 0 | 2000 | 5000 | 15000 | 30000;

export const AUTO_REFRESH_OPTIONS: readonly AutoRefreshIntervalMs[] = [0, 2000, 5000, 15000, 30000];
export const DEFAULT_AUTO_REFRESH_MS: AutoRefreshIntervalMs = 5000;

const STORAGE_KEY = 'camcp_auto_refresh_ms';

type StorageLike = Pick<Storage, 'getItem' | 'setItem'>;

type VisibilityDocumentLike = {
  readonly visibilityState: string;
  addEventListener(type: 'visibilitychange', listener: () => void): void;
  removeEventListener(type: 'visibilitychange', listener: () => void): void;
};

type TimerHandle = ReturnType<typeof setTimeout>;

export type AutoRefreshLoopOptions = {
  intervalMs: number;
  onTick: () => Promise<void> | void;
  document?: VisibilityDocumentLike | null | undefined;
  setTimer?: ((fn: () => void, ms: number) => TimerHandle) | undefined;
  clearTimer?: ((handle: TimerHandle) => void) | undefined;
};

export type AutoRefreshLoop = {
  stop: () => void;
};

export function parseAutoRefreshMs(raw: string | number | null | undefined): AutoRefreshIntervalMs | null {
  if (raw === null || raw === undefined || raw === '') return null;
  const parsed = typeof raw === 'number' ? raw : Number(raw);
  return AUTO_REFRESH_OPTIONS.includes(parsed as AutoRefreshIntervalMs)
    ? (parsed as AutoRefreshIntervalMs)
    : null;
}

export function initialAutoRefreshMs(storage?: StorageLike | null): AutoRefreshIntervalMs {
  try {
    const target = storage === undefined ? (typeof localStorage !== 'undefined' ? localStorage : null) : storage;
    const saved = parseAutoRefreshMs(target?.getItem(STORAGE_KEY));
    if (saved !== null) return saved;
  } catch {
    // Ignore storage failures in restricted contexts.
  }
  return DEFAULT_AUTO_REFRESH_MS;
}

export function persistAutoRefreshMs(ms: AutoRefreshIntervalMs, storage?: StorageLike | null): void {
  try {
    const target = storage === undefined ? (typeof localStorage !== 'undefined' ? localStorage : null) : storage;
    target?.setItem(STORAGE_KEY, String(ms));
  } catch {
    // Ignore storage failures.
  }
}

export function storageWatermarkOf(storage: StorageStatusSummary | null | undefined): string {
  if (!storage) return 'none';
  return `${storage.generation}:${storage.records}:${storage.bytes}:${storage.retainedTimeRange?.toTimeMs ?? 0}`;
}

export function shouldAutoRefreshHistory(state: {
  tab: string;
  hasStorage: boolean;
  cursorDepth: number;
  inspectorOpen: boolean;
  currentWatermark: string;
  lastFetchedWatermark: string | null;
}): boolean {
  return (
    state.tab === 'history' &&
    state.hasStorage &&
    state.cursorDepth === 1 &&
    !state.inspectorOpen &&
    state.currentWatermark !== state.lastFetchedWatermark
  );
}

/**
 * Visibility-aware single-flight polling loop.
 * Schedules the next tick only after the prior tick settles so slow requests never overlap,
 * pauses while the document is hidden, and runs one immediate tick when the tab becomes visible.
 */
export function createAutoRefreshLoop(options: AutoRefreshLoopOptions): AutoRefreshLoop {
  if (!Number.isFinite(options.intervalMs) || options.intervalMs <= 0) {
    return { stop: () => {} };
  }

  const doc =
    options.document === undefined
      ? typeof document !== 'undefined'
        ? document
        : null
      : options.document;
  const setTimer = options.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
  const clearTimer = options.clearTimer ?? ((handle) => clearTimeout(handle));

  let stopped = false;
  let inFlight = false;
  let pendingImmediate = false;
  let timer: TimerHandle | null = null;

  const isHidden = () => doc !== null && doc.visibilityState === 'hidden';

  const cancelTimer = () => {
    if (timer !== null) {
      clearTimer(timer);
      timer = null;
    }
  };

  const schedule = () => {
    if (stopped || inFlight || isHidden() || timer !== null) return;
    timer = setTimer(() => {
      timer = null;
      void run();
    }, options.intervalMs);
  };

  const run = async () => {
    if (stopped || isHidden()) return;
    if (inFlight) {
      pendingImmediate = true;
      return;
    }
    cancelTimer();
    inFlight = true;
    try {
      await options.onTick();
    } catch {
      // Caller owns error presentation; never terminate the loop on transient failures.
    } finally {
      inFlight = false;
      if (!stopped && !isHidden()) {
        if (pendingImmediate) {
          pendingImmediate = false;
          void run();
        } else {
          schedule();
        }
      }
    }
  };

  const handleVisibilityChange = () => {
    if (stopped) return;
    if (isHidden()) {
      cancelTimer();
      pendingImmediate = false;
      return;
    }
    void run();
  };

  doc?.addEventListener('visibilitychange', handleVisibilityChange);
  schedule();

  return {
    stop: () => {
      if (stopped) return;
      stopped = true;
      pendingImmediate = false;
      cancelTimer();
      doc?.removeEventListener('visibilitychange', handleVisibilityChange);
    },
  };
}

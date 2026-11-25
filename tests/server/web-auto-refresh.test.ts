import assert from 'node:assert/strict';
import test from 'node:test';
import type { StorageStatusSummary } from '../../src/shared/api-types.ts';
import {
  AUTO_REFRESH_OPTIONS,
  DEFAULT_AUTO_REFRESH_MS,
  createAutoRefreshLoop,
  initialAutoRefreshMs,
  parseAutoRefreshMs,
  persistAutoRefreshMs,
  shouldAutoRefreshHistory,
  storageWatermarkOf,
} from '../../src/web/auto-refresh.ts';

function makeStorageSummary(overrides: Partial<StorageStatusSummary> = {}): StorageStatusSummary {
  return {
    state: 'open',
    storeId: 'store-1',
    generation: 1,
    segments: 2,
    records: 100,
    bytes: 4096,
    retentionMs: 14 * 24 * 3_600_000,
    maxBytes: 16 * 1024 * 1024 * 1024,
    forgetBeforeMs: 0,
    retainedTimeRange: { fromTimeMs: 1_000, toTimeMs: 2_000 },
    counts: {
      text: 50,
      surface: 50,
      selection: 0,
      inputText: 0,
      activity: 0,
      menu: 0,
      context: 0,
      gap: 0,
      gapDiscarded: 0,
      gapException: 0,
    },
    ...overrides,
  };
}

class FakeTimerScheduler {
  private nextId = 1;
  private tasks = new Map<number, { fn: () => void; ms: number }>();

  readonly setTimer = (fn: () => void, ms: number): ReturnType<typeof setTimeout> => {
    const id = this.nextId++;
    this.tasks.set(id, { fn, ms });
    return id as unknown as ReturnType<typeof setTimeout>;
  };

  readonly clearTimer = (handle: ReturnType<typeof setTimeout>): void => {
    this.tasks.delete(handle as unknown as number);
  };

  get pendingCount(): number {
    return this.tasks.size;
  }

  pendingDelays(): number[] {
    return [...this.tasks.values()].map((t) => t.ms);
  }

  fireNext(): void {
    const first = this.tasks.entries().next();
    assert.ok(!first.done, 'expected a scheduled timer');
    const [id, task] = first.value;
    this.tasks.delete(id);
    task.fn();
  }
}

class FakeDocument {
  visibilityState: 'visible' | 'hidden' = 'visible';
  private listeners = new Set<() => void>();

  addEventListener(_type: 'visibilitychange', listener: () => void): void {
    this.listeners.add(listener);
  }

  removeEventListener(_type: 'visibilitychange', listener: () => void): void {
    this.listeners.delete(listener);
  }

  get listenerCount(): number {
    return this.listeners.size;
  }

  setVisibility(state: 'visible' | 'hidden'): void {
    this.visibilityState = state;
    for (const listener of [...this.listeners]) {
      listener();
    }
  }
}

async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

test('auto-refresh preference parsing and persistence handle valid, invalid, and throwing storage', () => {
  for (const ms of AUTO_REFRESH_OPTIONS) {
    assert.equal(parseAutoRefreshMs(ms), ms);
    assert.equal(parseAutoRefreshMs(String(ms)), ms);
  }
  assert.equal(parseAutoRefreshMs(null), null);
  assert.equal(parseAutoRefreshMs(''), null);
  assert.equal(parseAutoRefreshMs('1234'), null);
  assert.equal(parseAutoRefreshMs('off'), null);

  const mem = new Map<string, string>();
  const storage = {
    getItem: (k: string) => mem.get(k) ?? null,
    setItem: (k: string, v: string) => {
      mem.set(k, v);
    },
  };

  assert.equal(initialAutoRefreshMs(storage), DEFAULT_AUTO_REFRESH_MS);
  persistAutoRefreshMs(2000, storage);
  assert.equal(initialAutoRefreshMs(storage), 2000);
  persistAutoRefreshMs(0, storage);
  assert.equal(initialAutoRefreshMs(storage), 0);

  mem.set('chmcp_auto_refresh_ms', '999999');
  assert.equal(initialAutoRefreshMs(storage), DEFAULT_AUTO_REFRESH_MS);

  const throwingStorage = {
    getItem: () => {
      throw new Error('blocked');
    },
    setItem: () => {
      throw new Error('blocked');
    },
  };
  assert.equal(initialAutoRefreshMs(throwingStorage), DEFAULT_AUTO_REFRESH_MS);
  assert.doesNotThrow(() => persistAutoRefreshMs(15000, throwingStorage));
});

test('storageWatermarkOf and shouldAutoRefreshHistory gate page-1 history refreshes safely', () => {
  assert.equal(storageWatermarkOf(null), 'none');
  const base = makeStorageSummary();
  const w1 = storageWatermarkOf(base);
  const w2 = storageWatermarkOf(makeStorageSummary({ records: 101 }));
  const w3 = storageWatermarkOf(
    makeStorageSummary({ retainedTimeRange: { fromTimeMs: 1_000, toTimeMs: 2_500 } }),
  );
  assert.notEqual(w1, w2);
  assert.notEqual(w1, w3);

  // Refreshes only on History tab, page 1, inspector closed, with storage and changed watermark.
  assert.equal(
    shouldAutoRefreshHistory({
      tab: 'history',
      hasStorage: true,
      cursorDepth: 1,
      inspectorOpen: false,
      currentWatermark: w2,
      lastFetchedWatermark: w1,
    }),
    true,
  );

  // Skips when storage watermark is unchanged.
  assert.equal(
    shouldAutoRefreshHistory({
      tab: 'history',
      hasStorage: true,
      cursorDepth: 1,
      inspectorOpen: false,
      currentWatermark: w1,
      lastFetchedWatermark: w1,
    }),
    false,
  );

  // Skips on page 2+, while inspector is open, on other tabs, or without storage.
  assert.equal(
    shouldAutoRefreshHistory({
      tab: 'history',
      hasStorage: true,
      cursorDepth: 2,
      inspectorOpen: false,
      currentWatermark: w2,
      lastFetchedWatermark: w1,
    }),
    false,
  );
  assert.equal(
    shouldAutoRefreshHistory({
      tab: 'history',
      hasStorage: true,
      cursorDepth: 1,
      inspectorOpen: true,
      currentWatermark: w2,
      lastFetchedWatermark: w1,
    }),
    false,
  );
  assert.equal(
    shouldAutoRefreshHistory({
      tab: 'overview',
      hasStorage: true,
      cursorDepth: 1,
      inspectorOpen: false,
      currentWatermark: w2,
      lastFetchedWatermark: w1,
    }),
    false,
  );
  assert.equal(
    shouldAutoRefreshHistory({
      tab: 'history',
      hasStorage: false,
      cursorDepth: 1,
      inspectorOpen: false,
      currentWatermark: w2,
      lastFetchedWatermark: w1,
    }),
    false,
  );
});

test('createAutoRefreshLoop enforces single-flight, visibility pause/resume, error resilience, and clean stop', async () => {
  const timers = new FakeTimerScheduler();
  const doc = new FakeDocument();

  // Disabled loop schedules nothing and attaches no listeners.
  const disabledLoop = createAutoRefreshLoop({
    intervalMs: 0,
    onTick: () => {},
    document: doc,
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer,
  });
  assert.equal(timers.pendingCount, 0);
  assert.equal(doc.listenerCount, 0);
  disabledLoop.stop();

  let ticks = 0;
  let releaseTick: (() => void) | null = null;
  let shouldThrow = false;

  const loop = createAutoRefreshLoop({
    intervalMs: 5000,
    document: doc,
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer,
    onTick: () => {
      ticks += 1;
      if (shouldThrow) {
        shouldThrow = false;
        return Promise.reject(new Error('transient'));
      }
      return new Promise<void>((resolve) => {
        releaseTick = resolve;
      });
    },
  });

  // Initial timer scheduled at 5000ms without immediate duplicate tick.
  assert.equal(ticks, 0);
  assert.deepEqual(timers.pendingDelays(), [5000]);
  assert.equal(doc.listenerCount, 1);

  // Fire tick #1: while in flight, no second timer is scheduled.
  timers.fireNext();
  assert.equal(ticks, 1);
  assert.equal(timers.pendingCount, 0);

  // Visibility bounce while tick #1 is in flight queues one follow-up tick instead of overlapping.
  doc.setVisibility('hidden');
  doc.setVisibility('visible');
  assert.equal(ticks, 1);
  assert.equal(timers.pendingCount, 0);

  // Settling tick #1 immediately runs the queued visible wakeup tick #2.
  releaseTick!();
  releaseTick = null;
  await flushMicrotasks();
  assert.equal(ticks, 2);
  assert.equal(timers.pendingCount, 0);

  // Settling tick #2 reschedules the next 5000ms timer.
  releaseTick!();
  releaseTick = null;
  await flushMicrotasks();
  assert.equal(timers.pendingCount, 1);

  // Hiding the document cancels the scheduled timer.
  doc.setVisibility('hidden');
  assert.equal(timers.pendingCount, 0);

  // Returning to visible runs an immediate tick #3 even after transient failure.
  shouldThrow = true;
  doc.setVisibility('visible');
  await flushMicrotasks();
  assert.equal(ticks, 3);
  assert.equal(timers.pendingCount, 1);

  // Stopping while a tick is in flight cancels timers, detaches listeners, and never reschedules.
  timers.fireNext();
  assert.equal(ticks, 4);
  loop.stop();
  assert.equal(timers.pendingCount, 0);
  assert.equal(doc.listenerCount, 0);

  releaseTick!();
  releaseTick = null;
  await flushMicrotasks();
  assert.equal(timers.pendingCount, 0);

  // Further visibility changes do nothing after stop.
  doc.setVisibility('hidden');
  doc.setVisibility('visible');
  await flushMicrotasks();
  assert.equal(ticks, 4);
});

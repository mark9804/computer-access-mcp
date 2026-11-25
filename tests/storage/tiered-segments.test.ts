import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import type { TestContext } from 'node:test';
import type { Observation, SurfaceSnapshot } from '../../src/shared/protocol/generated.ts';
import {
  HISTORY_MAX_BYTES,
  HISTORY_RETENTION_MS,
  HOT_CACHE_MAX_BYTES,
  HOT_CACHE_MAX_SEGMENTS,
  MemoryKeyProvider,
  SegmentStore,
  StorageError,
} from '../../src/storage/index.ts';
import { formatBytes } from '../../src/web/format.ts';

const BASE_TIME = 1_750_000_000_000;

function makeTextObs(
  seq: number,
  text: string,
  eventTimeMs: number,
  options: {
    instanceId?: string;
    applicationId?: string;
    snapshotId?: string;
    windowId?: string;
  } = {},
): Observation {
  const instanceId = options.instanceId ?? 'inst-tiered';
  const applicationId = options.applicationId ?? 'com.example.editor';
  const snapshotId = options.snapshotId ?? `snap-${instanceId}-${seq}`;
  return {
    protocolVersion: 1,
    type: 'observation',
    eventId: `${instanceId}:${seq}`,
    instanceId,
    seq,
    eventTimeMs,
    monotonicMs: seq * 10,
    target: {
      kind: 'resolved',
      identity: {
        deviceId: 'dev-1',
        osSessionId: 'audit-1',
        desktopId: 'console-audit-1',
        processId: 1000,
        processStartTime: 'unix-ms:1750000000000.000',
        applicationId,
        windowId: options.windowId ?? 'win-1',
        windowGeneration: 1,
      },
    },
    stamp: {
      captureEpoch: 1,
      focusGeneration: 1,
      foregroundGeneration: 1,
      policyRevision: 1,
    },
    actor: 'unknown',
    relatedActionIds: [],
    payload: {
      kind: 'text.snapshot',
      snapshotId,
      editSessionId: 'edit-1',
      nodeId: 'node-1',
      source: 'fixture',
      scope: 'field',
      valueState: 'read',
      text,
      range: { unit: 'utf16', start: 0, length: text.length },
      totalLength: text.length,
      composition: 'unknown',
      captureStartMs: eventTimeMs,
      captureEndMs: eventTimeMs,
      coverage: { status: 'complete', truncated: false, missingReasons: [] },
    },
  };
}

function makeSurfaceObs(
  seq: number,
  label: string,
  eventTimeMs: number,
  options: {
    instanceId?: string;
    applicationId?: string;
    snapshotId?: string;
  } = {},
): Observation & { payload: SurfaceSnapshot } {
  const base = makeTextObs(seq, '', eventTimeMs, options);
  return {
    ...base,
    payload: {
      kind: 'surface.snapshot',
      snapshotId: options.snapshotId ?? `surf-${seq}`,
      surfaceId: 'surface-main',
      revision: seq,
      source: 'fixture',
      scope: 'window',
      mode: 'full',
      nodes: [
        {
          id: `n-${seq}`,
          role: 'text',
          axRole: 'AXStaticText',
          text: label,
          bounds: { x: 0, y: 0, width: 400, height: 40 },
          boundsObservedAtMs: eventTimeMs,
          observedAtMs: eventTimeMs,
          focused: true,
        },
      ],
      geometry: {
        coordinateSpace: 'window-top-left-point',
        windowSize: { width: 1200, height: 800 },
        observedAtMs: eventTimeMs,
      },
      captureStartMs: eventTimeMs,
      captureEndMs: eventTimeMs + 1,
      coverage: { status: 'complete', truncated: false, missingReasons: [] },
      gate: { secure: 'safe', privateState: 'normal', policyRevision: 1 },
      consistency: 'non-atomic',
    },
  };
}

async function createTempEnv(t: TestContext) {
  const parent = await realpath(await mkdtemp(join(tmpdir(), 'chmcp-tiered-')));
  const root = join(parent, 'data');
  const key = randomBytes(32);
  const keyProvider = new MemoryKeyProvider(key);
  t.after(async () => {
    key.fill(0);
    await rm(parent, { recursive: true, force: true });
  });
  return { parent, root, keyProvider };
}

function expectCode(code: StorageError['code']) {
  return (err: unknown): boolean => {
    assert.ok(err instanceof StorageError);
    assert.equal(err.code, code);
    return true;
  };
}

test('storage defaults are 14 days / 16 GiB with bounded hot cache and GiB UI formatting', () => {
  assert.equal(HISTORY_RETENTION_MS, 14 * 24 * 60 * 60 * 1000);
  assert.equal(HISTORY_MAX_BYTES, 16 * 1024 * 1024 * 1024);
  assert.equal(HOT_CACHE_MAX_BYTES, 32 * 1024 * 1024);
  assert.equal(HOT_CACHE_MAX_SEGMENTS, 16);
  assert.equal(formatBytes(HISTORY_MAX_BYTES), '16.00 GiB');
  assert.equal(formatBytes(512 * 1024 * 1024), '512.00 MiB');
});

test('cold/hot tiered SegmentStore serves read, layout, search, pagination, and latestApplicationTarget across evicted segments', async (t) => {
  const env = await createTempEnv(t);
  let now = BASE_TIME;
  const store = await SegmentStore.open({
    root: env.root,
    keyProvider: env.keyProvider,
    maxSegmentBytes: 2200,
    hotCacheMaxSegments: 2,
    hotCacheMaxBytes: 6000,
    clock: () => now,
  });

  try {
    // Write 16 distinct records across >= 8 rolled segments with two apps and two surfaces sharing a snapshotId.
    const pad = 'Z'.repeat(500);
    for (let seq = 1; seq <= 16; seq++) {
      now = BASE_TIME + seq * 1000;
      const appId = seq % 4 === 1 ? 'com.example.rare' : 'com.example.editor';
      if (seq === 2 || seq === 14) {
        await store.append(
          makeSurfaceObs(seq, `surface-${seq}-${pad}`, now, {
            applicationId: appId,
            snapshotId: 'shared-surf-snap',
          }),
        );
      } else if (seq === 3) {
        await store.append(
          makeSurfaceObs(seq, `unique-surface-${pad}`, now, {
            applicationId: 'com.example.layout',
            snapshotId: 'cold-layout-snap',
          }),
        );
      } else {
        await store.append(
          makeTextObs(seq, `rec-${seq}-${pad}`, now, {
            applicationId: appId,
            windowId: `win-${seq}`,
          }),
        );
      }
    }

    const st = store.status();
    assert.ok(st.segments >= 8, `expected >= 8 rolled segments, got ${st.segments}`);
    assert.equal(st.records, 16);
    assert.equal(st.counts.text, 13);
    assert.equal(st.counts.surface, 3);
    assert.equal(st.retainedTimeRange?.fromTimeMs, BASE_TIME + 1000);
    assert.equal(st.retainedTimeRange?.toTimeMs, BASE_TIME + 16_000);

    // Cold read by eventId and snapshotId (segment 1 is well outside the 2-segment hot cache).
    assert.equal((await store.read('inst-tiered:1'))?.eventId, 'inst-tiered:1');
    assert.equal((await store.read('snap-inst-tiered-1'))?.eventId, 'inst-tiered:1');
    assert.equal((await store.read('cold-layout-snap'))?.eventId, 'inst-tiered:3');

    // Ambiguous snapshotId spanning two separate cold/hot segments must reject with snapshot-ambiguous.
    await assert.rejects(store.read('shared-surf-snap'), expectCode('snapshot-ambiguous'));
    await assert.rejects(
      store.layout({ snapshotId: 'shared-surf-snap' }),
      expectCode('snapshot-ambiguous'),
    );

    // Cold layout query by snapshotId and eventId.
    const layoutBySnap = await store.layout({ snapshotId: 'cold-layout-snap' });
    assert.equal(layoutBySnap.found, true);
    if (layoutBySnap.found) {
      assert.equal(layoutBySnap.eventId, 'inst-tiered:3');
      assert.equal(layoutBySnap.nodes[0]?.id, 'n-3');
    }

    // Latest target for an app whose latest record lives in an older segment.
    const rareTarget = await store.latestApplicationTarget('com.example.rare');
    assert.ok(rareTarget && 'windowId' in rareTarget);
    assert.equal(rareTarget.windowId, 'win-13');
    const layoutTarget = await store.latestApplicationTarget('com.example.layout');
    assert.equal(layoutTarget?.applicationId, 'com.example.layout');
    assert.equal(await store.latestApplicationTarget('com.example.missing'), null);

    // Full DESC pagination across all cold + hot segments returns exact reverse order 16..1.
    const seenDesc: string[] = [];
    let cursor: string | undefined;
    for (;;) {
      const page = await store.search({
        limit: 4,
        order: 'desc',
        ...(cursor ? { cursor } : {}),
      });
      seenDesc.push(...page.records.map((r) => r.eventId));
      if (!page.hasMore) break;
      cursor = page.nextCursor;
      assert.ok(cursor);
    }
    assert.deepEqual(
      seenDesc,
      Array.from({ length: 16 }, (_, idx) => `inst-tiered:${16 - idx}`),
    );

    // Full ASC pagination filtered by applicationId skips unrelated segments cleanly.
    const rarePage = await store.search({ applicationId: 'com.example.rare', order: 'asc' });
    assert.deepEqual(
      rarePage.records.map((r) => r.eventId),
      ['inst-tiered:1', 'inst-tiered:5', 'inst-tiered:9', 'inst-tiered:13'],
    );
  } finally {
    await store.close();
  }
});

test('cold/hot tiered search preserves exact global ordering with overlapping/out-of-order timestamps across segments', async (t) => {
  const env = await createTempEnv(t);
  const now = BASE_TIME + 50_000;
  const store = await SegmentStore.open({
    root: env.root,
    keyProvider: env.keyProvider,
    maxSegmentBytes: 1800,
    hotCacheMaxSegments: 1,
    clock: () => now,
  });

  try {
    // Deliberately interleave eventTimeMs across segments (including exact timestamp ties).
    const schedule = [
      { seq: 1, t: BASE_TIME + 5000 },
      { seq: 2, t: BASE_TIME + 2000 },
      { seq: 3, t: BASE_TIME + 4000 },
      { seq: 4, t: BASE_TIME + 4000 },
      { seq: 5, t: BASE_TIME + 1000 },
      { seq: 6, t: BASE_TIME + 6000 },
      { seq: 7, t: BASE_TIME + 3000 },
      { seq: 8, t: BASE_TIME + 4000 },
    ];
    const pad = 'Q'.repeat(500);
    for (const item of schedule) {
      await store.append(makeTextObs(item.seq, `item-${item.seq}-${pad}`, item.t));
    }
    assert.ok(store.status().segments >= 4);

    // Expected ASC order: seq 5 (1000), 2 (2000), 7 (3000), 3 (4000), 4 (4000), 8 (4000), 1 (5000), 6 (6000).
    const expectedAsc = [5, 2, 7, 3, 4, 8, 1, 6].map((s) => `inst-tiered:${s}`);
    const ascGot: string[] = [];
    let cursor: string | undefined;
    for (;;) {
      const page = await store.search({ limit: 2, order: 'asc', ...(cursor ? { cursor } : {}) });
      ascGot.push(...page.records.map((r) => r.eventId));
      if (!page.hasMore) break;
      cursor = page.nextCursor;
    }
    assert.deepEqual(ascGot, expectedAsc);

    // Expected DESC order: exact reverse of ASC (including tie order: 8, 4, 3 at t=4000).
    const expectedDesc = [...expectedAsc].reverse();
    const descGot: string[] = [];
    cursor = undefined;
    for (;;) {
      const page = await store.search({ limit: 3, order: 'desc', ...(cursor ? { cursor } : {}) });
      descGot.push(...page.records.map((r) => r.eventId));
      if (!page.hasMore) break;
      cursor = page.nextCursor;
    }
    assert.deepEqual(descGot, expectedDesc);
  } finally {
    await store.close();
  }
});

test('cold/hot tiered append enforces dedup, out-of-order, cold text.changed baseline, and cold text-delta recovery', async (t) => {
  const env = await createTempEnv(t);
  let now = BASE_TIME;
  const store = await SegmentStore.open({
    root: env.root,
    keyProvider: env.keyProvider,
    maxSegmentBytes: 2400,
    hotCacheMaxSegments: 1,
    clock: () => now,
  });

  try {
    // Segment 1: keyframe + v2 delta frame in the same segment.
    const docBase = 'Paragraph zero '.repeat(40); // ~600 chars
    const obs1 = makeTextObs(1, docBase, now + 100);
    const obs2 = makeTextObs(2, `${docBase}edit-1`, now + 200);
    await store.append(obs1);
    await store.append(obs2);

    // Push several more large records to force segment 1 out of the 1-segment hot cache.
    for (let seq = 3; seq <= 8; seq++) {
      now = BASE_TIME + seq * 1000;
      await store.append(makeTextObs(seq, `${seq}:${'M'.repeat(700)}`, now, { instanceId: 'inst-other' }));
    }
    assert.ok(store.status().segments >= 4);

    // Idempotent duplicate of cold obs1 succeeds; conflicting payload or duplicate cold snapshotId rejects.
    await store.append(obs1);
    await assert.rejects(
      store.append(makeTextObs(1, 'tampered-payload', BASE_TIME + 100)),
      expectCode('duplicate-conflict'),
    );
    await assert.rejects(
      store.append(makeTextObs(99, 'different-seq-same-snap', now + 50, { snapshotId: 'snap-inst-tiered-1' })),
      expectCode('duplicate-conflict'),
    );

    // text.changed referencing a baseline living in evicted cold segment 1 succeeds!
    now += 100;
    const coldDeltaChange: Observation = {
      ...makeTextObs(3, '', now),
      payload: {
        kind: 'text.changed',
        baseSnapshotId: 'snap-inst-tiered-2',
        after: {
          kind: 'text.snapshot',
          snapshotId: 'snap-inst-tiered-3',
          editSessionId: 'edit-1',
          nodeId: 'node-1',
          source: 'fixture',
          scope: 'field',
          valueState: 'read',
          text: `${docBase}edit-1-and-2`,
          range: { unit: 'utf16', start: 0, length: `${docBase}edit-1-and-2`.length },
          totalLength: `${docBase}edit-1-and-2`.length,
          composition: 'unknown',
          captureStartMs: now,
          captureEndMs: now,
          coverage: { status: 'complete', truncated: false, missingReasons: [] },
        },
      },
    };
    await store.append(coldDeltaChange);
    const readChanged = await store.read('inst-tiered:3');
    assert.equal(readChanged?.payload.kind, 'text.snapshot');
    if (readChanged?.payload.kind === 'text.snapshot') {
      assert.equal(readChanged.payload.text, `${docBase}edit-1-and-2`);
    }

    // Partial forget right between obs1 (t+100) and obs2 (t+200) inside cold segment 1:
    // obs2 must still materialize full text on cold reload and elide dangling delta in textView='delta'.
    await store.forget({ beforeMs: BASE_TIME + 150 });
    assert.equal(await store.read('inst-tiered:1'), null);
    const obs2AfterForget = await store.read('inst-tiered:2');
    assert.equal(obs2AfterForget?.payload.kind, 'text.snapshot');
    if (obs2AfterForget?.payload.kind === 'text.snapshot') {
      assert.equal(obs2AfterForget.payload.text, `${docBase}edit-1`);
    }
    const deltaView = await store.search({ text: 'edit-1', textView: 'delta', order: 'asc' });
    const rec2 = deltaView.records.find((r) => r.eventId === 'inst-tiered:2');
    assert.ok(rec2 && rec2.payload.kind === 'text.snapshot');
    assert.equal(rec2.payload.text, `${docBase}edit-1`);
    assert.equal(deltaView.textDeltas?.['inst-tiered:2'], undefined);
  } finally {
    await store.close();
  }
});

test('post-open tampering of a cold segment fails closed with invalid-store on cache miss', async (t) => {
  const env = await createTempEnv(t);
  let now = BASE_TIME;
  const store = await SegmentStore.open({
    root: env.root,
    keyProvider: env.keyProvider,
    maxSegmentBytes: 1800,
    hotCacheMaxSegments: 1,
    clock: () => now,
  });

  try {
    const pad = 'T'.repeat(600);
    for (let seq = 1; seq <= 6; seq++) {
      now = BASE_TIME + seq * 1000;
      await store.append(makeTextObs(seq, `rec-${seq}-${pad}`, now));
    }
    assert.ok(store.status().segments >= 4);

    // Corrupt a byte inside cold closed seg-00000001.cah after open().
    const seg1Path = join(env.root, 'seg-00000001.cah');
    const raw = Buffer.from(await readFile(seg1Path));
    raw[raw.length - 1] = (raw[raw.length - 1] ?? 0) ^ 0xff;
    await writeFile(seg1Path, raw, { mode: 0o600 });

    // Reading from cold seg-00000001.cah must detect AEAD tampering and fail closed.
    await assert.rejects(store.read('inst-tiered:1'), expectCode('invalid-store'));
    assert.equal(store.status().state, 'failed');
    assert.equal((await readdir(env.root)).some((f) => f.endsWith('.idx')), false);
  } finally {
    await store.close();
  }
});

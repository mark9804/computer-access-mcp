import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  appendFile,
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  symlink,
  truncate,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import type { TestContext } from 'node:test';
import type { Observation, SurfaceNode, SurfaceSnapshot } from '../../src/shared/protocol/generated.ts';
import {
  HISTORY_MAX_BYTES,
  HISTORY_RETENTION_MS,
  MemoryKeyProvider,
  SEGMENT_HEADER_BYTES,
  SEGMENT_MAX_BYTES,
  SegmentStore,
  StorageError,
} from '../../src/storage/index.ts';

const SECRET = 'SYNTHETIC-ONLY-中文正文-秘密-c8f71';
const APP_ID = 'com.example.synthetic.editor';
const BASE_TIME = 1_700_000_100_000;

function makeTextObservation(
  seq: number,
  text = `${SECRET}-${seq}`,
  eventTimeMs = BASE_TIME + seq * 1000,
  applicationId = APP_ID,
): Observation {
  return {
    protocolVersion: 1,
    type: 'observation',
    eventId: `inst-1:${seq}`,
    instanceId: 'inst-1',
    seq,
    eventTimeMs,
    monotonicMs: seq * 10,
    target: {
      kind: 'resolved',
      identity: {
        deviceId: 'dev-1',
        osSessionId: 'audit-100',
        desktopId: 'console-audit-100',
        processId: 4242,
        processStartTime: 'unix-ms:1700000000000.000',
        applicationId,
        windowId: 'win-private-1',
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
      snapshotId: `snap-${seq}`,
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

function makeSurfaceObservation(
  seq: number,
  nodes: SurfaceNode[],
  eventTimeMs = BASE_TIME + seq * 1000,
  snapshotId = `surface-snap-${seq}`,
): Observation & { payload: SurfaceSnapshot } {
  return {
    ...makeTextObservation(seq, '', eventTimeMs),
    payload: {
      kind: 'surface.snapshot',
      snapshotId,
      surfaceId: 'surface-main',
      revision: seq,
      source: 'fixture',
      scope: 'window',
      mode: 'full',
      nodes,
      geometry: {
        coordinateSpace: 'window-top-left-point',
        windowSize: { width: 1200, height: 800 },
        observedAtMs: eventTimeMs,
      },
      captureStartMs: eventTimeMs,
      captureEndMs: eventTimeMs + 5,
      coverage: { status: 'complete', truncated: false, missingReasons: [] },
      gate: { secure: 'safe', privateState: 'normal', policyRevision: 1 },
      consistency: 'non-atomic',
    },
  };
}

function expectCode(code: StorageError['code']) {
  return (err: unknown): boolean => {
    assert.ok(err instanceof StorageError);
    assert.equal(err.code, code);
    assert.equal(err.message.includes(SECRET), false);
    return true;
  };
}

async function createTempEnv(t: TestContext) {
  const parent = await realpath(await mkdtemp(join(tmpdir(), 'camcp-segment-store-')));
  const root = join(parent, 'data');
  const key = randomBytes(32);
  const keyProvider = new MemoryKeyProvider(key);
  t.after(async () => {
    key.fill(0);
    await rm(parent, { recursive: true, force: true });
  });
  return { parent, root, key, keyProvider };
}

test('SegmentStore writes pure-ASCII NTFS/APFS-safe files, 32-byte CAHS header, and zero plaintext on disk', async (t) => {
  const env = await createTempEnv(t);
  // Pre-populate sibling daemon files to verify coexistence in dataRoot.
  await mkdir(env.root, { mode: 0o700 });
  await writeFile(join(env.root, 'admin.token'), 'synthetic-token', { mode: 0o600 });

  const store = await SegmentStore.open({
    root: env.root,
    keyProvider: env.keyProvider,
    clock: () => BASE_TIME,
  });

  try {
    assert.equal(store.status().retentionMs, HISTORY_RETENTION_MS);
    assert.equal(store.status().maxBytes, HISTORY_MAX_BYTES);
    assert.equal(store.status().segments, 0);

    await store.append(makeTextObservation(1, SECRET, BASE_TIME));
    assert.equal(store.status().segments, 1);
    assert.equal(store.status().records, 1);

    const files = (await readdir(env.root)).sort();
    assert.deepEqual(files, ['admin.token', 'seg-00000001.cah', 'store.lock', 'store.meta']);
    for (const name of files) {
      assert.equal(name.includes(':'), false);
    }

    // Verify 32-byte segment header layout.
    const segBytes = await readFile(join(env.root, 'seg-00000001.cah'));
    assert.ok(segBytes.length > SEGMENT_HEADER_BYTES);
    assert.equal(segBytes.subarray(0, 5).toString('binary'), 'CAHS\x01');
    assert.deepEqual([...segBytes.subarray(5, 8)], [0, 0, 0]);
    assert.equal(segBytes.readBigUInt64BE(8), 1n);
    assert.equal(segBytes.readBigUInt64BE(16), BigInt(BASE_TIME));
    assert.deepEqual([...segBytes.subarray(24, 32)], [0, 0, 0, 0, 0, 0, 0, 0]);

    // Queries must not materialize plaintext index files, and ciphertext must contain no secrets.
    for (let i = 0; i < 10; i++) {
      const found = await store.search({ text: '中文正文' });
      assert.equal(found.records.length, 1);
    }
    assert.deepEqual((await readdir(env.root)).sort(), files);

    for (const storeFile of ['store.meta', 'seg-00000001.cah']) {
      const raw = await readFile(join(env.root, storeFile));
      assert.equal((await lstat(join(env.root, storeFile))).mode & 0o777, 0o600);
      for (const needle of [SECRET, APP_ID, 'inst-1:1', 'win-private-1', 'snap-1', 'eventTimeMs']) {
        assert.equal(raw.includes(Buffer.from(needle, 'utf8')), false);
        assert.equal(raw.includes(Buffer.from(needle, 'utf16le')), false);
      }
    }
  } finally {
    await store.close();
  }
});

test('SegmentStore rejects uninitialized or wrong master key cleanly', async (t) => {
  const env = await createTempEnv(t);
  const emptyProvider = new MemoryKeyProvider();
  await assert.rejects(
    SegmentStore.open({ root: env.root, keyProvider: emptyProvider }),
    expectCode('key-unavailable'),
  );

  const store = await SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME });
  await store.append(makeTextObservation(1));
  await store.close();

  const wrongProvider = new MemoryKeyProvider(randomBytes(32));
  await assert.rejects(
    SegmentStore.open({ root: env.root, keyProvider: wrongProvider, clock: () => BASE_TIME }),
    expectCode('authentication-failed'),
  );
});

test('SegmentStore rolls active segment at 4 MiB, closes sealed segment, and reloads all records', async (t) => {
  const env = await createTempEnv(t);
  let now = BASE_TIME;
  const store = await SegmentStore.open({
    root: env.root,
    keyProvider: env.keyProvider,
    clock: () => now,
  });

  // Use distinct 8000-char payloads (~8.4 KB per full encrypted frame) so ~500 frames crosses 4 MiB cleanly.
  let count = 0;
  try {
    while (store.status().segments < 2) {
      count++;
      now += 10;
      const chunkPayload = String.fromCharCode(65 + (count % 26)).repeat(7900);
      await store.append(makeTextObservation(count, `${count}:${chunkPayload}`, now));
      assert.ok(count < 1000, 'segment should roll well before 1000 records');
    }

    const seg1Stat = await lstat(join(env.root, 'seg-00000001.cah'));
    const seg2Stat = await lstat(join(env.root, 'seg-00000002.cah'));
    assert.ok(seg1Stat.size >= SEGMENT_MAX_BYTES);
    assert.equal(seg2Stat.size, SEGMENT_HEADER_BYTES);

    // Append one more into seg-00000002.cah.
    count++;
    now += 10;
    await store.append(makeTextObservation(count, `${count}:tail`, now));
    assert.ok((await lstat(join(env.root, 'seg-00000002.cah'))).size > SEGMENT_HEADER_BYTES);
  } finally {
    await store.close();
  }

  const reopened = await SegmentStore.open({
    root: env.root,
    keyProvider: env.keyProvider,
    clock: () => now,
  });
  try {
    assert.equal(reopened.status().records, count);
    assert.equal(reopened.status().segments, 2);
    const first = await reopened.read('inst-1:1');
    const last = await reopened.read(`inst-1:${count}`);
    assert.equal(first?.eventId, 'inst-1:1');
    assert.equal(last?.eventId, `inst-1:${count}`);
  } finally {
    await reopened.close();
  }
});

test('SegmentStore evicts closed segments by 7-day TTL and maxBytes capacity without unlinking open handles', async (t) => {
  const env = await createTempEnv(t);
  let now = BASE_TIME;

  // Part 1: 7-day TTL eviction across rolled segments.
  const store = await SegmentStore.open({
    root: env.root,
    keyProvider: env.keyProvider,
    maxSegmentBytes: 2048,
    clock: () => now,
  });

  try {
    const body = 'X'.repeat(800);
    // Write 3 old records at t = BASE_TIME -> rolls seg-00000001.cah and opens seg-00000002.cah.
    await store.append(makeTextObservation(1, body, now));
    await store.append(makeTextObservation(2, body, now + 1));
    assert.ok((await readdir(env.root)).includes('seg-00000001.cah'));

    // Advance 6 days and write newer records into later segments.
    now = BASE_TIME + 6 * 24 * 60 * 60 * 1000;
    await store.append(makeTextObservation(3, body, now));
    await store.append(makeTextObservation(4, body, now + 1));
    assert.equal(store.status().records, 4);

    // Advance past 7 days from BASE_TIME (7d + 10s): records 1 & 2 expire, closed seg-00000001.cah is unlinked.
    now = BASE_TIME + HISTORY_RETENTION_MS + 10_000;
    const evicted = await store.pruneExpired();
    assert.equal(evicted, 2);
    assert.equal(store.status().records, 2);
    assert.equal((await readdir(env.root)).includes('seg-00000001.cah'), false);
    assert.equal(await store.read('inst-1:1'), null);
    assert.ok(await store.read('inst-1:3'));

    // Advance past 7 days from the remaining active segment too: active segment closes and unlinks cleanly.
    now += HISTORY_RETENTION_MS + 10_000;
    await store.pruneExpired();
    assert.equal(store.status().records, 0);
    assert.equal(store.status().segments, 0);
    assert.equal((await readdir(env.root)).some((f) => f.endsWith('.cah')), false);
  } finally {
    await store.close();
  }

  // Part 2: maxBytes eviction of closed segments (and closing active segment when needed).
  const capRoot = join(env.parent, 'cap-data');
  const capStore = await SegmentStore.open({
    root: capRoot,
    keyProvider: env.keyProvider,
    maxSegmentBytes: 2048,
    maxBytes: 5000,
    clock: () => now,
  });

  try {
    for (let seq = 1; seq <= 12; seq++) {
      now += 100;
      await capStore.append(makeTextObservation(seq, 'B'.repeat(700), now));
      assert.ok(capStore.status().bytes <= 5000);
    }
    assert.equal((await readdir(capRoot)).includes('seg-00000001.cah'), false);
    assert.equal(await capStore.read('inst-1:1'), null);
    assert.ok(await capStore.read('inst-1:12'));
  } finally {
    await capStore.close();
  }
});

test('SegmentStore heals torn trailing frames at EOF on open() and rejects middle-frame or earlier-segment tampering', async (t) => {
  const env = await createTempEnv(t);

  // Case 1: Torn partial length prefix (2 trailing bytes) at EOF.
  let store = await SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME });
  await store.append(makeTextObservation(1, 'record-one', BASE_TIME + 1));
  await store.append(makeTextObservation(2, 'record-two', BASE_TIME + 2));
  await store.append(makeTextObservation(3, 'record-three', BASE_TIME + 3));
  await store.close();

  const seg1Path = join(env.root, 'seg-00000001.cah');
  const cleanSize3 = (await lstat(seg1Path)).size;
  await appendFile(seg1Path, Buffer.from([0x00, 0x99]));

  store = await SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME + 10 });
  assert.equal(store.status().records, 3);
  assert.equal((await lstat(seg1Path)).size, cleanSize3);
  await store.close();

  // Case 2: Torn incomplete frame body at EOF (missing last 9 bytes of record 3).
  await truncate(seg1Path, cleanSize3 - 9);
  store = await SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME + 20 });
  assert.equal(store.status().records, 2);
  assert.ok(await store.read('inst-1:1'));
  assert.ok(await store.read('inst-1:2'));
  assert.equal(await store.read('inst-1:3'), null);
  // Appending a new frame after crash recovery uses the healed offset and frameIndex cleanly.
  await store.append(makeTextObservation(4, 'record-four-after-heal', BASE_TIME + 25));
  assert.equal(store.status().records, 3);
  await store.close();

  // Case 3: Corrupted GCM tag on final frame at exact EOF heals back to previous valid frame.
  const bytesWith4 = Buffer.from(await readFile(seg1Path));
  bytesWith4[bytesWith4.length - 1] = (bytesWith4[bytesWith4.length - 1] ?? 0) ^ 0xff;
  await writeFile(seg1Path, bytesWith4, { mode: 0o600 });

  store = await SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME + 30 });
  assert.equal(store.status().records, 2);
  assert.equal(await store.read('inst-1:4'), null);
  await store.close();

  // Case 4: Middle-frame tampering MUST fail closed with invalid-store (never silently truncate).
  const intactTwoFrames = Buffer.from(await readFile(seg1Path));
  const middleTampered = Buffer.from(intactTwoFrames);
  // Offset 48 lies inside frame 0 while frame 1 follows it.
  middleTampered[48] = (middleTampered[48] ?? 0) ^ 0x01;
  await writeFile(seg1Path, middleTampered, { mode: 0o600 });

  await assert.rejects(
    SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME + 40 }),
    expectCode('invalid-store'),
  );

  // Restore intact 2 frames, force a second segment, then tamper with final byte of sealed seg-00000001.cah.
  await writeFile(seg1Path, intactTwoFrames, { mode: 0o600 });
  store = await SegmentStore.open({
    root: env.root,
    keyProvider: env.keyProvider,
    maxSegmentBytes: intactTwoFrames.length + 10,
    clock: () => BASE_TIME + 50,
  });
  await store.append(makeTextObservation(5, 'triggers-roll-to-seg2', BASE_TIME + 51));
  await store.append(makeTextObservation(6, 'lives-in-seg2', BASE_TIME + 52));
  assert.equal(store.status().segments, 2);
  await store.close();

  const seg1Sealed = Buffer.from(await readFile(seg1Path));
  seg1Sealed[seg1Sealed.length - 1] = (seg1Sealed[seg1Sealed.length - 1] ?? 0) ^ 0xff;
  await writeFile(seg1Path, seg1Sealed, { mode: 0o600 });

  await assert.rejects(
    SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME + 60 }),
    expectCode('invalid-store'),
  );
});

test('SegmentStore AAD prevents frame reordering and cross-store segment transplanting', async (t) => {
  const env = await createTempEnv(t);
  const storeA = await SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME });
  await storeA.append(makeTextObservation(1, 'frame-zero', BASE_TIME + 1));
  await storeA.append(makeTextObservation(2, 'frame-one', BASE_TIME + 2));
  await storeA.close();

  const segPath = join(env.root, 'seg-00000001.cah');
  const raw = await readFile(segPath);
  const header = raw.subarray(0, 32);
  const f0Len = 4 + raw.readUInt32BE(32);
  const frame0 = raw.subarray(32, 32 + f0Len);
  const frame1 = raw.subarray(32 + f0Len);

  // Swap frame0 and frame1: AAD frameIndex (0 vs 1) causes immediate authentication failure on frame 0.
  await writeFile(segPath, Buffer.concat([header, frame1, frame0]), { mode: 0o600 });
  await assert.rejects(
    SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME }),
    expectCode('invalid-store'),
  );

  // Restore valid segment and attempt to copy it into storeB sharing the same master key (different storeId).
  await writeFile(segPath, raw, { mode: 0o600 });
  const rootB = join(env.parent, 'store-b');
  const storeB = await SegmentStore.open({ root: rootB, keyProvider: env.keyProvider, clock: () => BASE_TIME });
  await storeB.append(makeTextObservation(1, 'other-store-1', BASE_TIME + 1));
  await storeB.append(makeTextObservation(2, 'other-store-2', BASE_TIME + 2));
  await storeB.close();

  await copyFile(segPath, join(rootB, 'seg-00000001.cah'));
  await assert.rejects(
    SegmentStore.open({ root: rootB, keyProvider: env.keyProvider, clock: () => BASE_TIME }),
    expectCode('invalid-store'),
  );
});

test('SegmentStore supports text.changed materialization, HMAC search cursors, read by eventId/snapshotId, layout, and forget', async (t) => {
  const env = await createTempEnv(t);
  let now = BASE_TIME;
  const store = await SegmentStore.open({
    root: env.root,
    keyProvider: env.keyProvider,
    maxSegmentBytes: 4096,
    clock: () => now,
  });

  try {
    // 1. Baseline + text.changed materialization.
    await store.append(makeTextObservation(1, 'alpha initial', now + 10));
    const delta: Observation = {
      ...makeTextObservation(2, '', now + 20),
      payload: {
        kind: 'text.changed',
        baseSnapshotId: 'snap-1',
        after: {
          kind: 'text.snapshot',
          snapshotId: 'snap-2',
          editSessionId: 'edit-1',
          nodeId: 'node-1',
          source: 'fixture',
          scope: 'field',
          valueState: 'read',
          text: 'alpha updated 中文',
          range: { unit: 'utf16', start: 0, length: 'alpha updated 中文'.length },
          totalLength: 'alpha updated 中文'.length,
          composition: 'unknown',
          captureStartMs: now + 20,
          captureEndMs: now + 20,
          coverage: { status: 'complete', truncated: false, missingReasons: [] },
        },
      },
    };
    await store.append(delta);

    // Read by both eventId and snapshotId returns materialized text.snapshot.
    const byEvent = await store.read('inst-1:2');
    const bySnap = await store.read('snap-2');
    assert.equal(byEvent?.payload.kind, 'text.snapshot');
    assert.deepEqual(bySnap, byEvent);

    // 2. Surface snapshot & layout projection with pagination cursor.
    const surfaceObs = makeSurfaceObservation(
      3,
      [
        {
          id: 'n1',
          role: 'text',
          axRole: 'AXStaticText',
          text: 'Header message in window',
          bounds: { x: 10, y: 20, width: 300, height: 40 },
          boundsObservedAtMs: now + 30,
          observedAtMs: now + 30,
          focused: false,
        },
        {
          id: 'n2',
          role: 'editable',
          axRole: 'AXTextArea',
          text: 'Composer text body for layout slicing',
          bounds: { x: 10, y: 500, width: 600, height: 80 },
          boundsObservedAtMs: now + 30,
          observedAtMs: now + 30,
          focused: true,
        },
      ],
      now + 30,
      'surface-snap-3',
    );
    await store.append(surfaceObs);
    assert.equal((await store.read('surface-snap-3'))?.eventId, 'inst-1:3');

    const layoutPage1 = await store.layout({ snapshotId: 'surface-snap-3', maxNodes: 1 });
    assert.equal(layoutPage1.found, true);
    if (layoutPage1.found) {
      assert.equal(layoutPage1.nodes.length, 1);
      assert.equal(layoutPage1.hasMore, true);
      assert.ok(layoutPage1.nextCursor);

      // Modifying filter with existing cursor must reject with invalid-cursor.
      await assert.rejects(
        store.layout({ snapshotId: 'surface-snap-3', maxNodes: 2, cursor: layoutPage1.nextCursor }),
        expectCode('invalid-cursor'),
      );

      const layoutPage2 = await store.layout({
        snapshotId: 'surface-snap-3',
        maxNodes: 1,
        cursor: layoutPage1.nextCursor,
      });
      assert.equal(layoutPage2.found, true);
      if (layoutPage2.found) {
        assert.equal(layoutPage2.nodes[0]?.id, 'n2');
        assert.equal(layoutPage2.hasMore, false);
      }
    }

    // 3. Search with HMAC-bound pagination cursors.
    for (let seq = 4; seq <= 8; seq++) {
      await store.append(makeTextObservation(seq, `batch-item-${seq}`, now + seq * 10));
    }

    const page1 = await store.search({ kind: 'text', limit: 3, order: 'desc' });
    assert.equal(page1.records.length, 3);
    assert.equal(page1.hasMore, true);
    assert.ok(page1.nextCursor);
    assert.equal(page1.records[0]?.eventId, 'inst-1:8');

    // Forged or mismatched-filter cursor rejects with invalid-cursor.
    await assert.rejects(
      store.search({ kind: 'text', limit: 3, order: 'asc', cursor: page1.nextCursor }),
      expectCode('invalid-cursor'),
    );
    await assert.rejects(
      store.search({ kind: 'text', limit: 3, order: 'desc', cursor: 'A'.repeat(43) }),
      expectCode('invalid-cursor'),
    );

    const page2 = await store.search({ kind: 'text', limit: 3, order: 'desc', cursor: page1.nextCursor });
    assert.equal(page2.records.length, 3);
    assert.equal(page2.records[0]?.eventId, 'inst-1:5');

    // 4. Partial forget({ beforeMs }) persists forgetBeforeMs in store.meta and invalidates cursors.
    const cutoff = now + 50;
    const partialForget = await store.forget({ beforeMs: cutoff });
    assert.equal(partialForget.forgetBeforeMs, cutoff);
    assert.equal(partialForget.remainingRecords, 4); // seq 5, 6, 7, 8

    await assert.rejects(
      store.search({ kind: 'text', limit: 3, order: 'desc', cursor: page1.nextCursor }),
      expectCode('cursor-expired'),
    );
    assert.equal(await store.read('inst-1:1'), null);
    assert.ok(await store.read('inst-1:5'));
  } finally {
    await store.close();
  }

  // Reopen and verify partial forget cutoff persisted via store.meta, then test forget({ all: true }).
  const reopened = await SegmentStore.open({
    root: env.root,
    keyProvider: env.keyProvider,
    clock: () => now + 100,
  });
  try {
    assert.equal(reopened.status().records, 4);
    assert.equal(await reopened.read('inst-1:2'), null);

    const prevStoreId = reopened.storeId;
    const prevGen = reopened.generation;
    const wiped = await reopened.forget({ all: true });
    assert.ok(wiped.deletedSegments >= 1);
    assert.equal(wiped.remainingRecords, 0);
    assert.equal(wiped.generation, prevGen + 1);
    assert.notEqual(reopened.storeId, prevStoreId);
    assert.equal((await readdir(env.root)).some((f) => f.endsWith('.cah')), false);

    // Fresh writes succeed cleanly after forget({ all: true }).
    await reopened.append(makeTextObservation(1, 'fresh-epoch-record', now + 200));
    assert.equal(reopened.status().records, 1);
    assert.equal(reopened.status().segments, 1);
  } finally {
    await reopened.close();
  }
});

test('SegmentStore rejects insecure permissions and symlinked segment/meta files on POSIX', { skip: process.platform === 'win32' }, async (t) => {
  const env = await createTempEnv(t);
  const store = await SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME });
  await store.append(makeTextObservation(1));
  await store.close();

  await chmod(join(env.root, 'seg-00000001.cah'), 0o644);
  await assert.rejects(
    SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME }),
    expectCode('unsafe-permissions'),
  );
  await chmod(join(env.root, 'seg-00000001.cah'), 0o600);

  const outside = join(env.parent, 'outside.cah');
  await writeFile(outside, 'fake', { mode: 0o600 });
  await symlink(outside, join(env.root, 'seg-00000002.cah'));
  await assert.rejects(
    SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME }),
    expectCode('unsafe-path'),
  );
});

test('SegmentStore enforces generation fences, ambiguous snapshot rejection, and partial tail header recovery', async (t) => {
  const env = await createTempEnv(t);
  let store = await SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME });
  try {
    const oldGen = store.generation;
    // Two surface snapshots sharing the same snapshotId trigger snapshot-ambiguous on read/layout by snapshotId.
    await store.append(
      makeSurfaceObservation(
        1,
        [{ id: 'n1', role: 'text', text: 'first', observedAtMs: BASE_TIME + 1 }],
        BASE_TIME + 1,
        'dup-surface-id',
      ),
    );
    await store.append(
      makeSurfaceObservation(
        2,
        [{ id: 'n2', role: 'text', text: 'second', observedAtMs: BASE_TIME + 2 }],
        BASE_TIME + 2,
        'dup-surface-id',
      ),
    );

    await assert.rejects(store.read('dup-surface-id'), expectCode('snapshot-ambiguous'));
    await assert.rejects(store.layout({ snapshotId: 'dup-surface-id' }), expectCode('snapshot-ambiguous'));
    // Exact eventId lookup remains unambiguous.
    assert.equal((await store.read('inst-1:1'))?.eventId, 'inst-1:1');

    await store.forget({ beforeMs: BASE_TIME });
    await assert.rejects(
      store.append(makeTextObservation(3, 'stale-write', BASE_TIME + 3), { generation: oldGen }),
      expectCode('stale-generation'),
    );
  } finally {
    await store.close();
  }

  // Simulate crash mid-roll where seg-00000002.cah was created with only 10 header bytes.
  await writeFile(join(env.root, 'seg-00000002.cah'), Buffer.from('CAHS\x01\x00\x00\x00\x00\x00'), { mode: 0o600 });
  store = await SegmentStore.open({ root: env.root, keyProvider: env.keyProvider, clock: () => BASE_TIME + 50 });
  try {
    assert.equal(store.status().records, 2);
    assert.equal(store.status().segments, 1);
    assert.equal((await readdir(env.root)).includes('seg-00000002.cah'), false);
  } finally {
    await store.close();
  }
});

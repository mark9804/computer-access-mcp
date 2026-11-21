import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import test from 'node:test';
import type { HistoryQuery, HistoryQueryResult } from '../../src/shared/api-types.ts';
import type { Observation } from '../../src/shared/protocol/generated.ts';
import { SegmentStore } from '../../src/storage/segment-store.ts';
import { APP, code, NOW, observation, SECRET, temporary } from './history-store-fixtures.ts';

function bounded(page: HistoryQueryResult, budget = 64 * 1024): void {
  assert.equal(page.bytes, Buffer.byteLength(JSON.stringify(page)));
  assert.ok(page.bytes <= budget);
  assert.equal(page.hasMore, page.nextCursor !== undefined);
  if (page.nextCursor) {
    assert.match(page.nextCursor, /^[A-Za-z0-9_-]{43}$/);
    for (const value of [SECRET, APP, 'synthetic-private-window', '中文', '/Users']) {
      assert.ok(!page.nextCursor.includes(value));
    }
  }
}

async function append(store: SegmentStore, records: Observation[]): Promise<void> {
  for (const record of records) await store.append(record, { generation: store.generation });
}

async function pages(store: SegmentStore, options: HistoryQuery): Promise<HistoryQueryResult[]> {
  const results: HistoryQueryResult[] = [];
  const tokens = new Set<string>();
  let cursor: string | undefined;
  do {
    const page = await store.search({ ...options, ...(cursor === undefined ? {} : { cursor }) });
    bounded(page, options.maxBytes);
    results.push(page);
    cursor = page.nextCursor;
    if (cursor) {
      assert.ok(!tokens.has(cursor));
      tokens.add(cursor);
    }
    assert.ok(results.length <= 20, 'pagination must terminate');
  } while (cursor !== undefined);
  return results;
}

test('pagination asc/desc uses stable append ties, fixes high water and returns only detached records', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  try {
    const input = [
      observation(1, '中文甲', NOW + 20),
      observation(2, '中文乙', NOW + 10),
      observation(3, '中文丙', NOW + 10),
      observation(4, '中文丁', NOW + 30),
    ];
    await append(store, input);
    const asc = await store.search({ limit: 1 });
    const desc = await store.search({ limit: 1, order: 'desc' });
    bounded(asc);
    bounded(desc);
    assert.deepEqual(asc.records, [input[1]]);
    assert.deepEqual(desc.records, [input[3]]);
    await append(store, [
      observation(5, '晚到早事件', NOW),
      observation(6, '晚到同事件', NOW + 10),
      observation(7, '晚到未来', NOW + 40),
    ]);
    const ascRest = await pages(store, { limit: 1, cursor: asc.nextCursor! });
    const descRest = await pages(store, { limit: 1, order: 'desc', cursor: desc.nextCursor! });
    assert.deepEqual(
      ascRest.flatMap((page) => page.records).map((record) => record.seq),
      [3, 1, 4],
    );
    assert.deepEqual(
      descRest.flatMap((page) => page.records).map((record) => record.seq),
      [1, 3, 2],
    );
    asc.records[0]!.eventId = 'caller mutation';
    const replay = await store.search({ limit: 1, cursor: asc.nextCursor! });
    assert.equal(replay.records[0]!.seq, 3);
    assert.deepEqual(await store.read(input[1]!.eventId), input[1]);
    assert.deepEqual(
      (await store.search()).records.map((record) => record.seq),
      [5, 2, 3, 6, 1, 4, 7],
    );
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('Chinese and kind filters respect application and time scope across pages', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  try {
    const input = [
      observation(1, '共同中文甲', NOW),
      observation(2, '', NOW + 1),
      observation(3, '共同中文乙', NOW + 2),
      observation(4, '', NOW + 3),
      observation(5, 'other', NOW + 4),
    ];
    input[1]!.payload = { kind: 'context.changed', reason: 'focus' };
    input[3]!.payload = { kind: 'gap', reason: 'policy-boundary', count: 1 };
    if (input[4]!.target.kind === 'resolved') input[4]!.target.identity.applicationId = 'synthetic.other';
    await append(store, input);
    const texts = await pages(store, {
      kind: 'text',
      text: '共同中文',
      applicationId: APP,
      fromTimeMs: NOW,
      toTimeMs: NOW + 3,
      limit: 1,
    });
    assert.deepEqual(
      texts.flatMap((page) => page.records).map((record) => record.seq),
      [1, 3],
    );
    assert.deepEqual(
      (await store.search({ kind: 'context' })).records.map((record) => record.seq),
      [2],
    );
    assert.deepEqual(
      (await store.search({ kind: 'gap' })).records.map((record) => record.seq),
      [4],
    );
    assert.deepEqual(
      (await store.search({ kind: 'all' })).records.map((record) => record.seq),
      [1, 2, 3, 4, 5],
    );
    for (const kind of ['all', 'text', 'gap', 'context'] as const) {
      const absent = await store.search({ kind, text: '没有匹配', applicationId: APP });
      assert.deepEqual(absent.records, []);
      bounded(absent);
    }
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('cursor binds normalized query and budgets, rejects tampering/cross-instance without filesystem persistence', async () => {
  const temp = await temporary();
  const other = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 10 });
  const foreign = await SegmentStore.open({ root: other.root, keyProvider: other.provider, clock: () => NOW + 10 });
  try {
    await append(store, [observation(1), observation(2), observation(3)]);
    const query: HistoryQuery = {
      applicationId: APP,
      text: '中文',
      fromTimeMs: NOW,
      toTimeMs: NOW + 10,
      kind: 'text',
      order: 'asc',
      limit: 1,
      maxBytes: 5000,
    };
    const before = await readdir(temp.root);
    const first = await store.search(query);
    bounded(first, 5000);
    const cursor = first.nextCursor!;
    const changes: HistoryQuery[] = [
      { applicationId: 'other' },
      { text: '秘密' },
      { fromTimeMs: NOW - 1 },
      { toTimeMs: NOW + 11 },
      { kind: 'all' },
      { order: 'desc' },
      { limit: 2 },
      { maxBytes: 5001 },
    ];
    for (const changed of changes) {
      await assert.rejects(store.search({ ...query, ...changed, cursor }), code('invalid-cursor'));
    }
    const altered = `${cursor[0] === 'A' ? 'B' : 'A'}${cursor.slice(1)}`;
    for (const value of [altered, '', 'a'.repeat(129), 'not-a-token', '中文', 'x'.repeat(43)]) {
      await assert.rejects(store.search({ ...query, cursor: value }), code('invalid-cursor'));
    }
    await assert.rejects(foreign.search({ ...query, cursor }), code('invalid-cursor'));
    const resumed = await store.search({ ...query, cursor });
    assert.equal(resumed.records[0]!.seq, 2);
    assert.deepEqual(await readdir(temp.root), before);
    const defaults = await store.search({ limit: 1 });
    assert.equal(
      (await store.search({ kind: 'all', order: 'asc', limit: 1, maxBytes: 65536, cursor: defaults.nextCursor! }))
        .records[0]!.seq,
      2,
    );
    assert.equal(store.status().state, 'open');
  } finally {
    await store.close();
    await foreign.close();
    await temp.cleanup();
    await other.cleanup();
  }
});

test('Forget synchronously fences cursors and queued pages; close/reopen cannot resurrect cursor bodies', async () => {
  const temp = await temporary();
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 10 });
  try {
    await append(store, [observation(1), observation(2), observation(3)]);
    const first = await store.search({ limit: 1 });
    const pending = assert.rejects(store.search({ limit: 1, cursor: first.nextCursor! }), code('cursor-expired'));
    const forgotten = store.forget({ all: true });
    await assert.rejects(store.search({ limit: 1, cursor: first.nextCursor! }), code('cursor-expired'));
    await pending;
    await forgotten;
    assert.equal(await store.read('synthetic-instance:2'), null);
    assert.deepEqual((await store.search()).records, []);
    await append(store, [observation(4), observation(5)]);
    const fresh = await store.search({ limit: 1 });
    const queued = assert.rejects(store.search({ limit: 1, cursor: fresh.nextCursor! }), code('cursor-expired'));
    await store.close();
    await queued;
    await assert.rejects(store.search({ limit: 1, cursor: fresh.nextCursor! }), code('invalid-cursor'));
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 10 });
    await assert.rejects(store.search({ limit: 1, cursor: fresh.nextCursor! }), code('invalid-cursor'));
    assert.deepEqual(
      (await store.search()).records.map((record) => record.seq),
      [4, 5],
    );
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('TTL pruning and segment eviction invalidate paging without raising append generation', async () => {
  for (const removal of ['ttl', 'eviction', 'partial-forget', 'empty-forget'] as const) {
    const temp = await temporary();
    let now = NOW;
    const store = await SegmentStore.open({
      root: temp.root,
      keyProvider: temp.provider,
      clock: () => now,
      retentionMs: 1000,
      maxSegmentBytes: 1024,
      maxBytes: removal === 'eviction' ? 2800 : 128 * 1024 * 1024,
    });
    try {
      await append(store, [observation(1, 'old', NOW - 900), observation(2, 'new', NOW), observation(3, 'newest', NOW)]);
      const first = await store.search({ limit: 1 });
      const generation = store.generation;
      if (removal === 'ttl') now += 101;
      else if (removal === 'eviction') await append(store, [observation(4, 'x'.repeat(300), NOW)]);
      else await store.forget({ beforeMs: removal === 'partial-forget' ? NOW : 0 });
      await assert.rejects(store.search({ limit: 1, cursor: first.nextCursor! }), code('cursor-expired'));
      if (removal === 'ttl' || removal === 'eviction') assert.equal(store.generation, generation);
      if (removal !== 'empty-forget') assert.equal(await store.read('synthetic-instance:1'), null);
      assert.equal(store.status().state, 'open');
    } finally {
      await store.close();
      await temp.cleanup();
    }
  }
});

test('cursor cache caps at 256 and has a fixed five-minute chain lifetime, not sliding on reuse', async () => {
  const temp = await temporary();
  let now = NOW;
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => now });
  try {
    await append(store, [observation(1), observation(2), observation(3), observation(4)]);
    const cursors: string[] = [];
    for (let index = 0; index < 257; index++) {
      cursors.push((await store.search({ limit: 1 })).nextCursor!);
    }
    assert.equal(new Set(cursors).size, 257);
    await assert.rejects(store.search({ limit: 1, cursor: cursors[0]! }), code('invalid-cursor'));
    let continued: string | undefined;
    for (const cursor of cursors.slice(1)) {
      const next = await store.search({ limit: 1, cursor });
      assert.equal(next.records[0]!.seq, 2);
      bounded(next);
      continued = next.nextCursor;
    }
    now += 5 * 60 * 1000 - 1;
    const nearExpiry = await store.search({ limit: 1, cursor: continued! });
    bounded(nearExpiry);
    assert.equal(nearExpiry.records[0]!.seq, 3);
    now++;
    await assert.rejects(store.search({ limit: 1, cursor: nearExpiry.nextCursor! }), code('cursor-expired'));
    await assert.rejects(store.search({ limit: 1, cursor: continued! }), code('cursor-expired'));
    const fresh = await store.search({ limit: 1 });
    assert.equal(fresh.records[0]!.seq, 1);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('full UTF-8 byte budget includes metadata/token; oversized/zero-limit pages cannot loop', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  try {
    const partial = observation(1, '中文𠮷'.repeat(15));
    if (partial.payload.kind === 'text.snapshot') {
      partial.payload.coverage = { status: 'partial', truncated: true, missingReasons: ['budget-exceeded'] };
    }
    await append(store, [partial, observation(2, 'b'), observation(3, '字'.repeat(3000)), observation(4, 'tail')]);
    const first = await store.search({ limit: 1 });
    bounded(first);
    assert.ok(first.truncated);
    for (const maxBytes of [512, 513, 999, 1000, first.bytes - 1, first.bytes, first.bytes + 1, 2000, 4096, 10000, 262144]) {
      const result = await pages(store, { maxBytes });
      for (const page of result) bounded(page, maxBytes);
      const ids = result.flatMap((page) => page.records).map((record) => record.seq);
      assert.equal(new Set(ids).size, ids.length);
      assert.deepEqual(ids, [1, 2, 3, 4].slice(0, ids.length));
    }
    const exact = await store.search({ limit: 1, maxBytes: first.bytes });
    assert.equal(exact.records.length, 1);
    assert.ok(exact.hasMore);
    bounded(exact, first.bytes);
    const oneLess = await store.search({ limit: 1, maxBytes: first.bytes - 1 });
    assert.deepEqual(oneLess.records, []);
    assert.equal(oneLess.truncated, true);
    assert.equal(oneLess.nextCursor, undefined);
    const blocked = await pages(store, { maxBytes: 4096 });
    assert.deepEqual(
      blocked.flatMap((page) => page.records).map((record) => record.seq),
      [1, 2],
    );
    const end = blocked.at(-1)!;
    assert.ok(end.truncated);
    assert.equal(end.hasMore, false);
    const zero = await store.search({ limit: 0, maxBytes: 512 });
    bounded(zero, 512);
    assert.deepEqual(zero.records, []);
    assert.equal(zero.truncated, true);
    assert.equal(zero.hasMore, false);
    assert.equal(zero.nextCursor, undefined);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('search query validation rejects unknown fields, bad types and snapshots mutable query objects', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
  try {
    for (const query of [
      { kind: 'wat' },
      { order: 'wat' },
      { cursor: 1 },
      { kind: null },
      { order: null },
      { cursor: null },
    ]) {
      await assert.rejects(
        store.search(query as unknown as HistoryQuery),
        code('cursor' in query ? 'invalid-cursor' : 'invalid-input'),
      );
    }
    await assert.rejects(store.search({ unknown: true } as unknown as HistoryQuery), code('invalid-input'));
    await append(store, [observation(1), observation(2)]);
    const mutable: HistoryQuery = { limit: 1, kind: 'text' };
    const pending = store.search(mutable);
    mutable.limit = 0;
    mutable.kind = 'gap';
    const first = await pending;
    assert.equal(first.records.length, 1);
    const resumed = await store.search({ limit: 1, kind: 'text', cursor: first.nextCursor! });
    assert.equal(resumed.records[0]!.seq, 2);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

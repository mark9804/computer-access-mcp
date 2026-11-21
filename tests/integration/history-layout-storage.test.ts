import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { SegmentStore } from '../../src/storage/segment-store.ts';
import type { Observation, SurfaceSnapshot } from '../../src/shared/protocol/generated.ts';
import type { HistoryLayoutPage } from '../../src/shared/history-layout.ts';
import { APP, code, NOW, observation, temporary } from './history-store-fixtures.ts';

function surface(
  seq = 1,
  time = NOW,
  text = '合成布局𠮷',
  snapshotId = `layout-snapshot-${seq}`,
): Observation & { payload: SurfaceSnapshot } {
  const record = observation(seq, '', time);
  return {
    ...record,
    payload: {
      kind: 'surface.snapshot',
      snapshotId,
      surfaceId: 'layout-surface',
      revision: seq,
      source: 'ax.tree',
      scope: 'window',
      mode: 'full',
      captureStartMs: time,
      captureEndMs: time,
      geometry: { coordinateSpace: 'window-top-left-point', windowSize: { width: 900, height: 600 }, observedAtMs: time },
      nodes: [
        { id: 'root', role: 'container', observedAtMs: time },
        {
          id: 'a',
          parentId: 'root',
          role: 'text',
          axRole: 'AXStaticText',
          text,
          observedAtMs: time,
          bounds: { x: -1.5, y: 20, width: 200, height: 30 },
          boundsObservedAtMs: time,
          focused: false,
        },
        {
          id: 'b',
          parentId: 'root',
          role: 'editable',
          axRole: 'AXTextArea',
          text: '',
          observedAtMs: time,
          focused: true,
          bounds: { x: 20, y: 500, width: 800, height: 40 },
          boundsObservedAtMs: time,
        },
      ],
      gate: { secure: 'safe', privateState: 'normal', policyRevision: 1 },
      coverage: { status: 'partial', missingReasons: ['bounded-surface'], truncated: false },
      consistency: 'non-atomic',
    },
  };
}

function page(value: Awaited<ReturnType<SegmentStore['layout']>>): HistoryLayoutPage {
  assert.equal(value.found, true);
  if (!value.found) throw Error('fixture');
  return value;
}

test('JSON layout geometry and text survive encrypted reopen without materializing older content', async () => {
  const temp = await temporary();
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
  const record = surface();
  try {
    await store.append(record, { generation: store.generation });
    const first = page(await store.layout({ eventId: record.eventId }));
    assert.deepEqual(
      first.nodes.map((n) => n.id),
      ['a', 'b'],
    );
    assert.deepEqual(first.nodes[0]!.bounds, [-1.5, 20, 200, 30]);
    assert.equal(first.nodes[1]!.text, '');
    assert.equal(first.snapshotFocusedNodeId, 'b');
    assert.equal(first.sourceCoverage.status, 'partial');
    assert.equal(first.hasMore, false);
    for (const name of await readdir(temp.root)) {
      const bytes = await readFile(join(temp.root, name));
      for (const secret of ['合成布局', APP, 'window-top-left-point', 'layout-surface']) {
        assert.equal(bytes.includes(Buffer.from(secret)), false);
      }
    }
    await store.close();
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
    assert.deepEqual(page(await store.layout({ snapshotId: record.payload.snapshotId })), first);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('layout continuation is fixed to one record and preserves every UTF16 text segment', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
  try {
    const record = surface(1, NOW, 'A𠮷中文B𠮷尾');
    await store.append(record, { generation: store.generation });
    const request = { eventId: record.eventId, maxNodes: 1, maxChars: 3 };
    let result = page(await store.layout(request));
    const firstCursor = result.nextCursor;
    const chunks = [...result.nodes];
    assert.ok(firstCursor);
    assert.equal(firstCursor.length, 43);
    assert.equal(firstCursor.includes('synthetic'), false);
    await store.append(surface(2, NOW, 'newer-unrelated'), { generation: store.generation });
    for (let i = 0; result.hasMore && i < 20; i++) {
      result = page(await store.layout({ ...request, cursor: result.nextCursor! }));
      chunks.push(...result.nodes);
    }
    assert.equal(result.hasMore, false);
    assert.equal(
      chunks
        .filter((n) => n.id === 'a')
        .map((n) => n.text)
        .join(''),
      record.payload.nodes[1]!.text,
    );
    assert.equal(chunks.at(-1)!.id, 'b');
    for (const n of chunks) assert.ok(n.text === null || n.text.isWellFormed());
    await assert.rejects(store.layout({ ...request, maxChars: 4, cursor: firstCursor }), code('invalid-cursor'));
    await assert.rejects(
      store.layout({ eventId: 'synthetic-instance:2', maxNodes: 1, maxChars: 3, cursor: firstCursor }),
      code('invalid-cursor'),
    );
    await assert.rejects(store.search({ kind: 'surface', cursor: firstCursor }), code('invalid-cursor'));
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('cursorScope isolates search and layout across readers', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
  try {
    const record = surface(1, NOW, 'A𠮷中文B𠮷尾');
    await store.append(record, { generation: store.generation });
    await store.append(surface(2, NOW, 'synthetic second'), { generation: store.generation });
    const query = { kind: 'surface', limit: 1 } as const;
    const layout = { eventId: record.eventId, maxNodes: 1, maxChars: 3 };
    const cursor = (await store.search(query, 'owned-lease-caller')).nextCursor;
    const layoutCursor = page(await store.layout(layout, 'owned-lease-caller')).nextCursor;
    assert.ok(cursor);
    assert.ok(layoutCursor);
    for (const scope of [undefined, 'another-reader', 'regranted-reader']) {
      await assert.rejects(store.search({ ...query, cursor }, scope), code('invalid-cursor'));
      await assert.rejects(store.layout({ ...layout, cursor: layoutCursor }, scope), code('invalid-cursor'));
    }
    assert.equal((await store.search({ ...query, cursor }, 'owned-lease-caller')).records[0]?.eventId, 'synthetic-instance:2');
    assert.ok(page(await store.layout({ ...layout, cursor: layoutCursor }, 'owned-lease-caller')).nodes.length > 0);
    await assert.rejects(store.search({ ...query, cursorScope: 'from-wire' } as never), code('invalid-input'));
    await assert.rejects(store.layout({ ...layout, cursorScope: 'from-wire' } as never), code('invalid-layout-query'));
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

for (const action of ['forget', 'ttl', 'cursor-timeout', 'reload'] as const) {
  test(`layout cursor invalidates after ${action}`, async () => {
    const temp = await temporary();
    let now = NOW;
    let store = await SegmentStore.open({
      root: temp.root,
      keyProvider: temp.provider,
      clock: () => now,
      retentionMs: 1_000_000,
    });
    try {
      const record = surface();
      await store.append(record, { generation: store.generation });
      const request = { eventId: record.eventId, maxChars: 2 };
      const first = page(await store.layout(request));
      assert.ok(first.nextCursor);
      if (action === 'forget') await store.forget({ all: true });
      if (action === 'ttl') now += 1_000_001;
      if (action === 'cursor-timeout') now += 300_001;
      if (action === 'reload') {
        await store.close();
        store = await SegmentStore.open({
          root: temp.root,
          keyProvider: temp.provider,
          clock: () => now,
          retentionMs: 1_000_000,
        });
      }
      await assert.rejects(
        store.layout({ ...request, cursor: first.nextCursor }),
        code(action === 'reload' ? 'invalid-cursor' : 'cursor-expired'),
      );
      if (action === 'forget' || action === 'ttl') {
        assert.equal((await store.layout({ eventId: record.eventId })).found, false);
      }
    } finally {
      await store.close();
      await temp.cleanup();
    }
  });
}

test('layout pagination keeps its original expiry and invalidates on unrelated segment eviction', async () => {
  const temp = await temporary();
  let now = NOW;
  const store = await SegmentStore.open({
    root: temp.root,
    keyProvider: temp.provider,
    clock: () => now,
    maxSegmentBytes: 600,
    maxBytes: 4200,
    retentionMs: 1_000_000,
  });
  try {
    const record = surface(1, NOW, 'abcdefghijklmnop');
    await store.append(record, { generation: store.generation });
    const request = { eventId: record.eventId, maxChars: 2 };
    const first = page(await store.layout(request));
    assert.ok(first.nextCursor);
    now += 299_999;
    const second = page(await store.layout({ ...request, cursor: first.nextCursor }));
    assert.ok(second.nextCursor);
    now += 2;
    await assert.rejects(store.layout({ ...request, cursor: second.nextCursor }), code('cursor-expired'));
    await store.append(surface(2, now, 'abcdefghijklmnop'), { generation: store.generation });
    const fresh = page(await store.layout({ eventId: 'synthetic-instance:2', maxChars: 2 }));
    assert.ok(fresh.nextCursor);
    await store.append(surface(3, now, 'x'.repeat(200)), { generation: store.generation });
    await assert.rejects(
      store.layout({ eventId: 'synthetic-instance:2', maxChars: 2, cursor: fresh.nextCursor }),
      code('cursor-expired'),
    );
    assert.equal((await store.layout({ eventId: 'synthetic-instance:2' })).found, true);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('geometry missing in old snapshots remains unknown, never borrowed from another event', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
  try {
    const old = surface();
    delete old.payload.geometry;
    for (const n of old.payload.nodes) {
      delete n.bounds;
      delete n.boundsObservedAtMs;
      delete n.focused;
      delete n.axRole;
    }
    await store.append(old, { generation: store.generation });
    await store.append(surface(2), { generation: store.generation });
    const result = page(await store.layout({ eventId: old.eventId }));
    assert.equal(result.coordinateSpace, null);
    assert.equal(result.windowSize, null);
    assert.equal(result.snapshotFocusedNodeId, null);
    assert.equal(result.nodes[0]!.bounds, null);
    assert.equal(result.nodes[0]!.roleSource, 'category');
    const spatial = page(await store.layout({ eventId: old.eventId, bounds: { x: 0, y: 0, width: 1000, height: 1000 } }));
    assert.equal(spatial.nodes.length, 0);
    assert.ok(spatial.projection.missingGeometryFilteredNodes > 0);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('selector never guesses latest/time and refuses ambiguous snapshot IDs', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
  try {
    await store.append(surface(1, NOW, 'first', 'duplicate-snapshot'), { generation: store.generation });
    await store.append(surface(2, NOW, 'second', 'duplicate-snapshot'), { generation: store.generation });
    await assert.rejects(store.layout({ snapshotId: 'duplicate-snapshot' }), code('snapshot-ambiguous'));
    assert.equal(page(await store.layout({ eventId: 'synthetic-instance:1' })).nodes[0]!.text, 'first');
    assert.equal(
      (await store.layout({ eventId: 'synthetic-instance:1', applicationId: 'not.the.application' })).found,
      false,
    );
    await store.append(observation(3), { generation: store.generation });
    const nonSurface = await store.layout({ eventId: 'synthetic-instance:3' });
    assert.equal(nonSurface.found, false);
    if (!nonSurface.found) assert.equal(nonSurface.reason, 'not-a-surface-snapshot');
    for (const bad of [
      {},
      { eventId: 'x', snapshotId: 'y' },
      { snapshotId: 'x', maxChars: NaN },
      { snapshotId: 'x', bounds: { x: 0, y: 0, width: -1, height: 2 } },
    ]) {
      await assert.rejects(store.layout(bad), code('invalid-layout-query'));
    }
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('bounded layout remains a valid <=65536-byte tool envelope even for escaped stored text', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
  try {
    const record = surface(1, NOW, '\u0001'.repeat(8192));
    await store.append(record, { generation: store.generation });
    const result = page(await store.layout({ eventId: record.eventId }));
    const envelope = {
      ok: true,
      operation: 'historyLayout',
      data: result,
      source: result.source,
      coverage: result.coverage,
      truncated: result.truncated,
      missingReasons: result.missingReasons,
      untrustedData: true,
    };
    assert.ok(Buffer.byteLength(JSON.stringify(envelope)) <= 65536);
    assert.equal(result.nodes[0]!.text!.length, 8192);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

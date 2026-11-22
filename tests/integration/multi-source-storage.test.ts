import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import type { Observation } from '../../src/shared/protocol/generated.ts';
import { EvidenceCorrelator } from '../../src/host/collectors/evidence-correlator.ts';
import { CollectorAdmission } from '../../src/host/collectors/admission.ts';
import { SegmentStore } from '../../src/storage/segment-store.ts';
import { APP, code, NOW, observation, temporary } from './history-store-fixtures.ts';

type Channel = 'surface' | 'selection' | 'input';
const BODY = 'SYNTHETIC-multi-source-中文-𠮷';

function evidence(kind: Channel, seq: number, time = NOW + seq, text = `${BODY}-${kind}`): Observation {
  const record = observation(seq, '', time);
  record.monotonicMs = seq * 10;
  const gate = { secure: 'safe', privateState: 'normal', policyRevision: record.stamp.policyRevision } as const;
  const capture = { captureStartMs: time, captureEndMs: time };
  const coverage = { status: 'partial', truncated: false, missingReasons: ['synthetic-partial'] } as const;
  if (kind === 'surface') {
    record.payload = {
      kind: 'surface.snapshot',
      snapshotId: `synthetic-surface-snapshot-${seq}`,
      surfaceId: 'synthetic-surface',
      revision: seq,
      source: 'ax.tree',
      scope: 'window',
      mode: 'full',
      nodes: [
        { id: 'root', role: 'container', observedAtMs: time },
        { id: 'body', parentId: 'root', role: 'text', text, observedAtMs: time },
      ],
      ...capture,
      coverage: { ...coverage, missingReasons: [...coverage.missingReasons] },
      gate,
      consistency: 'non-atomic',
    };
  } else if (kind === 'selection') {
    record.payload = {
      kind: 'selection.snapshot',
      snapshotId: `synthetic-selection-${seq}`,
      surfaceId: 'synthetic-surface',
      source: 'ax.marker',
      scope: 'selection',
      text,
      range: { unit: 'utf16', start: 7, length: text.length },
      ...capture,
      coverage: { status: 'partial', truncated: false, missingReasons: ['selection-only'] },
      gate,
    };
  } else {
    record.payload = {
      kind: 'input.text',
      source: 'cg.unicode',
      scope: 'field',
      eventKind: 'text',
      text,
      modifiers: [],
      intervalStartMs: time,
      intervalEndMs: time,
      eventCount: 1,
      surfaceId: 'synthetic-surface',
      gate,
      secureInput: 'inactive',
      coverage: { status: 'partial', truncated: false, missingReasons: ['input-events-partial', 'effect-unverified'] },
      effect: 'unverified',
    };
  }
  return record;
}

function related(record: Observation, ids: string[]): Observation {
  return { ...record, relation: { basis: 'temporal-same-surface', evidenceIds: ids, effect: 'unverified' } };
}

test('multi-source bodies persist encrypted with distinct filters, counts, sources and exact retention defaults', async () => {
  const temp = await temporary();
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  try {
    const records = [
      observation(1, `${BODY}-ax`),
      evidence('surface', 2),
      evidence('selection', 3),
      evidence('input', 4),
    ];
    for (const record of records) await store.append(record, { generation: store.generation });
    const status = store.status();
    assert.equal(status.records, 4);
    assert.equal(status.counts.text, 1);
    assert.equal(status.counts.surface, 1);
    assert.equal(status.counts.selection, 1);
    assert.equal(status.counts.inputText, 1);
    assert.equal(status.retentionMs, 14 * 24 * 60 * 60 * 1000);
    assert.equal(status.maxBytes, 16 * 1024 * 1024 * 1024);
    for (const [index, kind] of (['text', 'surface', 'selection', 'input'] as const).entries()) {
      const page = await store.search({ kind, text: BODY, applicationId: APP });
      assert.deepEqual(page.records, [records[index]]);
      assert.equal(page.bytes, Buffer.byteLength(JSON.stringify(page)));
    }
    assert.deepEqual((await store.search({ text: BODY })).records, records);
    assert.deepEqual((await store.search({ kind: 'text', text: '-input' })).records, []);
    assert.deepEqual((await store.search({ text: 'ax.tree' })).records, []);
    for (const name of await readdir(temp.root)) {
      const bytes = await readFile(join(temp.root, name));
      for (const text of [BODY, APP, 'synthetic-surface', 'cg.unicode', 'selection-only']) {
        assert.equal(bytes.includes(Buffer.from(text)), false);
      }
    }
    await store.close();
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
    assert.deepEqual((await store.search()).records, records);
    assert.equal(store.status().counts.surface, 1);
    assert.equal(store.status().counts.selection, 1);
    assert.equal(store.status().counts.inputText, 1);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('surface strategy reset keeps target identity while a new full revision persists without false removals', async () => {
  const temp = await temporary();
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  try {
    const before = evidence('surface', 1);
    const after = evidence('surface', 2);
    const input = evidence('input', 3);
    if (before.payload.kind !== 'surface.snapshot' || after.payload.kind !== 'surface.snapshot') throw Error('fixture');
    before.payload.revision = 17;
    after.payload.revision = 1;
    after.payload.nodes[0]!.id = 'new-root';
    after.payload.nodes[1]!.id = 'new-body';
    after.payload.nodes[1]!.parentId = 'new-root';
    const ack = {
      protocolVersion: 1,
      type: 'configured',
      requestId: 'strategy-reset',
      ownerId: 'synthetic-host',
      instanceId: before.instanceId,
      policyRevision: 1,
    } as const;
    const admission = new CollectorAdmission(ack, before.stamp, () => true);
    if (before.target.kind !== 'resolved') throw Error('fixture');
    admission.setBoundary(before.stamp, before.target.identity);
    assert.equal(admission.acknowledge(ack), true);
    for (const record of [before, after, input]) {
      assert.equal(admission.accept(record).accepted, true);
      await store.append(record, { generation: store.generation });
    }
    assert.equal(after.payload.mode, 'full');
    assert.equal(after.payload.baseRevision, undefined);
    assert.equal(after.payload.changes, undefined);
    assert.deepEqual(after.target, input.target);
    assert.equal(input.payload.kind, 'input.text');
    if (input.payload.kind !== 'input.text') throw Error('fixture');
    assert.equal(after.payload.surfaceId, input.payload.surfaceId);
    await store.close();
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
    assert.deepEqual((await store.search({ kind: 'surface' })).records, [before, after]);
    assert.deepEqual(await store.read(input.eventId), input);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('field denylist evidence retains its security gate declaration through encrypted reopen', async () => {
  const temp = await temporary();
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  try {
    const records = [observation(1, BODY), evidence('surface', 2), evidence('selection', 3), evidence('input', 4)];
    for (const record of records) {
      const payload = record.payload;
      if (!['text.snapshot', 'surface.snapshot', 'selection.snapshot', 'input.text'].includes(payload.kind)) {
        throw Error('fixture');
      }
      (
        payload as Extract<
          Observation['payload'],
          { kind: 'text.snapshot' | 'surface.snapshot' | 'selection.snapshot' | 'input.text' }
        >
      ).gate = {
        secure: 'not-declared-sensitive',
        privateState: 'normal',
        policyRevision: record.stamp.policyRevision,
      };
      await store.append(record, { generation: store.generation });
    }
    await store.close();
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
    assert.deepEqual((await store.search({ text: BODY })).records, records);
    for (const record of records) assert.deepEqual(await store.read(record.eventId), record);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('surface diff is an independent current tree, not a chain or a cross-node text concatenation', async () => {
  const temp = await temporary();
  let now = NOW;
  const store = await SegmentStore.open({
    root: temp.root,
    keyProvider: temp.provider,
    clock: () => now,
    retentionMs: 100,
  });
  try {
    const old = evidence('surface', 1, NOW - 90, 'old-only-body');
    const current = evidence('surface', 2, NOW - 10, 'current-only-body');
    assert.equal(current.payload.kind, 'surface.snapshot');
    if (current.payload.kind !== 'surface.snapshot') throw Error('fixture');
    current.payload.mode = 'diff';
    current.payload.baseRevision = 1;
    current.payload.changes = { added: [], updated: ['body'], removed: [] };
    current.payload.nodes.push({ id: 'other', parentId: 'root', role: 'text', text: 'separate-node', observedAtMs: NOW - 10 });
    await store.append(old, { generation: store.generation });
    await store.append(current, { generation: store.generation });
    await store.forget({ beforeMs: NOW - 50 });
    assert.equal(await store.read(old.eventId), null);
    assert.deepEqual(await store.read(current.eventId), current);
    assert.deepEqual((await store.search({ text: 'old-only-body' })).records, []);
    assert.deepEqual((await store.search({ text: 'current-only-bodyseparate-node' })).records, []);
    assert.deepEqual((await store.search({ text: 'current-only-body' })).records, [current]);
    now = NOW + 90;
    assert.deepEqual((await store.search()).records, []);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('standalone full-current diff survives reopen without its base revision', async () => {
  const temp = await temporary();
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  try {
    const current = evidence('surface', 20);
    if (current.payload.kind !== 'surface.snapshot') throw Error('fixture');
    current.payload.mode = 'diff';
    current.payload.baseRevision = 19;
    current.payload.changes = { added: [], updated: ['body'], removed: [] };
    await store.append(current, { generation: store.generation });
    await store.close();
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
    assert.deepEqual(await store.read(current.eventId), current);
    assert.deepEqual((await store.search({ text: BODY })).records, [current]);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('surface nodes cannot freshen old text outside the current capture interval', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  try {
    for (const time of [NOW, NOW + 3]) {
      const current = evidence('surface', 2);
      if (current.payload.kind !== 'surface.snapshot') throw Error('fixture');
      current.payload.nodes[1]!.observedAtMs = time;
      await assert.rejects(store.append(current, { generation: store.generation }), code('invalid-input'));
    }
    assert.equal(store.status().records, 0);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('new payload duplicate IDs keep canonical idempotence, conflicts and clone isolation', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  try {
    const original = evidence('surface', 1);
    const input = structuredClone(original);
    const pending = store.append(input, { generation: store.generation });
    if (input.payload.kind !== 'surface.snapshot') throw Error('fixture');
    input.payload.nodes[1]!.text = 'mutated after append';
    await pending;
    await store.append(original, { generation: store.generation });
    await assert.rejects(store.append(input, { generation: store.generation }), code('duplicate-conflict'));
    const read = await store.read(original.eventId);
    if (read?.payload.kind !== 'surface.snapshot') throw Error('fixture');
    read.payload.nodes.length = 0;
    assert.deepEqual(await store.read(original.eventId), original);
    assert.equal(store.status().records, 1);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('multi-source page budgets preserve coverage and return no unmatched body', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  try {
    const records = [evidence('surface', 1), evidence('selection', 2), evidence('input', 3)];
    if (records[0]!.payload.kind !== 'surface.snapshot') throw Error('fixture');
    records[0]!.payload.coverage.truncated = true;
    records[0]!.payload.coverage.missingReasons.push('node-budget');
    for (const record of records) await store.append(record, { generation: store.generation });
    const first = await store.search({ text: BODY, limit: 1, maxBytes: 4096 });
    assert.deepEqual(first.records, [records[0]]);
    assert.equal(first.truncated, true);
    assert.ok(first.nextCursor);
    assert.equal(first.bytes, Buffer.byteLength(JSON.stringify(first)));
    const second = await store.search({ text: BODY, limit: 1, maxBytes: 4096, cursor: first.nextCursor! });
    assert.deepEqual(second.records, [records[1]]);
    assert.ok(second.nextCursor);
    const third = await store.search({ text: BODY, limit: 1, maxBytes: 4096, cursor: second.nextCursor! });
    assert.deepEqual(third.records, [records[2]]);
    assert.equal(third.hasMore, false);
    const bounded = await store.search({ maxBytes: 512 });
    assert.equal(bounded.records.length, 0);
    assert.equal(bounded.truncated, true);
    assert.equal(bounded.bytes, Buffer.byteLength(JSON.stringify(bounded)));
    assert.ok(bounded.bytes <= 512);
    const scoped = await store.search({ fromTimeMs: NOW + 2, toTimeMs: NOW + 2, text: BODY });
    assert.deepEqual(scoped.records, [records[1]]);
    assert.equal(JSON.stringify(scoped).includes(`${BODY}-surface`), false);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('relations remain advisory IDs and query bounds strip references without pulling source text', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  try {
    const prior = evidence('surface', 1, NOW + 1, 'private-other-channel');
    const record = related(evidence('input', 2), [prior.eventId]);
    await store.append(prior, { generation: store.generation });
    await store.append(record, { generation: store.generation });
    assert.deepEqual(await store.read(record.eventId), record);
    assert.deepEqual((await store.search()).records, [prior, record]);
    for (const query of [{ kind: 'input' as const }, { fromTimeMs: NOW + 2 }, { text: '-input' }]) {
      const page = await store.search(query);
      assert.deepEqual(page.records, [evidence('input', 2)]);
      assert.equal(JSON.stringify(page).includes(prior.eventId), false);
      assert.equal(JSON.stringify(page).includes('private-other-channel'), false);
      assert.equal(page.bytes, Buffer.byteLength(JSON.stringify(page)));
    }
    assert.deepEqual(await store.read(record.eventId), record);
    await store.append(record, { generation: store.generation });
    assert.equal(store.status().records, 2);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('equal-clock native batch relations survive storage and read projection with earlier sequence only', async () => {
  const temp = await temporary();
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  const correlator = new EvidenceCorrelator();
  try {
    const selection = evidence('selection', 1, NOW);
    selection.monotonicMs = 100;
    await store.append(selection, { generation: store.generation });
    correlator.commit(selection);
    const surface = evidence('surface', 2, NOW);
    surface.monotonicMs = 100;
    const linked = correlator.preview(surface);
    assert.deepEqual(linked.relation, {
      basis: 'temporal-same-surface',
      evidenceIds: [selection.eventId],
      effect: 'unverified',
    });
    await store.append(linked, { generation: store.generation });
    correlator.commit(linked);
    assert.deepEqual(await store.read(linked.eventId), linked);
    assert.deepEqual((await store.search({ fromTimeMs: NOW, toTimeMs: NOW })).records, [selection, linked]);
    await store.close();
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
    assert.deepEqual(await store.read(linked.eventId), linked);
    assert.deepEqual((await store.search()).records, [selection, linked]);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('Forget strips unavailable relation IDs without changing survivor segment ciphertext or reviving evidence after reopen', async () => {
  const temp = await temporary();
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  try {
    const prior = evidence('selection', 1);
    const record = related(evidence('input', 2), [prior.eventId]);
    await store.append(prior, { generation: store.generation });
    await store.append(record, { generation: store.generation });
    const before = new Map<string, Buffer>();
    for (const name of await readdir(temp.root)) before.set(name, await readFile(join(temp.root, name)));
    await store.forget({ beforeMs: NOW + 2 });
    assert.equal(await store.read(prior.eventId), null);
    assert.deepEqual(await store.read(record.eventId), evidence('input', 2));
    const page = await store.search();
    assert.deepEqual(page.records, [evidence('input', 2)]);
    let unchanged = 0;
    for (const name of await readdir(temp.root)) {
      if (name.endsWith('.cah')) {
        assert.deepEqual(await readFile(join(temp.root, name)), before.get(name));
        unchanged++;
      }
    }
    assert.ok(unchanged >= 1);
    await store.close();
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
    assert.deepEqual(await store.read(record.eventId), evidence('input', 2));
    await store.append(record, { generation: store.generation });
    assert.equal(store.status().records, 1);
    await store.forget({ all: true });
    assert.equal(store.status().counts.inputText, 0);
    assert.equal(store.status().counts.selection, 0);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('relation TTL preview race drops absent IDs instead of failing the otherwise valid capture', async () => {
  const temp = await temporary();
  let now = NOW;
  const store = await SegmentStore.open({
    root: temp.root,
    keyProvider: temp.provider,
    clock: () => now,
    retentionMs: 100,
  });
  try {
    const prior = evidence('surface', 1, NOW - 99);
    const next = related(evidence('input', 2, NOW + 1), [prior.eventId]);
    await store.append(prior, { generation: store.generation });
    now = NOW + 1;
    await store.append(next, { generation: store.generation });
    assert.equal(await store.read(prior.eventId), null);
    assert.deepEqual(await store.read(next.eventId), evidence('input', 2, NOW + 1));
    await store.append(next, { generation: store.generation });
    assert.equal(store.status().records, 1);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('relations cannot inject other-store, future, same-channel or cross-context references', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  try {
    const prior = evidence('surface', 1);
    await store.append(prior, { generation: store.generation });
    const injected = related(evidence('input', 2), ['other-store:99']);
    await store.append(injected, { generation: store.generation });
    assert.equal((await store.read(injected.eventId))?.relation, undefined);
    const wrongContext = related(evidence('input', 3), [prior.eventId]);
    wrongContext.stamp.captureEpoch++;
    await assert.rejects(store.append(wrongContext, { generation: store.generation }), code('invalid-input'));
    const sameChannel = related(evidence('surface', 3), [prior.eventId]);
    await assert.rejects(store.append(sameChannel, { generation: store.generation }), code('invalid-input'));
    const future = related(evidence('input', 3, NOW), [prior.eventId]);
    await assert.rejects(store.append(future, { generation: store.generation }), code('invalid-input'));
    const self = related(evidence('input', 3), ['synthetic-instance:3']);
    await assert.rejects(store.append(self, { generation: store.generation }), code('invalid-input'));
    assert.equal(store.status().records, 2);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('generation fences prevent multi-source writes and correlator commits across Forget', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 100 });
  const correlator = new EvidenceCorrelator();
  try {
    const prior = evidence('surface', 1);
    await store.append(prior, { generation: store.generation });
    correlator.commit(prior);
    const generation = store.generation;
    const pending = store.append(correlator.preview(evidence('input', 2)), { generation });
    const rejection = assert.rejects(pending, code('stale-generation'));
    const forget = store.forget({ all: true });
    correlator.clear();
    await rejection;
    await forget;
    assert.equal(correlator.preview(evidence('selection', 3)).relation, undefined);
    assert.equal(store.status().records, 0);
    assert.equal(store.status().counts.surface, 0);
    assert.equal(store.status().counts.inputText, 0);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

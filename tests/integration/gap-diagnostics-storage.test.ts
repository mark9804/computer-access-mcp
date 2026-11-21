import assert from 'node:assert/strict';
import test from 'node:test';
import { SegmentStore } from '../../src/storage/segment-store.ts';
import { observation, temporary, NOW } from './history-store-fixtures.ts';
import type { GapDiagnostic } from '../../src/shared/protocol/generated.ts';

test('surface failure codes survive encrypted reopen without reclassifying old gaps', async () => {
  const temp = await temporary();
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
  const codes: GapDiagnostic['code'][] = [
    'surface-not-started-budget',
    'surface-call-budget',
    'surface-time-budget',
    'surface-anchor-unavailable',
    'surface-boundary-unverified',
    'surface-security-excluded',
    'surface-provider-unavailable',
  ];
  try {
    for (const [i, code] of codes.entries()) {
      const event = observation(i + 1);
      event.payload = { kind: 'gap', reason: 'read-error', count: 1, diagnostic: { code } };
      await store.append(event, { generation: store.generation });
    }
    const legacy = observation(8);
    legacy.payload = { kind: 'gap', reason: 'stale', count: 1 };
    await store.append(legacy, { generation: store.generation });
    await store.close();
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
    const records = (await store.search({ kind: 'gap', limit: 20 })).records;
    assert.equal(records.length, 8);
    assert.deepEqual(
      records.slice(0, 7).map((record) => (record.payload.kind === 'gap' ? record.payload.diagnostic?.code : null)),
      codes,
    );
    assert.deepEqual(records[7]!.payload, legacy.payload);
    assert.equal(store.status().counts.surface, 0);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('fixed gap diagnostics persist encrypted and old gaps remain undiagnosed after reopen', async () => {
  const temp = await temporary();
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
  try {
    const fresh = observation(1);
    fresh.target = { kind: 'unresolved', reason: 'policy-boundary' };
    fresh.payload = {
      kind: 'gap',
      reason: 'policy-boundary',
      count: 1,
      diagnostic: { code: 'focused-role-not-text', role: 'AXMenuItem' },
    };
    const input = observation(3);
    input.target = { kind: 'unresolved', reason: 'policy-boundary' };
    input.payload = { kind: 'gap', reason: 'stale', count: 1, diagnostic: { code: 'input-context-unverified' } };
    const old = observation(2);
    old.target = { kind: 'unresolved', reason: 'policy-boundary' };
    old.payload = { kind: 'gap', reason: 'policy-boundary', count: 1 };
    await store.append(fresh, { generation: store.generation });
    await store.append(old, { generation: store.generation });
    await store.append(input, { generation: store.generation });
    await store.close();
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
    const result = await store.search({ kind: 'gap' });
    assert.equal(result.records.length, 3);
    assert.deepEqual(result.records[0]!.payload, fresh.payload);
    assert.deepEqual(result.records[1]!.payload, old.payload);
    assert.deepEqual(result.records[2]!.payload, input.payload);
    assert.equal(store.status().counts.text, 0);
    await store.forget({ all: true });
    assert.equal((await store.search()).records.length, 0);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

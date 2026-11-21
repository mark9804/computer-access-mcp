import assert from 'node:assert/strict';
import test from 'node:test';
import type { Observation } from '../../src/shared/protocol/generated.ts';
import { EvidenceCorrelator, evidenceMetadata } from '../../src/host/collectors/evidence-correlator.ts';
import { NOW, observation } from './history-store-fixtures.ts';

const BODY = 'SYNTHETIC-CORRELATOR-NEVER-CACHED-正文';
type Channel = 'surface' | 'selection' | 'input';
function record(kind: Channel, seq: number, eventTimeMs = NOW + seq, monotonicMs = seq): Observation {
  const item = observation(seq, '', eventTimeMs); item.monotonicMs = monotonicMs;
  const gate = { secure: 'safe', privateState: 'normal', policyRevision: 1 } as const;
  const capture = { captureStartMs: eventTimeMs, captureEndMs: eventTimeMs };
  if (kind === 'surface') item.payload = { kind: 'surface.snapshot', snapshotId: `snapshot-${seq}`, surfaceId: 'surface-1', revision: seq,
    source: 'ax.tree', scope: 'window', mode: 'full', nodes: [{ id: 'node-1', role: 'text', text: BODY, observedAtMs: eventTimeMs }],
    ...capture, gate, coverage: { status: 'partial', truncated: false, missingReasons: ['bounded-window'] }, consistency: 'non-atomic' };
  else if (kind === 'selection') item.payload = { kind: 'selection.snapshot', snapshotId: `snapshot-${seq}`, surfaceId: 'surface-1',
    source: 'ax.range', scope: 'selection', text: BODY, range: { unit: 'utf16', start: 0, length: BODY.length }, ...capture, gate,
    coverage: { status: 'partial', truncated: false, missingReasons: ['selection-only'] } };
  else item.payload = { kind: 'input.text', source: 'cg.unicode', scope: 'field', eventKind: 'text', text: BODY, modifiers: [],
    intervalStartMs: eventTimeMs, intervalEndMs: eventTimeMs, eventCount: 1, surfaceId: 'surface-1', gate, secureInput: 'inactive',
    coverage: { status: 'partial', truncated: false, missingReasons: ['input-events-partial', 'effect-unverified'] }, effect: 'unverified' };
  return item;
}

function inspectCache(correlator: EvidenceCorrelator): unknown[] {
  const values = Object.values(correlator);
  assert.equal(values.length, 1); assert.ok(Array.isArray(values[0]));
  return values[0];
}

test('preview clones without modifying input and only commit makes cross-channel evidence eligible', () => {
  const correlator = new EvidenceCorrelator(); const first = record('surface', 1); const second = record('input', 2);
  assert.equal(correlator.preview(first).relation, undefined);
  assert.equal(correlator.preview(second).relation, undefined);
  correlator.commit(first);
  const linked = correlator.preview(second);
  assert.deepEqual(linked.relation, { basis: 'temporal-same-surface', evidenceIds: [first.eventId], effect: 'unverified' });
  assert.equal(second.relation, undefined); assert.notEqual(linked.payload, second.payload);
  if (linked.payload.kind !== 'input.text' || second.payload.kind !== 'input.text') throw Error('fixture');
  linked.payload.text = 'mutated preview'; linked.target = { kind: 'unresolved', reason: 'not-observed' };
  assert.equal(second.payload.text, BODY); assert.equal(second.target.kind, 'resolved');
  correlator.commit(second);
  assert.deepEqual(correlator.preview(record('selection', 3)).relation?.evidenceIds, [second.eventId, first.eventId]);
});

test('helper-supplied associations are never trusted or copied into another surface/store', () => {
  const correlator = new EvidenceCorrelator();
  const item = record('input', 2);
  item.relation = { basis: 'temporal-same-surface', evidenceIds: ['foreign-store:9'], effect: 'unverified' };
  const result = correlator.preview(item);
  assert.equal(result.relation, undefined); assert.deepEqual(item.relation.evidenceIds, ['foreign-store:9']);
  const prior = record('surface', 1); correlator.commit(prior);
  assert.deepEqual(correlator.preview(item).relation?.evidenceIds, [prior.eventId]);
});

test('both clocks require nonnegative evidence age within the inclusive 1500ms window', () => {
  const correlator = new EvidenceCorrelator(); const earlier = record('surface', 1, NOW, 100);
  correlator.commit(earlier);
  for (const [event, monotonic] of [[NOW - 1, 101], [NOW + 1, 99], [NOW + 1501, 101], [NOW + 1, 1601]]) {
    assert.equal(correlator.preview(record('input', 2, event, monotonic)).relation, undefined);
  }
  assert.deepEqual(correlator.preview(record('input', 2, NOW + 1500, 1600)).relation?.evidenceIds, [earlier.eventId]);
  assert.equal(correlator.preview(record('input', 1, NOW + 1, 101)).relation, undefined);
  const unfinished = record('input', 2, NOW + 1, 101);
  if (unfinished.payload.kind !== 'input.text') throw Error('fixture'); unfinished.payload.intervalEndMs = NOW + 2;
  assert.equal(correlator.preview(unfinished).relation, undefined);
});

test('same native batch clocks allow only strictly earlier committed sequences, never causal claims', () => {
  const correlator = new EvidenceCorrelator(); const selection = record('selection', 1, NOW, 100);
  correlator.commit(selection);
  const surface = record('surface', 2, NOW, 100);
  const linked = correlator.preview(surface);
  assert.deepEqual(linked.relation, { basis: 'temporal-same-surface', evidenceIds: [selection.eventId], effect: 'unverified' });
  assert.equal(correlator.preview(record('surface', 1, NOW, 100)).relation, undefined);
  assert.equal(correlator.preview(record('surface', 0, NOW, 100)).relation, undefined);
  correlator.commit(surface);
  assert.deepEqual(correlator.preview(record('input', 3, NOW, 100)).relation?.evidenceIds, [surface.eventId, selection.eventId]);
  assert.deepEqual(correlator.preview(record('input', 3, NOW, 101)).relation?.evidenceIds, [surface.eventId, selection.eventId]);
  assert.deepEqual(correlator.preview(record('input', 3, NOW + 1, 100)).relation?.evidenceIds, [surface.eventId, selection.eventId]);
});

test('context identity includes instance, epoch, policy, all target fields, generations and exact surfaceId', () => {
  const changes: Array<[string, (item: Observation) => void]> = [
    ['instance', item => { item.instanceId = 'different-instance'; item.eventId = `${item.instanceId}:${item.seq}`; }],
    ['epoch', item => { item.stamp.captureEpoch++; }],
    ['policy', item => { item.stamp.policyRevision++; }],
    ['foreground', item => { item.stamp.foregroundGeneration++; }],
    ['focus', item => { item.stamp.focusGeneration++; }],
    ['unresolved', item => { item.target = { kind: 'unresolved', reason: 'not-observed' }; }],
    ['surface', item => { if (item.payload.kind === 'input.text') item.payload.surfaceId = 'different-surface'; }],
  ];
  for (const field of ['deviceId', 'osSessionId', 'desktopId', 'processStartTime', 'applicationId', 'windowId'] as const) {
    changes.push([field, item => { if (item.target.kind === 'resolved') item.target.identity[field] += '-other'; }]);
  }
  for (const field of ['processId', 'windowGeneration'] as const) {
    changes.push([field, item => { if (item.target.kind === 'resolved') item.target.identity[field]++; }]);
  }
  for (const [name, change] of changes) {
    const correlator = new EvidenceCorrelator(); correlator.commit(record('surface', 1));
    const candidate = record('input', 2); change(candidate);
    assert.equal(correlator.preview(candidate).relation, undefined, name);
    correlator.commit(candidate);
    assert.equal(correlator.preview(record('selection', 3)).relation, undefined, `return after ${name}`);
  }
});

test('context tuple cannot collide through identity separators and ambiguous/missing identity is omitted', () => {
  const correlator = new EvidenceCorrelator(); const first = record('surface', 1);
  const second = record('input', 2);
  if (first.target.kind !== 'resolved' || second.target.kind !== 'resolved') throw Error('fixture');
  first.target.identity.windowId = 'a|b'; first.target.identity.processStartTime = 'c';
  second.target.identity.windowId = 'a'; second.target.identity.processStartTime = 'b|c';
  correlator.commit(first); assert.equal(correlator.preview(second).relation, undefined);
  const missing = record('input', 2); if (missing.payload.kind !== 'input.text') throw Error('fixture');
  missing.payload.surfaceId = '';
  assert.equal(evidenceMetadata(missing), undefined);
  const invalid = record('input', 2); invalid.stamp.captureEpoch = NaN;
  assert.equal(evidenceMetadata(invalid), undefined);
});

test('legacy text node/edit IDs do not imply a new surface identity and non-content clears context', () => {
  const correlator = new EvidenceCorrelator(); const legacy = observation(1, BODY, NOW + 1);
  if (legacy.payload.kind !== 'text.snapshot') throw Error('fixture');
  legacy.payload.nodeId = 'surface-1'; legacy.payload.editSessionId = 'surface-1';
  correlator.commit(legacy); assert.equal(correlator.preview(record('input', 2)).relation, undefined);
  correlator.commit(record('surface', 2));
  assert.equal(correlator.preview(observation(3, BODY, NOW + 3)).relation, undefined);
  correlator.commit({ ...record('selection', 3), payload: { kind: 'context.changed', reason: 'focus' } });
  assert.equal(correlator.preview(record('input', 4)).relation, undefined);
});

test('interleaved legacy focused text neither links nor clears proven same-window input metadata',()=>{
  const correlator=new EvidenceCorrelator();const input=record('input',1);correlator.commit(input);
  const legacy=observation(2,BODY,NOW+2);legacy.monotonicMs=2;correlator.commit(legacy);
  assert.equal(correlator.preview(legacy).relation,undefined);assert.deepEqual(correlator.preview(record('surface',3)).relation?.evidenceIds,[input.eventId]);
  const other=observation(4,BODY,NOW+4);other.monotonicMs=4;other.stamp.focusGeneration++;correlator.commit(other);
  assert.equal(correlator.preview(record('surface',5)).relation,undefined);
  correlator.commit(record('input',6));correlator.commit({...record('surface',7),payload:{kind:'context.changed',reason:'focus'}});assert.equal(correlator.preview(record('surface',8)).relation,undefined);
});
test('relation list is bounded to four recent cross-channel IDs without same-kind/self links', () => {
  const correlator = new EvidenceCorrelator();
  for (let seq = 1; seq <= 8; seq++) correlator.commit(record(seq % 2 ? 'surface' : 'selection', seq));
  assert.deepEqual(correlator.preview(record('input', 9)).relation?.evidenceIds,
    [8, 7, 6, 5].map(seq => `synthetic-instance:${seq}`));
  assert.deepEqual(correlator.preview(record('surface', 9)).relation?.evidenceIds,
    [8, 6, 4, 2].map(seq => `synthetic-instance:${seq}`));
});

test('cache is metadata-only, bounded to 64 entries and does not retain caller objects or source text', () => {
  const correlator = new EvidenceCorrelator();
  for (let seq = 1; seq <= 100; seq++) correlator.commit(record('surface', seq));
  const entries = inspectCache(correlator);
  assert.equal(entries.length, 64);
  for (const entry of entries) assert.deepEqual(Object.keys(entry as object).sort(),
    ['context', 'endMs', 'eventId', 'eventTimeMs', 'kind', 'monotonicMs', 'seq']);
  const serialized = JSON.stringify(correlator);
  for (const forbidden of [BODY, 'nodes', 'payload', 'snapshotId', 'ax.tree', 'coverage', 'bounded-window']) assert.equal(serialized.includes(forbidden), false);
  const input = record('input', 101); correlator.commit(input);
  if (input.payload.kind !== 'input.text' || input.target.kind !== 'resolved') throw Error('fixture');
  input.payload.text = 'changed body'; input.target.identity.windowId = 'changed-window'; input.stamp.captureEpoch++;
  assert.deepEqual(correlator.preview(record('selection', 102)).relation?.evidenceIds,
    [101, 100, 99, 98].map(seq => `synthetic-instance:${seq}`));
  correlator.clear(); assert.deepEqual(inspectCache(correlator), []);
  assert.equal(correlator.preview(record('input', 103)).relation, undefined);
});

test('commit prunes expired metadata and refuses backwards clocks/replayed sequence as correlation seeds', () => {
  for (const makeInvalid of [
    () => record('selection', 2, NOW, 11),
    () => record('input', 2, NOW - 1501, 11),
    () => record('input', 2, NOW + 2, 9),
    () => record('input', 1, NOW + 2, 11),
  ]) {
    const correlator = new EvidenceCorrelator(); correlator.commit(record('surface', 1, NOW + 1, 10));
    correlator.commit(makeInvalid()); assert.deepEqual(inspectCache(correlator), []);
    assert.equal(correlator.preview(record('selection', 3, NOW + 3, 12)).relation, undefined);
  }
  const correlator = new EvidenceCorrelator(); correlator.commit(record('surface', 1));
  correlator.commit(record('input', 2, NOW + 1600, 1600));
  assert.equal(inspectCache(correlator).length, 1);
  assert.deepEqual(correlator.preview(record('selection', 3, NOW + 1601, 1601)).relation?.evidenceIds, ['synthetic-instance:2']);
});

test('debounced bounded-late input seeds only subsequent same-surface evidence, never retroactive AX',()=>{
  const correlator=new EvidenceCorrelator();const during=record('surface',1,NOW+500,1000);correlator.commit(during);
  const input=record('input',2,NOW,1100);assert.equal(correlator.preview(input).relation,undefined);correlator.commit(input);
  const next=record('surface',3,NOW+700,1100);assert.deepEqual(correlator.preview(next).relation?.evidenceIds,[input.eventId]);
  assert.equal(correlator.preview(record('surface',4,NOW+1600,1200)).relation,undefined);
  const wrong=record('input',5,NOW+400,1300);wrong.stamp.focusGeneration++;correlator.commit(wrong);assert.equal(correlator.preview(record('surface',6,NOW+800,1300)).relation,undefined);
});
test('late input seed enforces inclusive event and delivery bounds independently',()=>{
  for(const [late,mono,accepted] of [[1500,1500,true],[1501,1,false],[1,1501,false]] as const){
    const c=new EvidenceCorrelator();c.commit(record('surface',1,NOW+2000,2000));c.commit(record('input',2,NOW+2000-late,2000+mono));
    assert.equal(inspectCache(c).length,accepted?1:0);
  }
});
test('clear is the lifecycle fence and separate correlator instances never share metadata', () => {
  const first = new EvidenceCorrelator(); const second = new EvidenceCorrelator();
  first.commit(record('surface', 1));
  assert.equal(second.preview(record('input', 2)).relation, undefined);
  for (const boundary of ['pause', 'stop', 'Forget', 'policy', 'close']) {
    first.clear(); assert.equal(first.preview(record('input', 2)).relation, undefined, boundary);
    first.commit(record('surface', 1));
  }
});

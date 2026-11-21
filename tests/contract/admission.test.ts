import test from 'node:test';
import assert from 'node:assert/strict';
import { CollectorAdmission } from '../../src/host/collectors/admission.ts';
import { control, observation, target } from '../../fixtures/contract/examples.ts';
import { activityObservation, activityIdentity } from '../integration/input-activity-fixtures.ts';
import { surfaceObservation } from '../../fixtures/contract/multi-source.ts';
import type { Configured } from '../../src/shared/protocol/generated.ts';
const ack: Configured = { protocolVersion: 1, type: 'configured', requestId: 'cfg-1', ownerId: 'host-1', instanceId: 'fixture-1', policyRevision: 1 };
function gate() { const event = observation(); const value = new CollectorAdmission({ ...ack }, event.stamp, () => true); value.setBoundary(event.stamp, target); return value; }
test('application counts never establish a text baseline and cannot cross a capture boundary', () => {
  const value = gate(); value.acknowledge(ack);
  const event=activityObservation();value.setBoundary({...event.stamp,foregroundGeneration:3,focusGeneration:5},target);
  assert.equal(value.accept(event).accepted,true);assert.equal(value.commit(event.eventId),false);
  assert.equal(value.accept({...event,seq:2,eventId:'fixture-1:2',stamp:{...event.stamp,captureEpoch:0}}).reason,'stale');
  assert.equal(value.accept({...event,seq:3,eventId:'fixture-1:3',stamp:{...event.stamp,focusGeneration:6}}).reason,'stale');
});
test('an unfocused window surface never establishes a focused text delta baseline', () => {
  const value=gate();value.acknowledge(ack);
  const event=surfaceObservation();event.payload.scope='window';for(const node of event.payload.nodes)node.focused=false;
  assert.equal(value.accept(event).accepted,true);assert.equal(value.commit(event.eventId),false);
  const next=observation();if(next.payload.kind!=='text.snapshot')throw Error('fixture');
  assert.equal(value.accept({...next,eventId:'fixture-1:2',seq:2,payload:{kind:'text.changed',baseSnapshotId:event.payload.snapshotId,after:next.payload}}).reason,'baseline');
});
test('input activity must match application and process identity when a resolved boundary is known', () => {
  for (const changed of [{applicationId:'other.allowed'},{processId:99},{processStartTime:'reused'},{osSessionId:'other-session'},{desktopId:'other-desktop'}]) {
    const value=gate();value.acknowledge(ack);const event=activityObservation();event.target={kind:'application',identity:activityIdentity(changed)};
    assert.equal(value.accept(event).reason,'target');
  }
});
test('matching ACK precedes admission; duplicates do not revoke grant', () => {
  const value = gate(); assert.equal(value.accept(observation()).reason, 'unconfigured');
  assert.equal(value.acknowledge({ ...ack, ownerId: 'other' }), false); assert.equal(value.acknowledge(ack), true); assert.equal(value.acknowledge(ack), false);
  assert.equal(value.accept(observation()).accepted, true); assert.equal(value.accept(observation()).reason, 'sequence');
});
test('old instance, epoch, target and missing baseline rejected', () => {
  const value = gate(); value.acknowledge(ack);
  assert.equal(value.accept({ ...observation(), instanceId: 'old' }).reason, 'stale');
  assert.equal(value.accept({ ...observation(), stamp: { ...observation().stamp, captureEpoch: 0 } }).reason, 'stale');
  assert.equal(value.accept({ ...observation(), target: { kind: 'resolved', identity: { ...target, processStartTime: 'reused-pid' } } }).reason, 'target');
  const after = observation().payload; assert.equal(after.kind, 'text.snapshot');
  if (after.kind !== 'text.snapshot') throw new Error('fixture');
  assert.equal(value.accept({ ...observation(), eventId: 'fixture-1:2', seq: 2, payload: { kind: 'text.changed', baseSnapshotId: 'missing', after } }).reason, 'baseline');
});
test('Host policy defaults deny and failed sink cannot establish delta baseline', () => {
  const event = observation(); const denied = new CollectorAdmission({ ...ack }, event.stamp); denied.setBoundary(event.stamp, target); denied.acknowledge(ack);
  assert.equal(denied.accept(event).reason, 'policy');
  const value = gate(); value.acknowledge(ack); value.accept(event);
  if (event.payload.kind !== 'text.snapshot') throw new Error('fixture');
  const after = { ...event.payload, snapshotId: 's-2' };
  assert.equal(value.accept({ ...event, eventId: 'fixture-1:2', seq: 2, payload: { kind: 'text.changed', baseSnapshotId: 's-1', after } }).reason, 'baseline');
  assert.equal(value.commit(event.eventId), true);
  assert.equal(value.accept({ ...event, eventId: 'fixture-1:3', seq: 3, payload: { kind: 'text.changed', baseSnapshotId: 's-1', after: { ...after, nodeId: 'other' } } }).reason, 'baseline');
  assert.equal(value.accept({ ...event, eventId: 'fixture-1:4', seq: 4, payload: { kind: 'text.changed', baseSnapshotId: 's-1', after: { ...after, editSessionId: 'other' } } }).reason, 'baseline');
  assert.equal(value.accept({ ...event, eventId: 'fixture-1:5', seq: 5, payload: { kind: 'text.changed', baseSnapshotId: 's-1', after } }).accepted, true);
});
test('event identity cannot be reused to overwrite pending baseline', () => {
  const value = gate(); value.acknowledge(ack); const event = observation(); value.accept(event);
  if (event.payload.kind !== 'text.snapshot') throw new Error('fixture');
  assert.equal(value.accept({ ...event, seq: 2, payload: { ...event.payload, snapshotId: 's-overwrite' } }).reason, 'sequence');
  assert.equal(value.commit(event.eventId), true);
  assert.throws(() => value.setBoundary({ ...event.stamp, policyRevision: 2 }, target), /policy-revision-mismatch/);
});
test('boundary and revoke invalidate accepted baselines', () => {
  const value = gate(); value.acknowledge(ack); value.accept(observation()); value.revoke();
  assert.equal(value.accept({ ...observation(), seq: 2 }).reason, 'unconfigured');
  assert.equal(value.acknowledge(ack), false);
});
test('valid message of wrong type cannot masquerade as configured ACK', () => {
  const value = gate();
  assert.equal(value.acknowledge({ ...control('start'), requestId: 'cfg-1' } as unknown as Configured), false);
});
test('Collector cannot authenticate an Agent actor by inventing relatedActionId', () => {
  const value = gate(); value.acknowledge(ack);
  assert.equal(value.accept({ ...observation(), actor: 'agent', relatedActionIds: ['invented-action'] }).accepted, false);
});

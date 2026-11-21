import type { ApplicationTargetIdentity, Observation, Stamp } from '../../src/shared/protocol/generated.ts';
import { target } from '../../fixtures/contract/examples.ts';

export function activityIdentity(overrides: Partial<ApplicationTargetIdentity> = {}): ApplicationTargetIdentity {
  const { windowId: _window, windowGeneration: _generation, ...identity } = target;
  return { ...identity, ...overrides };
}
export function activityObservation(seq = 1, stamp: Stamp = { captureEpoch: 1, foregroundGeneration: 1, focusGeneration: 1, policyRevision: 1 }, instanceId = 'fixture-1', start = 1000): Observation {
  return {
    protocolVersion: 1, type: 'observation', eventId: `${instanceId}:${seq}`, instanceId, seq,
    eventTimeMs: start + 1000, monotonicMs: start + 1000,
    target: { kind: 'application', identity: activityIdentity() }, stamp, actor: 'unknown', relatedActionIds: [],
    payload: { kind: 'input.activity', source: 'fixture', scope: 'application', intervalStartMs: start, intervalEndMs: start + 1000,
      counts: { pointerReleases: 1, dragSamples: 2, scrollSamples: 3, shortcutPresses: 1 },
      gate: { policyRevision: stamp.policyRevision, secureInput: 'inactive', targetAttribution: 'event-target-pid', detail: 'coarse-counts' },
      coverage: { status: 'partial', truncated: false, missingReasons: ['input-events-partial', 'application-only', 'effect-unverified'] } },
  };
}

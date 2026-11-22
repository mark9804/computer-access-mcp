import type { ApplicationTarget, ApplicationTargetIdentity, InputActivity, Observation } from '../../src/shared/protocol/generated.ts';
import type { ContractCase } from './cases.ts';
import { configure, messages, observation, target, textSnapshot } from './examples.ts';

// Synthetic only: no desktop, event tap, permission or native input APIs.
export function inputActivity(source: InputActivity['source'] = 'fixture'): Observation & { target: ApplicationTarget; payload: InputActivity } {
  const identity: ApplicationTargetIdentity = {
    deviceId: target.deviceId, osSessionId: target.osSessionId, desktopId: target.desktopId,
    processId: target.processId, processStartTime: target.processStartTime, applicationId: target.applicationId,
  };
  return {
    ...observation(), eventId: 'fixture-1:3', seq: 3, eventTimeMs: 2000,
    target: { kind: 'application', identity },
    payload: {
      kind: 'input.activity', source, scope: 'application', intervalStartMs: 1000, intervalEndMs: 2000,
      counts: { pointerReleases: 1, dragSamples: 0, scrollSamples: 0, shortcutPresses: 0 },
      gate: { policyRevision: 1, secureInput: 'inactive', targetAttribution: 'event-target-pid', detail: 'coarse-counts' },
      coverage: { status: 'partial', truncated: false, missingReasons: ['input-events-partial', 'application-only', 'effect-unverified'] },
    },
  };
}
const mutate = (value: unknown, edit: (copy: any) => void): unknown => { const copy = structuredClone(value); edit(copy); return copy; };
const valid = (name: string, value: unknown): ContractCase => ({ name: `input-${name}`, valid: true, value });
const invalid = (name: string, edit: (copy: any) => void, value: unknown = inputActivity()): ContractCase => ({ name: `input-${name}`, valid: false, value: mutate(value, edit) });

// A bucket has one application identity, one exact second and bounded coarse
// counts. Schema primitive mechanics are sampled in cases.ts, not per property.
export const inputActivityCases: ContractCase[] = [
  valid('policy-enabled', mutate(configure(), x => { x.policy.inputActivity = true; })),
  valid('capability', mutate(messages[0], x => { x.capabilities.push({ name: 'input.activity', direction: 'observe', scope: 'app-local', support: 'supported', reason: 'synthetic-only' }); })),
  valid('fixture', inputActivity()),
  valid('listen-only', inputActivity('cg.listen-only')),
  valid('win32-listen-only', inputActivity('win32.listen-only')),
  valid('earliest-interval', mutate(inputActivity(), x => { x.payload.intervalStartMs = 0; x.payload.intervalEndMs = x.eventTimeMs = 1000; })),
  valid('distributed-cap', mutate(inputActivity(), x => { x.payload.counts = { pointerReleases: 64, dragSamples: 64, scrollSamples: 64, shortcutPresses: 64 }; })),
  invalid('missing-gate', x => { delete x.payload.gate; }),
  invalid('forbidden-detail', x => { x.payload.keyCode = 42; }),
  invalid('window-identity', x => { x.target.identity.windowId = target.windowId; }),
  invalid('resolved-target', x => { x.target = { kind: 'resolved', identity: { ...target } }; }),
  invalid('stale-gate', x => { x.payload.gate.policyRevision = 2; }),
  invalid('secure-input-active', x => { x.payload.gate.secureInput = 'active'; }),
  invalid('foreground-attribution', x => { x.payload.gate.targetAttribution = 'foreground-pid'; }),
  invalid('detailed-gate', x => { x.payload.gate.detail = 'raw-events'; }),
  invalid('unaligned-second', x => { x.payload.intervalStartMs++; x.payload.intervalEndMs++; x.eventTimeMs++; }),
  invalid('short-interval', x => { x.payload.intervalEndMs--; x.eventTimeMs--; }),
  invalid('long-interval', x => { x.payload.intervalEndMs++; x.eventTimeMs++; }),
  invalid('event-time-not-end', x => { x.eventTimeMs = x.payload.intervalStartMs; }),
  invalid('negative-count', x => { x.payload.counts.dragSamples = -1; }),
  invalid('fractional-count', x => { x.payload.counts.dragSamples = 0.5; }),
  invalid('zero-total', x => { x.payload.counts.pointerReleases = 0; }),
  invalid('over-total-cap', x => { x.payload.counts.pointerReleases = 256; x.payload.counts.dragSamples = 1; }),
  invalid('coverage-complete', x => { x.payload.coverage.status = 'complete'; }),
  invalid('coverage-without-reasons', x => { x.payload.coverage.missingReasons = []; }),
  invalid('actor-agent', x => { x.actor = 'agent'; x.relatedActionIds = ['synthetic-action']; }),
  invalid('related-action', x => { x.relatedActionIds = ['synthetic-action']; }),
  invalid('application-target-text', x => { x.payload = textSnapshot(); }),
];

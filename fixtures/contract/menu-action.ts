import type { ApplicationTarget, ApplicationTargetIdentity, ContentGate, MenuAction, Observation } from '../../src/shared/protocol/generated.ts';
import type { ContractCase } from './cases.ts';
import { configure, messages, observation, target } from './examples.ts';

// Synthetic wire fixtures for top menu bar observations (no native AX calls).
const gate = (): ContentGate => ({ secure: 'safe', privateState: 'normal', policyRevision: 1 });

export function menuAction(
  source: MenuAction['source'] = 'fixture',
  path: string[] = ['File', 'Save'],
  truncated = false,
): Observation & { target: ApplicationTarget; payload: MenuAction } {
  const identity: ApplicationTargetIdentity = {
    deviceId: target.deviceId, osSessionId: target.osSessionId, desktopId: target.desktopId,
    processId: target.processId, processStartTime: target.processStartTime, applicationId: target.applicationId,
  };
  return {
    ...observation(),
    eventId: 'fixture-1:4',
    seq: 4,
    eventTimeMs: 2500,
    target: { kind: 'application', identity },
    payload: {
      kind: 'menu.action',
      source,
      scope: 'menu-bar',
      path,
      observedAtMs: 2500,
      gate: gate(),
      secureInput: 'inactive',
      coverage: {
        status: 'partial',
        truncated,
        missingReasons: truncated
          ? ['menu-bar-only', 'effect-unverified', 'menu-title-truncated']
          : ['menu-bar-only', 'effect-unverified'],
      },
      effect: 'unverified',
    },
  };
}

const mutate = (value: unknown, edit: (copy: any) => void): unknown => {
  const copy = structuredClone(value);
  edit(copy);
  return copy;
};
const valid = (name: string, value: unknown): ContractCase => ({ name: `menu-${name}`, valid: true, value });
const invalid = (name: string, edit: (copy: any) => void, value: unknown = menuAction()): ContractCase => ({
  name: `menu-${name}`, valid: false, value: mutate(value, edit),
});

// Supplementary-plane character (2 UTF-16 code units, 1 code point) for UTF-16 budget boundaries.
const pair = '\u{1D11E}';

export const menuActionCases: ContractCase[] = [
  valid('policy-enabled', mutate(configure(), x => { x.policy.menuActions = true; })),
  valid('policy-disabled', mutate(configure(), x => { x.policy.menuActions = false; })),
  valid('capability', mutate(messages[0], x => {
    x.capabilities.push({ name: 'menu.action', direction: 'observe', scope: 'app-local', support: 'supported', reason: 'synthetic-only' });
  })),
  valid('fixture-two-level', menuAction('fixture', ['File', 'Save'])),
  valid('ax-two-level', menuAction('ax.menu', ['\u6587\u4ef6', '\u4fdd\u5b58'])),
  valid('uia-two-level', menuAction('uia.menu', ['File', 'Save'])),
  valid('three-level-truncated', menuAction('ax.menu', ['File', 'Export', 'PDF...'], true)),
  valid('max-depth-8', menuAction('ax.menu', ['L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'L8'])),
  valid('exact-utf16-budget', menuAction('ax.menu', [pair.repeat(64), pair.repeat(64), pair.repeat(64), pair.repeat(64)])),
  valid('gate-user-authorized-not-declared-sensitive', mutate(menuAction('ax.menu'), x => {
    x.payload.gate = { secure: 'not-declared-sensitive', privateState: 'user-authorized', policyRevision: 1 };
  })),

  invalid('policy-invalid-type', x => { x.policy.menuActions = 'true'; }, configure()),
  invalid('target-resolved', x => { x.target = { kind: 'resolved', identity: { ...target } }; }),
  invalid('target-unresolved', x => { x.target = { kind: 'unresolved', reason: 'focus-unavailable' }; }),
  invalid('target-window-identity', x => { x.target.identity.windowId = target.windowId; }),
  invalid('relation-present', x => { x.relation = { basis: 'temporal-same-surface', evidenceIds: ['earlier:1'], effect: 'unverified' }; }),
  invalid('actor-user-estimated', x => { x.actor = 'user-estimated'; }),
  invalid('actor-agent', x => { x.actor = 'agent'; x.relatedActionIds = ['action-1']; }),
  invalid('related-action', x => { x.relatedActionIds = ['action-1']; }),

  invalid('path-too-short', x => { x.payload.path = ['File']; }),
  invalid('path-empty-array', x => { x.payload.path = []; }),
  invalid('path-too-deep', x => { x.payload.path = ['L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'L8', 'L9']; }),
  invalid('path-empty-segment', x => { x.payload.path = ['File', '']; }),
  invalid('path-blank-spaces', x => { x.payload.path = ['File', '   ']; }),
  invalid('path-blank-unicode-nbsp-bom', x => { x.payload.path = ['File', '\u00a0\u3000\ufeff']; }),
  invalid('path-control-newline', x => { x.payload.path = ['File', 'Save\nAs']; }),
  invalid('path-control-cr', x => { x.payload.path = ['File', 'Save\rAs']; }),
  invalid('path-control-tab', x => { x.payload.path = ['File', 'Save\tAs']; }),
  invalid('path-control-nul', x => { x.payload.path = ['File', 'Save\u0000As']; }),
  invalid('path-control-del', x => { x.payload.path = ['File', 'Save\u007fAs']; }),
  invalid('path-control-c1-nel', x => { x.payload.path = ['File', 'Save\u0085As']; }),
  invalid('path-control-c1-high', x => { x.payload.path = ['File', 'Save\u009fAs']; }),
  invalid('path-segment-over-utf16', x => { x.payload.path = ['File', pair.repeat(65)]; }),
  invalid('path-total-over-utf16', x => {
    x.payload.path = [pair.repeat(64), pair.repeat(64), pair.repeat(64), pair.repeat(64), 'a'];
  }),

  invalid('event-time-mismatch', x => { x.eventTimeMs = x.payload.observedAtMs + 1; }),

  invalid('coverage-complete', x => { x.payload.coverage = { status: 'complete', truncated: false, missingReasons: [] }; }),
  invalid('coverage-unknown', x => { x.payload.coverage.status = 'unknown'; }),
  invalid('coverage-missing-menu-bar-only', x => { x.payload.coverage.missingReasons = ['effect-unverified']; }),
  invalid('coverage-missing-effect-unverified', x => { x.payload.coverage.missingReasons = ['menu-bar-only']; }),
  invalid('coverage-truncated-without-reason', x => { x.payload.coverage.truncated = true; }),
  invalid('coverage-untruncated-with-reason', x => {
    x.payload.coverage.missingReasons = ['menu-bar-only', 'effect-unverified', 'menu-title-truncated'];
  }),

  invalid('gate-missing', x => { delete x.payload.gate; }),
  invalid('gate-secure-sensitive', x => { x.payload.gate.secure = 'sensitive'; }),
  invalid('gate-secure-unknown', x => { x.payload.gate.secure = 'unknown'; }),
  invalid('gate-private', x => { x.payload.gate.privateState = 'private'; }),
  invalid('gate-private-unknown', x => { x.payload.gate.privateState = 'unknown'; }),
  invalid('gate-policy-revision-mismatch', x => { x.payload.gate.policyRevision = 2; }),

  invalid('source-invalid', x => { x.payload.source = 'cg.listen-only'; }),
  invalid('scope-invalid', x => { x.payload.scope = 'application'; }),
  invalid('secure-input-active', x => { x.payload.secureInput = 'active'; }),
  invalid('effect-confirmed', x => { x.payload.effect = 'confirmed'; }),
  invalid('extra-field', x => { x.payload.coords = { x: 1, y: 2 }; }),
];

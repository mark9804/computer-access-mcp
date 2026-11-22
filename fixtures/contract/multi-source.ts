import type { CaptureDiagnostics, ContentGate, InputText, Observation, SelectionSnapshot, State, SurfaceSnapshot, TextSnapshot } from '../../src/shared/protocol/generated.ts';
import type { ContractCase } from './cases.ts';
import { configure, messages, observation } from './examples.ts';
import { visibleRangeObservation } from './text-range.ts';
import { inputActivity } from './input-activity.ts';

// Synthetic wire evidence. Test data relationships, not every schema property
// crossed with every malformed JSON value. Runtime authorization is tested at Host.
const gate = (): ContentGate => ({ secure: 'safe', privateState: 'normal', policyRevision: 1 });
export function surfaceObservation(): Observation & { payload: SurfaceSnapshot } {
  return { ...observation(), payload: {
    kind: 'surface.snapshot', snapshotId: 'surface-snapshot-1', surfaceId: 'surface-1', revision: 1,
    source: 'ax.tree', scope: 'region', mode: 'full',
    nodes: [{ id: 'root', role: 'container', observedAtMs: 100 }, { id: 'text', parentId: 'root', role: 'text', text: '合成🙂', observedAtMs: 101 }],
    captureStartMs: 100, captureEndMs: 101, coverage: { status: 'partial', truncated: false, missingReasons: ['bounded-surface'] },
    gate: gate(), consistency: 'non-atomic',
  } };
}
export function surfaceDiffObservation(): Observation & { payload: SurfaceSnapshot } {
  const message = surfaceObservation();
  Object.assign(message.payload, { mode: 'diff', revision: 2, baseRevision: 1, changes: { added: ['text'], updated: ['root'], removed: [] } });
  return message;
}
export function selectionObservation(text = '选区🙂', start = 10): Observation & { payload: SelectionSnapshot } {
  return { ...observation(), payload: {
    kind: 'selection.snapshot', snapshotId: 'selection-snapshot-1', surfaceId: 'surface-1', source: 'ax.range', scope: 'selection',
    text, range: { unit: 'utf16', start, length: text.length }, captureStartMs: 100, captureEndMs: 101,
    coverage: { status: 'partial', truncated: false, missingReasons: ['selection-only'] }, gate: gate(),
  } };
}
export function inputTextObservation(text = '输入🙂'): Observation & { payload: InputText } {
  return { ...observation(), payload: {
    kind: 'input.text', source: 'cg.unicode', scope: 'field', eventKind: 'text', text, modifiers: [],
    intervalStartMs: 100, intervalEndMs: 101, eventCount: 1, surfaceId: 'surface-1', gate: gate(), secureInput: 'inactive',
    coverage: { status: 'partial', truncated: false, missingReasons: ['input-events-partial', 'effect-unverified'] }, effect: 'unverified',
  } };
}
export function markerObservation(): Observation & { payload: TextSnapshot } {
  const message = observation();
  return { ...message, payload: { ...(message.payload as TextSnapshot), source: 'ax.marker', rangeBasis: 'prefix', gate: gate() } };
}
const mutate = (value: unknown, edit: (copy: any) => void): unknown => { const copy = structuredClone(value); edit(copy); return copy; };
const valid = (name: string, value: unknown): ContractCase => ({ name: `multi-${name}`, valid: true, value });
const invalid = (name: string, edit: (copy: any) => void, value: unknown = surfaceObservation()): ContractCase => ({ name: `multi-${name}`, valid: false, value: mutate(value, edit) });
const edited = (name: string, edit: (copy: any) => void, value: unknown = surfaceObservation()): ContractCase => valid(name, mutate(value, edit));
const relation = () => ({ basis: 'temporal-same-surface', evidenceIds: ['earlier-synthetic:1'], effect: 'unverified' });

export function captureDiagnosticsState(): State & { captureDiagnostics: CaptureDiagnostics } {
  return { protocolVersion: 1, type: 'state', requestId: 'diagnostics-state', instanceId: 'fixture-1', state: 'running', stamp: { ...observation().stamp }, reason: '',
    captureDiagnostics: { axEnablement: 'enabled', axAttribute: 'manual', observer: 'best-effort' } };
}
export const multiSourceCases: ContractCase[] = [
  valid('diagnostics-state', captureDiagnosticsState()),
  invalid('diagnostics-extra-provider-content', x => { x.captureDiagnostics.error = 'SYNTHETIC_PRIVATE'; }, captureDiagnosticsState()),

  edited('policy-all-options', x => { Object.assign(x.policy, { applicationScope: 'denylist', excludedApplicationIds: ['test.excluded'], allowBrowserContent: true, axCompatibility: true, textMarkers: true, captureScope: 'window', maxTreeNodes: 96, inputText: true, selectionCapture: true, fieldSecurity: 'denylist' }); }, configure()),
  edited('policy-overlap-deny-wins', x => { x.policy.excludedApplicationIds = [...x.policy.allowedApplicationIds]; }, configure()),
  invalid('policy-case-duplicate', x => { x.policy.allowedApplicationIds = ['test.App', 'TEST.app']; }, configure()),
  invalid('policy-excluded-case-duplicate', x => { x.policy.excludedApplicationIds = ['test.App', 'TEST.app']; }, configure()),
  invalid('policy-invalid-application-id', x => { x.policy.allowedApplicationIds = ['test.app\n']; }, configure()),
  invalid('policy-invalid-excluded-id', x => { x.policy.excludedApplicationIds = ['test/secret']; }, configure()),
  invalid('policy-scope-unknown', x => { x.policy.captureScope = 'application'; }, configure()),
  invalid('policy-tree-budget-minimum', x => { x.policy.maxTreeNodes = 0; }, configure()),
  invalid('policy-tree-budget-maximum', x => { x.policy.maxTreeNodes = 97; }, configure()),

  valid('marker-prefix', markerObservation()),
  edited('marker-visible', x => { x.payload.source = 'ax.marker'; x.payload.gate = gate(); }, visibleRangeObservation()),
  invalid('marker-without-gate', x => { delete x.payload.gate; }, markerObservation()),

  valid('surface-full', surfaceObservation()),
  valid('surface-diff-materialized', surfaceDiffObservation()),
  edited('surface-fixture-source', x => { x.payload.source = 'fixture'; }),
  edited('surface-uia-tree-source', x => { x.payload.source = 'uia.tree'; }),
  edited('surface-empty-window', x => { x.payload.scope = 'window'; x.payload.nodes = []; }),
  edited('surface-complete-removed', x => { x.payload.coverage = { status: 'complete', truncated: false, missingReasons: [] }; x.payload.changes.removed = ['old-node']; }, surfaceDiffObservation()),
  edited('surface-budget-and-roles', x => {
    x.payload.nodes = Array.from({ length: 96 }, (_, i) => ({ id: `node-${i}`, ...(i > 0 ? { parentId: `node-${i - 1}` } : {}), role: ['container', 'text', 'editable', 'terminal', 'other'][i % 5], observedAtMs: 100 }));
    x.payload.nodes[95].text = '🙂'.repeat(4096);
  }),
  edited('surface-unicode-id-byte-distinct', x => { x.payload.nodes = [{ id: 'é', role: 'container', observedAtMs: 100 }, { id: 'e\u0301', parentId: 'é', role: 'text', text: '合成', observedAtMs: 101 }]; }),
  edited('surface-special-map-ids', x => { x.payload.nodes[0].id = '__proto__'; x.payload.nodes[1].parentId = '__proto__'; x.payload.nodes[1].id = 'constructor'; }),
  invalid('surface-duplicate-node', x => { x.payload.nodes.push({ ...x.payload.nodes[1] }); }),
  invalid('surface-two-node-cycle', x => { x.payload.nodes[0].parentId = 'text'; }),
  invalid('surface-missing-parent', x => { x.payload.nodes[1].parentId = 'old-node'; }),
  invalid('surface-total-utf16-not-codepoints', x => { x.payload.nodes[0].text = '🙂'.repeat(2048); x.payload.nodes[1].text = '🙂'.repeat(2049); }),
  invalid('surface-too-many-nodes', x => { x.payload.nodes = Array.from({ length: 97 }, (_, i) => ({ id: `node-${i}`, role: 'container', observedAtMs: 100 })); }),
  ...[99, 102].map(time => invalid(`surface-observed-outside-${time}`, x => { x.payload.nodes[1].observedAtMs = time; })),
  invalid('surface-backward-time', x => { x.payload.captureEndMs = 99; }),
  invalid('surface-full-with-base', x => { x.payload.baseRevision = 1; }),
  invalid('surface-full-with-changes', x => { x.payload.changes = { added: [], updated: [], removed: [] }; }),
  invalid('surface-diff-missing-base', x => { delete x.payload.baseRevision; }, surfaceDiffObservation()),
  invalid('surface-diff-missing-changes', x => { delete x.payload.changes; }, surfaceDiffObservation()),
  invalid('surface-diff-nonpreceding-base', x => { x.payload.baseRevision = 2; }, surfaceDiffObservation()),
  invalid('surface-diff-duplicate-change', x => { x.payload.changes.added = ['text', 'text']; }, surfaceDiffObservation()),
  invalid('surface-diff-added-updated-overlap', x => { x.payload.changes.updated = ['text']; }, surfaceDiffObservation()),
  invalid('surface-diff-removed-current', x => { x.payload.coverage = { status: 'complete', truncated: false, missingReasons: [] }; x.payload.changes = { added: [], updated: [], removed: ['text'] }; }, surfaceDiffObservation()),
  ...['added', 'updated'].map(field => invalid(`surface-diff-${field}-not-current`, x => { x.payload.changes[field] = ['old-node']; }, surfaceDiffObservation())),
  invalid('surface-diff-partial-removal', x => { x.payload.changes.removed = ['old-node']; }, surfaceDiffObservation()),
  invalid('surface-diff-parent-in-old-nodes', x => { x.payload.nodes = [x.payload.nodes[1]]; x.payload.changes.updated = []; }, surfaceDiffObservation()),
  invalid('surface-partial-no-reason', x => { x.payload.coverage.missingReasons = []; }),
  invalid('surface-complete-has-reason', x => { x.payload.coverage.status = 'complete'; }),
  invalid('surface-extra-node-field', x => { x.payload.nodes[1].title = 'synthetic-private'; }),
  invalid('surface-atomic-claim', x => { x.payload.consistency = 'atomic'; }),

  valid('selection', selectionObservation()),
  edited('selection-uia-text-source', x => { x.payload.source = 'uia.text'; }, selectionObservation()),
  valid('selection-empty-safe-end', selectionObservation('', Number.MAX_SAFE_INTEGER)),
  valid('selection-utf16-budget', selectionObservation('🙂'.repeat(4096))),
  invalid('selection-text-length-mismatch', x => { x.payload.range.length--; }, selectionObservation()),
  invalid('selection-range-overflow', x => { x.payload.range.start = Number.MAX_SAFE_INTEGER - 1; }, selectionObservation()),
  invalid('selection-backward-time', x => { x.payload.captureStartMs = 102; }, selectionObservation()),
  invalid('selection-complete-claim', x => { x.payload.coverage = { status: 'complete', truncated: false, missingReasons: [] }; }, selectionObservation()),
  invalid('selection-missing-reason', x => { x.payload.coverage.missingReasons = ['text-budget']; }, selectionObservation()),
  invalid('selection-text-over-budget', () => {}, selectionObservation('🙂'.repeat(4097))),

  valid('input-text-unicode', inputTextObservation()),
  edited('input-text-win32-unicode', x => { x.payload.source = 'win32.unicode'; }, inputTextObservation()),
  edited('input-return', x => { x.payload.eventKind = 'return'; x.payload.text = ''; }, inputTextObservation()),
  ...['command', 'control'].map(modifier => edited(`input-shortcut-${modifier}`, x => { x.payload.eventKind = 'shortcut'; x.payload.text = ''; x.payload.modifiers = [modifier]; }, inputTextObservation())),
  edited('input-budget', x => { x.payload.text = '🙂'.repeat(1024); x.payload.eventCount = 256; x.payload.intervalEndMs = x.eventTimeMs = 5100; }, inputTextObservation()),
  invalid('input-empty-text', () => {}, inputTextObservation('')),
  invalid('input-text-command', x => { x.payload.modifiers = ['command']; }, inputTextObservation()),
  invalid('input-return-has-body', x => { x.payload.eventKind = 'return'; }, inputTextObservation()),
  invalid('input-shortcut-no-command', x => { x.payload.eventKind = 'shortcut'; x.payload.text = ''; x.payload.modifiers = ['option', 'shift']; }, inputTextObservation()),
  invalid('input-duplicate-modifier', x => { x.payload.modifiers = ['shift', 'shift']; }, inputTextObservation()),
  invalid('input-backward-time', x => { x.payload.intervalEndMs = x.eventTimeMs = 99; }, inputTextObservation()),
  invalid('input-negative-start', x => { x.payload.intervalStartMs = -1; }, inputTextObservation()),
  invalid('input-too-long-interval', x => { x.payload.intervalEndMs = x.eventTimeMs = 5101; }, inputTextObservation()),
  invalid('input-wrong-envelope-time', x => { x.eventTimeMs++; }, inputTextObservation()),
  invalid('input-too-much-text', () => {}, inputTextObservation('🙂'.repeat(1025))),
  ...[0, 257, 1.5].map((value, i) => invalid(`input-count-malformed-${i}`, x => { x.payload.eventCount = value; }, inputTextObservation())),
  ...['input-events-partial', 'effect-unverified'].map(reason => invalid(`input-missing-${reason}`, x => { x.payload.coverage.missingReasons = x.payload.coverage.missingReasons.filter((item: string) => item !== reason); }, inputTextObservation())),
  invalid('input-secure-active', x => { x.payload.secureInput = 'active'; }, inputTextObservation()),
  invalid('input-claims-effect', x => { x.payload.effect = 'confirmed'; }, inputTextObservation()),
  invalid('input-keycode-leak', x => { x.payload.keyCode = 42; }, inputTextObservation()),

  // All content channels use the same gate and resolved-target guard. Exercise
  // routing per kind; test each shared failure once, not kind × failure products.
  ...[surfaceObservation(), selectionObservation(), inputTextObservation()].map((message, i) => invalid(`content-${i}-fixture-missing-gate`, x => { x.payload.source = 'fixture'; delete x.payload.gate; }, message)),
  edited('content-user-authorized', x => { x.payload.gate.privateState = 'user-authorized'; }),
  edited('content-not-declared-sensitive', x => { x.payload.gate.secure = 'not-declared-sensitive'; }),
  invalid('content-self-grant', x => { x.payload.gate.fieldSecurity = 'denylist'; }),
  invalid('content-stale-gate', x => { x.payload.gate.policyRevision++; }),
  invalid('content-secure-sensitive', x => { x.payload.gate.secure = 'sensitive'; }),
  invalid('content-private-unknown', x => { x.payload.gate.privateState = 'unknown'; }),
  invalid('content-agent', x => { x.actor = 'agent'; x.relatedActionIds = ['action-1']; }),
  invalid('content-action-correlation', x => { x.relatedActionIds = ['action-1']; }),
  invalid('content-unresolved', x => { x.target = { kind: 'unresolved', reason: 'focus-unavailable' }; }),
  invalid('content-application-only', x => { x.target.kind = 'application'; delete x.target.identity.windowId; delete x.target.identity.windowGeneration; }),

  edited('content-relation', x => { x.relation = relation(); }),
  invalid('relation-duplicate', x => { x.relation = { ...relation(), evidenceIds: ['prior:1', 'prior:1'] }; }),
  invalid('relation-self', x => { x.relation = { ...relation(), evidenceIds: [x.eventId] }; }),
  invalid('relation-empty', x => { x.relation = { ...relation(), evidenceIds: [] }; }),
  invalid('relation-too-many', x => { x.relation = { ...relation(), evidenceIds: ['prior:1', 'prior:2', 'prior:3', 'prior:4', 'prior:5'] }; }),
  invalid('relation-claims-effect', x => { x.relation = { ...relation(), effect: 'confirmed' }; }),
  invalid('relation-on-gap', x => { x.relation = relation(); x.payload = { kind: 'gap', reason: 'read-error', count: 1 }; }),
  invalid('relation-on-input-activity', x => { x.relation = relation(); }, inputActivity()),
];

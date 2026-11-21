import type { CapturePolicy, Configure, Control, Observation, TargetIdentity, TextSnapshot, WireMessage } from '../../src/shared/protocol/generated.ts';

export const target: TargetIdentity = { deviceId: 'synthetic-mac', osSessionId: 'synthetic-user', desktopId: 'desktop-1', processId: 42, processStartTime: 'birth-1', applicationId: 'test.allowed', windowId: '9007199254740993', windowGeneration: 1 };
export const policy: CapturePolicy = { enabled: true, allowedApplicationIds: ['test.allowed'], maxTextCodeUnits: 4096, maxPending: 16, debounceMs: 10, maxWaitMs: 100, readTimeoutMs: 200 };
export function configure(revision = 1, enabled = true): Configure { return { protocolVersion: 1, type: 'configure', requestId: `cfg-${revision}`, ownerId: 'host-1', instanceId: 'fixture-1', policyRevision: revision, policy: { ...policy, enabled } }; }
export function control(command: Control['command'], revision = 1): Control { return { protocolVersion: 1, type: 'control', requestId: command, ownerId: 'host-1', instanceId: 'fixture-1', policyRevision: revision, command, leaseDurationMs: 1000 }; }
export function textSnapshot(text = '你好🙂'): TextSnapshot { return { kind: 'text.snapshot', snapshotId: 's-1', editSessionId: 'edit-1', nodeId: 'field-1', source: 'fixture', scope: 'field', valueState: 'read', text, range: { unit: 'utf16', start: 0, length: text.length }, totalLength: text.length, composition: 'unknown', captureStartMs: 100, captureEndMs: 101, coverage: { status: 'complete', truncated: false, missingReasons: [] } }; }
export function observation(text = '你好🙂'): Observation { return { protocolVersion: 1, type: 'observation', eventId: 'fixture-1:1', instanceId: 'fixture-1', seq: 1, eventTimeMs: 101, monotonicMs: 1, target: { kind: 'resolved', identity: { ...target } }, stamp: { captureEpoch: 1, foregroundGeneration: 1, focusGeneration: 1, policyRevision: 1 }, actor: 'unknown', relatedActionIds: [], payload: textSnapshot(text) }; }
export const messages: WireMessage[] = [
  { protocolVersion: 1, type: 'hello', instanceId: 'fixture-1', maxFrameBytes: 65536, capabilities: [{ name: 'text.snapshot', direction: 'observe', scope: 'app-local', support: 'supported', reason: 'synthetic-only' }, { name: 'gesture.pinch', direction: 'act', scope: 'authorized-desktop', support: 'unknown', reason: 'not-implemented' }] },
  configure(),
  { protocolVersion: 1, type: 'configured', requestId: 'cfg-1', ownerId: 'host-1', instanceId: 'fixture-1', policyRevision: 1 },
  control('start'),
  { protocolVersion: 1, type: 'state', requestId: 'start', instanceId: 'fixture-1', state: 'running', stamp: { captureEpoch: 1, foregroundGeneration: 0, focusGeneration: 0, policyRevision: 1 }, reason: '' },
  observation(), observation(''),
  { ...observation(), eventId: 'fixture-1:2', seq: 2, payload: { kind: 'text.changed', baseSnapshotId: 's-0', after: textSnapshot('変更') } },
  { ...observation(), target: { kind: 'unresolved', reason: 'policy-boundary' }, payload: { kind: 'gap', reason: 'stale', count: 1 } },
  { protocolVersion: 1, type: 'action.request', requestId: 'r-1', actionId: 'a-1', target: { ...target }, stamp: { captureEpoch: 1, foregroundGeneration: 1, focusGeneration: 1, policyRevision: 1 }, snapshotId: 'live-snapshot', backendId: 'synthetic', runtimeGeneration: 1, deadlineMs: 1000, sessionId: 'session-1', agentId: 'agent-1', grantId: 'host-bound', leaseId: 'lease-1', mode: 'background', expectedCondition: 'synthetic-value-equals', action: { kind: 'text.set', text: 'synthetic content only' } },
  { protocolVersion: 1, type: 'action.receipt', requestId: 'r-1', actionId: 'a-1', dispatch: 'unknown', effect: 'uncertain', startedMs: 100, endedMs: 200, route: 'synthetic', evidenceIds: [], reason: 'timeout' },
  { protocolVersion: 1, type: 'action.receipt', requestId: 'r-2', actionId: 'a-2', dispatch: 'dispatched', effect: 'confirmed', startedMs: 100, endedMs: 200, route: 'synthetic', evidenceIds: ['postcondition-1'], reason: '' },
  { protocolVersion: 1, type: 'error', requestId: 'bad-request', code: 'unsupported', retryable: false },
];

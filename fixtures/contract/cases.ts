import { messages, observation } from './examples.ts';
import { inputActivityCases } from './input-activity.ts';
import { textRangeCases } from './text-range.ts';
import { multiSourceCases } from './multi-source.ts';
import { surfaceGeometryCases } from './surface-geometry.ts';
import { granularGapDiagnostics } from './gap-diagnostics.ts';

export interface ContractCase { name: string; valid: boolean; value: unknown }
const mutate = (value: unknown, edit: (copy: any) => void): unknown => { const copy = structuredClone(value); edit(copy); return copy; };
const gapDiagnosticRoundtrips = [...granularGapDiagnostics, ['input-context-unverified', 'stale'], ['surface-boundary-unverified', 'read-error']] as const;
export const cases: ContractCase[] = [
  ...surfaceGeometryCases,
  ...messages.map((value, index) => ({ name: `valid-${index}-${value.type}`, valid: true, value })),
  { name: 'native-with-gate', valid: true, value: mutate(observation(), x => { x.payload.source = 'ax.range'; x.payload.gate = { secure: 'safe', privateState: 'normal', policyRevision: x.stamp.policyRevision }; }) },
  { name: 'native-without-gate', valid: false, value: mutate(observation(), x => { x.payload.source = 'ax.range'; }) },
  { name: 'native-unknown-gate', valid: false, value: mutate(observation(), x => { x.payload.source = 'ax.range'; x.payload.gate = { secure: 'unknown', privateState: 'normal', policyRevision: x.stamp.policyRevision }; }) },
  { name: 'native-stale-gate', valid: false, value: mutate(observation(), x => { x.payload.source = 'ax.range'; x.payload.gate = { secure: 'safe', privateState: 'normal', policyRevision: 999 }; }) },
  { name: 'unknown-version', valid: false, value: { ...messages[0], protocolVersion: 2 } },
  { name: 'unknown-property', valid: false, value: { ...messages[0], authorized: true } },
  // One sample per schema primitive/shape, not a repeated matrix per field.
  { name: 'boolean-not-integer', valid: false, value: mutate(observation(), x => { x.seq = true; }) },
  { name: 'number-not-boolean', valid: false, value: mutate(messages[1], x => { x.policy.enabled = 1; }) },
  { name: 'number-not-string', valid: false, value: { ...messages[0], instanceId: 1 } },
  { name: 'empty-identity', valid: false, value: { ...messages[0], instanceId: '' } },
  { name: 'object-not-array', valid: false, value: { ...messages[0], capabilities: {} } },
  { name: 'null-policy', valid: false, value: mutate(messages[1], x => { x.policy = null; }) },
  { name: 'unsafe-integer', valid: false, value: mutate(observation(), x => { x.seq = 9007199254740992; }) },
  { name: 'zero-seq', valid: false, value: mutate(observation(), x => { x.seq = 0; }) },
  { name: 'wrong-text-unit', valid: false, value: mutate(observation(), x => { x.payload.range.unit = 'utf8'; }) },
  { name: 'emoji-range-codepoints-not-utf16', valid: false, value: mutate(observation(), x => { x.payload.range.length = 3; }) },
  { name: 'missing-text', valid: false, value: mutate(observation(), x => { delete x.payload.text; }) },
  { name: 'redacted-with-body', valid: false, value: mutate(observation(), x => { x.payload.valueState = 'redacted'; }) },
  { name: 'partial-without-reason', valid: false, value: mutate(observation(), x => { x.payload.coverage.status = 'partial'; }) },
  { name: 'complete-but-truncated', valid: false, value: mutate(observation(), x => { x.payload.coverage.truncated = true; }) },
  { name: 'backwards-capture', valid: false, value: mutate(observation(), x => { x.payload.captureEndMs = 1; }) },
  { name: 'unresolved-text', valid: false, value: mutate(observation(), x => { x.target = { kind: 'unresolved', reason: 'focus-unavailable' }; }) },
  { name: 'agent-without-action', valid: false, value: mutate(observation(), x => { x.actor = 'agent'; }) },
  { name: 'same-delta-baseline', valid: false, value: mutate(messages[7], x => { x.payload.baseSnapshotId = x.payload.after.snapshotId; }) },
  { name: 'confirmed-without-evidence', valid: false, value: mutate(messages[11], x => { x.evidenceIds = []; }) },
  { name: 'unknown-dispatch-success', valid: false, value: mutate(messages[11], x => { x.dispatch = 'unknown'; }) },
  { name: 'refused-after-dispatch', valid: false, value: mutate(messages[11], x => { x.effect = 'refused'; }) },
  { name: 'invalid-debounce', valid: false, value: mutate(messages[1], x => { x.policy.maxWaitMs = 1; }) },
  { name: 'extra-nested-field', valid: false, value: mutate(messages[9], x => { x.action.script = 'never-executed'; }) },
  { name: 'read-range-past-total', valid: false, value: mutate(observation(), x => { x.payload.totalLength = 1; }) },
  { name: 'excess-text', valid: false, value: observation('中'.repeat(8193)) },
  { name: 'prototype-constructor-key', valid: false, value: JSON.parse(JSON.stringify({ ...messages[0], constructor: 'unexpected' })) },
  { name: 'prototype-proto-key', valid: false, value: JSON.parse(JSON.stringify(messages[0]).replace('"instanceId"', '"__proto__":{},"instanceId"')) },
  { name: 'null', valid: false, value: null },
  { name: 'array', valid: false, value: [] },
  { name: 'gap-specific-nontext-role', valid: true, value: mutate(observation(), x => { x.target = {kind:'unresolved',reason:'policy-boundary'}; x.payload={kind:'gap',reason:'policy-boundary',count:1,diagnostic:{code:'focused-role-not-text',role:'AXMenuItem'}}; }) },
  { name: 'gap-explicit-provider-unresolved-target', valid: true, value: mutate(observation(), x => { x.target={kind:'unresolved',reason:'focus-unavailable'}; x.payload={kind:'gap',reason:'read-error',count:3,providerApplicationId:'com.example.current-provider',diagnostic:{code:'focused-field-unavailable'}}; }) },
  { name: 'gap-provider-rejects-non-id', valid: false, value: mutate(observation(), x => { x.payload={kind:'gap',reason:'stale',count:1,providerApplicationId:'com.example.provider\n'}; }) },
  { name: 'gap-specific-security-no-role', valid: true, value: mutate(observation(), x => { x.payload={kind:'gap',reason:'policy-boundary',count:1,diagnostic:{code:'field-security-unknown'}}; }) },
  { name: 'gap-diagnostic-rejects-user-code', valid: false, value: mutate(observation(), x => { x.payload={kind:'gap',reason:'policy-boundary',count:1,diagnostic:{code:'SYNTHETIC_PRIVATE'}}; }) },
  { name: 'gap-diagnostic-rejects-raw-role', valid: false, value: mutate(observation(), x => { x.payload={kind:'gap',reason:'policy-boundary',count:1,diagnostic:{code:'focused-role-not-text',role:'AXPrivateDocument'}}; }) },
  { name: 'gap-diagnostic-rejects-body', valid: false, value: mutate(observation(), x => { x.payload={kind:'gap',reason:'policy-boundary',count:1,diagnostic:{code:'secure-field',text:'SYNTHETIC_PRIVATE'}}; }) },
  { name: 'gap-diagnostic-rejects-null', valid: false, value: mutate(observation(), x => { x.payload={kind:'gap',reason:'policy-boundary',count:1,diagnostic:null}; }) },
  // Cross-language rollout cases for new distinctions and old generic records.
  ...gapDiagnosticRoundtrips.map(([code, reason]) => ({
    name: `gap-diagnostic-roundtrip-${code}`, valid: true,
    value: { ...observation(), target: { kind: 'unresolved', reason: 'focus-unavailable' }, payload: { kind: 'gap', reason, count: 2, diagnostic: { code } } },
  })),
  { name: 'detailed-gap-rejects-raw-boundary-data', valid: false, value: mutate(observation(), x => {
    x.payload = { kind: 'gap', reason: 'read-error', count: 1, diagnostic: { code: 'surface-boundary-ax-failed', path: 'SYNTHETIC_PRIVATE' } };
  }) },
  ...inputActivityCases,
  ...textRangeCases,
  ...multiSourceCases,
];

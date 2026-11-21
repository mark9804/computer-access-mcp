import type { Gap, GapDiagnostic } from '../../src/shared/protocol/generated.ts';

/** Expected native broad reasons for the seven new, metadata-only diagnoses. */
export const granularGapDiagnostics = [
  ['input-target-mismatch', 'stale'],
  ['input-role-not-editable', 'stale'],
  ['input-verification-timeout', 'stale'],
  ['input-field-security-unknown', 'stale'],
  ['surface-boundary-mismatch', 'read-error'],
  ['surface-boundary-ax-failed', 'read-error'],
  ['surface-boundary-incomplete', 'read-error'],
] as const satisfies readonly (readonly [GapDiagnostic['code'], Gap['reason']])[];

import type { Gap, GapDiagnostic } from './protocol/generated.ts';

export type GapDisposition = 'discarded' | 'exception';

// Exhaustive diagnostic code classification: expected focus/policy/security discards vs real capture exceptions.
export const GAP_DIAGNOSTIC_DISPOSITION: Readonly<Record<GapDiagnostic['code'], GapDisposition>> = Object.freeze({
  'focus-changed': 'discarded',
  'input-target-mismatch': 'discarded',
  'surface-boundary-mismatch': 'discarded',
  'input-role-not-editable': 'discarded',
  'focused-field-unavailable': 'discarded',
  'focused-role-not-text': 'discarded',
  'input-context-unverified': 'discarded',
  'surface-boundary-unverified': 'discarded',
  'application-not-allowed': 'discarded',
  'browser-excluded': 'discarded',
  'secure-field': 'discarded',
  'field-security-unknown': 'discarded',
  'input-field-security-unknown': 'discarded',
  'input-policy-boundary': 'discarded',
  'surface-security-excluded': 'discarded',
  'desktop-unavailable': 'discarded',

  'read-deadline': 'exception',
  'surface-time-budget': 'exception',
  'surface-call-budget': 'exception',
  'surface-not-started-budget': 'exception',
  'input-verification-timeout': 'exception',
  'input-text-budget': 'exception',
  'input-text-backpressure': 'exception',
  'input-text-read-unavailable': 'exception',
  'accessibility-denied': 'exception',
  'application-unavailable': 'exception',
  'visible-range-unavailable': 'exception',
  'text-read-unavailable': 'exception',
  'text-result-invalid': 'exception',
  'invalid-sampling-policy': 'exception',
  'capture-authority-changed': 'exception',
  'worker-retirement-pending': 'exception',
  'surface-anchor-unavailable': 'exception',
  'surface-boundary-ax-failed': 'exception',
  'surface-boundary-incomplete': 'exception',
  'surface-provider-unavailable': 'exception',
});

// Fallback classification when a legacy or undiagnosed gap omits `diagnostic`.
export const GAP_REASON_DISPOSITION: Readonly<Record<Gap['reason'], GapDisposition>> = Object.freeze({
  'policy-boundary': 'discarded',
  stale: 'discarded',
  'desktop-unavailable': 'discarded',

  timeout: 'exception',
  'read-error': 'exception',
  budget: 'exception',
  backpressure: 'exception',
  'host-lost': 'exception',
  'baseline-unavailable': 'exception',
});

export function classifyGap(gap: Pick<Gap, 'reason' | 'diagnostic'>): GapDisposition {
  if (gap.diagnostic !== undefined) {
    return GAP_DIAGNOSTIC_DISPOSITION[gap.diagnostic.code];
  }
  return GAP_REASON_DISPOSITION[gap.reason];
}

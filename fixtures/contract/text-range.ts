import type { Observation, TextSnapshot } from '../../src/shared/protocol/generated.ts';
import type { ContractCase } from './cases.ts';
import { configure, observation, textSnapshot } from './examples.ts';

// Absolute UTF16 ranges, not offsets into the retained substring.
export function visibleRangeSnapshot(text = '可见🙂', start = 10, totalLength = 40): TextSnapshot {
  return {
    ...textSnapshot(text), rangeBasis: 'visible', scope: 'accessible-range',
    range: { unit: 'utf16', start, length: text.length }, totalLength,
    coverage: { status: 'partial', truncated: false, missingReasons: ['visible-range-only'] },
  };
}
export function visibleRangeObservation(text = '可见🙂', start = 10, totalLength = 40): Observation & { payload: TextSnapshot } {
  return { ...observation(), payload: visibleRangeSnapshot(text, start, totalLength) };
}
const mutate = (value: unknown, edit: (copy: any) => void): unknown => { const copy = structuredClone(value); edit(copy); return copy; };
const valid = (name: string, value: unknown): ContractCase => ({ name: `range-${name}`, valid: true, value });
const invalid = (name: string, edit: (copy: any) => void, value: unknown = visibleRangeObservation()): ContractCase => ({ name: `range-${name}`, valid: false, value: mutate(value, edit) });

export const textRangeCases: ContractCase[] = [
  valid('policy-visible-interval-min', mutate(configure(), x => { x.policy.textRange = 'visible'; x.policy.sampleIntervalMs = 1000; })),
  valid('policy-prefix-interval-max', mutate(configure(), x => { x.policy.textRange = 'prefix'; x.policy.sampleIntervalMs = 30000; })),
  ...[999, 1000.5, 30001].map(value => invalid(`policy-interval-${value}`, x => { x.policy.sampleIntervalMs = value; }, configure())),
  valid('legacy-nonzero-accessible-range', mutate(visibleRangeObservation(), x => { delete x.payload.rangeBasis; x.payload.selection = { unit: 'utf16', start: 30, length: 1 }; })),
  valid('explicit-prefix', mutate(observation(), x => { x.payload.rangeBasis = 'prefix'; })),
  invalid('explicit-prefix-nonzero', x => { x.payload.rangeBasis = 'prefix'; }),
  valid('visible-fixture', visibleRangeObservation()),
  valid('visible-uia-text', mutate(visibleRangeObservation(), x => { x.payload.source = 'uia.text'; x.payload.gate = { secure: 'safe', privateState: 'normal', policyRevision: 1 }; })),
  valid('visible-empty-field-caret', mutate(visibleRangeObservation('', 0, 0), x => { x.payload.selection = { unit: 'utf16', start: 0, length: 0 }; })),
  valid('visible-max-text-and-selection', mutate(visibleRangeObservation('🙂'.repeat(4096), 100, 8292), x => { x.payload.selection = { unit: 'utf16', start: 100, length: 8192 }; })),
  valid('visible-safe-end-caret', mutate(visibleRangeObservation('可见🙂', Number.MAX_SAFE_INTEGER - 4, Number.MAX_SAFE_INTEGER), x => { x.payload.selection = { unit: 'utf16', start: Number.MAX_SAFE_INTEGER, length: 0 }; })),
  valid('visible-text-changed', mutate(visibleRangeObservation(), x => { x.payload = { kind: 'text.changed', baseSnapshotId: 'earlier-synthetic', after: x.payload }; })),
  invalid('visible-missing-total', x => { delete x.payload.totalLength; }),
  invalid('visible-value-not-range-source', x => { x.payload.source = 'ax.value'; x.payload.gate = { secure: 'safe', privateState: 'normal', policyRevision: 1 }; }),
  invalid('visible-uia-value', x => { x.payload.source = 'uia.value'; x.payload.gate = { secure: 'safe', privateState: 'normal', policyRevision: 1 }; }),
  invalid('visible-field-scope', x => { x.payload.scope = 'field'; }),
  invalid('visible-redacted', x => { x.payload.valueState = 'redacted'; delete x.payload.text; delete x.payload.range; delete x.payload.totalLength; }),
  invalid('visible-complete', x => { x.payload.coverage = { status: 'complete', truncated: false, missingReasons: [] }; }),
  invalid('visible-missing-reason', x => { x.payload.coverage.missingReasons = ['text-budget']; }),
  invalid('visible-empty-nonempty-total', x => { x.payload.text = ''; x.payload.range.length = 0; }),
  invalid('visible-range-past-total', x => { x.payload.totalLength = 13; }),
  invalid('visible-range-unsafe-sum', x => { x.payload.range.start = Number.MAX_SAFE_INTEGER - 3; x.payload.totalLength = Number.MAX_SAFE_INTEGER; }),
  invalid('visible-codepoints-not-utf16', x => { x.payload.range.length = 3; }),
  invalid('visible-text-too-long', () => {}, visibleRangeObservation('🙂'.repeat(4097), 10, 10000)),
  invalid('visible-selection-before', x => { x.payload.selection = { unit: 'utf16', start: 9, length: 1 }; }),
  invalid('visible-selection-after', x => { x.payload.selection = { unit: 'utf16', start: 15, length: 0 }; }),
  invalid('visible-selection-crosses-end', x => { x.payload.selection = { unit: 'utf16', start: 11, length: 4 }; }),
  invalid('legacy-selection-overflow', x => { x.payload.selection = { unit: 'utf16', start: Number.MAX_SAFE_INTEGER, length: 1 }; delete x.payload.rangeBasis; delete x.payload.totalLength; }),
  invalid('visible-changed-invalid-after', x => { x.payload.totalLength = 11; x.payload = { kind: 'text.changed', baseSnapshotId: 'earlier-synthetic', after: x.payload }; }),
];

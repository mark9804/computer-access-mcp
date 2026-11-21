import assert from 'node:assert/strict';
import test from 'node:test';
import { geometryObservation } from '../../fixtures/contract/surface-geometry.ts';
import { validateMessage } from '../../src/shared/protocol/validate.ts';

// JSON-representable geometry cases run once in protocol.test.ts. Nonfinite
// numbers need a runtime test: JSON serialization would silently replace them.
test('surface geometry refuses nonfinite coordinates before serialization', () => {
  for (const value of [NaN, Infinity, -Infinity]) {
    const record = geometryObservation(); record.payload.nodes[1]!.bounds!.x = value;
    assert.throws(() => validateMessage(record), { code: 'invalid-message' });
  }
});

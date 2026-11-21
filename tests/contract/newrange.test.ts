import test from 'node:test';
import assert from 'node:assert/strict';
import { ProtocolError, validateMessage } from '../../src/shared/protocol/validate.ts';
import { configure } from '../../fixtures/contract/examples.ts';

// Offset, coverage, optional legacy fields and bounds are shared contract cases.
// Keep only JS-runtime inputs that cannot travel through the JSON fixture corpus.
test('interval and range basis reject runtime non-JSON numbers and accessors', () => {
  for (const value of [NaN, Infinity, -Infinity, undefined]) {
    assert.throws(() => validateMessage({ ...configure(), policy: { ...configure().policy, sampleIntervalMs: value } }), ProtocolError);
  }
  const message = configure();
  let invoked = false;
  Object.defineProperty(message.policy, 'textRange', { get: () => { invoked = true; throw new Error('must-not-execute'); }, enumerable: true });
  assert.throws(() => validateMessage(message), ProtocolError);
  assert.equal(invoked, false);
});

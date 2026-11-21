import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeFrame, ProtocolError, validateMessage } from '../../src/shared/protocol/validate.ts';
import { inputTextObservation, surfaceObservation } from '../../fixtures/contract/multi-source.ts';

// Shared JSON examples run once in protocol.test.ts and through both actual
// language decoders in test-cross-language.mjs. Only JS-runtime-only behavior
// belongs here: accessors/non-JSON values cannot be represented in JSON fixtures.
test('non-JSON runtime values, sparse nodes, getters and prototype pollution are refused without evaluation', () => {
  for (const value of [NaN, Infinity, -Infinity, undefined]) {
    const message = surfaceObservation();
    Object.assign(message.payload, { revision: value });
    assert.throws(() => validateMessage(message), ProtocolError);
  }
  const sparse = surfaceObservation();
  delete sparse.payload.nodes[0];
  assert.throws(() => validateMessage(sparse), ProtocolError);
  const accessor = surfaceObservation();
  let invoked = false;
  Object.defineProperty(accessor.payload.nodes[0]!, 'text', { enumerable: true, get: () => { invoked = true; throw new Error('must-not-evaluate'); } });
  assert.throws(() => validateMessage(accessor), ProtocolError);
  assert.equal(invoked, false);
  const polluted = JSON.parse(JSON.stringify(surfaceObservation()).replace('"role":"text"', '"role":"text","__proto__":{}'));
  assert.throws(() => validateMessage(polluted), ProtocolError);
});

test('serialization errors expose fixed protocol codes without reflecting content', () => {
  const message = inputTextObservation('SYNTHETIC_PRIVATE_SENTINEL');
  message.payload.eventKind = 'shortcut';
  assert.throws(() => encodeFrame(message), (error: unknown) => {
    assert.ok(error instanceof ProtocolError);
    assert.equal(error.code, 'invalid-message');
    assert.equal(error.message, 'invalid-message');
    assert.equal(String(error).includes(message.payload.text), false);
    return true;
  });
});

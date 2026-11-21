import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeFrame, encodeFrame, validateMessage } from '../../src/shared/protocol/validate.ts';
import { inputActivity } from '../../fixtures/contract/input-activity.ts';

test('input validation preserves frozen records and never rewrites gate, target or time', () => {
  const message = inputActivity();
  Object.freeze(message.payload.counts);
  Object.freeze(message.payload.gate);
  Object.freeze(message.payload.coverage.missingReasons);
  Object.freeze(message.payload.coverage);
  Object.freeze(message.payload);
  Object.freeze(message.target.identity);
  Object.freeze(message.target);
  Object.freeze(message);
  assert.equal(validateMessage(message), message);
  assert.deepEqual(decodeFrame(encodeFrame(message)), message);
});

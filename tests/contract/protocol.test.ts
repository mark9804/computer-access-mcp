import test from 'node:test';
import assert from 'node:assert/strict';
import { cases } from '../../fixtures/contract/cases.ts';
import { messages } from '../../fixtures/contract/examples.ts';
import { inputActivity } from '../../fixtures/contract/input-activity.ts';
import { menuAction } from '../../fixtures/contract/menu-action.ts';
import { inputTextObservation, selectionObservation, surfaceObservation } from '../../fixtures/contract/multi-source.ts';
import { decodeFrame, encodeFrame, FrameDecoder, ProtocolError, validateMessage } from '../../src/shared/protocol/validate.ts';

for (const fixture of cases) test(fixture.name, () => {
  if (fixture.valid) {
    const value = validateMessage(fixture.value);
    assert.equal(value, fixture.value);
    assert.deepEqual(decodeFrame(encodeFrame(value)), fixture.value);
  } else {
    assert.throws(() => validateMessage(fixture.value), ProtocolError);
  }
});
test('UTF8 frame roundtrip and fragmented NDJSON', () => {
  const allChannels = [...messages, inputActivity(), menuAction(), inputTextObservation(), selectionObservation(), surfaceObservation()];
  const data = Buffer.concat(allChannels.map(message => Buffer.from(encodeFrame(message))));
  const decoder = new FrameDecoder();
  const output = [];
  for (let start = 0; start < data.length; start += 7) output.push(...decoder.push(data.subarray(start, start + 7)));
  decoder.finish(); assert.deepEqual(output, allChannels);
});
test('invalid UTF8 and JSON errors do not echo content', () => {
  for (const bytes of [new Uint8Array([0xff]), Buffer.from('{"secret":"synthetic-sensitive"')]) {
    assert.throws(() => decodeFrame(bytes), error => error instanceof ProtocolError && error.message === 'invalid-message');
  }
});
test('hard frame budget and truncated stream fail closed', () => {
  assert.throws(() => decodeFrame(new Uint8Array(65537)), /frame-too-large/);
  const decoder = new FrameDecoder(); decoder.push(Buffer.from('{')); assert.throws(() => decoder.finish(), /invalid-message/);
});
test('lone surrogate and runtime non-JSON prototypes rejected', () => {
  assert.throws(() => validateMessage({ ...messages[0], instanceId: '\ud800' }), /invalid-message/);
  const value = Object.create(messages[0]!); assert.throws(() => validateMessage(value), /invalid-message/);
});

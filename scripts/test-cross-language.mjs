import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { cases } from '../fixtures/contract/cases.ts';
import { decodeFrame } from '../src/shared/protocol/validate.ts';

function swift(args) {
  const result = spawnSync('swift', args, { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  if (result.status !== 0) { process.stderr.write(result.stderr); throw new Error(`swift command failed: ${result.status}`); }
  return result.stdout.trim();
}
swift(['build', '--package-path', 'native/macos/contract', '--product', 'contract-check']);
const bin = join(swift(['build', '--package-path', 'native/macos/contract', '--show-bin-path']), 'contract-check');
const strings = cases.map(item => JSON.stringify(item.value));
strings.push('{"protocolVersion":1,"type":"hello","instanceId":"\\ud800","capabilities":[],"maxFrameBytes":65536}');
strings.push('not-json');
strings.push('{"protocolVersion":2,"bad":"\\ud800"}');
strings.push('{"protocolVersion":2,"bad":' + '['.repeat(33) + '0' + ']'.repeat(33) + '}');
strings.push('\ufeff' + JSON.stringify(cases[0].value));
strings.push('{"protocolVersion":1,"type":"hello","instanceId":"first","instanceId":"last","capabilities":[],"maxFrameBytes":65536}');
const expected = strings.map(text => {
  try { const value = decodeFrame(Buffer.from(text)); return { valid: true, message: value }; }
  catch (error) { return { valid: false, code: error.code }; }
});
// The central protocol test owns expected validity; this stage compares the
// independent decoders rather than rerunning the same object validation loop.
for (const [index, fixture] of cases.entries()) assert.equal(expected[index].valid, fixture.valid, fixture.name);
const result = spawnSync(bin, ['--validate-jsonl'], { input: strings.join('\n') + '\n', encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
assert.equal(result.status, 0, result.stderr);
const actual = result.stdout.trim().split('\n').map(line => JSON.parse(line));
assert.deepEqual(actual, expected);
console.log(`PASS: ${actual.length} shared valid/invalid fixtures agree in TypeScript and Swift, including canonical message roundtrips.`);

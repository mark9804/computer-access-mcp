import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import assert from 'node:assert/strict';
import { cases } from '../fixtures/contract/cases.ts';
import { decodeFrame } from '../src/shared/protocol/validate.ts';

function prependPath(env, dir) {
  const next = { ...env };
  const pathKey = Object.keys(next).find((k) => k.toLowerCase() === 'path') || 'PATH';
  const current = next[pathKey] || '';
  next[pathKey] = current ? `${dir};${current}` : dir;
  return next;
}

function resolveCargo() {
  if (process.platform === 'win32') {
    const check = spawnSync('where', ['cargo'], { encoding: 'utf8' });
    if (check.status !== 0) {
      const cargoHome =
        process.env.CARGO_HOME || (process.env.USERPROFILE ? join(process.env.USERPROFILE, '.cargo') : '');
      const candidate = cargoHome ? join(cargoHome, 'bin', 'cargo.exe') : '';
      if (candidate && existsSync(candidate)) {
        return {
          command: candidate,
          env: prependPath(process.env, dirname(candidate)),
        };
      }
    }
  }
  return { command: 'cargo', env: process.env };
}

function runTool(command, args, env) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
    ...(env ? { env } : {}),
  });
  if (result.error) throw result.error;
  if (result.status !== 0) { process.stderr.write(result.stderr ?? ''); throw new Error(`${command} command failed: ${result.status}`); }
  return result.stdout.trim();
}

function buildChecker() {
  if (process.platform === 'darwin') {
    runTool('swift', ['build', '--package-path', 'native/macos', '--product', 'contract-check']);
    const bin = join(runTool('swift', ['build', '--package-path', 'native/macos', '--show-bin-path']), 'contract-check');
    return { bin, language: 'Swift' };
  }
  if (process.platform === 'win32') {
    const cargo = resolveCargo();
    const manifest = 'native/windows/contract/Cargo.toml';
    runTool(cargo.command, ['build', '--release', '--manifest-path', manifest, '--bin', 'contract-check'], cargo.env);
    const metadata = JSON.parse(
      runTool(cargo.command, ['metadata', '--no-deps', '--format-version', '1', '--manifest-path', manifest], cargo.env),
    );
    const candidates = [
      join(metadata.target_directory, 'release', 'contract-check.exe'),
      join('native', 'windows', 'target', 'release', 'contract-check.exe'),
      join('native', 'windows', 'contract', 'target', 'release', 'contract-check.exe'),
    ];
    const bin = candidates.find(candidate => existsSync(candidate));
    if (!bin) throw new Error(`contract-check.exe not found in: ${candidates.join(', ')}`);
    return { bin, language: 'Rust' };
  }
  throw new Error(`Unsupported platform for cross-language contract test: ${process.platform}`);
}

const { bin, language } = buildChecker();
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
console.log(`PASS: ${actual.length} shared valid/invalid fixtures agree in TypeScript and ${language}, including canonical message roundtrips.`);

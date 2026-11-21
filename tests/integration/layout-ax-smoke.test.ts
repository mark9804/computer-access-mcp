import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Observation, SurfaceSnapshot } from '../../src/shared/protocol/generated.ts';
import { NOW, observation } from './history-store-fixtures.ts';

const script = new URL('../../scripts/test-layout-ax-smoke.mjs', import.meta.url);
interface SmokeModule {
  parseLayoutSmokeArgs(argv: string[]): string;
  fixtureMetadata(stdout: string, mode: string): { processId: number; processStartTime: string };
  assertFixedObservation(record: Observation, expected: { processId: number; processStartTime: string }): void;
}
// Importing the runner calls only its pure guards, never live AX or a store.
const smoke = await import(script.href) as SmokeModule;
const identity = { processId: 123, processStartTime: 'unix-ms:1700000000000.000' };
function surface(): Observation & { payload: SurfaceSnapshot } {
  const base = observation(1, '', NOW);
  assert.equal(base.target.kind, 'resolved');
  if (base.target.kind !== 'resolved') throw Error('synthetic-fixture');
  return { ...base, target: { kind: 'resolved', identity: { ...base.target.identity, ...identity,
    applicationId: 'com.dsh.computer-access.fixture', deviceId: 'synthetic-layout-ax' } },
    payload: { kind: 'surface.snapshot', snapshotId: 'synthetic-layout-smoke', surfaceId: 'synthetic-layout-surface',
      revision: 1, source: 'ax.tree', scope: 'window', mode: 'full', captureStartMs: NOW, captureEndMs: NOW,
      nodes: [{ id: 'editor', role: 'editable', text: 'synthetic', observedAtMs: NOW }],
      gate: { secure: 'not-declared-sensitive', privateState: 'normal', policyRevision: 1 },
      coverage: { status: 'partial', truncated: false, missingReasons: ['bounded-surface'] }, consistency: 'non-atomic' } };
}

test('layout AX runner rejects missing, widened and native-fixture flags before work', () => {
  for (const args of [[], ['--authorized-synthetic-layout', '--fixture'],
    ['--authorized-synthetic-layout', 'input'], ['--authorized-synthetic-layout', 'surface', '--dataRoot=/private']]) {
    assert.throws(() => smoke.parseLayoutSmokeArgs(args), /explicit-synthetic-layout-authorization-required/u);
    const child = spawnSync(process.execPath, [fileURLToPath(script), ...args], {
      encoding: 'utf8', env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, timeout: 3000,
    });
    assert.equal(child.status, 64); assert.equal(child.stdout, '');
    assert.deepEqual(JSON.parse(child.stderr), { ok: false, failure: 'explicit-synthetic-layout-authorization-required' });
  }
});

test('preparation metadata is exact, bounded and binds PID plus process birth without provider content', () => {
  const valid = { marker: 'fixture-prepared-plain', ...identity };
  assert.deepEqual(smoke.fixtureMetadata(JSON.stringify(valid), 'plain'), identity);
  for (const value of [null, [], {}, { ...valid, marker: 'fixture-prepared-protected' },
    { ...valid, processId: 1 }, { ...valid, processId: '123' }, { ...valid, processStartTime: 'unverified' },
    { ...valid, processStartTime: 'unix-ms:1700000000000.000\nprivate' }, { ...valid, text: 'private-provider-text' }]) {
    assert.throws(() => smoke.fixtureMetadata(JSON.stringify(value), 'plain'), /^Error: fixture-metadata-invalid$/u);
  }
  assert.throws(() => smoke.fixtureMetadata('private-provider-output', 'plain'), /^Error: fixture-metadata-invalid$/u);
});

test('observation guard refuses foreign identity, native fixture payloads, and unauthorized input channels', () => {
  const record = surface(); smoke.assertFixedObservation(record, identity);
  assert.equal(record.target.kind, 'resolved'); if (record.target.kind !== 'resolved') return;
  const expectedTarget = record.target.identity;
  for (const mismatch of [{ processId: 999 }, { processStartTime: 'unix-ms:1700000000000.001' },
    { applicationId: 'com.private.application' }, { deviceId: 'another-device' }]) {
    assert.throws(() => smoke.assertFixedObservation({ ...record, target: { kind: 'resolved',
      identity: { ...expectedTarget, ...mismatch } } }, identity), /non-fixture-observation/u);
  }
  assert.throws(() => smoke.assertFixedObservation({ ...record, payload: { ...record.payload, source: 'fixture' } }, identity), /surface-not-real-ax/u);
  const input = { ...record, payload: { kind: 'input.text' } } as unknown as Observation;
  assert.throws(() => smoke.assertFixedObservation(input, identity), /unexpected-input-evidence/u);
});

test('layout runner preserves canonical fixture identity and cannot imply UI/input/profile authorization', async () => {
  const source = await readFile(script, 'utf8');
  const preparation = await readFile(new URL('../../scripts/prepare-fixture-smoke.swift', import.meta.url), 'utf8');
  assert.match(source, /selectionCapture: false, inputText: false, inputActivity: false/u);
  assert.match(source, /await realpath\(temp\) === temp/u);
  assert.doesNotMatch(source, /allowFixture:|fixtureArgs:|input-fixture-smoke|probe-authorized|plugin_manager|historySearch|historyRead|key-store|osascript|AXIsProcessTrustedWithOptions|supervisor\.resume\(/u);
  assert.match(preparation, /CommandLine\.arguments\[2\] == "--metadata"/u);
  assert.match(preparation, /bundle == expectedBundle/u); assert.match(preparation, /executable == expectedExecutable/u);
  assert.match(preparation, /current\[0\]\.launchDate == launchDate/u);
});

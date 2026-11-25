import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, realpath, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { PassThrough, Writable } from 'node:stream';
import type { TestContext } from 'node:test';
import type { SpawnSpec } from '../../src/host/collectors/process.ts';
import { createSourceNavigation, parseSourceNavigationReport } from '../../src/host/service/source-navigation.ts';
import { target } from '../../fixtures/contract/examples.ts';

const identity = { ...target, applicationId: 'com.example.synthetic', processId: 123, processStartTime: 'unix-ms:1700000100000.000', osSessionId: 'audit-100', desktopId: 'console-audit-100' };
const report = (outcome = 'activated', reason = 'activated') => ({ version: 1, outcome, reason, captured: false, launched: false });
const encoded = (value: unknown) => Buffer.from(JSON.stringify(value));
test('navigation response is bounded, strict and separates dispatch from confirmed foreground', () => {
  for (const value of [report(), report('refused', 'application-mismatch'), report('uncertain', 'activation-unconfirmed'), report('uncertain', 'activation-rejected'), report('uncertain', 'deadline-exceeded')]) assert.deepEqual(parseSourceNavigationReport(encoded(value)), value);
  for (const value of [null, { ...report(), url: 'private' }, { ...report(), captured: true }, { ...report(), launched: true }, report('activated', 'activation-unconfirmed'), report('refused', 'activated'), report('refused', 'postcondition-changed'), report('refused', 'activation-rejected'), report('uncertain', 'input-too-large'), report('uncertain', '/private/secret')]) assert.throws(() => parseSourceNavigationReport(encoded(value)), /navigation-response-invalid/);
  assert.throws(() => parseSourceNavigationReport(Buffer.alloc(1025)), /navigation-response-invalid/);
  assert.throws(() => parseSourceNavigationReport(Buffer.from([255])), /navigation-response-invalid/);
});
async function fixture(t: TestContext, mode: 'normal' | 'refused' | 'unknown' | 'hang' | 'oversize' | 'bad-exit' | 'unconfirmed' = 'normal') {
  const base = await realpath(tmpdir());
  const root = await realpath(await mkdtemp(join(base, 'dsh-navigation-synthetic-')));
  const binaryName = process.platform === 'win32' ? 'computer-history-collector.exe' : 'computer-history-collector';
  const executable = join(root, binaryName);
  const content = 'Synthetic inert bytes, never executed';
  await writeFile(executable, content, { mode: 0o700 });
  const hash = (text: string) => createHash('sha256').update(text).digest('hex');
  const files: Record<string, { sha256: string }> = {
    [binaryName]: { sha256: hash(content) },
  };
  if (process.platform === 'darwin') {
    const resource = 'HistoryContract_HistoryContract.bundle/Contents/Resources/wire.schema.json';
    await mkdir(join(root, 'HistoryContract_HistoryContract.bundle/Contents/Resources'), { recursive: true });
    await writeFile(join(root, resource), '{}', { mode: 0o600 });
    files[resource] = { sha256: hash('{}') };
  }
  await writeFile(
    join(root, 'manifest.json'),
    JSON.stringify({ version: 1, platform: process.platform, arch: process.arch, files }),
    { mode: 0o600 },
  );
  const calls: SpawnSpec[] = []; const inputs: string[] = []; let terminations = 0; let waitHook: (() => Promise<boolean>) | undefined;
  let ready!: () => void; const spawned = new Promise<void>(resolve => { ready = resolve; });
  const navigator = createSourceNavigation({ executable, spawn(spec) {
    calls.push(spec); ready(); const stdout = new PassThrough(); const stderr = new PassThrough();
    let end!: (v: { exitCode: number | null; signal: NodeJS.Signals | null }) => void;
    const done = new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>(resolve => { end = resolve; });
    let input = '';
    const stdin = new Writable({ write(chunk, _encoding, callback) { input += String(chunk); callback(); }, final(callback) {
      inputs.push(input); callback();
      if (mode === 'hang') return;
      end({ exitCode: mode === 'bad-exit' ? 70 : 0, signal: null });
      // done intentionally precedes pipe drain, as in managed subprocess providers.
      setImmediate(() => { stdout.end(mode === 'oversize' ? Buffer.alloc(1025) : mode === 'unknown' ? 'invalid private payload' : encoded(mode === 'refused' ? report('refused', 'application-unavailable') : report())); stderr.end(); });
    } });
    return { stdin, stdout, stderr, done, terminate() { terminations++; stdout.destroy(); stderr.destroy(); end({ exitCode: null, signal: 'SIGTERM' }); }, async waitForExit() { if (waitHook) return waitHook(); if (mode === 'unconfirmed') return false; await done; return true; } };
  } });
  t.after(async () => { try { if (mode === 'unconfirmed') await assert.rejects(navigator.close(), /shutdown-unconfirmed/); else await navigator.close(); } finally { assert.equal(await realpath(root), root); assert.ok(root.startsWith(join(base, 'dsh-navigation-synthetic-'))); await rm(root, { recursive: true, force: false }); } });
  return { navigator, executable, calls, inputs, spawned, set waitHook(value: (() => Promise<boolean>) | undefined) { waitHook = value; }, get terminations() { return terminations; } };
}
const supportedPlatform = { skip: process.platform !== 'darwin' && process.platform !== 'win32', timeout: 15000 };
test('owner navigation uses fixed mode and stdin identity only; never a stale window token or launch command', supportedPlatform, async t => {
  const f = await fixture(t); assert.equal(f.calls.length, 0);
  let checks = 0;
  const value = await f.navigator.navigate(identity, new AbortController().signal, () => { checks++; });
  assert.equal(value.outcome, 'activated'); assert.equal(checks, 3); assert.equal(f.calls.length, 1);
  assert.deepEqual(f.calls[0]!.argv, [f.executable, '--navigate-source']);
  assert.deepEqual(JSON.parse(f.inputs[0]!), { version: 1, applicationId: identity.applicationId, processId: identity.processId, processStartTime: identity.processStartTime, osSessionId: identity.osSessionId, desktopId: identity.desktopId });
  assert.equal(f.inputs[0]!.includes(identity.windowId), false); assert.ok(f.terminations > 0);
});
test('Windows wts session navigation accepts winsta0-default and refuses non-default or mismatched desktops', supportedPlatform, async t => {
  const f = await fixture(t);
  const winIdentity = {
    ...identity,
    applicationId: 'code.exe',
    osSessionId: 'wts-1',
    desktopId: 'winsta0-default-wts-1',
  };
  const activated = await f.navigator.navigate(winIdentity, new AbortController().signal, () => {});
  assert.equal(activated.outcome, 'activated');
  assert.equal(f.calls.length, 1);
  assert.deepEqual(JSON.parse(f.inputs[0]!), {
    version: 1,
    applicationId: 'code.exe',
    processId: winIdentity.processId,
    processStartTime: winIdentity.processStartTime,
    osSessionId: 'wts-1',
    desktopId: 'winsta0-default-wts-1',
  });

  for (const invalidTarget of [
    { ...winIdentity, desktopId: 'winsta0-winlogon-wts-1' },
    { ...winIdentity, desktopId: 'winsta0-default-wts-2' },
    { ...winIdentity, desktopId: 'console-wts-1' },
    { ...winIdentity, osSessionId: 'audit-1', desktopId: 'winsta0-default-audit-1' },
  ]) {
    const refused = await f.navigator.navigate(invalidTarget, new AbortController().signal, () => {});
    assert.equal(refused.outcome, 'refused');
    assert.equal(refused.reason, 'navigation-target-unavailable');
  }
  assert.equal(f.calls.length, 1);
});
test('invalid target, cancelled caller and authority loss before spawn are inert', supportedPlatform, async t => {
  const f = await fixture(t);
  assert.equal((await f.navigator.navigate({ ...identity, processStartTime: 'fixture-start' }, new AbortController().signal, () => {})).outcome, 'refused');
  assert.equal((await f.navigator.navigate(identity, AbortSignal.abort(), () => {})).reason, 'navigation-cancelled');
  assert.equal((await f.navigator.navigate(identity, new AbortController().signal, () => { throw Error('private'); })).outcome, 'refused');
  assert.equal(f.calls.length, 0);
});
test('ambiguous native output never retries and never claims refusal after possible dispatch', supportedPlatform, async t => {
  for (const mode of ['unknown', 'oversize', 'bad-exit'] as const) {
    const f = await fixture(t, mode); const value = await f.navigator.navigate(identity, new AbortController().signal, () => {});
    assert.equal(value.outcome, 'uncertain'); assert.equal(value.reason, 'navigation-response-invalid'); assert.equal(f.calls.length, 1);
    assert.equal(JSON.stringify(value).includes('private'), false);
  }
});
test('abort, concurrent request and close bound owned work without replay', supportedPlatform, async t => {
  const f = await fixture(t, 'hang'); const abort = new AbortController();
  const pending = f.navigator.navigate(identity, abort.signal, () => {}); await f.spawned;
  assert.equal((await f.navigator.navigate(identity, new AbortController().signal, () => {})).reason, 'navigation-busy');
  abort.abort(); assert.equal((await pending).reason, 'navigation-cancelled-after-dispatch'); assert.equal(f.calls.length, 1);
  await f.navigator.close(); assert.equal((await f.navigator.navigate(identity, new AbortController().signal, () => {})).outcome, 'refused');
});
test('cancellation and authority changes during process join cannot return stale activated receipt', supportedPlatform, async t => {
  for (const change of ['abort', 'authority'] as const) {
    const f = await fixture(t); const controller = new AbortController(); let current = true;
    let joining!: () => void; const joined = new Promise<void>(resolve => { joining = resolve; });
    let release!: () => void; const blocked = new Promise<void>(resolve => { release = resolve; });
    f.waitHook = async () => { joining(); await blocked; return true; };
    const pending = f.navigator.navigate(identity, controller.signal, () => { if (!current) throw Error('no-longer-current'); });
    await joined; if (change === 'abort') controller.abort(); else current = false;
    release(); const result = await pending; assert.equal(result.outcome, 'uncertain'); assert.equal(result.reason, 'navigation-cancelled-after-dispatch');
    assert.equal(f.calls.length, 1);
  }
});
test('unconfirmed helper exit poisons navigation and cannot dispatch another activation', supportedPlatform, async t => {
  const f = await fixture(t, 'unconfirmed');
  const value = await f.navigator.navigate(identity, new AbortController().signal, () => {});
  assert.equal(value.outcome, 'uncertain'); assert.equal(value.reason, 'navigation-exit-unconfirmed');
  assert.equal((await f.navigator.navigate(identity, new AbortController().signal, () => {})).reason, 'navigation-unavailable'); assert.equal(f.calls.length, 1);
});
test('navigation deadline returns uncertainty and bounded cleanup rather than replay', supportedPlatform, async t => {
  const f = await fixture(t, 'hang');
  const value = await f.navigator.navigate(identity, new AbortController().signal, () => {});
  assert.equal(value.outcome, 'uncertain'); assert.equal(value.reason, 'navigation-timeout'); assert.equal(f.calls.length, 1);
});
test('explicit native refusal survives without any automatic second attempt', supportedPlatform, async t => {
  const f = await fixture(t, 'refused'); const value = await f.navigator.navigate(identity, new AbortController().signal, () => {});
  assert.equal(value.outcome, 'refused'); assert.equal(value.reason, 'application-unavailable'); assert.equal(f.calls.length, 1);
});

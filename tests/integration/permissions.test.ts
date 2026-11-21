import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, realpath, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { PassThrough, Writable } from 'node:stream';
import type { SpawnManaged, SpawnSpec } from '../../src/host/collectors/process.ts';
import { createPermissionActions, parsePermissionReport } from '../../src/host/service/permissions.ts';
import type { PermissionAction } from '../../src/host/service/permissions.ts';
import type { TestContext } from 'node:test';
const report = (action: PermissionAction) => ({ version: 1, action, accessibility: 'not-granted', desktop: { status: 'unknown', reason: 'lock-state-unavailable', sessionAvailable: true, onConsole: true, loginDone: true }, screenRecording: 'not-required', promptRequested: action === 'request-accessibility', settingsOpened: action === 'open-accessibility-settings', captured: false, inputMonitoring: { state: 'not-granted', promptRequested: action === 'request-input-monitoring', settingsOpened: action === 'open-input-monitoring-settings' } });
const encode = (value: unknown) => Buffer.from(JSON.stringify(value));
test('permission DTO validation rejects coercible non-string enums',()=>{
  const base=report('check');
  for(const value of [
    {...base,accessibility:['granted']},
    {...base,inputMonitoring:{...base.inputMonitoring,state:['granted']}},
    {...base,desktop:{...base.desktop,status:['unknown']}},
    {...base,desktop:{...base.desktop,reason:['lock-state-unavailable']}},
    {...base,desktop:{...base.desktop,lockSource:['unknown']}},
  ])assert.throws(()=>parsePermissionReport(encode(value),'check'),/permission-response-invalid/);
});
test('onboarding report retains unknown lock independently from Accessibility, without content', () => {
  const value = { ...report('check'), accessibility: 'granted' };
  assert.deepEqual(parsePermissionReport(encode(value), 'check'), value);
  for (const extra of [{ screenshot: 'secret' }, { captured: true }, { screenRecording: 'granted' }, { action: 'request-accessibility' }, { promptRequested: true }, { settingsOpened: true }, { desktop: { ...value.desktop, status: 'unlocked', reason: 'ready' } }, { desktop: { ...value.desktop, screenLocked: 'false' } }, { desktop: { ...value.desktop, title: 'secret' } }]) {
    assert.throws(() => parsePermissionReport(encode({ ...value, ...extra }), 'check'), /permission-response-invalid/);
  }
});
test('a Secure Input marker is a blocked boundary, not a ready desktop or a lock claim', () => {
  const base = report('check');
  const value = { ...base, desktop: { ...base.desktop, reason: 'secure-input-indicated', lockTransition: true, screenLocked: false } };
  assert.equal(parsePermissionReport(encode(value), 'check').desktop.reason, 'secure-input-indicated');
  assert.throws(() => parsePermissionReport(encode({ ...value, desktop: { ...value.desktop, status: 'unlocked' } }), 'check'), /permission-response-invalid/);
  assert.throws(() => parsePermissionReport(encode({ ...value, desktop: { ...value.desktop, status: 'locked' } }), 'check'), /permission-response-invalid/);
});
test('Input Monitoring is checked and requested independently from Accessibility without creating a tap',()=>{
  const value={...report('check'),inputMonitoring:{state:'not-granted',promptRequested:false,settingsOpened:false}};
  assert.equal(parsePermissionReport(encode(value),'check').inputMonitoring?.state,'not-granted');
  const request={...value,action:'request-input-monitoring',inputMonitoring:{state:'not-granted',promptRequested:true,settingsOpened:false}};
  assert.equal(parsePermissionReport(encode(request),'request-input-monitoring').promptRequested,false);
  assert.equal(parsePermissionReport(encode(request),'request-input-monitoring').inputMonitoring?.promptRequested,true);
  assert.throws(()=>parsePermissionReport(encode({...request,promptRequested:true}),'request-input-monitoring'),/permission-response-invalid/);
  assert.throws(()=>parsePermissionReport(encode({...request,inputMonitoring:undefined}),'request-input-monitoring'),/permission-response-invalid/);
  assert.throws(()=>parsePermissionReport(encode({...value,inputMonitoring:{...value.inputMonitoring,pressedKey:'private'}}),'check'),/permission-response-invalid/);
  const settings={...value,action:'open-input-monitoring-settings',inputMonitoring:{state:'not-granted',promptRequested:false,settingsOpened:true}};
  assert.equal(parsePermissionReport(encode(settings),'open-input-monitoring-settings').settingsOpened,false);
});
test('console compatibility result requires independently verified session and no positive lock or transition', () => {
  const desktop = { status: 'unlocked', reason: 'ready-console-compat', sessionAvailable: true, onConsole: true, loginDone: true, consoleLocked: false, registrySessionMatched: true, sessionMatchesProcess: true, sessionStable: true, signalsValid: true, lockTransition: false, lockSource: 'io-console-compat' };
  const value = { ...report('check'), accessibility: 'granted', desktop };
  assert.deepEqual(parsePermissionReport(encode(value), 'check'), value);
  for (const extra of [{ consoleLocked: true }, { screenLocked: true }, { registryScreenLocked: true }, { registrySessionMatched: false }, { sessionMatchesProcess: false }, { sessionStable: false }, { signalsValid: false }, { lockTransition: true }, { lockSource: 'unknown' }]) {
    assert.throws(() => parsePermissionReport(encode({ ...value, desktop: { ...desktop, ...extra } }), 'check'), /permission-response-invalid/);
  }
});
async function fixture(t: TestContext) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dsh-permission-synthetic-')));
  const executable = join(root, 'computer-access-collector');
  const content = 'Synthetic non-executable fixture data'; await writeFile(executable, content, { mode: 0o700 });
  const resource = 'AccessContract_AccessContract.bundle/Contents/Resources/wire.schema.json';
  await mkdir(join(root, 'AccessContract_AccessContract.bundle/Contents/Resources'), { recursive: true });
  await writeFile(join(root, resource), '{}', { mode: 0o600 });
  const hash = (text: string) => createHash('sha256').update(text).digest('hex');
  await writeFile(join(root, 'manifest.json'), JSON.stringify({ version: 1, platform: 'darwin', arch: process.arch, files: { 'computer-access-collector': { sha256: hash(content) }, [resource]: { sha256: hash('{}') } } }), { mode: 0o600 });
  t.after(async () => { assert.ok(root.startsWith(await realpath(tmpdir()) + '/dsh-permission-synthetic-')); await rm(root, { recursive: true, force: true }); });
  return { root, executable };
}
const onlyMac = { skip: process.platform !== 'darwin' };
test('permission actions are inert until perform, fixed argv, no collection and no automatic retry', onlyMac, async t => {
  const f = await fixture(t); const calls: SpawnSpec[] = [];
  const spawn: SpawnManaged = spec => {
    calls.push(spec); const stdout = new PassThrough(); const stderr = new PassThrough();
    const action = spec.argv[2] as PermissionAction;
    let finish!: (value: { exitCode: number | null; signal: NodeJS.Signals | null }) => void;
    const done = new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>(resolve => { finish = resolve; });
    const stdin = new Writable({ write(_chunk, _encoding, callback) { callback(); }, final(callback) { stdout.end(encode(report(action))); stderr.end(); finish({ exitCode: 0, signal: null }); callback(); } });
    return { stdin, stdout, stderr, done, terminate() { stdout.destroy(); stderr.destroy(); finish({ exitCode: null, signal: 'SIGTERM' }); }, async waitForExit() { await done; return true; } };
  };
  const service = createPermissionActions({ executable: f.executable, spawn }); t.after(() => service.close());
  assert.equal(calls.length, 0);
  for (const action of ['check', 'request-accessibility', 'open-accessibility-settings', 'request-input-monitoring', 'open-input-monitoring-settings'] as const) {
    const result = await service.perform(action, new AbortController().signal);
    assert.equal(result.captured, false); assert.equal(result.helperPath, f.executable);
    assert.deepEqual(calls.at(-1)!.argv, [f.executable, '--permissions', action]);
  }
  assert.equal(calls.length, 5);
  await assert.rejects(service.perform('check', AbortSignal.abort()), /permission-action-cancelled/);
  assert.equal(calls.length, 5);
});
test('permission failure is sanitized and does not replay an authorization request', onlyMac, async t => {
  const f = await fixture(t); let count = 0;
  const service = createPermissionActions({ executable: f.executable, spawn() { count++; throw new Error('private output'); } });
  await assert.rejects(service.perform('request-accessibility', new AbortController().signal), /permission-helper-unavailable/);
  assert.equal(count, 1); await service.close();
  await assert.rejects(service.perform('check', new AbortController().signal), /permission-helper-unavailable/);
  assert.equal(count, 1);
});
test('missing pipes and never-settling exit are bounded and poison later permission work', { ...onlyMac, timeout: 6000 }, async t => {
  const f = await fixture(t); let count = 0; let terminated = 0;
  const service = createPermissionActions({ executable: f.executable, spawn() {
    count++;
    return { stdin: undefined, stdout: undefined, stderr: undefined, done: new Promise(() => {}), terminate() { terminated++; }, waitForExit() { return new Promise(() => {}); } };
  } });
  await assert.rejects(service.perform('check', new AbortController().signal), /permission-helper-exit-unconfirmed/);
  await assert.rejects(service.perform('check', new AbortController().signal), /permission-helper-unavailable/);
  await assert.rejects(service.close(), /permission-helper-exit-unconfirmed/);
  assert.equal(count, 1); assert.ok(terminated >= 1);
});
test('a completed command with unconfirmed owned-process exit cannot return a permission result', { ...onlyMac, timeout: 4000 }, async t => {
  const f = await fixture(t); let count = 0; let terminated = 0;
  const service = createPermissionActions({ executable: f.executable, spawn() {
    count++; const stdout = new PassThrough(); const stderr = new PassThrough();
    const stdin = new Writable({ write(_chunk, _encoding, callback) { callback(); }, final(callback) { stdout.end(encode(report('check'))); stderr.end(); callback(); } });
    return { stdin, stdout, stderr, done: Promise.resolve({ exitCode: 0, signal: null }), terminate() { terminated++; }, waitForExit() { return new Promise(() => {}); } };
  } });
  await assert.rejects(service.perform('check', new AbortController().signal), /permission-helper-exit-unconfirmed/);
  await assert.rejects(service.perform('check', new AbortController().signal), /permission-helper-unavailable/);
  await assert.rejects(service.close(), /permission-helper-exit-unconfirmed/);
  assert.equal(count, 1); assert.ok(terminated >= 1);
});

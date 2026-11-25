import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, realpath, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { PassThrough, Writable } from 'node:stream';
import type { SpawnManaged, SpawnSpec } from '../../src/host/collectors/process.ts';
import { createPermissionActions, parsePermissionReport, toPermissionStatus } from '../../src/host/service/permissions.ts';
import type { PermissionAction } from '../../src/host/service/permissions.ts';
import type { TestContext } from 'node:test';
const report = (action: PermissionAction) => ({ version: 1, action, accessibility: 'not-granted', desktop: { status: 'unknown', reason: 'lock-state-unavailable', sessionAvailable: true, onConsole: true, loginDone: true }, screenRecording: 'not-required', promptRequested: action === 'request-accessibility', settingsOpened: action === 'open-accessibility-settings', captured: false, inputMonitoring: { state: 'not-granted', promptRequested: action === 'request-input-monitoring', settingsOpened: action === 'open-input-monitoring-settings' } });
const encode = (value: unknown) => Buffer.from(JSON.stringify(value));
test('permission DTO validation rejects coercible non-string enums',()=>{
  const base=report('check');
  for(const platform of ['darwin','win32'] as const){
    for(const value of [
      {...base,accessibility:['granted']},
      {...base,inputMonitoring:{...base.inputMonitoring,state:['granted']}},
      {...base,desktop:{...base.desktop,status:['unknown']}},
      {...base,desktop:{...base.desktop,reason:['lock-state-unavailable']}},
      {...base,desktop:{...base.desktop,lockSource:['unknown']}},
    ])assert.throws(()=>parsePermissionReport(encode(value),'check',platform),/permission-response-invalid/);
  }
});
test('onboarding report retains unknown lock independently from Accessibility, without content', () => {
  const value = { ...report('check'), accessibility: 'granted' };
  assert.deepEqual(parsePermissionReport(encode(value), 'check', 'darwin'), value);
  for (const extra of [{ screenshot: 'secret' }, { captured: true }, { screenRecording: 'granted' }, { action: 'request-accessibility' }, { promptRequested: true }, { settingsOpened: true }, { desktop: { ...value.desktop, status: 'unlocked', reason: 'ready' } }, { desktop: { ...value.desktop, screenLocked: 'false' } }, { desktop: { ...value.desktop, title: 'secret' } }]) {
    assert.throws(() => parsePermissionReport(encode({ ...value, ...extra }), 'check', 'darwin'), /permission-response-invalid/);
  }
});
test('a Secure Input marker is a blocked boundary, not a ready desktop or a lock claim', () => {
  const base = report('check');
  const value = { ...base, desktop: { ...base.desktop, reason: 'secure-input-indicated', lockTransition: true, screenLocked: false } };
  assert.equal(parsePermissionReport(encode(value), 'check', 'darwin').desktop.reason, 'secure-input-indicated');
  assert.throws(() => parsePermissionReport(encode({ ...value, desktop: { ...value.desktop, status: 'unlocked' } }), 'check', 'darwin'), /permission-response-invalid/);
  assert.throws(() => parsePermissionReport(encode({ ...value, desktop: { ...value.desktop, status: 'locked' } }), 'check', 'darwin'), /permission-response-invalid/);
});
test('Input Monitoring is checked and requested independently from Accessibility without creating a tap',()=>{
  const value={...report('check'),inputMonitoring:{state:'not-granted',promptRequested:false,settingsOpened:false}};
  assert.equal(parsePermissionReport(encode(value),'check','darwin').inputMonitoring?.state,'not-granted');
  const request={...value,action:'request-input-monitoring',inputMonitoring:{state:'not-granted',promptRequested:true,settingsOpened:false}};
  assert.equal(parsePermissionReport(encode(request),'request-input-monitoring','darwin').promptRequested,false);
  assert.equal(parsePermissionReport(encode(request),'request-input-monitoring','darwin').inputMonitoring?.promptRequested,true);
  assert.throws(()=>parsePermissionReport(encode({...request,promptRequested:true}),'request-input-monitoring','darwin'),/permission-response-invalid/);
  assert.throws(()=>parsePermissionReport(encode({...request,inputMonitoring:undefined}),'request-input-monitoring','darwin'),/permission-response-invalid/);
  assert.throws(()=>parsePermissionReport(encode({...value,inputMonitoring:{...value.inputMonitoring,pressedKey:'private'}}),'check','darwin'),/permission-response-invalid/);
  const settings={...value,action:'open-input-monitoring-settings',inputMonitoring:{state:'not-granted',promptRequested:false,settingsOpened:true}};
  assert.equal(parsePermissionReport(encode(settings),'open-input-monitoring-settings','darwin').settingsOpened,false);
});
test('console compatibility result requires independently verified session and no positive lock or transition', () => {
  const desktop = { status: 'unlocked', reason: 'ready-console-compat', sessionAvailable: true, onConsole: true, loginDone: true, consoleLocked: false, registrySessionMatched: true, sessionMatchesProcess: true, sessionStable: true, signalsValid: true, lockTransition: false, lockSource: 'io-console-compat' };
  const value = { ...report('check'), accessibility: 'granted', desktop };
  assert.deepEqual(parsePermissionReport(encode(value), 'check', 'darwin'), value);
  for (const extra of [{ consoleLocked: true }, { screenLocked: true }, { registryScreenLocked: true }, { registrySessionMatched: false }, { sessionMatchesProcess: false }, { sessionStable: false }, { signalsValid: false }, { lockTransition: true }, { lockSource: 'unknown' }]) {
    assert.throws(() => parsePermissionReport(encode({ ...value, desktop: { ...desktop, ...extra } }), 'check', 'darwin'), /permission-response-invalid/);
  }
});
async function fixture(t: TestContext) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'dsh-permission-synthetic-')));
  const binaryName = process.platform === 'win32' ? 'computer-history-collector.exe' : 'computer-history-collector';
  const executable = join(root, binaryName);
  const content = 'Synthetic non-executable fixture data';
  await writeFile(executable, content, { mode: 0o700 });
  const hash = (text: string) => createHash('sha256').update(text).digest('hex');
  const files: Record<string, { sha256: string }> = {
    [binaryName]: { sha256: hash(content) },
  };
  if (process.platform === 'darwin') {
    const resource = 'AccessContract_AccessContract.bundle/Contents/Resources/wire.schema.json';
    await mkdir(join(root, 'AccessContract_AccessContract.bundle/Contents/Resources'), { recursive: true });
    await writeFile(join(root, resource), '{}', { mode: 0o600 });
    files[resource] = { sha256: hash('{}') };
  }
  await writeFile(
    join(root, 'manifest.json'),
    JSON.stringify({ version: 1, platform: process.platform, arch: process.arch, files }),
    { mode: 0o600 },
  );
  t.after(async () => {
    assert.ok(root.startsWith(join(await realpath(tmpdir()), 'dsh-permission-synthetic-')));
    await rm(root, { recursive: true, force: true });
  });
  return { root, executable };
}
const supportedPlatform = { skip: process.platform !== 'darwin' && process.platform !== 'win32' };
test('Windows wts-session and win32-desktop permission DTOs validate unlocked, locked, unknown, and fail-closed invariants', () => {
  for (const lockSource of ['wts-session', 'win32-desktop'] as const) {
    const unlockedDesktop = {
      status: 'unlocked' as const,
      reason: 'ready',
      sessionAvailable: true,
      sessionMatchesProcess: true,
      sessionStable: true,
      signalsValid: true,
      lockTransition: false,
      screenLocked: false,
      lockSource,
    };
    const unlocked = {
      version: 1 as const,
      action: 'check' as const,
      accessibility: 'not-applicable' as const,
      desktop: unlockedDesktop,
      screenRecording: 'not-required' as const,
      promptRequested: false,
      settingsOpened: false,
      captured: false as const,
      inputMonitoring: { state: 'not-applicable' as const, promptRequested: false, settingsOpened: false },
    };
    const parsedUnlocked = parsePermissionReport(encode(unlocked), 'check', 'win32');
    assert.deepEqual(parsedUnlocked, unlocked);
    const status = toPermissionStatus({ ...parsedUnlocked, checkedAt: 1234 }, 'win32');
    assert.equal(status.platform, 'win32');
    assert.equal(status.accessibility, 'not-applicable');
    assert.equal(status.inputMonitoring, 'not-applicable');
    assert.equal(status.desktopStatus, 'unlocked');
    assert.equal(status.desktopReason, 'ready');

    const locked = {
      ...unlocked,
      desktop: { ...unlockedDesktop, status: 'locked' as const, reason: 'screen-locked', screenLocked: true },
    };
    assert.deepEqual(parsePermissionReport(encode(locked), 'check', 'win32'), locked);

    const unknownTransition = {
      ...unlocked,
      desktop: { ...unlockedDesktop, status: 'unknown' as const, reason: 'desktop-lock-transition', lockTransition: true },
    };
    assert.deepEqual(parsePermissionReport(encode(unknownTransition), 'check', 'win32'), unknownTransition);

    const unknownUnavailable = {
      ...unlocked,
      desktop: {
        status: 'unknown' as const,
        reason: 'lock-state-unavailable',
        sessionAvailable: true,
        sessionMatchesProcess: true,
        sessionStable: true,
        signalsValid: false,
        lockTransition: false,
        lockSource,
      },
    };
    assert.deepEqual(parsePermissionReport(encode(unknownUnavailable), 'check', 'win32'), unknownUnavailable);

    // Fail-closed invalid combinations must all be refused.
    for (const invalidDesktop of [
      { ...unlockedDesktop, sessionAvailable: false },
      { ...unlockedDesktop, sessionMatchesProcess: false },
      { ...unlockedDesktop, sessionStable: false },
      { ...unlockedDesktop, signalsValid: false },
      { ...unlockedDesktop, lockTransition: true },
      { ...unlockedDesktop, screenLocked: true },
      { ...unlockedDesktop, screenLocked: undefined },
      { ...unlockedDesktop, lockSource: 'unknown' },
      { ...unlockedDesktop, lockSource: undefined },
      { ...unlockedDesktop, reason: 'ready-console-compat' },
      { ...unlockedDesktop, status: 'unknown', reason: 'lock-state-unavailable' },
      { ...unlockedDesktop, status: 'unknown', reason: 'ready', signalsValid: false },
      { ...unlockedDesktop, status: 'unknown', reason: 'ready-console-compat', signalsValid: false },
      { ...unlockedDesktop, status: 'unknown', reason: 'screen-locked', screenLocked: true },
      { ...unlockedDesktop, status: 'unknown', reason: 'screen-locked', screenLocked: false },
      { ...unlockedDesktop, status: 'unknown', reason: 'screen-locked', screenLocked: undefined },
      { ...unlockedDesktop, status: 'locked', reason: 'lock-state-unavailable', screenLocked: true },
      { ...unlockedDesktop, status: 'locked', reason: 'screen-locked', screenLocked: false },
    ]) {
      const cleaned = Object.fromEntries(Object.entries(invalidDesktop).filter(([, v]) => v !== undefined));
      assert.throws(
        () => parsePermissionReport(encode({ ...unlocked, desktop: cleaned }), 'check', 'win32'),
        /permission-response-invalid/,
      );
    }
  }
});

test('platform-scoped permission DTO validation rejects cross-platform enums and contradictory screen-locked states', () => {
  const macBase = report('check');
  // darwin strictly rejects Windows lockSources and not-applicable grants.
  for (const invalidDarwin of [
    { ...macBase, accessibility: 'not-applicable' },
    { ...macBase, inputMonitoring: { ...macBase.inputMonitoring, state: 'not-applicable' } },
    { ...macBase, desktop: { ...macBase.desktop, lockSource: 'wts-session' } },
    { ...macBase, desktop: { ...macBase.desktop, lockSource: 'win32-desktop' } },
    {
      ...macBase,
      desktop: {
        status: 'unlocked',
        reason: 'ready',
        sessionAvailable: true,
        sessionMatchesProcess: true,
        sessionStable: true,
        signalsValid: true,
        lockTransition: false,
        screenLocked: false,
        lockSource: 'wts-session',
      },
    },
    // Two-way screen-locked consistency on darwin: unknown + screen-locked + not locked must fail.
    { ...macBase, desktop: { ...macBase.desktop, status: 'unknown', reason: 'screen-locked', screenLocked: false } },
    { ...macBase, desktop: { ...macBase.desktop, status: 'unknown', reason: 'screen-locked' } },
  ]) {
    assert.throws(
      () => parsePermissionReport(encode(invalidDarwin), 'check', 'darwin'),
      /permission-response-invalid/,
    );
  }

  // win32 strictly rejects macOS lockSources and contradictory screen-locked states.
  const winBase = {
    version: 1 as const,
    action: 'check' as const,
    accessibility: 'not-applicable' as const,
    desktop: {
      status: 'unknown' as const,
      reason: 'lock-state-unavailable',
      sessionAvailable: true,
      sessionMatchesProcess: true,
      sessionStable: true,
      signalsValid: false,
      lockTransition: false,
      lockSource: 'unknown',
    },
    screenRecording: 'not-required' as const,
    promptRequested: false,
    settingsOpened: false,
    captured: false as const,
    inputMonitoring: { state: 'not-applicable' as const, promptRequested: false, settingsOpened: false },
  };
  assert.deepEqual(parsePermissionReport(encode(winBase), 'check', 'win32'), winBase);

  for (const macLockSource of ['cg-session', 'io-session', 'io-console-compat', 'locked-signal']) {
    assert.throws(
      () =>
        parsePermissionReport(
          encode({ ...winBase, desktop: { ...winBase.desktop, lockSource: macLockSource } }),
          'check',
          'win32',
        ),
      /permission-response-invalid/,
    );
  }

  for (const contradictoryWin of [
    { ...winBase, desktop: { ...winBase.desktop, status: 'unknown', reason: 'screen-locked', screenLocked: false } },
    { ...winBase, desktop: { ...winBase.desktop, status: 'unknown', reason: 'screen-locked' } },
  ]) {
    assert.throws(
      () => parsePermissionReport(encode(contradictoryWin), 'check', 'win32'),
      /permission-response-invalid/,
    );
  }
});

test('permission actions are inert until perform, fixed argv, no collection and no automatic retry', supportedPlatform, async t => {
  const f = await fixture(t); const calls: SpawnSpec[] = [];
  const spawn: SpawnManaged = spec => {
    calls.push(spec); const stdout = new PassThrough(); const stderr = new PassThrough();
    const action = spec.argv[2] as PermissionAction;
    let finish!: (value: { exitCode: number | null; signal: NodeJS.Signals | null }) => void;
    const done = new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>(resolve => { finish = resolve; });
    const stdin = new Writable({ write(_chunk, _encoding, callback) { callback(); }, final(callback) { stdout.end(encode(report(action))); stderr.end(); finish({ exitCode: 0, signal: null }); callback(); } });
    return { stdin, stdout, stderr, done, terminate() { stdout.destroy(); stderr.destroy(); finish({ exitCode: null, signal: 'SIGTERM' }); }, async waitForExit() { await done; return true; } };
  };
  const service = createPermissionActions({ executable: f.executable, spawn, platform: process.platform }); t.after(() => service.close());
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

test('createPermissionActions enforces platform-scoped DTO rules for both win32 and darwin', supportedPlatform, async (t) => {
  const f = await fixture(t);
  let payload: unknown = null;
  const spawn: SpawnManaged = () => {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    let finish!: (value: { exitCode: number | null; signal: NodeJS.Signals | null }) => void;
    const done = new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>((resolve) => {
      finish = resolve;
    });
    const stdin = new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      },
      final(callback) {
        stdout.end(encode(payload));
        stderr.end();
        finish({ exitCode: 0, signal: null });
        callback();
      },
    });
    return {
      stdin,
      stdout,
      stderr,
      done,
      terminate() {
        stdout.destroy();
        stderr.destroy();
        finish({ exitCode: null, signal: 'SIGTERM' });
      },
      async waitForExit() {
        await done;
        return true;
      },
    };
  };

  const winPayload = {
    version: 1,
    action: 'check',
    accessibility: 'not-applicable',
    desktop: {
      status: 'unlocked',
      reason: 'ready',
      sessionAvailable: true,
      sessionMatchesProcess: true,
      sessionStable: true,
      signalsValid: true,
      lockTransition: false,
      screenLocked: false,
      lockSource: 'wts-session',
    },
    screenRecording: 'not-required',
    promptRequested: false,
    settingsOpened: false,
    captured: false,
    inputMonitoring: { state: 'not-applicable', promptRequested: false, settingsOpened: false },
  };
  const macPayload = {
    ...report('check'),
    accessibility: 'granted',
    desktop: {
      status: 'unlocked',
      reason: 'ready-console-compat',
      sessionAvailable: true,
      onConsole: true,
      loginDone: true,
      consoleLocked: false,
      registrySessionMatched: true,
      sessionMatchesProcess: true,
      sessionStable: true,
      signalsValid: true,
      lockTransition: false,
      lockSource: 'io-console-compat',
    },
  };

  const winActions = createPermissionActions({ executable: f.executable, spawn, platform: 'win32' });
  const macActions = createPermissionActions({ executable: f.executable, spawn, platform: 'darwin' });
  const hostActions = createPermissionActions({ executable: f.executable, spawn, platform: process.platform });
  t.after(async () => {
    await winActions.close();
    await macActions.close();
    await hostActions.close();
  });

  payload = winPayload;
  const winOk = await winActions.perform('check');
  assert.equal(winOk.desktop.lockSource, 'wts-session');
  await assert.rejects(macActions.perform('check'), /permission-response-invalid/);

  payload = macPayload;
  const macOk = await macActions.perform('check');
  assert.equal(macOk.desktop.lockSource, 'io-console-compat');
  await assert.rejects(winActions.perform('check'), /permission-response-invalid/);

  payload = process.platform === 'win32' ? winPayload : macPayload;
  const hostOk = await hostActions.perform('check');
  assert.equal(hostOk.desktop.status, 'unlocked');
});
test('permission failure is sanitized and does not replay an authorization request', supportedPlatform, async t => {
  const f = await fixture(t); let count = 0;
  const service = createPermissionActions({ executable: f.executable, spawn() { count++; throw new Error('private output'); } });
  await assert.rejects(service.perform('request-accessibility', new AbortController().signal), /permission-helper-unavailable/);
  assert.equal(count, 1); await service.close();
  await assert.rejects(service.perform('check', new AbortController().signal), /permission-helper-unavailable/);
  assert.equal(count, 1);
});
test('missing pipes and never-settling exit are bounded and poison later permission work', { ...supportedPlatform, timeout: 6000 }, async t => {
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
test('a completed command with unconfirmed owned-process exit cannot return a permission result', { ...supportedPlatform, timeout: 4000 }, async t => {
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

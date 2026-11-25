import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { lstat, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import type { TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';
import { spawnLocal } from '../../src/host/collectors/local-process.ts';
import { CollectorSupervisor } from '../../src/host/collectors/supervisor.ts';
import { verifyNativeBinary } from '../../src/host/service/binaries.ts';
import { createHistoryService } from '../../src/host/service/history-service.ts';
import { parseSourceNavigationReport } from '../../src/host/service/source-navigation.ts';
import type { CapturePolicy, Observation } from '../../src/shared/protocol/generated.ts';
import { DPAPI_KEY_FILENAME, MemoryKeyProvider, WindowsDpapiKeyProvider } from '../../src/storage/key-provider.ts';
import { SegmentStore } from '../../src/storage/segment-store.ts';

const REPO_ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const NATIVE_BIN_DIR = join(REPO_ROOT, 'native-bin');
const COLLECTOR_PATH = join(NATIVE_BIN_DIR, 'computer-history-collector.exe');
const KEY_STORE_PATH = join(NATIVE_BIN_DIR, 'computer-history-key-store.exe');
const MANIFEST_PATH = join(NATIVE_BIN_DIR, 'manifest.json');

const BASE_FIXTURE_POLICY: CapturePolicy = {
  enabled: true,
  allowedApplicationIds: ['test.allowed'],
  maxTextCodeUnits: 512,
  maxPending: 16,
  debounceMs: 10,
  maxWaitMs: 100,
  readTimeoutMs: 2_000,
};

function hasBuiltWindowsNativeBinaries(): boolean {
  if (process.platform !== 'win32') return false;
  if (!existsSync(COLLECTOR_PATH) || !existsSync(KEY_STORE_PATH) || !existsSync(MANIFEST_PATH)) {
    return false;
  }
  try {
    const parsed = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8')) as {
      version?: unknown;
      platform?: unknown;
      files?: Record<string, unknown>;
    };
    return (
      parsed.version === 1 &&
      parsed.platform === 'win32' &&
      Boolean(parsed.files?.['computer-history-collector.exe']) &&
      Boolean(parsed.files?.['computer-history-key-store.exe'])
    );
  } catch {
    return false;
  }
}

const skipReason = hasBuiltWindowsNativeBinaries()
  ? false
  : 'requires win32 with built native-bin/computer-history-collector.exe, native-bin/computer-history-key-store.exe, and native-bin/manifest.json';

const opts = { skip: skipReason, timeout: 25_000 };

const sha256 = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');

async function makeTempDir(t: TestContext, prefix: string): Promise<string> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), prefix)));
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  return dir;
}

function currentWindowsSessionId(): number | null {
  const res = spawnSync('tasklist', ['/fi', `PID eq ${process.pid}`, '/fo', 'csv', '/nh'], {
    encoding: 'utf8',
    timeout: 5_000,
  });
  if (res.status !== 0 || typeof res.stdout !== 'string') return null;
  const match = /^"[^"]*","[^"]*","[^"]*","([0-9]+)"/.exec(res.stdout.trim());
  if (!match?.[1]) return null;
  const parsed = Number.parseInt(match[1], 10);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

function runNavigateSource(payload: string | Buffer) {
  const result = spawnSync(COLLECTOR_PATH, ['--navigate-source'], {
    input: payload,
    timeout: 6_000,
    maxBuffer: 65_536,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.stderr.byteLength, 0, `unexpected stderr: ${result.stderr.toString('utf8')}`);
  assert.ok(result.stdout.byteLength > 0 && result.stdout.byteLength <= 1_024);
  assert.equal(result.stdout[result.stdout.byteLength - 1], 0x0a, 'receipt must end with single LF');
  const receipt = parseSourceNavigationReport(result.stdout);
  return { status: result.status, receipt };
}

async function createFixtureHarness(t: TestContext, scenario: string) {
  const root = await makeTempDir(t, `chmcp-win-fixture-${scenario}-`);
  const collector = await verifyNativeBinary(COLLECTOR_PATH, 'computer-history-collector');
  const store = await SegmentStore.open({
    root: join(root, 'store'),
    keyProvider: new MemoryKeyProvider(Buffer.alloc(32, 0x37)),
  });

  const received: Observation[] = [];
  const waiters: Array<{
    predicate: (obs: Observation) => boolean;
    resolve: (obs: Observation) => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];

  const waitFor = (predicate: (obs: Observation) => boolean, timeoutMs = 8_000): Promise<Observation> => {
    const existing = received.find(predicate);
    if (existing) return Promise.resolve(existing);
    return new Promise<Observation>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = waiters.findIndex((w) => w.timer === timer);
        if (idx >= 0) waiters.splice(idx, 1);
        reject(new Error(`timeout waiting for observation in scenario=${scenario} (received=${received.length})`));
      }, timeoutMs);
      waiters.push({ predicate, resolve, reject, timer });
    });
  };

  const supervisor = new CollectorSupervisor({
    helperPath: collector.path,
    helperSha256: collector.sha256,
    cwd: root,
    deviceId: 'win-native-fixture-device',
    spawn: spawnLocal,
    allowFixture: true,
    fixtureArgs: ['--fixture-scenario', scenario],
    requestTimeoutMs: 4_000,
    leaseDurationMs: 1_500,
    onObservation: async (obs, valid) => {
      if (!valid()) return;
      try {
        await store.append(obs, { generation: store.generation, isCurrent: valid });
      } catch (error) {
        if (error && typeof error === 'object' && 'code' in error && error.code === 'stale-generation') return;
        throw error;
      }
      received.push(obs);
      for (let i = waiters.length - 1; i >= 0; i--) {
        const waiter = waiters[i];
        if (waiter && waiter.predicate(obs)) {
          clearTimeout(waiter.timer);
          waiters.splice(i, 1);
          waiter.resolve(obs);
        }
      }
    },
  });

  t.after(async () => {
    for (const waiter of waiters.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(new Error('fixture harness closed'));
    }
    await supervisor.stop();
    await store.close();
  });

  return { supervisor, store, received, waitFor };
}

test('verifyNativeBinary succeeds for built Windows collector and key-store against native-bin/manifest.json', opts, async () => {
  const collector = await verifyNativeBinary(COLLECTOR_PATH, 'computer-history-collector');
  assert.equal(collector.path, COLLECTOR_PATH);
  assert.match(collector.sha256, /^[a-f0-9]{64}$/);
  assert.equal(collector.sha256, sha256(await readFile(COLLECTOR_PATH)));

  const keyStore = await verifyNativeBinary(KEY_STORE_PATH, 'computer-history-key-store');
  assert.equal(keyStore.path, KEY_STORE_PATH);
  assert.match(keyStore.sha256, /^[a-f0-9]{64}$/);
  assert.equal(keyStore.sha256, sha256(await readFile(KEY_STORE_PATH)));
});

test(
  'HistoryService initializes DPAPI master key via real key-store.exe and checks live Windows permissions via real collector.exe',
  opts,
  async (t) => {
    const root = await makeTempDir(t, 'chmcp-win-service-');
    const dataRoot = join(root, 'data');

    const service = createHistoryService({
      dataRoot,
      helperPath: COLLECTOR_PATH,
      keyHelperPath: KEY_STORE_PATH,
      platform: 'win32',
      deviceId: 'win-native-e2e',
    });
    t.after(async () => {
      await service.close();
    });

    const initial = await service.status();
    assert.equal(initial.state, 'not-initialized');
    assert.equal(initial.platform, 'win32');

    const initialized = await service.initializeKey();
    assert.equal(initialized.state, 'stopped');
    assert.equal(initialized.storage?.state, 'open');
    assert.equal(initialized.storage?.records, 0);

    const status = await service.status();
    assert.equal(status.state, 'stopped');
    assert.equal(status.storage?.state, 'open');

    const keyFile = join(dataRoot, DPAPI_KEY_FILENAME);
    const keyStat = await lstat(keyFile);
    assert.equal(keyStat.isFile(), true);
    assert.equal(keyStat.isSymbolicLink(), false);
    const dpapiBlob = await readFile(keyFile);
    assert.ok(dpapiBlob.byteLength > 32, 'DPAPI ciphertext blob must be larger than 32-byte raw key');

    const provider = new WindowsDpapiKeyProvider({
      dataRoot,
      executable: KEY_STORE_PATH,
    });
    const rawKey = await provider.readKey();
    assert.ok(rawKey && rawKey.byteLength === 32, 'key-store.exe must round-trip 32-byte master key');
    try {
      assert.equal(dpapiBlob.includes(rawKey), false, 'master.key.dpapi must not store raw plaintext key bytes');
    } finally {
      rawKey.fill(0);
    }

    const perms = await service.checkPermissions();
    assert.equal(perms.platform, 'win32');
    assert.equal(perms.accessibility, 'not-applicable');
    assert.equal(perms.inputMonitoring, 'not-applicable');
    if (process.env.CI) {
      assert.ok(
        perms.desktopStatus === 'unlocked' || perms.desktopStatus === 'locked' || perms.desktopStatus === 'unknown',
        `unexpected win32 CI desktopStatus: ${perms.desktopStatus}`,
      );
      assert.equal(typeof perms.desktopReason, 'string');
      assert.ok(perms.desktopReason.length > 0);
      assert.notEqual(
        perms.desktopReason,
        'permission-helper-unavailable',
        'must execute real collector.exe --permissions on Windows CI',
      );
      if (perms.desktopStatus === 'unlocked') {
        assert.equal(perms.desktopReason, 'ready');
      } else if (perms.desktopStatus === 'locked') {
        assert.equal(perms.desktopReason, 'screen-locked');
      }
    } else {
      assert.equal(perms.desktopStatus, 'unlocked');
      assert.equal(perms.desktopReason, 'ready');
    }
    assert.equal(perms.promptRequested, false);
    assert.equal(perms.settingsOpened, false);
    assert.ok(Number.isSafeInteger(perms.checkedAtMs) && perms.checkedAtMs > 0);
  },
);

test('real Windows collector extended fixture scenarios: empty, value, focus-loss, sensitive, browser, readerror', opts, async (t) => {
  // 1. empty: resolves focus cleanly, suppresses initial blank snapshot, emits no gap.
  {
    const h = await createFixtureHarness(t, 'empty');
    await h.supervisor.start(BASE_FIXTURE_POLICY);
    const ctx = await h.waitFor(
      (m) =>
        m.payload.kind === 'context.changed' &&
        m.payload.reason === 'focus' &&
        m.target.kind === 'resolved' &&
        m.target.identity.applicationId === 'test.allowed',
    );
    assert.equal(ctx.target.kind, 'resolved');
    await new Promise((r) => setTimeout(r, 300));
    await h.supervisor.stop();
    assert.equal(h.received.some((m) => m.payload.kind === 'gap'), false);
    assert.equal(h.received.some((m) => m.payload.kind === 'text.snapshot'), false);
  }

  // 2. value: falls back from range read to bounded value read and persists complete snapshot.
  {
    const h = await createFixtureHarness(t, 'value');
    await h.supervisor.start(BASE_FIXTURE_POLICY);
    const snap = await h.waitFor((m) => m.payload.kind === 'text.snapshot');
    assert.equal(snap.payload.kind, 'text.snapshot');
    if (snap.payload.kind !== 'text.snapshot') throw new Error('expected text.snapshot');
    assert.equal(snap.payload.source, 'fixture');
    assert.equal(snap.payload.valueState, 'read');
    assert.equal(snap.payload.scope, 'field');
    assert.equal(snap.payload.text, 'Synthetic \u{1F9EA} text');
    assert.equal(snap.payload.coverage.status, 'complete');
    assert.equal(snap.payload.coverage.truncated, false);
    await h.supervisor.stop();
    assert.deepEqual((await h.store.read(snap.eventId))?.payload, snap.payload);
  }

  // 3. focus-loss: advances focusGeneration on focus-unavailable and emits focused-field-unavailable gap without text.
  {
    const h = await createFixtureHarness(t, 'focus-loss');
    await h.supervisor.start(BASE_FIXTURE_POLICY);
    const gap = await h.waitFor((m) => m.payload.kind === 'gap');
    assert.equal(gap.payload.kind, 'gap');
    if (gap.payload.kind !== 'gap') throw new Error('expected gap');
    assert.equal(gap.payload.reason, 'read-error');
    assert.equal(gap.payload.diagnostic?.code, 'focused-field-unavailable');
    assert.deepEqual(gap.target, { kind: 'unresolved', reason: 'focus-unavailable' });
    assert.ok(gap.stamp.focusGeneration >= 2, `expected focusGeneration >= 2, got ${gap.stamp.focusGeneration}`);
    assert.ok(h.supervisor.status().dropped >= 1, 'unresolved context.changed must be dropped by supervisor');
    await h.supervisor.stop();
    assert.equal(h.received.some((m) => m.payload.kind === 'text.snapshot'), false);
  }

  // 4. sensitive: blocks protected field before read and emits secure-field policy-boundary gap.
  {
    const h = await createFixtureHarness(t, 'sensitive');
    await h.supervisor.start(BASE_FIXTURE_POLICY);
    const gap = await h.waitFor((m) => m.payload.kind === 'gap');
    assert.equal(gap.payload.kind, 'gap');
    if (gap.payload.kind !== 'gap') throw new Error('expected gap');
    assert.equal(gap.payload.reason, 'policy-boundary');
    assert.equal(gap.payload.diagnostic?.code, 'secure-field');
    await h.supervisor.stop();
    assert.equal(h.received.some((m) => m.payload.kind === 'text.snapshot'), false);
    assert.equal((await h.store.search({ text: 'Synthetic' })).records.length, 0);
  }

  // 5. browser: mandatory-excluded browser remains blocked even under denylist + allowBrowserContent.
  {
    const h = await createFixtureHarness(t, 'browser');
    await h.supervisor.start({
      ...BASE_FIXTURE_POLICY,
      applicationScope: 'denylist',
      allowedApplicationIds: [],
      allowBrowserContent: true,
    });
    const gap = await h.waitFor((m) => m.payload.kind === 'gap');
    assert.equal(gap.payload.kind, 'gap');
    if (gap.payload.kind !== 'gap') throw new Error('expected gap');
    assert.equal(gap.payload.reason, 'policy-boundary');
    assert.equal(gap.payload.diagnostic?.code, 'application-not-allowed');
    await h.supervisor.stop();
    assert.equal(h.received.some((m) => m.payload.kind === 'text.snapshot'), false);
    assert.equal((await h.store.search({ text: 'Synthetic' })).records.length, 0);
  }

  // 6. readerror: reports text-read-unavailable read-error gap without emitting text.
  {
    const h = await createFixtureHarness(t, 'readerror');
    await h.supervisor.start(BASE_FIXTURE_POLICY);
    const gap = await h.waitFor((m) => m.payload.kind === 'gap');
    assert.equal(gap.payload.kind, 'gap');
    if (gap.payload.kind !== 'gap') throw new Error('expected gap');
    assert.equal(gap.payload.reason, 'read-error');
    assert.equal(gap.payload.diagnostic?.code, 'text-read-unavailable');
    await h.supervisor.stop();
    assert.equal(h.received.some((m) => m.payload.kind === 'text.snapshot'), false);
  }
});

test('real Windows collector --navigate-source enforces strict request validation and safety refusals', opts, () => {
  // 1. Invalid JSON and malformed payloads -> exit 64 + refused/invalid-request.
  for (const payload of ['not-json', '{}', '{"version":1,"version":1}', '\ufeff{}']) {
    const { status, receipt } = runNavigateSource(payload);
    assert.equal(status, 64, `expected exit 64 for payload ${JSON.stringify(payload)}`);
    assert.deepEqual(receipt, {
      version: 1,
      outcome: 'refused',
      reason: 'invalid-request',
      captured: false,
      launched: false,
    });
  }

  // 2. Oversized stdin (> 2048 B) -> exit 64 + refused/input-too-large.
  {
    const { status, receipt } = runNavigateSource(' '.repeat(2_049));
    assert.equal(status, 64);
    assert.deepEqual(receipt, {
      version: 1,
      outcome: 'refused',
      reason: 'input-too-large',
      captured: false,
      launched: false,
    });
  }

  // 3. Non-default desktop (winsta0-winlogon-wts-1) -> exit 64 + refused/invalid-request.
  {
    const payload = JSON.stringify({
      version: 1,
      applicationId: 'notepad.exe',
      processId: 4242,
      processStartTime: 'unix-ms:1700000000000.000',
      osSessionId: 'wts-1',
      desktopId: 'winsta0-winlogon-wts-1',
    });
    const { status, receipt } = runNavigateSource(payload);
    assert.equal(status, 64);
    assert.deepEqual(receipt, {
      version: 1,
      outcome: 'refused',
      reason: 'invalid-request',
      captured: false,
      launched: false,
    });
  }

  // 4. Browser app (msedge.exe) with nonexistent PID in the current WTS session -> refused/application-blocked or application-unavailable.
  {
    const sid = currentWindowsSessionId();
    assert.ok(sid !== null, 'failed to determine current Windows WTS session ID');
    const osSessionId = `wts-${sid}`;
    const payload = JSON.stringify({
      version: 1,
      applicationId: 'msedge.exe',
      processId: 2_147_483_640,
      processStartTime: 'unix-ms:1700000000000.000',
      osSessionId,
      desktopId: `winsta0-default-${osSessionId}`,
    });
    const { status, receipt } = runNavigateSource(payload);
    assert.equal(status, 0);
    assert.equal(receipt.outcome, 'refused');
    assert.equal(receipt.captured, false);
    assert.equal(receipt.launched, false);
    assert.ok(
      receipt.reason === 'application-blocked' || receipt.reason === 'application-unavailable',
      `expected application-blocked or application-unavailable, got ${receipt.reason}`,
    );
  }
});

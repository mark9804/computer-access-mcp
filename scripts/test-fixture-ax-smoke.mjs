import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { performance } from 'node:perf_hooks';

// Real GUI/AX integration, never an ordinary/offline test. No launch, permission
// request, existing History/Keychain, input listener, synthetic input event or
// clipboard access. The explicit flag authorizes only this exact fixture app.
const mode = process.argv[3];
const modes = ['plain', 'empty', 'secure', 'visible', 'async'];
if (process.argv[2] !== '--authorized-synthetic-ax' || !modes.includes(mode) || process.argv.length !== 4) {
  console.error(JSON.stringify({ ok: false, failure: 'explicit-synthetic-authorization-required' }));
  process.exit(64);
}
const APP_ID = 'com.dsh.computer-history.fixture';
const DEVICE_ID = 'synthetic-ax-smoke';
const PLAIN = '你好，合成测试 𠮷 smoke-1';
const PREFIX = 'FIXTURE-VISIBLE-PREFIX-314159';
const TAIL = 'FIXTURE-VISIBLE-TAIL-271828';
const BEFORE = '异步合成测试 FIXTURE-ASYNC-BEFORE-161803';
const AFTER = '异步合成测试 FIXTURE-ASYNC-AFTER-161803';
const CASE_WAIT_MS = 12_000;
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const runFile = promisify(execFile);
const ownFailures = new Set();
function check(condition, code) {
  if (condition) return;
  ownFailures.add(code);
  throw new Error(code);
}
const knownFailures = new Set([
  'unsupported-platform', 'permission-denied', 'helper-permission-denied',
  'desktop-unavailable', 'desktop-lock-transition', 'screen-locked',
  'session-unavailable', 'console-unavailable', 'login-incomplete',
  'lock-state-unavailable', 'desktop-signal-invalid', 'desktop-session-changed',
  'desktop-session-mismatch', 'start-failed', 'collector-not-running',
  'native-hash-mismatch', 'native-manifest-mismatch',
  'native-manifest-entry-missing',
  'unsafe-native-file', 'unsafe-native-manifest',
  'native-lock-unavailable', 'helper-hello-timeout', 'helper-response-timeout',
  'storage-commit-failed', 'authentication-failed', 'invalid-store',
]);
function failureCode(error) {
  return error instanceof Error && (ownFailures.has(error.message) || knownFailures.has(error.message))
    ? error.message : 'synthetic-smoke-failed';
}
async function prepareFixture(selectedMode, timeout = 6000) {
  try {
    // Asynchronous subprocess: do not block collector heartbeats or observations
    // while Swift prepares the synthetic before/after scenario.
    const result = await runFile('swift', ['scripts/prepare-fixture-smoke.swift', selectedMode], {
      cwd: root, encoding: 'utf8', timeout, killSignal: 'SIGKILL', maxBuffer: 4096,
    });
    check(result.stdout.trim() === `fixture-prepared-${selectedMode}`, 'fixture-preparation-unconfirmed');
  } catch (error) {
    // Swift/provider stderr may contain arbitrary runtime details. Never print it.
    const codes = new Map([[64, 'fixture-preparation-invalid'], [65, 'fixture-identity-mismatch'],
      [66, 'fixture-control-unavailable'], [67, 'fixture-secure-role-mismatch'],
      [68, 'fixture-preparation-action-failed'], [69, 'fixture-focus-unconfirmed'],
      [77, 'fixture-ax-permission-required']]);
    check(false, codes.get(error?.code) ?? 'fixture-preparation-failed');
  }
}
function visibleSnapshot(payload) {
  return payload.kind === 'text.snapshot' && payload.source === 'ax.range'
    && payload.valueState === 'read' && payload.rangeBasis === 'visible'
    && payload.scope === 'accessible-range' && payload.range?.unit === 'utf16'
    && Number.isSafeInteger(payload.range.start) && payload.range.start > 0
    && typeof payload.text === 'string' && payload.range.length === payload.text.length
    && payload.text.includes(TAIL) && !payload.text.includes(PREFIX)
    && Number.isSafeInteger(payload.totalLength)
    && payload.range.start + payload.range.length <= payload.totalLength
    && payload.coverage.status === 'partial'
    && payload.coverage.missingReasons.includes('visible-range-only');
}
let tempBase; let temp; let key; let store; let supervisor; let timer; let navigator;
let result; let failure; let observationFailure; let finish;
let secureInputBlockedStart = false;
let beforeSeen = false; let afterSeen = false; let seenText = 0;
const gaps = Object.create(null);
try {
  const [{ SegmentStore }, { MemoryKeyProvider }, { CollectorSupervisor }, { spawnLocal }, { verifyNativeBinary }] = await Promise.all([
    import('../dist/storage/segment-store.js'),
    import('../dist/storage/key-provider.js'),
    import('../dist/host/collectors/supervisor.js'),
    import('../dist/host/collectors/local-process.js'),
    import('../dist/host/service/binaries.js'),
  ]);
  // Verify current collector AND schema hashes before any GUI preparation.
  const binary = await verifyNativeBinary(join(root, 'native-bin/computer-history-collector'), 'computer-history-collector');
  tempBase = await realpath(tmpdir());
  temp = await realpath(await mkdtemp(join(tempBase, 'dsh-real-synthetic-ax-')));
  key = randomBytes(32);
  const storeOptions = { root: join(temp, 'data'), keyProvider: new MemoryKeyProvider(key) };
  store = await SegmentStore.open(storeOptions);
  // Async must leave a previous secure-field focus before start, then arm its
  // fixture-owned 2-second timer only after the collector has acknowledged start.
  await prepareFixture(mode === 'async' ? 'plain' : mode);
  const observed = new Promise(resolve => { finish = resolve; });
  supervisor = new CollectorSupervisor({
    helperPath: binary.path, helperSha256: binary.sha256, cwd: temp,
    deviceId: DEVICE_ID, spawn: spawnLocal,
    async onObservation(record, isCurrent) {
      try {
        check(record.target.kind === 'unresolved' || (record.target.identity.applicationId === APP_ID
          && record.target.identity.deviceId === DEVICE_ID), 'non-fixture-observation');
        check(record.payload.kind !== 'input.activity', 'unexpected-input-activity');
        if (record.payload.kind === 'text.snapshot') {
          check(record.target.kind === 'resolved', 'unresolved-text-observation');
          check(['ax.range', 'ax.value'].includes(record.payload.source), 'non-ax-text-observation');
          check(record.actor === 'unknown' && record.relatedActionIds.length === 0, 'unexpected-causal-attribution');
        }
        await store.append(record, { generation: store.generation, isCurrent });
        const payload = record.payload;
        if (payload.kind === 'gap') gaps[payload.reason] = (gaps[payload.reason] ?? 0) + 1;
        if (payload.kind !== 'text.snapshot') return;
        seenText++;
        if (mode === 'plain' && payload.text === PLAIN) finish(true);
        if (mode === 'empty' && payload.valueState === 'read' && payload.text === '' && payload.range?.length === 0) finish(true);
        if (mode === 'visible' && visibleSnapshot(payload)) finish(true);
        if (mode === 'async') {
          if (payload.text === BEFORE) beforeSeen = true;
          if (beforeSeen && payload.text === AFTER) { afterSeen = true; finish(true); }
        }
      } catch (error) {
        observationFailure = failureCode(error);
        finish(false);
        throw error;
      }
    },
  });
  try {
    await supervisor.start({ enabled: true, allowedApplicationIds: [APP_ID], inputActivity: false,
      textRange: mode === 'visible' ? 'visible' : 'prefix', sampleIntervalMs: 1000,
      maxTextCodeUnits: mode === 'visible' ? 2048 : 512, maxPending: 16,
      debounceMs: 150, maxWaitMs: 500, readTimeoutMs: 1500 });
  } catch (error) {
    // Preserve the already-confirmed NSSecureTextField/Secure Event Input negative
    // case ONLY. Missing AX, arbitrary desktop or startup errors are never a pass.
    if (mode === 'secure' && error instanceof Error && error.message === 'desktop-lock-transition') secureInputBlockedStart = true;
    else throw error;
  }
  const started = performance.now();
  if (!secureInputBlockedStart) {
    timer = setTimeout(() => finish(false), mode === 'secure' ? 6500 : CASE_WAIT_MS);
    if (mode === 'async') await prepareFixture('async', Math.min(6000, CASE_WAIT_MS));
    const found = await observed;
    clearTimeout(timer); timer = undefined;
    check(!observationFailure, observationFailure ?? 'observation-failed');
    check(mode === 'secure' || found, `${mode}-evidence-timeout`);
    check(supervisor.status().state === 'running', 'collector-not-running');
  }
  const observationWaitMs = Math.round(performance.now() - started);
  if (mode === 'plain') {
    await supervisor.pause();
    const beforePause = store.status().records;
    // Bounded observation period, not polling a job: prove our paused collector
    // contributes no records while the synthetic field remains unchanged.
    await new Promise(resolve => setTimeout(resolve, 1300));
    check(store.status().records === beforePause, 'paused-collector-stored-content');
    // The user may switch away during the pause window. Only the explicit test
    // setup re-focuses its own fixture; production resume never forces focus.
    await prepareFixture('plain');
    finish = undefined;
    const resumed = new Promise(resolve => { finish = resolve; });
    // Match HistoryService.resume: retire the paused helper, then use the exact
    // original policy. Do not carry one-shot AX/session objects across a pause.
    check((await supervisor.stop()).state === 'stopped', 'paused-helper-exit-unconfirmed');
    await supervisor.start({ enabled: true, allowedApplicationIds: [APP_ID], inputActivity: false,
      textRange: 'prefix', sampleIntervalMs: 1000, maxTextCodeUnits: 512, maxPending: 16,
      debounceMs: 150, maxWaitMs: 500, readTimeoutMs: 1500 });
    timer = setTimeout(() => finish(false), CASE_WAIT_MS);
    check(await resumed, 'resumed-fixture-evidence-timeout');
    clearTimeout(timer); timer = undefined;
  }
  const stopped = await supervisor.stop();
  check(stopped.state === 'stopped', 'owned-helper-exit-unconfirmed');
  // Reopen our newly minted encrypted store with the in-memory fake key. A pass
  // must survive persistence, not merely a callback or in-memory evidence flag.
  await store.close();
  store = await SegmentStore.open(storeOptions);
  const all = await store.search({ applicationId: APP_ID, kind: 'text', order: 'asc', limit: 100, maxBytes: 256 * 1024 });
  check(!all.hasMore, 'synthetic-query-incomplete');
  const snapshots = all.records.filter(record => record.payload.kind === 'text.snapshot');
  const matched = await store.search({ applicationId: APP_ID, text: '合成测试', limit: 10 });
  const status = store.status();
  let visibleRange;
  if (mode === 'plain') check(snapshots.some(record => record.payload.text === PLAIN) && matched.records.length > 0, 'synthetic-chinese-text-not-found');
  if (mode === 'empty') check(snapshots.some(record => record.payload.valueState === 'read' && record.payload.text === '' && record.payload.range?.length === 0), 'empty-field-not-observed');
  if (mode === 'secure') {
    check(status.counts.text === 0 && seenText === 0, 'secure-field-produced-text');
    check(secureInputBlockedStart || (gaps['policy-boundary'] ?? 0) > 0, 'secure-refusal-not-observed');
  }
  if (mode === 'visible') {
    const record = snapshots.find(record => visibleSnapshot(record.payload));
    check(record !== undefined, 'visible-tail-range-not-persisted');
    visibleRange = { ...record.payload.range, totalLength: record.payload.totalLength,
      rangeBasis: record.payload.rangeBasis, coverage: record.payload.coverage.status, truncated: record.payload.coverage.truncated,
      missingReasons: record.payload.coverage.missingReasons, tailMarkerFound: true, prefixMarkerAbsent: true };
  }
  if (mode === 'async') {
    const beforeIndex = snapshots.findIndex(record => record.payload.text === BEFORE);
    const afterIndex = snapshots.findIndex((record, index) => index > beforeIndex && record.payload.text === AFTER);
    check(beforeSeen && afterSeen && beforeIndex >= 0 && afterIndex > beforeIndex, 'async-before-after-not-persisted');
    check(snapshots[afterIndex].payload.captureStartMs >= snapshots[beforeIndex].payload.captureStartMs, 'async-snapshot-order-invalid');
  }
  let navigation;
  if (mode === 'plain') {
    const record = snapshots.find(record => record.payload.text === PLAIN);
    check(record?.target.kind === 'resolved', 'synthetic-navigation-record-missing');
    const identity = record.target.identity;
    const assertSynthetic = () => check(identity.applicationId === APP_ID && identity.deviceId === DEVICE_ID, 'synthetic-navigation-scope-invalid');
    const { createSourceNavigation } = await import('../dist/host/service/source-navigation.js');
    navigator = createSourceNavigation({ executable: binary.path, spawn: spawnLocal });
    // The fixture is already foreground: this tests the legitimate same-app
    // activation path, not restoration of an old window or a cross-app switch.
    const receipt = await navigator.navigate(identity, new AbortController().signal, assertSynthetic);
    check(receipt.outcome === 'activated' && receipt.captured === false && receipt.launched === false, 'synthetic-navigation-not-confirmed');
    const wrongBirth = { ...identity, processStartTime: 'unix-ms:1.000' };
    const refused = await navigator.navigate(wrongBirth, new AbortController().signal, assertSynthetic);
    check(refused.outcome === 'refused' && refused.reason === 'application-mismatch', 'synthetic-navigation-wrong-birth-accepted');
    navigation = { sameForegroundApp: receipt.outcome, wrongBirth: refused.reason, captured: false, launched: false };
    await navigator.close(); navigator = undefined;
    await store.forget({ all: true }); await store.close(); store = await SegmentStore.open(storeOptions);
    check(store.status().records === 0, 'synthetic-forget-reopen-resurrected');
  }
  result = { ok: true, mode, records: status.records, textRecords: status.counts.text, gapRecords: status.counts.gap,
    matchedChineseText: matched.records.length, gapReasons: gaps, secureInputBlockedStart,
    ...(visibleRange ? { visibleRange } : {}),
    ...(navigation ? { navigation, pauseResumeVerified: true, forgetReopenEmpty: true } : {}),
    ...(mode === 'async' ? { beforeSnapshotFound: true, afterSnapshotFound: true, inputCausalityAsserted: false } : {}),
    textRange: mode === 'visible' ? 'visible' : 'prefix', sampleIntervalMs: 1000,
    observationWaitMs, maxObservationWaitMs: CASE_WAIT_MS, encryptedStoreReopened: true,
    collectorStopped: true, existingHistoryRead: false, keychainAccess: false, inputActivity: false };
} catch (error) {
  failure = failureCode(error);
} finally {
  if (timer) clearTimeout(timer);
  let cleanupConfirmed = false;
  try {
    const stopped = await supervisor?.stop();
    check(!stopped || stopped.state === 'stopped', 'owned-helper-exit-unconfirmed');
    await navigator?.close();
    await store?.close();
    cleanupConfirmed = true;
  } catch (error) { failure = failureCode(error); }
  key?.fill(0);
  if (temp && cleanupConfirmed) {
    try {
      // Exact ownership/canonical-path checks before deleting only this newly
      // created synthetic directory. Never remove user History or a user lock.
      check(resolve(temp) === temp && dirname(temp) === tempBase
        && temp.startsWith(join(tempBase, 'dsh-real-synthetic-ax-'))
        && await realpath(temp) === temp, 'unsafe-synthetic-cleanup-path');
      await rm(temp, { recursive: true, force: false });
    } catch { failure = 'synthetic-cleanup-failed'; }
  }
}
if (failure) {
  console.error(JSON.stringify({ ok: false, mode, failure, gapReasons: gaps,
    existingHistoryRead: false, keychainAccess: false }));
  process.exitCode = 1;
} else {
  console.log(JSON.stringify({ ...result, temporaryStoreRemoved: true }, null, 2));
}

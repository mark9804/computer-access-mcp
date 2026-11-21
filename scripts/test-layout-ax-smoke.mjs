import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, readdir, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

// Standalone real-AX acceptance, never imported by the default offline runner.
// Only the fixed synthetic .app may be prepared/read. No launch, native --fixture,
// permission prompt, input listener/posting, real History, Keychain or model share.
const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const APP_ID = 'com.dsh.computer-access.fixture';
const DEVICE_ID = 'synthetic-layout-ax';
const PLAIN = '你好，合成测试 𠮷 smoke-1';
const CASES = ['surface', 'protected', 'excluded'];
const CASE_WAIT_MS = 12_000;
const NEGATIVE_WAIT_MS = 4_000;
const PREPARE_WAIT_MS = 10_000;
const MAX_LAYOUT_PAGES = 8_300; // At most 8192 UTF16 + 96 nodes, with progress required.
const runFile = promisify(execFile);

const failures = new Set([
  'explicit-synthetic-layout-authorization-required', 'unsupported-platform',
  'fixture-preparation-failed', 'fixture-preparation-unconfirmed', 'fixture-identity-mismatch',
  'fixture-control-unavailable', 'fixture-focus-unconfirmed', 'fixture-ax-permission-required',
  'fixture-metadata-invalid', 'non-fixture-observation', 'unexpected-input-evidence',
  'unexpected-content-evidence', 'surface-not-real-ax', 'surface-evidence-timeout',
  'surface-geometry-unavailable', 'surface-roles-unavailable', 'surface-focus-unavailable',
  'surface-unicode-unavailable', 'surface-identity-mismatch', 'collector-not-running',
  'surface-reopen-mismatch', 'layout-mismatch', 'layout-pagination-failed',
  'layout-filter-failed', 'plaintext-at-rest', 'negative-content-produced',
  'negative-refusal-unconfirmed', 'pause-produced-evidence', 'owned-helper-exit-unconfirmed',
  'unsafe-cleanup', 'cleanup-failed', 'observation-failed', 'layout-smoke-timeout',
  'permission-denied', 'desktop-unavailable', 'desktop-lock-transition', 'screen-locked',
  'session-unavailable', 'console-unavailable', 'login-incomplete', 'lock-state-unavailable',
  'desktop-signal-invalid', 'desktop-session-changed', 'desktop-session-mismatch',
  'native-hash-mismatch', 'native-resource-mismatch', 'native-manifest-mismatch',
  'native-manifest-entry-missing', 'unsafe-native-file', 'unsafe-native-manifest',
  'helper-hello-timeout', 'helper-response-timeout', 'helper-exited', 'start-failed',
  'storage-commit-failed', 'authentication-failed', 'invalid-store',
]);
const diagnosticCodes = new Set([
  'application-not-allowed', 'application-unavailable', 'browser-excluded',
  'focused-field-unavailable', 'focused-role-not-text', 'secure-field',
  'field-security-unknown', 'visible-range-unavailable', 'text-read-unavailable',
  'text-result-invalid', 'focus-changed', 'invalid-sampling-policy', 'read-deadline',
  'accessibility-denied', 'desktop-unavailable', 'capture-authority-changed',
  'worker-retirement-pending', 'surface-not-started-budget', 'surface-call-budget',
  'surface-time-budget', 'surface-anchor-unavailable', 'surface-boundary-unverified',
  'surface-security-excluded', 'surface-provider-unavailable', 'other',
]);
function check(condition, code) { if (!condition) throw new Error(code); }
function same(actual, expected, code) {
  try { assert.deepStrictEqual(actual, expected); } catch { throw new Error(code); }
}
function code(error) { return error instanceof Error && failures.has(error.message) ? error.message : 'synthetic-layout-failed'; }
function count(value) { return Number.isSafeInteger(value) && value >= 0 ? value : 0; }

export function parseLayoutSmokeArgs(argv) {
  check((argv.length === 1 || argv.length === 2) && argv[0] === '--authorized-synthetic-layout'
    && (argv.length === 1 || CASES.includes(argv[1])), 'explicit-synthetic-layout-authorization-required');
  return argv[1] ?? 'surface';
}

export function fixtureMetadata(stdout, mode) {
  let value;
  try { value = JSON.parse(stdout); } catch { throw new Error('fixture-metadata-invalid'); }
  check(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === 'marker,processId,processStartTime'
    && value.marker === `fixture-prepared-${mode}`
    && Number.isSafeInteger(value.processId) && value.processId > 1
    && typeof value.processStartTime === 'string' && /^unix-ms:[0-9]+\.[0-9]{3}$/u.test(value.processStartTime), 'fixture-metadata-invalid');
  return { processId: value.processId, processStartTime: value.processStartTime };
}

export function assertFixedObservation(record, expected) {
  check(record?.target?.kind === 'unresolved' || (record?.target?.kind === 'resolved'
    && record.target.identity.applicationId === APP_ID && record.target.identity.deviceId === DEVICE_ID
    && record.target.identity.processId === expected.processId
    && record.target.identity.processStartTime === expected.processStartTime), 'non-fixture-observation');
  check(!['input.text', 'input.activity', 'selection.snapshot'].includes(record?.payload?.kind), 'unexpected-input-evidence');
  if (record?.payload?.kind === 'surface.snapshot') {
    check(record.target.kind === 'resolved' && record.payload.source === 'ax.tree'
      && record.payload.scope === 'window', 'surface-not-real-ax');
  }
  if (record?.payload?.kind === 'text.snapshot') {
    check(record.target.kind === 'resolved' && record.payload.source === 'ax.range', 'unexpected-content-evidence');
  }
}

function page(value) { check(value?.found === true && value.source === 'encrypted-history', 'layout-mismatch'); return value; }
function projected(node) {
  return { id: node.id, role: node.axRole ?? node.role, roleSource: node.axRole === undefined ? 'category' : 'ax',
    text: node.text ?? null, textOffset: 0, textLength: node.text?.length ?? null, textTruncated: false,
    bounds: node.bounds === undefined ? null : [node.bounds.x, node.bounds.y, node.bounds.width, node.bounds.height],
    observedAtMs: node.observedAtMs, boundsObservedAtMs: node.boundsObservedAtMs ?? null, focused: node.focused ?? null };
}
function intersects(a, b) {
  return a.width > 0 && a.height > 0 && b.width > 0 && b.height > 0
    && a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;
}
function envelope(value) {
  const result = { ok: true, operation: 'historyLayout', data: value, source: value.source, coverage: value.coverage,
    truncated: value.truncated, missingReasons: value.missingReasons, untrustedData: true };
  const bytes = Buffer.byteLength(JSON.stringify(result));
  check(bytes <= 65_536 && Buffer.byteLength(JSON.stringify(value)) <= 60_000, 'layout-pagination-failed');
  return bytes;
}

// The exact production Store.layout API is also the model tool's pure storage
// path. This test does NOT invoke a model, grant sharing, or use a fake collector.
export async function verifyStoredLayout(store, record) {
  const snapshot = record.payload;
  check(snapshot.kind === 'surface.snapshot' && record.target.kind === 'resolved', 'layout-mismatch');
  const locator = { eventId: record.eventId, applicationId: APP_ID };
  const event = page(await store.layout(locator));
  const bySnapshot = page(await store.layout({ snapshotId: snapshot.snapshotId, applicationId: APP_ID }));
  same(event, bySnapshot, 'surface-reopen-mismatch');
  same(event.sourceCoverage, snapshot.coverage, 'layout-mismatch');
  same(event.windowSize, snapshot.geometry?.windowSize ?? null, 'layout-mismatch');
  check(event.coordinateSpace === (snapshot.geometry?.coordinateSpace ?? null), 'layout-mismatch');
  check(event.geometryObservedAtMs === (snapshot.geometry?.observedAtMs ?? null), 'layout-mismatch');
  check(event.eventId === record.eventId && event.snapshotId === snapshot.snapshotId
    && event.windowId === record.target.identity.windowId && event.evidenceSource === 'ax.tree', 'layout-mismatch');
  const defaults = snapshot.nodes.filter(node => (typeof node.text === 'string' && /\S/u.test(node.text))
    || (node.role === 'editable' && node.focused === true));
  same(event.nodes, defaults.map(projected), 'layout-mismatch');
  check(!event.hasMore, 'layout-mismatch');
  const focused = snapshot.nodes.find(node => node.focused === true)?.id ?? null;
  check(event.snapshotFocusedNodeId === focused, 'layout-mismatch');
  let maximumEnvelopeBytes = envelope(event);

  const request = { ...locator, maxNodes: 1, maxChars: 3 };
  const reconstructed = new Map(); const order = []; const cursors = new Set();
  let current = page(await store.layout(request)); let pages = 0;
  for (;;) {
    pages++; check(pages <= MAX_LAYOUT_PAGES && current.nodes.length === 1, 'layout-pagination-failed');
    maximumEnvelopeBytes = Math.max(maximumEnvelopeBytes, envelope(current));
    same(current.sourceCoverage, snapshot.coverage, 'layout-pagination-failed');
    const node = current.nodes[0]; const previous = reconstructed.get(node.id);
    const original = defaults.find(candidate => candidate.id === node.id);
    check(original !== undefined && (node.text === null || (node.text.length <= 3 && node.text.isWellFormed())), 'layout-pagination-failed');
    if (previous === undefined) { order.push(node.id); check(node.textOffset === 0, 'layout-pagination-failed'); }
    else check(typeof previous === 'string' && node.textOffset === previous.length, 'layout-pagination-failed');
    check(previous === undefined || (typeof node.text === 'string' && node.text.length > 0), 'layout-pagination-failed');
    reconstructed.set(node.id, node.text === null ? null : (previous ?? '') + node.text);
    same({ ...node, text: original.text ?? null, textOffset: 0, textTruncated: false }, projected(original), 'layout-pagination-failed');
    if (!current.hasMore) {
      check(current.nextCursor === undefined, 'layout-pagination-failed');
      if (pages > 1) check(current.coverage.status !== 'complete' && current.missingReasons.includes('continuation-page'), 'layout-pagination-failed');
      break;
    }
    check(current.truncated && typeof current.nextCursor === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(current.nextCursor)
      && !cursors.has(current.nextCursor), 'layout-pagination-failed');
    cursors.add(current.nextCursor);
    current = page(await store.layout({ ...request, cursor: current.nextCursor }));
  }
  same(order, defaults.map(node => node.id), 'layout-pagination-failed');
  for (const node of defaults) same(reconstructed.get(node.id), node.text ?? null, 'layout-pagination-failed');
  check(pages > 1, 'layout-pagination-failed');

  // Explicit node IDs must expose the actual stored wrappers/unknowns, not make
  // geometry up from siblings. No fake surface is appended to the live test DB.
  const requested = snapshot.nodes.slice(0, Math.min(3, snapshot.nodes.length));
  const selection = page(await store.layout({ ...locator, nodeIds: requested.map(node => node.id) }));
  same(selection.nodes, requested.map(projected), 'layout-filter-failed');
  check(!selection.hasMore, 'layout-filter-failed');
  const known = defaults.find(node => node.bounds && node.bounds.width > 0 && node.bounds.height > 0);
  check(known !== undefined, 'surface-geometry-unavailable');
  const spatial = page(await store.layout({ ...locator, bounds: known.bounds }));
  same(spatial.nodes, defaults.filter(node => node.bounds && intersects(node.bounds, known.bounds)).map(projected), 'layout-filter-failed');
  check(spatial.projection.missingGeometryFilteredNodes === defaults.filter(node => !node.bounds).length, 'layout-filter-failed');
  const unknown = snapshot.nodes.filter(node => node.bounds === undefined);
  let unknownGeometryChecked = false;
  if (unknown.length > 0) {
    const unknownIds = unknown.map(node => node.id);
    const unlocated = page(await store.layout({ ...locator, nodeIds: unknownIds }));
    check(unlocated.nodes.every(node => node.bounds === null && node.boundsObservedAtMs === null), 'layout-filter-failed');
    const rejected = page(await store.layout({ ...locator, nodeIds: unknownIds, bounds: known.bounds }));
    check(rejected.nodes.length === 0 && rejected.projection.missingGeometryFilteredNodes === unknown.length, 'layout-filter-failed');
    unknownGeometryChecked = true;
  }
  const noArea = page(await store.layout({ ...locator, bounds: { x: 0, y: 0, width: 0, height: 0 } }));
  check(noArea.nodes.length === 0, 'layout-filter-failed');
  const absent = await store.layout({ ...locator, applicationId: 'synthetic-not-the-fixture' });
  check(absent.found === false, 'layout-filter-failed');
  return { eventLocatorVerified: true, snapshotLocatorVerified: true, geometryVerified: true,
    storedProjectionVerified: true, unicodeContinuationVerified: true, continuationPages: pages,
    nodeIdFilterVerified: true, boundsFilterVerified: true, unknownGeometryChecked,
    unknownGeometryNodes: unknown.length, maximumEnvelopeBytes };
}

async function prepareFixture(mode) {
  let prepared;
  try {
    prepared = await runFile('swift', ['scripts/prepare-fixture-smoke.swift', mode, '--metadata'], {
      cwd: ROOT, encoding: 'utf8', timeout: PREPARE_WAIT_MS, killSignal: 'SIGKILL', maxBuffer: 4096,
    });
  } catch (error) {
    const mapped = new Map([[65, 'fixture-identity-mismatch'], [66, 'fixture-control-unavailable'],
      [69, 'fixture-focus-unconfirmed'], [77, 'fixture-ax-permission-required']]);
    throw new Error(mapped.get(error?.code) ?? 'fixture-preparation-failed');
  }
  return fixtureMetadata(prepared.stdout.trim(), mode);
}

async function checkEncryptedAtRest(root) {
  // Only this run's freshly minted encrypted store. Never list a user dataRoot.
  for (const name of await readdir(root)) {
    const bytes = await readFile(join(root, name));
    for (const fixed of [PLAIN, APP_ID, 'window-top-left-point']) check(!bytes.includes(Buffer.from(fixed)), 'plaintext-at-rest');
  }
}

async function main(mode) {
  let tempBase; let temp; let key; let store; let supervisor; let timer; let deadline;
  let result; let failure; let finish; let observationFailure; let captured;
  const diagnostics = {}; const committed = {}; let pausedAndStopped = false; let reopened = false;
  try {
    check(process.platform === 'darwin', 'unsupported-platform');
    const [{ SegmentStore }, { MemoryKeyProvider }, { CollectorSupervisor }, { spawnLocal }, { verifyNativeBinary }] = await Promise.all([
      import('../dist/storage/segment-store.js'), import('../dist/storage/key-provider.js'), import('../dist/host/collectors/supervisor.js'),
      import('../dist/host/collectors/local-process.js'), import('../dist/host/service/binaries.js'),
    ]);
    const binary = await verifyNativeBinary(join(ROOT, 'native-bin/computer-access-collector'), 'computer-access-collector');
    tempBase = await realpath(tmpdir());
    temp = await realpath(await mkdtemp(join(tempBase, 'dsh-layout-synthetic-'))); key = randomBytes(32);
    const options = { root: join(temp, 'data'), keyProvider: new MemoryKeyProvider(key) };
    store = await SegmentStore.open(options);
    const expected = await prepareFixture(mode === 'protected' ? 'protected' : 'plain');
    const observed = new Promise(resolve => { finish = resolve; });
    // Deadline is armed before start: neither startup nor a missing observation can
    // leave a listener running indefinitely. Stop is idempotent and bounded by the
    // production supervisor's request/exit timeouts, including failure teardown.
    deadline = setTimeout(() => { observationFailure = 'layout-smoke-timeout'; finish(false); void supervisor?.stop(); }, 22_000);
    supervisor = new CollectorSupervisor({ helperPath: binary.path, helperSha256: binary.sha256,
      cwd: temp, deviceId: DEVICE_ID, spawn: spawnLocal, requestTimeoutMs: 3000,
      async onObservation(record, isCurrent) {
        try {
          assertFixedObservation(record, expected);
          if (mode !== 'surface') check(['gap', 'context.changed'].includes(record.payload.kind), 'negative-content-produced');
          await store.append(record, { generation: store.generation, isCurrent });
          const payload = record.payload;
          committed[payload.kind] = (committed[payload.kind] ?? 0) + 1;
          if (payload.kind === 'gap') {
            const diagnostic = diagnosticCodes.has(payload.diagnostic?.code) ? payload.diagnostic.code : 'other';
            diagnostics[diagnostic] = (diagnostics[diagnostic] ?? 0) + 1;
            // A genuine focus/authority break ends this invocation; never re-prepare,
            // auto-resume or retry against another current app/window.
            if (['focus-changed', 'capture-authority-changed'].includes(diagnostic)) throw new Error('surface-identity-mismatch');
          }
          if (mode !== 'surface' || captured || payload.kind !== 'surface.snapshot') return;
          const focused = payload.nodes.find(node => node.focused === true && node.text === PLAIN);
          check(focused !== undefined && focused.axRole === 'AXTextField', 'surface-focus-unavailable');
          check(payload.geometry?.coordinateSpace === 'window-top-left-point' && payload.geometry.windowSize.width > 0
            && payload.geometry.windowSize.height > 0 && focused.bounds !== undefined, 'surface-geometry-unavailable');
          // Independent known-fixture constraints catch desktop-absolute values
          // mislabeled as window-relative without performing another AX read.
          check(focused.bounds.x >= 0 && focused.bounds.x <= 64
            && focused.bounds.width >= 600 && focused.bounds.width <= 640 && focused.bounds.height > 0
            && focused.bounds.x + focused.bounds.width <= payload.geometry.windowSize.width + 1
            && focused.bounds.y >= 0 && focused.bounds.y < payload.geometry.windowSize.height
            && focused.bounds.y + focused.bounds.height <= payload.geometry.windowSize.height + 1, 'surface-geometry-unavailable');
          check(payload.nodes.some(node => node.axRole && node.focused === false), 'surface-roles-unavailable');
          check(focused.text.isWellFormed() && focused.text.includes('合成测试') && focused.text.includes('𠮷'), 'surface-unicode-unavailable');
          captured = structuredClone(record); finish(true);
        } catch (error) {
          observationFailure = code(error); finish(false); throw new Error(observationFailure);
        }
      },
    });
    await supervisor.start({ enabled: true, applicationScope: 'allowlist', allowedApplicationIds: [APP_ID],
      excludedApplicationIds: mode === 'excluded' ? [APP_ID] : [], allowBrowserContent: false,
      fieldSecurity: 'denylist', axCompatibility: false, textMarkers: false, captureScope: 'window', maxTreeNodes: 48,
      selectionCapture: false, inputText: false, inputActivity: false, textRange: 'prefix', sampleIntervalMs: 1000,
      maxTextCodeUnits: 4096, maxPending: 16, debounceMs: 150, maxWaitMs: 500, readTimeoutMs: 1500 });
    timer = setTimeout(() => finish(mode !== 'surface'), mode === 'surface' ? CASE_WAIT_MS : NEGATIVE_WAIT_MS);
    check(await observed && !observationFailure, observationFailure ?? 'surface-evidence-timeout');
    clearTimeout(timer); timer = undefined;
    check(supervisor.status().state === 'running', 'collector-not-running');
    const before = store.status();
    if (mode !== 'surface') {
      check(before.counts.text === 0 && before.counts.surface === 0 && before.counts.selection === 0
        && before.counts.inputText === 0 && before.counts.activity === 0, 'negative-content-produced');
      if (mode === 'protected') check((diagnostics['secure-field'] ?? 0) > 0, 'negative-refusal-unconfirmed');
    }
    check((await supervisor.pause()).state === 'paused', 'pause-produced-evidence');
    const paused = store.status().records;
    await new Promise(resolve => setTimeout(resolve, 1100));
    check(store.status().records === paused, 'pause-produced-evidence');
    check((await supervisor.stop()).state === 'stopped', 'owned-helper-exit-unconfirmed');
    pausedAndStopped = true; clearTimeout(deadline); deadline = undefined;
    await store.close(); await checkEncryptedAtRest(options.root);
    store = await SegmentStore.open(options); reopened = true;
    let layout;
    if (mode === 'surface') {
      check(captured !== undefined, 'surface-evidence-timeout');
      const query = await store.search({ kind: 'surface', applicationId: APP_ID, limit: 100 });
      check(query.records.some(record => record.eventId === captured.eventId), 'surface-reopen-mismatch');
      layout = await verifyStoredLayout(store, captured);
    } else {
      const status = store.status();
      check(status.counts.surface === 0 && status.counts.text === 0 && status.counts.inputText === 0
        && status.counts.selection === 0 && status.counts.activity === 0, 'negative-content-produced');
    }
    result = { ok: true, mode, nativeSession: true, realAX: mode !== 'excluded', syntheticOnly: true,
      records: count(before.records), surfaceRecords: count(before.counts.surface), textRecords: count(before.counts.text),
      diagnosticCounts: diagnostics, ...(layout ? { relativeFixtureGeometryVerified: true, layout } : { negativeVerified: true,
        negativeEvidence: mode === 'protected' ? 'secure-field-refusal-with-zero-content' : 'zero-content-under-exact-exclusion-policy' }), pausedAndStopped, reopened,
      inputMonitoring: false, eventPosting: false, existingHistoryRead: false, keychainAccess: false,
      profileChanged: false, modelShared: false };
  } catch (error) { failure = observationFailure ?? code(error); }
  finally {
    if (timer) clearTimeout(timer); if (deadline) clearTimeout(deadline);
    let stopped = !supervisor; let closed = !store;
    // Cleanup is attempted independently: a failed pause/stop must not skip store
    // close. A live helper is never retried via start/resume/new instance.
    try { if (supervisor?.status().state === 'running') await supervisor.pause(); } catch { /* stop below owns teardown */ }
    try { if (supervisor) stopped = (await supervisor.stop()).state === 'stopped'; } catch { stopped = false; }
    try { await store?.close(); closed = true; } catch { closed = false; }
    if (!stopped || !closed) failure = 'owned-helper-exit-unconfirmed';
    key?.fill(0);
    if (temp && stopped && closed) {
      try {
        check(resolve(temp) === temp && dirname(temp) === tempBase && temp.startsWith(join(tempBase, 'dsh-layout-synthetic-'))
          && await realpath(temp) === temp, 'unsafe-cleanup');
        await rm(temp, { recursive: true, force: false });
      } catch { failure = 'cleanup-failed'; }
    }
  }
  if (failure) {
    const state = supervisor?.status();
    return { ok: false, mode, failure, diagnosticCounts: diagnostics,
      received: count(state?.received), dropped: count(state?.dropped), committedRecords: Object.values(committed).reduce((a, b) => a + count(b), 0),
      pausedAndStopped, reopened, syntheticOnly: true, existingHistoryRead: false, keychainAccess: false, modelShared: false };
  }
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let mode;
  try { mode = parseLayoutSmokeArgs(process.argv.slice(2)); }
  catch { console.error(JSON.stringify({ ok: false, failure: 'explicit-synthetic-layout-authorization-required' })); process.exitCode = 64; }
  if (mode) {
    const result = await main(mode);
    if (result.ok) console.log(JSON.stringify(result, null, 2));
    else { console.error(JSON.stringify(result)); process.exitCode = 1; }
  }
}

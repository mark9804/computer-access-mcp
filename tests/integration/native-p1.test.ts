import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { CollectorSupervisor } from '../../src/host/collectors/supervisor.ts';
import { spawnLocal } from '../../src/host/collectors/local-process.ts';
import { CollectorDebugLog } from '../../src/host/collectors/debug-log.ts';
import { FrameDecoder } from '../../src/shared/protocol/validate.ts';
import type { Observation, CapturePolicy, WireMessage } from '../../src/shared/protocol/generated.ts';
import { MemoryKeyProvider } from '../../src/storage/key-provider.ts';
import { SegmentStore } from '../../src/storage/segment-store.ts';
import type { TestContext } from 'node:test';

const path = process.env.DSH_TEST_FIXTURE_HELPER;
const policy: CapturePolicy = {
  enabled: true,
  allowedApplicationIds: ['test.allowed'],
  maxTextCodeUnits: 512,
  maxPending: 16,
  debounceMs: 10,
  maxWaitMs: 100,
  readTimeoutMs: 150,
};
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

async function fixture(t: TestContext, scenario = 'allowed') {
  assert.ok(path, 'set DSH_TEST_FIXTURE_HELPER to run native synthetic fixture mode');
  const binary = await realpath(path);
  const root = await realpath(await mkdtemp(join(tmpdir(), 'camcp-p1-native-')));
  const store = await SegmentStore.open({
    root: join(root, 'store'),
    keyProvider: new MemoryKeyProvider(Buffer.alloc(32, 0x24)),
  });
  let resolveSnapshot: (m: Observation) => void = () => {};
  let resolveGap: (m: Observation) => void = () => {};
  let resolveActivity: (m: Observation) => void = () => {};
  const snapshot = new Promise<Observation>((resolve) => {
    resolveSnapshot = resolve;
  });
  const gap = new Promise<Observation>((resolve) => {
    resolveGap = resolve;
  });
  const activity = new Promise<Observation>((resolve) => {
    resolveActivity = resolve;
  });
  const received: Observation[] = [];
  const debugLog = new CollectorDebugLog(join(root, 'debug-log'), true);
  await debugLog.prepare();
  const supervisor = new CollectorSupervisor({
    helperPath: binary,
    helperSha256: createHash('sha256').update(await readFile(binary)).digest('hex'),
    cwd: root,
    deviceId: 'synthetic-test-device',
    spawn: spawnLocal,
    allowFixture: true,
    fixtureArgs: ['--fixture-scenario', scenario],
    debugTrace: true,
    debugLog,
    requestTimeoutMs: 4000,
    leaseDurationMs: 1500,
    onObservation: async (m, valid) => {
      if (!valid()) return;
      try {
        await store.append(m, { generation: store.generation, isCurrent: valid });
      } catch (error) {
        if (error && typeof error === 'object' && 'code' in error && error.code === 'stale-generation') return;
        throw error;
      }
      received.push(m);
      if (m.payload.kind === 'text.snapshot') resolveSnapshot(m);
      if (m.payload.kind === 'gap') resolveGap(m);
      if (m.payload.kind === 'input.activity') resolveActivity(m);
    },
  });
  t.after(async () => {
    await supervisor.stop();
    await debugLog.close();
    await store.close();
    assert.ok(root.startsWith((await realpath(tmpdir())) + '/camcp-p1-native-'));
    await rm(root, { recursive: true, force: true });
  });
  return {
    supervisor,
    debugLog,
    store,
    snapshot,
    gap,
    activity,
    received,
    nextSnapshot: () =>
      new Promise<Observation>((resolve) => {
        resolveSnapshot = resolve;
      }),
  };
}

const opts = { skip: !path, timeout: 20000 };

test('opt-in native synthetic input counts pass Host and encrypted activity query; pause/Forget fence them', opts, async (t) => {
  const h = await fixture(t, 'activity');
  await h.supervisor.start({ ...policy, inputActivity: true });
  const event = await h.activity;
  assert.equal(event.target.kind, 'application');
  assert.equal(event.payload.kind, 'input.activity');
  if (event.payload.kind !== 'input.activity') throw Error('expected activity');
  assert.equal(event.payload.source, 'fixture');
  assert.equal(event.payload.counts.pointerReleases, 1);
  assert.equal(event.payload.intervalStartMs % 1000, 0);
  assert.equal(event.payload.intervalEndMs - event.payload.intervalStartMs, 1000);
  assert.equal(event.eventTimeMs, event.payload.intervalEndMs);
  const query = await h.store.search({ kind: 'activity', applicationId: 'test.allowed' });
  assert.ok(query.records.length >= 1);
  assert.ok(h.store.status().counts.activity >= 1);
  await h.supervisor.pause();
  const before = h.received.filter((m) => m.payload.kind === 'input.activity').length;
  await tick();
  assert.equal(h.received.filter((m) => m.payload.kind === 'input.activity').length, before);
  await h.supervisor.stop();
  await h.store.forget({ all: true });
  assert.equal((await h.store.search({ kind: 'activity' })).records.length, 0);
});

test('native visible slice retains nonzero UTF16 range and partial coverage through Host and storage', opts, async (t) => {
  const h = await fixture(t, 'partial');
  await h.supervisor.start({ ...policy, textRange: 'visible', sampleIntervalMs: 1000 });
  const event = await h.snapshot;
  assert.equal(event.payload.kind, 'text.snapshot');
  if (event.payload.kind !== 'text.snapshot') throw Error('fixture');
  assert.equal(event.payload.rangeBasis, 'visible');
  assert.ok(event.payload.range!.start > 0);
  assert.equal(event.payload.range!.length, event.payload.text!.length);
  assert.equal(event.payload.coverage.status, 'partial');
  assert.ok(event.payload.coverage.missingReasons.includes('visible-range-only'));
  assert.equal(event.payload.scope, 'accessible-range');
  assert.ok(event.payload.totalLength! > event.payload.range!.start + event.payload.range!.length);
  await h.supervisor.stop();
  assert.deepEqual((await h.store.read(event.eventId))?.payload, event.payload);
});

test('activity fixture remains text-only without explicit input scope', opts, async (t) => {
  const h = await fixture(t, 'activity');
  await h.supervisor.start(policy);
  await h.snapshot;
  await h.supervisor.stop();
  assert.equal(h.received.some((m) => m.payload.kind === 'input.activity'), false);
});

test('native fixture -> managed Host -> SegmentStore -> bounded read/Forget', opts, async (t) => {
  const h = await fixture(t);
  await h.supervisor.start(policy);
  const event = await h.snapshot;
  assert.equal(event.payload.kind, 'text.snapshot');
  if (event.payload.kind !== 'text.snapshot') throw new Error('expected snapshot');
  assert.equal(event.payload.source, 'fixture');
  assert.ok(event.payload.text?.includes('Synthetic'));
  const result = await h.store.search({ text: 'Synthetic' });
  assert.ok(result.records.length >= 1);

  await tick();
  await h.debugLog.flush();
  const logs = (await readdir(h.debugLog.directory)).filter((name) => name.endsWith('.jsonl'));
  const saved = (await Promise.all(logs.map((name) => readFile(join(h.debugLog.directory, name), 'utf8')))).join('');
  assert.ok(saved.includes('worker-launch'));
  assert.equal(saved.includes('Synthetic'), false);

  await h.supervisor.pause();
  const before = h.received.length;
  await tick();
  assert.equal(h.received.length, before);

  await h.debugLog.flush();
  const persisted = (await Promise.all(logs.map((name) => readFile(join(h.debugLog.directory, name), 'utf8')))).join('');
  const entries = persisted
    .split('\n')
    .filter((line) => line.startsWith('{'))
    .map((line) => JSON.parse(line) as { event: string; detail?: Record<string, unknown> });
  const written = entries.find((entry) => entry.event === 'worker-request-written');
  const received = entries.find((entry) => entry.event === 'worker-response-received');
  const dispatched = entries.find((entry) => entry.event === 'worker-response-dispatched');
  assert.ok(written && received && dispatched);
  assert.ok(Number.isSafeInteger(written.detail?.requestId) && Number(written.detail?.requestId) > 0);
  assert.equal(received.detail?.requestId, written.detail?.requestId);
  assert.equal(dispatched.detail?.requestId, written.detail?.requestId);
  assert.equal('debugRequestId' in event, false);
  assert.equal('debugRequestId' in event.payload, false);
  assert.equal(persisted.includes('Synthetic'), false);

  assert.equal(h.supervisor.status().state, 'paused');
  await h.supervisor.stop();
  const forgotten = await h.store.forget({ all: true });
  assert.equal(forgotten.remainingRecords, 0);
  assert.equal((await h.store.search()).records.length, 0);
});

test('native same-helper explicit resume observes a fresh post-pause snapshot', opts, async (t) => {
  const h = await fixture(t);
  await h.supervisor.start(policy);
  const first = await h.snapshot;
  await h.supervisor.pause();
  const next = h.nextSnapshot();
  await h.supervisor.resume();
  const after = await next;
  assert.ok(after.seq > first.seq);
  assert.ok(after.stamp.captureEpoch > first.stamp.captureEpoch);
  assert.equal(h.supervisor.status().state, 'running');
});

test('native locked/unknown fixture never starts or stores content', opts, async (t) => {
  for (const scenario of ['locked', 'unknown']) {
    const h = await fixture(t, scenario);
    await assert.rejects(h.supervisor.start(policy));
    assert.equal(h.received.filter((m) => m.payload.kind === 'text.snapshot').length, 0);
    await h.supervisor.stop();
  }
});

test('native hung reader reports timeout while stop still reaps owned work', opts, async (t) => {
  const h = await fixture(t, 'workerhang');
  await h.supervisor.start(policy);
  const gap = await h.gap;
  assert.equal(gap.payload.kind, 'gap');
  if (gap.payload.kind === 'gap') assert.equal(gap.payload.reason, 'timeout');
  const start = performance.now();
  await h.supervisor.stop();
  assert.ok(performance.now() - start < 4000);
  assert.equal(h.supervisor.status().state, 'stopped');
  assert.equal(h.received.some((m) => m.payload.kind === 'text.snapshot'), false);
});

test('native standalone fixture exits when Host pipe closes without a stop command', opts, async () => {
  assert.ok(path);
  const binary = await realpath(path);
  const child = spawnLocal({
    argv: [
      binary,
      '--fixture',
      '--owner-id',
      'synthetic-owner',
      '--instance-id',
      'synthetic-instance',
      '--device-id',
      'synthetic-device',
    ],
    cwd: dirname(binary),
    stdio: { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' },
    graceMs: 300,
  });
  let resolveHello: () => void = () => {};
  const hello = new Promise<void>((resolve) => {
    resolveHello = resolve;
  });
  const decoder = new FrameDecoder();
  const messages: WireMessage[] = [];
  child.stdout!.on('data', (chunk: Buffer) => {
    for (const m of decoder.push(chunk)) {
      messages.push(m);
      if (m.type === 'hello') resolveHello();
    }
  });
  child.stderr!.resume();
  const timer = setTimeout(() => child.terminate(), 4000);
  try {
    await hello;
    child.stdin!.end();
    const result = await child.done;
    assert.equal(result.exitCode, 0);
    assert.equal(messages.some((m) => m.type === 'observation'), false);
  } finally {
    clearTimeout(timer);
    child.terminate();
  }
});

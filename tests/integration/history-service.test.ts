import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough, Writable } from 'node:stream';
import { createHash } from 'node:crypto';
import { mkdtemp, realpath, lstat, readdir, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHistoryService, HistoryOperationError } from '../../src/host/service/history-service.ts';
import { FrameDecoder, encodeFrame } from '../../src/shared/protocol/validate.ts';
import { observation, target } from '../../fixtures/contract/examples.ts';
import type { SpawnManaged, ManagedProcess } from '../../src/host/collectors/process.ts';
import type { Observation, WireMessage } from '../../src/shared/protocol/generated.ts';
import type { TestContext } from 'node:test';

async function fixture(
  t: TestContext,
  options: { sourceNavigation?: boolean; startPauseReason?: string; debugTrace?: boolean } = {},
) {
  const recordedTarget = options.sourceNavigation
    ? {
        ...target,
        processStartTime: 'unix-ms:1700000000000.123',
        osSessionId: 'audit-42',
        desktopId: 'console-audit-42',
      }
    : target;
  const navigationRequests: Record<string, unknown>[] = [];
  const configuredPolicies: unknown[] = [];
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'camcp-history-service-')));
  const helperPath = join(dir, 'computer-access-collector');
  const keyHelperPath = join(dir, 'computer-access-key-store');
  const files: Record<string, { sha256: string }> = {};
  for (const name of ['computer-access-collector', 'computer-access-key-store']) {
    const content = `Synthetic ${name}`;
    await writeFile(join(dir, name), content, { mode: 0o700 });
    files[name] = { sha256: createHash('sha256').update(content).digest('hex') };
  }
  const resource = 'AccessContract_AccessContract.bundle/Contents/Resources/wire.schema.json';
  await mkdir(join(dir, 'AccessContract_AccessContract.bundle/Contents/Resources'), { recursive: true });
  await writeFile(join(dir, resource), '{}', { mode: 0o600 });
  files[resource] = { sha256: createHash('sha256').update('{}').digest('hex') };
  await writeFile(join(dir, 'manifest.json'), JSON.stringify({ version: 1, platform: 'darwin', arch: process.arch, files }), {
    mode: 0o600,
  });

  let spawnCount = 0;
  let readKeyCount = 0;
  let collectorCount = 0;
  let text: (value: string) => void = () => {};
  let multi: () => void = () => {};
  let blockKey: (() => Promise<void>) | undefined;
  let keyResponse: Record<string, unknown> = {
    version: 1,
    status: 'ok',
    key: Buffer.alloc(32, 0x28).toString('base64'),
  };

  const spawn: SpawnManaged = (spec) => {
    spawnCount++;
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    let end: (v: { exitCode: number | null; signal: NodeJS.Signals | null }) => void = () => {};
    const done = new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>((resolve) => {
      end = resolve;
    });
    let input = '';
    const decoder = new FrameDecoder();
    const instance = spec.argv[spec.argv.indexOf('--instance-id') + 1] ?? '';
    const owner = spec.argv[spec.argv.indexOf('--owner-id') + 1] ?? '';
    let revision = 1;
    let sequence = 0;
    let epoch = 1;
    const emit = (m: WireMessage) => stdout.write(encodeFrame(m));
    const stamp = () => ({
      captureEpoch: epoch,
      focusGeneration: epoch,
      foregroundGeneration: 1,
      policyRevision: revision,
    });

    const stdin = new Writable({
      write(chunk, _enc, callback) {
        if (spec.argv[0] === keyHelperPath || spec.argv[1] === '--navigate-source') {
          input += String(chunk);
        } else {
          for (const m of decoder.push(chunk)) {
            if (m.type === 'configure') {
              configuredPolicies.push(m.policy);
              revision = m.policyRevision;
              emit({
                protocolVersion: 1,
                type: 'configured',
                requestId: m.requestId,
                ownerId: owner,
                instanceId: instance,
                policyRevision: revision,
              });
            }
            if (m.type === 'control') {
              if (m.command !== 'heartbeat') epoch++;
              const refused = m.command === 'start' ? options.startPauseReason : undefined;
              emit({
                protocolVersion: 1,
                type: 'state',
                requestId: m.requestId,
                instanceId: instance,
                state:
                  m.command === 'stop'
                    ? 'stopped'
                    : m.command === 'pause' || refused
                      ? 'paused'
                      : 'running',
                stamp: stamp(),
                reason: m.command === 'pause' ? 'user-paused' : refused ?? '',
              });
            }
          }
        }
        callback();
      },
      final(callback) {
        if (spec.argv[1] === '--navigate-source') {
          navigationRequests.push(JSON.parse(input));
          stdout.end(
            JSON.stringify({ version: 1, outcome: 'activated', reason: 'activated', captured: false, launched: false }),
          );
          stderr.end();
          end({ exitCode: 0, signal: null });
          callback();
          return;
        }
        if (spec.argv[0] === keyHelperPath) {
          void (async () => {
            await blockKey?.();
            const req = JSON.parse(input) as { command: string };
            if (req.command === 'get') readKeyCount++;
            stdout.write(JSON.stringify(keyResponse));
            stdout.end();
            stderr.end();
            end({ exitCode: 0, signal: null });
            callback();
          })();
        } else {
          callback();
        }
      },
    });

    const handle: ManagedProcess = {
      stdin,
      stdout,
      stderr,
      done,
      terminate() {
        stdout.end();
        stderr.end();
        end({ exitCode: 0, signal: null });
      },
      async waitForExit() {
        await done;
        return true;
      },
    };

    if (spec.argv[0] !== keyHelperPath && spec.argv[1] !== '--navigate-source') {
      collectorCount++;
      queueMicrotask(() =>
        emit({
          protocolVersion: 1,
          type: 'hello',
          instanceId: instance,
          maxFrameBytes: 65536,
          capabilities: [
            { name: 'text.snapshot', support: 'supported', direction: 'observe', scope: 'app-local', reason: '' },
            {
              name: 'input.activity',
              support: 'supported',
              direction: 'observe',
              scope: 'authorized-desktop',
              reason: 'synthetic-only',
            },
            {
              name: 'text.visible-range',
              support: 'supported',
              direction: 'observe',
              scope: 'app-local',
              reason: 'synthetic-only',
            },
            ...(
              ['ax.enablement', 'text.marker', 'surface.snapshot', 'selection.snapshot', 'input.text', 'menu.action', 'field.denylist'] as const
            ).map((name) => ({
              name,
              support: 'supported' as const,
              direction: 'observe' as const,
              scope: 'app-local' as const,
              reason: 'synthetic-only',
            })),
          ],
        }),
      );

      multi = () => {
        const source = observation('synthetic-multi');
        epoch++;
        const when = Date.now();
        const event = (payload: Observation['payload']) =>
          emit({
            ...source,
            instanceId: instance,
            eventId: `${instance}:${++sequence}`,
            seq: sequence,
            eventTimeMs: when,
            monotonicMs: when,
            stamp: stamp(),
            target: { kind: 'resolved', identity: { ...recordedTarget, deviceId: 'test-device' } },
            payload,
          });
        const gate = { secure: 'safe', privateState: 'normal', policyRevision: revision } as const;
        event({ kind: 'context.changed', reason: 'focus' });
        event({
          kind: 'input.text',
          source: 'cg.unicode',
          scope: 'field',
          eventKind: 'text',
          text: 'synthetic-multi',
          modifiers: [],
          eventCount: 1,
          intervalStartMs: when,
          intervalEndMs: when,
          surfaceId: 'multi-surface',
          gate,
          secureInput: 'inactive',
          effect: 'unverified',
          coverage: { status: 'partial', truncated: false, missingReasons: ['input-events-partial', 'effect-unverified'] },
        });
        if (source.payload.kind !== 'text.snapshot') throw Error('fixture');
        event({ ...source.payload, source: 'ax.range', gate, captureStartMs: when, captureEndMs: when });
        event({
          kind: 'surface.snapshot',
          snapshotId: 'multi-snapshot',
          surfaceId: 'multi-surface',
          revision: 1,
          source: 'ax.tree',
          scope: 'region',
          mode: 'full',
          nodes: [{ id: 'node', role: 'text', text: 'synthetic-multi', observedAtMs: when }],
          captureStartMs: when,
          captureEndMs: when,
          gate,
          consistency: 'non-atomic',
          coverage: { status: 'complete', truncated: false, missingReasons: [] },
        });
      };

      text = (value) => {
        const source = observation(value);
        epoch++;
        emit({
          ...source,
          instanceId: instance,
          eventId: `${instance}:${++sequence}`,
          seq: sequence,
          stamp: stamp(),
          target: { kind: 'resolved', identity: { ...recordedTarget, deviceId: 'test-device' } },
          payload: { kind: 'context.changed', reason: 'focus' },
        });
        if (source.payload.kind !== 'text.snapshot') throw new Error('fixture');
        emit({
          ...source,
          instanceId: instance,
          eventId: `${instance}:${++sequence}`,
          seq: sequence,
          eventTimeMs: Date.now(),
          stamp: stamp(),
          target: { kind: 'resolved', identity: { ...recordedTarget, deviceId: 'test-device' } },
          payload: {
            ...source.payload,
            snapshotId: `s-${epoch}`,
            source: 'ax.range',
            gate: { secure: 'safe', privateState: 'normal', policyRevision: revision },
          },
        });
      };
    }
    return handle;
  };

  const dataRoot = join(dir, 'data');
  const service = createHistoryService({
    dataRoot,
    helperPath,
    keyHelperPath,
    deviceId: 'test-device',
    spawn,
    debugTrace: options.debugTrace === true,
  });
  t.after(async () => {
    await service.close();
    assert.ok(dir.startsWith((await realpath(tmpdir())) + '/camcp-history-service-'));
    await rm(dir, { recursive: true, force: true });
  });

  return {
    service,
    dir,
    helperPath,
    files,
    debugDirectory: join(dataRoot, 'debug-log'),
    navigationRequests,
    configuredPolicies,
    text: (v: string) => text(v),
    multi: () => multi(),
    get spawns() {
      return spawnCount;
    },
    get keyReads() {
      return readKeyCount;
    },
    get collectors() {
      return collectorCount;
    },
    set blockKey(value: (() => Promise<void>) | undefined) {
      blockKey = value;
    },
    set keyResponse(value: Record<string, unknown>) {
      keyResponse = value;
    },
  };
}

const onlyMac = { skip: process.platform !== 'darwin', timeout: 10000 };

test('HistoryService construction and status do not touch keys or spawn collectors', onlyMac, async (t) => {
  const h = await fixture(t);
  const status = await h.service.status();
  assert.equal(status.state, 'not-initialized');
  assert.equal(h.spawns, 0);
  assert.equal(status.storage, null);
  assert.deepEqual(
    status.adapters.map((a) => a.id),
    ['generic', 'vscode-family', 'browser-family', 'terminal-family', 'qq', 'feishu', 'wechat', 'slack', 'typora', 'figma'],
  );
  await assert.rejects(lstat(h.debugDirectory), { code: 'ENOENT' });
});

test('HistoryService keeps closed retirement reasons identical in status and the failed startup receipt', onlyMac, async (t) => {
  for (const reason of ['worker-retirement-ack-failed', 'worker-retirement-exit-unconfirmed'] as const) {
    const h = await fixture(t, { startPauseReason: reason });
    await assert.rejects(h.service.start({ allowedApplicationIds: [target.applicationId], inputText: true }), {
      code: reason,
    });
    const state = await h.service.status();
    assert.equal(state.state, 'failed');
    assert.equal(state.reason, reason);
    assert.equal(state.storage?.records, 0);
    assert.equal(h.collectors, 1);
  }
});

test('retention defaults to seven days and 128 MiB without auto collection on initializeKey', onlyMac, async (t) => {
  const h = await fixture(t);
  await h.service.initializeKey();
  const status = await h.service.status();
  assert.equal(status.storage?.retentionMs, 7 * 24 * 3600 * 1000);
  assert.equal(status.storage?.maxBytes, 128 * 1024 * 1024);
  assert.equal(status.state, 'stopped');
  assert.equal(h.collectors, 0);
  await assert.rejects(lstat(h.debugDirectory), { code: 'ENOENT' });
});

test('explicit inputActivity scope is preserved across resume and debugTrace writes JSONL only when enabled', onlyMac, async (t) => {
  const h = await fixture(t, { debugTrace: true });
  await h.service.start({
    applicationScope: 'allowlist',
    allowedApplicationIds: [target.applicationId],
    inputActivity: false,
    menuActions: false,
  });
  assert.equal((await h.service.status()).activeScope?.inputActivity, false);
  assert.equal((await h.service.status()).activeScope?.menuActions, false);
  assert.equal((h.configuredPolicies[0] as { inputActivity: boolean }).inputActivity, false);
  assert.equal((h.configuredPolicies[0] as { menuActions: boolean }).menuActions, false);
  await h.service.stop();
  await h.service.start({
    applicationScope: 'allowlist',
    allowedApplicationIds: [target.applicationId],
    inputActivity: true,
  });
  assert.equal((await h.service.status()).activeScope?.inputActivity, true);
  assert.equal((await h.service.status()).activeScope?.menuActions, true);
  await h.service.pause();
  await h.service.resume();
  assert.equal((h.configuredPolicies.at(-1) as { inputActivity: boolean }).inputActivity, true);
  assert.equal((h.configuredPolicies.at(-1) as { menuActions: boolean }).menuActions, true);
  await h.service.stop();
  const files = (await readdir(h.debugDirectory)).filter((name) => name.endsWith('.jsonl'));
  const lines = (await Promise.all(files.map((name) => readFile(join(h.debugDirectory, name), 'utf8'))))
    .join('')
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as { event: string });
  assert.ok(lines.filter((value) => value.event === 'collection-start').length >= 3);
  assert.ok(lines.filter((value) => value.event === 'helper-exit').length >= 3);
  await assert.rejects(
    h.service.start({
      applicationScope: 'allowlist',
      allowedApplicationIds: [target.applicationId],
      inputActivity: 'true' as unknown as boolean,
    }),
    /invalid-capture-options/,
  );
  await assert.rejects(
    h.service.start({
      applicationScope: 'allowlist',
      allowedApplicationIds: [target.applicationId],
      menuActions: 'true' as unknown as boolean,
    }),
    /invalid-capture-options/,
  );
});

test('explicit denylist and content channels remain separate and survive original-scope resume', onlyMac, async (t) => {
  const h = await fixture(t);
  const request = {
    allowedApplicationIds: [] as string[],
    applicationScope: 'denylist' as const,
    fieldSecurity: 'denylist' as const,
    excludedApplicationIds: ['test.excluded'],
    allowBrowserContent: true,
    axCompatibility: true,
    textMarkers: true,
    captureScope: 'region' as const,
    maxTreeNodes: 32,
    inputText: true,
    selectionCapture: true,
    inputActivity: false,
  };
  await h.service.start(request);
  const configured = structuredClone(h.configuredPolicies.at(-1));
  request.excludedApplicationIds.push('test.later');
  await h.service.pause();
  await h.service.resume();
  assert.deepEqual(h.configuredPolicies.at(-1), configured);
  const status = await h.service.status();
  assert.equal(status.activeScope?.applicationScope, 'denylist');
  assert.ok(status.mandatoryExcludedApplicationIds.includes('com.1password'));
  assert.ok(status.mandatoryExcludedApplicationIds.includes('com.apple.safari'));
  assert.equal(status.activeScope?.fieldSecurity, 'denylist');
  assert.equal(status.activeScope?.inputText, true);
  assert.equal(status.activeScope?.inputActivity, false);
});

test('visible sampling and polling interval require explicit valid scope and survive resume unchanged', onlyMac, async (t) => {
  const h = await fixture(t);
  const base = { applicationScope: 'allowlist' as const, allowedApplicationIds: [target.applicationId] };
  for (const input of [
    { ...base, textRange: 'all' },
    { ...base, textRange: null },
    { ...base, sampleIntervalMs: null },
    { ...base, sampleIntervalMs: 999 },
    { ...base, sampleIntervalMs: 30001 },
    { ...base, sampleIntervalMs: 1.5 },
    { ...base, sampleIntervalMs: '1000' },
  ]) {
    await assert.rejects(h.service.start(input as never));
  }
  assert.equal(h.spawns, 0);
  await h.service.start({ ...base, textRange: 'visible', sampleIntervalMs: 30000 });
  await h.service.pause();
  await h.service.resume();
  const policy = h.configuredPolicies.at(-1) as { textRange: string; sampleIntervalMs: number };
  assert.equal(policy.textRange, 'visible');
  assert.equal(policy.sampleIntervalMs, 30000);
});

test('service correlates committed input with same-batch surface across an interleaved focused snapshot', onlyMac, async (t) => {
  const h = await fixture(t);
  await h.service.start({
    applicationScope: 'allowlist',
    allowedApplicationIds: [target.applicationId],
    captureScope: 'region',
    inputText: true,
  });
  h.multi();
  let records = (await h.service.search({})).records;
  for (let attempt = 0; !records.some((record) => record.payload.kind === 'surface.snapshot') && attempt < 20; attempt++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
    records = (await h.service.search({})).records;
  }
  const surface = records.find((record) => record.payload.kind === 'surface.snapshot');
  const input = records.find((record) => record.payload.kind === 'input.text');
  assert.ok(surface);
  assert.ok(input);
  assert.deepEqual(surface.relation, {
    basis: 'temporal-same-surface',
    evidenceIds: [input.eventId],
    effect: 'unverified',
  });
  await h.service.pause();
  await h.service.forget({ all: true });
  assert.equal((await h.service.search({})).records.length, 0);
});

test('explicit key initialization remains stopped; collection, search, read, and Forget share service operations', onlyMac, async (t) => {
  const h = await fixture(t);
  await h.service.initializeKey();
  assert.equal((await h.service.status()).state, 'stopped');
  assert.equal(h.collectors, 0);
  await h.service.start({ applicationScope: 'allowlist', allowedApplicationIds: [target.applicationId] });
  h.text('Synthetic 中 test');
  await new Promise<void>((resolve) => setImmediate(resolve));
  let records = (await h.service.search({ text: 'Synthetic' })).records;
  if (records.length === 0) {
    await new Promise<void>((resolve) => setImmediate(resolve));
    records = (await h.service.search({ text: 'Synthetic' })).records;
  }
  assert.equal(records.length, 1);
  const readRes = await h.service.read(records[0]!.eventId);
  assert.equal(readRes.found, true);
  assert.equal(readRes.record?.eventId, records[0]!.eventId);
  await h.service.forget({ all: true });
  assert.equal((await h.service.search({})).records.length, 0);
  assert.equal((await h.service.status()).state, 'stopped');
});

test('Keychain refusal diagnostics reach service error and status without spawning a Collector', onlyMac, async (t) => {
  const h = await fixture(t);
  h.keyResponse = { version: 1, status: 'denied', phase: 'lookup', osStatus: -25308 };
  await assert.rejects(h.service.initializeKey(), (error: unknown) => {
    assert.ok(error instanceof HistoryOperationError);
    assert.equal(error.code, 'keychain-ui-required');
    assert.deepEqual(error.diagnostic, { phase: 'lookup', osStatus: -25308 });
    return true;
  });
  const status = await h.service.status();
  assert.equal(status.reason, 'keychain-ui-required');
  assert.equal(h.collectors, 0);
  assert.equal(status.storage, null);
  h.keyResponse = { version: 1, status: 'missing', phase: 'lookup', osStatus: -25300 };
  await assert.rejects(
    h.service.start({ applicationScope: 'allowlist', allowedApplicationIds: [target.applicationId] }),
    /key-unavailable/,
  );
  assert.equal((await h.service.status()).reason, 'key-unavailable');
  assert.equal(h.collectors, 0);
});

test('pause and stop replace stale failed-command reasons', onlyMac, async (t) => {
  const h = await fixture(t);
  await h.service.start({ applicationScope: 'allowlist', allowedApplicationIds: [target.applicationId] });
  await assert.rejects(
    h.service.start({ applicationScope: 'allowlist', allowedApplicationIds: [target.applicationId] }),
    /already-running/,
  );
  await h.service.pause();
  assert.equal((await h.service.status()).reason, 'user-paused');
  await h.service.stop();
  assert.equal((await h.service.status()).reason, '');
});

test('Forget reports stopped-after-forget rather than a stale paused reason', onlyMac, async (t) => {
  const h = await fixture(t);
  await h.service.start({ applicationScope: 'allowlist', allowedApplicationIds: [target.applicationId] });
  await h.service.pause();
  await h.service.forget({ all: true });
  const status = await h.service.status();
  assert.equal(status.state, 'stopped');
  assert.equal(status.reason, 'stopped-after-forget');
});

test('source navigation resolves retained evidence and refuses missing or unverifiable targets without collector work', onlyMac, async (t) => {
  const h = await fixture(t);
  await h.service.initializeKey();
  const missing = await h.service.openSource({ eventId: 'synthetic:missing' });
  assert.equal(missing.outcome, 'refused');
  assert.equal(missing.reason, 'source-not-found');
  assert.equal(h.collectors, 0);
  await h.service.start({ applicationScope: 'allowlist', allowedApplicationIds: [target.applicationId] });
  h.text('synthetic source');
  let records = (await h.service.search({ text: 'synthetic source' })).records;
  for (let attempts = 0; records.length === 0 && attempts < 10; attempts++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
    records = (await h.service.search({ text: 'synthetic source' })).records;
  }
  assert.equal(records.length, 1);
  const before = h.spawns;
  const result = await h.service.openSource({ eventId: records[0]!.eventId });
  assert.equal(result.outcome, 'refused');
  assert.equal(result.reason, 'navigation-target-unavailable');
  assert.equal(h.spawns, before);
});

test('event-based navigation passes only stored identity to helper and Forget removes the route', onlyMac, async (t) => {
  const h = await fixture(t, { sourceNavigation: true });
  await h.service.start({ applicationScope: 'allowlist', allowedApplicationIds: [target.applicationId] });
  h.text('synthetic source route');
  let records = (await h.service.search({ text: 'synthetic source route' })).records;
  for (let attempts = 0; records.length === 0 && attempts < 10; attempts++) {
    await new Promise<void>((resolve) => setImmediate(resolve));
    records = (await h.service.search({ text: 'synthetic source route' })).records;
  }
  assert.equal(records.length, 1);
  await h.service.stop();
  const collectors = h.collectors;
  const result = await h.service.openSource({ eventId: records[0]!.eventId });
  assert.equal(result.outcome, 'activated');
  assert.equal(h.navigationRequests.length, 1);
  assert.equal(h.collectors, collectors);
  const request = h.navigationRequests[0]!;
  assert.equal(request.applicationId, target.applicationId);
  assert.equal(request.processStartTime, 'unix-ms:1700000000000.123');
  assert.equal(request.osSessionId, 'audit-42');
  assert.equal('windowId' in request, false);
  assert.equal('text' in request, false);
  await h.service.forget({ all: true });
  const expired = await h.service.openSource({ eventId: records[0]!.eventId });
  assert.equal(expired.reason, 'source-not-found');
  assert.equal(h.navigationRequests.length, 1);
});

test('queued source navigation is cancelled by Forget before dispatch and concurrent clicks do not queue', onlyMac, async (t) => {
  const h = await fixture(t);
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  h.blockKey = () => blocked;
  const request = h.service.openSource({ eventId: 'synthetic:missing' });
  await new Promise<void>((resolve) => setImmediate(resolve));
  const second = await h.service.openSource({ eventId: 'synthetic:missing' });
  assert.equal(second.reason, 'navigation-busy');
  const forget = h.service.forget({ all: true });
  release();
  await assert.rejects(request, /navigation-cancelled/);
  await forget;
  assert.equal(h.collectors, 0);
});

test('stop cancels a start awaiting Keychain without later starting a helper', onlyMac, async (t) => {
  const h = await fixture(t);
  let release: () => void = () => {};
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  h.blockKey = () => blocked;
  const start = h.service.start({ applicationScope: 'allowlist', allowedApplicationIds: [target.applicationId] });
  await new Promise<void>((resolve) => setImmediate(resolve));
  const stopping = h.service.stop();
  release();
  await assert.rejects(start, /start-cancelled/);
  await stopping;
  assert.equal(h.collectors, 0);
  assert.notEqual((await h.service.status()).state, 'running');
});

test('reloadCollector re-verifies binary manifest, preserves running scope, and never starts stopped or paused service', onlyMac, async (t) => {
  const h = await fixture(t);

  // 1. Not-initialized -> never touches key or spawns collector.
  const uninit = await h.service.reloadCollector();
  assert.equal(uninit.state, 'not-initialized');
  assert.equal(h.spawns, 0);
  assert.equal(h.collectors, 0);

  // 2. Running -> stops old collector, re-verifies updated binary + manifest, restarts with exact same scope.
  await h.service.start({
    applicationScope: 'allowlist',
    allowedApplicationIds: [target.applicationId],
    captureScope: 'region',
    inputActivity: false,
  });
  assert.equal(h.collectors, 1);
  const initialPolicy = structuredClone(h.configuredPolicies.at(-1));

  const updatedBinary = 'Synthetic computer-access-collector v2';
  await writeFile(h.helperPath, updatedBinary, { mode: 0o700 });
  h.files['computer-access-collector'] = {
    sha256: createHash('sha256').update(updatedBinary).digest('hex'),
  };
  await writeFile(
    join(h.dir, 'manifest.json'),
    JSON.stringify({ version: 1, platform: 'darwin', arch: process.arch, files: h.files }),
    { mode: 0o600 },
  );

  const reloaded = await h.service.reloadCollector();
  assert.equal(reloaded.state, 'running');
  assert.equal(h.collectors, 2);
  assert.deepEqual(h.configuredPolicies.at(-1), initialPolicy);
  assert.deepEqual(reloaded.activeScope?.allowedApplicationIds, [target.applicationId]);
  assert.equal(reloaded.activeScope?.captureScope, 'region');
  assert.equal(reloaded.activeScope?.inputActivity, false);

  // 3. Paused -> stops old collector and NEVER resumes capture.
  await h.service.pause();
  const afterPauseReload = await h.service.reloadCollector();
  assert.equal(afterPauseReload.state, 'stopped');
  assert.equal(h.collectors, 2);

  // 4. Stopped -> stays stopped and never spawns collector.
  const afterStopReload = await h.service.reloadCollector();
  assert.equal(afterStopReload.state, 'stopped');
  assert.equal(h.collectors, 2);

  // 5. Tampered binary without manifest update fails closed on reloadCollector while running.
  await h.service.start({
    applicationScope: 'allowlist',
    allowedApplicationIds: [target.applicationId],
  });
  assert.equal(h.collectors, 3);
  await writeFile(h.helperPath, 'tampered-binary-bytes', { mode: 0o700 });
  await assert.rejects(h.service.reloadCollector(), /native-hash-mismatch/);
  assert.equal(h.collectors, 3);
  assert.notEqual((await h.service.status()).state, 'running');
});

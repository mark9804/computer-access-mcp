import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PassThrough, Writable } from 'node:stream';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { target } from '../../fixtures/contract/examples.ts';
import { CollectorAdmission } from '../../src/host/collectors/admission.ts';
import type { ManagedProcess, SpawnManaged } from '../../src/host/collectors/process.ts';
import { CollectorSupervisor } from '../../src/host/collectors/supervisor.ts';
import { createHistoryService } from '../../src/host/service/history-service.ts';
import { startHttpServer } from '../../src/server/http-server.ts';
import type {
  ApplicationTarget,
  ApplicationTargetIdentity,
  Capability,
  CapturePolicy,
  Configured,
  ContentGate,
  MenuAction,
  Observation,
  Stamp,
  WireMessage,
} from '../../src/shared/protocol/generated.ts';
import { encodeFrame, FrameDecoder } from '../../src/shared/protocol/validate.ts';
import { HISTORY_RETENTION_MS, MemoryKeyProvider, SegmentStore, StorageError } from '../../src/storage/index.ts';
import { NOW, observation, temporary } from '../integration/history-store-fixtures.ts';

const REPO_ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));

function menuIdentity(overrides: Partial<ApplicationTargetIdentity> = {}): ApplicationTargetIdentity {
  return {
    deviceId: target.deviceId,
    osSessionId: target.osSessionId,
    desktopId: target.desktopId,
    processId: target.processId,
    processStartTime: target.processStartTime,
    applicationId: target.applicationId,
    ...overrides,
  };
}

function makeMenuObservation(
  seq: number,
  path: string[],
  options: {
    instanceId?: string;
    eventTimeMs?: number;
    stamp?: Stamp;
    source?: MenuAction['source'];
    truncated?: boolean;
    identity?: Partial<ApplicationTargetIdentity>;
    gate?: Partial<ContentGate>;
  } = {},
): Observation & { target: ApplicationTarget; payload: MenuAction } {
  const instanceId = options.instanceId ?? 'synthetic-instance';
  const eventTimeMs = options.eventTimeMs ?? NOW + seq * 1000;
  const stamp: Stamp = options.stamp ?? {
    captureEpoch: 1,
    foregroundGeneration: 1,
    focusGeneration: 1,
    policyRevision: 1,
  };
  const truncated = options.truncated ?? false;
  const gate: ContentGate = {
    secure: 'safe',
    privateState: 'normal',
    policyRevision: stamp.policyRevision,
    ...options.gate,
  };

  return {
    protocolVersion: 1,
    type: 'observation',
    eventId: `${instanceId}:${seq}`,
    instanceId,
    seq,
    eventTimeMs,
    monotonicMs: seq * 10,
    target: {
      kind: 'application',
      identity: menuIdentity(options.identity),
    },
    stamp,
    actor: 'unknown',
    relatedActionIds: [],
    payload: {
      kind: 'menu.action',
      source: options.source ?? 'ax.menu',
      scope: 'menu-bar',
      path,
      observedAtMs: eventTimeMs,
      gate,
      secureInput: 'inactive',
      coverage: {
        status: 'partial',
        truncated,
        missingReasons: truncated
          ? ['menu-bar-only', 'effect-unverified', 'menu-title-truncated']
          : ['menu-bar-only', 'effect-unverified'],
      },
      effect: 'unverified',
    },
  };
}

async function createSupervisorHarness(options: {
  includeMenuCapability?: boolean;
  allowFixture?: boolean;
  onObservation?: (message: Observation, isCurrent: () => boolean) => Promise<void>;
} = {}) {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'chmcp-menu-sup-')));
  const helperPath = join(dir, 'fake-helper');
  const helperContent = 'synthetic-menu-helper';
  await writeFile(helperPath, helperContent, { mode: 0o700 });

  let sendToHost!: (message: WireMessage) => void;
  let instanceId = '';
  let seq = 0;
  let stamp: Stamp = { captureEpoch: 1, foregroundGeneration: 1, focusGeneration: 1, policyRevision: 1 };
  const accepted: Observation[] = [];

  const spawn: SpawnManaged = (spec) => {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const decoder = new FrameDecoder();
    instanceId = spec.argv[spec.argv.indexOf('--instance-id') + 1]!;
    const ownerId = spec.argv[spec.argv.indexOf('--owner-id') + 1]!;
    let finishExit!: (res: { exitCode: number | null; signal: NodeJS.Signals | null }) => void;
    const done = new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>((resolveExit) => {
      finishExit = resolveExit;
    });

    sendToHost = (message: WireMessage) => {
      stdout.write(encodeFrame(message));
    };

    const stdin = new Writable({
      write(chunk, _enc, cb) {
        for (const msg of decoder.push(chunk)) {
          if (msg.type === 'configure') {
            stamp = { ...stamp, policyRevision: msg.policyRevision };
            sendToHost({
              protocolVersion: 1,
              type: 'configured',
              requestId: msg.requestId,
              ownerId,
              instanceId,
              policyRevision: msg.policyRevision,
            });
          } else if (msg.type === 'control') {
            if (msg.command !== 'heartbeat') {
              stamp = { ...stamp, captureEpoch: stamp.captureEpoch + 1 };
            }
            sendToHost({
              protocolVersion: 1,
              type: 'state',
              requestId: msg.requestId,
              instanceId,
              state: msg.command === 'stop' ? 'stopped' : msg.command === 'pause' ? 'paused' : 'running',
              stamp: { ...stamp },
              reason: msg.command === 'pause' ? 'user-paused' : '',
            });
          }
        }
        cb();
      },
    });

    const capabilities: Capability[] = [
      { name: 'text.snapshot', direction: 'observe', scope: 'app-local', support: 'supported', reason: '' },
      { name: 'field.denylist', direction: 'observe', scope: 'app-local', support: 'supported', reason: '' },
    ];
    if (options.includeMenuCapability !== false) {
      capabilities.push({
        name: 'menu.action',
        direction: 'observe',
        scope: 'app-local',
        support: 'supported',
        reason: 'foreground-menu-bar',
      });
    }

    queueMicrotask(() => {
      sendToHost({
        protocolVersion: 1,
        type: 'hello',
        instanceId,
        maxFrameBytes: 65536,
        capabilities,
      });
    });

    const proc: ManagedProcess = {
      stdin,
      stdout,
      stderr,
      done,
      terminate() {
        stdout.end();
        stderr.end();
        finishExit({ exitCode: 0, signal: null });
      },
      async waitForExit() {
        await done;
        return true;
      },
    };
    return proc;
  };

  const supervisor = new CollectorSupervisor({
    helperPath,
    helperSha256: createHash('sha256').update(helperContent).digest('hex'),
    cwd: dir,
    deviceId: target.deviceId,
    allowFixture: options.allowFixture ?? false,
    requestTimeoutMs: 500,
    leaseDurationMs: 1500,
    spawn,
    onObservation:
      options.onObservation ??
      (async (msg) => {
        accepted.push(msg);
      }),
  });

  const emitMenu = (
    path: string[] = ['File', 'Save'],
    overrides: {
      stamp?: Stamp;
      source?: MenuAction['source'];
      identity?: Partial<ApplicationTargetIdentity>;
      gate?: Partial<ContentGate>;
    } = {},
  ) => {
    const nextSeq = ++seq;
    const msg = makeMenuObservation(nextSeq, path, {
      instanceId,
      stamp: overrides.stamp ?? { ...stamp },
      source: overrides.source ?? 'ax.menu',
      ...(overrides.identity ? { identity: overrides.identity } : {}),
      ...(overrides.gate ? { gate: overrides.gate } : {}),
    });
    sendToHost(msg);
    return msg;
  };

  const emitContext = (reason: 'application' | 'focus' = 'focus', bumpEpoch = false) => {
    stamp = {
      ...stamp,
      captureEpoch: bumpEpoch ? stamp.captureEpoch + 1 : stamp.captureEpoch,
      focusGeneration: stamp.focusGeneration + 1,
    };
    const nextSeq = ++seq;
    sendToHost({
      protocolVersion: 1,
      type: 'observation',
      eventId: `${instanceId}:${nextSeq}`,
      instanceId,
      seq: nextSeq,
      eventTimeMs: NOW + nextSeq * 10,
      monotonicMs: nextSeq * 10,
      target: bumpEpoch
        ? { kind: 'unresolved', reason: 'focus-unavailable' }
        : { kind: 'resolved', identity: { ...target } },
      stamp: { ...stamp },
      actor: 'unknown',
      relatedActionIds: [],
      payload: { kind: 'context.changed', reason },
    });
  };

  return {
    supervisor,
    accepted,
    emitMenu,
    emitContext,
    send: (msg: WireMessage) => sendToHost(msg),
    get instanceId() {
      return instanceId;
    },
    get stamp() {
      return { ...stamp };
    },
    async cleanup() {
      await supervisor.stop();
      await rm(dir, { recursive: true, force: true });
    },
  };
}

const basePolicy: CapturePolicy = {
  enabled: true,
  applicationScope: 'allowlist',
  allowedApplicationIds: [target.applicationId],
  menuActions: true,
  maxTextCodeUnits: 4096,
  maxPending: 16,
  debounceMs: 10,
  maxWaitMs: 30,
  readTimeoutMs: 100,
};

const flushTurn = () => new Promise<void>((resolveTurn) => setTimeout(resolveTurn, 25));

test('SegmentStore persists menu.action, maintains counts.menu across reopen/eviction/forget, and supports kind/text search', async () => {
  const temp = await temporary();
  let now = NOW;
  let store = await SegmentStore.open({
    root: temp.root,
    keyProvider: temp.provider,
    clock: () => now,
    maxSegmentBytes: 2048,
  });

  try {
    await store.append(makeMenuObservation(1, ['File', 'Save'], { eventTimeMs: now }));
    await store.append(
      makeMenuObservation(2, ['File', 'Export', 'PDF...'], {
        eventTimeMs: now + 10,
        truncated: true,
      }),
    );
    await store.append(makeMenuObservation(3, ['\u6587\u4ef6', '\u4fdd\u5b58'], { eventTimeMs: now + 20 }));
    await store.append(observation(4, 'regular document text', now + 30));

    assert.equal(store.status().counts.menu, 3);
    assert.equal(store.status().counts.text, 1);

    // Filter by kind: 'menu' via both search() and query() alias.
    const allMenus = await store.search({ kind: 'menu' });
    assert.deepEqual(
      allMenus.records.map((r) => r.eventId),
      ['synthetic-instance:1', 'synthetic-instance:2', 'synthetic-instance:3'],
    );
    assert.equal((await store.query({ kind: 'menu' })).records.length, 3);

    // Substring match against payload.path.join(' > ').
    const saveMatches = await store.search({ kind: 'menu', text: 'Save' });
    assert.deepEqual(
      saveMatches.records.map((r) => r.eventId),
      ['synthetic-instance:1'],
    );
    const joinedPathMatches = await store.search({ kind: 'menu', text: 'Export > PDF' });
    assert.deepEqual(
      joinedPathMatches.records.map((r) => r.eventId),
      ['synthetic-instance:2'],
    );
    const cjkMatches = await store.search({ text: '\u6587\u4ef6 > \u4fdd\u5b58' });
    assert.deepEqual(
      cjkMatches.records.map((r) => r.eventId),
      ['synthetic-instance:3'],
    );

    // Cursor fingerprint isolates kind='menu' from kind='all' and kind='activity'.
    const page1 = await store.search({ kind: 'menu', limit: 2 });
    assert.equal(page1.records.length, 2);
    assert.equal(page1.hasMore, true);
    assert.ok(page1.nextCursor);
    await assert.rejects(
      store.search({ kind: 'activity', limit: 2, cursor: page1.nextCursor }),
      (err: unknown) => err instanceof StorageError && err.code === 'invalid-cursor',
    );
    const page2 = await store.search({ kind: 'menu', limit: 2, cursor: page1.nextCursor });
    assert.deepEqual(
      page2.records.map((r) => r.eventId),
      ['synthetic-instance:3'],
    );

    // read() returns exact record; layout() reports not-a-surface-snapshot.
    const readBack = await store.read('synthetic-instance:2');
    assert.equal(readBack?.payload.kind, 'menu.action');
    if (readBack?.payload.kind === 'menu.action') {
      assert.deepEqual(readBack.payload.path, ['File', 'Export', 'PDF...']);
      assert.equal(readBack.payload.coverage.truncated, true);
    }
    const layoutRes = await store.layout({ eventId: 'synthetic-instance:1' });
    assert.equal(layoutRes.found, false);
    if (!layoutRes.found) {
      assert.equal(layoutRes.reason, 'not-a-surface-snapshot');
    }

    // Close and reopen preserves counts.menu and searchability.
    await store.close();
    store = await SegmentStore.open({
      root: temp.root,
      keyProvider: temp.provider,
      clock: () => now,
      maxSegmentBytes: 2048,
    });
    assert.equal(store.status().counts.menu, 3);
    assert.equal((await store.search({ kind: 'menu', text: 'Save' })).records.length, 1);

    // Partial forget drops seq 1 and updates counts.menu.
    await store.forget({ beforeMs: now + 10 });
    assert.equal(store.status().counts.menu, 2);
    assert.equal(await store.read('synthetic-instance:1'), null);

    // TTL expiration evicts older menu records while keeping fresh ones.
    now += 6 * 24 * 60 * 60 * 1000;
    await store.append(makeMenuObservation(5, ['Edit', 'Copy'], { eventTimeMs: now }));
    assert.equal(store.status().counts.menu, 3);

    now = NOW + HISTORY_RETENTION_MS + 10_000;
    await store.pruneExpired();
    assert.equal(store.status().counts.menu, 1);
    assert.deepEqual(
      (await store.search({ kind: 'menu' })).records.map((r) => r.eventId),
      ['synthetic-instance:5'],
    );

    // Full forget clears counts.menu.
    await store.forget({ all: true });
    assert.equal(store.status().counts.menu, 0);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('SegmentStore updates counts.menu on maxBytes segment eviction', async () => {
  const temp = await temporary();
  let now = NOW;
  const store = await SegmentStore.open({
    root: temp.root,
    keyProvider: temp.provider,
    clock: () => now,
    maxSegmentBytes: 1500,
    maxBytes: 4200,
  });

  try {
    await store.append(makeMenuObservation(1, ['File', 'Open...'], { eventTimeMs: now }));
    await store.append(makeMenuObservation(2, ['File', 'Save'], { eventTimeMs: now + 1 }));
    assert.equal(store.status().counts.menu, 2);

    // Fill later segments with text snapshots to force eviction of seg-00000001.cah.
    for (let seq = 3; seq <= 12; seq++) {
      now += 100;
      const body = String.fromCharCode(65 + (seq % 26)).repeat(600);
      await store.append(observation(seq, body, now));
    }

    assert.equal(await store.read('synthetic-instance:1'), null);
    assert.equal(await store.read('synthetic-instance:2'), null);
    assert.equal(store.status().counts.menu, 0);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('CollectorAdmission enforces application identity and epoch/generation fencing for menu.action', () => {
  const ack: Configured = {
    protocolVersion: 1,
    type: 'configured',
    requestId: 'cfg-menu-1',
    ownerId: 'host-1',
    instanceId: 'synthetic-instance',
    policyRevision: 1,
  };
  const initialStamp: Stamp = { captureEpoch: 2, foregroundGeneration: 4, focusGeneration: 6, policyRevision: 1 };
  const admission = new CollectorAdmission({ ...ack }, initialStamp, () => true);
  admission.acknowledge(ack);
  admission.setBoundary(initialStamp, target);

  // Earlier foreground/focus generations within the same captureEpoch are admitted without establishing a text baseline.
  const validMenu = makeMenuObservation(1, ['File', 'Save'], {
    stamp: { captureEpoch: 2, foregroundGeneration: 3, focusGeneration: 5, policyRevision: 1 },
  });
  assert.equal(admission.accept(validMenu).accepted, true);
  assert.equal(admission.commit(validMenu.eventId), false);

  // Stale captureEpoch or future focusGeneration are rejected.
  assert.equal(
    admission.accept(
      makeMenuObservation(2, ['File', 'Save'], {
        stamp: { captureEpoch: 1, foregroundGeneration: 3, focusGeneration: 5, policyRevision: 1 },
      }),
    ).reason,
    'stale',
  );
  assert.equal(
    admission.accept(
      makeMenuObservation(3, ['File', 'Save'], {
        stamp: { captureEpoch: 2, foregroundGeneration: 4, focusGeneration: 7, policyRevision: 1 },
      }),
    ).reason,
    'stale',
  );

  // Application identity mismatch against the resolved boundary is rejected.
  for (const changed of [
    { applicationId: 'other.allowed' },
    { processId: target.processId + 1 },
    { processStartTime: 'reused-pid' },
    { osSessionId: 'other-session' },
    { desktopId: 'other-desktop' },
  ]) {
    const fresh = new CollectorAdmission({ ...ack }, initialStamp, () => true);
    fresh.acknowledge(ack);
    fresh.setBoundary(initialStamp, target);
    const badTarget = makeMenuObservation(1, ['File', 'Save'], {
      stamp: initialStamp,
      identity: changed,
    });
    assert.equal(fresh.accept(badTarget).reason, 'target');
  }
});

test('CollectorSupervisor enforces menu.action capability, privacy gates, applicationAnchor, sameAuthority, and AX-only unlock', async () => {
  // 1. Missing 'menu.action' capability rejects startup when policy.menuActions === true.
  const missingCap = await createSupervisorHarness({ includeMenuCapability: false });
  try {
    await assert.rejects(missingCap.supervisor.start(basePolicy), /content-capability-unavailable/);
  } finally {
    await missingCap.cleanup();
  }

  // 2. Disabled policy.menuActions drops menu.action observations.
  const disabled = await createSupervisorHarness({ includeMenuCapability: true });
  try {
    await disabled.supervisor.start({ ...basePolicy, menuActions: false });
    disabled.emitMenu(['File', 'Save']);
    await flushTurn();
    assert.equal(disabled.accepted.length, 0);
    assert.equal(disabled.supervisor.status().accepted.menu, 0);
  } finally {
    await disabled.cleanup();
  }

  // 3. Enabled policy accepts ax.menu, rejects fixture when allowFixture=false, and enforces privacy & gate checks.
  const strict = await createSupervisorHarness({ includeMenuCapability: true, allowFixture: false });
  try {
    await strict.supervisor.start({
      ...basePolicy,
      applicationScope: 'denylist',
      allowedApplicationIds: [],
      allowBrowserContent: false,
      fieldSecurity: 'strict',
    });

    // Valid ax.menu -> accepted.
    strict.emitMenu(['File', 'Save']);
    // Fixture source disallowed when allowFixture=false -> dropped.
    strict.emitMenu(['File', 'Fixture'], { source: 'fixture' });
    // Mandatory excluded family (1Password, Safari) -> dropped.
    strict.emitMenu(['File', 'Unlock'], { identity: { applicationId: 'com.1password.1password' } });
    strict.emitMenu(['File', 'New Private Window'], { identity: { applicationId: 'com.apple.Safari' } });
    // System UI -> dropped.
    strict.emitMenu(['Control', 'Wi-Fi'], { identity: { applicationId: 'com.apple.ControlCenter' } });
    // Wrong deviceId -> dropped.
    strict.emitMenu(['File', 'WrongDevice'], { identity: { deviceId: 'other-device' } });
    // fieldSecurity='strict' rejects not-declared-sensitive -> dropped.
    strict.emitMenu(['File', 'StrictDrop'], { gate: { secure: 'not-declared-sensitive' } });
    // allowBrowserContent=false rejects user-authorized privateState -> dropped.
    strict.emitMenu(['File', 'BrowserDrop'], {
      identity: { applicationId: 'com.google.Chrome' },
      gate: { privateState: 'user-authorized' },
    });

    await flushTurn();
    assert.equal(strict.accepted.length, 1);
    assert.equal(strict.supervisor.status().accepted.menu, 1);
    assert.equal(strict.supervisor.status().accepted.text, 0);
    assert.equal(strict.supervisor.status().accepted.activity, 0);
    assert.equal(strict.supervisor.status().state, 'running');

    // AX-only desktop unlock (menuActions=true, inputText/inputActivity off) auto-resumes cleanly.
    const lockStamp = { ...strict.stamp, captureEpoch: strict.stamp.captureEpoch + 1 };
    strict.send({
      protocolVersion: 1,
      type: 'state',
      requestId: 'desktop',
      instanceId: strict.instanceId,
      state: 'paused',
      stamp: lockStamp,
      reason: 'screen-locked',
    });
    await flushTurn();
    assert.equal(strict.supervisor.status().state, 'paused');

    const unlockStamp = { ...lockStamp, captureEpoch: lockStamp.captureEpoch + 1 };
    strict.send({
      protocolVersion: 1,
      type: 'state',
      requestId: 'desktop',
      instanceId: strict.instanceId,
      state: 'running',
      stamp: unlockStamp,
      reason: '',
    });
    await flushTurn();
    assert.equal(strict.supervisor.status().state, 'running');
  } finally {
    await strict.cleanup();
  }

  // 4. denylist + allowBrowserContent + fieldSecurity='denylist' accepts browser user-authorized & not-declared-sensitive.
  const denylist = await createSupervisorHarness({ includeMenuCapability: true, allowFixture: false });
  try {
    await denylist.supervisor.start({
      ...basePolicy,
      applicationScope: 'denylist',
      allowedApplicationIds: [],
      allowBrowserContent: true,
      fieldSecurity: 'denylist',
    });
    denylist.emitMenu(['File', 'New Tab'], {
      identity: { applicationId: 'com.google.Chrome' },
      gate: { secure: 'not-declared-sensitive', privateState: 'user-authorized' },
    });
    await flushTurn();
    assert.equal(denylist.supervisor.status().accepted.menu, 1);
  } finally {
    await denylist.cleanup();
  }

  // 5. applicationAnchor pins identity within captureEpoch even when inputActivity is off.
  const anchored = await createSupervisorHarness({ includeMenuCapability: true });
  try {
    await anchored.supervisor.start({ ...basePolicy, inputActivity: false, menuActions: true });
    anchored.emitMenu(['File', 'Save']);
    await flushTurn();
    assert.equal(anchored.supervisor.status().accepted.menu, 1);
    anchored.emitMenu(['File', 'Quit'], { identity: { processStartTime: 'reused-pid' } });
    await flushTurn();
    assert.equal(anchored.supervisor.status().state, 'failed');
    assert.equal(anchored.supervisor.status().reason, 'input-activity-identity-changed');
    assert.equal(anchored.accepted.length, 1);
  } finally {
    await anchored.cleanup();
  }

  // 6. sameAuthority survives focus generation changes within captureEpoch, but drops on captureEpoch advance.
  let releaseWrite!: () => void;
  const writeGate = new Promise<void>((resolveGate) => {
    releaseWrite = resolveGate;
  });
  const validity: boolean[] = [];
  const authHarness = await createSupervisorHarness({
    includeMenuCapability: true,
    onObservation: async (msg, isCurrent) => {
      if (msg.payload.kind === 'menu.action') {
        await writeGate;
        validity.push(isCurrent());
      }
    },
  });
  try {
    await authHarness.supervisor.start(basePolicy);
    const oldStamp = authHarness.stamp;
    authHarness.emitMenu(['Edit', 'Undo'], { stamp: oldStamp });
    await flushTurn();
    authHarness.emitContext('focus', false);
    releaseWrite();
    await flushTurn();
    assert.deepEqual(validity, [true]);
    assert.equal(authHarness.supervisor.status().accepted.menu, 1);

    // Advance captureEpoch via application context change; old-epoch menu.action must drop.
    authHarness.emitContext('application', true);
    authHarness.emitMenu(['Edit', 'Redo'], { stamp: oldStamp });
    await flushTurn();
    assert.equal(authHarness.supervisor.status().accepted.menu, 1);
  } finally {
    await authHarness.cleanup();
  }
});

test('MCP history_search/history_status and Admin HTTP API expose menu.action end-to-end', async () => {
  const tempRoot = await realpath(await mkdtemp(join(tmpdir(), 'chmcp-menu-mcp-')));
  const dataDir = join(tempRoot, 'data');
  const binDir = join(tempRoot, 'native-bin');
  await mkdir(join(binDir, 'HistoryContract_HistoryContract.bundle/Contents/Resources'), { recursive: true });
  const collectorPath = join(binDir, 'computer-history-collector');
  const collectorStub = 'synthetic-menu-e2e-collector';
  await writeFile(collectorPath, collectorStub, { mode: 0o700 });
  const schemaRel = 'HistoryContract_HistoryContract.bundle/Contents/Resources/wire.schema.json';
  const schemaBytes = await readFile(join(REPO_ROOT, 'src/shared/protocol/wire.schema.json'));
  await writeFile(join(binDir, schemaRel), schemaBytes, { mode: 0o600 });
  const sha256 = (data: Buffer | string) => createHash('sha256').update(data).digest('hex');
  await writeFile(
    join(binDir, 'manifest.json'),
    JSON.stringify({
      version: 1,
      platform: process.platform,
      arch: process.arch,
      files: {
        'computer-history-collector': { sha256: sha256(collectorStub) },
        [schemaRel]: { sha256: sha256(schemaBytes) },
      },
    }),
    { mode: 0o600 },
  );

  const keyProvider = new MemoryKeyProvider();
  (await keyProvider.getOrCreateKey()).fill(0);
  const recentNow = Date.now();
  let emitLiveMenu!: (path: string[], truncated?: boolean) => void;

  const spawn: SpawnManaged = (spec) => {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const decoder = new FrameDecoder();
    const instanceId = spec.argv[spec.argv.indexOf('--instance-id') + 1] ?? '';
    const ownerId = spec.argv[spec.argv.indexOf('--owner-id') + 1] ?? '';
    let policyRevision = 1;
    let captureEpoch = 1;
    let seq = 0;
    let finishExit!: (res: { exitCode: number | null; signal: NodeJS.Signals | null }) => void;
    const done = new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>((resolveExit) => {
      finishExit = resolveExit;
    });
    const send = (msg: WireMessage) => stdout.write(encodeFrame(msg));
    const currentStamp = (): Stamp => ({
      captureEpoch,
      foregroundGeneration: 1,
      focusGeneration: 1,
      policyRevision,
    });

    const stdin = new Writable({
      write(chunk, _enc, cb) {
        for (const msg of decoder.push(chunk)) {
          if (msg.type === 'configure') {
            policyRevision = msg.policyRevision;
            send({
              protocolVersion: 1,
              type: 'configured',
              requestId: msg.requestId,
              ownerId,
              instanceId,
              policyRevision,
            });
          } else if (msg.type === 'control') {
            if (msg.command !== 'heartbeat') captureEpoch++;
            send({
              protocolVersion: 1,
              type: 'state',
              requestId: msg.requestId,
              instanceId,
              state: msg.command === 'stop' ? 'stopped' : msg.command === 'pause' ? 'paused' : 'running',
              stamp: currentStamp(),
              reason: msg.command === 'pause' ? 'user-paused' : '',
            });
          }
        }
        cb();
      },
    });

    queueMicrotask(() => {
      send({
        protocolVersion: 1,
        type: 'hello',
        instanceId,
        maxFrameBytes: 65536,
        capabilities: [
          'text.snapshot',
          'surface.snapshot',
          'selection.snapshot',
          'input.text',
          'input.activity',
          'menu.action',
          'ax.enablement',
          'text.marker',
          'field.denylist',
        ].map((name) => ({
          name: name as Capability['name'],
          direction: 'observe' as const,
          scope: name === 'input.activity' ? ('authorized-desktop' as const) : ('app-local' as const),
          support: 'supported' as const,
          reason: '',
        })),
      });
    });

    emitLiveMenu = (path: string[], truncated = false) => {
      const nextSeq = ++seq;
      send(
        makeMenuObservation(nextSeq, path, {
          instanceId,
          eventTimeMs: Date.now(),
          stamp: currentStamp(),
          truncated,
          identity: { applicationId: 'com.google.antigravity-ide', deviceId: 'menu-dev' },
        }),
      );
    };

    return {
      stdin,
      stdout,
      stderr,
      done,
      terminate() {
        stdout.end();
        stderr.end();
        finishExit({ exitCode: 0, signal: null });
      },
      async waitForExit() {
        await done;
        return true;
      },
    };
  };

  // Seed one unrelated text snapshot and one menu.action before starting live capture.
  const seedStore = await SegmentStore.open({ root: dataDir, keyProvider, clock: () => recentNow });
  await seedStore.append(
    makeMenuObservation(1, ['File', 'Export', 'PDF...'], {
      eventTimeMs: recentNow,
      truncated: true,
      identity: { applicationId: 'com.google.antigravity-ide', deviceId: 'menu-dev' },
    }),
  );
  await seedStore.append(observation(2, 'unrelated text body', recentNow + 10));
  await seedStore.close();

  const service = createHistoryService({
    dataRoot: dataDir,
    helperPath: collectorPath,
    deviceId: 'menu-dev',
    keyProvider,
    spawn,
  });
  await service.initializeKey();
  // Explicitly enable menuActions so this end-to-end test is platform-independent.
  await service.start({ menuActions: true });
  emitLiveMenu(['File', 'Save']);

  for (let i = 0; i < 20; i++) {
    const st = await service.status();
    if (st.collector?.accepted.menu === 1 && st.storage?.counts.menu === 2) break;
    await flushTurn();
  }

  const srv = await startHttpServer({
    dataDir,
    port: 0,
    service,
  });

  try {
    const { token: readToken } = await srv.authStore.createLease({
      label: 'menu-reader',
      scopes: ['read'],
      ttlMs: null,
    });

    const mcpCall = async (body: unknown) => {
      const res = await fetch(srv.mcpUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${readToken}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify(body),
      });
      assert.equal(res.status, 200);
      return (await res.json()) as {
        result?: {
          tools?: Array<{ name: string; inputSchema?: { properties?: Record<string, { enum?: string[] }> } }>;
          content?: Array<{ text: string }>;
          isError?: boolean;
        };
      };
    };

    // 1. tools/list includes 'menu' in history_search kind enum.
    const toolsList = await mcpCall({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    const searchTool = toolsList.result?.tools?.find((t) => t.name === 'history_search');
    assert.ok(searchTool?.inputSchema?.properties?.kind?.enum?.includes('menu'));

    // 2. history_status exposes activeScope.menuActions, collector.accepted.menu, and storage.counts.menu.
    const statusRpc = await mcpCall({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'history_status', arguments: {} },
    });
    const statusBody = JSON.parse(statusRpc.result?.content?.[0]?.text ?? '{}') as {
      activeScope: { menuActions: boolean };
      collector: { accepted: { menu: number } };
      storage: { counts: { menu: number; text: number } };
    };
    assert.equal(statusBody.activeScope.menuActions, true);
    assert.equal(statusBody.collector.accepted.menu, 1);
    assert.equal(statusBody.storage.counts.menu, 2);
    assert.equal(statusBody.storage.counts.text, 1);

    // 3. history_search(kind: 'menu') and history_search(kind: 'menu', text: 'Save') work over MCP.
    const allMenuRpc = await mcpCall({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'history_search', arguments: { kind: 'menu' } },
    });
    const allMenuBody = JSON.parse(allMenuRpc.result?.content?.[0]?.text ?? '{}') as {
      records: Array<{ eventId: string; payload: { kind: string; path: string[] } }>;
    };
    assert.equal(allMenuBody.records.length, 2);
    assert.equal(allMenuBody.records[0]?.payload.kind, 'menu.action');

    const saveMenuRpc = await mcpCall({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: { name: 'history_search', arguments: { kind: 'menu', text: 'Save' } },
    });
    const saveMenuBody = JSON.parse(saveMenuRpc.result?.content?.[0]?.text ?? '{}') as {
      records: Array<{ eventId: string; payload: { path: string[] } }>;
    };
    assert.equal(saveMenuBody.records.length, 1);
    assert.deepEqual(saveMenuBody.records[0]?.payload.path, ['File', 'Save']);

    // 4. Admin /api/history/search accepts kind='menu' and matches joined path.
    const adminSearchRes = await fetch(`${srv.baseUrl}/api/history/search`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${srv.adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ kind: 'menu', text: 'Export > PDF' }),
    });
    assert.equal(adminSearchRes.status, 200);
    const adminSearch = (await adminSearchRes.json()) as { records: Array<{ eventId: string }> };
    assert.equal(adminSearch.records.length, 1);
    assert.equal(adminSearch.records[0]?.eventId, 'synthetic-instance:1');
  } finally {
    await srv.close();
    await rm(tempRoot, { recursive: true, force: true });
  }
});

test('locale/en.json and locale/zh.json have identical key sets including menu action strings', async () => {
  const en = JSON.parse(await readFile(join(REPO_ROOT, 'locale/en.json'), 'utf8')) as {
    meta: Record<string, string>;
    ui: Record<string, string>;
  };
  const zh = JSON.parse(await readFile(join(REPO_ROOT, 'locale/zh.json'), 'utf8')) as {
    meta: Record<string, string>;
    ui: Record<string, string>;
  };
  assert.deepEqual(Object.keys(en.meta).sort(), Object.keys(zh.meta).sort());
  assert.deepEqual(Object.keys(en.ui).sort(), Object.keys(zh.ui).sort());
  assert.ok(en.ui.chMenuActions && en.ui.chMenuActions.length > 0);
  assert.ok(zh.ui.chMenuActions && zh.ui.chMenuActions.length > 0);
  assert.ok(en.ui.kind_menu && en.ui.kind_menu.length > 0);
  assert.ok(zh.ui.kind_menu && zh.ui.kind_menu.length > 0);
});

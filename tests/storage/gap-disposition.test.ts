import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { PassThrough, Writable } from 'node:stream';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { target } from '../../fixtures/contract/examples.ts';
import { CollectorSupervisor } from '../../src/host/collectors/supervisor.ts';
import type { SpawnManaged } from '../../src/host/collectors/process.ts';
import {
  classifyGap,
  GAP_DIAGNOSTIC_DISPOSITION,
  GAP_REASON_DISPOSITION,
} from '../../src/shared/gap-classification.ts';
import type { CapturePolicy, Gap, GapDiagnostic, Observation, WireMessage } from '../../src/shared/protocol/generated.ts';
import { encodeFrame, FrameDecoder } from '../../src/shared/protocol/validate.ts';
import { HISTORY_RETENTION_MS, SegmentStore, StorageError } from '../../src/storage/index.ts';
import { NOW, observation, temporary } from '../integration/history-store-fixtures.ts';

const EXPECTED_DISCARDED_CODES: readonly GapDiagnostic['code'][] = [
  'focus-changed',
  'input-target-mismatch',
  'surface-boundary-mismatch',
  'input-role-not-editable',
  'focused-field-unavailable',
  'focused-role-not-text',
  'input-context-unverified',
  'surface-boundary-unverified',
  'application-not-allowed',
  'browser-excluded',
  'secure-field',
  'field-security-unknown',
  'input-field-security-unknown',
  'input-policy-boundary',
  'surface-security-excluded',
  'desktop-unavailable',
];

const EXPECTED_EXCEPTION_CODES: readonly GapDiagnostic['code'][] = [
  'read-deadline',
  'surface-time-budget',
  'surface-call-budget',
  'surface-not-started-budget',
  'input-verification-timeout',
  'input-text-budget',
  'input-text-backpressure',
  'input-text-read-unavailable',
  'accessibility-denied',
  'application-unavailable',
  'visible-range-unavailable',
  'text-read-unavailable',
  'text-result-invalid',
  'invalid-sampling-policy',
  'capture-authority-changed',
  'worker-retirement-pending',
  'surface-anchor-unavailable',
  'surface-boundary-ax-failed',
  'surface-boundary-incomplete',
  'surface-provider-unavailable',
];

const EXPECTED_DISCARDED_REASONS: readonly Gap['reason'][] = [
  'policy-boundary',
  'stale',
  'desktop-unavailable',
];

const EXPECTED_EXCEPTION_REASONS: readonly Gap['reason'][] = [
  'timeout',
  'read-error',
  'budget',
  'backpressure',
  'host-lost',
  'baseline-unavailable',
];

function gapObservation(seq: number, payload: Gap, eventTimeMs = NOW + seq * 1000): Observation {
  const base = observation(seq, 'placeholder', eventTimeMs);
  return {
    ...base,
    target: { kind: 'unresolved', reason: 'policy-boundary' },
    payload,
  };
}

test('gap classification exhaustively covers every wire schema diagnostic code and reason', async () => {
  const schemaPath = fileURLToPath(new URL('../../src/shared/protocol/wire.schema.json', import.meta.url));
  const schema = JSON.parse(await readFile(schemaPath, 'utf8')) as {
    $defs: {
      GapDiagnostic: { properties: { code: { enum: string[] } } };
      Gap: { properties: { reason: { enum: string[] } } };
    };
  };

  const schemaCodes = [...schema.$defs.GapDiagnostic.properties.code.enum].sort();
  const tableCodes = Object.keys(GAP_DIAGNOSTIC_DISPOSITION).sort();
  assert.deepEqual(tableCodes, schemaCodes);
  assert.equal(EXPECTED_DISCARDED_CODES.length, 16);
  assert.equal(EXPECTED_EXCEPTION_CODES.length, 20);
  assert.deepEqual([...EXPECTED_DISCARDED_CODES, ...EXPECTED_EXCEPTION_CODES].sort(), schemaCodes);

  for (const code of EXPECTED_DISCARDED_CODES) {
    assert.equal(GAP_DIAGNOSTIC_DISPOSITION[code], 'discarded', code);
    // Diagnostic takes precedence even if reason alone would classify as exception.
    assert.equal(classifyGap({ reason: 'read-error', diagnostic: { code } }), 'discarded', code);
  }
  for (const code of EXPECTED_EXCEPTION_CODES) {
    assert.equal(GAP_DIAGNOSTIC_DISPOSITION[code], 'exception', code);
    // Diagnostic takes precedence even if reason alone would classify as discarded.
    assert.equal(classifyGap({ reason: 'stale', diagnostic: { code } }), 'exception', code);
  }

  const schemaReasons = [...schema.$defs.Gap.properties.reason.enum].sort();
  const tableReasons = Object.keys(GAP_REASON_DISPOSITION).sort();
  assert.deepEqual(tableReasons, schemaReasons);
  assert.deepEqual([...EXPECTED_DISCARDED_REASONS, ...EXPECTED_EXCEPTION_REASONS].sort(), schemaReasons);

  for (const reason of EXPECTED_DISCARDED_REASONS) {
    assert.equal(GAP_REASON_DISPOSITION[reason], 'discarded', reason);
    assert.equal(classifyGap({ reason }), 'discarded', reason);
  }
  for (const reason of EXPECTED_EXCEPTION_REASONS) {
    assert.equal(GAP_REASON_DISPOSITION[reason], 'exception', reason);
    assert.equal(classifyGap({ reason }), 'exception', reason);
  }
});

test('SegmentStore maintains gapDiscarded and gapException across append, reopen, search, forget, and eviction', async () => {
  const temp = await temporary();
  let now = NOW;
  let store = await SegmentStore.open({
    root: temp.root,
    keyProvider: temp.provider,
    clock: () => now,
    maxSegmentBytes: 2048,
  });

  try {
    // 2 discarded (1 diagnosed, 1 legacy undiagnosed), 2 exception (1 diagnosed, 1 legacy), 1 text record.
    await store.append(
      gapObservation(1, { kind: 'gap', reason: 'stale', count: 1, diagnostic: { code: 'focus-changed' } }, now),
    );
    await store.append(
      gapObservation(2, { kind: 'gap', reason: 'timeout', count: 1, diagnostic: { code: 'read-deadline' } }, now + 10),
    );
    await store.append(
      gapObservation(3, { kind: 'gap', reason: 'policy-boundary', count: 2 }, now + 20),
    );
    await store.append(
      gapObservation(4, { kind: 'gap', reason: 'budget', count: 1 }, now + 30),
    );
    await store.append(observation(5, 'regular captured text', now + 40));

    assert.equal(store.status().counts.gap, 4);
    assert.equal(store.status().counts.gapDiscarded, 2);
    assert.equal(store.status().counts.gapException, 2);
    assert.equal(store.status().counts.text, 1);

    // Search filters: exception, discarded, gap (all gaps), and query() alias.
    const exceptions = await store.search({ kind: 'exception' });
    assert.deepEqual(
      exceptions.records.map((r) => r.eventId),
      ['synthetic-instance:2', 'synthetic-instance:4'],
    );

    const discarded = await store.query({ kind: 'discarded' });
    assert.deepEqual(
      discarded.records.map((r) => r.eventId),
      ['synthetic-instance:1', 'synthetic-instance:3'],
    );

    const allGaps = await store.search({ kind: 'gap' });
    assert.equal(allGaps.records.length, 4);

    // Cursor fingerprint must isolate kind='exception' vs kind='discarded' vs kind='gap'.
    const page1 = await store.search({ kind: 'exception', limit: 1 });
    assert.equal(page1.hasMore, true);
    assert.ok(page1.nextCursor);
    await assert.rejects(
      store.search({ kind: 'discarded', limit: 1, cursor: page1.nextCursor }),
      (err: unknown) => err instanceof StorageError && err.code === 'invalid-cursor',
    );
    await assert.rejects(
      store.search({ kind: 'gap', limit: 1, cursor: page1.nextCursor }),
      (err: unknown) => err instanceof StorageError && err.code === 'invalid-cursor',
    );
    const page2 = await store.search({ kind: 'exception', limit: 1, cursor: page1.nextCursor });
    assert.deepEqual(
      page2.records.map((r) => r.eventId),
      ['synthetic-instance:4'],
    );

    // Close and reopen: retroactive classification must preserve exact counts.
    await store.close();
    store = await SegmentStore.open({
      root: temp.root,
      keyProvider: temp.provider,
      clock: () => now,
      maxSegmentBytes: 2048,
    });
    assert.equal(store.status().counts.gap, 4);
    assert.equal(store.status().counts.gapDiscarded, 2);
    assert.equal(store.status().counts.gapException, 2);
    assert.equal((await store.search({ kind: 'exception' })).records.length, 2);
    assert.equal((await store.search({ kind: 'discarded' })).records.length, 2);

    // Partial forget removes seq 1 (discarded) and seq 2 (exception).
    await store.forget({ beforeMs: now + 20 });
    assert.equal(store.status().counts.gap, 2);
    assert.equal(store.status().counts.gapDiscarded, 1);
    assert.equal(store.status().counts.gapException, 1);

    // Append newer records after advancing clock so older records expire by 7-day TTL.
    now += 6 * 24 * 60 * 60 * 1000;
    await store.append(
      gapObservation(
        6,
        { kind: 'gap', reason: 'read-error', count: 1, diagnostic: { code: 'surface-time-budget' } },
        now,
      ),
    );
    assert.equal(store.status().counts.gap, 3);
    assert.equal(store.status().counts.gapDiscarded, 1);
    assert.equal(store.status().counts.gapException, 2);

    now = NOW + HISTORY_RETENTION_MS + 10_000;
    await store.pruneExpired();
    assert.equal(store.status().counts.gap, 1);
    assert.equal(store.status().counts.gapDiscarded, 0);
    assert.equal(store.status().counts.gapException, 1);

    // Full forget clears everything cleanly.
    await store.forget({ all: true });
    assert.equal(store.status().counts.gap, 0);
    assert.equal(store.status().counts.gapDiscarded, 0);
    assert.equal(store.status().counts.gapException, 0);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('SegmentStore updates gapDiscarded and gapException on maxBytes segment eviction', async () => {
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
    await store.append(
      gapObservation(1, { kind: 'gap', reason: 'stale', count: 1, diagnostic: { code: 'focus-changed' } }, now),
    );
    await store.append(
      gapObservation(2, { kind: 'gap', reason: 'read-error', count: 1, diagnostic: { code: 'read-deadline' } }, now + 1),
    );
    assert.equal(store.status().counts.gapDiscarded, 1);
    assert.equal(store.status().counts.gapException, 1);

    // Write enough incompressible text frames to roll segments and evict seg-00000001.cah.
    for (let seq = 3; seq <= 12; seq++) {
      now += 100;
      const payload = String.fromCharCode(65 + (seq % 26)).repeat(600);
      await store.append(observation(seq, payload, now));
    }

    assert.equal(await store.read('synthetic-instance:1'), null);
    assert.equal(await store.read('synthetic-instance:2'), null);
    assert.equal(store.status().counts.gap, 0);
    assert.equal(store.status().counts.gapDiscarded, 0);
    assert.equal(store.status().counts.gapException, 0);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('CollectorSupervisor separates accepted discarded vs exception gaps and preserves lastException across noisy discards', async () => {
  const temp = await temporary();
  const helperPath = `${temp.parent}/fake-helper`;
  const { writeFile } = await import('node:fs/promises');
  await writeFile(helperPath, 'synthetic', { mode: 0o700 });

  let sendToHost!: (message: WireMessage) => void;
  let instanceId = '';
  let seq = 0;
  let stamp = { captureEpoch: 1, foregroundGeneration: 1, focusGeneration: 1, policyRevision: 1 };

  const spawn: SpawnManaged = (spec) => {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const decoder = new FrameDecoder();
    instanceId = spec.argv[spec.argv.indexOf('--instance-id') + 1]!;
    const ownerId = spec.argv[spec.argv.indexOf('--owner-id') + 1]!;
    let finishExit!: (res: { exitCode: number | null; signal: NodeJS.Signals | null }) => void;
    const done = new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>((resolve) => {
      finishExit = resolve;
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
            if (msg.command !== 'heartbeat') stamp = { ...stamp, captureEpoch: stamp.captureEpoch + 1 };
            sendToHost({
              protocolVersion: 1,
              type: 'state',
              requestId: msg.requestId,
              instanceId,
              state: msg.command === 'stop' ? 'stopped' : msg.command === 'pause' ? 'paused' : 'running',
              stamp,
              reason: msg.command === 'pause' ? 'user-paused' : '',
            });
          }
        }
        cb();
      },
    });

    queueMicrotask(() => {
      sendToHost({
        protocolVersion: 1,
        type: 'hello',
        instanceId,
        maxFrameBytes: 65536,
        capabilities: [
          { name: 'text.snapshot', direction: 'observe', scope: 'app-local', support: 'supported', reason: '' },
        ],
      });
    });

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

  const turn = () => new Promise<void>((resolve) => setTimeout(resolve, 25));
  const emitGap = (payload: Gap) => {
    seq += 1;
    sendToHost({
      protocolVersion: 1,
      type: 'observation',
      eventId: `${instanceId}:${seq}`,
      instanceId,
      seq,
      eventTimeMs: NOW + seq * 10,
      monotonicMs: seq * 10,
      target: { kind: 'unresolved', reason: 'policy-boundary' },
      stamp,
      actor: 'unknown',
      relatedActionIds: [],
      payload,
    });
  };

  const supervisor = new CollectorSupervisor({
    helperPath,
    cwd: temp.parent,
    deviceId: target.deviceId,
    allowFixture: true,
    spawn,
    onObservation: async () => {},
  });

  const policy: CapturePolicy = {
    enabled: true,
    applicationScope: 'allowlist',
    allowedApplicationIds: [target.applicationId],
    maxTextCodeUnits: 4096,
    maxPending: 16,
    debounceMs: 50,
    maxWaitMs: 500,
    readTimeoutMs: 1000,
  };

  try {
    await supervisor.start(policy);

    // 1. Discarded gap must NOT populate lastException*.
    emitGap({ kind: 'gap', reason: 'stale', count: 1, diagnostic: { code: 'input-context-unverified' } });
    await turn();
    let st = supervisor.status();
    assert.equal(st.accepted.gaps, 1);
    assert.equal(st.accepted.gapsDiscarded, 1);
    assert.equal(st.accepted.gapsException, 0);
    assert.equal(st.lastGapReason, 'stale');
    assert.deepEqual(st.lastGapDiagnostic, { code: 'input-context-unverified' });
    assert.equal(st.lastExceptionReason, null);
    assert.equal(st.lastExceptionDiagnostic, null);

    // 2. Exception gap populates both lastGap* and lastException*.
    emitGap({ kind: 'gap', reason: 'timeout', count: 1, diagnostic: { code: 'read-deadline' } });
    await turn();
    st = supervisor.status();
    assert.equal(st.accepted.gaps, 2);
    assert.equal(st.accepted.gapsDiscarded, 1);
    assert.equal(st.accepted.gapsException, 1);
    assert.equal(st.lastGapReason, 'timeout');
    assert.deepEqual(st.lastGapDiagnostic, { code: 'read-deadline' });
    assert.equal(st.lastExceptionReason, 'timeout');
    assert.deepEqual(st.lastExceptionDiagnostic, { code: 'read-deadline' });

    // Detached copy invariant on lastExceptionDiagnostic.
    st.lastExceptionDiagnostic!.code = 'accessibility-denied';
    assert.equal(supervisor.status().lastExceptionDiagnostic?.code, 'read-deadline');

    // 3. Subsequent discarded gap updates lastGap* but preserves lastException*.
    emitGap({ kind: 'gap', reason: 'policy-boundary', count: 1, diagnostic: { code: 'focused-role-not-text', role: 'AXMenuItem' } });
    await turn();
    st = supervisor.status();
    assert.equal(st.accepted.gaps, 3);
    assert.equal(st.accepted.gapsDiscarded, 2);
    assert.equal(st.accepted.gapsException, 1);
    assert.equal(st.lastGapReason, 'policy-boundary');
    assert.deepEqual(st.lastGapDiagnostic, { code: 'focused-role-not-text', role: 'AXMenuItem' });
    assert.equal(st.lastExceptionReason, 'timeout');
    assert.deepEqual(st.lastExceptionDiagnostic, { code: 'read-deadline' });

    // 4. Legacy undiagnosed exception gap updates lastExceptionReason and clears lastExceptionDiagnostic.
    emitGap({ kind: 'gap', reason: 'host-lost', count: 1 });
    await turn();
    st = supervisor.status();
    assert.equal(st.accepted.gaps, 4);
    assert.equal(st.accepted.gapsDiscarded, 2);
    assert.equal(st.accepted.gapsException, 2);
    assert.equal(st.lastExceptionReason, 'host-lost');
    assert.equal(st.lastExceptionDiagnostic, null);

    // 5. Paused supervisor drops gaps without altering exception telemetry.
    await supervisor.pause();
    emitGap({ kind: 'gap', reason: 'read-error', count: 1, diagnostic: { code: 'accessibility-denied' } });
    await turn();
    st = supervisor.status();
    assert.equal(st.accepted.gapsException, 2);
    assert.equal(st.lastExceptionReason, 'host-lost');
  } finally {
    await supervisor.stop();
    await temp.cleanup();
  }
});

import assert from 'node:assert/strict';
import { lstat, mkdtemp, readdir, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import type { TestContext } from 'node:test';
import { CollectorDebugLog } from '../../src/host/collectors/debug-log.ts';
import { EvidenceCorrelator, evidenceMetadata } from '../../src/host/collectors/evidence-correlator.ts';
import { createHistoryService } from '../../src/host/service/history-service.ts';
import type { Observation } from '../../src/shared/protocol/generated.ts';
import { MemoryKeyProvider, SegmentStore } from '../../src/storage/index.ts';

const NOW = 1_700_000_200_000;

async function makeTempDir(t: TestContext): Promise<string> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'camcp-host-')));
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  return dir;
}

function makeCorrelatedObservation(
  kind: 'surface' | 'selection' | 'input' | 'text',
  seq: number,
  eventTimeMs = NOW + seq * 10,
  monotonicMs = seq * 10,
): Observation {
  const gate = { secure: 'safe', privateState: 'normal', policyRevision: 1 } as const;
  const base = {
    protocolVersion: 1 as const,
    type: 'observation' as const,
    eventId: `run-1:${seq}`,
    instanceId: 'run-1',
    seq,
    eventTimeMs,
    monotonicMs,
    target: {
      kind: 'resolved' as const,
      identity: {
        deviceId: 'dev-1',
        osSessionId: 'audit-1',
        desktopId: 'console-audit-1',
        processId: 999,
        processStartTime: 'unix-ms:1700000000000.000',
        applicationId: 'com.google.antigravity-ide',
        windowId: 'win-1|pipe',
        windowGeneration: 1,
      },
    },
    stamp: {
      captureEpoch: 1,
      focusGeneration: 1,
      foregroundGeneration: 1,
      policyRevision: 1,
    },
    actor: 'unknown' as const,
    relatedActionIds: [],
  };

  if (kind === 'surface') {
    return {
      ...base,
      payload: {
        kind: 'surface.snapshot',
        snapshotId: `s-${seq}`,
        surfaceId: 'surf-1',
        revision: seq,
        source: 'ax.tree',
        scope: 'window',
        mode: 'full',
        nodes: [{ id: 'n1', role: 'text', text: 'never-cached-in-correlator', observedAtMs: eventTimeMs }],
        captureStartMs: eventTimeMs,
        captureEndMs: eventTimeMs,
        gate,
        coverage: { status: 'complete', truncated: false, missingReasons: [] },
        consistency: 'non-atomic',
      },
    };
  }
  if (kind === 'selection') {
    return {
      ...base,
      payload: {
        kind: 'selection.snapshot',
        snapshotId: `sel-${seq}`,
        surfaceId: 'surf-1',
        source: 'ax.range',
        scope: 'selection',
        text: 'selected',
        range: { unit: 'utf16', start: 0, length: 8 },
        captureStartMs: eventTimeMs,
        captureEndMs: eventTimeMs,
        gate,
        coverage: { status: 'partial', truncated: false, missingReasons: ['selection-only'] },
      },
    };
  }
  if (kind === 'input') {
    return {
      ...base,
      payload: {
        kind: 'input.text',
        source: 'cg.unicode',
        scope: 'field',
        eventKind: 'text',
        text: 'typed',
        modifiers: [],
        intervalStartMs: eventTimeMs,
        intervalEndMs: eventTimeMs,
        eventCount: 1,
        surfaceId: 'surf-1',
        gate,
        secureInput: 'inactive',
        coverage: { status: 'partial', truncated: false, missingReasons: ['input-events-partial', 'effect-unverified'] },
        effect: 'unverified',
      },
    };
  }
  return {
    ...base,
    payload: {
      kind: 'text.snapshot',
      snapshotId: `txt-${seq}`,
      editSessionId: 'edit-1',
      nodeId: 'node-1',
      source: 'ax.value',
      scope: 'field',
      valueState: 'read',
      text: 'focused-text',
      range: { unit: 'utf16', start: 0, length: 12 },
      totalLength: 12,
      composition: 'unknown',
      captureStartMs: eventTimeMs,
      captureEndMs: eventTimeMs,
      gate,
      coverage: { status: 'complete', truncated: false, missingReasons: [] },
    },
  };
}

test('EvidenceCorrelator uses typed struct fields, preserves across same-window text, and retains zero body text', () => {
  const correlator = new EvidenceCorrelator();
  const inputObs = makeCorrelatedObservation('input', 1);
  const meta = evidenceMetadata(inputObs);
  assert.ok(meta);
  assert.equal(meta.context.applicationId, 'com.google.antigravity-ide');
  assert.equal(meta.context.surfaceId, 'surf-1');

  correlator.commit(inputObs);
  // Interleaved legacy focused text on the same resolved window preserves prior input seed.
  correlator.commit(makeCorrelatedObservation('text', 2));

  const linkedSurface = correlator.preview(makeCorrelatedObservation('surface', 3));
  assert.deepEqual(linkedSurface.relation, {
    basis: 'temporal-same-surface',
    evidenceIds: ['run-1:1'],
    effect: 'unverified',
  });
  correlator.commit(linkedSurface);

  const serialized = JSON.stringify(correlator);
  assert.equal(serialized.includes('never-cached-in-correlator'), false);
  assert.equal(serialized.includes('typed'), false);
});

test('CollectorDebugLog stays completely off unless enabled and writes rotating JSONL when enabled', async (t) => {
  const base = await makeTempDir(t);
  const disabledDir = join(base, 'disabled-log');
  const offLog = new CollectorDebugLog(disabledDir, false);
  await offLog.prepare();
  offLog.append({ timeMs: NOW, event: 'ignored' });
  await offLog.flush();
  await offLog.close();
  await assert.rejects(lstat(disabledDir), { code: 'ENOENT' });

  const enabledDir = join(base, 'enabled-log');
  const onLog = new CollectorDebugLog(enabledDir, true);
  await onLog.prepare();
  onLog.append({ timeMs: NOW, runId: 'run-42', event: 'collection-start', detail: { ok: true } });
  await onLog.flush();
  await onLog.close();

  const files = await readdir(enabledDir);
  assert.deepEqual(files, ['trace-0.jsonl']);
  const content = JSON.parse((await readFile(join(enabledDir, 'trace-0.jsonl'), 'utf8')).trim());
  assert.equal(content.event, 'collection-start');
  assert.equal(content.runId, 'run-42');
});

test('HistoryService exposes built-in adapters, defaults debugTrace to false, and implements HistoryServiceContract', async (t) => {
  const base = await makeTempDir(t);
  const dataRoot = join(base, 'service-data');
  const keyProvider = new MemoryKeyProvider();

  const service = createHistoryService({
    dataRoot,
    deviceId: 'dev-1',
    keyProvider,
  });

  try {
    const initial = await service.status();
    assert.equal(initial.state, 'not-initialized');

    // reloadCollector on not-initialized service must not touch keys or start capture.
    const reloadedUninit = await service.reloadCollector();
    assert.equal(reloadedUninit.state, 'not-initialized');
    assert.equal(reloadedUninit.storage, null);
    assert.equal(reloadedUninit.collector, null);
    assert.deepEqual(
      initial.adapters.map((a) => a.id),
      ['generic', 'vscode-family', 'browser-family', 'terminal-family', 'qq', 'feishu', 'wechat', 'slack', 'typora', 'figma'],
    );
    assert.deepEqual(
      initial.adapters.find((a) => a.id === 'wechat')?.bundleIds,
      ['com.tencent.xinWeChat', 'wechat.exe', 'weixin.exe'],
    );
    assert.deepEqual(
      initial.adapters.find((a) => a.id === 'slack')?.bundleIds,
      ['com.tinyspeck.slackmacgap', 'slack.exe', '91750d7e.slack'],
    );
    assert.deepEqual(
      initial.adapters.find((a) => a.id === 'typora')?.bundleIds,
      ['abnerworks.Typora', 'typora.exe'],
    );
    assert.deepEqual(
      initial.adapters.find((a) => a.id === 'figma')?.bundleIds,
      ['com.figma.Desktop', 'figma.exe'],
    );
    assert.equal(initial.adapters.find((a) => a.id === 'figma')?.mode, 'custom');
    assert.deepEqual(
      initial.adapters.find((a) => a.id === 'qq')?.bundleIds,
      ['com.tencent.qq', 'qq.exe'],
    );
    assert.deepEqual(
      initial.adapters.find((a) => a.id === 'feishu')?.bundleIds,
      ['com.electron.lark', 'com.bytedance.feishu', 'feishu.exe', 'lark.exe'],
    );
    for (const id of ['com.google.antigravity', 'com.google.antigravity-ide', 'antigravity.exe', 'code.exe', 'cursor.exe']) {
      assert.ok(
        initial.adapters.find((a) => a.id === 'vscode-family')?.bundleIds.includes(id),
        `expected vscode-family to include ${id}`,
      );
    }
    for (const id of ['com.google.Chrome', 'chrome.exe', 'msedge.exe', 'firefox.exe']) {
      assert.ok(
        initial.adapters.find((a) => a.id === 'browser-family')?.bundleIds.includes(id),
        `expected browser-family to include ${id}`,
      );
    }
    for (const id of ['com.apple.Terminal', 'windowsterminal.exe', 'wt.exe']) {
      assert.ok(
        initial.adapters.find((a) => a.id === 'terminal-family')?.bundleIds.includes(id),
        `expected terminal-family to include ${id}`,
      );
    }

    const initialized = await service.initializeKey();
    assert.equal(initialized.state, 'stopped');
    assert.equal(initialized.storage?.records, 0);
    // reloadCollector on stopped service keeps state stopped and never starts capture.
    const reloadedStopped = await service.reloadCollector();
    assert.equal(reloadedStopped.state, 'stopped');
    assert.equal(reloadedStopped.collector, null);
    // Default debugTrace=false creates no debug-log directory.
    await assert.rejects(lstat(join(dataRoot, 'debug-log')), { code: 'ENOENT' });
    await service.close();

    // Seed one recent surface record via SegmentStore, then reopen HistoryService and query via contract.
    const recentNow = Date.now();
    const seededStore = await SegmentStore.open({ root: dataRoot, keyProvider, clock: () => recentNow });
    await seededStore.append(makeCorrelatedObservation('surface', 1, recentNow));
    await seededStore.close();

    const reopenedService = createHistoryService({
      dataRoot,
      deviceId: 'dev-1',
      keyProvider,
    });
    try {
      const searchRes = await reopenedService.search({ applicationId: 'com.google.antigravity-ide' });
      assert.equal(searchRes.records.length, 1);

      const readRes = await reopenedService.read('s-1');
      assert.equal(readRes.found, true);
      assert.equal(readRes.record?.eventId, 'run-1:1');

      const layoutRes = await reopenedService.layout({ snapshotId: 's-1' });
      assert.equal(layoutRes.found, true);

      const forgetRes = await reopenedService.forget({ all: true });
      assert.equal(forgetRes.deletedSegments, 1);
      assert.equal(forgetRes.remainingRecords, 0);
    } finally {
      await reopenedService.close();
    }

    // Reopening without explicit deviceId reuses persisted device.id instead of fluctuating OS hostname.
    const autoDeviceService = createHistoryService({
      dataRoot,
      keyProvider,
    });
    try {
      const autoStatus = await autoDeviceService.status();
      assert.equal(autoStatus.deviceId, 'dev-1');
    } finally {
      await autoDeviceService.close();
    }
  } finally {
    await service.close();
  }
});

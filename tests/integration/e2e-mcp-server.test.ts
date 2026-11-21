import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PassThrough, Writable } from 'node:stream';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { target } from '../../fixtures/contract/examples.ts';
import type { ManagedProcess, SpawnManaged } from '../../src/host/collectors/process.ts';
import { createHistoryService } from '../../src/host/service/history-service.ts';
import { startHttpServer } from '../../src/server/http-server.ts';
import { runStdioProxy } from '../../src/server/stdio-proxy.ts';
import type { CreateLeaseResponse } from '../../src/shared/api-types.ts';
import type { Observation, WireMessage } from '../../src/shared/protocol/generated.ts';
import { encodeFrame, FrameDecoder } from '../../src/shared/protocol/validate.ts';
import { MemoryKeyProvider } from '../../src/storage/key-provider.ts';
import { SegmentStore } from '../../src/storage/segment-store.ts';

const REPO_ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));

async function mcpRequest(mcpUrl: string, token: string, payload: unknown): Promise<Response> {
  return await fetch(mcpUrl, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });
}

function parseMcpToolJson<T = Record<string, unknown>>(rpcBody: unknown): T {
  const obj = rpcBody as { result?: { content?: Array<{ type: string; text: string }>; isError?: boolean } };
  assert.ok(obj.result, `Expected JSON-RPC result, received: ${JSON.stringify(rpcBody)}`);
  assert.notEqual(obj.result.isError, true, `Unexpected tool error: ${JSON.stringify(obj.result)}`);
  const text = obj.result.content?.[0]?.text;
  assert.equal(typeof text, 'string');
  return JSON.parse(text!) as T;
}

test('E2E HTTP server + MemoryKeyProvider + SegmentStore + Web UI + MCP HTTP & stdio-proxy', async (t) => {
  const tempRoot = await realpath(await mkdtemp(join(tmpdir(), 'camcp-e2e-')));
  t.after(async () => {
    await rm(tempRoot, { recursive: true, force: true });
  });

  const dataDir = join(tempRoot, 'data');
  const binDir = join(tempRoot, 'native-bin');
  await mkdir(binDir, { recursive: true, mode: 0o700 });

  // Prepare verified synthetic collector executable + schema bundle manifest for HistoryService.
  const collectorPath = join(binDir, 'computer-access-collector');
  const collectorStub = 'synthetic-e2e-collector-binary';
  await writeFile(collectorPath, collectorStub, { mode: 0o700 });
  const bundleSchemaRel = 'AccessContract_AccessContract.bundle/Contents/Resources/wire.schema.json';
  await mkdir(join(binDir, 'AccessContract_AccessContract.bundle/Contents/Resources'), { recursive: true });
  const schemaBytes = await readFile(join(REPO_ROOT, 'src/shared/protocol/wire.schema.json'));
  await writeFile(join(binDir, bundleSchemaRel), schemaBytes, { mode: 0o600 });
  const sha256 = (data: Buffer | string) => createHash('sha256').update(data).digest('hex');
  await writeFile(
    join(binDir, 'manifest.json'),
    JSON.stringify({
      version: 1,
      platform: process.platform,
      arch: process.arch,
      files: {
        'computer-access-collector': { sha256: sha256(collectorStub) },
        [bundleSchemaRel]: { sha256: sha256(schemaBytes) },
      },
    }),
    { mode: 0o600 },
  );

  let emitSyntheticEvidence: (() => void) | undefined;
  let collectorSpawnCount = 0;

  const spawn: SpawnManaged = (spec) => {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    let finishExit!: (res: { exitCode: number | null; signal: NodeJS.Signals | null }) => void;
    const done = new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>((resolveDone) => {
      finishExit = resolveDone;
    });

    if (spec.argv[1] === '--permissions') {
      const stdin = new Writable({
        write(_c, _e, cb) {
          cb();
        },
        final(cb) {
          stdout.end(
            JSON.stringify({
              version: 1,
              action: spec.argv[2],
              accessibility: 'granted',
              desktop: {
                status: 'unlocked',
                reason: 'ready',
                sessionAvailable: true,
                onConsole: true,
                loginDone: true,
                screenLocked: false,
                sessionMatchesProcess: true,
                sessionStable: true,
                signalsValid: true,
                lockTransition: false,
              },
              screenRecording: 'not-required',
              promptRequested: false,
              settingsOpened: false,
              captured: false,
              inputMonitoring: { state: 'granted', promptRequested: false, settingsOpened: false },
            }),
          );
          stderr.end();
          finishExit({ exitCode: 0, signal: null });
          cb();
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
          finishExit({ exitCode: 0, signal: null });
        },
        async waitForExit() {
          await done;
          return true;
        },
      };
    }

    collectorSpawnCount += 1;
    const decoder = new FrameDecoder();
    const instanceId = spec.argv[spec.argv.indexOf('--instance-id') + 1] ?? '';
    const ownerId = spec.argv[spec.argv.indexOf('--owner-id') + 1] ?? '';
    let policyRevision = 1;
    let captureEpoch = 1;
    let seq = 0;

    const send = (msg: WireMessage) => stdout.write(encodeFrame(msg));
    const currentStamp = () => ({
      captureEpoch,
      focusGeneration: 1,
      foregroundGeneration: 1,
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
          { name: 'text.snapshot', support: 'supported', direction: 'observe', scope: 'app-local', reason: '' },
          { name: 'surface.snapshot', support: 'supported', direction: 'observe', scope: 'app-local', reason: '' },
          { name: 'selection.snapshot', support: 'supported', direction: 'observe', scope: 'app-local', reason: '' },
          { name: 'input.text', support: 'supported', direction: 'observe', scope: 'app-local', reason: '' },
          { name: 'input.activity', support: 'supported', direction: 'observe', scope: 'authorized-desktop', reason: '' },
          { name: 'text.visible-range', support: 'supported', direction: 'observe', scope: 'app-local', reason: '' },
          { name: 'ax.enablement', support: 'supported', direction: 'observe', scope: 'app-local', reason: '' },
          { name: 'text.marker', support: 'supported', direction: 'observe', scope: 'app-local', reason: '' },
          { name: 'field.denylist', support: 'supported', direction: 'observe', scope: 'app-local', reason: '' },
        ],
      });
    });

    emitSyntheticEvidence = () => {
      const now = Date.now();
      const appIdentity = {
        ...target,
        deviceId: 'e2e-local-device',
        applicationId: 'com.google.antigravity-ide',
      };
      const gate = { secure: 'safe' as const, privateState: 'normal' as const, policyRevision };

      const sendObs = (payload: Observation['payload'], offsetMs: number) => {
        const nextSeq = ++seq;
        send({
          protocolVersion: 1,
          type: 'observation',
          eventId: `${instanceId}:${nextSeq}`,
          instanceId,
          seq: nextSeq,
          eventTimeMs: now + offsetMs,
          monotonicMs: 100 + offsetMs,
          target: { kind: 'resolved', identity: appIdentity },
          stamp: currentStamp(),
          actor: 'unknown',
          relatedActionIds: [],
          payload,
        });
      };

      sendObs({ kind: 'context.changed', reason: 'focus' }, 1);
      sendObs(
        {
          kind: 'text.snapshot',
          snapshotId: 'e2e-text-snap-1',
          editSessionId: 'edit-1',
          nodeId: 'editor-main',
          source: 'ax.range',
          scope: 'field',
          valueState: 'read',
          text: 'Antigravity SegmentStore architecture notes',
          range: { unit: 'utf16', start: 0, length: 43 },
          totalLength: 43,
          composition: 'not-composing',
          captureStartMs: now + 2,
          captureEndMs: now + 2,
          gate,
          coverage: { status: 'complete', truncated: false, missingReasons: [] },
        },
        2,
      );
      sendObs(
        {
          kind: 'surface.snapshot',
          snapshotId: 'e2e-surface-snap-1',
          surfaceId: 'editor-surface-1',
          revision: 1,
          source: 'ax.tree',
          scope: 'window',
          mode: 'full',
          geometry: {
            coordinateSpace: 'window-top-left-point',
            windowSize: { width: 1280, height: 800 },
            observedAtMs: now + 3,
          },
          nodes: [
            { id: 'root', role: 'container', axRole: 'AXWindow', observedAtMs: now + 3 },
            {
              id: 'pane-1',
              parentId: 'root',
              role: 'editable',
              axRole: 'AXTextArea',
              text: 'SegmentStore E2E layout content',
              focused: true,
              bounds: { x: 40, y: 60, width: 900, height: 640 },
              boundsObservedAtMs: now + 3,
              observedAtMs: now + 3,
            },
          ],
          captureStartMs: now + 3,
          captureEndMs: now + 3,
          gate,
          consistency: 'non-atomic',
          coverage: { status: 'complete', truncated: false, missingReasons: [] },
        },
        3,
      );
    };

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

  const keyProvider = new MemoryKeyProvider();
  const service = createHistoryService({
    dataRoot: dataDir,
    collectorPath,
    deviceId: 'e2e-local-device',
    keyProvider,
    spawn,
    platform: 'darwin',
  });

  const server = await startHttpServer({
    dataDir,
    host: '127.0.0.1',
    port: 0,
    pkgRoot: REPO_ROOT,
    webDistDir: join(REPO_ROOT, 'dist', 'web'),
    service,
  });

  try {
    // 1. Verify GET / serves the built Web UI HTML (and static JS/CSS bundles).
    const indexRes = await fetch(`${server.baseUrl}/`);
    assert.equal(indexRes.status, 200);
    assert.match(indexRes.headers.get('content-type') ?? '', /text\/html/);
    const indexHtml = await indexRes.text();
    assert.match(indexHtml, /<div id="root"><\/div>/);
    assert.match(indexHtml, /app\.js/);

    const appJsRes = await fetch(`${server.baseUrl}/app.js`);
    assert.equal(appJsRes.status, 200);
    assert.ok((await appJsRes.text()).length > 1000);

    // 2. Authenticate with Admin Token to initialize key + SegmentStore and start capture.
    const adminHeaders = {
      Authorization: `Bearer ${server.adminToken}`,
      'Content-Type': 'application/json',
      Origin: server.baseUrl,
    };

    const initKeyRes = await fetch(`${server.baseUrl}/api/key/init`, {
      method: 'POST',
      headers: adminHeaders,
      body: '{}',
    });
    assert.equal(initKeyRes.status, 200);
    const initStatus = (await initKeyRes.json()) as { state: string; storage: { state: string; records: number } };
    assert.equal(initStatus.state, 'stopped');
    assert.equal(initStatus.storage.state, 'open');

    const startRes = await fetch(`${server.baseUrl}/api/capture/start`, {
      method: 'POST',
      headers: adminHeaders,
      body: JSON.stringify({
        applicationScope: 'allowlist',
        allowedApplicationIds: ['com.google.antigravity-ide'],
        captureScope: 'window',
      }),
    });
    assert.equal(startRes.status, 200);
    assert.equal(((await startRes.json()) as { state: string }).state, 'running');

    assert.ok(emitSyntheticEvidence);
    emitSyntheticEvidence();

    // Wait for observations to land in SegmentStore.
    let storedCount = 0;
    for (let i = 0; i < 40 && storedCount < 3; i++) {
      await new Promise((r) => setTimeout(r, 15));
      storedCount = (await service.status()).storage?.records ?? 0;
    }
    assert.equal(storedCount, 3);

    // Confirm real AEAD SegmentStore files exist on disk with zero plaintext leakage.
    const diskEntries = await readdir(dataDir);
    assert.ok(diskEntries.includes('store.lock'));
    assert.ok(diskEntries.includes('store.meta'));
    assert.ok(diskEntries.includes('seg-00000001.cah'));
    const segBytes = await readFile(join(dataDir, 'seg-00000001.cah'));
    assert.equal(segBytes.includes(Buffer.from('Antigravity SegmentStore architecture notes')), false);
    assert.equal(segBytes.includes(Buffer.from('SegmentStore E2E layout content')), false);

    // Create a read-only Client Lease and a read+pause Client Lease via Admin API.
    const readLeaseRes = await fetch(`${server.baseUrl}/api/leases`, {
      method: 'POST',
      headers: adminHeaders,
      body: JSON.stringify({ label: 'antigravity-reader', scopes: ['read'], ttlMs: 3_600_000 }),
    });
    assert.equal(readLeaseRes.status, 201);
    const readLease = (await readLeaseRes.json()) as CreateLeaseResponse;
    assert.match(readLease.token, /^camcp_[0-9a-f]{64}$/);

    const pauseLeaseRes = await fetch(`${server.baseUrl}/api/leases`, {
      method: 'POST',
      headers: adminHeaders,
      body: JSON.stringify({ label: 'antigravity-guardian', scopes: ['read', 'pause'], ttlMs: null }),
    });
    assert.equal(pauseLeaseRes.status, 201);
    const pauseLease = (await pauseLeaseRes.json()) as CreateLeaseResponse;

    // 3. Connect via HTTP /mcp using read-only lease.
    const mcpInit = await (
      await mcpRequest(server.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-03-26',
          capabilities: {},
          clientInfo: { name: 'antigravity-e2e', version: '1.0.0' },
        },
      })
    ).json();
    assert.equal((mcpInit as { result: { serverInfo: { name: string } } }).result.serverInfo.name, 'computer-access-mcp');

    const readToolsList = (await (
      await mcpRequest(server.mcpUrl, readLease.token, { jsonrpc: '2.0', id: 2, method: 'tools/list' })
    ).json()) as { result: { tools: Array<{ name: string }> } };
    assert.deepEqual(
      readToolsList.result.tools.map((tool) => tool.name),
      ['history_status', 'history_search', 'history_read', 'history_layout', 'history_layout_guide'],
    );

    const statusTool = parseMcpToolJson<{ state: string; storage: { records: number } }>(
      await (
        await mcpRequest(server.mcpUrl, readLease.token, {
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: { name: 'history_status', arguments: {} },
        })
      ).json(),
    );
    assert.equal(statusTool.state, 'running');
    assert.equal(statusTool.storage.records, 3);

    const searchTool = parseMcpToolJson<{ records: Observation[] }>(
      await (
        await mcpRequest(server.mcpUrl, readLease.token, {
          jsonrpc: '2.0',
          id: 4,
          method: 'tools/call',
          params: { name: 'history_search', arguments: { text: 'architecture notes', kind: 'text' } },
        })
      ).json(),
    );
    assert.equal(searchTool.records.length, 1);
    const textEventId = searchTool.records[0]!.eventId;

    const readTool = parseMcpToolJson<{ found: boolean; record: Observation }>(
      await (
        await mcpRequest(server.mcpUrl, readLease.token, {
          jsonrpc: '2.0',
          id: 5,
          method: 'tools/call',
          params: { name: 'history_read', arguments: { id: textEventId } },
        })
      ).json(),
    );
    assert.equal(readTool.found, true);
    assert.equal(
      readTool.record.payload.kind === 'text.snapshot' ? readTool.record.payload.text : '',
      'Antigravity SegmentStore architecture notes',
    );

    const layoutTool = parseMcpToolJson<{
      found: boolean;
      windowSize: { width: number; height: number };
      nodes: Array<{ id: string; text: string | null; bounds: number[] | null }>;
    }>(
      await (
        await mcpRequest(server.mcpUrl, readLease.token, {
          jsonrpc: '2.0',
          id: 6,
          method: 'tools/call',
          params: { name: 'history_layout', arguments: { snapshotId: 'e2e-surface-snap-1' } },
        })
      ).json(),
    );
    assert.equal(layoutTool.found, true);
    assert.deepEqual(layoutTool.windowSize, { width: 1280, height: 800 });
    assert.equal(layoutTool.nodes[0]?.id, 'pane-1');
    assert.equal(layoutTool.nodes[0]?.text, 'SegmentStore E2E layout content');
    assert.deepEqual(layoutTool.nodes[0]?.bounds, [40, 60, 900, 640]);

    // Scope enforcement: read-only lease is denied history_pause (-32003) and history_reload (-32003).
    const deniedPause = (await (
      await mcpRequest(server.mcpUrl, readLease.token, {
        jsonrpc: '2.0',
        id: 7,
        method: 'tools/call',
        params: { name: 'history_pause', arguments: {} },
      })
    ).json()) as { error?: { code: number } };
    assert.equal(deniedPause.error?.code, -32003);
    assert.equal((await service.status()).state, 'running');

    for (const token of [readLease.token, pauseLease.token]) {
      const deniedReload = (await (
        await mcpRequest(server.mcpUrl, token, {
          jsonrpc: '2.0',
          id: 70,
          method: 'tools/call',
          params: { name: 'history_reload', arguments: { mode: 'collector' } },
        })
      ).json()) as { error?: { code: number } };
      assert.equal(deniedReload.error?.code, -32003);
    }

    // Opt-in reload lease hot-reloads the running collector without widening activeScope.
    const reloadLeaseRes = await fetch(`${server.baseUrl}/api/leases`, {
      method: 'POST',
      headers: adminHeaders,
      body: JSON.stringify({ label: 'antigravity-reloader', scopes: ['read', 'reload'], ttlMs: null }),
    });
    assert.equal(reloadLeaseRes.status, 201);
    const reloadLease = (await reloadLeaseRes.json()) as CreateLeaseResponse;

    const spawnsBeforeReload = collectorSpawnCount;
    const reloadWhileRunning = parseMcpToolJson<{
      ok: boolean;
      mode: string;
      restarted: boolean;
      resumed: boolean;
      status: { state: string; activeScope: { allowedApplicationIds: string[] } };
    }>(
      await (
        await mcpRequest(server.mcpUrl, reloadLease.token, {
          jsonrpc: '2.0',
          id: 71,
          method: 'tools/call',
          params: { name: 'history_reload', arguments: { mode: 'collector' } },
        })
      ).json(),
    );
    assert.equal(reloadWhileRunning.ok, true);
    assert.equal(reloadWhileRunning.mode, 'collector');
    assert.equal(reloadWhileRunning.restarted, true);
    assert.equal(reloadWhileRunning.resumed, true);
    assert.equal(reloadWhileRunning.status.state, 'running');
    assert.deepEqual(reloadWhileRunning.status.activeScope.allowedApplicationIds, ['com.google.antigravity-ide']);
    assert.equal(collectorSpawnCount, spawnsBeforeReload + 1);

    // 4. Connect via stdio-proxy using read+pause lease to verify tools/list and history_pause.
    const proxyIn = new PassThrough();
    const proxyOut = new PassThrough();
    const proxyErr = new PassThrough();
    let stdoutText = '';
    proxyOut.on('data', (chunk: Buffer) => {
      stdoutText += chunk.toString('utf8');
    });

    const proxyPromise = runStdioProxy({
      url: server.mcpUrl,
      env: { COMPUTER_ACCESS_TOKEN: pauseLease.token },
      input: proxyIn,
      output: proxyOut,
      errorOutput: proxyErr,
    });

    proxyIn.write(JSON.stringify({ jsonrpc: '2.0', id: 101, method: 'tools/list' }) + '\n');
    proxyIn.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 102,
        method: 'tools/call',
        params: { name: 'history_pause', arguments: {} },
      }) + '\n',
    );
    proxyIn.end();
    await proxyPromise;

    const proxyLines = stdoutText
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    assert.equal(proxyLines.length, 2);
    const pauseToolsList = (proxyLines[0] as { result: { tools: Array<{ name: string }> } }).result.tools.map(
      (tool) => tool.name,
    );
    assert.deepEqual(pauseToolsList, [
      'history_status',
      'history_search',
      'history_read',
      'history_layout',
      'history_layout_guide',
      'history_pause',
    ]);
    const pausedResult = parseMcpToolJson<{ state: string; reason: string }>(proxyLines[1]);
    assert.equal(pausedResult.state, 'paused');
    assert.equal(pausedResult.reason, 'user-paused');
    assert.equal((await service.status()).state, 'paused');

    // Calling history_reload while paused stops the retiring collector and NEVER resumes capture.
    const spawnsWhilePaused = collectorSpawnCount;
    const reloadWhilePaused = parseMcpToolJson<{
      ok: boolean;
      mode: string;
      restarted: boolean;
      resumed: boolean;
      status: { state: string };
    }>(
      await (
        await mcpRequest(server.mcpUrl, reloadLease.token, {
          jsonrpc: '2.0',
          id: 103,
          method: 'tools/call',
          params: { name: 'history_reload', arguments: { mode: 'collector' } },
        })
      ).json(),
    );
    assert.equal(reloadWhilePaused.ok, true);
    assert.equal(reloadWhilePaused.resumed, false);
    assert.equal(reloadWhilePaused.status.state, 'stopped');
    assert.equal(collectorSpawnCount, spawnsWhilePaused);

    // 5. Revoke all leases via DELETE /api/leases/:id and verify immediate HTTP 401 on /mcp.
    for (const lease of [readLease, pauseLease, reloadLease]) {
      const delRes = await fetch(`${server.baseUrl}/api/leases/${encodeURIComponent(lease.lease.id)}`, {
        method: 'DELETE',
        headers: adminHeaders,
      });
      assert.equal(delRes.status, 200);

      const postRevoke = await mcpRequest(server.mcpUrl, lease.token, {
        jsonrpc: '2.0',
        id: 999,
        method: 'ping',
      });
      assert.equal(postRevoke.status, 401);
    }
  } finally {
    await server.close();
  }

  // Reopen SegmentStore directly after server shutdown to confirm persisted records remain intact.
  const reopened = await SegmentStore.open({ root: dataDir, keyProvider });
  try {
    assert.equal(reopened.status().records, 3);
    const persisted = await reopened.read('e2e-surface-snap-1');
    assert.equal(persisted?.payload.kind, 'surface.snapshot');
  } finally {
    await reopened.close();
    await keyProvider.deleteKey();
  }
});

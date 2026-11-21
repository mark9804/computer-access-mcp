import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { lstat, mkdtemp, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { createServer as createNetServer } from 'node:net';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { AuthStore } from '../../src/server/auth-store.ts';
import {
  consumeRestartResume,
  RESTART_EXIT_CODE,
  RESTART_RESUME_FILENAME,
  runCli,
  writeRestartResume,
} from '../../src/server/cli.ts';
import { startHttpServer } from '../../src/server/http-server.ts';
import { MAX_MCP_TOOL_OUTPUT_BYTES, UNTRUSTED_EVIDENCE_NOTE } from '../../src/server/mcp-handler.ts';
import { runStdioProxy } from '../../src/server/stdio-proxy.ts';
import {
  createMockHistoryService,
  makeSampleSurfaceSnapshot,
  makeSampleTextSnapshot,
} from './mock-service.ts';

const REPO_ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));

async function mcpPost(mcpUrl: string, token: string | null, body: unknown): Promise<Response> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  if (token !== null) {
    headers.Authorization = `Bearer ${token}`;
  }
  return await fetch(mcpUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
}

test('MCP HTTP endpoint enforces client lease scopes, protocol versions, and immediate revocation', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'camcp-mcp-test-'));
  let nowMs = 1_700_000_000_000;
  const authStore = await AuthStore.open({ dataDir: dir, now: () => nowMs });
  const mockService = createMockHistoryService(dir);
  await mockService.initializeKey();
  await mockService.start({});
  mockService.seedObservation(makeSampleTextSnapshot('evt_alpha', 'Design notes on segment storage'));
  mockService.seedObservation(makeSampleSurfaceSnapshot('evt_surface_alpha', 'snap_alpha', 'Main Editor Pane'));

  const srv = await startHttpServer({
    dataDir: dir,
    port: 0,
    authStore,
    service: mockService,
  });

  try {
    // Missing token and Admin token must both return 401 on /mcp.
    assert.equal((await mcpPost(srv.mcpUrl, null, { jsonrpc: '2.0', id: 1, method: 'ping' })).status, 401);
    assert.equal((await mcpPost(srv.mcpUrl, srv.adminToken, { jsonrpc: '2.0', id: 1, method: 'ping' })).status, 401);

    const readOnly = await authStore.createLease({ label: 'reader', scopes: ['read'], ttlMs: 30_000 });
    const readPause = await authStore.createLease({
      label: 'guardian',
      scopes: ['read', 'pause'],
      ttlMs: null,
    });

    // Protocol version negotiation: 2025-03-26 and 2024-11-05.
    for (const version of ['2025-03-26', '2024-11-05']) {
      const initRes = await mcpPost(srv.mcpUrl, readOnly.token, {
        jsonrpc: '2.0',
        id: `init-${version}`,
        method: 'initialize',
        params: { protocolVersion: version, capabilities: {}, clientInfo: { name: 'test', version: '1.0' } },
      });
      assert.equal(initRes.status, 200);
      const initBody = (await initRes.json()) as {
        result: {
          protocolVersion: string;
          serverInfo: { name: string; version: string };
          capabilities: { tools: object; resources: object };
          instructions?: string;
        };
      };
      assert.equal(initBody.result.protocolVersion, version);
      assert.equal(initBody.result.serverInfo.name, 'computer-access-mcp');
      assert.equal(initBody.result.serverInfo.version, '0.2.0');
      assert.deepEqual(initBody.result.capabilities, { tools: {}, resources: {} });
      assert.equal(typeof initBody.result.instructions, 'string');
      assert.ok(initBody.result.instructions?.includes('history_layout_guide'));
    }

    // Notification returns 202 Accepted with empty body.
    const notifRes = await mcpPost(srv.mcpUrl, readOnly.token, {
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    });
    assert.equal(notifRes.status, 202);
    assert.equal(await notifRes.text(), '');

    // Batch request mixing requests and notification.
    const batchRes = await mcpPost(srv.mcpUrl, readOnly.token, [
      { jsonrpc: '2.0', id: 10, method: 'ping' },
      { jsonrpc: '2.0', method: 'notifications/initialized' },
      { jsonrpc: '2.0', id: 11, method: 'tools/list' },
    ]);
    assert.equal(batchRes.status, 200);
    const batchJson = (await batchRes.json()) as Array<{ id: number; result: Record<string, unknown> }>;
    assert.equal(batchJson.length, 2);
    assert.equal(batchJson[0]?.id, 10);
    assert.equal(batchJson[1]?.id, 11);

    // Scope filtering on tools/list: readOnly vs read+pause.
    const readTools = (batchJson[1]?.result.tools as Array<{ name: string }>).map((t) => t.name);
    assert.deepEqual(readTools, [
      'history_status',
      'history_search',
      'history_read',
      'history_layout',
      'history_layout_guide',
    ]);

    const fullToolsRes = (await (
      await mcpPost(srv.mcpUrl, readPause.token, { jsonrpc: '2.0', id: 12, method: 'tools/list' })
    ).json()) as { result: { tools: Array<{ name: string }> } };
    assert.deepEqual(
      fullToolsRes.result.tools.map((t) => t.name),
      [
        'history_status',
        'history_search',
        'history_read',
        'history_layout',
        'history_layout_guide',
        'history_pause',
      ],
    );

    // Execute all 4 read tools with readOnly token.
    const statusCall = (await (
      await mcpPost(srv.mcpUrl, readOnly.token, {
        jsonrpc: '2.0',
        id: 20,
        method: 'tools/call',
        params: { name: 'history_status', arguments: {} },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const statusPayload = JSON.parse(statusCall.result.content[0]?.text ?? '{}') as {
      state: string;
      safetyNote: string;
    };
    assert.equal(statusPayload.state, 'running');
    assert.equal(statusPayload.safetyNote, UNTRUSTED_EVIDENCE_NOTE);

    const searchCall = (await (
      await mcpPost(srv.mcpUrl, readOnly.token, {
        jsonrpc: '2.0',
        id: 21,
        method: 'tools/call',
        params: { name: 'history_search', arguments: { text: 'segment', kind: 'text' } },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const searchPayload = JSON.parse(searchCall.result.content[0]?.text ?? '{}') as {
      records: Array<{ eventId: string }>;
    };
    assert.equal(searchPayload.records.length, 1);
    assert.equal(searchPayload.records[0]?.eventId, 'evt_alpha');

    const readCall = (await (
      await mcpPost(srv.mcpUrl, readOnly.token, {
        jsonrpc: '2.0',
        id: 22,
        method: 'tools/call',
        params: { name: 'history_read', arguments: { id: 'evt_alpha' } },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const readPayload = JSON.parse(readCall.result.content[0]?.text ?? '{}') as { found: boolean };
    assert.equal(readPayload.found, true);

    const layoutCall = (await (
      await mcpPost(srv.mcpUrl, readOnly.token, {
        jsonrpc: '2.0',
        id: 23,
        method: 'tools/call',
        params: { name: 'history_layout', arguments: { snapshotId: 'snap_alpha', nodeIds: ['n1'] } },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const layoutPayload = JSON.parse(layoutCall.result.content[0]?.text ?? '{}') as {
      found: boolean;
      nodes: Array<{ id: string; text: string }>;
    };
    assert.equal(layoutPayload.found, true);
    assert.equal(layoutPayload.nodes.length, 1);
    assert.equal(layoutPayload.nodes[0]?.text, 'Main Editor Pane');

    // Read-only lease attempting history_pause MUST be denied.
    const deniedPause = (await (
      await mcpPost(srv.mcpUrl, readOnly.token, {
        jsonrpc: '2.0',
        id: 24,
        method: 'tools/call',
        params: { name: 'history_pause', arguments: {} },
      })
    ).json()) as { error?: { code: number; message: string } };
    assert.ok(deniedPause.error);
    assert.equal(deniedPause.error.code, -32003);

    // Neither read-only nor read+pause leases may invoke history_reload (-32003).
    for (const token of [readOnly.token, readPause.token]) {
      const deniedReload = (await (
        await mcpPost(srv.mcpUrl, token, {
          jsonrpc: '2.0',
          id: 240,
          method: 'tools/call',
          params: { name: 'history_reload', arguments: {} },
        })
      ).json()) as { error?: { code: number; message: string } };
      assert.ok(deniedReload.error);
      assert.equal(deniedReload.error.code, -32003);
    }

    // Lease with pause scope succeeds on history_pause.
    const allowedPause = (await (
      await mcpPost(srv.mcpUrl, readPause.token, {
        jsonrpc: '2.0',
        id: 25,
        method: 'tools/call',
        params: { name: 'history_pause', arguments: {} },
      })
    ).json()) as { result: { content: Array<{ text: string }> } };
    const pausePayload = JSON.parse(allowedPause.result.content[0]?.text ?? '{}') as { state: string };
    assert.equal(pausePayload.state, 'paused');

    // Expiry returns 401.
    nowMs += 31_000;
    assert.equal((await mcpPost(srv.mcpUrl, readOnly.token, { jsonrpc: '2.0', id: 26, method: 'ping' })).status, 401);

    // Revocation via DELETE /api/leases/:id immediately yields 401 on /mcp.
    const delRes = await fetch(`${srv.baseUrl}/api/leases/${readPause.lease.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${srv.adminToken}` },
    });
    assert.equal(delRes.status, 200);
    assert.equal((await mcpPost(srv.mcpUrl, readPause.token, { jsonrpc: '2.0', id: 27, method: 'ping' })).status, 401);
  } finally {
    await srv.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('MCP tools/call strictly enforces 64 KiB (65536 UTF-8 bytes) output ceiling without splitting Unicode', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'camcp-mcp-cap-'));
  const mockService = createMockHistoryService(dir);
  await mockService.initializeKey();

  // Single oversized record (>120 KB UTF-8 with astral plane surrogate pairs \u{20BB7} and CJK).
  const astralRepeat = '\u{20BB7}\u4E2D\u6587ABC'.repeat(12_000);
  mockService.seedObservation(makeSampleTextSnapshot('evt_huge', astralRepeat));

  // Many medium records whose combined search response exceeds 64 KiB.
  for (let i = 0; i < 45; i += 1) {
    mockService.seedObservation(
      makeSampleTextSnapshot(`evt_bulk_${i}`, `bulk-match-${i}-${'X'.repeat(2400)}`, 'com.test.app', 1_700_000_100_000 + i),
    );
  }

  const srv = await startHttpServer({ dataDir: dir, port: 0, service: mockService });

  try {
    const { token } = await srv.authStore.createLease({ label: 'cap-test', scopes: ['read'], ttlMs: null });

    // 1) Oversized single history_read result capped <= 65536 bytes.
    const readRes = await mcpPost(srv.mcpUrl, token, {
      jsonrpc: '2.0',
      id: 'read-huge-1',
      method: 'tools/call',
      params: { name: 'history_read', arguments: { id: 'evt_huge' } },
    });
    assert.equal(readRes.status, 200);
    const rawReadText = await readRes.text();
    const readBytes = Buffer.byteLength(rawReadText, 'utf8');
    assert.ok(readBytes <= MAX_MCP_TOOL_OUTPUT_BYTES, `Expected <= 65536 bytes, got ${readBytes}`);
    assert.equal(rawReadText.isWellFormed(), true);

    const parsedReadRpc = JSON.parse(rawReadText) as { result: { content: Array<{ text: string }> } };
    const innerRead = JSON.parse(parsedReadRpc.result.content[0]?.text ?? '{}') as {
      truncated: boolean;
      preview: string;
    };
    assert.equal(innerRead.truncated, true);
    assert.equal(innerRead.preview.isWellFormed(), true);

    // 2) Oversized multi-record history_search result trims trailing records to fit <= 65536 bytes.
    const searchRes = await mcpPost(srv.mcpUrl, token, {
      jsonrpc: '2.0',
      id: 'search-bulk-1',
      method: 'tools/call',
      params: { name: 'history_search', arguments: { text: 'bulk-match-', limit: 45 } },
    });
    assert.equal(searchRes.status, 200);
    const rawSearchText = await searchRes.text();
    const searchBytes = Buffer.byteLength(rawSearchText, 'utf8');
    assert.ok(searchBytes <= MAX_MCP_TOOL_OUTPUT_BYTES, `Expected <= 65536 bytes, got ${searchBytes}`);

    const parsedSearchRpc = JSON.parse(rawSearchText) as { result: { content: Array<{ text: string }> } };
    const innerSearch = JSON.parse(parsedSearchRpc.result.content[0]?.text ?? '{}') as {
      records: unknown[];
      truncated: boolean;
      hasMore: boolean;
    };
    assert.equal(innerSearch.truncated, true);
    assert.equal(innerSearch.hasMore, true);
    assert.ok(innerSearch.records.length > 0 && innerSearch.records.length < 45);
  } finally {
    await srv.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('stdio-proxy and CLI serve/stdio complete live round-trip over ephemeral-port http-server', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'camcp-stdio-test-'));
  const mockService = createMockHistoryService(dir);
  await mockService.initializeKey();
  mockService.seedObservation(makeSampleTextSnapshot('evt_stdio_1', 'Terminal workflow captured'));

  const abortController = new AbortController();
  const serveOut = new PassThrough();
  let bannerText = '';

  const servePromise = runCli(['serve', '--port', '0', '--data-dir', dir], {
    stdout: serveOut,
    stderr: new PassThrough(),
    signal: abortController.signal,
    createService: () => mockService,
  });

  // Wait for startup banner containing Web UI token URL and MCP HTTP URL.
  const { baseUrl, adminToken, mcpUrl } = await new Promise<{
    baseUrl: string;
    adminToken: string;
    mcpUrl: string;
  }>((resolveBanner, rejectBanner) => {
    const timeout = setTimeout(() => rejectBanner(new Error(`Timed out waiting for serve banner: ${bannerText}`)), 5000);
    serveOut.on('data', (chunk: Buffer) => {
      bannerText += chunk.toString('utf8');
      const webMatch = /^Web UI:\s+(http:\/\/127\.0\.0\.1:\d+)\/#token=([0-9a-f]{64})$/m.exec(bannerText);
      const mcpMatch = /^MCP HTTP:\s+(http:\/\/127\.0\.0\.1:\d+\/mcp)$/m.exec(bannerText);
      if (webMatch?.[1] && webMatch[2] && mcpMatch?.[1]) {
        clearTimeout(timeout);
        resolveBanner({
          baseUrl: webMatch[1],
          adminToken: webMatch[2],
          mcpUrl: mcpMatch[1],
        });
      }
    });
  });

  try {
    // Issue a client lease over HTTP Admin API.
    const createRes = await fetch(`${baseUrl}/api/leases`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ label: 'stdio-client', scopes: ['read'], ttlMs: null }),
    });
    assert.equal(createRes.status, 201);
    const { token: clientToken, lease } = (await createRes.json()) as {
      token: string;
      lease: { id: string };
    };

    // Spawn real CLI `stdio` subprocess and run full JSON-RPC round-trip!
    const child = spawn(process.execPath, [join(REPO_ROOT, 'src/server/cli.ts'), 'stdio', '--url', mcpUrl], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        COMPUTER_ACCESS_TOKEN: clientToken,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const stdoutLines: string[] = [];
    let stdoutBuf = '';
    child.stdout.on('data', (chunk: Buffer) => {
      stdoutBuf += chunk.toString('utf8');
      const parts = stdoutBuf.split('\n');
      stdoutBuf = parts.pop() ?? '';
      for (const line of parts) {
        if (line.trim() !== '') stdoutLines.push(line);
      }
    });

    child.stdin.write(
      `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } })}\n`,
    );
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })}\n`);
    child.stdin.write(
      `${JSON.stringify({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'history_read', arguments: { id: 'evt_stdio_1' } },
      })}\n`,
    );
    child.stdin.end();

    const exitCode = await new Promise<number | null>((resolveExit) => {
      child.once('close', (code) => resolveExit(code));
    });
    assert.equal(exitCode, 0);
    // Notification produced no stdout line -> exactly 3 responses for ids 1, 2, 3.
    assert.equal(stdoutLines.length, 3);

    const r1 = JSON.parse(stdoutLines[0] ?? '{}') as { id: number; result: { serverInfo: { name: string } } };
    const r2 = JSON.parse(stdoutLines[1] ?? '{}') as { id: number; result: { tools: Array<{ name: string }> } };
    const r3 = JSON.parse(stdoutLines[2] ?? '{}') as {
      id: number;
      result: { content: Array<{ text: string }> };
    };
    assert.equal(r1.id, 1);
    assert.equal(r1.result.serverInfo.name, 'computer-access-mcp');
    assert.equal(r2.id, 2);
    assert.equal(r2.result.tools.length, 5);
    assert.equal(r3.id, 3);
    assert.match(r3.result.content[0]?.text ?? '', /Terminal workflow captured/);

    // Revoke lease and verify in-process runStdioProxy surfaces immediate 401 error without hanging.
    await fetch(`${baseUrl}/api/leases/${lease.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${adminToken}` },
    });

    const inStream = new PassThrough();
    const outStream = new PassThrough();
    let revokedOut = '';
    outStream.on('data', (c: Buffer) => {
      revokedOut += c.toString('utf8');
    });

    inStream.end(`${JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'tools/list' })}\n`);
    await runStdioProxy({
      url: mcpUrl,
      token: clientToken,
      input: inStream,
      output: outStream,
      errorOutput: new PassThrough(),
    });

    const errResp = JSON.parse(revokedOut.trim()) as {
      id: number;
      error: { code: number; message: string; data?: { status: number } };
    };
    assert.equal(errResp.id, 99);
    assert.equal(errResp.error.code, -32001);
    assert.equal(errResp.error.data?.status, 401);
  } finally {
    abortController.abort();
    const serveExit = await servePromise;
    assert.equal(serveExit, 0);
    await rm(dir, { recursive: true, force: true });
  }
});

test('MCP history_reload enforces opt-in reload scope and handles collector and server modes', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'camcp-mcp-reload-'));
  const mockService = createMockHistoryService(dir);
  await mockService.initializeKey();
  await mockService.start({ captureScope: 'window' });

  let restartInvoked = 0;
  let resolveRestart!: () => void;
  const restartDone = new Promise<void>((resolveDone) => {
    resolveRestart = resolveDone;
  });

  const srv = await startHttpServer({
    dataDir: dir,
    port: 0,
    service: mockService,
    onRequestServerRestart: async () => {
      restartInvoked += 1;
      resolveRestart();
    },
  });

  try {
    const readPause = await srv.authStore.createLease({
      label: 'no-reload',
      scopes: ['read', 'pause'],
      ttlMs: null,
    });
    const reloadLease = await srv.authStore.createLease({
      label: 'opt-in-reloader',
      scopes: ['read', 'reload'],
      ttlMs: null,
    });

    // read+pause does not list history_reload and receives -32003 if calling it directly.
    const noReloadList = (await (
      await mcpPost(srv.mcpUrl, readPause.token, { jsonrpc: '2.0', id: 1, method: 'tools/list' })
    ).json()) as { result: { tools: Array<{ name: string }> } };
    assert.equal(
      noReloadList.result.tools.some((t) => t.name === 'history_reload'),
      false,
    );

    const denied = (await (
      await mcpPost(srv.mcpUrl, readPause.token, {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'history_reload', arguments: { mode: 'collector' } },
      })
    ).json()) as { error?: { code: number } };
    assert.equal(denied.error?.code, -32003);

    // Opt-in reload lease sees history_reload in tools/list.
    const reloadList = (await (
      await mcpPost(srv.mcpUrl, reloadLease.token, { jsonrpc: '2.0', id: 3, method: 'tools/list' })
    ).json()) as { result: { tools: Array<{ name: string }> } };
    assert.deepEqual(
      reloadList.result.tools.map((t) => t.name),
      [
        'history_status',
        'history_search',
        'history_read',
        'history_layout',
        'history_layout_guide',
        'history_reload',
      ],
    );

    // Invalid mode returns -32602.
    const badMode = (await (
      await mcpPost(srv.mcpUrl, reloadLease.token, {
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: { name: 'history_reload', arguments: { mode: 'invalid' } },
      })
    ).json()) as { error?: { code: number } };
    assert.equal(badMode.error?.code, -32602);

    // Default mode ('collector') reloads running collector and preserves running state.
    const colReload = (await (
      await mcpPost(srv.mcpUrl, reloadLease.token, {
        jsonrpc: '2.0',
        id: 5,
        method: 'tools/call',
        params: { name: 'history_reload', arguments: {} },
      })
    ).json()) as { result: { content: Array<{ text: string }>; isError?: boolean } };
    assert.notEqual(colReload.result.isError, true);
    const colPayload = JSON.parse(colReload.result.content[0]?.text ?? '{}') as {
      ok: boolean;
      mode: string;
      restarted: boolean;
      resumed: boolean;
      status: { state: string };
    };
    assert.equal(colPayload.ok, true);
    assert.equal(colPayload.mode, 'collector');
    assert.equal(colPayload.restarted, true);
    assert.equal(colPayload.resumed, true);
    assert.equal(colPayload.status.state, 'running');

    // Mode 'server' returns ok + resumed=true and triggers restart callback after flush.
    const srvReload = (await (
      await mcpPost(srv.mcpUrl, reloadLease.token, {
        jsonrpc: '2.0',
        id: 6,
        method: 'tools/call',
        params: { name: 'history_reload', arguments: { mode: 'server' } },
      })
    ).json()) as { result: { content: Array<{ text: string }>; isError?: boolean } };
    assert.notEqual(srvReload.result.isError, true);
    assert.deepEqual(JSON.parse(srvReload.result.content[0]?.text ?? '{}'), {
      ok: true,
      mode: 'server',
      restarted: true,
      resumed: true,
    });
    await restartDone;
    assert.equal(restartInvoked, 1);
  } finally {
    await srv.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('restart-resume.json enforces 0600 permissions, immediate unlink, TTL expiry, symlink rejection, and worker handoff', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'camcp-restart-handoff-'));
  try {
    const scope = {
      applicationScope: 'allowlist' as const,
      allowedApplicationIds: ['com.tencent.xinWeChat'],
      excludedApplicationIds: ['com.apple.Safari'],
      allowBrowserContent: false,
      fieldSecurity: 'denylist' as const,
      axCompatibility: true,
      textMarkers: true,
      captureScope: 'window' as const,
      maxTreeNodes: 48,
      inputText: true,
      selectionCapture: true,
      inputActivity: true,
      textRange: 'prefix' as const,
      maxTextCodeUnits: 4096,
      sampleIntervalMs: 1000,
    };

    // 1. writeRestartResume creates 0600 file; consumeRestartResume reads and immediately unlinks.
    const now = 1_700_000_000_000;
    await writeRestartResume(dir, scope, now);
    const resumePath = join(dir, RESTART_RESUME_FILENAME);
    if (process.platform !== 'win32') {
      const info = await stat(resumePath);
      assert.equal(info.mode & 0o777, 0o600);
    }
    const consumed = await consumeRestartResume(dir, now + 5_000);
    assert.deepEqual(consumed, scope);
    await assert.rejects(lstat(resumePath), { code: 'ENOENT' });
    assert.equal(await consumeRestartResume(dir, now + 5_000), null);

    // 2. Expired TTL (> 30s) returns null AND still immediately unlinks the file.
    await writeRestartResume(dir, scope, now);
    assert.equal(await consumeRestartResume(dir, now + 31_000), null);
    await assert.rejects(lstat(resumePath), { code: 'ENOENT' });

    // 3. Symlinked restart-resume.json is refused without following.
    const outsideTarget = join(dir, 'outside-scope.json');
    await writeFile(outsideTarget, JSON.stringify({ activeScope: scope, expiresAtMs: now + 30_000 }), 'utf8');
    await symlink(outsideTarget, resumePath);
    assert.equal(await consumeRestartResume(dir, now + 1_000), null);
    await rm(resumePath);

    // 4. Worker mode self-restart while running writes restart-resume.json, exits 75, and next worker resumes exact scope.
    const mock1 = createMockHistoryService(dir);
    await mock1.initializeKey();
    await mock1.start({
      applicationScope: 'allowlist',
      allowedApplicationIds: ['com.tencent.xinWeChat'],
      captureScope: 'region',
    });

    const out1 = new PassThrough();
    let banner1 = '';
    const worker1Promise = runCli(['serve', '--worker', '--port', '0', '--data-dir', dir], {
      stdout: out1,
      stderr: new PassThrough(),
      createService: () => mock1,
    });
    const info1 = await new Promise<{ baseUrl: string; adminToken: string }>((resolveBanner, rejectBanner) => {
      const timeout = setTimeout(() => rejectBanner(new Error(`Worker 1 banner timeout: ${banner1}`)), 5000);
      out1.on('data', (chunk: Buffer) => {
        banner1 += chunk.toString('utf8');
        const m = /^Web UI:\s+(http:\/\/127\.0\.0\.1:\d+)\/#token=([0-9a-f]{64})$/m.exec(banner1);
        if (m?.[1] && m[2]) {
          clearTimeout(timeout);
          resolveBanner({ baseUrl: m[1], adminToken: m[2] });
        }
      });
    });

    const restartRes = await fetch(`${info1.baseUrl}/api/service/reload`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${info1.adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ mode: 'server' }),
    });
    assert.equal(restartRes.status, 202);
    assert.deepEqual(await restartRes.json(), {
      ok: true,
      mode: 'server',
      restarted: true,
      resumed: true,
    });
    assert.equal(await worker1Promise, RESTART_EXIT_CODE);
    assert.equal(mock1.closed, true);

    // Boot worker 2: consumes & unlinks restart-resume.json and automatically starts exact prior scope.
    const mock2 = createMockHistoryService(dir);
    const ac2 = new AbortController();
    const out2 = new PassThrough();
    let banner2 = '';
    const worker2Promise = runCli(['serve', '--worker', '--port', '0', '--data-dir', dir], {
      stdout: out2,
      stderr: new PassThrough(),
      signal: ac2.signal,
      createService: () => mock2,
    });
    const info2 = await new Promise<{ baseUrl: string; adminToken: string }>((resolveBanner, rejectBanner) => {
      const timeout = setTimeout(() => rejectBanner(new Error(`Worker 2 banner timeout: ${banner2}`)), 5000);
      out2.on('data', (chunk: Buffer) => {
        banner2 += chunk.toString('utf8');
        const m = /^Web UI:\s+(http:\/\/127\.0\.0\.1:\d+)\/#token=([0-9a-f]{64})$/m.exec(banner2);
        if (m?.[1] && m[2]) {
          clearTimeout(timeout);
          resolveBanner({ baseUrl: m[1], adminToken: m[2] });
        }
      });
    });

    // File must already be unlinked on boot, and service resumed with exact prior scope.
    await assert.rejects(lstat(resumePath), { code: 'ENOENT' });
    const resumedStatus = await mock2.status();
    assert.equal(resumedStatus.state, 'running');
    assert.equal(resumedStatus.activeScope?.applicationScope, 'allowlist');
    assert.deepEqual(resumedStatus.activeScope?.allowedApplicationIds, ['com.tencent.xinWeChat']);
    assert.equal(resumedStatus.activeScope?.captureScope, 'region');

    // Pause capture, then trigger server restart -> must NOT write restart-resume.json and must exit 75.
    await mock2.pause();
    const pausedRestartRes = await fetch(`${info2.baseUrl}/api/service/reload`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${info2.adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ mode: 'server' }),
    });
    assert.equal(pausedRestartRes.status, 202);
    assert.deepEqual(await pausedRestartRes.json(), {
      ok: true,
      mode: 'server',
      restarted: true,
      resumed: false,
    });
    assert.equal(await worker2Promise, RESTART_EXIT_CODE);
    await assert.rejects(lstat(resumePath), { code: 'ENOENT' });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('CLI serve supervisor respawns worker on exit code 75 and forwards SIGTERM cleanly', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'camcp-supervisor-test-'));
  const port = await new Promise<number>((resolvePort, rejectPort) => {
    const probe = createNetServer();
    probe.once('error', rejectPort);
    probe.listen(0, '127.0.0.1', () => {
      const addr = probe.address() as AddressInfo;
      probe.close(() => resolvePort(addr.port));
    });
  });

  const child = spawn(
    process.execPath,
    [join(REPO_ROOT, 'src/server/cli.ts'), 'serve', '--port', String(port), '--data-dir', dir],
    {
      cwd: REPO_ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );

  let output = '';
  const waitForBannerCount = (expected: number): Promise<string> =>
    new Promise((resolveBanner, rejectBanner) => {
      const check = () => {
        const matches = [...output.matchAll(/^Web UI:\s+http:\/\/127\.0\.0\.1:\d+\/#token=([0-9a-f]{64})$/gm)];
        if (matches.length >= expected) {
          clearTimeout(timeout);
          child.stdout.off('data', onData);
          resolveBanner(matches[expected - 1]![1]!);
        }
      };
      const onData = (chunk: Buffer) => {
        output += chunk.toString('utf8');
        check();
      };
      const timeout = setTimeout(
        () => rejectBanner(new Error(`Timed out waiting for banner #${expected}: ${output}`)),
        10_000,
      );
      child.stdout.on('data', onData);
      check();
    });

  try {
    const adminToken = await waitForBannerCount(1);
    const baseUrl = `http://127.0.0.1:${port}`;

    const reloadRes = await fetch(`${baseUrl}/api/service/reload`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ mode: 'server' }),
    });
    assert.equal(reloadRes.status, 202);
    assert.deepEqual(await reloadRes.json(), {
      ok: true,
      mode: 'server',
      restarted: true,
      resumed: false,
    });

    // Supervisor catches exit 75 and respawns a fresh worker on the same port.
    const secondToken = await waitForBannerCount(2);
    assert.equal(secondToken, adminToken);

    const statusRes = await fetch(`${baseUrl}/api/auth/check`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(statusRes.status, 200);
    assert.deepEqual(await statusRes.json(), { authenticated: true });

    child.kill('SIGTERM');
    const exitCode = await new Promise<number | null>((resolveExit) => {
      child.once('exit', (code) => resolveExit(code));
    });
    assert.equal(exitCode, 0);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
    }
    await rm(dir, { recursive: true, force: true });
  }
});

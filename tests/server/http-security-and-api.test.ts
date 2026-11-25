import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { HistoryOperationError } from '../../src/host/service/history-service.ts';
import { startHttpServer } from '../../src/server/http-server.ts';
import {
  createMockHistoryService,
  makeSampleSurfaceSnapshot,
  makeSampleTextSnapshot,
} from './mock-service.ts';

function rawHttpGet(
  port: number,
  path: string,
  headers: Record<string, string>,
): Promise<{ status: number; body: string }> {
  return new Promise((resolveReq, rejectReq) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port,
        path,
        method: 'GET',
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          resolveReq({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.on('error', rejectReq);
    req.end();
  });
}

test('HTTP server blocks DNS rebinding Host headers and cross-origin /api/* requests', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'chmcp-http-sec-'));
  const mockService = createMockHistoryService(dir);
  const srv = await startHttpServer({
    dataDir: dir,
    port: 0,
    service: mockService,
    webDistDir: join(dir, 'nonexistent-web'),
  });

  try {
    // Host header validation (DNS rebinding defense).
    for (const maliciousHost of [
      'evil.example',
      `evil.example:${srv.port}`,
      '127.0.0.1.evil.example',
      '192.168.1.10:43180',
    ]) {
      const res = await rawHttpGet(srv.port, '/api/auth/check', { Host: maliciousHost });
      assert.equal(res.status, 403, `Expected 403 for Host: ${maliciousHost}`);
    }

    for (const validHost of [`127.0.0.1:${srv.port}`, `localhost:${srv.port}`, `[::1]:${srv.port}`]) {
      const res = await rawHttpGet(srv.port, '/api/auth/check', { Host: validHost });
      assert.equal(res.status, 200, `Expected 200 for Host: ${validHost}`);
    }

    // Cross-origin Origin header defense on /api/*.
    for (const badOrigin of [
      'https://evil.example',
      'http://evil.example',
      'null',
      `http://127.0.0.1:${srv.port === 3000 ? 3001 : 3000}`,
    ]) {
      const res = await fetch(`${srv.baseUrl}/api/status`, {
        headers: {
          Authorization: `Bearer ${srv.adminToken}`,
          Origin: badOrigin,
        },
      });
      assert.equal(res.status, 403, `Expected 403 for Origin: ${badOrigin}`);
    }

    // Matching local origin succeeds.
    const sameOriginRes = await fetch(`${srv.baseUrl}/api/status`, {
      headers: {
        Authorization: `Bearer ${srv.adminToken}`,
        Origin: `http://127.0.0.1:${srv.port}`,
      },
    });
    assert.equal(sameOriginRes.status, 200);
  } finally {
    await srv.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('Admin REST API enforces admin token separation, validates inputs, and serves static assets', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'chmcp-http-api-'));
  const webDir = join(dir, 'web-dist');
  await mkdir(webDir, { recursive: true });
  await writeFile(join(webDir, 'index.html'), '<!doctype html><title>Panel</title>', 'utf8');
  await writeFile(join(webDir, 'app.js'), 'console.log("app");', 'utf8');
  await writeFile(join(webDir, 'styles.css'), 'body { margin: 0; }', 'utf8');
  await writeFile(join(webDir, 'icon.svg'), '<svg xmlns="http://www.w3.org/2000/svg"></svg>', 'utf8');

  const mockService = createMockHistoryService(dir);
  mockService.seedObservation(makeSampleTextSnapshot('evt_1', 'hello world from editor'));
  mockService.seedObservation(makeSampleSurfaceSnapshot('evt_surf_1', 'snap_1', 'Editor window content'));

  const srv = await startHttpServer({
    dataDir: dir,
    port: 0,
    service: mockService,
    webDistDir: webDir,
  });

  try {
    // Static assets served cleanly without requiring Authorization header.
    const htmlRes = await fetch(`${srv.baseUrl}/`);
    assert.equal(htmlRes.status, 200);
    assert.match(await htmlRes.text(), /<title>Panel<\/title>/);

    const jsRes = await fetch(`${srv.baseUrl}/app.js`);
    assert.equal(jsRes.status, 200);
    assert.match(jsRes.headers.get('content-type') ?? '', /javascript/);

    const cssRes = await fetch(`${srv.baseUrl}/styles.css`);
    assert.equal(cssRes.status, 200);
    assert.match(cssRes.headers.get('content-type') ?? '', /text\/css/);

    const iconRes = await fetch(`${srv.baseUrl}/icon.svg`);
    assert.equal(iconRes.status, 200);
    assert.match(iconRes.headers.get('content-type') ?? '', /image\/svg\+xml/);

    // /api/auth/check reflects admin auth accurately.
    const unauthCheck = (await (await fetch(`${srv.baseUrl}/api/auth/check`)).json()) as {
      authenticated: boolean;
    };
    assert.equal(unauthCheck.authenticated, false);

    const authHeaders = {
      Authorization: `Bearer ${srv.adminToken}`,
      'Content-Type': 'application/json',
    };
    const okCheck = (await (
      await fetch(`${srv.baseUrl}/api/auth/check`, { headers: authHeaders })
    ).json()) as { authenticated: boolean };
    assert.equal(okCheck.authenticated, true);

    // Unauthenticated /api/status returns 401.
    assert.equal((await fetch(`${srv.baseUrl}/api/status`)).status, 401);

    // Create a client lease and verify a client token CANNOT access admin /api/* endpoints.
    const createLeaseRes = await fetch(`${srv.baseUrl}/api/leases`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ label: 'agent-1', scopes: ['read', 'pause'], ttlMs: null }),
    });
    assert.equal(createLeaseRes.status, 201);
    const createdLease = (await createLeaseRes.json()) as { token: string; lease: { id: string } };
    assert.match(createdLease.token, /^chmcp_/);

    const clientAttemptAdmin = await fetch(`${srv.baseUrl}/api/status`, {
      headers: { Authorization: `Bearer ${createdLease.token}` },
    });
    assert.equal(clientAttemptAdmin.status, 401);

    // Key init & lifecycle controls.
    const initRes = await fetch(`${srv.baseUrl}/api/key/init`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${srv.adminToken}` },
    });
    assert.equal(initRes.status, 200);
    assert.equal(((await initRes.json()) as { state: string }).state, 'stopped');

    // Invalid capture start options rejected via validateCaptureStartOptions.
    const badStartRes = await fetch(`${srv.baseUrl}/api/capture/start`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ applicationScope: 'allowlist', allowedApplicationIds: [] }),
    });
    assert.equal(badStartRes.status, 400);

    const goodStartRes = await fetch(`${srv.baseUrl}/api/capture/start`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ captureScope: 'window' }),
    });
    assert.equal(goodStartRes.status, 200);
    assert.equal(((await goodStartRes.json()) as { state: string }).state, 'running');

    // Permissions routes.
    for (const action of [
      'request-accessibility',
      'open-accessibility',
      'request-input-monitoring',
      'open-input-monitoring',
    ]) {
      const pRes = await fetch(`${srv.baseUrl}/api/permissions/${action}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${srv.adminToken}` },
      });
      assert.equal(pRes.status, 200);
    }
    const unknownPermRes = await fetch(`${srv.baseUrl}/api/permissions/unknown-action`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${srv.adminToken}` },
    });
    assert.equal(unknownPermRes.status, 404);

    // Pause / resume / stop.
    assert.equal(
      (
        (await (
          await fetch(`${srv.baseUrl}/api/capture/pause`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${srv.adminToken}` },
          })
        ).json()) as { state: string }
      ).state,
      'paused',
    );
    assert.equal(
      (
        (await (
          await fetch(`${srv.baseUrl}/api/capture/resume`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${srv.adminToken}` },
          })
        ).json()) as { state: string }
      ).state,
      'running',
    );

    // History search / read / layout / source / forget.
    const searchRes = (await (
      await fetch(`${srv.baseUrl}/api/history/search`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ text: 'hello' }),
      })
    ).json()) as { records: Array<{ eventId: string }> };
    assert.equal(searchRes.records.length, 1);
    assert.equal(searchRes.records[0]?.eventId, 'evt_1');

    const readRes = (await (
      await fetch(`${srv.baseUrl}/api/history/read`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ id: 'evt_1' }),
      })
    ).json()) as { found: boolean };
    assert.equal(readRes.found, true);

    const layoutRes = (await (
      await fetch(`${srv.baseUrl}/api/history/layout`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ snapshotId: 'snap_1' }),
      })
    ).json()) as { found: boolean; nodes: unknown[] };
    assert.equal(layoutRes.found, true);
    assert.equal(layoutRes.nodes.length, 2);

    const sourceRes = (await (
      await fetch(`${srv.baseUrl}/api/source/open`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ applicationId: 'com.google.antigravity-ide' }),
      })
    ).json()) as { outcome: string };
    assert.equal(sourceRes.outcome, 'activated');

    const forgetRes = (await (
      await fetch(`${srv.baseUrl}/api/history/forget`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ all: true }),
      })
    ).json()) as { remainingRecords: number };
    assert.equal(forgetRes.remainingRecords, 0);

    // Lease list + delete + rotate admin token.
    const leasesList = (await (
      await fetch(`${srv.baseUrl}/api/leases`, { headers: authHeaders })
    ).json()) as { leases: Array<{ id: string }> };
    assert.equal(leasesList.leases.length, 1);

    const delRes = await fetch(`${srv.baseUrl}/api/leases/${createdLease.lease.id}`, {
      method: 'DELETE',
      headers: authHeaders,
    });
    assert.equal(delRes.status, 200);

    const rotateRes = (await (
      await fetch(`${srv.baseUrl}/api/admin/rotate-token`, {
        method: 'POST',
        headers: authHeaders,
      })
    ).json()) as { token: string };
    assert.match(rotateRes.token, /^[0-9a-f]{64}$/);
    assert.notEqual(rotateRes.token, authHeaders.Authorization.replace('Bearer ', ''));

    // Old admin token immediately rejected after rotation.
    const oldTokenCheck = await fetch(`${srv.baseUrl}/api/status`, { headers: authHeaders });
    assert.equal(oldTokenCheck.status, 401);
  } finally {
    await srv.close();
    assert.equal(mockService.closed, true);
    await rm(dir, { recursive: true, force: true });
  }
});

test('POST /api/service/reload supports collector and server modes with strict admin auth and no auto-start', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'chmcp-http-reload-'));
  const mockService = createMockHistoryService(dir);
  let serverRestartCalls = 0;
  let resolveRestart!: () => void;
  const restartTriggered = new Promise<void>((resolve) => {
    resolveRestart = resolve;
  });

  const srvWithoutRestart = await startHttpServer({
    dataDir: dir,
    port: 0,
    service: mockService,
    closeServiceOnStop: false,
  });

  try {
    const authHeaders = {
      Authorization: `Bearer ${srvWithoutRestart.adminToken}`,
      'Content-Type': 'application/json',
    };

    // Unauthenticated or client-token calls to /api/service/reload are rejected with 401.
    assert.equal(
      (await fetch(`${srvWithoutRestart.baseUrl}/api/service/reload`, { method: 'POST', body: '{}' })).status,
      401,
    );
    const reloadLease = await srvWithoutRestart.authStore.createLease({
      label: 'agent-reload',
      scopes: ['read', 'reload'],
      ttlMs: null,
    });
    assert.equal(
      (
        await fetch(`${srvWithoutRestart.baseUrl}/api/service/reload`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${reloadLease.token}`, 'Content-Type': 'application/json' },
          body: '{}',
        })
      ).status,
      401,
    );

    // Invalid mode returns 400.
    const invalidModeRes = await fetch(`${srvWithoutRestart.baseUrl}/api/service/reload`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ mode: 'bogus' }),
    });
    assert.equal(invalidModeRes.status, 400);

    // Collector reload while not-initialized NEVER starts capture.
    const reloadUninit = (await (
      await fetch(`${srvWithoutRestart.baseUrl}/api/service/reload`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({}),
      })
    ).json()) as { ok: boolean; mode: string; restarted: boolean; resumed: boolean; status: { state: string } };
    assert.equal(reloadUninit.ok, true);
    assert.equal(reloadUninit.mode, 'collector');
    assert.equal(reloadUninit.restarted, true);
    assert.equal(reloadUninit.resumed, false);
    assert.equal(reloadUninit.status.state, 'not-initialized');

    // Mode 'server' without restart hook returns 501.
    const unavailRes = await fetch(`${srvWithoutRestart.baseUrl}/api/service/reload`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ mode: 'server' }),
    });
    assert.equal(unavailRes.status, 501);
    assert.deepEqual(await unavailRes.json(), { error: 'server-restart-unavailable' });
  } finally {
    await srvWithoutRestart.close();
  }

  // Start server with restart callback and running capture.
  await mockService.initializeKey();
  await mockService.start({ captureScope: 'window' });

  const srvWithRestart = await startHttpServer({
    dataDir: dir,
    port: 0,
    service: mockService,
    onRequestServerRestart: async () => {
      serverRestartCalls += 1;
      resolveRestart();
    },
  });

  try {
    const authHeaders = {
      Authorization: `Bearer ${srvWithRestart.adminToken}`,
      'Content-Type': 'application/json',
    };

    // Collector reload while running preserves running state.
    const reloadRunningRes = await fetch(`${srvWithRestart.baseUrl}/api/service/reload`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ mode: 'collector' }),
    });
    assert.equal(reloadRunningRes.status, 200);
    const reloadRunning = (await reloadRunningRes.json()) as {
      ok: boolean;
      mode: string;
      restarted: boolean;
      resumed: boolean;
      status: { state: string };
    };
    assert.equal(reloadRunning.ok, true);
    assert.equal(reloadRunning.mode, 'collector');
    assert.equal(reloadRunning.restarted, true);
    assert.equal(reloadRunning.resumed, true);
    assert.equal(reloadRunning.status.state, 'running');

    // Server reload returns 202 immediately and invokes callback after response flushes.
    const serverReloadRes = await fetch(`${srvWithRestart.baseUrl}/api/service/reload`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ mode: 'server' }),
    });
    assert.equal(serverReloadRes.status, 202);
    const serverReloadBody = (await serverReloadRes.json()) as {
      ok: boolean;
      mode: string;
      restarted: boolean;
      resumed: boolean;
    };
    assert.deepEqual(serverReloadBody, {
      ok: true,
      mode: 'server',
      restarted: true,
      resumed: true,
    });

    await restartTriggered;
    assert.equal(serverRestartCalls, 1);
  } finally {
    await srvWithRestart.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('GET /api/status supports lightweight polling with permissions=0 without invoking checkPermissions', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'chmcp-http-status-poll-'));
  const mockService = createMockHistoryService(dir);
  const srv = await startHttpServer({
    dataDir: dir,
    port: 0,
    service: mockService,
    webDistDir: join(dir, 'nonexistent-web'),
  });

  try {
    const authHeaders = { Authorization: `Bearer ${srv.adminToken}` };

    // Default request includes permissions.
    const fullRes = await fetch(`${srv.baseUrl}/api/status`, { headers: authHeaders });
    assert.equal(fullRes.status, 200);
    const fullBody = (await fullRes.json()) as { status: { state: string }; permissions?: { accessibility: string } };
    assert.equal(fullBody.status.state, 'not-initialized');
    assert.equal(fullBody.permissions?.accessibility, 'granted');
    assert.equal(
      mockService.calls.filter((c) => c === 'checkPermissions').length,
      1,
    );

    // Lightweight polling skips checkPermissions completely.
    for (const query of ['permissions=0', 'permissions=false']) {
      const pollRes = await fetch(`${srv.baseUrl}/api/status?${query}`, { headers: authHeaders });
      assert.equal(pollRes.status, 200);
      const pollBody = (await pollRes.json()) as Record<string, unknown>;
      assert.equal('permissions' in pollBody, false);
      assert.equal(typeof pollBody.status, 'object');
      assert.equal(typeof pollBody.dataRoot, 'string');
    }
    assert.equal(
      mockService.calls.filter((c) => c === 'checkPermissions').length,
      1,
      'lightweight status polls must not invoke checkPermissions',
    );

    // Explicit permissions=1 / true still runs checkPermissions.
    const explicitRes = await fetch(`${srv.baseUrl}/api/status?permissions=1`, { headers: authHeaders });
    assert.equal(explicitRes.status, 200);
    const explicitBody = (await explicitRes.json()) as { permissions?: { accessibility: string } };
    assert.equal(explicitBody.permissions?.accessibility, 'granted');
    assert.equal(
      mockService.calls.filter((c) => c === 'checkPermissions').length,
      2,
    );

    // Invalid permissions parameter is rejected with 400.
    const invalidRes = await fetch(`${srv.baseUrl}/api/status?permissions=maybe`, { headers: authHeaders });
    assert.equal(invalidRes.status, 400);
    assert.deepEqual(await invalidRes.json(), { error: 'invalid-permissions-param' });
  } finally {
    await srv.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('GET /api/status degrades permission-helper-unavailable to honest unknown PermissionStatus while propagating other errors', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'chmcp-http-status-perm-fallback-'));
  const baseService = createMockHistoryService(dir);
  let platform: 'win32' | 'darwin' = 'win32';
  let checkPermissionsError: Error = new HistoryOperationError('permission-helper-unavailable');

  const service = {
    ...baseService,
    async status() {
      const current = await baseService.status();
      return { ...current, platform };
    },
    async checkPermissions(): Promise<never> {
      throw checkPermissionsError;
    },
  };

  const srv = await startHttpServer({
    dataDir: dir,
    port: 0,
    service,
    webDistDir: join(dir, 'nonexistent-web'),
  });

  try {
    const authHeaders = { Authorization: `Bearer ${srv.adminToken}` };

    // Windows: permission-helper-unavailable returns 200 with honest unknown desktop + not-applicable TCC fields.
    platform = 'win32';
    checkPermissionsError = new HistoryOperationError('permission-helper-unavailable');
    const winRes = await fetch(`${srv.baseUrl}/api/status`, { headers: authHeaders });
    assert.equal(winRes.status, 200);
    const winBody = (await winRes.json()) as {
      status: { platform: string };
      permissions?: {
        platform: string;
        accessibility: string;
        inputMonitoring: string;
        desktopStatus: string;
        desktopReason: string;
        promptRequested?: boolean;
        settingsOpened?: boolean;
        checkedAtMs: number;
      };
    };
    assert.equal(winBody.status.platform, 'win32');
    assert.ok(winBody.permissions);
    assert.equal(winBody.permissions.platform, 'win32');
    assert.equal(winBody.permissions.accessibility, 'not-applicable');
    assert.equal(winBody.permissions.inputMonitoring, 'not-applicable');
    assert.equal(winBody.permissions.desktopStatus, 'unknown');
    assert.equal(winBody.permissions.desktopReason, 'permission-helper-unavailable');
    assert.equal(winBody.permissions.promptRequested, false);
    assert.equal(winBody.permissions.settingsOpened, false);
    assert.equal(typeof winBody.permissions.checkedAtMs, 'number');

    // Direct /api/permissions remains strictly fail-closed.
    const directPermRes = await fetch(`${srv.baseUrl}/api/permissions`, { headers: authHeaders });
    assert.equal(directPermRes.status, 400);
    assert.deepEqual(await directPermRes.json(), { error: 'permission-helper-unavailable' });

    // macOS: permission-helper-unavailable returns 200 with unknown accessibility/inputMonitoring/desktop.
    platform = 'darwin';
    const macRes = await fetch(`${srv.baseUrl}/api/status`, { headers: authHeaders });
    assert.equal(macRes.status, 200);
    const macBody = (await macRes.json()) as typeof winBody;
    assert.equal(macBody.status.platform, 'darwin');
    assert.ok(macBody.permissions);
    assert.equal(macBody.permissions.platform, 'darwin');
    assert.equal(macBody.permissions.accessibility, 'unknown');
    assert.equal(macBody.permissions.inputMonitoring, 'unknown');
    assert.equal(macBody.permissions.desktopStatus, 'unknown');
    assert.equal(macBody.permissions.desktopReason, 'permission-helper-unavailable');
    assert.equal(macBody.permissions.promptRequested, false);
    assert.equal(macBody.permissions.settingsOpened, false);
    assert.equal(typeof macBody.permissions.checkedAtMs, 'number');

    // Other HistoryOperationError codes must still fail and propagate.
    for (const code of ['permission-action-busy', 'permission-response-invalid', 'permission-helper-exit-failed']) {
      checkPermissionsError = new HistoryOperationError(code);
      const errRes = await fetch(`${srv.baseUrl}/api/status`, { headers: authHeaders });
      assert.equal(errRes.status, 400, `Expected 400 for ${code}`);
      assert.deepEqual(await errRes.json(), { error: code });
    }

    // Non-HistoryOperationError errors must also fail and propagate.
    checkPermissionsError = new Error('permission-helper-unavailable');
    const nonOpErrRes = await fetch(`${srv.baseUrl}/api/status`, { headers: authHeaders });
    assert.equal(nonOpErrRes.status, 400);
    assert.deepEqual(await nonOpErrRes.json(), { error: 'permission-helper-unavailable' });
  } finally {
    await srv.close();
    await rm(dir, { recursive: true, force: true });
  }
});

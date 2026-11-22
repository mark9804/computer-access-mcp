import { lstat, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { dirname, extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { HISTORY_QUERY_KINDS } from '../shared/api-types.ts';
import type {
  CreateLeaseRequest,
  HistoryForgetRequest,
  HistoryLayoutRequest,
  HistoryQuery,
  HistoryQueryKind,
  HistoryServiceContract,
  OpenSourceRequest,
  PermissionStatus,
  ReloadMode,
  ReloadResult,
  StatusApiResponse,
} from '../shared/api-types.ts';
import { validateCaptureStartOptions } from '../shared/app-policy.ts';
import { HistoryOperationError } from '../host/service/history-service.ts';
import { AuthStore, AuthValidationError } from './auth-store.ts';
import { createMcpHandler } from './mcp-handler.ts';

export const DEFAULT_HTTP_HOST = '127.0.0.1';
export const DEFAULT_HTTP_PORT = 43180;
const MAX_API_BODY_BYTES = 256 * 1024;

const DEFAULT_PKG_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

const STATIC_CONTENT_TYPES: Readonly<Record<string, string>> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
};

const VALID_QUERY_KINDS = new Set<HistoryQueryKind>(HISTORY_QUERY_KINDS);

const FALLBACK_INDEX_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>computer-access-mcp</title>
  </head>
  <body>
    <main style="font-family: system-ui, sans-serif; max-width: 640px; margin: 48px auto; padding: 0 16px;">
      <h1>computer-access-mcp</h1>
      <p>Local daemon is running. Web UI static bundle was not found in dist/web.</p>
      <p>Run <code>pnpm build:client</code> to build the control panel.</p>
    </main>
  </body>
</html>
`;

class HttpRouteError extends Error {
  readonly status: number;

  constructor(status: number, code: string) {
    super(code);
    this.name = 'HttpRouteError';
    this.status = status;
  }
}

export function isLoopbackHostHeader(hostHeader: string | string[] | undefined): boolean {
  if (typeof hostHeader !== 'string' || hostHeader.length === 0) {
    return false;
  }
  const match = /^(127\.0\.0\.1|localhost|\[::1\])(?::([0-9]{1,5}))?$/i.exec(hostHeader.trim());
  if (!match) {
    return false;
  }
  const portPart = match[2];
  if (portPart !== undefined) {
    const portNum = Number(portPart);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535 || String(portNum) !== portPart) {
      return false;
    }
  }
  return true;
}

export function isAllowedLocalOrigin(
  originHeader: string | string[] | undefined,
  actualPort: number,
): boolean {
  if (originHeader === undefined) {
    return true;
  }
  if (typeof originHeader !== 'string' || originHeader.trim() === '' || originHeader === 'null') {
    return false;
  }
  let parsed: URL;
  try {
    parsed = new URL(originHeader);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'http:') {
    return false;
  }
  if (parsed.username !== '' || parsed.password !== '') {
    return false;
  }
  const hostname = parsed.hostname.toLowerCase();
  if (hostname !== '127.0.0.1' && hostname !== 'localhost' && hostname !== '[::1]') {
    return false;
  }
  const effectivePort = parsed.port === '' ? '80' : parsed.port;
  return effectivePort === String(actualPort);
}

function extractBearerToken(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return match?.[1] ?? null;
}

function sendJson(
  res: ServerResponse,
  statusCode: number,
  payload: unknown,
  options?: { closeConnection?: boolean; onFlushed?: () => void },
): void {
  const body = JSON.stringify(payload);
  const headers: Record<string, string | number> = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Length': Buffer.byteLength(body, 'utf8'),
  };
  if (options?.closeConnection) {
    headers.Connection = 'close';
  }
  res.writeHead(statusCode, headers);
  if (options?.onFlushed) {
    const onFlushed = options.onFlushed;
    res.end(body, () => {
      setImmediate(onFlushed);
    });
  } else {
    res.end(body);
  }
}

async function readJsonObject(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : (chunk as Buffer);
    total += buf.byteLength;
    if (total > MAX_API_BODY_BYTES) {
      throw new HttpRouteError(413, 'payload-too-large');
    }
    chunks.push(buf);
  }
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (raw === '') {
    return {};
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new HttpRouteError(400, 'invalid-json');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new HttpRouteError(400, 'invalid-json-object');
  }
  return parsed as Record<string, unknown>;
}

async function readSafeStaticFile(filePath: string): Promise<Buffer | null> {
  try {
    const info = await lstat(filePath);
    if (info.isSymbolicLink() || !info.isFile()) {
      return null;
    }
    return await readFile(filePath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw err;
  }
}

function parseHistoryQuery(body: Record<string, unknown>): HistoryQuery {
  const query: HistoryQuery = {};
  if (body.fromTimeMs !== undefined) {
    if (typeof body.fromTimeMs !== 'number' || !Number.isFinite(body.fromTimeMs)) {
      throw new HttpRouteError(400, 'invalid-from-time');
    }
    query.fromTimeMs = Math.floor(body.fromTimeMs);
  }
  if (body.toTimeMs !== undefined) {
    if (typeof body.toTimeMs !== 'number' || !Number.isFinite(body.toTimeMs)) {
      throw new HttpRouteError(400, 'invalid-to-time');
    }
    query.toTimeMs = Math.floor(body.toTimeMs);
  }
  if (body.applicationId !== undefined) {
    if (typeof body.applicationId !== 'string') {
      throw new HttpRouteError(400, 'invalid-application-id');
    }
    if (body.applicationId.trim() !== '') {
      query.applicationId = body.applicationId.trim();
    }
  }
  if (body.text !== undefined) {
    if (typeof body.text !== 'string') {
      throw new HttpRouteError(400, 'invalid-text-filter');
    }
    if (body.text !== '') {
      query.text = body.text;
    }
  }
  if (body.kind !== undefined) {
    if (typeof body.kind !== 'string' || !VALID_QUERY_KINDS.has(body.kind as HistoryQueryKind)) {
      throw new HttpRouteError(400, 'invalid-kind');
    }
    query.kind = body.kind as HistoryQueryKind;
  }
  if (body.textView !== undefined) {
    if (body.textView !== 'full' && body.textView !== 'delta') {
      throw new HttpRouteError(400, 'invalid-text-view');
    }
    query.textView = body.textView;
  }
  if (body.limit !== undefined) {
    if (typeof body.limit !== 'number' || !Number.isSafeInteger(body.limit) || body.limit < 1 || body.limit > 500) {
      throw new HttpRouteError(400, 'invalid-limit');
    }
    query.limit = body.limit;
  }
  if (body.maxBytes !== undefined) {
    if (typeof body.maxBytes !== 'number' || !Number.isSafeInteger(body.maxBytes) || body.maxBytes < 256) {
      throw new HttpRouteError(400, 'invalid-max-bytes');
    }
    query.maxBytes = body.maxBytes;
  }
  if (body.order !== undefined) {
    if (body.order !== 'asc' && body.order !== 'desc') {
      throw new HttpRouteError(400, 'invalid-order');
    }
    query.order = body.order;
  }
  if (body.cursor !== undefined) {
    if (typeof body.cursor !== 'string') {
      throw new HttpRouteError(400, 'invalid-cursor');
    }
    query.cursor = body.cursor;
  }
  return query;
}

function parseLayoutRequest(body: Record<string, unknown>): HistoryLayoutRequest {
  const req: HistoryLayoutRequest = {};
  if (body.eventId !== undefined) {
    if (typeof body.eventId !== 'string') throw new HttpRouteError(400, 'invalid-event-id');
    if (body.eventId.trim() !== '') req.eventId = body.eventId.trim();
  }
  if (body.snapshotId !== undefined) {
    if (typeof body.snapshotId !== 'string') throw new HttpRouteError(400, 'invalid-snapshot-id');
    if (body.snapshotId.trim() !== '') req.snapshotId = body.snapshotId.trim();
  }
  if (!req.eventId && !req.snapshotId) {
    throw new HttpRouteError(400, 'invalid-layout-query');
  }
  if (body.applicationId !== undefined) {
    if (typeof body.applicationId !== 'string') throw new HttpRouteError(400, 'invalid-application-id');
    if (body.applicationId.trim() !== '') req.applicationId = body.applicationId.trim();
  }
  if (body.maxNodes !== undefined) {
    if (typeof body.maxNodes !== 'number' || !Number.isSafeInteger(body.maxNodes) || body.maxNodes < 1) {
      throw new HttpRouteError(400, 'invalid-max-nodes');
    }
    req.maxNodes = body.maxNodes;
  }
  if (body.maxChars !== undefined) {
    if (typeof body.maxChars !== 'number' || !Number.isSafeInteger(body.maxChars) || body.maxChars < 1) {
      throw new HttpRouteError(400, 'invalid-max-chars');
    }
    req.maxChars = body.maxChars;
  }
  if (body.cursor !== undefined) {
    if (typeof body.cursor !== 'string') throw new HttpRouteError(400, 'invalid-cursor');
    req.cursor = body.cursor;
  }
  if (body.nodeIds !== undefined) {
    if (!Array.isArray(body.nodeIds) || body.nodeIds.some((n) => typeof n !== 'string')) {
      throw new HttpRouteError(400, 'invalid-node-ids');
    }
    req.nodeIds = [...(body.nodeIds as string[])];
  }
  if (body.bounds !== undefined) {
    if (body.bounds === null || typeof body.bounds !== 'object' || Array.isArray(body.bounds)) {
      throw new HttpRouteError(400, 'invalid-bounds');
    }
    const b = body.bounds as Record<string, unknown>;
    if (
      typeof b.x !== 'number' ||
      !Number.isFinite(b.x) ||
      typeof b.y !== 'number' ||
      !Number.isFinite(b.y) ||
      typeof b.width !== 'number' ||
      !Number.isFinite(b.width) ||
      b.width < 0 ||
      typeof b.height !== 'number' ||
      !Number.isFinite(b.height) ||
      b.height < 0
    ) {
      throw new HttpRouteError(400, 'invalid-bounds');
    }
    req.bounds = { x: b.x, y: b.y, width: b.width, height: b.height };
  }
  return req;
}

function parseForgetRequest(body: Record<string, unknown>): HistoryForgetRequest {
  const req: HistoryForgetRequest = {};
  if (body.all !== undefined) {
    if (typeof body.all !== 'boolean') throw new HttpRouteError(400, 'invalid-forget-request');
    req.all = body.all;
  }
  if (body.beforeMs !== undefined) {
    if (typeof body.beforeMs !== 'number' || !Number.isFinite(body.beforeMs)) {
      throw new HttpRouteError(400, 'invalid-forget-request');
    }
    req.beforeMs = Math.floor(body.beforeMs);
  }
  if (req.all !== true && req.beforeMs === undefined) {
    throw new HttpRouteError(400, 'invalid-forget-request');
  }
  return req;
}

function parseOpenSourceRequest(body: Record<string, unknown>): OpenSourceRequest {
  const req: OpenSourceRequest = {};
  if (body.eventId !== undefined) {
    if (typeof body.eventId !== 'string') throw new HttpRouteError(400, 'invalid-event-id');
    if (body.eventId.trim() !== '') req.eventId = body.eventId.trim();
  }
  if (body.applicationId !== undefined) {
    if (typeof body.applicationId !== 'string') throw new HttpRouteError(400, 'invalid-application-id');
    if (body.applicationId.trim() !== '') req.applicationId = body.applicationId.trim();
  }
  if (!req.eventId && !req.applicationId) {
    throw new HttpRouteError(400, 'invalid-open-source-request');
  }
  return req;
}

export interface HttpServerOptions {
  dataDir: string;
  service: HistoryServiceContract | ((ctx: { dataDir: string }) => HistoryServiceContract | Promise<HistoryServiceContract>);
  authStore?: AuthStore;
  host?: string;
  port?: number;
  webDistDir?: string;
  pkgRoot?: string;
  closeServiceOnStop?: boolean;
  onRequestServerRestart?: () => Promise<void>;
}

export interface RunningHttpServer {
  readonly server: Server;
  readonly host: string;
  readonly port: number;
  readonly baseUrl: string;
  readonly mcpUrl: string;
  readonly adminToken: string;
  readonly authStore: AuthStore;
  readonly service: HistoryServiceContract;
  close(): Promise<void>;
}

export async function startHttpServer(options: HttpServerOptions): Promise<RunningHttpServer> {
  const dataDir = resolve(options.dataDir);
  const host = options.host ?? DEFAULT_HTTP_HOST;
  const requestedPort = options.port ?? DEFAULT_HTTP_PORT;
  const pkgRoot = resolve(options.pkgRoot ?? DEFAULT_PKG_ROOT);
  const webDistDir = resolve(options.webDistDir ?? join(pkgRoot, 'dist', 'web'));
  const closeServiceOnStop = options.closeServiceOnStop ?? true;

  const authStore = options.authStore ?? (await AuthStore.open({ dataDir }));
  await authStore.init();

  const service =
    typeof options.service === 'function' ? await options.service({ dataDir }) : options.service;

  let serverRestartPending = false;
  const triggerServerRestart = options.onRequestServerRestart
    ? async (): Promise<void> => {
        if (serverRestartPending) return;
        serverRestartPending = true;
        try {
          await options.onRequestServerRestart!();
        } catch (err) {
          serverRestartPending = false;
          throw err;
        }
      }
    : undefined;

  const mcpHandler = createMcpHandler({
    authStore,
    service,
    layoutGuides: {
      builtInDir: join(pkgRoot, 'layout-guides'),
      userDir: join(dataDir, 'layout-guides'),
    },
    ...(triggerServerRestart ? { onRequestServerRestart: triggerServerRestart } : {}),
  });
  let actualPort = requestedPort;

  const handleApi = async (
    req: IncomingMessage,
    res: ServerResponse,
    pathname: string,
    searchParams: URLSearchParams,
  ): Promise<void> => {
    if (!isAllowedLocalOrigin(req.headers.origin, actualPort)) {
      sendJson(res, 403, { error: 'cross-origin-rejected' });
      return;
    }

    const method = req.method ?? 'GET';
    const bearer = extractBearerToken(req.headers.authorization);
    const isAdmin = bearer !== null && authStore.verifyAdminToken(bearer);

    if (method === 'GET' && pathname === '/api/auth/check') {
      sendJson(res, 200, { authenticated: isAdmin });
      return;
    }

    if (!isAdmin) {
      res.setHeader('WWW-Authenticate', 'Bearer realm="computer-access-admin"');
      sendJson(res, 401, { error: 'unauthorized' });
      return;
    }

    if (method === 'GET' && pathname === '/api/status') {
      const rawPermissions = searchParams.get('permissions');
      if (
        rawPermissions !== null &&
        rawPermissions !== '0' &&
        rawPermissions !== '1' &&
        rawPermissions !== 'false' &&
        rawPermissions !== 'true'
      ) {
        throw new HttpRouteError(400, 'invalid-permissions-param');
      }
      const includePermissions = rawPermissions !== '0' && rawPermissions !== 'false';
      const status = await service.status();
      let permissions: PermissionStatus | undefined;
      if (includePermissions) {
        try {
          permissions = await service.checkPermissions();
        } catch (error) {
          if (error instanceof HistoryOperationError && error.code === 'permission-helper-unavailable') {
            permissions = {
              platform: status.platform,
              accessibility: status.platform === 'win32' ? 'not-applicable' : 'unknown',
              inputMonitoring: status.platform === 'win32' ? 'not-applicable' : 'unknown',
              desktopStatus: 'unknown',
              desktopReason: 'permission-helper-unavailable',
              promptRequested: false,
              settingsOpened: false,
              checkedAtMs: Date.now(),
            };
          } else {
            throw error;
          }
        }
      }
      const response: StatusApiResponse = {
        status,
        ...(permissions !== undefined ? { permissions } : {}),
        dataRoot: status.dataRoot,
        stdioLauncher: {
          command: process.execPath,
          args: [join(pkgRoot, 'dist', 'server', 'cli.js'), 'stdio'],
        },
      };
      sendJson(res, 200, response);
      return;
    }

    if (method === 'POST' && pathname === '/api/key/init') {
      await readJsonObject(req);
      const status = await service.initializeKey();
      sendJson(res, 200, status);
      return;
    }

    if (method === 'GET' && pathname === '/api/permissions') {
      const permissions = await service.checkPermissions();
      sendJson(res, 200, permissions);
      return;
    }

    const permMatch = /^\/api\/permissions\/([a-z-]+)$/.exec(pathname);
    if (method === 'POST' && permMatch) {
      await readJsonObject(req);
      const action = permMatch[1];
      switch (action) {
        case 'request-accessibility':
          sendJson(res, 200, await service.requestAccessibility());
          return;
        case 'open-accessibility':
          sendJson(res, 200, await service.openAccessibilitySettings());
          return;
        case 'request-input-monitoring':
          sendJson(res, 200, await service.requestInputMonitoring());
          return;
        case 'open-input-monitoring':
          sendJson(res, 200, await service.openInputMonitoringSettings());
          return;
        default:
          throw new HttpRouteError(404, 'unknown-permission-action');
      }
    }

    if (method === 'POST' && pathname === '/api/capture/start') {
      const body = await readJsonObject(req);
      const normalized = validateCaptureStartOptions(body);
      const status = await service.start(normalized);
      sendJson(res, 200, status);
      return;
    }

    if (method === 'POST' && pathname === '/api/capture/pause') {
      await readJsonObject(req);
      sendJson(res, 200, await service.pause());
      return;
    }

    if (method === 'POST' && pathname === '/api/capture/resume') {
      await readJsonObject(req);
      sendJson(res, 200, await service.resume());
      return;
    }

    if (method === 'POST' && pathname === '/api/capture/stop') {
      await readJsonObject(req);
      sendJson(res, 200, await service.stop());
      return;
    }

    if (method === 'POST' && pathname === '/api/service/reload') {
      const body = await readJsonObject(req);
      const rawMode = body.mode;
      const mode: ReloadMode = rawMode === undefined ? 'collector' : (rawMode as ReloadMode);
      if (mode !== 'collector' && mode !== 'server') {
        throw new HttpRouteError(400, 'invalid-reload-mode');
      }

      if (mode === 'collector') {
        const status = await service.reloadCollector();
        const result: ReloadResult = {
          ok: true,
          mode: 'collector',
          restarted: true,
          resumed: status.state === 'running',
          status,
        };
        sendJson(res, 200, result);
        return;
      }

      if (!triggerServerRestart) {
        sendJson(res, 501, { error: 'server-restart-unavailable' });
        return;
      }

      const current = await service.status();
      const wasRunning = current.state === 'running';
      const result: ReloadResult = {
        ok: true,
        mode: 'server',
        restarted: true,
        resumed: wasRunning,
      };
      sendJson(res, 202, result, {
        closeConnection: true,
        onFlushed: () => {
          void triggerServerRestart().catch(() => {});
        },
      });
      return;
    }

    if (method === 'POST' && pathname === '/api/history/search') {
      const body = await readJsonObject(req);
      const query = parseHistoryQuery(body);
      sendJson(res, 200, await service.search(query));
      return;
    }

    if (method === 'POST' && pathname === '/api/history/read') {
      const body = await readJsonObject(req);
      const rawId = body.id ?? body.eventId ?? body.snapshotId;
      if (typeof rawId !== 'string' || rawId.trim() === '') {
        throw new HttpRouteError(400, 'invalid-history-id');
      }
      sendJson(res, 200, await service.read(rawId.trim()));
      return;
    }

    if (method === 'POST' && pathname === '/api/history/layout') {
      const body = await readJsonObject(req);
      const layoutReq = parseLayoutRequest(body);
      sendJson(res, 200, await service.layout(layoutReq));
      return;
    }

    if (method === 'POST' && pathname === '/api/history/forget') {
      const body = await readJsonObject(req);
      const forgetReq = parseForgetRequest(body);
      sendJson(res, 200, await service.forget(forgetReq));
      return;
    }

    if (method === 'POST' && pathname === '/api/source/open') {
      const body = await readJsonObject(req);
      const openReq = parseOpenSourceRequest(body);
      sendJson(res, 200, await service.openSource(openReq));
      return;
    }

    if (method === 'GET' && pathname === '/api/leases') {
      sendJson(res, 200, { leases: authStore.listLeases() });
      return;
    }

    if (method === 'POST' && pathname === '/api/leases') {
      const body = await readJsonObject(req);
      const created = await authStore.createLease({
        label: body.label as CreateLeaseRequest['label'],
        scopes: body.scopes as CreateLeaseRequest['scopes'],
        ttlMs: (body.ttlMs ?? null) as CreateLeaseRequest['ttlMs'],
      });
      sendJson(res, 201, created);
      return;
    }

    const leaseDeleteMatch = /^\/api\/leases\/([^/]+)$/.exec(pathname);
    if (method === 'DELETE' && leaseDeleteMatch?.[1]) {
      const id = decodeURIComponent(leaseDeleteMatch[1]);
      const revoked = await authStore.revokeLease(id);
      if (!revoked) {
        throw new HttpRouteError(404, 'lease-not-found');
      }
      sendJson(res, 200, { revoked: true, lease: revoked });
      return;
    }

    if (method === 'POST' && pathname === '/api/admin/rotate-token') {
      await readJsonObject(req);
      const token = await authStore.rotateAdminToken();
      sendJson(res, 200, { token });
      return;
    }

    throw new HttpRouteError(404, 'not-found');
  };

  const handleStatic = async (req: IncomingMessage, res: ServerResponse, pathname: string): Promise<void> => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.setHeader('Allow', 'GET, HEAD');
      sendJson(res, 405, { error: 'method-not-allowed' });
      return;
    }

    if (pathname === '/' || pathname === '/index.html') {
      const builtHtml = await readSafeStaticFile(join(webDistDir, 'index.html'));
      const htmlBuf = builtHtml ?? Buffer.from(FALLBACK_INDEX_HTML, 'utf8');
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Content-Length': htmlBuf.byteLength,
      });
      if (req.method === 'HEAD') {
        res.end();
      } else {
        res.end(htmlBuf);
      }
      return;
    }

    if (pathname === '/icon.svg') {
      const iconBuf =
        (await readSafeStaticFile(join(webDistDir, 'icon.svg'))) ??
        (await readSafeStaticFile(join(pkgRoot, 'icon.svg')));
      if (!iconBuf) {
        sendJson(res, 404, { error: 'not-found' });
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
        'Content-Length': iconBuf.byteLength,
      });
      res.end(req.method === 'HEAD' ? undefined : iconBuf);
      return;
    }

    const ext = extname(pathname).toLowerCase();
    const contentType = STATIC_CONTENT_TYPES[ext];
    if (!contentType) {
      sendJson(res, 404, { error: 'not-found' });
      return;
    }

    const candidate = resolve(webDistDir, `.${pathname}`);
    if (!candidate.startsWith(`${webDistDir}${sep}`)) {
      sendJson(res, 403, { error: 'forbidden' });
      return;
    }

    const assetBuf = await readSafeStaticFile(candidate);
    if (!assetBuf) {
      sendJson(res, 404, { error: 'not-found' });
      return;
    }

    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      'Content-Length': assetBuf.byteLength,
    });
    res.end(req.method === 'HEAD' ? undefined : assetBuf);
  };

  const server = createServer((req, res) => {
    void (async () => {
      if (!isLoopbackHostHeader(req.headers.host)) {
        sendJson(res, 403, { error: 'invalid-host' });
        return;
      }

      let parsedUrl: URL;
      try {
        parsedUrl = new URL(req.url ?? '/', 'http://127.0.0.1');
      } catch {
        sendJson(res, 400, { error: 'invalid-url' });
        return;
      }
      const pathname = parsedUrl.pathname;

      if (pathname === '/mcp') {
        await mcpHandler(req, res);
        return;
      }

      if (pathname === '/api' || pathname.startsWith('/api/')) {
        try {
          await handleApi(req, res, pathname, parsedUrl.searchParams);
        } catch (err) {
          if (err instanceof HttpRouteError) {
            sendJson(res, err.status, { error: err.message });
            return;
          }
          if (err instanceof AuthValidationError) {
            sendJson(res, 400, { error: err.code, message: err.message });
            return;
          }
          const message = err instanceof Error ? err.message : 'operation-failed';
          sendJson(res, 400, { error: message });
        }
        return;
      }

      await handleStatic(req, res, pathname);
    })().catch((err) => {
      if (!res.headersSent) {
        sendJson(res, 500, { error: err instanceof Error ? err.message : 'internal-server-error' });
      } else {
        res.destroy();
      }
    });
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    const onError = (err: Error) => {
      server.off('listening', onListening);
      rejectListen(err);
    };
    const onListening = () => {
      server.off('error', onError);
      resolveListen();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(requestedPort, host);
  });

  const addr = server.address();
  if (!addr || typeof addr === 'string') {
    throw new Error('unexpected-server-address');
  }
  actualPort = (addr as AddressInfo).port;

  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    server.closeAllConnections();
    await new Promise<void>((resolveClose, rejectClose) => {
      server.close((err) => {
        if (err) rejectClose(err);
        else resolveClose();
      });
    });
    await authStore.close();
    if (closeServiceOnStop) {
      await service.close();
    }
  };

  const baseUrl = `http://${host}:${actualPort}`;
  return {
    server,
    host,
    port: actualPort,
    baseUrl,
    mcpUrl: `${baseUrl}/mcp`,
    get adminToken() {
      return authStore.getAdminToken();
    },
    authStore,
    service,
    close,
  };
}

import type {
  CaptureStartOptions,
  ClientLease,
  CreateLeaseRequest,
  CreateLeaseResponse,
  HistoryForgetRequest,
  HistoryForgetResult,
  HistoryLayoutRequest,
  HistoryLayoutResult,
  HistoryQuery,
  HistoryQueryResult,
  HistoryReadResult,
  OpenSourceRequest,
  OpenSourceResult,
  PermissionStatus,
  ReloadMode,
  ReloadResult,
  ServiceStatus,
  StatusApiResponse,
} from '../shared/api-types.ts';

const TOKEN_STORAGE_KEY = 'chmcp_admin_token';

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function consumeHashToken(): string | null {
  const rawHash = window.location.hash.startsWith('#') ? window.location.hash.slice(1) : '';
  if (!rawHash) return getAdminToken();
  const token = new URLSearchParams(rawHash).get('token')?.trim() ?? '';
  if (token) {
    setAdminToken(token);
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
    return token;
  }
  return getAdminToken();
}

export const getAdminToken = (): string | null => sessionStorage.getItem(TOKEN_STORAGE_KEY);
export const setAdminToken = (token: string): void => sessionStorage.setItem(TOKEN_STORAGE_KEY, token.trim());
export const clearAdminToken = (): void => sessionStorage.removeItem(TOKEN_STORAGE_KEY);

async function request<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  const token = getAdminToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const init: RequestInit = { method, headers };
  if (body !== undefined) init.body = JSON.stringify(body);
  const res = await fetch(path, init);
  if (res.status === 204) return undefined as T;
  const payload = (await res.json().catch(() => null)) as Record<string, unknown> | null;
  if (!res.ok) {
    const msg = typeof payload?.error === 'string' ? payload.error : `HTTP ${res.status}`;
    throw new ApiError(res.status, msg);
  }
  return payload as T;
}

const unwrapStatus = (res: ServiceStatus | { status: ServiceStatus }): ServiceStatus =>
  'status' in res && typeof res.status === 'object' && res.status !== null ? res.status : (res as ServiceStatus);

export const api = {
  checkAuth: () => request<{ authenticated: boolean }>('/api/auth/check'),
  getStatus: (options?: { includePermissions?: boolean }) =>
    request<StatusApiResponse>(
      options?.includePermissions === false ? '/api/status?permissions=0' : '/api/status',
    ),
  initializeKey: () => request<ServiceStatus | { status: ServiceStatus }>('/api/key/init', 'POST').then(unwrapStatus),
  checkPermissions: () => request<PermissionStatus>('/api/permissions'),
  permissionAction: (
    action: 'request-accessibility' | 'open-accessibility' | 'request-input-monitoring' | 'open-input-monitoring',
  ) => request<PermissionStatus>(`/api/permissions/${action}`, 'POST'),
  startCapture: (options: CaptureStartOptions) =>
    request<ServiceStatus | { status: ServiceStatus }>('/api/capture/start', 'POST', options).then(unwrapStatus),
  pauseCapture: () =>
    request<ServiceStatus | { status: ServiceStatus }>('/api/capture/pause', 'POST').then(unwrapStatus),
  resumeCapture: () =>
    request<ServiceStatus | { status: ServiceStatus }>('/api/capture/resume', 'POST').then(unwrapStatus),
  stopCapture: () =>
    request<ServiceStatus | { status: ServiceStatus }>('/api/capture/stop', 'POST').then(unwrapStatus),
  reloadService: (mode: ReloadMode = 'collector') =>
    request<ReloadResult>('/api/service/reload', 'POST', { mode }),
  getLeases: () =>
    request<ClientLease[] | { leases: ClientLease[] }>('/api/leases').then((r) => (Array.isArray(r) ? r : r.leases)),
  createLease: (body: CreateLeaseRequest) => request<CreateLeaseResponse>('/api/leases', 'POST', body),
  revokeLease: (id: string) => request<unknown>(`/api/leases/${encodeURIComponent(id)}`, 'DELETE'),
  searchHistory: (query: HistoryQuery) => request<HistoryQueryResult>('/api/history/search', 'POST', query),
  readHistory: (id: string) => request<HistoryReadResult>('/api/history/read', 'POST', { id }),
  getHistoryLayout: (req: HistoryLayoutRequest) => request<HistoryLayoutResult>('/api/history/layout', 'POST', req),
  forgetHistory: (req: HistoryForgetRequest) => request<HistoryForgetResult>('/api/history/forget', 'POST', req),
  openSource: (req: OpenSourceRequest) => request<OpenSourceResult>('/api/source/open', 'POST', req),
};

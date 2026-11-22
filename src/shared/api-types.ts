import type { CaptureDiagnostics, GapDiagnostic, Observation } from './protocol/generated.ts';
import type {
  HistoryLayoutNode,
  HistoryLayoutPage,
  HistoryLayoutRequest,
  HistoryLayoutResult,
  HistoryLayoutUnavailable,
} from './history-layout.ts';

export type {
  HistoryLayoutNode,
  HistoryLayoutPage,
  HistoryLayoutRequest,
  HistoryLayoutResult,
  HistoryLayoutUnavailable,
};

export interface NormalizedCaptureStartOptions {
  applicationScope: 'allowlist' | 'denylist';
  allowedApplicationIds: string[];
  excludedApplicationIds: string[];
  allowBrowserContent: boolean;
  fieldSecurity: 'strict' | 'denylist';
  axCompatibility: boolean;
  textMarkers: boolean;
  captureScope: 'focused' | 'region' | 'window';
  maxTreeNodes: number;
  inputText: boolean;
  selectionCapture: boolean;
  inputActivity: boolean;
  menuActions: boolean;
  textRange: 'prefix' | 'visible';
  maxTextCodeUnits: number;
  sampleIntervalMs: number;
}

export type CaptureStartOptions = {
  [K in keyof NormalizedCaptureStartOptions]?: NormalizedCaptureStartOptions[K] | undefined;
};

export type ServiceLifecycleState =
  | 'not-initialized'
  | 'stopped'
  | 'starting'
  | 'running'
  | 'paused'
  | 'failed';

export type PermissionGrantState = 'granted' | 'not-granted' | 'unknown' | 'not-applicable';

export interface PermissionStatus {
  platform: string;
  accessibility: PermissionGrantState;
  inputMonitoring: PermissionGrantState;
  desktopStatus: 'unlocked' | 'locked' | 'unknown';
  desktopReason: string;
  promptRequested?: boolean;
  settingsOpened?: boolean;
  checkedAtMs: number;
}

export interface StorageRecordCounts {
  text: number;
  surface: number;
  selection: number;
  inputText: number;
  activity: number;
  menu: number;
  context: number;
  gap: number;
  gapDiscarded: number;
  gapException: number;
}

export interface StorageStatusSummary {
  state: 'open' | 'closed' | 'failed';
  storeId: string;
  generation: number;
  segments: number;
  records: number;
  bytes: number;
  retentionMs: number;
  maxBytes: number;
  forgetBeforeMs: number;
  retainedTimeRange: { fromTimeMs: number; toTimeMs: number } | null;
  counts: StorageRecordCounts;
}

export interface CollectorAcceptedCounts {
  text: number;
  surface: number;
  selection: number;
  inputText: number;
  activity: number;
  menu: number;
  gaps: number;
  gapsDiscarded: number;
  gapsException: number;
}

export interface CollectorStatusSummary {
  state: 'stopped' | 'starting' | 'running' | 'paused' | 'failed';
  reason: string;
  instanceId: string | null;
  received: number;
  dropped: number;
  pending: number;
  accepted: CollectorAcceptedCounts;
  lastGapReason: string | null;
  lastGapDiagnostic: GapDiagnostic | null;
  lastExceptionReason: string | null;
  lastExceptionDiagnostic: GapDiagnostic | null;
  captureDiagnostics: CaptureDiagnostics | null;
}

export type AdapterMode = 'declarative' | 'custom' | 'fallback';

export interface AdapterSummary {
  id: string;
  name: string;
  bundleIds: string[];
  mode: AdapterMode;
}

export interface ServiceStatus {
  state: ServiceLifecycleState;
  reason: string;
  platform: string;
  deviceId: string;
  dataRoot: string;
  activeScope: NormalizedCaptureStartOptions | null;
  mandatoryExcludedApplicationIds: string[];
  storage: StorageStatusSummary | null;
  collector: CollectorStatusSummary | null;
  adapters: AdapterSummary[];
}

export interface StdioLauncherSpec {
  command: string;
  args: string[];
}

export interface StatusApiResponse {
  status: ServiceStatus;
  permissions?: PermissionStatus;
  dataRoot: string;
  stdioLauncher?: StdioLauncherSpec;
}

export const HISTORY_QUERY_KINDS = [
  'all',
  'text',
  'gap',
  'exception',
  'discarded',
  'context',
  'activity',
  'menu',
  'surface',
  'selection',
  'input',
] as const;

export type HistoryQueryKind = (typeof HISTORY_QUERY_KINDS)[number];

export type HistoryTextView = 'full' | 'delta';

export interface HistoryTextDelta {
  baseEventId: string;
  start: number;
  deleteCount: number;
  insert: string;
  totalLength: number;
}

export interface HistoryQuery {
  fromTimeMs?: number;
  toTimeMs?: number;
  applicationId?: string;
  text?: string;
  kind?: HistoryQueryKind;
  textView?: HistoryTextView;
  limit?: number;
  maxBytes?: number;
  order?: 'asc' | 'desc';
  cursor?: string;
}

export interface HistoryQueryResult {
  records: Observation[];
  truncated: boolean;
  bytes: number;
  hasMore: boolean;
  nextCursor?: string;
  textDeltas?: Record<string, HistoryTextDelta>;
}

export interface HistoryReadResult {
  found: boolean;
  record: Observation | null;
}

export interface HistoryForgetRequest {
  beforeMs?: number;
  all?: boolean;
}

export interface HistoryForgetResult {
  deletedSegments: number;
  remainingRecords: number;
  remainingBytes: number;
  forgetBeforeMs: number;
  generation: number;
}

export interface OpenSourceRequest {
  eventId?: string;
  applicationId?: string;
}

export interface OpenSourceResult {
  outcome: 'activated' | 'refused' | 'uncertain';
  reason: string;
}

export type ClientScope = 'read' | 'pause' | 'reload';

export type ReloadMode = 'collector' | 'server';

export interface ReloadResult {
  ok: true;
  mode: ReloadMode;
  restarted: boolean;
  resumed: boolean;
  status?: ServiceStatus;
}

export interface ClientLease {
  id: string;
  label: string;
  scopes: ClientScope[];
  createdAtMs: number;
  expiresAtMs: number | null;
  revokedAtMs: number | null;
  lastUsedAtMs: number | null;
}

export interface StoredClientLease extends ClientLease {
  tokenSha256: string;
}

export interface CreateLeaseRequest {
  label: string;
  scopes: ClientScope[];
  ttlMs: number | null;
}

export interface CreateLeaseResponse {
  lease: ClientLease;
  token: string;
}

export interface HistoryServiceContract {
  status(): Promise<ServiceStatus>;
  initializeKey(): Promise<ServiceStatus>;
  checkPermissions(): Promise<PermissionStatus>;
  requestAccessibility(): Promise<PermissionStatus>;
  openAccessibilitySettings(): Promise<PermissionStatus>;
  requestInputMonitoring(): Promise<PermissionStatus>;
  openInputMonitoringSettings(): Promise<PermissionStatus>;
  start(options: CaptureStartOptions): Promise<ServiceStatus>;
  pause(): Promise<ServiceStatus>;
  resume(): Promise<ServiceStatus>;
  stop(): Promise<ServiceStatus>;
  reloadCollector(): Promise<ServiceStatus>;
  search(query: HistoryQuery): Promise<HistoryQueryResult>;
  read(id: string): Promise<HistoryReadResult>;
  layout(req: HistoryLayoutRequest): Promise<HistoryLayoutResult>;
  forget(req: HistoryForgetRequest): Promise<HistoryForgetResult>;
  openSource(req: OpenSourceRequest): Promise<OpenSourceResult>;
  close(): Promise<void>;
}

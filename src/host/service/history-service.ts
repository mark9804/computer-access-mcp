import { constants, lstatSync, readFileSync } from 'node:fs';
import { open as openFile } from 'node:fs/promises';
import { hostname } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  CaptureStartOptions,
  HistoryForgetRequest,
  HistoryForgetResult,
  HistoryLayoutRequest,
  HistoryLayoutResult,
  HistoryQuery,
  HistoryQueryResult,
  HistoryReadResult,
  HistoryServiceContract,
  NormalizedCaptureStartOptions,
  OpenSourceRequest,
  OpenSourceResult,
  PermissionStatus,
  ServiceStatus,
} from '../../shared/api-types.ts';
import {
  BUILT_IN_ADAPTERS,
  MANDATORY_EXCLUDED_APPLICATION_IDS,
  validateCaptureStartOptions,
} from '../../shared/app-policy.ts';
import type { CapturePolicy, Observation } from '../../shared/protocol/generated.ts';
import { KEY_ERROR_CODES, KeyProviderError, safeKeyDiagnostic } from '../../storage/errors.ts';
import type { KeyDiagnostic } from '../../storage/errors.ts';
import { createPlatformKeyProvider } from '../../storage/key-provider.ts';
import type { KeyProvider } from '../../storage/key-provider.ts';
import { defaultDataRoot } from '../../storage/platform-paths.ts';
import { HISTORY_MAX_BYTES, HISTORY_RETENTION_MS, SegmentStore } from '../../storage/segment-store.ts';
import { CollectorDebugLog } from '../collectors/debug-log.ts';
import { EvidenceCorrelator } from '../collectors/evidence-correlator.ts';
import { spawnLocal } from '../collectors/local-process.ts';
import type { SpawnManaged } from '../collectors/process.ts';
import { CollectorSupervisor } from '../collectors/supervisor.ts';
import { verifyNativeBinary } from './binaries.ts';
import { createPermissionActions, PermissionActionError, toPermissionStatus } from './permissions.ts';
import type { PermissionAction } from './permissions.ts';
import { createSourceNavigation } from './source-navigation.ts';

export type { HistoryQuery } from '../../shared/api-types.ts';

export class HistoryOperationError extends Error {
  readonly code: string;
  readonly diagnostic: KeyDiagnostic | undefined;

  constructor(code: string, diagnostic?: KeyDiagnostic) {
    super(code);
    this.name = 'HistoryOperationError';
    this.code = code;
    this.diagnostic = safeKeyDiagnostic(diagnostic);
  }
}

export interface HistoryServiceOptions {
  root?: string;
  dataRoot?: string;
  helperPath?: string;
  collectorPath?: string;
  keyHelperPath?: string;
  keyStorePath?: string;
  deviceId?: string;
  debugTrace?: boolean;
  keyProvider?: KeyProvider;
  spawn?: SpawnManaged;
  platform?: NodeJS.Platform;
  retentionMs?: number;
  maxBytes?: number;
  maxSegmentBytes?: number;
}

const DEVICE_ID_FILENAME = 'device.id';
const DEVICE_ID_PATTERN = /^[A-Za-z0-9._-]{1,96}$/;

function defaultDeviceId(): string {
  const cleaned = hostname()
    .replace(/[^A-Za-z0-9._-]/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
  return cleaned.length > 0 ? cleaned : 'local-device';
}

function readPersistedDeviceId(dataRoot: string): string | null {
  const filePath = join(dataRoot, DEVICE_ID_FILENAME);
  try {
    const stat = lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0 || stat.size > 128) {
      return null;
    }
    const raw = readFileSync(filePath, 'utf8').trim();
    return DEVICE_ID_PATTERN.test(raw) ? raw : null;
  } catch {
    return null;
  }
}

async function persistDeviceIdIfMissing(dataRoot: string, deviceId: string, platform: NodeJS.Platform): Promise<void> {
  const filePath = join(dataRoot, DEVICE_ID_FILENAME);
  const flags =
    constants.O_CREAT |
    constants.O_EXCL |
    constants.O_WRONLY |
    (typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0);
  try {
    const handle = await openFile(filePath, flags, platform === 'win32' ? undefined : 0o600);
    try {
      await handle.writeFile(`${deviceId}\n`, 'utf8');
      await handle.datasync();
    } finally {
      await handle.close();
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      return;
    }
  }
}

const SAFE_REASONS = new Set<string>([
  'content-capability-unavailable',
  'input-monitoring-required',
  'input-monitoring-unavailable',
  'input-monitoring-disabled',
  'worker-retirement-ack-failed',
  'worker-retirement-exit-unconfirmed',
  'input-activity-policy-invalid',
  'input-activity-identity-changed',
  'text-range-policy-invalid',
  'sample-interval-invalid',
  'text-visible-range-unavailable',
  'invalid-capture-options',
  'invalid-allowed-application-ids',
  'invalid-excluded-application-ids',
  'invalid-input',
  'invalid-cursor',
  'cursor-expired',
  'invalid-layout-query',
  'invalid-layout-position',
  'layout-budget-too-small',
  'snapshot-ambiguous',
  'navigation-cancelled',
  ...KEY_ERROR_CODES,
  'already-owned',
  'native-lock-unavailable',
  'unsafe-path',
  'unsafe-permissions',
  'authentication-failed',
  'invalid-store',
  'budget-exceeded',
  'io-failure',
  'stale-generation',
  'configuration-invalid',
  'unsupported-platform',
  'native-path-must-be-absolute',
  'unsafe-native-file',
  'unsafe-native-manifest',
  'native-manifest-mismatch',
  'native-manifest-entry-missing',
  'native-hash-mismatch',
  'native-resource-manifest-missing',
  'unsafe-native-resource',
  'native-resource-mismatch',
  'application-allowlist-invalid',
  'text-budget-invalid',
  'start-cancelled',
  'user-resume-required',
  'already-running',
  'collector-not-running',
  'collector-not-paused',
  'stop-failed',
  'pause-failed',
  'permission-denied',
  'permission-action-busy',
  'permission-action-cancelled',
  'permission-action-timeout',
  'permission-helper-unavailable',
  'permission-helper-exit-failed',
  'permission-helper-exit-unconfirmed',
  'permission-response-invalid',
  'desktop-unavailable',
  'session-unavailable',
  'console-unavailable',
  'login-incomplete',
  'lock-state-unavailable',
  'screen-locked',
  'desktop-signal-invalid',
  'desktop-session-changed',
  'desktop-session-mismatch',
  'desktop-lock-transition',
  'secure-input-indicated',
  'secure-input-active',
  'secure-input-suppressed',
  'helper-exit-unconfirmed',
]);

function safeReason(error: unknown): string {
  const code =
    error && typeof error === 'object' && 'code' in error
      ? error.code
      : error instanceof Error
        ? error.message
        : undefined;
  return typeof code === 'string' && SAFE_REASONS.has(code) ? code : 'operation-failed';
}

function toWireCapturePolicy(scope: NormalizedCaptureStartOptions): CapturePolicy {
  return {
    enabled: true,
    applicationScope: scope.applicationScope,
    allowedApplicationIds: [...scope.allowedApplicationIds],
    excludedApplicationIds: [...scope.excludedApplicationIds],
    allowBrowserContent: scope.allowBrowserContent,
    fieldSecurity: scope.fieldSecurity,
    axCompatibility: scope.axCompatibility,
    textMarkers: scope.textMarkers,
    captureScope: scope.captureScope,
    maxTreeNodes: scope.maxTreeNodes,
    inputText: scope.inputText,
    selectionCapture: scope.selectionCapture,
    inputActivity: scope.inputActivity,
    menuActions: scope.menuActions,
    textRange: scope.textRange,
    maxTextCodeUnits: scope.maxTextCodeUnits,
    sampleIntervalMs: scope.sampleIntervalMs,
    maxPending: 16,
    debounceMs: 150,
    maxWaitMs: 1000,
    readTimeoutMs: 1500,
  };
}

export function createHistoryService(options: HistoryServiceOptions = {}): HistoryServiceContract {
  const platform = options.platform ?? process.platform;
  const dataRoot = options.dataRoot ?? options.root ?? defaultDataRoot(platform);
  const exeSuffix = platform === 'win32' ? '.exe' : '';
  const defaultCollectorPath = fileURLToPath(
    new URL(`../../../native-bin/computer-access-collector${exeSuffix}`, import.meta.url),
  );
  const defaultKeyHelperPath = fileURLToPath(
    new URL(`../../../native-bin/computer-access-key-store${exeSuffix}`, import.meta.url),
  );
  const helperPath = options.helperPath ?? options.collectorPath ?? defaultCollectorPath;
  const keyHelperPath = options.keyHelperPath ?? options.keyStorePath ?? defaultKeyHelperPath;
  const deviceId = options.deviceId ?? readPersistedDeviceId(dataRoot) ?? defaultDeviceId();
  const debugTrace = options.debugTrace === true;
  const spawn = options.spawn ?? spawnLocal;
  const retentionMs = options.retentionMs ?? HISTORY_RETENTION_MS;
  const maxBytes = options.maxBytes ?? HISTORY_MAX_BYTES;

  if (!isAbsolute(dataRoot) || !DEVICE_ID_PATTERN.test(deviceId)) {
    throw new Error('configuration-invalid');
  }

  const usesCustomKeyProvider = options.keyProvider !== undefined;
  const keyProvider: KeyProvider =
    options.keyProvider ??
    createPlatformKeyProvider({
      platform,
      dataRoot,
      keyHelperPath,
      deviceId,
      spawn,
    });

  const permissions = createPermissionActions({ executable: helperPath, spawn, platform });
  const navigator = createSourceNavigation({ executable: helperPath, spawn });
  const correlator = new EvidenceCorrelator();
  const debugLog = new CollectorDebugLog(join(dataRoot, 'debug-log'), debugTrace);

  let store: SegmentStore | undefined;
  let collector: CollectorSupervisor | undefined;
  let activeScope: NormalizedCaptureStartOptions | null = null;
  let closed = false;
  let reason = '';
  let operations: Promise<void> = Promise.resolve();
  let sourceGeneration = 0;
  let controlEpoch = 0;
  let navigationEpoch = 0;
  let navigationPending = false;
  let retentionTimer: ReturnType<typeof setInterval> | undefined;
  let pruning = false;

  const exclusive = <T>(task: () => Promise<T>): Promise<T> => {
    const next = operations.then(async () => {
      if (closed) throw new Error('service-closed');
      try {
        return await task();
      } catch (error) {
        if (error instanceof PermissionActionError) {
          reason = safeReason(error);
          throw new HistoryOperationError(reason);
        }
        reason = safeReason(error);
        const diag = error instanceof KeyProviderError ? error.diagnostic : undefined;
        throw new HistoryOperationError(reason, diag);
      }
    });
    operations = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  };

  async function verifyKeyHelperIfNeeded(): Promise<void> {
    if (!usesCustomKeyProvider && platform === 'darwin') {
      await verifyNativeBinary(keyHelperPath, 'computer-access-key-store');
    }
  }

  async function openStore(assertActive: () => void = () => {}): Promise<SegmentStore> {
    assertActive();
    if (store) return store;
    await verifyKeyHelperIfNeeded();
    assertActive();
    store = await SegmentStore.open({
      root: dataRoot,
      keyProvider,
      retentionMs,
      maxBytes,
      ...(options.maxSegmentBytes !== undefined ? { maxSegmentBytes: options.maxSegmentBytes } : {}),
      platform,
    });
    await persistDeviceIdIfMissing(dataRoot, deviceId, platform);
    if (!closed && !retentionTimer) {
      retentionTimer = setInterval(() => {
        if (!store || closed || pruning) return;
        pruning = true;
        void store
          .pruneExpired()
          .catch(() => {
            reason = 'retention-failed';
            sourceGeneration++;
            controlEpoch++;
            correlator.clear();
            void collector?.stop().catch(() => {
              reason = 'helper-exit-unconfirmed';
            });
          })
          .finally(() => {
            pruning = false;
          });
      }, 60_000);
      retentionTimer.unref();
    }
    return store;
  }

  function snapshotStatus(): ServiceStatus {
    const collectorState = collector?.status() ?? null;
    const lifecycleState = closed
      ? 'stopped'
      : collectorState?.state ?? (store ? 'stopped' : 'not-initialized');

    return {
      state: lifecycleState,
      reason: collectorState?.reason || reason || '',
      platform,
      deviceId,
      dataRoot,
      activeScope: activeScope ? structuredClone(activeScope) : null,
      mandatoryExcludedApplicationIds: [...MANDATORY_EXCLUDED_APPLICATION_IDS],
      storage: store?.status() ?? null,
      collector: collectorState,
      adapters: BUILT_IN_ADAPTERS.map((adapter) => ({
        ...adapter,
        bundleIds: [...adapter.bundleIds],
      })),
    };
  }

  async function runPermissionAction(action: PermissionAction): Promise<PermissionStatus> {
    if (platform === 'darwin') {
      const report = await permissions.perform(action);
      return toPermissionStatus(report, platform);
    }
    if (platform === 'win32') {
      if (action === 'check') {
        const report = await permissions.perform('check');
        return toPermissionStatus(report, platform);
      }
      return {
        platform,
        accessibility: 'not-applicable',
        inputMonitoring: 'not-applicable',
        desktopStatus: 'unknown',
        desktopReason: 'lock-state-unavailable',
        promptRequested: false,
        settingsOpened: false,
        checkedAtMs: Date.now(),
      };
    }
    return {
      platform,
      accessibility: 'not-applicable',
      inputMonitoring: 'not-applicable',
      desktopStatus: 'unlocked',
      desktopReason: 'ready',
      promptRequested: false,
      settingsOpened: false,
      checkedAtMs: Date.now(),
    };
  }

  async function startInternal(
    normalized: NormalizedCaptureStartOptions,
    expectedEpoch: number,
  ): Promise<ServiceStatus> {
    const assertCurrent = () => {
      if (closed || expectedEpoch !== controlEpoch) {
        throw new Error('start-cancelled');
      }
    };

    assertCurrent();
    if (collector && collector.status().state !== 'stopped' && collector.status().state !== 'failed') {
      throw new Error('already-running');
    }
    if (collector) {
      const stopped = await collector.stop();
      if (stopped.reason === 'helper-exit-unconfirmed') {
        throw new Error(stopped.reason);
      }
    }

    assertCurrent();
    const persistence = await openStore(assertCurrent);
    assertCurrent();
    const binary = await verifyNativeBinary(helperPath, 'computer-access-collector');
    assertCurrent();

    if (debugTrace) {
      await debugLog.prepare();
      assertCurrent();
    }

    correlator.clear();
    const activeGeneration = ++sourceGeneration;
    const storageGeneration = persistence.generation;
    let starting = true;

    activeScope = structuredClone(normalized);
    const wirePolicy = toWireCapturePolicy(normalized);

    collector = new CollectorSupervisor({
      helperPath: binary.path,
      cwd: dataRoot,
      deviceId,
      spawn,
      debugTrace,
      ...(debugTrace ? { debugLog } : {}),
      onObservation: async (observation: Observation, isCurrent) => {
        const stillAllowed = () => {
          if (closed || activeGeneration !== sourceGeneration || !isCurrent()) return false;
          try {
            if (starting) assertCurrent();
            return true;
          } catch {
            return false;
          }
        };
        if (!stillAllowed()) return;
        try {
          const related = correlator.preview(observation);
          await persistence.append(related, {
            generation: storageGeneration,
            isCurrent: stillAllowed,
          });
          if (stillAllowed()) {
            correlator.commit(related);
          }
        } catch (error) {
          if (error && typeof error === 'object' && 'code' in error && error.code === 'stale-generation') {
            return;
          }
          throw new Error('history-write-failed');
        }
      },
    });

    try {
      await collector.start(wirePolicy);
      try {
        assertCurrent();
      } catch (error) {
        if (sourceGeneration === activeGeneration) sourceGeneration++;
        await collector.stop();
        throw error;
      }
      starting = false;
      reason = '';
      return snapshotStatus();
    } catch (error) {
      reason =
        collector.status().reason ||
        (error instanceof Error && error.message === 'start-cancelled' ? 'start-cancelled' : 'start-failed');
      throw new Error(reason);
    }
  }

  const service: HistoryServiceContract = {
    status: async () => snapshotStatus(),

    initializeKey: () =>
      exclusive(async () => {
        await verifyKeyHelperIfNeeded();
        const key = await keyProvider.getOrCreateKey();
        key.fill(0);
        await openStore();
        reason = '';
        return snapshotStatus();
      }),

    checkPermissions: () => exclusive(() => runPermissionAction('check')),
    requestAccessibility: () => exclusive(() => runPermissionAction('request-accessibility')),
    openAccessibilitySettings: () => exclusive(() => runPermissionAction('open-accessibility-settings')),
    requestInputMonitoring: () => exclusive(() => runPermissionAction('request-input-monitoring')),
    openInputMonitoringSettings: () => exclusive(() => runPermissionAction('open-input-monitoring-settings')),

    start: (input: CaptureStartOptions) => {
      const epoch = controlEpoch;
      return exclusive(async () => {
        const normalized = validateCaptureStartOptions(input);
        return startInternal(normalized, epoch);
      });
    },

    pause: () => {
      const running = collector;
      sourceGeneration++;
      controlEpoch++;
      navigationEpoch++;
      navigator.cancel();
      correlator.clear();
      const pausing = running?.pause().then(
        () => true,
        () => false,
      );
      return exclusive(async () => {
        if (!pausing) throw new Error('collector-not-running');
        if (!(await pausing)) throw new Error('pause-failed');
        await store?.barrier();
        await debugLog.flush();
        reason = '';
        return snapshotStatus();
      });
    },

    resume: () => {
      const epoch = controlEpoch;
      return exclusive(async () => {
        if (!collector || collector.status().state !== 'paused' || !activeScope) {
          throw new Error('collector-not-paused');
        }
        const savedScope = structuredClone(activeScope);
        const stopped = await collector.stop();
        if (stopped.reason === 'helper-exit-unconfirmed') {
          throw new Error(stopped.reason);
        }
        return startInternal(savedScope, epoch);
      });
    },

    stop: () => {
      sourceGeneration++;
      controlEpoch++;
      navigationEpoch++;
      navigator.cancel();
      correlator.clear();
      const running = collector;
      const stopping = running?.stop().then(
        (value) => ({ ok: true as const, value }),
        () => ({ ok: false as const }),
      );
      return exclusive(async () => {
        if (stopping) {
          const res = await stopping;
          if (!res.ok) throw new Error('stop-failed');
          if (res.value.reason === 'helper-exit-unconfirmed') {
            throw new Error(res.value.reason);
          }
        }
        await store?.barrier();
        await debugLog.flush();
        reason = '';
        return snapshotStatus();
      });
    },

    reloadCollector: () => {
      const epoch = controlEpoch;
      return exclusive(async () => {
        const wasRunning = collector?.status().state === 'running';
        const priorScope = activeScope ? structuredClone(activeScope) : null;

        if (collector) {
          sourceGeneration++;
          correlator.clear();
          const stopped = await collector.stop();
          if (stopped.reason === 'helper-exit-unconfirmed') {
            throw new Error(stopped.reason);
          }
          collector = undefined;
          await store?.barrier();
          await debugLog.flush();
        }

        // Never start capture if the service was stopped, paused, failed, or not-initialized.
        if (wasRunning && priorScope) {
          return startInternal(priorScope, epoch);
        }

        return snapshotStatus();
      });
    },

    search: (query: HistoryQuery = {}) =>
      exclusive(async () => {
        const persistence = await openStore();
        return persistence.search(query);
      }),

    read: (id: string): Promise<HistoryReadResult> =>
      exclusive(async () => {
        if (typeof id !== 'string' || id.length === 0 || id.length > 256) {
          throw new Error('invalid-input');
        }
        const persistence = await openStore();
        const record = await persistence.read(id);
        return { found: record !== null, record };
      }),

    layout: (req: HistoryLayoutRequest): Promise<HistoryLayoutResult> =>
      exclusive(async () => {
        const persistence = await openStore();
        return persistence.layout(req);
      }),

    forget: (req: HistoryForgetRequest): Promise<HistoryForgetResult> => {
      sourceGeneration++;
      controlEpoch++;
      navigationEpoch++;
      navigator.cancel();
      correlator.clear();
      const requested = structuredClone(req);
      const stopping = collector?.stop().then(
        (value) => ({ ok: true as const, value }),
        () => ({ ok: false as const }),
      );
      return exclusive(async () => {
        if (stopping) {
          const res = await stopping;
          if (!res.ok) throw new Error('stop-failed');
          if (res.value.reason === 'helper-exit-unconfirmed') {
            throw new Error(res.value.reason);
          }
        }
        const persistence = await openStore();
        const result = await persistence.forget(requested);
        reason = 'stopped-after-forget';
        return result;
      });
    },

    openSource: (req: OpenSourceRequest): Promise<OpenSourceResult> => {
      if (navigationPending) {
        return Promise.resolve({ outcome: 'refused', reason: 'navigation-busy' });
      }
      if (platform !== 'darwin' && platform !== 'win32') {
        return Promise.resolve({ outcome: 'refused', reason: 'unsupported-platform' });
      }
      if (
        !req ||
        typeof req !== 'object' ||
        (req.eventId === undefined && req.applicationId === undefined)
      ) {
        return Promise.resolve({ outcome: 'refused', reason: 'invalid-input' });
      }

      navigationPending = true;
      const epoch = navigationEpoch;
      return exclusive(async () => {
        const assertCurrent = () => {
          if (closed || navigationEpoch !== epoch) {
            throw new Error('navigation-cancelled');
          }
        };
        assertCurrent();

        const persistence = await openStore(assertCurrent);
        assertCurrent();

        let targetIdentity;
        if (req.eventId !== undefined) {
          if (typeof req.eventId !== 'string' || req.eventId.length === 0 || req.eventId.length > 256) {
            return { outcome: 'refused' as const, reason: 'invalid-input' };
          }
          const record = await persistence.read(req.eventId);
          assertCurrent();
          if (!record) {
            return { outcome: 'refused' as const, reason: 'source-not-found' };
          }
          if (record.target.kind === 'unresolved' || record.target.identity.deviceId !== deviceId) {
            return { outcome: 'refused' as const, reason: 'navigation-target-unavailable' };
          }
          targetIdentity = record.target.identity;
        } else {
          if (
            typeof req.applicationId !== 'string' ||
            req.applicationId.length === 0 ||
            req.applicationId.length > 256
          ) {
            return { outcome: 'refused' as const, reason: 'invalid-input' };
          }
          const latest = await persistence.latestApplicationTarget(req.applicationId);
          assertCurrent();
          if (!latest) {
            return { outcome: 'refused' as const, reason: 'source-not-found' };
          }
          if (latest.deviceId !== deviceId) {
            return { outcome: 'refused' as const, reason: 'navigation-target-unavailable' };
          }
          targetIdentity = latest;
        }

        const report = await navigator.navigate(targetIdentity, undefined, assertCurrent);
        return { outcome: report.outcome, reason: report.reason };
      }).finally(() => {
        navigationPending = false;
      });
    },

    close: async () => {
      if (closed) return;
      closed = true;
      sourceGeneration++;
      controlEpoch++;
      navigationEpoch++;
      navigator.cancel();
      correlator.clear();
      if (retentionTimer) clearInterval(retentionTimer);
      retentionTimer = undefined;

      let failed = false;
      try {
        await permissions.close();
      } catch {
        failed = true;
      }
      try {
        await navigator.close();
      } catch {
        failed = true;
      }
      try {
        if ((await collector?.stop())?.reason === 'helper-exit-unconfirmed') {
          failed = true;
        }
      } catch {
        failed = true;
      }
      await operations;
      await debugLog.close();
      try {
        await store?.close();
      } catch {
        failed = true;
      }
      store = undefined;
      if (failed) {
        throw new Error('shutdown-unconfirmed');
      }
    },
  };

  return service;
}

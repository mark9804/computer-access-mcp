import type {
  CaptureStartOptions,
  HistoryForgetRequest,
  HistoryForgetResult,
  HistoryLayoutPage,
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
  ServiceLifecycleState,
  ServiceStatus,
} from '../../src/shared/api-types.ts';
import {
  BUILT_IN_ADAPTERS,
  MANDATORY_EXCLUDED_APPLICATION_IDS,
  validateCaptureStartOptions,
} from '../../src/shared/app-policy.ts';
import { classifyGap } from '../../src/shared/gap-classification.ts';
import type { Observation, SurfaceNode, SurfaceSnapshot } from '../../src/shared/protocol/generated.ts';

export interface MockHistoryService extends HistoryServiceContract {
  readonly records: Observation[];
  readonly calls: string[];
  closed: boolean;
  seedObservation(obs: Observation): void;
}

function matchesKind(obs: Observation, kind: HistoryQuery['kind']): boolean {
  if (!kind || kind === 'all') return true;
  const pKind = obs.payload.kind;
  switch (kind) {
    case 'text':
      return pKind === 'text.snapshot' || pKind === 'text.changed';
    case 'gap':
      return pKind === 'gap';
    case 'exception':
      return obs.payload.kind === 'gap' && classifyGap(obs.payload) === 'exception';
    case 'discarded':
      return obs.payload.kind === 'gap' && classifyGap(obs.payload) === 'discarded';
    case 'context':
      return pKind === 'context.changed';
    case 'activity':
      return pKind === 'input.activity';
    case 'menu':
      return pKind === 'menu.action';
    case 'surface':
      return pKind === 'surface.snapshot';
    case 'selection':
      return pKind === 'selection.snapshot';
    case 'input':
      return pKind === 'input.text';
    default:
      return false;
  }
}

function extractSearchableText(obs: Observation): string {
  switch (obs.payload.kind) {
    case 'text.snapshot':
      return obs.payload.text ?? '';
    case 'text.changed':
      return obs.payload.after.text ?? '';
    case 'selection.snapshot':
      return obs.payload.text;
    case 'input.text':
      return obs.payload.text;
    case 'menu.action':
      return obs.payload.path.join(' > ');
    case 'surface.snapshot':
      return obs.payload.nodes.map((n: SurfaceNode) => n.text ?? '').join('\n');
    default:
      return '';
  }
}

function extractApplicationId(obs: Observation): string | null {
  if (obs.target.kind === 'resolved' || obs.target.kind === 'application') {
    return obs.target.identity.applicationId;
  }
  return null;
}

export function createMockHistoryService(dataRoot: string): MockHistoryService {
  let state: ServiceLifecycleState = 'not-initialized';
  let reason = 'key-not-initialized';
  let activeScope: NormalizedCaptureStartOptions | null = null;
  let generation = 1;
  let forgetBeforeMs = 0;
  const records: Observation[] = [];
  const calls: string[] = [];

  let permissions: PermissionStatus = {
    platform: 'darwin',
    accessibility: 'granted',
    inputMonitoring: 'granted',
    desktopStatus: 'unlocked',
    desktopReason: 'ready',
    checkedAtMs: 1_700_000_000_000,
  };

  const buildStatus = (): ServiceStatus => ({
    state,
    reason,
    platform: 'darwin',
    deviceId: 'test-device',
    dataRoot,
    activeScope,
    mandatoryExcludedApplicationIds: [...MANDATORY_EXCLUDED_APPLICATION_IDS],
    storage:
      state === 'not-initialized'
        ? null
        : {
            state: 'open',
            storeId: 'store_test_1',
            generation,
            segments: 1,
            records: records.length,
            bytes: Buffer.byteLength(JSON.stringify(records), 'utf8'),
            retentionMs: 7 * 24 * 60 * 60 * 1000,
            maxBytes: 128 * 1024 * 1024,
            forgetBeforeMs,
            retainedTimeRange:
              records.length > 0
                ? {
                    fromTimeMs: Math.min(...records.map((r) => r.eventTimeMs)),
                    toTimeMs: Math.max(...records.map((r) => r.eventTimeMs)),
                  }
                : null,
            counts: {
              text: records.filter(
                (r) => r.payload.kind === 'text.snapshot' || r.payload.kind === 'text.changed',
              ).length,
              surface: records.filter((r) => r.payload.kind === 'surface.snapshot').length,
              selection: records.filter((r) => r.payload.kind === 'selection.snapshot').length,
              inputText: records.filter((r) => r.payload.kind === 'input.text').length,
              activity: records.filter((r) => r.payload.kind === 'input.activity').length,
              menu: records.filter((r) => r.payload.kind === 'menu.action').length,
              context: records.filter((r) => r.payload.kind === 'context.changed').length,
              gap: records.filter((r) => r.payload.kind === 'gap').length,
              gapDiscarded: records.filter(
                (r) => r.payload.kind === 'gap' && classifyGap(r.payload) === 'discarded',
              ).length,
              gapException: records.filter(
                (r) => r.payload.kind === 'gap' && classifyGap(r.payload) === 'exception',
              ).length,
            },
          },
    collector: null,
    adapters: BUILT_IN_ADAPTERS.map((a) => ({ ...a, bundleIds: [...a.bundleIds] })),
  });

  const mock: MockHistoryService = {
    records,
    calls,
    closed: false,

    seedObservation(obs: Observation): void {
      records.push(obs);
    },

    async status(): Promise<ServiceStatus> {
      calls.push('status');
      return buildStatus();
    },

    async initializeKey(): Promise<ServiceStatus> {
      calls.push('initializeKey');
      state = 'stopped';
      reason = 'ready';
      return buildStatus();
    },

    async checkPermissions(): Promise<PermissionStatus> {
      calls.push('checkPermissions');
      return { ...permissions };
    },

    async requestAccessibility(): Promise<PermissionStatus> {
      calls.push('requestAccessibility');
      permissions = { ...permissions, promptRequested: true };
      return { ...permissions };
    },

    async openAccessibilitySettings(): Promise<PermissionStatus> {
      calls.push('openAccessibilitySettings');
      permissions = { ...permissions, settingsOpened: true };
      return { ...permissions };
    },

    async requestInputMonitoring(): Promise<PermissionStatus> {
      calls.push('requestInputMonitoring');
      permissions = { ...permissions, promptRequested: true };
      return { ...permissions };
    },

    async openInputMonitoringSettings(): Promise<PermissionStatus> {
      calls.push('openInputMonitoringSettings');
      permissions = { ...permissions, settingsOpened: true };
      return { ...permissions };
    },

    async start(options: CaptureStartOptions): Promise<ServiceStatus> {
      calls.push('start');
      activeScope = validateCaptureStartOptions(options);
      state = 'running';
      reason = 'capturing';
      return buildStatus();
    },

    async pause(): Promise<ServiceStatus> {
      calls.push('pause');
      state = 'paused';
      reason = 'paused';
      return buildStatus();
    },

    async resume(): Promise<ServiceStatus> {
      calls.push('resume');
      state = 'running';
      reason = 'capturing';
      return buildStatus();
    },

    async stop(): Promise<ServiceStatus> {
      calls.push('stop');
      state = 'stopped';
      reason = 'stopped';
      activeScope = null;
      return buildStatus();
    },

    async reloadCollector(): Promise<ServiceStatus> {
      calls.push('reloadCollector');
      if (state === 'running' && activeScope) {
        return buildStatus();
      }
      if (state === 'paused' || state === 'failed') {
        state = 'stopped';
        reason = 'stopped';
      }
      return buildStatus();
    },

    async search(query: HistoryQuery): Promise<HistoryQueryResult> {
      calls.push('search');
      let filtered = records.filter((obs) => {
        const ts = obs.eventTimeMs;
        if (query.fromTimeMs !== undefined && ts < query.fromTimeMs) return false;
        if (query.toTimeMs !== undefined && ts > query.toTimeMs) return false;
        if (query.applicationId !== undefined && extractApplicationId(obs) !== query.applicationId) {
          return false;
        }
        if (!matchesKind(obs, query.kind)) return false;
        if (query.text !== undefined) {
          if (!extractSearchableText(obs).toLowerCase().includes(query.text.toLowerCase())) {
            return false;
          }
        }
        return true;
      });

      filtered = filtered.sort((a, b) =>
        query.order === 'asc' ? a.eventTimeMs - b.eventTimeMs : b.eventTimeMs - a.eventTimeMs,
      );

      const limit = query.limit ?? 50;
      const sliced = filtered.slice(0, limit);
      const hasMore = filtered.length > sliced.length;
      const result: HistoryQueryResult = {
        records: sliced,
        truncated: false,
        bytes: Buffer.byteLength(JSON.stringify(sliced), 'utf8'),
        hasMore,
      };
      if (hasMore) {
        result.nextCursor = 'cursor_page_2';
      }
      return result;
    },

    async read(id: string): Promise<HistoryReadResult> {
      calls.push(`read:${id}`);
      const match =
        records.find((r) => r.eventId === id) ??
        records.find((r) => r.payload.kind === 'surface.snapshot' && r.payload.snapshotId === id) ??
        null;
      return {
        found: match !== null,
        record: match,
      };
    },

    async layout(req: HistoryLayoutRequest): Promise<HistoryLayoutResult> {
      calls.push('layout');
      const found = records.find(
        (r) =>
          r.payload.kind === 'surface.snapshot' &&
          ((req.eventId !== undefined && r.eventId === req.eventId) ||
            (req.snapshotId !== undefined && r.payload.snapshotId === req.snapshotId)),
      );
      if (!found || found.payload.kind !== 'surface.snapshot') {
        return {
          found: false,
          source: 'encrypted-history',
          untrustedData: true,
          reason: 'not-found-or-forgotten',
          coverage: { status: 'unknown', truncated: false, missingReasons: ['not-found-or-forgotten'] },
          missingReasons: ['not-found-or-forgotten'],
          truncated: false,
          hasMore: false,
        };
      }

      const surf: SurfaceSnapshot = found.payload;
      const nodes = surf.nodes
        .filter((n) => !req.nodeIds || req.nodeIds.includes(n.id))
        .map((n) => ({
          id: n.id,
          role: n.axRole ?? n.role,
          roleSource: (n.axRole ? 'ax' : 'category') as 'ax' | 'category',
          text: n.text ?? null,
          textOffset: 0,
          textLength: n.text ? n.text.length : null,
          textTruncated: false,
          bounds: n.bounds
            ? ([n.bounds.x, n.bounds.y, n.bounds.width, n.bounds.height] as [number, number, number, number])
            : null,
          observedAtMs: n.observedAtMs,
          boundsObservedAtMs: n.boundsObservedAtMs ?? null,
          focused: n.focused ?? null,
        }));

      const focusedNode = surf.nodes.find((n) => n.focused === true);
      const page: HistoryLayoutPage = {
        found: true,
        source: 'encrypted-history',
        evidenceSource: surf.source,
        untrustedData: true,
        consistency: 'non-atomic',
        eventId: found.eventId,
        snapshotId: surf.snapshotId,
        applicationId: found.target.kind === 'resolved' ? found.target.identity.applicationId : 'unknown',
        windowId: found.target.kind === 'resolved' ? found.target.identity.windowId : 'unknown',
        captureStartMs: surf.captureStartMs,
        captureEndMs: surf.captureEndMs,
        geometryObservedAtMs: surf.geometry?.observedAtMs ?? null,
        coordinateSpace: surf.geometry?.coordinateSpace ?? null,
        windowSize: surf.geometry?.windowSize ?? null,
        snapshotFocusedNodeId: focusedNode?.id ?? null,
        sourceCoverage: surf.coverage,
        coverage: surf.coverage,
        projection: {
          totalNodes: surf.nodes.length,
          defaultOmittedNodes: 0,
          defaultFilteredNodes: 0,
          nodeIdFilteredNodes: surf.nodes.length - nodes.length,
          spatialFilteredNodes: 0,
          missingGeometryFilteredNodes: 0,
          missingGeometryNodes: 0,
          unmatchedRequestedNodeIds: 0,
          matchedNodes: nodes.length,
          returnedNodes: nodes.length,
          returnedTextUnits: nodes.reduce((sum: number, n) => sum + (n.text?.length ?? 0), 0),
        },
        nodes,
        truncated: false,
        missingReasons: [],
        hasMore: false,
      };
      return page;
    },

    async forget(req: HistoryForgetRequest): Promise<HistoryForgetResult> {
      calls.push('forget');
      if (req.all) {
        records.length = 0;
        generation += 1;
        forgetBeforeMs = Date.now();
      } else if (req.beforeMs !== undefined) {
        forgetBeforeMs = req.beforeMs;
        for (let i = records.length - 1; i >= 0; i -= 1) {
          const rec = records[i];
          if (rec && rec.eventTimeMs < req.beforeMs) {
            records.splice(i, 1);
          }
        }
      }
      return {
        deletedSegments: 1,
        remainingRecords: records.length,
        remainingBytes: Buffer.byteLength(JSON.stringify(records), 'utf8'),
        forgetBeforeMs,
        generation,
      };
    },

    async openSource(req: OpenSourceRequest): Promise<OpenSourceResult> {
      calls.push(`openSource:${req.applicationId ?? req.eventId ?? ''}`);
      return {
        outcome: 'activated',
        reason: 'ok',
      };
    },

    async close(): Promise<void> {
      calls.push('close');
      mock.closed = true;
    },
  };

  return mock;
}

export function makeSampleTextSnapshot(
  id: string,
  text: string,
  appId = 'com.google.antigravity-ide',
  timeMs = 1_700_000_001_000,
): Observation {
  return {
    protocolVersion: 1,
    type: 'observation',
    eventId: id,
    instanceId: 'inst_1',
    seq: 1,
    eventTimeMs: timeMs,
    monotonicMs: 100,
    target: {
      kind: 'resolved',
      identity: {
        deviceId: 'test-device',
        osSessionId: 'sess-1',
        desktopId: 'desk-1',
        processId: 1234,
        processStartTime: '2026-11-20T00:00:00Z',
        applicationId: appId,
        windowId: 'win-1',
        windowGeneration: 1,
      },
    },
    stamp: {
      captureEpoch: 1,
      foregroundGeneration: 1,
      focusGeneration: 1,
      policyRevision: 1,
    },
    actor: 'user-estimated',
    relatedActionIds: [],
    payload: {
      kind: 'text.snapshot',
      snapshotId: `snap_${id}`,
      editSessionId: 'edit_1',
      nodeId: 'node_1',
      source: 'ax.value',
      scope: 'field',
      valueState: 'read',
      rangeBasis: 'prefix',
      text,
      range: { unit: 'utf16', start: 0, length: text.length },
      totalLength: text.length,
      composition: 'not-composing',
      captureStartMs: timeMs - 5,
      captureEndMs: timeMs,
      coverage: { status: 'complete', truncated: false, missingReasons: [] },
      gate: {
        secure: 'not-declared-sensitive',
        privateState: 'normal',
        policyRevision: 1,
      },
    },
  };
}

export function makeSampleSurfaceSnapshot(eventId: string, snapshotId: string, nodeText: string): Observation {
  return {
    protocolVersion: 1,
    type: 'observation',
    eventId,
    instanceId: 'inst_1',
    seq: 2,
    eventTimeMs: 1_700_000_002_000,
    monotonicMs: 200,
    target: {
      kind: 'resolved',
      identity: {
        deviceId: 'test-device',
        osSessionId: 'sess-1',
        desktopId: 'desk-1',
        processId: 1234,
        processStartTime: '2026-11-20T00:00:00Z',
        applicationId: 'com.google.antigravity-ide',
        windowId: 'win-1',
        windowGeneration: 1,
      },
    },
    stamp: {
      captureEpoch: 1,
      foregroundGeneration: 1,
      focusGeneration: 1,
      policyRevision: 1,
    },
    actor: 'user-estimated',
    relatedActionIds: [],
    payload: {
      kind: 'surface.snapshot',
      snapshotId,
      surfaceId: 'surf_1',
      revision: 1,
      source: 'ax.tree',
      scope: 'window',
      mode: 'full',
      consistency: 'non-atomic',
      captureStartMs: 1_700_000_001_990,
      captureEndMs: 1_700_000_002_000,
      coverage: { status: 'complete', truncated: false, missingReasons: [] },
      gate: {
        secure: 'not-declared-sensitive',
        privateState: 'normal',
        policyRevision: 1,
      },
      geometry: {
        coordinateSpace: 'window-top-left-point',
        windowSize: { width: 1280, height: 800 },
        observedAtMs: 1_700_000_002_000,
      },
      nodes: [
        {
          id: 'n1',
          role: 'editable',
          axRole: 'AXTextArea',
          text: nodeText,
          focused: true,
          observedAtMs: 1_700_000_002_000,
          bounds: { x: 20, y: 40, width: 800, height: 600 },
          boundsObservedAtMs: 1_700_000_002_000,
        },
        {
          id: 'n2',
          role: 'text',
          axRole: 'AXStaticText',
          text: 'Sidebar Label',
          focused: false,
          observedAtMs: 1_700_000_002_000,
          bounds: { x: 0, y: 40, width: 20, height: 20 },
          boundsObservedAtMs: 1_700_000_002_000,
        },
      ],
    },
  };
}

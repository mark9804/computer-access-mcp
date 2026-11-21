import { Buffer } from 'node:buffer';
import type { Coverage, Observation, SurfaceNode } from '../../shared/protocol/generated.ts';
import { validateMessage } from '../../shared/protocol/validate.ts';
import type {
  HistoryLayoutNode,
  HistoryLayoutPage,
  HistoryLayoutPosition,
  HistoryLayoutProjectionCounts,
  HistoryLayoutUnavailable,
  HistoryLayoutUnavailableReason,
  NormalizedHistoryLayoutRequest,
} from '../../shared/history-layout.ts';

export const HISTORY_LAYOUT_MAX_BYTES = 60_000;
const CURSOR_PLACEHOLDER = 'x'.repeat(43);

export type HistoryLayoutErrorCode =
  | 'invalid-layout-query'
  | 'invalid-layout-position'
  | 'invalid-layout-record'
  | 'invalid-layout-result'
  | 'layout-budget-too-small';

export class HistoryLayoutError extends Error {
  readonly code: HistoryLayoutErrorCode;

  constructor(code: HistoryLayoutErrorCode) {
    super(code);
    this.name = 'HistoryLayoutError';
    this.code = code;
  }
}

function reject(code: HistoryLayoutErrorCode): never {
  throw new HistoryLayoutError(code);
}

function isPlainObject(value: unknown, allowedKeys: readonly string[]): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string' || !allowedKeys.includes(key)) return false;
    const desc = Object.getOwnPropertyDescriptor(value, key);
    return !!desc && 'value' in desc && desc.enumerable === true;
  });
}

function isNonEmptyId(value: unknown, maxLength: number): value is string {
  return (
    typeof value === 'string' &&
    value.length >= 1 &&
    value.length <= maxLength &&
    value.isWellFormed() &&
    value.trim().length > 0
  );
}

function isSafeInt(value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
}

function isFiniteCoord(value: unknown, min = -1_000_000, max = 1_000_000): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= min && value <= max;
}

function isBoundsRect(value: unknown): value is { x: number; y: number; width: number; height: number } {
  return (
    isPlainObject(value, ['x', 'y', 'width', 'height']) &&
    isFiniteCoord(value.x) &&
    isFiniteCoord(value.y) &&
    isFiniteCoord(value.width, 0) &&
    isFiniteCoord(value.height, 0)
  );
}

export function normalizeHistoryLayoutRequest(input: unknown): NormalizedHistoryLayoutRequest {
  const allowed = ['eventId', 'snapshotId', 'applicationId', 'maxNodes', 'maxChars', 'bounds', 'nodeIds', 'cursor'];
  if (!isPlainObject(input, allowed)) reject('invalid-layout-query');

  const hasEventId = input.eventId !== undefined;
  const hasSnapshotId = input.snapshotId !== undefined;
  if (hasEventId === hasSnapshotId) reject('invalid-layout-query');
  if (Object.hasOwn(input, 'eventId') && !isNonEmptyId(input.eventId, 240)) reject('invalid-layout-query');
  if (Object.hasOwn(input, 'snapshotId') && !isNonEmptyId(input.snapshotId, 128)) reject('invalid-layout-query');
  if (Object.hasOwn(input, 'applicationId') && input.applicationId !== undefined && !isNonEmptyId(input.applicationId, 200)) {
    reject('invalid-layout-query');
  }
  if (
    Object.hasOwn(input, 'cursor') &&
    input.cursor !== undefined &&
    (typeof input.cursor !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(input.cursor))
  ) {
    reject('invalid-layout-query');
  }
  if (Object.hasOwn(input, 'maxNodes') && input.maxNodes !== undefined && !isSafeInt(input.maxNodes, 1, 200)) {
    reject('invalid-layout-query');
  }
  if (Object.hasOwn(input, 'maxChars') && input.maxChars !== undefined && !isSafeInt(input.maxChars, 1, 24_000)) {
    reject('invalid-layout-query');
  }
  if (Object.hasOwn(input, 'bounds') && input.bounds !== undefined && !isBoundsRect(input.bounds)) {
    reject('invalid-layout-query');
  }
  if (Object.hasOwn(input, 'nodeIds') && input.nodeIds !== undefined) {
    if (
      !Array.isArray(input.nodeIds) ||
      input.nodeIds.length === 0 ||
      input.nodeIds.length > 96 ||
      input.nodeIds.some((id) => !isNonEmptyId(id, 96)) ||
      new Set(input.nodeIds).size !== input.nodeIds.length
    ) {
      reject('invalid-layout-query');
    }
  }

  return {
    ...(typeof input.eventId === 'string' ? { eventId: input.eventId } : {}),
    ...(typeof input.snapshotId === 'string' ? { snapshotId: input.snapshotId } : {}),
    ...(typeof input.applicationId === 'string' ? { applicationId: input.applicationId } : {}),
    ...(typeof input.cursor === 'string' ? { cursor: input.cursor } : {}),
    maxNodes: typeof input.maxNodes === 'number' ? input.maxNodes : 96,
    maxChars: typeof input.maxChars === 'number' ? input.maxChars : 12_000,
    ...(isBoundsRect(input.bounds) ? { bounds: { ...input.bounds } } : {}),
    ...(Array.isArray(input.nodeIds) ? { nodeIds: [...(input.nodeIds as string[])] } : {}),
  };
}

export function createHistoryLayoutUnavailable(reason: HistoryLayoutUnavailableReason): HistoryLayoutUnavailable {
  if (reason !== 'not-found-or-forgotten' && reason !== 'not-a-surface-snapshot') {
    reject('invalid-layout-result');
  }
  return {
    found: false,
    source: 'encrypted-history',
    untrustedData: true,
    reason,
    coverage: { status: 'unknown', truncated: false, missingReasons: [reason] },
    missingReasons: [reason],
    truncated: false,
    hasMore: false,
  };
}

function defaultIncluded(node: SurfaceNode): boolean {
  return (node.text !== undefined && /\S/u.test(node.text)) || (node.role === 'editable' && node.focused === true);
}

function intersects(
  a: { x: number; y: number; width: number; height: number },
  b: { x: number; y: number; width: number; height: number },
): boolean {
  return (
    a.width > 0 &&
    a.height > 0 &&
    b.width > 0 &&
    b.height > 0 &&
    a.x < b.x + b.width &&
    b.x < a.x + a.width &&
    a.y < b.y + b.height &&
    b.y < a.y + a.height
  );
}

function scalarBoundary(value: string, offset: number): boolean {
  if (offset === 0 || offset === value.length) return true;
  const before = value.charCodeAt(offset - 1);
  const after = value.charCodeAt(offset);
  return !(before >= 0xd800 && before <= 0xdbff && after >= 0xdc00 && after <= 0xdfff);
}

function safeEnd(value: string, end: number): number {
  return scalarBoundary(value, end) ? end : end - 1;
}

function cloneCoverage(value: Coverage): Coverage {
  return {
    status: value.status,
    truncated: value.truncated,
    missingReasons: [...value.missingReasons],
  };
}

function nodeProjection(node: SurfaceNode, offset: number, end: number): HistoryLayoutNode {
  return {
    id: node.id,
    role: node.axRole ?? node.role,
    roleSource: node.axRole === undefined ? 'category' : 'ax',
    text: node.text === undefined ? null : node.text.slice(offset, end),
    textOffset: offset,
    textLength: node.text?.length ?? null,
    textTruncated: node.text !== undefined && (offset > 0 || end < node.text.length),
    bounds: node.bounds === undefined ? null : [node.bounds.x, node.bounds.y, node.bounds.width, node.bounds.height],
    observedAtMs: node.observedAtMs,
    boundsObservedAtMs: node.boundsObservedAtMs ?? null,
    focused: node.focused ?? null,
  };
}

export interface HistoryLayoutProjection {
  page: HistoryLayoutPage;
  nextPosition?: HistoryLayoutPosition;
}

export interface HistoryLayoutProjectionOptions {
  maxBytes?: number;
}

function withinByteBudget(page: HistoryLayoutPage, maxBytes: number): boolean {
  const data = page.hasMore && page.nextCursor === undefined ? { ...page, nextCursor: CURSOR_PLACEHOLDER } : page;
  return Buffer.byteLength(JSON.stringify(data)) <= maxBytes;
}

export function projectHistoryLayout(
  record: Observation,
  request: NormalizedHistoryLayoutRequest,
  position: HistoryLayoutPosition = { nodeOffset: 0, textOffset: 0 },
  options: HistoryLayoutProjectionOptions = {},
): HistoryLayoutProjection {
  const query = normalizeHistoryLayoutRequest(request);
  if (
    !isPlainObject(options, ['maxBytes']) ||
    (options.maxBytes !== undefined && !isSafeInt(options.maxBytes, 1, HISTORY_LAYOUT_MAX_BYTES))
  ) {
    reject('invalid-layout-query');
  }
  const maxBytes = options.maxBytes ?? HISTORY_LAYOUT_MAX_BYTES;

  try {
    validateMessage(record);
  } catch {
    reject('invalid-layout-record');
  }
  if (record.payload.kind !== 'surface.snapshot' || record.target.kind !== 'resolved') {
    reject('invalid-layout-record');
  }
  const snapshot = record.payload;
  if (
    (query.eventId !== undefined && record.eventId !== query.eventId) ||
    (query.snapshotId !== undefined && snapshot.snapshotId !== query.snapshotId) ||
    (query.applicationId !== undefined && record.target.identity.applicationId !== query.applicationId)
  ) {
    reject('invalid-layout-record');
  }

  const selectedIds = query.nodeIds === undefined ? undefined : new Set(query.nodeIds);
  const rawIds = new Set(snapshot.nodes.map((node) => node.id));
  const counts: HistoryLayoutProjectionCounts = {
    totalNodes: snapshot.nodes.length,
    defaultOmittedNodes: 0,
    defaultFilteredNodes: 0,
    nodeIdFilteredNodes: 0,
    spatialFilteredNodes: 0,
    missingGeometryFilteredNodes: 0,
    missingGeometryNodes: 0,
    unmatchedRequestedNodeIds: query.nodeIds?.filter((id) => !rawIds.has(id)).length ?? 0,
    matchedNodes: 0,
    returnedNodes: 0,
    returnedTextUnits: 0,
  };

  const candidates: SurfaceNode[] = [];
  for (const node of snapshot.nodes) {
    const included = defaultIncluded(node);
    if (!included) counts.defaultOmittedNodes++;
    if (node.bounds === undefined) counts.missingGeometryNodes++;
    if (selectedIds !== undefined) {
      if (!selectedIds.has(node.id)) {
        counts.nodeIdFilteredNodes++;
        continue;
      }
    } else if (!included) {
      counts.defaultFilteredNodes++;
      continue;
    }
    if (query.bounds !== undefined) {
      if (node.bounds === undefined) {
        counts.missingGeometryFilteredNodes++;
        continue;
      }
      if (!intersects(node.bounds, query.bounds)) {
        counts.spatialFilteredNodes++;
        continue;
      }
    }
    candidates.push(node);
  }
  counts.matchedNodes = candidates.length;

  if (
    !isPlainObject(position, ['nodeOffset', 'textOffset']) ||
    !isSafeInt(position.nodeOffset, 0, candidates.length) ||
    !isSafeInt(position.textOffset)
  ) {
    reject('invalid-layout-position');
  }
  if (position.nodeOffset === candidates.length) {
    if (candidates.length !== 0 || position.textOffset !== 0) reject('invalid-layout-position');
  } else {
    const value = candidates[position.nodeOffset]!.text;
    if (value === undefined || value.length === 0) {
      if (position.textOffset !== 0) reject('invalid-layout-position');
    } else if (position.textOffset >= value.length || !scalarBoundary(value, position.textOffset)) {
      reject('invalid-layout-position');
    }
  }

  const reasons: string[] = [];
  if (snapshot.geometry === undefined) reasons.push('geometry-unavailable');
  else if (candidates.some((node) => node.bounds === undefined)) reasons.push('node-geometry-unavailable');
  if (counts.defaultFilteredNodes > 0) reasons.push('default-node-filter');
  if (counts.nodeIdFilteredNodes > 0) reasons.push('node-id-filter');
  if (counts.spatialFilteredNodes > 0) reasons.push('spatial-filter');
  if (counts.missingGeometryFilteredNodes > 0) reasons.push('spatial-filter-geometry-unavailable');
  if (counts.unmatchedRequestedNodeIds > 0) reasons.push('requested-node-not-found');
  if (position.nodeOffset > 0 || position.textOffset > 0) reasons.push('continuation-page');

  const makePage = (nodes: HistoryLayoutNode[], hasMore: boolean): HistoryLayoutPage => {
    const missingReasons = hasMore ? [...reasons, 'page-truncated'] : [...reasons];
    const combinedReasons = [...new Set([...snapshot.coverage.missingReasons, ...missingReasons])];
    return {
      found: true,
      source: 'encrypted-history',
      evidenceSource: snapshot.source,
      untrustedData: true,
      consistency: 'non-atomic',
      eventId: record.eventId,
      snapshotId: snapshot.snapshotId,
      applicationId: record.target.kind === 'resolved' ? record.target.identity.applicationId : '',
      windowId: record.target.kind === 'resolved' ? record.target.identity.windowId : '',
      captureStartMs: snapshot.captureStartMs,
      captureEndMs: snapshot.captureEndMs,
      geometryObservedAtMs: snapshot.geometry?.observedAtMs ?? null,
      coordinateSpace: snapshot.geometry?.coordinateSpace ?? null,
      windowSize:
        snapshot.geometry === undefined
          ? null
          : { width: snapshot.geometry.windowSize.width, height: snapshot.geometry.windowSize.height },
      snapshotFocusedNodeId: snapshot.nodes.find((node) => node.focused === true)?.id ?? null,
      sourceCoverage: cloneCoverage(snapshot.coverage),
      coverage: {
        status:
          snapshot.coverage.status === 'unknown'
            ? 'unknown'
            : combinedReasons.length > 0
              ? 'partial'
              : snapshot.coverage.status,
        truncated: snapshot.coverage.truncated || hasMore,
        missingReasons: combinedReasons,
      },
      projection: {
        ...counts,
        returnedNodes: nodes.length,
        returnedTextUnits: nodes.reduce((sum, node) => sum + (node.text?.length ?? 0), 0),
      },
      nodes,
      truncated: hasMore,
      missingReasons,
      hasMore,
    };
  };

  const fits = (nodes: HistoryLayoutNode[], hasMore: boolean): boolean => withinByteBudget(makePage(nodes, hasMore), maxBytes);

  const nodes: HistoryLayoutNode[] = [];
  let nodeOffset = position.nodeOffset;
  let textOffset = position.textOffset;
  let units = 0;

  while (nodeOffset < candidates.length && nodes.length < query.maxNodes) {
    const node = candidates[nodeOffset]!;
    const value = node.text;
    const remaining = query.maxChars - units;
    const end = value === undefined ? 0 : safeEnd(value, Math.min(value.length, textOffset + remaining));
    if (value !== undefined && value.length > textOffset && end === textOffset) {
      if (nodes.length === 0) reject('layout-budget-too-small');
      break;
    }
    const projected = nodeProjection(node, textOffset, end);
    const partial = value !== undefined && end < value.length;
    const hasMore = partial || nodeOffset + 1 < candidates.length;
    if (fits([...nodes, projected], hasMore)) {
      nodes.push(projected);
      units += projected.text?.length ?? 0;
      if (partial) {
        textOffset = end;
        break;
      }
      nodeOffset++;
      textOffset = 0;
      continue;
    }

    let low = textOffset + 1;
    let high = end;
    let best = textOffset;
    if (value !== undefined) {
      while (low <= high) {
        const middle = Math.floor((low + high) / 2);
        const boundary = safeEnd(value, middle);
        if (boundary > textOffset && fits([...nodes, nodeProjection(node, textOffset, boundary)], true)) {
          best = boundary;
          low = middle + 1;
        } else if (boundary === textOffset) {
          low = middle + 1;
        } else {
          high = middle - 1;
        }
      }
    }
    if (best > textOffset) {
      const fragment = nodeProjection(node, textOffset, best);
      nodes.push(fragment);
      units += fragment.text?.length ?? 0;
      textOffset = best;
      break;
    }
    if (nodes.length === 0) reject('layout-budget-too-small');
    break;
  }

  const hasMore = nodeOffset < candidates.length;
  const page = makePage(nodes, hasMore);
  if (!fits(nodes, hasMore)) reject('layout-budget-too-small');
  return hasMore ? { page, nextPosition: { nodeOffset, textOffset } } : { page };
}

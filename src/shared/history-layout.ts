import type { Coverage, SurfaceNode, SurfaceSnapshot } from './protocol/generated.ts';

export interface HistoryLayoutRequest {
  snapshotId?: string;
  eventId?: string;
  applicationId?: string;
  maxNodes?: number;
  // Maximum UTF-16 code units returned per page.
  maxChars?: number;
  bounds?: { x: number; y: number; width: number; height: number };
  nodeIds?: string[];
  cursor?: string;
}

export interface NormalizedHistoryLayoutRequest extends HistoryLayoutRequest {
  maxNodes: number;
  maxChars: number;
}

export interface HistoryLayoutPosition {
  nodeOffset: number;
  textOffset: number;
}

export interface HistoryLayoutNode {
  id: string;
  role: string;
  roleSource: 'ax' | 'category';
  text: string | null;
  textOffset: number;
  textLength: number | null;
  textTruncated: boolean;
  bounds: [number, number, number, number] | null;
  observedAtMs: number;
  boundsObservedAtMs: number | null;
  focused: boolean | null;
}

export interface HistoryLayoutProjectionCounts {
  totalNodes: number;
  defaultOmittedNodes: number;
  defaultFilteredNodes: number;
  nodeIdFilteredNodes: number;
  spatialFilteredNodes: number;
  missingGeometryFilteredNodes: number;
  missingGeometryNodes: number;
  unmatchedRequestedNodeIds: number;
  matchedNodes: number;
  returnedNodes: number;
  returnedTextUnits: number;
}

export interface HistoryLayoutPage {
  found: true;
  source: 'encrypted-history';
  evidenceSource: SurfaceSnapshot['source'];
  untrustedData: true;
  consistency: 'non-atomic';
  eventId: string;
  snapshotId: string;
  applicationId: string;
  windowId: string;
  captureStartMs: number;
  captureEndMs: number;
  geometryObservedAtMs: number | null;
  coordinateSpace: 'window-top-left-point' | null;
  windowSize: { width: number; height: number } | null;
  snapshotFocusedNodeId: string | null;
  sourceCoverage: Coverage;
  coverage: Coverage;
  projection: HistoryLayoutProjectionCounts;
  nodes: HistoryLayoutNode[];
  truncated: boolean;
  missingReasons: string[];
  hasMore: boolean;
  nextCursor?: string;
}

export type HistoryLayoutUnavailableReason = 'not-found-or-forgotten' | 'not-a-surface-snapshot';

export interface HistoryLayoutUnavailable {
  found: false;
  source: 'encrypted-history';
  untrustedData: true;
  reason: HistoryLayoutUnavailableReason;
  coverage: Coverage;
  missingReasons: string[];
  truncated: false;
  hasMore: false;
}

export type HistoryLayoutResult = HistoryLayoutPage | HistoryLayoutUnavailable;
export type HistoryLayoutCategoryRole = SurfaceNode['role'];

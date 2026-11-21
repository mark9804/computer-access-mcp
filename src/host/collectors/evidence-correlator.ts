import type { Observation } from '../../shared/protocol/generated.ts';

const MAX_AGE_MS = 1500;
const MAX_ENTRIES = 64;
const MAX_RELATIONS = 4;

export type EvidenceKind = 'surface.snapshot' | 'selection.snapshot' | 'input.text';

export interface WindowContextIdentity {
  readonly instanceId: string;
  readonly deviceId: string;
  readonly osSessionId: string;
  readonly desktopId: string;
  readonly processStartTime: string;
  readonly applicationId: string;
  readonly windowId: string;
  readonly processId: number;
  readonly windowGeneration: number;
  readonly captureEpoch: number;
  readonly foregroundGeneration: number;
  readonly focusGeneration: number;
  readonly policyRevision: number;
}

export interface SurfaceContextIdentity extends WindowContextIdentity {
  readonly surfaceId: string;
}

export interface EvidenceMetadata {
  readonly eventId: string;
  readonly context: SurfaceContextIdentity;
  readonly kind: EvidenceKind;
  readonly seq: number;
  readonly eventTimeMs: number;
  readonly monotonicMs: number;
  readonly endMs: number;
}

const isClock = (value: number): boolean => Number.isSafeInteger(value) && value >= 0;
const isId = (value: string): boolean => typeof value === 'string' && value.length > 0 && value.isWellFormed();

export function sameWindowContext(a: WindowContextIdentity, b: WindowContextIdentity): boolean {
  return (
    a.instanceId === b.instanceId &&
    a.deviceId === b.deviceId &&
    a.osSessionId === b.osSessionId &&
    a.desktopId === b.desktopId &&
    a.processStartTime === b.processStartTime &&
    a.applicationId === b.applicationId &&
    a.windowId === b.windowId &&
    a.processId === b.processId &&
    a.windowGeneration === b.windowGeneration &&
    a.captureEpoch === b.captureEpoch &&
    a.foregroundGeneration === b.foregroundGeneration &&
    a.focusGeneration === b.focusGeneration &&
    a.policyRevision === b.policyRevision
  );
}

export function sameSurfaceContext(a: SurfaceContextIdentity, b: SurfaceContextIdentity): boolean {
  return a.surfaceId === b.surfaceId && sameWindowContext(a, b);
}

function extractWindowContext(record: Observation): WindowContextIdentity | undefined {
  if (record.target.kind !== 'resolved') return undefined;
  const target = record.target.identity;
  const stamp = record.stamp;
  if (
    !isId(record.instanceId) ||
    !isId(target.deviceId) ||
    !isId(target.osSessionId) ||
    !isId(target.desktopId) ||
    !isId(target.processStartTime) ||
    !isId(target.applicationId) ||
    !isId(target.windowId) ||
    !isClock(target.processId) ||
    !isClock(target.windowGeneration) ||
    !isClock(stamp.captureEpoch) ||
    !isClock(stamp.foregroundGeneration) ||
    !isClock(stamp.focusGeneration) ||
    !isClock(stamp.policyRevision)
  ) {
    return undefined;
  }
  return {
    instanceId: record.instanceId,
    deviceId: target.deviceId,
    osSessionId: target.osSessionId,
    desktopId: target.desktopId,
    processStartTime: target.processStartTime,
    applicationId: target.applicationId,
    windowId: target.windowId,
    processId: target.processId,
    windowGeneration: target.windowGeneration,
    captureEpoch: stamp.captureEpoch,
    foregroundGeneration: stamp.foregroundGeneration,
    focusGeneration: stamp.focusGeneration,
    policyRevision: stamp.policyRevision,
  };
}

export function evidenceMetadata(record: Observation): EvidenceMetadata | undefined {
  const payload = record.payload;
  if (
    payload.kind !== 'surface.snapshot' &&
    payload.kind !== 'selection.snapshot' &&
    payload.kind !== 'input.text'
  ) {
    return undefined;
  }
  const windowCtx = extractWindowContext(record);
  if (!windowCtx || !isId(payload.surfaceId)) {
    return undefined;
  }

  const startMs = payload.kind === 'input.text' ? payload.intervalStartMs : payload.captureStartMs;
  const endMs = payload.kind === 'input.text' ? payload.intervalEndMs : payload.captureEndMs;
  if (
    !isClock(record.seq) ||
    !isClock(record.eventTimeMs) ||
    !isClock(record.monotonicMs) ||
    !isClock(startMs) ||
    !isClock(endMs) ||
    record.eventId !== `${record.instanceId}:${record.seq}` ||
    endMs < startMs ||
    endMs > record.eventTimeMs
  ) {
    return undefined;
  }

  return {
    eventId: record.eventId,
    context: {
      ...windowCtx,
      surfaceId: payload.surfaceId,
    },
    kind: payload.kind,
    seq: record.seq,
    eventTimeMs: record.eventTimeMs,
    monotonicMs: record.monotonicMs,
    endMs,
  };
}

export function canRelateEvidence(earlier: EvidenceMetadata, later: EvidenceMetadata): boolean {
  const eventAge = later.eventTimeMs - earlier.eventTimeMs;
  const monotonicAge = later.monotonicMs - earlier.monotonicMs;
  return (
    sameSurfaceContext(earlier.context, later.context) &&
    earlier.eventId !== later.eventId &&
    earlier.kind !== later.kind &&
    earlier.seq < later.seq &&
    earlier.endMs <= later.endMs &&
    eventAge >= 0 &&
    eventAge <= MAX_AGE_MS &&
    monotonicAge >= 0 &&
    monotonicAge <= MAX_AGE_MS
  );
}

export class EvidenceCorrelator {
  private entries: EvidenceMetadata[] = [];

  preview(record: Observation): Observation {
    const result = structuredClone(record);
    delete result.relation;
    const current = evidenceMetadata(record);
    if (!current) return result;

    const evidenceIds = this.entries
      .filter((earlier) => canRelateEvidence(earlier, current))
      .slice(-MAX_RELATIONS)
      .reverse()
      .map((earlier) => earlier.eventId);

    if (evidenceIds.length > 0) {
      result.relation = {
        basis: 'temporal-same-surface',
        evidenceIds,
        effect: 'unverified',
      };
    }
    return result;
  }

  commit(record: Observation): void {
    const current = evidenceMetadata(record);
    if (!current) {
      if (record.payload.kind === 'text.snapshot' || record.payload.kind === 'text.changed') {
        const windowCtx = extractWindowContext(record);
        if (
          windowCtx &&
          isClock(record.seq) &&
          isClock(record.eventTimeMs) &&
          isClock(record.monotonicMs)
        ) {
          this.entries = this.entries.filter(
            (earlier) =>
              earlier.seq < record.seq &&
              earlier.eventTimeMs <= record.eventTimeMs &&
              earlier.monotonicMs <= record.monotonicMs &&
              record.eventTimeMs - earlier.eventTimeMs <= MAX_AGE_MS &&
              record.monotonicMs - earlier.monotonicMs <= MAX_AGE_MS &&
              sameWindowContext(earlier.context, windowCtx),
          );
          return;
        }
      }
      this.clear();
      return;
    }

    const last = this.entries.at(-1);
    if (last && !sameSurfaceContext(last.context, current.context)) {
      this.clear();
    } else if (last && (current.seq <= last.seq || current.monotonicMs < last.monotonicMs)) {
      this.clear();
      return;
    } else if (last && (current.eventTimeMs < last.eventTimeMs || current.endMs < last.endMs)) {
      const delayedInput =
        current.kind === 'input.text' &&
        last.eventTimeMs - current.eventTimeMs <= MAX_AGE_MS &&
        last.endMs - current.endMs <= MAX_AGE_MS &&
        current.monotonicMs - last.monotonicMs <= MAX_AGE_MS;
      this.clear();
      if (!delayedInput) return;
    }

    this.entries = this.entries
      .filter(
        (earlier) =>
          current.eventTimeMs - earlier.eventTimeMs <= MAX_AGE_MS &&
          current.monotonicMs - earlier.monotonicMs <= MAX_AGE_MS,
      )
      .slice(-(MAX_ENTRIES - 1));
    this.entries.push(current);
  }

  clear(): void {
    this.entries = [];
  }
}

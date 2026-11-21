import type { Configured, Observation, Stamp, TargetIdentity, TextSnapshot } from '../../shared/protocol/generated.ts';
import { sameApplication, sameStamp, sameTarget } from '../../shared/protocol/identity.ts';
import { validateMessage } from '../../shared/protocol/validate.ts';

type Decision = {
  accepted: boolean;
  reason: 'accepted' | 'unconfigured' | 'stale' | 'sequence' | 'target' | 'baseline' | 'policy' | 'budget';
};

type Baseline = { snapshot: TextSnapshot; target: TargetIdentity };

export class CollectorAdmission {
  private acked = false;
  private revoked = false;
  private lastSeq = 0;
  private stamp: Stamp;
  private target: TargetIdentity | undefined;
  private readonly expected: { ownerId: string; instanceId: string; requestId: string; policyRevision: number };
  private readonly authorize: (message: Observation) => boolean;
  private baselines = new Map<string, Baseline>();
  private pending = new Map<string, Baseline>();

  constructor(
    expected: { ownerId: string; instanceId: string; requestId: string; policyRevision: number },
    stamp: Stamp,
    authorize: (message: Observation) => boolean = () => false,
  ) {
    if (stamp.policyRevision !== expected.policyRevision) {
      throw new Error('policy-revision-mismatch');
    }
    this.expected = structuredClone(expected);
    this.stamp = structuredClone(stamp);
    this.authorize = authorize;
  }

  acknowledge(message: Configured): boolean {
    validateMessage(message);
    if (
      message.type !== 'configured' ||
      this.revoked ||
      this.acked ||
      message.ownerId !== this.expected.ownerId ||
      message.instanceId !== this.expected.instanceId ||
      message.requestId !== this.expected.requestId ||
      message.policyRevision !== this.expected.policyRevision
    ) {
      return false;
    }
    this.acked = true;
    return true;
  }

  setBoundary(stamp: Stamp, target?: TargetIdentity): void {
    if (stamp.policyRevision !== this.expected.policyRevision) {
      throw new Error('policy-revision-mismatch');
    }
    this.stamp = structuredClone(stamp);
    this.target = target ? structuredClone(target) : undefined;
    this.baselines.clear();
    this.pending.clear();
  }

  revoke(): void {
    this.revoked = true;
    this.acked = false;
    this.baselines.clear();
    this.pending.clear();
  }

  accept(message: Observation): Decision {
    validateMessage(message);
    if (message.type !== 'observation' || !this.acked || this.revoked) {
      return { accepted: false, reason: 'unconfigured' };
    }

    const activity = message.payload.kind === 'input.activity';
    const compatible = activity
      ? message.stamp.captureEpoch === this.stamp.captureEpoch &&
        message.stamp.policyRevision === this.stamp.policyRevision &&
        message.stamp.foregroundGeneration <= this.stamp.foregroundGeneration &&
        message.stamp.focusGeneration <= this.stamp.focusGeneration
      : sameStamp(message.stamp, this.stamp);

    if (
      message.instanceId !== this.expected.instanceId ||
      message.stamp.policyRevision !== this.expected.policyRevision ||
      !compatible
    ) {
      return { accepted: false, reason: 'stale' };
    }
    if (
      message.seq <= this.lastSeq ||
      message.eventId !== `${message.instanceId}:${message.seq}` ||
      this.pending.has(message.eventId)
    ) {
      return { accepted: false, reason: 'sequence' };
    }
    this.lastSeq = message.seq;

    if (message.actor === 'agent' || message.relatedActionIds.length > 0) {
      return { accepted: false, reason: 'target' };
    }
    try {
      if (!this.authorize(structuredClone(message))) {
        return { accepted: false, reason: 'policy' };
      }
    } catch {
      return { accepted: false, reason: 'policy' };
    }

    const payload = message.payload;
    if (
      payload.kind === 'input.activity' &&
      (message.target.kind !== 'application' ||
        (this.target && !sameApplication(message.target.identity, this.target)))
    ) {
      return { accepted: false, reason: 'target' };
    }
    if (
      ['surface.snapshot', 'selection.snapshot', 'input.text'].includes(payload.kind) &&
      (!this.target || message.target.kind !== 'resolved' || !sameTarget(this.target, message.target.identity))
    ) {
      return { accepted: false, reason: 'target' };
    }
    if (payload.kind === 'text.snapshot' || payload.kind === 'text.changed') {
      if (!this.target || message.target.kind !== 'resolved' || !sameTarget(message.target.identity, this.target)) {
        return { accepted: false, reason: 'target' };
      }
      const snapshot = payload.kind === 'text.changed' ? payload.after : payload;
      if (
        this.baselines.has(snapshot.snapshotId) ||
        [...this.pending.values()].some((item) => item.snapshot.snapshotId === snapshot.snapshotId)
      ) {
        return { accepted: false, reason: 'baseline' };
      }
      if (payload.kind === 'text.changed') {
        const base = this.baselines.get(payload.baseSnapshotId);
        if (
          !base ||
          !sameTarget(base.target, message.target.identity) ||
          base.snapshot.nodeId !== snapshot.nodeId ||
          base.snapshot.editSessionId !== snapshot.editSessionId ||
          base.snapshot.source !== snapshot.source ||
          base.snapshot.scope !== snapshot.scope ||
          base.snapshot.coverage.status !== 'complete' ||
          snapshot.coverage.status !== 'complete'
        ) {
          return { accepted: false, reason: 'baseline' };
        }
      }
      if (this.pending.size >= 64) {
        return { accepted: false, reason: 'budget' };
      }
      this.pending.set(message.eventId, {
        snapshot: structuredClone(snapshot),
        target: structuredClone(message.target.identity),
      });
    }
    return { accepted: true, reason: 'accepted' };
  }

  commit(eventId: string): boolean {
    const item = this.pending.get(eventId);
    if (!item || this.revoked) return false;
    this.pending.delete(eventId);
    if (this.baselines.size >= 64) this.baselines.clear();
    this.baselines.set(item.snapshot.snapshotId, item);
    return true;
  }

  discard(eventId: string): void {
    this.pending.delete(eventId);
  }
}

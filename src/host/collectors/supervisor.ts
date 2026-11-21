import { createHash, randomUUID } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { dirname, isAbsolute } from 'node:path';
import type { CollectorStatusSummary } from '../../shared/api-types.ts';
import { applicationAllowed, validApplicationPolicy } from '../../shared/app-policy.ts';
import type { CollectorFaultReason } from '../../shared/ipc-types.ts';
import type {
  ApplicationTargetIdentity,
  CapturePolicy,
  GapDiagnostic,
  Observation,
  Stamp,
  State,
  WireMessage,
} from '../../shared/protocol/generated.ts';
import { sameApplication, sameStamp } from '../../shared/protocol/identity.ts';
import { encodeFrame, FrameDecoder } from '../../shared/protocol/validate.ts';
import { isPosixPlatform } from '../../storage/platform-paths.ts';
import { CollectorAdmission } from './admission.ts';
import type { CollectorDebugLog } from './debug-log.ts';
import { CollectorDebugTrace } from './debug-trace.ts';
import type { ManagedProcess, SpawnManaged } from './process.ts';

export type SupervisorStatus = CollectorStatusSummary;

const NATIVE_REASONS = new Set([
  'input-monitoring-required',
  'input-monitoring-unavailable',
  'input-monitoring-disabled',
  'worker-retirement-ack-failed',
  'worker-retirement-exit-unconfirmed',
  'input-session-boundary-requires-resume',
  'permission-denied',
  'desktop-unavailable',
  'user-paused',
  'user-stopped',
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
  'read-timeout-recovering',
  'read-timeout-unrecoverable',
  'read-timeout-exhausted',
  'worker-exit-unconfirmed',
]);

const nativeReason = (value: string, fallback: string): string =>
  NATIVE_REASONS.has(value) ? value : fallback;

function terminalNotice(message: State): CollectorFaultReason | undefined {
  if (message.state !== 'stopped') return undefined;
  if (message.requestId === 'lease' && message.reason === 'lease-expired') return 'helper-lease-expired';
  if (message.requestId !== 'owner') return undefined;
  if (message.reason === 'owner-eof') return 'helper-owner-eof';
  if (message.reason === 'parent-death') return 'helper-parent-death';
  if (message.reason === 'signal') return 'helper-signaled';
  return undefined;
}

const addCount = (value: number, count: number): number =>
  value + Math.min(Number.MAX_SAFE_INTEGER - value, count);

interface PendingReply {
  expected: WireMessage['type'];
  resolve(message: WireMessage): void;
  reject(error: Error): void;
  timer: ReturnType<typeof setTimeout>;
}

interface PendingObservation {
  readonly message: Observation;
  readonly admission: CollectorAdmission;
  readonly generation: number;
  readonly enqueuedAt: number;
}

export interface SupervisorOptions {
  helperPath: string;
  helperSha256?: string;
  cwd: string;
  deviceId: string;
  spawn: SpawnManaged;
  onObservation: (message: Observation, isCurrent: () => boolean) => Promise<void>;
  allowFixture?: boolean;
  fixtureArgs?: readonly string[];
  requestTimeoutMs?: number;
  leaseDurationMs?: number;
  debugTrace?: boolean;
  debugLog?: CollectorDebugLog;
}

export class CollectorSupervisor {
  private readonly options: SupervisorOptions;
  private process: ManagedProcess | undefined;
  private admission: CollectorAdmission | undefined;
  private currentStamp: Stamp | undefined;
  private policy: CapturePolicy | undefined;
  private applicationAnchor: { epoch: number; identity: ApplicationTargetIdentity } | undefined;
  private ownerId = randomUUID();
  private instanceId: string | undefined;
  private revision = 0;
  private generation = 0;
  private state: SupervisorStatus['state'] = 'stopped';
  private reason = '';
  private activation:
    | {
        child: ManagedProcess;
        epoch: number;
        cleared: boolean;
        requestId?: string;
        runningAck?: boolean;
        recovered?: boolean;
      }
    | undefined;
  private requests = new Map<string, PendingReply>();
  private hello:
    | { resolve(): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout> }
    | undefined;
  private heartbeat: ReturnType<typeof setInterval> | undefined;
  private streamDecoder = new FrameDecoder();
  private work: Promise<void> | undefined;
  private waiting: PendingObservation[] = [];
  private writing: { startedAt: number } | undefined;

  private received = 0;
  private dropped = 0;
  private acceptedText = 0;
  private acceptedActivity = 0;
  private acceptedSurface = 0;
  private acceptedSelection = 0;
  private acceptedInputText = 0;
  private acceptedGaps = 0;
  private lastGapReason: string | null = null;
  private lastGapDiagnostic: GapDiagnostic | null = null;
  private captureDiagnostics: State['captureDiagnostics'] | null = null;

  private controlBusy = false;
  private pauseEpoch: number | undefined;
  private controlEpoch = 0;
  private dispatchEnabled = false;
  private configuredRequestId: string | undefined;
  private userPaused = false;
  private readRecovery: { stamp: Stamp; controlEpoch: number } | undefined;
  private stopping: Promise<SupervisorStatus> | undefined;
  private debugTrace: CollectorDebugTrace;

  constructor(options: SupervisorOptions) {
    this.options = options;
    this.debugTrace = new CollectorDebugTrace(options.debugTrace === true);
  }

  private get pending(): number {
    return this.waiting.length + Number(this.writing !== undefined);
  }

  private get timeout(): number {
    return this.options.requestTimeoutMs ?? 3000;
  }

  private get lease(): number {
    return this.options.leaseDurationMs ?? 6000;
  }

  status(): SupervisorStatus {
    return {
      state: this.state,
      reason: this.reason,
      instanceId: this.instanceId ?? null,
      received: this.received,
      dropped: this.dropped,
      pending: this.pending,
      accepted: {
        text: this.acceptedText,
        surface: this.acceptedSurface,
        selection: this.acceptedSelection,
        inputText: this.acceptedInputText,
        activity: this.acceptedActivity,
        gaps: this.acceptedGaps,
      },
      lastGapReason: this.lastGapReason,
      lastGapDiagnostic: this.lastGapDiagnostic ? { ...this.lastGapDiagnostic } : null,
      captureDiagnostics: this.captureDiagnostics ? { ...this.captureDiagnostics } : null,
    };
  }

  private async verifyHelperPath(): Promise<string> {
    if (!isAbsolute(this.options.helperPath)) {
      throw new Error('invalid-helper-manifest');
    }
    if (this.options.helperSha256 !== undefined && !/^[a-f0-9]{64}$/i.test(this.options.helperSha256)) {
      throw new Error('invalid-helper-manifest');
    }

    const stat = await lstat(this.options.helperPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 128 * 1024 * 1024) {
      throw new Error('unsafe-helper');
    }
    if (isPosixPlatform() && (stat.mode & 0o022) !== 0) {
      throw new Error('unsafe-helper');
    }

    if (this.options.helperSha256 !== undefined) {
      const hash = createHash('sha256').update(await readFile(this.options.helperPath)).digest('hex');
      if (hash !== this.options.helperSha256.toLowerCase()) {
        throw new Error('helper-hash-mismatch');
      }
    }

    return this.options.helperPath;
  }

  async start(policy: CapturePolicy): Promise<SupervisorStatus> {
    if (
      this.state !== 'stopped' ||
      this.stopping ||
      this.process ||
      !policy.enabled ||
      !validApplicationPolicy(policy)
    ) {
      throw new Error('start-not-available');
    }
    if (!this.options.allowFixture && process.platform !== 'darwin') {
      throw new Error('unsupported-platform');
    }

    this.state = 'starting';
    this.reason = '';
    this.policy = structuredClone(policy);
    this.revision++;
    this.generation++;
    this.controlEpoch++;
    this.instanceId = randomUUID();
    this.ownerId = randomUUID();
    this.streamDecoder = new FrameDecoder();
    this.acceptedGaps = 0;
    this.lastGapReason = null;
    this.lastGapDiagnostic = null;
    this.captureDiagnostics = null;

    const runId = this.instanceId;
    const logDebug = (event: string, detail?: Record<string, string | number | boolean | null>) => {
      if (!this.options.debugTrace || !this.options.debugLog) return;
      this.options.debugLog.append({
        timeMs: Date.now(),
        runId,
        event,
        ...(detail ? { detail } : {}),
      });
    };

    this.debugTrace = new CollectorDebugTrace(this.options.debugTrace === true, {
      runId,
      onEntry: (entry) => this.options.debugLog?.append(entry),
    });

    this.currentStamp = undefined;
    this.applicationAnchor = undefined;
    this.admission = undefined;
    this.dispatchEnabled = false;
    this.userPaused = false;
    this.configuredRequestId = undefined;
    this.controlBusy = false;
    this.readRecovery = undefined;

    const launchControlEpoch = this.controlEpoch;
    let activation: NonNullable<CollectorSupervisor['activation']> | undefined;

    try {
      const launchGeneration = this.generation;
      const helperPath = await this.verifyHelperPath();
      if (launchGeneration !== this.generation || this.state !== 'starting') {
        throw new Error('start-cancelled');
      }

      logDebug('collection-start');
      const child = this.options.spawn({
        argv: [
          helperPath,
          this.options.allowFixture ? '--fixture' : '--serve',
          '--owner-id',
          this.ownerId,
          '--instance-id',
          this.instanceId,
          '--device-id',
          this.options.deviceId,
          ...(this.options.allowFixture ? (this.options.fixtureArgs ?? []) : []),
        ],
        cwd: this.options.cwd || dirname(helperPath),
        stdio: { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' },
        env: this.options.debugTrace
          ? { COMPUTER_ACCESS_DEBUG: '1', DSH_COMPUTER_ACCESS_DEBUG: '1' }
          : {},
        graceMs: 500,
      });

      this.process = child;
      if (!child.stdin || !child.stdout || !child.stderr) {
        throw new Error('missing-helper-pipes');
      }

      const ready = new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          this.hello = undefined;
          reject(new Error('helper-hello-timeout'));
        }, this.timeout);
        this.hello = { resolve, reject, timer };
      });

      child.stdout.on('data', (chunk: Buffer) => {
        if (this.process !== child || this.state === 'failed') return;
        try {
          for (const message of this.streamDecoder.push(chunk)) {
            if (this.process !== child) break;
            this.message(message);
          }
        } catch {
          this.fail('invalid-helper-frame');
        }
      });

      child.stderr.on('data', (chunk: Buffer) => {
        if (this.process === child) {
          this.debugTrace.push(chunk);
        }
      });

      child.stdin.on('error', () => {
        if (this.process === child && this.state !== 'stopped') {
          this.fail('helper-input-closed');
        }
      });

      void child.done.then(
        (result) => {
          logDebug('helper-exit', { exitCode: result.exitCode, signal: result.signal });
          if (this.process !== child) return;
          this.debugTrace.reset();
          this.process = undefined;
          if (this.state !== 'stopped' && this.state !== 'failed') {
            this.fail('helper-exited');
          }
        },
        () => {
          if (this.process === child) {
            this.process = undefined;
            if (this.state !== 'stopped' && this.state !== 'failed') {
              this.fail('helper-exited');
            }
          }
        },
      );

      await ready;
      if (launchGeneration !== this.generation) {
        throw new Error('start-cancelled');
      }

      const requestId = randomUUID();
      this.admission = new CollectorAdmission(
        { ownerId: this.ownerId, instanceId: this.instanceId, requestId, policyRevision: this.revision },
        { captureEpoch: 0, foregroundGeneration: 0, focusGeneration: 0, policyRevision: this.revision },
        (message) => this.authorize(message),
      );

      const response = await this.request(
        {
          protocolVersion: 1,
          type: 'configure',
          requestId,
          ownerId: this.ownerId,
          instanceId: this.instanceId,
          policyRevision: this.revision,
          policy: this.policy,
        },
        'configured',
      );
      if (
        this.process !== child ||
        this.state !== 'starting' ||
        response.type !== 'configured' ||
        !this.admission?.acknowledge(response)
      ) {
        throw new Error('configuration-ack-mismatch');
      }

      activation = { child, epoch: launchControlEpoch, cleared: false };
      this.activation = activation;

      const started = await this.command('start');
      const latest = this.status();
      if (latest.state === 'failed') {
        throw new Error(latest.reason);
      }
      if (this.process !== child || this.stopping) {
        throw new Error('start-cancelled');
      }

      const suppressed = started.state === 'paused' && started.reason === 'secure-input-suppressed';
      if (started.state !== 'running' && !suppressed) {
        this.reason = nativeReason(started.reason, 'collector-not-running');
        throw new Error(this.reason);
      }

      const latestSuppressed = latest.state === 'paused' && latest.reason === 'secure-input-suppressed';
      const latestRecovery = latest.state === 'paused' && latest.reason === 'read-timeout-recovering';
      if (
        this.controlEpoch !== launchControlEpoch ||
        (this.state !== 'starting' && !latestSuppressed && !latestRecovery)
      ) {
        throw new Error('start-cancelled');
      }

      const blocked =
        (latestRecovery && !activation.recovered) ||
        ((suppressed || latestSuppressed) && !activation.cleared);
      if (this.activation === activation) {
        this.activation = undefined;
      }
      this.dispatchEnabled = !blocked;
      this.state = blocked ? 'paused' : 'running';
      this.reason = blocked
        ? latestRecovery
          ? 'read-timeout-recovering'
          : 'secure-input-suppressed'
        : '';
      if (activation.recovered) {
        this.readRecovery = undefined;
      }

      this.heartbeat = setInterval(() => {
        if (!this.controlBusy && this.process === child && this.state !== 'stopped' && this.state !== 'failed') {
          void this.command('heartbeat').catch(() => {
            if (this.process === child && this.state !== 'stopped') {
              this.fail('heartbeat-failed');
            }
          });
        }
      }, Math.floor(this.lease / 3));

      return this.status();
    } catch {
      if (this.activation === activation) {
        this.activation = undefined;
      }
      if (launchControlEpoch !== this.controlEpoch && !['failed', 'paused'].includes(this.status().state)) {
        if (this.stopping) await this.stopping;
        throw new Error(this.reason || 'start-cancelled');
      }
      const failedReason = this.reason || 'start-failed';
      await this.stop();
      if (this.status().state !== 'failed') {
        this.state = 'failed';
        this.reason = failedReason;
      }
      throw new Error(this.reason);
    }
  }

  private authorize(message: Observation): boolean {
    if (!this.dispatchEnabled || !this.policy?.enabled || message.stamp.policyRevision !== this.revision) {
      return false;
    }
    if (message.target.kind !== 'unresolved' && !applicationAllowed(this.policy, message.target.identity.applicationId)) {
      return false;
    }
    if (message.payload.kind === 'gap') {
      return (
        message.payload.providerApplicationId === undefined ||
        applicationAllowed(this.policy, message.payload.providerApplicationId)
      );
    }
    if (message.payload.kind === 'input.activity') {
      return (
        this.policy.inputActivity === true &&
        message.target.kind === 'application' &&
        applicationAllowed(this.policy, message.target.identity.applicationId) &&
        message.target.identity.deviceId === this.options.deviceId &&
        (message.payload.source === 'cg.listen-only' || this.options.allowFixture === true) &&
        message.payload.gate.policyRevision === this.revision &&
        message.payload.gate.secureInput === 'inactive' &&
        message.payload.gate.targetAttribution === 'event-target-pid' &&
        message.payload.gate.detail === 'coarse-counts'
      );
    }
    if (
      message.target.kind !== 'resolved' ||
      !applicationAllowed(this.policy, message.target.identity.applicationId) ||
      message.target.identity.deviceId !== this.options.deviceId
    ) {
      return false;
    }
    if (message.payload.kind === 'context.changed') {
      return true;
    }

    const value = message.payload;
    const gateAllowed = (
      gate: { secure: string; privateState: string; policyRevision: number } | undefined,
    ) =>
      !!gate &&
      (gate.secure === 'safe' ||
        (gate.secure === 'not-declared-sensitive' && this.policy?.fieldSecurity === 'denylist')) &&
      gate.policyRevision === this.revision &&
      (gate.privateState === 'normal' ||
        (gate.privateState === 'user-authorized' &&
          this.policy?.applicationScope === 'denylist' &&
          this.policy.allowBrowserContent === true));

    if (value.kind === 'surface.snapshot') {
      return (
        (this.policy.captureScope === 'region' || this.policy.captureScope === 'window') &&
        value.scope === this.policy.captureScope &&
        value.nodes.length <= (this.policy.maxTreeNodes ?? 64) &&
        value.nodes.reduce((sum, node) => sum + (node.text?.length ?? 0), 0) <= this.policy.maxTextCodeUnits &&
        (value.source !== 'fixture' || this.options.allowFixture === true) &&
        gateAllowed(value.gate)
      );
    }
    if (value.kind === 'selection.snapshot') {
      return (
        this.policy.selectionCapture === true &&
        value.text.length <= this.policy.maxTextCodeUnits &&
        (value.source !== 'fixture' || this.options.allowFixture === true) &&
        (value.source !== 'ax.marker' || this.policy.textMarkers === true) &&
        gateAllowed(value.gate)
      );
    }
    if (value.kind === 'input.text') {
      return (
        this.policy.inputText === true &&
        value.text.length <= Math.min(2048, this.policy.maxTextCodeUnits) &&
        (value.source !== 'fixture' || this.options.allowFixture === true) &&
        gateAllowed(value.gate)
      );
    }

    const text = value.kind === 'text.changed' ? value.after : value;
    const basis = text.rangeBasis ?? 'prefix';
    if (basis !== (this.policy.textRange ?? 'prefix')) return false;
    if (basis === 'prefix' && text.range && text.range.start !== 0) return false;
    if (
      basis === 'visible' &&
      ((text.source !== 'ax.range' &&
        !(text.source === 'ax.marker' && this.policy.textMarkers === true) &&
        !(text.source === 'fixture' && this.options.allowFixture === true)) ||
        text.scope !== 'accessible-range' ||
        text.coverage.status !== 'partial' ||
        !text.coverage.missingReasons.includes('visible-range-only'))
    ) {
      return false;
    }
    if (text.source === 'ax.marker' && this.policy.textMarkers !== true) return false;
    if (text.source === 'fixture') return this.options.allowFixture === true;
    return gateAllowed(text.gate);
  }

  private message(message: WireMessage): void {
    if (this.state === 'failed') return;

    if (message.type === 'error') {
      const code = message.code;
      this.fail(
        code === 'permission-denied' || code === 'unsupported' || code === 'stale'
          ? `helper-${code}`
          : 'helper-protocol-error',
      );
      return;
    }

    if (!('instanceId' in message) || message.instanceId !== this.instanceId) {
      this.fail('helper-instance-mismatch');
      return;
    }

    if (message.type === 'hello') {
      const ready = this.hello;
      if (!ready) {
        this.fail('unexpected-hello');
        return;
      }
      clearTimeout(ready.timer);
      this.hello = undefined;

      if (!message.capabilities.some((c) => c.name === 'text.snapshot' && c.direction === 'observe' && c.support === 'supported')) {
        ready.reject(new Error('text-capability-unavailable'));
      } else if (
        this.policy?.textRange === 'visible' &&
        !message.capabilities.some((c) => c.name === 'text.visible-range' && c.direction === 'observe' && c.support === 'supported')
      ) {
        this.reason = 'text-visible-range-unavailable';
        ready.reject(new Error(this.reason));
      } else if (
        this.policy?.inputActivity === true &&
        !message.capabilities.some((c) => c.name === 'input.activity' && c.direction === 'observe' && c.support === 'supported')
      ) {
        this.reason = 'input-monitoring-unavailable';
        ready.reject(new Error(this.reason));
      } else {
        const required = [
          this.policy?.fieldSecurity === 'denylist' && 'field.denylist',
          this.policy?.axCompatibility === true && 'ax.enablement',
          this.policy?.textMarkers === true && 'text.marker',
          this.policy?.captureScope !== undefined && this.policy.captureScope !== 'focused' && 'surface.snapshot',
          this.policy?.selectionCapture === true && 'selection.snapshot',
          this.policy?.inputText === true && 'input.text',
        ].filter(Boolean);

        if (
          required.some(
            (name) =>
              !message.capabilities.some((c) => c.name === name && c.direction === 'observe' && c.support === 'supported'),
          )
        ) {
          this.reason = 'content-capability-unavailable';
          ready.reject(new Error(this.reason));
        } else {
          ready.resolve();
        }
      }
      return;
    }

    if (message.type === 'configured' || message.type === 'state') {
      const pending = this.requests.get(message.requestId);
      if (pending && pending.expected === message.type) {
        this.requests.delete(message.requestId);
        clearTimeout(pending.timer);
        if (message.type === 'state') {
          if (message.stamp.policyRevision !== this.revision || !this.advance(message.stamp)) {
            pending.reject(new Error('state-stale'));
            return;
          }
          this.captureDiagnostics =
            message.state === 'running' && !this.userPaused && !this.stopping && message.captureDiagnostics
              ? { ...message.captureDiagnostics }
              : null;
          if (message.state === 'paused') {
            this.dispatchEnabled = false;
            if (this.state !== 'stopped') {
              this.state = 'paused';
              this.reason = nativeReason(message.reason, this.reason || 'user-paused');
              if (this.reason !== 'read-timeout-recovering' || message.reason !== 'read-timeout-recovering') {
                this.readRecovery = undefined;
              }
            }
          }
          if (message.requestId === this.activation?.requestId && message.state === 'running') {
            this.activation.runningAck = true;
          }
          if (message.state === 'stopped' && this.state !== 'stopped') {
            this.fail('collector-stopped');
          }
        }
        if (message.type === 'configured') {
          this.configuredRequestId = message.requestId;
        }
        pending.resolve(message);
        return;
      }

      if (this.state === 'stopped') return;

      if (message.type === 'state' && !pending) {
        const terminal = terminalNotice(message);
        if (terminal) {
          this.fail(this.isNonStaleStamp(message.stamp) ? terminal : 'unexpected-helper-response');
          return;
        }
      }

      if (
        message.type === 'state' &&
        message.requestId === this.configuredRequestId &&
        message.state === 'ready' &&
        this.state === 'starting' &&
        this.advance(message.stamp)
      ) {
        return;
      }

      if (message.type === 'state' && message.requestId === 'read-recovery') {
        this.readRecoveryNotice(message);
        return;
      }

      if (
        message.type === 'state' &&
        message.state === 'running' &&
        message.requestId === 'desktop' &&
        (this.policy?.inputText === true || this.policy?.inputActivity === true)
      ) {
        this.fail('unexpected-helper-response');
        return;
      }

      if (message.type === 'state' && message.stamp.policyRevision === this.revision && this.advance(message.stamp)) {
        this.captureDiagnostics =
          message.state === 'running' && !this.userPaused && !this.stopping && message.captureDiagnostics
            ? { ...message.captureDiagnostics }
            : null;
        const activation = this.activation;
        if (message.state === 'paused') {
          if (activation) activation.cleared = false;
          this.readRecovery = undefined;
          this.dispatchEnabled = false;
          if (
            this.pauseEpoch !== this.controlEpoch &&
            !(
              message.reason === 'secure-input-suppressed' &&
              activation &&
              activation.child === this.process &&
              activation.epoch === this.controlEpoch
            )
          ) {
            this.controlEpoch++;
            this.controlBusy = false;
          }
          this.state = 'paused';
          this.reason = nativeReason(message.reason, this.reason || 'desktop-unavailable');
          return;
        }
        if (
          message.state === 'running' &&
          message.requestId === 'secure-input' &&
          message.reason === 'secure-input-cleared' &&
          this.state === 'paused' &&
          this.reason === 'secure-input-suppressed' &&
          activation &&
          activation.child === this.process &&
          activation.epoch === this.controlEpoch
        ) {
          activation.cleared = true;
          return;
        }
        if (
          message.state === 'running' &&
          (message.requestId === 'desktop' ||
            (message.requestId === 'secure-input' &&
              message.reason === 'secure-input-cleared' &&
              this.reason === 'secure-input-suppressed')) &&
          this.state === 'paused' &&
          !this.userPaused &&
          !this.controlBusy
        ) {
          this.dispatchEnabled = true;
          this.state = 'running';
          this.reason = '';
          return;
        }
      }

      this.fail('unexpected-helper-response');
      return;
    }

    if (message.type !== 'observation') {
      this.fail('unexpected-helper-message');
      return;
    }

    this.received++;
    if (!this.dispatchEnabled || !this.admission) {
      this.dropped++;
      return;
    }
    if (message.payload.kind === 'context.changed' || message.payload.kind === 'gap') {
      if (!this.advance(message.stamp, message)) {
        this.dropped++;
        return;
      }
    }

    const admission = this.admission;
    const decision = admission.accept(message);
    if (!decision.accepted) {
      this.dropped++;
      return;
    }

    if (this.policy?.inputActivity === true && message.target.kind !== 'unresolved') {
      const anchor = this.applicationAnchor;
      if (anchor?.epoch === message.stamp.captureEpoch && !sameApplication(anchor.identity, message.target.identity)) {
        admission.discard(message.eventId);
        this.dropped++;
        this.fail('input-activity-identity-changed');
        return;
      }
      if (!anchor || anchor.epoch !== message.stamp.captureEpoch) {
        this.applicationAnchor = {
          epoch: message.stamp.captureEpoch,
          identity: structuredClone(message.target.identity),
        };
      }
    }

    const limit = this.policy?.maxPending ?? 16;
    if (this.pending >= limit) {
      this.pruneObsoleteWaiting();
      if (this.pending >= limit) {
        admission.discard(message.eventId);
        this.dropped++;
        this.fail('host-backpressure');
        return;
      }
    }

    this.waiting.push({
      message,
      admission,
      generation: this.generation,
      enqueuedAt: performance.now(),
    });
    this.work ??= Promise.resolve().then(() => this.drainObservations());
  }

  private sameAuthority({ message, admission, generation }: PendingObservation): boolean {
    const stamp = message.stamp;
    return (
      this.admission === admission &&
      this.currentStamp !== undefined &&
      (message.payload.kind === 'input.activity'
        ? this.policy?.inputActivity === true &&
          this.currentStamp.captureEpoch === stamp.captureEpoch &&
          this.currentStamp.policyRevision === stamp.policyRevision &&
          this.currentStamp.foregroundGeneration >= stamp.foregroundGeneration &&
          this.currentStamp.focusGeneration >= stamp.focusGeneration
        : this.generation === generation && sameStamp(this.currentStamp, stamp))
    );
  }

  private discardWaiting(item: PendingObservation): void {
    item.admission.discard(item.message.eventId);
    this.dropped++;
  }

  private pruneObsoleteWaiting(): void {
    this.waiting = this.waiting.filter((item) => {
      if (this.sameAuthority(item)) return true;
      this.discardWaiting(item);
      return false;
    });
  }

  private async drainObservations(): Promise<void> {
    try {
      for (let item; (item = this.waiting.shift()); ) {
        try {
          await this.persist(item);
        } catch {
          item.admission.discard(item.message.eventId);
          this.fail('storage-commit-failed');
        } finally {
          this.writing = undefined;
        }
      }
    } finally {
      this.work = undefined;
    }
  }

  private async persist(item: PendingObservation): Promise<void> {
    const { message, admission } = item;
    const isCurrent = () => this.dispatchEnabled && this.sameAuthority(item);
    if (!isCurrent()) {
      this.discardWaiting(item);
      return;
    }
    this.writing = { startedAt: performance.now() };
    await this.options.onObservation(structuredClone(message), isCurrent);
    if (isCurrent()) {
      admission.commit(message.eventId);
      if (message.payload.kind === 'text.snapshot' || message.payload.kind === 'text.changed') {
        this.acceptedText++;
      }
      if (message.payload.kind === 'input.activity') {
        this.acceptedActivity++;
      }
      if (message.payload.kind === 'surface.snapshot') {
        this.acceptedSurface++;
      }
      if (message.payload.kind === 'selection.snapshot') {
        this.acceptedSelection++;
      }
      if (message.payload.kind === 'input.text') {
        this.acceptedInputText++;
      }
      if (message.payload.kind === 'gap') {
        this.acceptedGaps = addCount(this.acceptedGaps, 1);
        this.lastGapReason = message.payload.reason;
        this.lastGapDiagnostic = message.payload.diagnostic ? { ...message.payload.diagnostic } : null;
      }
    } else {
      admission.discard(message.eventId);
    }
  }

  private readRecoveryNotice(message: State): void {
    const { stamp, reason } = message;
    const previous = this.currentStamp;
    const recovery = this.readRecovery;
    const activation = this.activation;
    const startAckPending =
      activation?.child === this.process &&
      activation?.epoch === this.controlEpoch &&
      activation?.runningAck === true &&
      !this.controlBusy;

    if (this.stopping || this.state === 'stopped') return;
    if (reason === 'read-timeout-recovered' && (this.userPaused || this.controlBusy)) return;
    if (message.state === 'paused' && reason === 'read-timeout-recovering' && this.userPaused) return;
    if (this.policy?.inputText !== true || !previous || stamp.policyRevision !== this.revision) {
      this.fail('unexpected-helper-response');
      return;
    }
    if (
      message.state === 'paused' &&
      reason === 'read-timeout-recovering' &&
      (this.state === 'running' || (this.state === 'starting' && startAckPending)) &&
      !this.controlBusy &&
      stamp.captureEpoch > previous.captureEpoch &&
      this.advance(stamp)
    ) {
      this.dispatchEnabled = false;
      this.state = 'paused';
      this.reason = reason;
      this.readRecovery = { stamp: structuredClone(stamp), controlEpoch: this.controlEpoch };
      return;
    }
    if (
      message.state === 'running' &&
      reason === 'read-timeout-recovered' &&
      recovery?.controlEpoch === this.controlEpoch &&
      this.state === 'paused' &&
      this.reason === 'read-timeout-recovering' &&
      sameStamp(stamp, recovery.stamp) &&
      sameStamp(stamp, previous) &&
      this.advance(stamp)
    ) {
      if (startAckPending) {
        activation!.recovered = true;
        return;
      }
      this.readRecovery = undefined;
      this.dispatchEnabled = true;
      this.state = 'running';
      this.reason = '';
      return;
    }
    if (
      message.state === 'paused' &&
      (reason === 'read-timeout-exhausted' ||
        reason === 'read-timeout-unrecoverable' ||
        reason === 'worker-exit-unconfirmed') &&
      (this.state === 'running' ||
        recovery?.controlEpoch === this.controlEpoch ||
        this.userPaused ||
        (this.state === 'paused' &&
          this.reason === 'read-timeout-recovering' &&
          this.activation?.epoch === this.controlEpoch)) &&
      stamp.captureEpoch > previous.captureEpoch &&
      this.advance(stamp)
    ) {
      this.readRecovery = undefined;
      this.dispatchEnabled = false;
      this.state = 'paused';
      if (!this.userPaused) this.reason = reason;
      return;
    }
    this.fail('unexpected-helper-response');
  }

  private isNonStaleStamp(stamp: Stamp): boolean {
    if (stamp.policyRevision !== this.revision) return false;
    const previous = this.currentStamp;
    if (!previous) return true;
    return (
      stamp.captureEpoch >= previous.captureEpoch &&
      stamp.foregroundGeneration >= previous.foregroundGeneration &&
      stamp.focusGeneration >= previous.focusGeneration
    );
  }

  private advance(stamp: Stamp, context?: Observation): boolean {
    if (!this.isNonStaleStamp(stamp)) return false;
    const previous = this.currentStamp;
    if (!previous || !sameStamp(previous, stamp)) {
      this.generation++;
      this.currentStamp = structuredClone(stamp);
      this.captureDiagnostics = null;
      this.admission?.setBoundary(
        stamp,
        context?.target.kind === 'resolved' ? context.target.identity : undefined,
      );
    } else if (context?.payload.kind === 'context.changed') {
      this.generation++;
      this.admission?.setBoundary(
        stamp,
        context.target.kind === 'resolved' ? context.target.identity : undefined,
      );
    }
    return true;
  }

  private request(message: WireMessage & { requestId: string }, expected: WireMessage['type']): Promise<WireMessage> {
    const child = this.process;
    if (!child?.stdin || child.stdin.destroyed) {
      return Promise.reject(new Error('helper-unavailable'));
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.requests.delete(message.requestId);
        reject(new Error('helper-response-timeout'));
      }, this.timeout);
      this.requests.set(message.requestId, { expected, resolve, reject, timer });
      const frame = encodeFrame(message);
      if (child.stdin!.writableLength + frame.byteLength > 131072) {
        clearTimeout(timer);
        this.requests.delete(message.requestId);
        reject(new Error('helper-input-backpressure'));
        return;
      }
      child.stdin!.write(frame, (error) => {
        if (error) {
          clearTimeout(timer);
          this.requests.delete(message.requestId);
          reject(new Error('helper-write-failed'));
        }
      });
    });
  }

  private async command(command: 'start' | 'pause' | 'resume' | 'stop' | 'heartbeat'): Promise<State> {
    if (!this.instanceId) throw new Error('helper-unavailable');
    const requestId = randomUUID();
    if ((command === 'start' || command === 'resume') && this.activation) {
      this.activation.requestId = requestId;
    }
    const response = await this.request(
      {
        protocolVersion: 1,
        type: 'control',
        requestId,
        ownerId: this.ownerId,
        instanceId: this.instanceId,
        policyRevision: this.revision,
        command,
        leaseDurationMs: this.lease,
      },
      'state',
    );
    if (response.type !== 'state') throw new Error('wrong-control-response');
    return response;
  }

  async pause(): Promise<SupervisorStatus> {
    if (!this.process || this.stopping || this.controlBusy || (this.state !== 'running' && this.state !== 'paused')) {
      throw new Error('pause-unavailable');
    }
    const child = this.process;
    const epoch = ++this.controlEpoch;
    const current = () => this.process === child && this.controlEpoch === epoch && !this.stopping;
    if (this.activation) this.activation.cleared = false;
    this.readRecovery = undefined;
    this.dispatchEnabled = false;
    this.userPaused = true;
    this.generation++;
    this.controlBusy = true;
    this.pauseEpoch = epoch;
    this.captureDiagnostics = null;
    try {
      const response = await this.command('pause');
      if (!current()) throw new Error('pause-cancelled');
      if (response.state !== 'paused') throw new Error('pause-rejected');
      this.state = 'paused';
      this.reason = 'user-paused';
      await this.work;
      if (!current()) throw new Error('pause-cancelled');
      return this.status();
    } catch {
      if (current()) this.fail('pause-failed');
      throw new Error('pause-failed');
    } finally {
      if (this.pauseEpoch === epoch) this.pauseEpoch = undefined;
      if (this.controlEpoch === epoch) this.controlBusy = false;
    }
  }

  async resume(): Promise<SupervisorStatus> {
    if (!this.process || this.stopping || this.controlBusy || this.state !== 'paused') {
      throw new Error('resume-unavailable');
    }
    const child = this.process;
    const epoch = ++this.controlEpoch;
    const current = () => this.process === child && this.controlEpoch === epoch && !this.stopping;
    this.readRecovery = undefined;
    this.dispatchEnabled = false;
    this.controlBusy = true;
    const activation = { child, epoch, cleared: false };
    this.activation = activation;
    try {
      const response = await this.command('resume');
      if (!current()) throw new Error('resume-cancelled');
      const suppressed = response.state === 'paused' && response.reason === 'secure-input-suppressed';
      if (response.state !== 'running' && !suppressed) throw new Error('resume-rejected');
      const blocked =
        (suppressed || (this.state === 'paused' && this.reason === 'secure-input-suppressed')) &&
        !activation.cleared;
      this.dispatchEnabled = !blocked;
      this.userPaused = false;
      this.state = blocked ? 'paused' : 'running';
      this.reason = blocked ? 'secure-input-suppressed' : '';
      return this.status();
    } catch {
      if (current()) {
        this.dispatchEnabled = false;
        this.userPaused = true;
      }
      throw new Error('resume-failed');
    } finally {
      if (this.activation === activation) this.activation = undefined;
      if (this.controlEpoch === epoch) this.controlBusy = false;
    }
  }

  private fail(reason: CollectorFaultReason): void {
    const phase = this.state;
    if (phase === 'failed') return;
    if (this.activation) this.activation.cleared = false;
    this.readRecovery = undefined;
    this.dispatchEnabled = false;
    this.generation++;
    this.controlEpoch++;
    this.reason = reason;
    this.state = 'failed';
    this.admission?.revoke();
    this.captureDiagnostics = null;
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = undefined;
    if (this.hello) {
      clearTimeout(this.hello.timer);
      this.hello.reject(new Error(reason));
      this.hello = undefined;
    }
    for (const pending of this.requests.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error(reason));
    }
    this.requests.clear();
    if (this.instanceId && this.options.debugTrace && this.options.debugLog) {
      this.options.debugLog.append({
        timeMs: Date.now(),
        runId: this.instanceId,
        event: 'collector-fault',
        detail: { phase, reason },
      });
    }
    this.process?.terminate();
  }

  stop(): Promise<SupervisorStatus> {
    if (this.stopping) return this.stopping;
    const operation = this.stopOwned();
    this.stopping = operation;
    void operation.then(
      () => {
        if (this.stopping === operation) this.stopping = undefined;
      },
      () => {
        if (this.stopping === operation) this.stopping = undefined;
      },
    );
    return operation;
  }

  private async stopOwned(): Promise<SupervisorStatus> {
    const failed = this.state === 'failed';
    if (this.activation) this.activation.cleared = false;
    this.readRecovery = undefined;
    this.dispatchEnabled = false;
    this.generation++;
    this.controlEpoch++;
    this.admission?.revoke();
    this.captureDiagnostics = null;
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = undefined;
    if (!failed) this.state = 'stopped';
    this.controlBusy = true;

    for (const pending of this.requests.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error('stopped'));
    }
    this.requests.clear();
    if (this.hello) {
      clearTimeout(this.hello.timer);
      this.hello.reject(new Error('stopped'));
      this.hello = undefined;
    }

    const child = this.process;
    let confirmed = child === undefined;
    if (child) {
      if (!failed) {
        try {
          await this.command('stop');
        } catch {
          // Proceed with process termination.
        }
      }
      child.stdin?.end();
      child.terminate();
      const timeout = new AbortController();
      const timer = setTimeout(() => timeout.abort(), this.timeout);
      try {
        confirmed = await child.waitForExit(timeout.signal);
        if (!confirmed) throw new Error('helper-exit-unconfirmed');
      } catch {
        this.reason = 'helper-exit-unconfirmed';
        this.state = 'failed';
      } finally {
        clearTimeout(timer);
      }
      if (confirmed && this.process === child) {
        this.process = undefined;
      }
    }

    for (const pending of this.requests.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error('stopped'));
    }
    this.requests.clear();

    await this.work;
    if (failed && confirmed) this.state = 'stopped';
    if (this.state === 'stopped') {
      this.reason = '';
      this.userPaused = false;
      this.controlBusy = false;
    }
    return this.status();
  }
}

export { LIMITS, PROTOCOL_VERSION } from './protocol/generated.ts';
export type {
  ActionReceipt,
  ActionRequest,
  ApplicationTargetIdentity,
  Capability,
  CaptureDiagnostics,
  CapturePolicy,
  Configure,
  Configured,
  ContentGate,
  Control,
  Coverage,
  EvidenceRelation,
  Gap,
  GapDiagnostic,
  Hello,
  InputActivity,
  InputText,
  Observation,
  ProtocolFailure,
  SelectionSnapshot,
  Stamp,
  State,
  SurfaceBounds,
  SurfaceGeometry,
  SurfaceNode,
  SurfaceSnapshot,
  TargetIdentity,
  TargetRef,
  TextChanged,
  TextRange,
  TextSnapshot,
  WireMessage,
} from './protocol/generated.ts';

export type CollectorFaultReason =
  | 'invalid-helper-frame'
  | 'helper-input-closed'
  | 'helper-exited'
  | 'heartbeat-failed'
  | 'helper-permission-denied'
  | 'helper-unsupported'
  | 'helper-stale'
  | 'helper-protocol-error'
  | 'helper-instance-mismatch'
  | 'unexpected-hello'
  | 'collector-stopped'
  | 'unexpected-helper-response'
  | 'unexpected-helper-message'
  | 'input-activity-identity-changed'
  | 'host-backpressure'
  | 'storage-commit-failed'
  | 'pause-failed'
  | 'helper-lease-expired'
  | 'helper-owner-eof'
  | 'helper-parent-death'
  | 'helper-signaled';

export interface DebugLogEntry {
  timeMs: number;
  runId?: string;
  event: string;
  detail?: Record<string, string | number | boolean | null>;
}

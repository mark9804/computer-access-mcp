export { createManagedRunner, ManagedRunnerError } from './managed-runner.ts';
export type {
  ManagedRunnerController,
  ManagedRunnerErrorCode,
  SubprocessRunner,
  SubprocessRunRequest,
  SubprocessRunResult,
} from './managed-runner.ts';
export { CollectorAdmission } from './collectors/admission.ts';
export { CollectorDebugLog } from './collectors/debug-log.ts';
export { CollectorDebugTrace } from './collectors/debug-trace.ts';
export {
  canRelateEvidence,
   EvidenceCorrelator,
  evidenceMetadata,
  sameSurfaceContext,
  sameWindowContext,
} from './collectors/evidence-correlator.ts';
export type {
  EvidenceKind,
  EvidenceMetadata,
  SurfaceContextIdentity,
  WindowContextIdentity,
} from './collectors/evidence-correlator.ts';
export { spawnLocal } from './collectors/local-process.ts';
export type { ManagedProcess, SpawnManaged, SpawnSpec } from './collectors/process.ts';
export { CollectorSupervisor } from './collectors/supervisor.ts';
export type { SupervisorOptions, SupervisorStatus } from './collectors/supervisor.ts';
export { verifyNativeBinary } from './service/binaries.ts';
export type { BinaryFacts } from './service/binaries.ts';
export {
  createHistoryLayoutUnavailable,
  HISTORY_LAYOUT_MAX_BYTES,
  HistoryLayoutError,
  normalizeHistoryLayoutRequest,
  projectHistoryLayout,
} from './service/history-layout.ts';
export type {
  HistoryLayoutErrorCode,
  HistoryLayoutProjection,
  HistoryLayoutProjectionOptions,
} from './service/history-layout.ts';
export { createHistoryService, HistoryOperationError } from './service/history-service.ts';
export type { HistoryServiceOptions } from './service/history-service.ts';
export {
  createPermissionActions,
  parsePermissionReport,
  PermissionActionError,
  toPermissionStatus,
} from './service/permissions.ts';
export type { PermissionAction, PermissionReport } from './service/permissions.ts';
export {
  createSourceNavigation,
  navigationReport,
  parseSourceNavigationReport,
} from './service/source-navigation.ts';
export type { NavigationOutcome, SourceNavigationReport } from './service/source-navigation.ts';

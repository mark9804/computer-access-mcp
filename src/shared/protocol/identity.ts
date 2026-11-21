import type { Stamp, TargetIdentity, ApplicationTargetIdentity } from './generated.ts';
export function sameTarget(a: TargetIdentity, b: TargetIdentity): boolean {
  return a.deviceId === b.deviceId && a.osSessionId === b.osSessionId && a.desktopId === b.desktopId && a.processId === b.processId && a.processStartTime === b.processStartTime && a.applicationId === b.applicationId && a.windowId === b.windowId && a.windowGeneration === b.windowGeneration;
}
export function sameApplication(a: ApplicationTargetIdentity, b: ApplicationTargetIdentity): boolean {
  return a.deviceId === b.deviceId && a.osSessionId === b.osSessionId && a.desktopId === b.desktopId && a.processId === b.processId && a.processStartTime === b.processStartTime && a.applicationId === b.applicationId;
}
export function sameStamp(a: Stamp, b: Stamp): boolean {
  return a.captureEpoch === b.captureEpoch && a.foregroundGeneration === b.foregroundGeneration && a.focusGeneration === b.focusGeneration && a.policyRevision === b.policyRevision;
}

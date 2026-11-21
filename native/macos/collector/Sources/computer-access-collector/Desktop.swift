import Foundation
import ApplicationServices
import IOKit
import Darwin
import CollectorCore
import CCollectorSupport

private func sessionEvidence() -> DesktopSessionEvidence {
    DesktopSessionEvidence(WorkerProgress.withValue(api: 20, { CGSessionCopyCurrentDictionary() }) as? [String: Any])
}
private func registryEvidence(_ session: DesktopSessionEvidence) -> RegistryDesktopEvidence {
    let root = WorkerProgress.withValue(api: 21, { IORegistryGetRootEntry(kIOMainPortDefault) })
    guard root != 0 else { return RegistryDesktopEvidence(rootLock: nil, rows: nil, session: session) }
    defer { IOObjectRelease(root) }
    // Read ONLY the two documented-in-XNU properties, not the entire registry.
    let lock = WorkerProgress.withValue(api: 22, attribute: 22, { IORegistryEntryCreateCFProperty(root, "IOConsoleLocked" as CFString, kCFAllocatorDefault, 0) })?.takeRetainedValue()
    let users = WorkerProgress.withValue(api: 22, attribute: 23, { IORegistryEntryCreateCFProperty(root, "IOConsoleUsers" as CFString, kCFAllocatorDefault, 0) })?.takeRetainedValue()
    return RegistryDesktopEvidence(rootLock: lock, rows: users, session: session)
}

/// User-initiated check or capture gate. No AX content, key, window list or title.
/// IOConsoleLocked is a compatibility signal, NOT an atomic per-session oracle.
/// Require identity, a unique console, no transition markers and stable samples;
/// missing lock fields alone can never admit a read. Any positive lock wins.
func desktopAssessment(traceStages: Bool = false, sampleStages: Bool = false) -> DesktopAssessment {
    // Timing is diagnostic only; a synchronous OS query still cannot be interrupted.
    func measure<T>(_ phase: Int64, _ stage: String, _ body: () -> T) -> T {
        guard traceStages, CollectorDebugTrace.enabled else { return body() }
        let started = DispatchTime.now().uptimeNanoseconds
        let value = body()
        let elapsedMs = Int64((DispatchTime.now().uptimeNanoseconds - started) / 1_000_000)
        if sampleStages || elapsedMs >= 50 {
            CollectorDebugTrace.record("desktop-validation-phase", numbers: ["phase": phase, "elapsedMs": elapsedMs], strings: ["stage": stage])
        }
        return value
    }
    let before = measure(1, "session-before") { sessionEvidence() }
    let registryBefore = measure(2, "registry-before") { registryEvidence(before) }
    let after = measure(3, "session-after") { sessionEvidence() }
    let registryAfter = measure(4, "registry-after") { registryEvidence(after) }
    var processAudit: UInt32 = 0
    let auditValid = measure(5, "audit") { WorkerProgress.withValue(api: 23, { collector_audit_session(&processAudit) }) == 0 }
    let matches = auditValid && before.uid == getuid() && after.uid == getuid() && before.audit == processAudit && after.audit == processAudit
    func lock(_ a: Bool?, _ b: Bool?) -> Bool? { a == true || b == true ? true : a == false && b == false ? false : nil }
    let assessment = DesktopAssessment(sessionAvailable: before.available && after.available,
        onConsole: after.onConsole, loginDone: after.loginDone,
        screenLocked: lock(before.screenLocked, after.screenLocked),
        consoleLocked: lock(registryBefore.consoleLocked, registryAfter.consoleLocked),
        registryScreenLocked: lock(registryBefore.matched?.screenLocked, registryAfter.matched?.screenLocked),
        registrySessionMatched: registryBefore.sessionMatched && registryAfter.sessionMatched,
        sessionMatchesProcess: matches,
        sessionStable: before.sameDesktop(as: after) && registryBefore.sameDesktop(as: registryAfter),
        signalsValid: before.valid && after.valid && registryBefore.valid && registryAfter.valid,
        lockTransition: before.lockTimeMarker || after.lockTimeMarker || registryBefore.matched?.lockTimeMarker == true || registryAfter.matched?.lockTimeMarker == true,
        secureInputMarker: before.secureInputMarker || after.secureInputMarker || registryBefore.matched?.secureInputMarker == true || registryAfter.matched?.secureInputMarker == true)
    if assessment.desktopStatus != .unlocked {
        CollectorDebugTrace.record("desktop-boundary-signal", numbers: ["phase": 1],
            flags: ["lockPositive": assessment.desktopStatus == .locked, "transition": assessment.lockTransition,
                    "secureInputMarker": before.secureInputMarker || after.secureInputMarker || registryBefore.matched?.secureInputMarker == true || registryAfter.matched?.secureInputMarker == true,
                    "lockTimeMarker": before.lockTimeMarker || after.lockTimeMarker || registryBefore.matched?.lockTimeMarker == true || registryAfter.matched?.lockTimeMarker == true],
            strings: ["reason": assessment.reason])
    }
    return assessment
}
func desktopStatus() -> DesktopStatus { desktopAssessment().desktopStatus }

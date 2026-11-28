import Foundation
import AppKit
import ApplicationServices
import Carbon
import CollectorCore

final class NativeEnvironment: CollectorEnvironment {
    private let fixture: Bool
    private let scenario: String
    private let worker: WorkerManager
    private var observers: [(NotificationCenter, NSObjectProtocol)] = []
    private var active = false
    private var nextCheck: Int64 = 0
    private var nextDesktopTraceSample: UInt64 = 0
    private var boundary = DesktopBoundaryLatch()
    private var inputMonitor: InputActivityMonitor?
    private var fixtureInput = false
    private var nextFixtureInput: Int64 = 0
    private var inputPolicy: CapturePolicy?
    private var inputActivityStarting = false
    private var capturePolicy: CapturePolicy?
    var excludedApplicationEvent: () -> Void = {}
    func configurePolicy(_ policy: CapturePolicy) { capturePolicy = policy }
    private(set) var desktopReason = "desktop-unavailable"
    private(set) var secureInputBlocked = false
    private(set) var inputActivityReason = "input-monitoring-unavailable"
    var inputActivityEvent: (InputActivitySample) -> Void = { _ in }
    var inputActivityInvalidated: () -> Void = {}
    var inputActivityDisabled: (String) -> Void = { _ in }
    var desktopEvent: (DesktopStatus, Bool) -> Void = { _, _ in }
    var secureInputEvent: () -> Void = {}
    var applicationEvent: (SourceHint) -> Void = { _ in }
    init(fixture: Bool, scenario: String, worker: WorkerManager) {
        self.fixture = fixture; self.scenario = scenario; self.worker = worker
    }
    func beginMonitoring() -> (desktop: DesktopStatus, accessibility: Bool) {
        if fixture {
            active = true
            return (scenario == "locked" ? .locked : (scenario == "unknown" ? .unknown : .unlocked), true)
        }
        if !active {
            active = true
            // NSWorkspace is touched for the first time here, after start, not
            // from constructors, hello, configure or executable argument parsing.
            let center = NSWorkspace.shared.notificationCenter
            nonisolated(unsafe) weak var weakSelf = self
            let token = center.addObserver(forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: .main) { note in
                dispatchPrecondition(condition: .onQueue(.main))
                guard let self = weakSelf, self.active else { return }
                let when = SystemCollectorClock().unixMs
                let application: (application: NSRunningApplication, applicationId: String)
                switch ApplicationAvailability.application(note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
                    bundleIdentifier: { $0.bundleIdentifier }) {
                case .success(let observed): application = observed
                case .failure(let rejection):
                    ApplicationAvailability.record(rejection == .applicationMissing ? .activationApplicationMissing : rejection, phase: .activation)
                    self.excludedApplicationEvent(); return
                }
                let app = application.application, id = application.applicationId
                guard let policy = self.capturePolicy,
                      ApplicationPolicy.allows(id, policy: policy), BrowserGate.allows(id, policy: policy) else {
                    self.excludedApplicationEvent(); return
                }
                let identity: ApplicationIdentity
                switch AppIdentityGate.identityObservation(app) {
                case .success(let observed): identity = observed
                case .failure(let rejection):
                    ApplicationAvailability.record(rejection, phase: .activation)
                    // Missing app birth/PID is an unattributed application boundary,
                    // not evidence that the OS desktop or AX permission changed.
                    // Clear/retire the old context; a fresh read must resolve its
                    // own identity. Never fill this event from a later frontmost app.
                    self.excludedApplicationEvent(); return
                }
                self.applicationEvent(SourceHint(application: identity, eventTimeMs: when))
            }
            observers.append((center, token))
            for name in [NSWorkspace.sessionDidResignActiveNotification, NSWorkspace.screensDidSleepNotification] {
                let token = center.addObserver(forName: name, object: nil, queue: .main) { _ in
                    dispatchPrecondition(condition: .onQueue(.main))
                    guard let self = weakSelf, self.active else { return }
                    CollectorDebugTrace.record("desktop-boundary-signal", numbers: ["phase": name == NSWorkspace.screensDidSleepNotification ? 3 : 2])
                    self.boundary.block(); self.secureInputBlocked = false; self.desktopReason = "desktop-lock-transition"; self.desktopEvent(.unknown, false)
                }
                observers.append((center, token))
            }
            let distributed = DistributedNotificationCenter.default()
            // A lock/sleep notification is sticky. Compatibility polling cannot
            // erase it; explicit resume/start is required, followed by fresh gates.
            let lock = distributed.addObserver(forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { _ in
                dispatchPrecondition(condition: .onQueue(.main))
                guard let self = weakSelf, self.active else { return }
                CollectorDebugTrace.record("desktop-boundary-signal", numbers: ["phase": 4])
                self.boundary.block(); self.secureInputBlocked = false; self.desktopReason = "screen-locked"; self.desktopEvent(.locked, false)
            }
            observers.append((distributed, lock))
        }
        nextCheck = SystemCollectorClock().monotonicMs + 250
        boundary.resetForUserAction() // beginMonitoring requires user start/resume.
        return validateBeforeAccept()
    }
    func poll() {
        // DEBUG timestamps surround existing work only. Emit after all original
        // checks, never before reading a ready Worker response or a safety gate.
        let started = CollectorDebugTrace.enabled ? SystemCollectorClock().monotonicMs : 0
        var workerMs: Int64 = 0, activityMs: Int64 = 0, desktopMs: Int64 = 0
        var phaseAt = started
        defer {
            if CollectorDebugTrace.enabled {
                let elapsed = SystemCollectorClock().monotonicMs - started
                if elapsed >= 50 {
                    CollectorDebugTrace.record("collector-poll-summary", numbers: [
                        "elapsedMs": elapsed, "workerMs": workerMs, "activityMs": activityMs, "desktopMs": desktopMs,
                    ])
                }
            }
        }
        worker.poll()
        if CollectorDebugTrace.enabled {
            let end = SystemCollectorClock().monotonicMs; workerMs = end - phaseAt; phaseAt = end
        }
        inputMonitor?.poll()
        if CollectorDebugTrace.enabled {
            let end = SystemCollectorClock().monotonicMs; activityMs = end - phaseAt; phaseAt = end
        }
        if fixtureInput, active {
            let now = SystemCollectorClock().unixMs
            if now >= nextFixtureInput {
                nextFixtureInput = (now / 1_000 + 1) * 1_000
                inputActivityEvent(InputActivitySample(application: ApplicationIdentity(applicationId: "test.allowed", processId: 4242, processStartTime: "fixture-birth-1"),
                                                      category: .pointerRelease, callbackTimeMs: now))
            }
        }
        guard active, !fixture else { return }
        let now = SystemCollectorClock().monotonicMs
        guard now >= nextCheck else { return }
        nextCheck = now + 250
        let fresh = validateBeforeAccept()
        desktopEvent(fresh.desktop, fresh.accessibility)
        // Includes the desktopEvent callback; not isolated OS-query latency.
        if CollectorDebugTrace.enabled { desktopMs = SystemCollectorClock().monotonicMs - phaseAt }
    }
    func validateBeforeAccept() -> (desktop: DesktopStatus, accessibility: Bool) {
        guard active else { return (.unknown, false) }
        if fixture { return (scenario == "locked" ? .locked : scenario == "unknown" ? .unknown : .unlocked, true) }
        // Sample only timing diagnostics. Secure Input is independently checked
        // before/after this desktop+AX gate; neither result is a cached permit.
        var sampleStages = false
        if CollectorDebugTrace.enabled {
            let now = DispatchTime.now().uptimeNanoseconds
            if now >= nextDesktopTraceSample {
                nextDesktopTraceSample = now + 30_000_000_000
                sampleStages = true
            }
        }
        let secureBefore = IsSecureEventInputEnabled()
        let desktop = currentDesktop(traceStages: true, sampleStages: sampleStages)
        func accessibilityTrusted() -> Bool {
            guard CollectorDebugTrace.enabled else { return AXIsProcessTrusted() }
            let started = DispatchTime.now().uptimeNanoseconds
            let trusted = AXIsProcessTrusted()
            let elapsedMs = Int64((DispatchTime.now().uptimeNanoseconds - started) / 1_000_000)
            if sampleStages || elapsedMs >= 50 {
                CollectorDebugTrace.record("desktop-validation-phase", numbers: ["phase": 6, "elapsedMs": elapsedMs], strings: ["stage": "accessibility"])
            }
            return trusted
        }
        let markerOnly = desktop == .unknown && desktopReason == "secure-input-indicated" && !boundary.isLatched
        let accessibility = (desktop == .unlocked || markerOnly) && accessibilityTrusted()
        let secureAfter = IsSecureEventInputEnabled()
        secureInputBlocked = markerOnly || desktop == .unlocked && (secureBefore || secureAfter)
        return (desktop, accessibility)
    }
    private func currentDesktop(traceStages: Bool = false, sampleStages: Bool = false) -> DesktopStatus {
        guard active else { return .unknown }
        guard !boundary.isLatched else { secureInputBlocked = false; return .unknown }
        let assessment = desktopAssessment(traceStages: traceStages, sampleStages: sampleStages); desktopReason = assessment.reason
        return boundary.observe(assessment)
    }
    func inputMonitoringGranted() -> Bool { fixture || CGPreflightListenEventAccess() }
    func beginInputActivity(policy: CapturePolicy) -> Bool {
        endInputActivity()
        inputActivityStarting = true
        defer { inputActivityStarting = false }
        inputActivityReason = "input-monitoring-unavailable"
        guard active, policy.inputActivity == true else { return false }
        inputPolicy = policy
        if fixture {
            fixtureInput = scenario == "activity"
            nextFixtureInput = 0
            return fixtureInput
        }
        let monitor = InputActivityMonitor(policy: policy, desktopUnlocked: { [weak self] in
            guard let self else { return false }
            let fresh = self.validateBeforeAccept()
            if !self.inputActivityStarting && (fresh.desktop != .unlocked || !fresh.accessibility || self.secureInputBlocked) {
                self.desktopEvent(fresh.desktop, fresh.accessibility)
            }
            return fresh.desktop == .unlocked && fresh.accessibility && !self.secureInputBlocked
        })
        monitor.sample = { [weak self] in self?.inputActivityEvent($0) }
        monitor.invalidated = { [weak self] in self?.inputActivityInvalidated() }
        monitor.disabled = { [weak self] in self?.inputActivityDisabled($0) }
        monitor.secureInput = { [weak self] in self?.secureInputEvent() }
        guard monitor.begin() else {
            inputActivityReason = secureInputBlocked && monitor.reason == "input-monitoring-unavailable" ? "secure-input-active" : monitor.reason
            return false
        }
        inputMonitor = monitor
        return true
    }
    func endInputActivity() {
        inputMonitor?.end(); inputMonitor = nil
        fixtureInput = false; nextFixtureInput = 0; inputPolicy = nil
    }
    func clearInputActivity() {
        // Aggregation belongs to CollectorEngine; only a monotonic epoch fence stays here.
        inputMonitor?.invalidateEpoch()
    }
    func validateInputActivity(application: ApplicationIdentity) -> Bool {
        if fixture {
            return active && fixtureInput && inputPolicy?.inputActivity == true &&
                inputPolicy.map { ApplicationPolicy.allows(application.applicationId, policy: $0) } == true &&
                application == ApplicationIdentity(applicationId: "test.allowed", processId: 4242, processStartTime: "fixture-birth-1")
        }
        return inputMonitor?.validate(application: application) == true
    }
    func endMonitoring() {
        endInputActivity()
        active = false; secureInputBlocked = false
        for (center, observer) in observers { center.removeObserver(observer) }
        observers.removeAll()
    }
    func launch(_ ticket: ReadTicket) { worker.launch(ticket) }
    func cancelRead() { worker.cancel() }
    func abortTimedOutRead(_ ticket: ReadTicket) -> ReadTimeoutCleanup { worker.abortTimedOutRead(ticket) }
    func timedOutReadCleanup() -> ReadTimeoutCleanup { worker.timedOutReadCleanup() }
    var inputActivityHealthy: Bool { fixture ? fixtureInput : inputMonitor?.isHealthy == true }
    func retireRead() { worker.retire() }
    func readyForRead() -> Bool { worker.readyForRead }
}

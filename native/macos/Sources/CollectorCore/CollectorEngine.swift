import Foundation
import HistoryContract

/// Serial, platform-free control state machine. The executable calls it only on
/// its control run loop; potentially blocking AX calls live in a killable child.
public final class CollectorEngine {
    public let ownerId: String
    public let instanceId: String
    public let deviceId: String
    public let fixture: Bool
    public private(set) var state = "unconfigured"
    public private(set) var policyRevision: Int64 = 0
    public private(set) var captureEpoch: Int64 = 0
    public private(set) var foregroundGeneration: Int64 = 0
    public private(set) var focusGeneration: Int64 = 0
    public private(set) var shouldExit = false
    public private(set) var outstanding: ReadTicket?
    public private(set) var desktop: DesktopStatus = .unknown
    public var emit: (JSONValue) -> Void = { _ in }
    public var discardQueuedObservations: () -> Void = {}
    private let environment: CollectorEnvironment
    private let clock: CollectorClock
    private let osSessionId: String
    private let desktopId: String
    private var policy: CapturePolicy?
    private var userPaused = false
    private var primaryPauseReason: String?
    private var secureInputSuspended = false
    private struct ReadRecovery {
        let attempt: Int
        let started: Int64
        let due: Int64
        let requestId: Int64?
        var reaped = false
    }
    private var readRecovery: ReadRecovery?
    // Sliding monotonic budget, not reset by successful replies or app changes.
    private var readRecoveryAttempts: [Int64] = []
    private var readOnlyAXEnablement = false
    private var hasStarted = false
    private var leaseUntil: Int64
    private var seq: Int64 = 0
    private var snapshotSerial: Int64 = 0
    private var debugRequestSerial: Int64 = 0
    private var target = JSONValue.object(["kind": .string("unresolved"), "reason": .string("not-observed")])
    private var nextRead: Int64?
    private var pendingHint: SourceHint?
    private var lastRead: Int64?
    private var inputAccumulator = InputActivityAccumulator()
    private var inputListenerActive = false
    private var observedApplication: ApplicationIdentity?
    private var workerIdentity: WorkerSurfaceIdentity?
    private var dirtySince: Int64?
    private var nextReadFastOnly = false
    private var pendingSubmitFastRead = false
    private var menuTrackingUntilMs: Int64?
    private var captureDiagnostics: JSONValue?
    private var inputSessionEstablished = false
    // Only the immediately preceding accepted state of each snapshot channel.
    // These bounded, volatile values are not a retained-history/durable cache.
    private var lastTextState: JSONValue?
    private var lastSurfaceState: JSONValue?
    private var lastSelectionState: JSONValue?
    private var textHadNonblank = false
    private var selectionHadNonblank = false
    private var lastSurfaceRevision: Int64?
    // One immediately preceding, content-free unavailable state, not an app
    // identity, success interval, durable counter or reusable safety permit.
    private var lastUnavailableState: JSONValue?
    private let snapshotValidator: ContractValidator?

    public init(
        ownerId: String,
        instanceId: String,
        deviceId: String,
        osSessionId: String,
        desktopId: String,
        fixture: Bool,
        environment: CollectorEnvironment,
        clock: CollectorClock,
        validator: ContractValidator? = nil
    ) {
        self.ownerId = ownerId; self.instanceId = instanceId; self.deviceId = deviceId
        self.osSessionId = osSessionId; self.desktopId = desktopId; self.fixture = fixture
        self.environment = environment; self.clock = clock
        self.leaseUntil = clock.monotonicMs + 30_000
        self.snapshotValidator = validator ?? (try? ContractValidator())
    }

    public var stamp: JSONValue { .object(["captureEpoch": j(captureEpoch), "foregroundGeneration": j(foregroundGeneration), "focusGeneration": j(focusGeneration), "policyRevision": j(policyRevision)]) }

    public static func helloMessage(instanceId: String, fixture: Bool) -> JSONValue {
        var capabilities: [JSONValue] = [
            capability("text.snapshot", "observe", "supported", fixture ? "synthetic-fixture" : "focused-field"),
            capability("text.visible-range", "observe", "supported", "visible-range"),
            capability("input.activity", "observe", "supported", "coarse-event-counts"),
            capability("ax.enablement", "observe", "supported", "accessibility-enablement"),
            capability("text.marker", "observe", "supported", "text-marker-range"),
            capability("surface.snapshot", "observe", "supported", "bounded-surface-tree"),
            capability("selection.snapshot", "observe", "supported", "text-selection"),
            capability("input.text", "observe", "supported", "typed-text-events"),
            capability("menu.action", "observe", "supported", "foreground-menu-bar"),
            capability("field.denylist", "observe", "supported", "field-denylist-policy"),
        ]
        for name in ["pointer.click", "scroll", "gesture.pinch", "gesture.rotate", "gesture.pan", "gesture.swipe", "contact.touch", "contact.pen", "view.zoom"] {
            capabilities.append(capability(name, "observe", "unsupported", "not-implemented"))
        }
        for name in ["text.set", "pointer.click", "key.chord", "view.zoom"] {
            capabilities.append(capability(name, "act", "unsupported", "observe-only-collector"))
        }
        return .object([
            "protocolVersion": j(1),
            "type": .string("hello"),
            "instanceId": .string(instanceId),
            "capabilities": .array(capabilities),
            "maxFrameBytes": j(65_536),
        ])
    }

    public func hello() {
        emit(Self.helloMessage(instanceId: instanceId, fixture: fixture))
    }

    private static func capability(_ name: String, _ direction: String, _ support: String, _ reason: String) -> JSONValue {
        .object(["name": .string(name), "direction": .string(direction), "scope": .string("authorized-desktop"), "support": .string(support), "reason": .string(reason)])
    }
    public func failure(_ code: String, requestId: String = "invalid") {
        emit(.object(["protocolVersion": j(1), "type": .string("error"), "requestId": .string(requestId), "code": .string(code), "retryable": .bool(false)]))
    }
    private func stateMessage(_ requestId: String, _ reason: String) {
        var effective = reason
        if state == "paused", secureInputSuspended {
            effective = "secure-input-suppressed"
        } else if state == "paused" {
            let primary = primaryPauseReason == nil
            if primary { primaryPauseReason = reason }
            effective = primaryPauseReason ?? reason
            if requestId != "heartbeat", reason != "heartbeat" {
                CollectorDebugTrace.record("collector-pause", flags: ["primary": primary], strings: ["reason": reason])
            }
        } else { primaryPauseReason = nil }
        var value: [String: JSONValue] = ["protocolVersion": j(1), "type": .string("state"), "requestId": .string(requestId), "instanceId": .string(instanceId), "state": .string(state), "stamp": stamp, "reason": .string(effective)]
        if let captureDiagnostics { value["captureDiagnostics"] = captureDiagnostics }
        emit(.object(value))
    }
    public func receive(_ message: JSONValue) {
        guard !shouldExit else { return }
        if clock.monotonicMs >= leaseUntil { stop("lease-expired", requestId: "lease"); return }
        let request = message["requestId"]?.stringValue ?? "invalid"
        guard let type = message["type"]?.stringValue, type == "configure" || type == "control" else {
            failure(message["type"] == .string("action.request") ? "unsupported" : "invalid-message", requestId: request); return
        }
        guard message["ownerId"] == .string(ownerId), message["instanceId"] == .string(instanceId) else { failure("permission-denied", requestId: request); return }
        guard let revisionValue = message["policyRevision"]?.numberValue else { failure("invalid-message", requestId: request); return }
        let revision = Int64(revisionValue)
        if type == "configure" {
            guard revision > policyRevision, let p = message["policy"], let parsed = try? CapturePolicy(p) else { failure("stale", requestId: request); return }
            guard parsed.hasValidTextSettings else { failure("invalid-message", requestId: request); return }
            cancelReadRecovery("policy")
            boundary("policy-boundary")
            environment.endMonitoring(); desktop = .unknown
            policyRevision = revision; policy = parsed; hasStarted = false; userPaused = false
            environment.configurePolicy(parsed)
            state = "ready"
            emit(.object(["protocolVersion": j(1), "type": .string("configured"), "requestId": .string(request), "ownerId": .string(ownerId), "instanceId": .string(instanceId), "policyRevision": j(policyRevision)]))
            stateMessage(request, parsed.enabled ? "configured" : "policy-disabled")
            return
        }
        guard policy != nil, revision == policyRevision else { failure("stale", requestId: request); return }
        guard let command = message["command"]?.stringValue, let duration = message["leaseDurationMs"]?.numberValue,
              duration >= 1, duration <= 30_000 else { failure("invalid-message", requestId: request); return }
        leaseUntil = clock.monotonicMs + Int64(duration)
        switch command {
        case "start", "resume":
            guard policy?.enabled == true else { failure("permission-denied", requestId: request); return }
            // Repeated start must never clear an explicit user pause. Only resume can.
            if command == "start", userPaused || readRecovery != nil { stateMessage(request, "user-paused"); return }
            cancelReadRecovery("owner")
            if command == "resume" { userPaused = false }
            primaryPauseReason = nil // A genuinely new explicit attempt, not rejected start.
            secureInputSuspended = false
            inputSessionEstablished = false
            readOnlyAXEnablement = false
            hasStarted = true
            boundary("not-observed")
            guard environment.readyForRead() else {
                userPaused = true; state = "paused"; stateMessage(request, "worker-exit-unconfirmed"); return
            }
            let status = environment.beginMonitoring()
            desktop = status.desktop
            if status.accessibility, environment.secureInputBlocked {
                state = "running"; secureInputDetected(request); return
            }
            guard desktop == .unlocked, status.accessibility else {
                if policy?.inputActivity == true || policy?.inputText == true { userPaused = true }
                state = "paused"; stateMessage(request, desktop != .unlocked ? environment.desktopReason : "permission-denied"); return
            }
            if let policy, policy.inputActivity == true {
                guard environment.beginInputActivity(policy: policy) else {
                    if environment.inputActivityReason == "secure-input-active" {
                        state = "running"; secureInputDetected(request); return
                    }
                    userPaused = true; environment.endInputActivity()
                    state = "paused"; stateMessage(request, environment.inputActivityReason); return
                }
                inputListenerActive = true
            }
            state = "running"; schedule(); stateMessage(request, "started")
        case "pause":
            cancelReadRecovery("owner")
            secureInputSuspended = false
            primaryPauseReason = nil // Owner pause intentionally replaces the displayed cause.
            userPaused = true; boundary("policy-boundary"); state = "paused"; stateMessage(request, "user-paused")
        case "stop": stop("stopped", requestId: request)
        case "heartbeat": stateMessage(request, "heartbeat")
        default: failure("invalid-message", requestId: request)
        }
    }
    @discardableResult
    private func boundary(_ unresolved: String, endInput: Bool = true, retireInput: Bool = false, aborting ticket: ReadTicket? = nil) -> ReadTimeoutCleanup {
        lastUnavailableState = nil
        // Gate closes before cancellation; no partial activity bucket is flushed.
        if endInput { inputListenerActive = false; environment.endInputActivity() }
        clearInputActivity(); observedApplication = nil
        nextRead = nil; pendingHint = nil; outstanding = nil; workerIdentity = nil; dirtySince = nil; captureDiagnostics = nil
        nextReadFastOnly = false; pendingSubmitFastRead = false; menuTrackingUntilMs = nil
        clearSnapshotStates()
        captureEpoch += 1; focusGeneration += 1
        target = .object(["kind": .string("unresolved"), "reason": .string(unresolved)])
        discardQueuedObservations()
        if let ticket { return environment.abortTimedOutRead(ticket) }
        if retireInput { environment.retireRead() } else { environment.cancelRead() }
        return .ineligible
    }
    public func clearInputActivity() {
        inputAccumulator.clear(); environment.clearInputActivity()
    }
    /// Called when the native tap is disabled by the OS or listening permission is lost.
    /// No poll, focus event or unlock may silently create another listener.
    public func inputActivityUnavailable(_ reason: String) {
        guard hasStarted, policy?.inputActivity == true, !shouldExit else { return }
        let fixed = ["input-monitoring-required", "input-monitoring-unavailable", "input-monitoring-disabled"].contains(reason)
            ? reason : "input-monitoring-unavailable"
        cancelReadRecovery(fixed == "input-monitoring-required" ? "input-permission" : "input-listener")
        if secureInputSuspended { primaryPauseReason = nil; secureInputSuspended = false }
        userPaused = true; boundary("policy-boundary"); state = "paused"; stateMessage("input", fixed)
    }
    public func stop(_ reason: String, requestId: String = "owner") {
        guard !shouldExit else { return }
        cancelReadRecovery(reason == "lease-expired" ? "lease" : "owner")
        secureInputSuspended = false
        boundary("policy-boundary"); environment.endMonitoring(); desktop = .unknown
        state = "stopped"; shouldExit = true; stateMessage(requestId, reason)
    }
    /// A known privacy interval, not a listener failure or an owner pause. Every
    /// potentially input-bearing worker still needs its original healthy ACK/reap.
    public func secureInputDetected(_ requestId: String = "secure-input") {
        if readRecovery != nil {
            interruptReadRecovery("secure-input", requestId: "desktop", reason: "secure-input-active"); return
        }
        guard hasStarted, policy?.enabled == true, !shouldExit, !userPaused,
              state == "running" || secureInputSuspended else { return }
        guard !secureInputSuspended else { return }
        secureInputSuspended = true; primaryPauseReason = nil; state = "paused"
        boundary("policy-boundary", endInput: false, retireInput: inputSessionEstablished && policy?.inputText == true)
        CollectorDebugTrace.record("collector-secure-input", flags: ["blocked": true])
        stateMessage(requestId, "secure-input-suppressed")
    }
    public func desktopChanged(_ newStatus: DesktopStatus, accessibility: Bool) {
        guard hasStarted, policy?.enabled == true, !shouldExit else { return }
        let changed = desktop != newStatus
        desktop = newStatus
        if readRecovery != nil {
            // In recovery a second boundary is not part of the original read
            // failure. End the retry; do not fall through to Secure Input resume.
            if environment.secureInputBlocked && accessibility {
                interruptReadRecovery("secure-input", requestId: "desktop", reason: "secure-input-active")
            } else if newStatus != .unlocked || !accessibility {
                interruptReadRecovery(newStatus == .unlocked ? "accessibility" : "desktop", requestId: "desktop",
                    reason: newStatus == .unlocked ? "permission-denied" : environment.desktopReason)
            } else if !environment.inputMonitoringGranted() {
                interruptReadRecovery("input-permission", requestId: "input", reason: "input-monitoring-required")
            }
            return
        }
        if secureInputSuspended, (policy?.inputActivity == true || policy?.inputText == true), !environment.inputMonitoringGranted() {
            primaryPauseReason = nil; secureInputSuspended = false; userPaused = true
            boundary("policy-boundary"); state = "paused"; stateMessage("input", "input-monitoring-required"); return
        }
        if environment.secureInputBlocked && accessibility {
            secureInputDetected(); return
        }
        if secureInputSuspended && !userPaused && !environment.readyForRead(), newStatus == .unlocked, accessibility { return }
        if newStatus != .unlocked || !accessibility {
            let wasSecure = secureInputSuspended
            if wasSecure { secureInputSuspended = false; primaryPauseReason = nil }
            if wasSecure || policy?.inputActivity == true || policy?.inputText == true { userPaused = true }
            if wasSecure || changed || state == "running" {
                boundary("desktop-unavailable"); state = "paused"; stateMessage("desktop", newStatus != .unlocked ? environment.desktopReason : "permission-denied")
            }
        } else if secureInputSuspended && !userPaused && clock.monotonicMs < leaseUntil && environment.readyForRead() {
            if let policy, policy.inputActivity == true, !inputListenerActive {
                guard environment.beginInputActivity(policy: policy) else {
                    if environment.inputActivityReason != "secure-input-active" { inputActivityUnavailable(environment.inputActivityReason) }
                    return
                }
                inputListenerActive = true
            }
            // Retire completed before this fresh result; drop all pre/end-of-interval
            // buckets, dedup baselines and timestamp fences before the new read.
            boundary("not-observed", endInput: false)
            inputSessionEstablished = false; secureInputSuspended = false
            state = "running"; schedule(); stateMessage("secure-input", "secure-input-cleared")
            CollectorDebugTrace.record("collector-secure-input", flags: ["blocked": false])
        } else if !secureInputSuspended && !userPaused && state == "paused" && policy?.inputActivity != true && policy?.inputText != true {
            boundary("not-observed"); state = "running"; schedule(); stateMessage("desktop", "desktop-unlocked")
        }
    }
    public func inputSessionUnavailable(_ reason: String = "input-monitoring-unavailable") {
        guard (state == "running" || secureInputSuspended || readRecovery != nil), policy?.inputText == true else { return }
        let fixed = ["input-monitoring-required", "input-monitoring-disabled", "input-monitoring-unavailable", "input-session-boundary-requires-resume",
                     WorkerRetirement.Failure.ackFailed.rawValue, WorkerRetirement.Failure.exitUnconfirmed.rawValue].contains(reason) ? reason : "input-monitoring-unavailable"
        cancelReadRecovery(fixed == "input-monitoring-required" ? "input-permission" : "input-listener")
        if secureInputSuspended { primaryPauseReason = nil; secureInputSuspended = false }
        userPaused = true; boundary("policy-boundary"); state = "paused"; stateMessage("input", fixed)
    }
    public func excludedApplicationEvent() {
        guard state == "running" else { return }
        boundary("policy-boundary", endInput: false, retireInput: inputSessionEstablished && policy?.inputText == true); foregroundGeneration += 1; schedule()
    }
    public func applicationEvent(_ hint: SourceHint) {
        guard state == "running", desktop == .unlocked else { return }
        boundary("focus-unavailable", endInput: false, retireInput: inputSessionEstablished && policy?.inputText == true); foregroundGeneration += 1
        guard let policy, ApplicationPolicy.allows(hint.application.applicationId, policy: policy), BrowserGate.allows(hint.application.applicationId, policy: policy) else { schedule(); return }
        observedApplication = hint.application
        pendingHint = hint
        observation(.object(["kind": .string("context.changed"), "reason": .string("application")]), eventTime: hint.eventTimeMs)
        schedule()
    }
    public func inputActivity(_ sample: InputActivitySample) {
        guard state == "running", desktop == .unlocked, !userPaused, inputListenerActive,
              clock.monotonicMs < leaseUntil, let policy, policy.enabled, policy.inputActivity == true,
              ApplicationPolicy.allows(sample.application.applicationId, policy: policy),
              BrowserGate.allows(sample.application.applicationId, policy: policy), sample.callbackTimeMs >= 0,
              sample.callbackTimeMs <= clock.unixMs, clock.unixMs - sample.callbackTimeMs <= 200 else {
            clearInputActivity(); return
        }
        lastUnavailableState = nil // An admitted event is not an idle polling repetition.
        if let known = observedApplication, known != sample.application {
            // Detect an activation missed by NSWorkspace without reattributing old samples.
            applicationEvent(SourceHint(application: sample.application, eventTimeMs: sample.callbackTimeMs))
            return // The event predates the new boundary's native timestamp fence.
        }
        observedApplication = sample.application
        flushInputActivity()
        guard state == "running", inputListenerActive, !userPaused,
              sample.callbackTimeMs <= clock.unixMs, clock.unixMs - sample.callbackTimeMs <= 200 else {
            clearInputActivity(); return
        }
        inputAccumulator.add(sample, stamp: InputActivityStamp(captureEpoch: captureEpoch,
            foregroundGeneration: foregroundGeneration, focusGeneration: focusGeneration, policyRevision: policyRevision))
    }
    private func flushInputActivity() {
        guard let bucket = inputAccumulator.takeCompleted(nowMs: clock.unixMs) else { return }
        guard state == "running", desktop == .unlocked, !userPaused, inputListenerActive,
              clock.monotonicMs < leaseUntil, let policy, policy.enabled, policy.inputActivity == true,
              bucket.stamp.captureEpoch == captureEpoch, bucket.stamp.policyRevision == policyRevision,
              bucket.application == observedApplication, ApplicationPolicy.allows(bucket.application.applicationId, policy: policy), BrowserGate.allows(bucket.application.applicationId, policy: policy),
              environment.validateInputActivity(application: bucket.application) else { return }
        // A synchronous fresh gate can itself report a desktop/listener boundary.
        guard state == "running", inputListenerActive, bucket.stamp.captureEpoch == captureEpoch,
              bucket.stamp.policyRevision == policyRevision, clock.monotonicMs < leaseUntil else { return }
        let identity = JSONValue.object([
            "deviceId": .string(deviceId), "osSessionId": .string(osSessionId), "desktopId": .string(desktopId),
            "processId": j(Int(bucket.application.processId)), "processStartTime": .string(bucket.application.processStartTime),
            "applicationId": .string(bucket.application.applicationId),
        ])
        observation(bucket.payload(fixture: fixture), eventTime: bucket.intervalEndMs,
                    eventTarget: .object(["kind": .string("application"), "identity": identity]), eventStamp: bucket.stamp.json)
    }
    private var spacing: Int64 { Int64(max(policy?.debounceMs ?? 0, policy?.maxWaitMs ?? 1)) }
    /// Minimum quiet time after completion/timeout, not a strict wall-clock
    /// sample period. Application boundaries retain the initial debounce path.
    private var reconciliationSpacing: Int64 { max(spacing, Int64(policy?.sampleIntervalMs ?? (fixture ? 150 : 1_000))) }
    private var isMenuTrackingActive: Bool {
        guard let until = menuTrackingUntilMs else { return false }
        if clock.monotonicMs >= until {
            menuTrackingUntilMs = nil
            return false
        }
        return true
    }
    private func schedule() {
        let now = clock.monotonicMs
        let base = max(now + spacing, (lastRead ?? now) + spacing)
        if let until = menuTrackingUntilMs, until > now {
            nextRead = max(base, until)
        } else {
            menuTrackingUntilMs = nil
            nextRead = base
        }
    }
    /// Modal menu tracking signal from the isolated session worker. Defers periodic
    /// ReadTicket dispatches up to a hard 10s cap while a menu is open so modal
    /// tracking loops do not trigger read timeouts, then wakes reads on close.
    public func workerMenuTracking(_ active: Bool) {
        guard state == "running", !userPaused, !secureInputSuspended,
              let policy, policy.enabled, policy.menuActions == true, policy.usesSessionWorker else { return }
        if active {
            menuTrackingUntilMs = clock.monotonicMs + MenuPathLimits.maxMenuTrackingMs
        } else {
            menuTrackingUntilMs = nil
            workerDirty()
        }
    }
    /// Validates and emits a foreground top menu bar action from the isolated
    /// session worker after epoch/policy fencing and fresh desktop/AX/Secure Input gates.
    public func menuAction(_ record: MenuActionRecord) {
        guard !shouldExit, state == "running", !userPaused, !secureInputSuspended,
              desktop == .unlocked, clock.monotonicMs < leaseUntil,
              let policy, policy.enabled, policy.menuActions == true else { return }
        guard record.isValid,
              record.captureEpoch == captureEpoch,
              record.policyRevision == policyRevision,
              record.foregroundGeneration <= foregroundGeneration,
              record.focusGeneration <= focusGeneration,
              record.fieldSecurity == policy.fieldSecurityMode,
              record.observedAtMs <= clock.unixMs,
              clock.unixMs - record.observedAtMs <= MenuPathLimits.maxSelectionAgeMs else { return }
        if let known = observedApplication, known != record.application { return }
        let appId = record.application.applicationId
        guard ApplicationPolicy.allows(appId, policy: policy),
              BrowserGate.allows(appId, policy: policy) else { return }
        if BrowserGate.isKnownBrowser(appId) {
            guard record.privateState == "user-authorized",
                  policy.applicationScope == "denylist",
                  policy.allowBrowserContent == true else { return }
        } else {
            guard record.privateState == "normal" ||
                  (record.privateState == "user-authorized" && policy.applicationScope == "denylist" && policy.allowBrowserContent == true) else { return }
        }
        let fresh = environment.validateBeforeAccept()
        if fresh.accessibility, environment.secureInputBlocked {
            desktop = fresh.desktop
            secureInputDetected()
            return
        }
        guard fresh.desktop == .unlocked, fresh.accessibility else {
            desktopChanged(fresh.desktop, accessibility: fresh.accessibility)
            return
        }
        // Fresh validation can synchronously close the authority epoch or lease.
        guard !shouldExit, state == "running", !userPaused, !secureInputSuspended,
              desktop == .unlocked, clock.monotonicMs < leaseUntil,
              record.captureEpoch == captureEpoch,
              record.policyRevision == policyRevision,
              record.foregroundGeneration <= foregroundGeneration,
              record.focusGeneration <= focusGeneration,
              let currentPolicy = self.policy, currentPolicy.enabled, currentPolicy.menuActions == true,
              currentPolicy.fieldSecurityMode == record.fieldSecurity else { return }
        if let known = observedApplication, known != record.application { return }
        if observedApplication == nil { observedApplication = record.application }
        let identity = JSONValue.object([
            "deviceId": .string(deviceId),
            "osSessionId": .string(osSessionId),
            "desktopId": .string(desktopId),
            "processId": j(Int(record.application.processId)),
            "processStartTime": .string(record.application.processStartTime),
            "applicationId": .string(record.application.applicationId),
        ])
        observation(
            record.payload(fixture: fixture),
            eventTime: record.observedAtMs,
            eventTarget: .object(["kind": .string("application"), "identity": identity]),
            eventStamp: record.stamp
        )
    }
    /// Worker observer notifications contain no content and only advance an
    /// already-running schedule. Debounce is bounded by maxWait, not endless.
    public func workerDirty() {
        guard state == "running", !userPaused, let policy, policy.usesSessionWorker else { return }
        lastUnavailableState = nil
        let now = clock.monotonicMs
        if dirtySince == nil { dirtySince = now }
        let due = min(now + Int64(policy.debounceMs), dirtySince! + Int64(policy.maxWaitMs))
        nextRead = min(nextRead ?? due, due)
    }
    /// Immediate Return-submit wakeup from the session worker. Never launches a
    /// concurrent read: accelerates an idle schedule into a focused fast-read,
    /// or queues one behind the single in-flight read.
    public func workerSubmitDirty() {
        guard state == "running", !userPaused, let policy, policy.usesSessionWorker else { return }
        lastUnavailableState = nil
        if outstanding == nil {
            nextReadFastOnly = true
            nextRead = clock.monotonicMs
        } else {
            pendingSubmitFastRead = true
        }
    }
    /// The private transport may see EOF just after the deadline, between ticks.
    /// Cleanup still needs the exact owned ticket and a verifiable exit outcome.
    public func workerReadDeadlineReached(_ ticket: ReadTicket) {
        guard outstanding == ticket, ticket.captureEpoch == captureEpoch, ticket.policyRevision == policyRevision,
              state == "running", !userPaused, clock.monotonicMs >= ticket.deadlineMonotonicMs else { return }
        expireRead(ticket, reason: "timeout")
    }
    private func traceRecovery(_ phase: String, _ outcome: String, _ recovery: ReadRecovery, delay: Int64? = nil) {
        guard CollectorDebugTrace.enabled else { return }
        var numbers: [String: Int64] = ["attempt": Int64(recovery.attempt), "elapsedMs": min(Int64(Int32.max), max(0, clock.monotonicMs - recovery.started))]
        if let delay { numbers["delayMs"] = delay }
        if let requestId = recovery.requestId { numbers["requestId"] = requestId }
        CollectorDebugTrace.record("engine-read-recovery", numbers: numbers, strings: ["phase": phase, "outcome": outcome])
    }
    private func cancelReadRecovery(_ cause: String) {
        guard let recovery = readRecovery else { return }
        readRecovery = nil; primaryPauseReason = nil
        traceRecovery("cancelled", cause, recovery)
    }
    private func interruptReadRecovery(_ cause: String, requestId: String, reason: String) {
        cancelReadRecovery(cause)
        userPaused = true; boundary("policy-boundary"); state = "paused"; stateMessage(requestId, reason)
    }
    private func blockReadRecovery(_ cause: String, reason: String, _ recovery: ReadRecovery) {
        readRecovery = nil; primaryPauseReason = nil
        userPaused = true; state = "paused"; boundary("policy-boundary")
        traceRecovery("blocked", cause, recovery)
        let correlation = ["desktop", "secure-input", "accessibility"].contains(cause) ? "desktop"
            : ["input-permission", "input-listener"].contains(cause) ? "input" : "read-recovery"
        stateMessage(correlation, reason)
    }
    private func updateReadCleanup(_ cleanup: ReadTimeoutCleanup, _ recovery: ReadRecovery) -> Bool {
        switch cleanup {
        case .reaped where clock.monotonicMs - recovery.started < 1_000:
            if !recovery.reaped {
                readRecovery?.reaped = true; traceRecovery("reaped", "exact-exit", recovery)
            }
            return true
        case .awaitingExit where clock.monotonicMs - recovery.started < 1_000: return false
        case .reaped, .awaitingExit, .unconfirmed:
            blockReadRecovery("worker-exit-unconfirmed", reason: "worker-exit-unconfirmed", recovery); return false
        case .ineligible:
            blockReadRecovery("worker-ineligible", reason: "read-timeout-unrecoverable", recovery); return false
        }
    }
    private func continueReadRecovery(_ recovery: ReadRecovery) {
        guard recovery.reaped || updateReadCleanup(environment.timedOutReadCleanup(), recovery),
              clock.monotonicMs >= recovery.due else { return }
        guard environment.readyForRead() else {
            blockReadRecovery("worker-ineligible", reason: "read-timeout-unrecoverable", recovery); return
        }
        let fresh = environment.validateBeforeAccept()
        // A fresh native gate may report a boundary synchronously. Never let its
        // caller reopen a later pause/control epoch or renew an expired lease.
        guard readRecovery?.started == recovery.started, state == "paused", !userPaused, !shouldExit else { return }
        guard clock.monotonicMs < leaseUntil else { stop("lease-expired", requestId: "lease"); return }
        desktop = fresh.desktop
        if environment.secureInputBlocked && fresh.accessibility {
            blockReadRecovery("secure-input", reason: "secure-input-active", recovery); return
        }
        guard fresh.desktop == .unlocked else {
            blockReadRecovery("desktop", reason: environment.desktopReason, recovery); return
        }
        guard fresh.accessibility else {
            blockReadRecovery("accessibility", reason: "permission-denied", recovery); return
        }
        guard environment.inputMonitoringGranted() else {
            blockReadRecovery("input-permission", reason: "input-monitoring-required", recovery); return
        }
        guard policy?.inputActivity != true || inputListenerActive && environment.inputActivityHealthy else {
            blockReadRecovery("input-listener", reason: "input-monitoring-disabled", recovery); return
        }
        guard clock.monotonicMs < leaseUntil else { stop("lease-expired", requestId: "lease"); return }
        guard readRecovery?.started == recovery.started, state == "paused", !userPaused, !shouldExit else { return }
        // The coarse tap, if enabled, was kept but admitted nothing during the
        // pause. Fence its event timestamps again; the new worker has no old ctx.
        clearInputActivity(); readRecovery = nil
        nextReadFastOnly = false; pendingSubmitFastRead = false
        readOnlyAXEnablement = true
        state = "running"; nextRead = clock.monotonicMs
        stateMessage("read-recovery", "read-timeout-recovered")
        gap("timeout", diagnostic: ReadDiagnostic(code: .readDeadline))
        traceRecovery("resumed", "fresh-gates", recovery)
    }
    private func expireRead(_ ticket: ReadTicket, reason: String) {
        lastUnavailableState = nil
        if ticket.policy.inputText == true {
            let now = clock.monotonicMs
            if CollectorDebugTrace.enabled {
                var numbers = ["readRemainingMs": ticket.deadlineMonotonicMs - now]
                if let requestId = ticket.debugRequestId { numbers["requestId"] = requestId }
                CollectorDebugTrace.record("engine-read-timeout", numbers: numbers, flags: ["completion": reason != "timeout"], stack: true)
            }
            if reason != "timeout", environment.secureInputBlocked {
                blockReadRecovery("secure-input", reason: "read-timeout-unrecoverable",
                    ReadRecovery(attempt: 0, started: now, due: now, requestId: ticket.debugRequestId)); return
            }
            readRecoveryAttempts.removeAll { now - $0 >= 60_000 }
            if readRecoveryAttempts.count >= 3 {
                let recovery = ReadRecovery(attempt: 3, started: now, due: now, requestId: ticket.debugRequestId)
                // Use the same bounded transport cleanup even without a retry.
                _ = boundary("policy-boundary", aborting: ticket)
                blockReadRecovery("limit", reason: "read-timeout-exhausted", recovery); return
            }
            readRecoveryAttempts.append(now)
            let attempt = readRecoveryAttempts.count
            let delay = min(30_000, max(reconciliationSpacing, Int64(1_000 << (attempt - 1))))
            let recovery = ReadRecovery(attempt: attempt, started: now, due: now + delay, requestId: ticket.debugRequestId)
            state = "paused"; readRecovery = recovery
            let cleanup = boundary("policy-boundary", endInput: false, aborting: ticket)
            inputSessionEstablished = false
            guard readRecovery != nil else { return }
            if cleanup == .reaped || cleanup == .awaitingExit {
                stateMessage("read-recovery", "read-timeout-recovering")
                traceRecovery("waiting", "cooldown", recovery, delay: delay)
            }
            _ = updateReadCleanup(cleanup, recovery)
            return
        }
        outstanding = nil; nextReadFastOnly = false; pendingSubmitFastRead = false
        environment.cancelRead(); clearSnapshotStates()
        gap(reason, diagnostic: ReadDiagnostic(code: .readDeadline))
        nextRead = clock.monotonicMs + reconciliationSpacing
    }
    public func tick(parentAlive: Bool = true) {
        guard !shouldExit else { return }
        guard parentAlive else { stop("parent-death"); return }
        guard clock.monotonicMs < leaseUntil else { stop("lease-expired", requestId: "lease"); return }
        if let recovery = readRecovery {
            continueReadRecovery(recovery)
            if state != "running" { return }
        }
        if let ticket = outstanding, clock.monotonicMs >= ticket.deadlineMonotonicMs {
            expireRead(ticket, reason: "timeout")
            if state != "running" { return }
        }
        flushInputActivity()
        guard !isMenuTrackingActive else { return }
        guard state == "running", desktop == .unlocked, !userPaused, outstanding == nil,
              let due = nextRead, clock.monotonicMs >= due, let policy, policy.enabled, environment.readyForRead() else { return }
        var ticket = ReadTicket(token: UUID().uuidString, policyRevision: policyRevision, captureEpoch: captureEpoch, policy: policy, hint: pendingHint,
                                deadlineMonotonicMs: clock.monotonicMs + Int64(policy.readTimeoutMs), deviceId: deviceId, osSessionId: osSessionId, desktopId: desktopId, foregroundGeneration: foregroundGeneration, focusGeneration: focusGeneration)
        if readOnlyAXEnablement { ticket.readOnlyAXEnablement = true }
        if nextReadFastOnly {
            ticket.focusedFastOnly = true
            nextReadFastOnly = false
        }
        // Exhaustion stops diagnostic IDs rather than wrapping/reusing them. It
        // never stops or changes capture scheduling, authorization or deadlines.
        if CollectorDebugTrace.enabled, debugRequestSerial < 9_007_199_254_740_991 {
            debugRequestSerial += 1; ticket.debugRequestId = debugRequestSerial
        }
        outstanding = ticket; lastRead = clock.monotonicMs; nextRead = nil; pendingHint = nil; dirtySince = nil
        if ticket.policy.inputText == true { inputSessionEstablished = true }
        environment.launch(ticket)
    }
    private func validRead(_ read: TextRead, policy: CapturePolicy) -> Bool {
        let count = read.text.utf16.count
        guard read.rangeBasis == (policy.textRange ?? "prefix"),
              read.rangeStart >= 0, read.rangeStart <= 9_007_199_254_740_991,
              count <= policy.maxTextCodeUnits, count <= 8192,
              (["ax.range", "ax.value"].contains(read.source) || (read.source == "ax.marker" && policy.textMarkers == true)) else { return false }
        if let total = read.totalLength {
            guard total >= 0, total <= 9_007_199_254_740_991,
                  read.rangeStart <= total, count <= total - read.rangeStart else { return false }
        }
        if read.rangeBasis == "visible" {
            guard ["ax.range", "ax.marker"].contains(read.source), read.totalLength != nil, !read.complete,
                  count > 0 || read.totalLength == 0,
                  read.missingReasons.contains("visible-range-only") else { return false }
        } else if read.rangeBasis != "prefix" || read.rangeStart != 0 { return false }
        if read.complete {
            guard read.rangeStart == 0, read.totalLength == count,
                  !read.truncated, read.missingReasons.isEmpty else { return false }
        } else if read.missingReasons.isEmpty { return false }
        if let selection = read.selection {
            guard selection.start >= read.rangeStart, selection.length >= 0,
                  selection.start - read.rangeStart <= count,
                  selection.length <= count - (selection.start - read.rangeStart) else { return false }
        }
        return true
    }
    public func complete(_ result: ReadResult) {
        guard let ticket = outstanding, result.token == ticket.token else { return }
        outstanding = nil
        let isFastOnly = ticket.focusedFastOnly == true
        func stillAuthorized() -> Bool {
            state == "running" && desktop == .unlocked && !userPaused &&
                ticket.captureEpoch == captureEpoch && ticket.policyRevision == policyRevision && clock.monotonicMs < leaseUntil
        }
        guard stillAuthorized() else {
            nextReadFastOnly = false; pendingSubmitFastRead = false
            clearSnapshotStates(); gap("stale", diagnostic: ReadDiagnostic(code: .captureAuthorityChanged)); return
        }
        // A typed negative listener boundary carries no authority to accept
        // content and must not be lost behind a concurrent read deadline.
        if ticket.policy.inputText == true, let reason = result.reason,
           ["input-monitoring-required", "input-monitoring-disabled", "input-monitoring-unavailable", "input-session-boundary-requires-resume"].contains(reason) {
            inputSessionUnavailable(reason); return
        }
        // Read-local provider metadata is diagnostic only: never derive it from
        // target/observedApplication, admit content with it, or retain it for a retry.
        func providerApplicationId() -> String? {
            guard stillAuthorized(), clock.monotonicMs < ticket.deadlineMonotonicMs,
                  result.captureStartMs >= 0, result.captureEndMs >= result.captureStartMs,
                  result.captureEndMs <= clock.unixMs,
                  result.reason != "application-excluded", result.reason?.hasPrefix("secure-input-") != true,
                  result.diagnostic?.code != .secureField, result.diagnostic?.code != .applicationNotAllowed,
                  result.diagnostic?.code != .browserExcluded, result.surfaceFailure != .securityExcluded,
                  let app = result.diagnosticApplication ?? result.application,
                  result.application == nil || result.application == app,
                  app.processId > 0, !app.processStartTime.isEmpty, app.processStartTime.utf16.count <= 128,
                  app.applicationId.utf16.count <= 256,
                  app.applicationId.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]*$", options: .regularExpression) == app.applicationId.startIndex..<app.applicationId.endIndex,
                  ApplicationPolicy.allows(app.applicationId, policy: ticket.policy), BrowserGate.allows(app.applicationId, policy: ticket.policy),
                  ticket.hint == nil || ticket.hint?.application == app else { return nil }
            return app.applicationId
        }
        // A typed negative focus reply admits no content or identity. Read-local
        // diagnosticApplication alone does not require a new blocking OS gate:
        // that gate can turn an on-time failure into an unrelated input timeout.
        // Every content/identity path stays below.
        let negativeFocus = result.reason == "focus-unavailable" && result.diagnostic?.code == .focusedFieldUnavailable
            && result.application == nil && result.sessionIdentity == nil && result.text == nil
            && result.surface == nil && result.selection == nil && (result.inputRecords ?? []).isEmpty
            && (result.inputGaps ?? []).isEmpty && result.focusAbsent != true
            && (result.surfaceFailure == nil || result.surfaceFailure == .anchorUnavailable)
            && result.captureStartMs >= 0 && result.captureEndMs >= result.captureStartMs
            && result.captureEndMs <= clock.unixMs
        if negativeFocus {
            guard clock.monotonicMs < ticket.deadlineMonotonicMs else { expireRead(ticket, reason: "stale"); return }
            if CollectorDebugTrace.enabled {
                var numbers = ["readRemainingMs": ticket.deadlineMonotonicMs - clock.monotonicMs]
                if let requestId = ticket.debugRequestId { numbers["requestId"] = requestId }
                CollectorDebugTrace.record("engine-negative-focus", numbers: numbers)
            }
            clearSnapshotStates(); clearInputActivity(); workerIdentity = nil
            pendingHint = nil; dirtySince = nil
            if pendingSubmitFastRead {
                pendingSubmitFastRead = false
                nextReadFastOnly = true
                nextRead = clock.monotonicMs
            } else {
                nextRead = clock.monotonicMs + (isFastOnly ? min(reconciliationSpacing, 200) : reconciliationSpacing)
            }
            // One unavailable anchor, one state. No independent surface attempt
            // occurred; do not double count the same absence as another gap.
            reportUnavailable(result, unresolved: "focus-unavailable", gapReason: "read-error", providerApplicationId: providerApplicationId())
            return
        }
        // Availability failures still run every original fresh admission gate.
        // Only this exact material-free public state can suppress repeated output;
        // unknown applications are never claimed to be the same application.
        let negativeApplication = result.reason == "policy-boundary" && result.diagnostic?.code == .applicationUnavailable
            && result.application == nil && result.sessionIdentity == nil && result.text == nil
            && result.surface == nil && result.selection == nil && (result.inputRecords ?? []).isEmpty
            && (result.inputGaps ?? []).isEmpty && result.focusAbsent != true && result.surfaceFailure == nil
            && result.enablement == nil && result.privateState == nil && result.observerStatus == nil
            && result.captureStartMs >= 0 && result.captureEndMs >= result.captureStartMs
            && result.captureEndMs <= clock.unixMs
        if !negativeApplication { lastUnavailableState = nil }
        let fresh = environment.validateBeforeAccept()
        if fresh.accessibility, environment.secureInputBlocked {
            guard clock.monotonicMs < ticket.deadlineMonotonicMs else { expireRead(ticket, reason: "stale"); return }
            desktop = fresh.desktop; secureInputDetected(); return
        }
        guard fresh.desktop == .unlocked, fresh.accessibility else {
            desktopChanged(fresh.desktop, accessibility: fresh.accessibility)
            return // Never publish a buffered worker reply across a new boundary.
        }
        // Fresh validation can itself consume time or close the authority epoch.
        // Never adopt a late reply's app/identity or leave a running read unscheduled.
        guard stillAuthorized() else {
            nextReadFastOnly = false; pendingSubmitFastRead = false
            clearSnapshotStates(); gap("stale", diagnostic: ReadDiagnostic(code: .captureAuthorityChanged)); return
        }
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else {
            expireRead(ticket, reason: "stale"); return
        }
        if pendingSubmitFastRead, state == "running", !userPaused {
            pendingSubmitFastRead = false
            nextReadFastOnly = true
            nextRead = clock.monotonicMs
        } else if isFastOnly {
            nextRead = clock.monotonicMs + min(reconciliationSpacing, 200)
        } else {
            nextRead = clock.monotonicMs + reconciliationSpacing
        }
        if result.reason == "session-app-changed" {
            boundary("focus-unavailable", endInput: false, retireInput: ticket.policy.inputText == true); schedule(); return
        }
        if result.reason == "application-excluded" {
            nextReadFastOnly = false; pendingSubmitFastRead = false
            nextRead = clock.monotonicMs + reconciliationSpacing
            workerIdentity = nil; observedApplication = nil; clearInputActivity(); clearSnapshotStates()
            target = .object(["kind": .string("unresolved"), "reason": .string("policy-boundary")])
            return // Blacklisted apps produce no context or attributed gap.
        }
        if let enablement = result.enablement {
            captureDiagnostics = .object([
                "axEnablement": .string(enablement.status.rawValue),
                "axAttribute": .string(enablement.attribute.rawValue),
                "observer": .string(result.observerStatus == "best-effort" ? "best-effort" : "unavailable"),
            ])
        }
        if result.reason == "secure-input-active" || result.reason == "secure-input-indicated" { secureInputDetected(); return }
        if let reason = result.reason, reason.hasPrefix("input-monitoring-") {
            userPaused = true; boundary("policy-boundary"); state = "paused"; stateMessage("input", reason); return
        }
        if negativeApplication {
            nextReadFastOnly = false; pendingSubmitFastRead = false
            nextRead = clock.monotonicMs + reconciliationSpacing
            clearSnapshotStates(); clearInputActivity(); workerIdentity = nil
            pendingHint = nil; dirtySince = nil
            // Keep observedApplication only for the original missed-activation
            // retirement gate; never use it to attribute this unknown failure.
            reportUnavailable(result, unresolved: "policy-boundary", gapReason: "policy-boundary", providerApplicationId: providerApplicationId())
            return
        }
        let surfaceRequested = !isFastOnly && (ticket.policy.captureScope == "region" || ticket.policy.captureScope == "window")
        func reportSurfaceFailure() {
            guard surfaceRequested, result.surface == nil, let failure = result.surfaceFailure,
                  let code = ReadDiagnostic.Code(rawValue: failure.rawValue) else { return }
            gap(failure.gapReason, diagnostic: ReadDiagnostic(code: code), providerApplicationId: providerApplicationId())
        }
        guard let app = result.application,
              ApplicationPolicy.allows(app.applicationId, policy: ticket.policy), BrowserGate.allows(app.applicationId, policy: ticket.policy),
              result.captureEndMs >= result.captureStartMs,
              result.validWindowOnlyChannels(policy: ticket.policy),
              result.text.map({ validRead($0, policy: ticket.policy) }) != false,
              result.text != nil || result.surface != nil || result.selection != nil || !(result.inputRecords ?? []).isEmpty || (ticket.policy.inputText == true && result.sessionIdentity != nil),
              ticket.hint == nil || ticket.hint?.application == app else {
            clearSnapshotStates()
            let reason = result.reason ?? "read-error"
            if reason == "focus-unavailable" || reason == "policy-boundary" {
                focusGeneration += 1; target = .object(["kind": .string("unresolved"), "reason": .string(reason == "policy-boundary" ? "policy-boundary" : "focus-unavailable")])
                observation(.object(["kind": .string("context.changed"), "reason": .string("focus-unavailable")]))
            }
            gap(["policy-boundary", "stale", "timeout", "budget", "desktop-unavailable"].contains(reason) ? reason : "read-error", diagnostic: result.diagnostic, providerApplicationId: providerApplicationId())
            if !(reason == "stale" && result.diagnostic?.code == .focusChanged),
               result.diagnostic?.code.rawValue != result.surfaceFailure?.rawValue {
                reportSurfaceFailure()
            }
            return
        }
        if let known = observedApplication, known != app {
            // Missed activation: an AX reconciliation must not leave the prior app's bucket alive.
            let due = nextRead
            if ticket.policy.inputText == true {
                boundary("focus-unavailable", endInput: false, retireInput: true); nextRead = due; return
            }
            boundary("focus-unavailable", endInput: false)
            nextRead = due
        }
        observedApplication = app
        // Stable identities are accepted only from the same worker-owned AX
        // equality epoch. Legacy one-shot workers always rebaseline.
        let changed = result.sessionIdentity == nil || result.sessionIdentity != workerIdentity
        if changed { clearSnapshotStates(); foregroundGeneration += 1; focusGeneration += 1 }
        workerIdentity = result.sessionIdentity
        snapshotSerial += 1
        let window = result.sessionIdentity?.windowId ?? UUID().uuidString
        let node = result.sessionIdentity?.nodeId ?? UUID().uuidString
        target = .object(["kind": .string("resolved"), "identity": .object([
            "deviceId": .string(deviceId), "osSessionId": .string(osSessionId), "desktopId": .string(desktopId),
            "processId": j(Int(app.processId)), "processStartTime": .string(app.processStartTime), "applicationId": .string(app.applicationId),
            "windowId": .string(window), "windowGeneration": j(result.sessionIdentity?.windowGeneration ?? foregroundGeneration),
        ])])
        if changed { observation(.object(["kind": .string("context.changed"), "reason": .string("focus")]), eventTime: result.captureStartMs) }
        let privateState = result.privateState ?? (BrowserGate.isKnownBrowser(app.applicationId) ? "user-authorized" : "normal")
        guard ["normal", "user-authorized"].contains(privateState), privateState != "user-authorized" || (ticket.policy.applicationScope == "denylist" && ticket.policy.allowBrowserContent == true) else { clearSnapshotStates(); return }
        let gate: JSONValue = .object(["secure": .string(ticket.policy.contentGateSecure), "privateState": .string(privateState), "policyRevision": j(policyRevision)])
        if ticket.policy.inputText == true, let identity = result.sessionIdentity {
            for record in (result.inputRecords ?? []).sorted(by: { $0.intervalEndMs < $1.intervalEndMs }).prefix(4) where record.isValid {
                guard record.context.target.application == app, record.context.surfaceId == identity.surfaceId,
                      record.context.target.windowId == identity.windowId, record.context.target.windowGeneration == identity.windowGeneration,
                       record.context.fieldSecurityMode == ticket.policy.fieldSecurityMode, record.context.privateState.rawValue == privateState,
                       record.context.captureEpoch == captureEpoch,
                      record.context.policyRevision == policyRevision, record.context.foregroundGeneration == foregroundGeneration,
                      record.context.focusGeneration == focusGeneration, record.context.target.deviceId == deviceId,
                      record.context.target.osSessionId == osSessionId, record.context.target.desktopId == desktopId else { continue }
                observation(record.payload(), eventTime: record.intervalEndMs, eventTarget: record.context.target.json, eventStamp: record.context.stamp)
            }
        }
        if let read = result.text {
        var payload: [String: JSONValue] = [
            "kind": .string("text.snapshot"), "snapshotId": .string("s-\(snapshotSerial)-\(UUID().uuidString)"),
            "editSessionId": .string(UUID().uuidString), "nodeId": .string(node), "source": .string(fixture ? "fixture" : read.source),
            "scope": .string(read.complete ? "field" : "accessible-range"), "valueState": .string("read"), "text": .string(read.text),
            "range": textRange(start: read.rangeStart, length: read.text.utf16.count), "rangeBasis": .string(read.rangeBasis), "composition": .string("unknown"),
            "captureStartMs": j(result.captureStartMs), "captureEndMs": j(result.captureEndMs),
            "coverage": .object(["status": .string(read.complete ? "complete" : "partial"), "truncated": .bool(read.truncated), "missingReasons": .array(read.missingReasons.map(JSONValue.string))]),
            "gate": gate,
        ]
        if let length = read.totalLength { payload["totalLength"] = j(length) }
        if let selection = read.selection { payload["selection"] = textRange(start: selection.start, length: selection.length) }
        let current = snapshotState(payload, eventTime: result.captureEndMs)
        let confirmsBlank = read.complete && read.rangeBasis == "prefix" && read.rangeStart == 0 &&
            read.totalLength == read.text.utf16.count && !read.truncated && read.missingReasons.isEmpty
        if shouldEmitTextSnapshot(current, text: read.text, confirmsBlank: confirmsBlank,
                                  previous: &lastTextState, hadNonblank: &textHadNonblank) {
            observation(.object(payload), eventTime: result.captureEndMs)
        }
        } else { lastTextState = nil; textHadNonblank = false }
        if let surface = result.surface, result.validSurface(policy: ticket.policy) {
            var value: [String: JSONValue] = ["kind": .string("surface.snapshot"), "snapshotId": .string(UUID().uuidString),
                "surfaceId": .string(surface.surfaceId), "revision": j(surface.revision), "source": .string(fixture ? "fixture" : "ax.tree"),
                "scope": .string(surface.scope), "mode": .string(surface.mode), "nodes": .array(surface.nodes.map(\.json)),
                "captureStartMs": j(result.captureStartMs), "captureEndMs": j(result.captureEndMs), "gate": gate, "consistency": .string("non-atomic"),
                "coverage": .object(["status": .string(surface.complete ? "complete" : "partial"), "truncated": .bool(surface.truncated), "missingReasons": .array(surface.missingReasons.map(JSONValue.string))])]
            if let geometry = surface.geometry { value["geometry"] = geometry.json }
            if surface.mode == "diff", let base = surface.baseRevision {
                value["baseRevision"] = j(base)
                value["changes"] = .object(["added": .array(surface.added.map(JSONValue.string)), "updated": .array(surface.updated.map(JSONValue.string)), "removed": .array(surface.removed.map(JSONValue.string))])
            }
            let current = snapshotState(value, eventTime: result.captureEndMs, focusAbsent: result.focusAbsent == true)
            if current == nil || current != lastSurfaceState {
                if current != nil, surface.mode == "diff", surface.baseRevision != lastSurfaceRevision {
                    // Only a valid diff may become full; never repair malformed
                    // evidence. Skipped worker revisions were never emitted.
                    value["mode"] = .string("full")
                    value.removeValue(forKey: "baseRevision"); value.removeValue(forKey: "changes")
                }
                lastSurfaceState = current; lastSurfaceRevision = current == nil ? nil : surface.revision
                observation(.object(value), eventTime: result.captureEndMs)
            }
        } else if !isFastOnly { lastSurfaceState = nil; lastSurfaceRevision = nil }
        if let selection = result.selection, let identity = result.sessionIdentity, ticket.policy.selectionCapture == true,
           selection.text.utf16.count <= ticket.policy.maxTextCodeUnits, selection.rangeStart >= 0 {
            let value: [String: JSONValue] = ["kind": .string("selection.snapshot"), "snapshotId": .string(UUID().uuidString), "surfaceId": .string(identity.surfaceId),
                "source": .string(fixture ? "fixture" : selection.source), "scope": .string("selection"), "text": .string(selection.text),
                "range": textRange(start: selection.rangeStart, length: selection.text.utf16.count), "captureStartMs": j(result.captureStartMs), "captureEndMs": j(result.captureEndMs), "gate": gate,
                "coverage": .object(["status": .string("partial"), "truncated": .bool(selection.truncated), "missingReasons": .array(selection.missingReasons.map(JSONValue.string))])]
            let current = snapshotState(value, eventTime: result.captureEndMs)
            let confirmsBlank = !selection.truncated && selection.missingReasons.allSatisfy { ["selection-only", "non-atomic"].contains($0) }
            if shouldEmitTextSnapshot(current, text: selection.text, confirmsBlank: confirmsBlank,
                                      previous: &lastSelectionState, hadNonblank: &selectionHadNonblank) {
                observation(.object(value), eventTime: result.captureEndMs)
            }
        } else if !isFastOnly { lastSelectionState = nil; selectionHadNonblank = false }
        reportSurfaceFailure()
        if result.focusAbsent == true && result.surface == nil {
            // Only emit focused-field-unavailable when window surface capture also
            // failed; a successful window-only snapshot is normal.
            gap("read-error", diagnostic: ReadDiagnostic(code: .focusedFieldUnavailable), providerApplicationId: providerApplicationId())
        }
        if ticket.policy.inputText == true {
            for raw in (result.inputGaps ?? []).prefix(4) {
                guard let reason = InputTextGapReason(rawValue: raw) else { continue }
                gap(reason.gapReason, diagnostic: reason.diagnostic, providerApplicationId: providerApplicationId())
            }
        }
    }
    private func clearSnapshotStates() {
        lastTextState = nil; lastSurfaceState = nil; lastSelectionState = nil; lastSurfaceRevision = nil
        textHadNonblank = false; selectionHadNonblank = false
    }
    /// Only known-complete blank evidence may be omitted or consume a clear.
    /// Partial empty ranges do not prove an empty field/selection. Keep original
    /// strings and allow one blank after nonblank evidence in this identity epoch.
    private func shouldEmitTextSnapshot(_ current: JSONValue?, text: String, confirmsBlank: Bool,
                                        previous: inout JSONValue?, hadNonblank: inout Bool) -> Bool {
        guard let current else {
            // Invalid payloads still reach the output validator, never the filter.
            previous = nil; hadNonblank = false; return true
        }
        let nonblank = text.unicodeScalars.contains { !$0.properties.isWhitespace }
        let changed = current != previous
        previous = current
        if !nonblank && confirmsBlank {
            let clear = hadNonblank
            hadNonblank = false
            return clear
        }
        if nonblank { hadNonblank = true }
        return changed
    }
    /// Compare actual evidence, not new IDs, polling clocks or diff bookkeeping.
    /// JSONValue uses exact UTF-16 equality (Swift String == normalizes Unicode).
    /// No old timestamp is refreshed and an omitted sample creates no event ID.
    private func snapshotState(_ payload: [String: JSONValue], eventTime: Int64, focusAbsent: Bool = false) -> JSONValue? {
        // Validate BEFORE ignoring volatile fields, including geometry clocks and
        // diff invariants. Ineligible evidence is never cached or suppressed; the
        // unchanged output validator still rejects it and closes the transport.
        guard let snapshotValidator,
              (try? snapshotValidator.encodeFrame(observationMessage(.object(payload), eventTime: eventTime))) != nil else { return nil }
        var value = payload
        for key in ["snapshotId", "editSessionId", "captureStartMs", "captureEndMs", "revision", "mode", "baseRevision", "changes"] { value.removeValue(forKey: key) }
        if let nodes = value["nodes"]?.arrayValue {
            value["nodes"] = .array(nodes.map { node in
                guard var fields = node.objectValue else { return node }
                fields.removeValue(forKey: "observedAtMs")
                // Preserve availability of optional geometry evidence, not its clock.
                if fields["boundsObservedAtMs"] != nil { fields["boundsObservedAtMs"] = j(0) }
                return .object(fields)
            })
        }
        if var geometry = value["geometry"]?.objectValue {
            if geometry["observedAtMs"] != nil { geometry["observedAtMs"] = j(0) }
            value["geometry"] = .object(geometry)
        }
        return .object(["target": target, "stamp": stamp, "focusAbsent": .bool(focusAbsent), "payload": .object(value)])
    }
    /// Called only for the two exact, content-free shapes in complete(). This
    /// compares a negative observation, never a successful identity/safety permit.
    private func unavailableState(_ result: ReadResult, unresolved: String, providerApplicationId: String?) -> JSONValue? {
        // Invalid/mismatched diagnostic identity must not become a stable nil-app
        // state. Keep reporting it, without retaining any unbounded provider data.
        var provider = JSONValue.null
        if let app = result.diagnosticApplication {
            guard providerApplicationId != nil else { return nil }
            provider = .object(["applicationId": .string(app.applicationId), "processId": j(Int(app.processId)),
                "processStartTime": .string(app.processStartTime)])
        }
        guard result.privateState == nil || ["normal", "user-authorized"].contains(result.privateState!),
              result.observerStatus == nil || ["unavailable", "best-effort"].contains(result.observerStatus!) else { return nil }
        var enablement = JSONValue.null
        if let value = result.enablement {
            enablement = .object(["status": .string(value.status.rawValue), "attribute": .string(value.attribute.rawValue),
                "changed": .bool(value.changed)])
        }
        return .object(["target": target, "stamp": stamp, "unresolved": .string(unresolved),
            "reason": result.reason.map(JSONValue.string) ?? .null, "diagnostic": result.diagnostic?.json ?? .null,
            "provider": provider, "enablement": enablement,
            "privateState": result.privateState.map(JSONValue.string) ?? .null,
            "observerStatus": result.observerStatus.map(JSONValue.string) ?? .null,
            "focusAbsent": result.focusAbsent.map(JSONValue.bool) ?? .null,
            "surfaceFailure": result.surfaceFailure.map { .string($0.rawValue) } ?? .null])
    }
    private func reportUnavailable(_ result: ReadResult, unresolved: String, gapReason: String, providerApplicationId: String?) {
        // Compare before advancing a real unresolved boundary. Otherwise our own
        // per-poll focusGeneration increment would manufacture a state change.
        if let current = unavailableState(result, unresolved: unresolved, providerApplicationId: providerApplicationId),
           current == lastUnavailableState { return }
        lastUnavailableState = nil
        let changed = target["kind"] != .string("unresolved") || target["reason"] != .string(unresolved)
        if changed {
            focusGeneration += 1
            target = .object(["kind": .string("unresolved"), "reason": .string(unresolved)])
        }
        // Cache the published stamp, not its pre-context predecessor. Establish
        // before emit so a synchronous dirty/backpressure/boundary clears it.
        lastUnavailableState = unavailableState(result, unresolved: unresolved, providerApplicationId: providerApplicationId)
        if changed {
            observation(.object(["kind": .string("context.changed"), "reason": .string("focus-unavailable")]), preservingUnavailableState: true)
        }
        gap(gapReason, diagnostic: result.diagnostic, providerApplicationId: providerApplicationId, preservingUnavailableState: true)
    }
    public func reportBackpressure() { clearSnapshotStates(); gap("backpressure") }
    private func gap(_ reason: String, diagnostic: ReadDiagnostic? = nil, providerApplicationId: String? = nil, preservingUnavailableState: Bool = false) {
        var payload: [String: JSONValue] = ["kind": .string("gap"), "reason": .string(reason), "count": j(1)]
        if let diagnostic { payload["diagnostic"] = diagnostic.json }
        if let providerApplicationId { payload["providerApplicationId"] = .string(providerApplicationId) }
        observation(.object(payload), preservingUnavailableState: preservingUnavailableState)
    }
    private func observationMessage(_ payload: JSONValue, eventTime: Int64? = nil, eventTarget: JSONValue? = nil, eventStamp: JSONValue? = nil) -> JSONValue {
        .object(["protocolVersion": j(1), "type": .string("observation"), "eventId": .string("\(instanceId):\(seq + 1)"), "instanceId": .string(instanceId),
                 "seq": j(seq + 1), "eventTimeMs": j(eventTime ?? clock.unixMs), "monotonicMs": j(clock.monotonicMs), "target": eventTarget ?? target,
                 "stamp": eventStamp ?? stamp, "actor": .string("unknown"), "relatedActionIds": .array([]), "payload": payload])
    }
    private func observation(_ payload: JSONValue, eventTime: Int64? = nil, eventTarget: JSONValue? = nil, eventStamp: JSONValue? = nil, preservingUnavailableState: Bool = false) {
        if !preservingUnavailableState { lastUnavailableState = nil }
        let message = observationMessage(payload, eventTime: eventTime, eventTarget: eventTarget, eventStamp: eventStamp)
        seq += 1; emit(message)
    }
}

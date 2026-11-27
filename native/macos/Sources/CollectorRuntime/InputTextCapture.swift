import Foundation
import Darwin
import AppKit
import CoreGraphics
import Carbon
import CollectorCore

/// Closed development vocabulary shared by Session and the native input owner.
/// No caller can place provider strings, application names or input text here.
enum InputDebugTrace {
    enum Code: String { case context = "input-context-check", capture = "input-capture-check" }
    enum Stage: String {
        case event, receive, preReadSafety = "pre-read-safety", unicodeRead = "unicode-read", postReadSafety = "post-read-safety"
        case flush, poll, drain, safetyEntry = "safety-entry", safetyRequest = "safety-request", safetyResolve = "safety-resolve"
        case safetySecurity = "safety-security", safetyRole = "safety-role", safetyFinal = "safety-final", contextEstablish = "context-establish"
    }
    enum Reason: String {
        case accepted, inactive, tapDisabled = "tap-disabled", permissionUnavailable = "permission-unavailable", secureInputActive = "secure-input-active"
        case eventTypeUnsupported = "event-type-unsupported", targetPidInvalid = "target-pid-invalid", foregroundUnverified = "foreground-unverified"
        case policyDisabled = "policy-disabled", ticketMissing = "ticket-missing", applicationMissing = "application-missing", identityMissing = "identity-missing"
        case contextMissing = "context-missing", contextInvalid = "context-invalid", fieldSecurityPolicyChanged = "field-security-policy-changed"
        case applicationExcluded = "application-excluded", desktopUnavailable = "desktop-unavailable", accessibilityUnavailable = "accessibility-unavailable"
        case fieldMissing = "field-missing", windowMissing = "window-missing", targetPidMismatch = "target-pid-mismatch", contextChanged = "context-changed"
        case focusUnresolved = "focus-unresolved", fieldChanged = "field-changed", windowChanged = "window-changed", fieldSensitive = "field-sensitive"
        case fieldSecurityUnknown = "field-security-unknown", roleMissing = "role-missing", roleUnsupported = "role-unsupported"
        case focusWindowUnverified = "focus-window-unverified", surfaceChanged = "surface-changed", deadlineExceeded = "deadline-exceeded"
        case eventTimeInvalid = "event-time-invalid", eventBeforeBoundary = "event-before-boundary", eventInFuture = "event-in-future", eventAgeExceeded = "event-age-exceeded"
        case safetyUnavailable = "safety-unavailable", approvalNotFresh = "approval-not-fresh", applicationChanged = "application-changed", roleChanged = "role-changed"
        case unicodeUnavailable = "unicode-unavailable", unicodeSaturated = "unicode-saturated", unicodeInvalid = "unicode-invalid", unicodeBudget = "unicode-budget"
        case recordInvalid = "record-invalid", pendingFull = "pending-full", pendingTimeInvalid = "pending-time-invalid", pendingExpired = "pending-expired"
        case accumulatorStale = "accumulator-stale", accumulatorBudget = "accumulator-budget", accumulatorInvalid = "accumulator-invalid", empty, notDue = "not-due"
    }
    static func record(_ code: Code, stage: Stage, reason: Reason, readId: Int64, targetPid: Int32? = nil,
                       contextAgeMs: Int64? = nil, eventAgeMs: Int64? = nil, contextPresent: Bool? = nil,
                       ticketPresent: Bool? = nil, fieldPresent: Bool? = nil, windowPresent: Bool? = nil,
                       role: InputTextFieldRole? = nil, file: StaticString = #fileID, line: UInt = #line) {
        var numbers = ["readId": readId]
        if let targetPid { numbers["targetPid"] = Int64(targetPid) }
        if let contextAgeMs { numbers["contextAgeMs"] = contextAgeMs }
        if let eventAgeMs { numbers["eventAgeMs"] = eventAgeMs }
        var flags: [String: Bool] = [:]
        if let contextPresent { flags["contextPresent"] = contextPresent }
        if let ticketPresent { flags["ticketPresent"] = ticketPresent }
        if let fieldPresent { flags["fieldPresent"] = fieldPresent }
        if let windowPresent { flags["windowPresent"] = windowPresent }
        var strings = ["stage": stage.rawValue, "reason": reason.rawValue]
        if let role { strings["role"] = role.rawValue }
        CollectorDebugTrace.record(code.rawValue, numbers: numbers, flags: flags, strings: strings, file: file, line: line)
    }
    static func classification(_ rejection: InputTextReadRejection) -> (Stage, Reason)? {
        guard let stage = Stage(rawValue: rejection.stage.rawValue), let reason = Reason(rawValue: rejection.reason.rawValue) else { return nil }
        return (stage, reason)
    }
}

/// Passive opt-in Unicode evidence, owned ONLY by the isolated session worker.
/// Constructing it does not inspect the desktop, install a tap or request access.
/// safetyProvider must synchronously perform fresh AX safety/identity checks on
/// this worker run loop. A blocked provider may lose events; the parent's worker
/// watchdog must kill/reap it. This is not a zero-latency or race-free guarantee.
final class InputTextCapture {
    typealias SafetyProvider = (InputTextSafetyRequest) -> Result<InputTextApprovedContext, InputTextGapReason>
    private let policy: CapturePolicy
    private let safetyProvider: SafetyProvider
    private let clock = SystemCollectorClock()
    private var tap: CFMachPort?
    private var source: CFRunLoopSource?
    private var runLoop: CFRunLoop?
    private var timer: Timer?
    private var active = false
    private var acceptAfterNanoseconds: UInt64 = 0
    private var accumulator: InputTextAccumulator
    private var completed: [InputTextEmission] = []
    var debugReadId: Int64 = 0
    private func trace(_ stage: InputDebugTrace.Stage, _ reason: InputDebugTrace.Reason,
                       event: InputTextEventMetadata? = nil, targetPid: Int32? = nil, line: UInt = #line) {
        let now = DispatchTime.now().uptimeNanoseconds
        let age = event.flatMap { now >= $0.timestampNanoseconds ? Int64((now - $0.timestampNanoseconds) / 1_000_000) : nil }
        InputDebugTrace.record(.capture, stage: stage, reason: reason, readId: debugReadId,
            targetPid: targetPid ?? event?.targetProcessId, eventAgeMs: age, file: #fileID, line: line)
    }
    private(set) var reason = "input-monitoring-unavailable"
    var isListening: Bool { active }
    var isHealthy: Bool {
        guard active, reason == "input-text-listening-partial", let tap, CFMachPortIsValid(tap),
              CGEvent.tapIsEnabled(tap: tap), CGPreflightListenEventAccess() else { return false }
        return CGEvent.tapIsEnabled(tap: tap)
    }
    var gap: (InputTextGapReason) -> Void = { _ in }
    var disabled: (String) -> Void = { _ in }
    var secureInput: () -> Void = {}
    var submitTrigger: () -> Void = {}
    private var secureInputBlocked = false
    /// One-way for this worker. Only its healthy retirement and a fresh worker
    /// may reopen input; a brief secure interval cannot revive old callbacks.
    func suppressSecureInput() {
        invalidate()
        if !secureInputBlocked { secureInputBlocked = true; secureInput() }
    }

    init(policy: CapturePolicy, safetyProvider: @escaping SafetyProvider) {
        self.policy = policy; self.safetyProvider = safetyProvider
        self.accumulator = InputTextAccumulator(maxCodeUnits: InputTextLimits.codeUnitBudget(policy))
    }
    deinit { end() }

    func begin() -> Bool {
        end()
        guard policy.enabled, policy.inputText == true else { reason = "policy-disabled"; return false }
        guard CGPreflightListenEventAccess() else { CollectorDebugTrace.record("input-text-permission", stack: true); reason = "input-monitoring-required"; return false }
        guard !IsSecureEventInputEnabled() else { CollectorDebugTrace.record("input-text-secure"); reason = "secure-input-active"; suppressSecureInput(); return false }
        let mask = CGEventMask(1) << CGEventType.keyDown.rawValue
        guard let created = CGEvent.tapCreate(tap: .cgAnnotatedSessionEventTap, place: .tailAppendEventTap,
            options: .listenOnly, eventsOfInterest: mask, callback: { _, type, event, context in
                if let context { Unmanaged<InputTextCapture>.fromOpaque(context).takeUnretainedValue().receive(type, event) }
                // No mutation, suppression, injection, redirection or event copying.
                return Unmanaged.passUnretained(event)
            }, userInfo: Unmanaged.passUnretained(self).toOpaque()) else { CollectorDebugTrace.record("input-text-tap-create", stack: true); reason = "input-monitoring-unavailable"; return false }
        guard let createdSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, created, 0) else {
            CollectorDebugTrace.record("input-text-source-create", stack: true)
            CFMachPortInvalidate(created); reason = "input-monitoring-unavailable"; return false
        }
        let current = CFRunLoopGetCurrent()
        tap = created; source = createdSource; runLoop = current; active = true
        invalidate()
        CFRunLoopAddSource(current, createdSource, .commonModes)
        guard CGEvent.tapIsEnabled(tap: created) else { fail("input-monitoring-disabled"); return false }
        nonisolated(unsafe) weak var weakSelf = self
        let createdTimer = Timer(timeInterval: 0.05, repeats: true) { _ in weakSelf?.poll() }
        timer = createdTimer; RunLoop.current.add(createdTimer, forMode: .common)
        reason = "input-text-listening-partial"
        return true
    }
    /// Explicit lifecycle boundaries discard all content, including completed but
    /// not yet drained segments. They NEVER flush a previous focus or app.
    func end() {
        active = false
        timer?.invalidate(); timer = nil
        if let tap { CGEvent.tapEnable(tap: tap, enable: false) }
        if let source, let runLoop { CFRunLoopRemoveSource(runLoop, source, .commonModes); CFRunLoopSourceInvalidate(source) }
        if let tap { CFMachPortInvalidate(tap) }
        tap = nil; source = nil; runLoop = nil
        invalidate()
    }
    /// Called synchronously on this worker's run loop for an intentional
    /// retirement ACK. This is listener health, NOT authorization to read content.
    /// Secure Input can invalidate content while an otherwise healthy tap retires.
    /// A missing/disabled/failed listener or revoked permission never ACKs healthy.
    /// Parent must receive this ACK and reap the exact worker before replacement;
    /// a missing ACK or unexpected exit must latch failure instead of auto-restart.
    func retireHealthy() -> Bool {
        let healthy = isHealthy
        end() // Clear, disable and remove sources before any retirement ACK.
        return healthy
    }
    func invalidate() {
        acceptAfterNanoseconds = DispatchTime.now().uptimeNanoseconds
        accumulator.clear(); completed.removeAll(keepingCapacity: false)
    }
    private func fail(_ reason: String) {
        CollectorDebugTrace.record("input-text-failed", flags: ["required": reason == "input-monitoring-required", "disabled": reason == "input-monitoring-disabled", "secureInputActive": reason == "secure-input-active"], stack: true)
        self.reason = reason; end(); gap(.readError); disabled(reason)
        // Only a new explicit worker/start lifecycle can install another tap.
    }
    private func discard(_ reason: InputTextGapReason) { invalidate(); gap(reason) }

    /// Independent event source is not an independent content-safety permission.
    /// Blacklisted bundle families are rejected before AX metadata/Unicode reads.
    private func foregroundAllowed(expectedPid: Int32) -> Result<ApplicationIdentity, InputTextGapReason> {
        guard let app = NSWorkspace.shared.frontmostApplication else { return .failure(.stale) }
        let observed = app.processIdentifier
        guard observed == expectedPid else { return .failure(.processMismatch(expected: expectedPid, observed: Int64(observed))) }
        guard let bundleId = app.bundleIdentifier, ApplicationPolicy.allows(applicationId: bundleId, policy: policy),
              AppIdentityGate.permittedApplication(app, policy: policy),
              let identity = AppIdentityGate.identity(app) else { return .failure(.stale) }
        return .success(identity)
    }
    private func activeChecks(_ stage: InputDebugTrace.Stage, event: InputTextEventMetadata? = nil, targetPid: Int32? = nil) -> InputDebugTrace.Reason? {
        guard active else { trace(stage, .inactive, event: event, targetPid: targetPid); return .inactive }
        guard let tap, CGEvent.tapIsEnabled(tap: tap) else { trace(stage, .tapDisabled, event: event, targetPid: targetPid); return .tapDisabled }
        guard CGPreflightListenEventAccess() else { trace(stage, .permissionUnavailable, event: event, targetPid: targetPid); fail("input-monitoring-required"); return .permissionUnavailable }
        guard !IsSecureEventInputEnabled() else { trace(stage, .secureInputActive, event: event, targetPid: targetPid); suppressSecureInput(); return .secureInputActive }
        guard !secureInputBlocked else { invalidate(); return .secureInputActive }
        return nil
    }
    private func approve(_ request: InputTextSafetyRequest, stage: InputDebugTrace.Stage) -> Result<InputTextApprovedContext, InputTextGapReason> {
        let expectedPid: Int32
        switch request {
        case .event(let event): expectedPid = event.targetProcessId
        case .flush(let context): expectedPid = context.target.application.processId
        }
        guard activeChecks(stage, targetPid: expectedPid) == nil else { return .failure(.stale) }
        let before: ApplicationIdentity
        switch foregroundAllowed(expectedPid: expectedPid) {
        case .success(let identity): before = identity
        case .failure(let reason): trace(stage, .foregroundUnverified, targetPid: expectedPid); return .failure(reason)
        }
        let result: InputTextApprovedContext
        switch safetyProvider(request) {
        case .success(let approval): result = approval
        case .failure(let reason): trace(stage, .safetyUnavailable, targetPid: expectedPid); return .failure(reason)
        }
        guard activeChecks(stage, targetPid: expectedPid) == nil else { return .failure(.stale) }
        switch foregroundAllowed(expectedPid: expectedPid) {
        case .success(let after):
            guard after == before else { trace(stage, .foregroundUnverified, targetPid: expectedPid); return .failure(.targetMismatch) }
        case .failure(let reason): trace(stage, .foregroundUnverified, targetPid: expectedPid); return .failure(reason)
        }
        guard result.context.target.application == before else {
            trace(stage, .applicationChanged, targetPid: expectedPid)
            return .failure(result.context.isValid ? .targetMismatch : .stale)
        }
        return .success(result)
    }
    private func flushApproval(_ context: InputTextContext, stage: InputDebugTrace.Stage) -> Result<InputTextContext, InputTextGapReason> {
        InputTextReadGate.revalidateBufferedContext(context, policy: policy,
            nowNanoseconds: { DispatchTime.now().uptimeNanoseconds }, typedSafetyProvider: { self.approve($0, stage: .flush) },
            onRejection: { reason in
                if let fixed = InputDebugTrace.Reason(rawValue: reason.rawValue) {
                    self.trace(stage, fixed, targetPid: context.target.application.processId)
                }
            })
    }
    private func enqueue(_ record: InputTextEmission) {
        guard record.isValid else { trace(.flush, .recordInvalid, targetPid: record.context.target.application.processId); discard(.readError); return }
        guard completed.count < InputTextLimits.maxPending else { trace(.flush, .pendingFull, targetPid: record.context.target.application.processId); discard(.backpressure); return }
        completed.append(record)
    }
    func poll() {
        guard active else { return }
        if let rejection = activeChecks(.poll) {
            if active, rejection != .secureInputActive { fail("input-monitoring-disabled") }
            return
        }
        guard let pending = accumulator.pending else { return }
        let now = clock.unixMs
        guard now >= pending.intervalEndMs else { trace(.poll, .pendingTimeInvalid, targetPid: pending.context.target.application.processId); discard(.stale); return }
        guard now - pending.intervalStartMs <= 5_000 else { trace(.poll, .pendingExpired, targetPid: pending.context.target.application.processId); discard(.stale); return }
        // No Unicode read occurs here. Avoid AX IPC on every 10ms worker tick:
        // events, due flushes and IPC drains get fresh gates; lifecycle/observer
        // boundaries still clear immediately. Never use an old safety permit.
        guard accumulator.isDue(nowMs: now) else { return }
        switch flushApproval(pending.context, stage: .poll) {
        case .failure(let reason): discard(reason)
        case .success(let approved):
            if let record = accumulator.takeDue(nowMs: clock.unixMs, approvedContext: approved) { enqueue(record) }
        }
    }
    /// Final gate before worker IPC. Acts as a causal read barrier so buffered
    /// keystrokes in the verified context are sealed ahead of the snapshot.
    func drainPending() -> [InputTextEmission] {
        guard activeChecks(.drain) == nil else { invalidate(); return [] }
        if completed.isEmpty && accumulator.pending == nil { return [] }
        let drained = InputTextReadGate.drainAtBarrier(
            completed: &completed,
            accumulator: &accumulator,
            nowMs: clock.unixMs,
            policy: policy,
            nowNanoseconds: { DispatchTime.now().uptimeNanoseconds },
            typedSafetyProvider: { self.approve($0, stage: .drain) },
            onRejection: { reason in
                if let fixed = InputDebugTrace.Reason(rawValue: reason.rawValue) {
                    self.trace(.drain, fixed)
                }
            }
        )
        switch drained {
        case .success(let records):
            return records
        case .failure(let reason):
            discard(reason)
            return []
        }
    }
    private func receive(_ type: CGEventType, _ event: CGEvent) {
        // A queued callback from a removed source cannot mutate retirement state
        // or call the worker's gap/disabled handlers after end() returned.
        guard active else { trace(.event, .inactive); return }
        if type == .tapDisabledByTimeout || type == .tapDisabledByUserInput { trace(.event, .tapDisabled); fail("input-monitoring-disabled"); return }
        guard type == .keyDown else { trace(.event, .eventTypeUnsupported); return }
        guard activeChecks(.event) == nil else { return }
        let pid = event.getIntegerValueField(.eventTargetUnixProcessID)
        guard pid > 1, pid <= Int64(Int32.max) else { trace(.event, .targetPidInvalid); discard(.stale); return }
        if case .failure(let reason) = foregroundAllowed(expectedPid: Int32(pid)) {
            trace(.event, .foregroundUnverified, targetPid: Int32(pid)); discard(reason); return
        }
        let metadata = InputTextEventMetadata(targetProcessId: Int32(pid), timestampNanoseconds: event.timestamp, callbackTimeMs: clock.unixMs)
        let flags = event.flags
        var modifiers: [InputTextModifier] = []
        if flags.contains(.maskCommand) { modifiers.append(.command) }
        if flags.contains(.maskControl) { modifiers.append(.control) }
        if flags.contains(.maskAlternate) { modifiers.append(.option) }
        if flags.contains(.maskShift) { modifiers.append(.shift) }
        var safetyPass = 0
        let decision = InputTextReadGate.capture(metadata: metadata, modifiers: modifiers, policy: policy,
            afterNanoseconds: acceptAfterNanoseconds, nowNanoseconds: { DispatchTime.now().uptimeNanoseconds },
            typedSafetyProvider: { request in
                let stage: InputDebugTrace.Stage = safetyPass == 0 ? .preReadSafety : .postReadSafety
                safetyPass += 1
                let observedPid = event.getIntegerValueField(.eventTargetUnixProcessID)
                guard observedPid == pid else {
                    self.trace(stage, .targetPidMismatch, event: metadata)
                    return .failure(.processMismatch(expected: metadata.targetProcessId, observed: observedPid))
                }
                guard event.timestamp == metadata.timestampNanoseconds else { self.trace(stage, .eventTimeInvalid, event: metadata); return .failure(.stale) }
                return self.approve(request, stage: stage)
            }, readUnicode: {
                guard self.activeChecks(.unicodeRead, event: metadata) == nil else { return .unavailable }
                guard metadata.timestampNanoseconds > self.acceptAfterNanoseconds else { self.trace(.unicodeRead, .eventBeforeBoundary, event: metadata); return .unavailable }
                if case .failure = self.foregroundAllowed(expectedPid: metadata.targetProcessId) {
                    // This already accounts to the original Unicode read-error
                    // category if the normal post-approval checks pass.
                    self.trace(.unicodeRead, .foregroundUnverified, event: metadata); return .unavailable
                }
                guard !IsSecureEventInputEnabled() else { self.trace(.unicodeRead, .secureInputActive, event: metadata); self.suppressSecureInput(); return .unavailable }
                if let reason = InputTextLimits.eventRejection(metadata, nowNanoseconds: DispatchTime.now().uptimeNanoseconds,
                          afterNanoseconds: self.acceptAfterNanoseconds) {
                    if let classification = InputDebugTrace.classification(.init(stage: .unicodeRead, reason: reason)) {
                        self.trace(classification.0, classification.1, event: metadata)
                    }
                    return .unavailable
                }
                // Getter invoked only after exact safe field + PID + fresh event
                // gates. One extra unit detects saturation without retaining a
                // text prefix. CGEvent never escapes this synchronous callback.
                let budget = InputTextLimits.codeUnitBudget(self.policy)
                var units = [UniChar](repeating: 0, count: budget + 1)
                defer {
                    units.withUnsafeMutableBytes { raw in
                        if let base = raw.baseAddress, raw.count > 0 {
                            _ = memset_s(base, raw.count, 0, raw.count)
                        }
                    }
                }
                var length = 0
                event.keyboardGetUnicodeString(maxStringLength: units.count, actualStringLength: &length, unicodeString: &units)
                guard length >= 0, length <= budget else { return .saturated }
                guard length <= units.count else { return .saturated }
                let text = String(decoding: units.prefix(length), as: UTF16.self)
                // Reject invalid UTF-16 rather than invent replacement characters.
                guard text.utf16.elementsEqual(units.prefix(length)) else { self.trace(.unicodeRead, .unicodeInvalid, event: metadata); return .unavailable }
                return .text(text)
            }, onRejection: { rejection in
                if let classification = InputDebugTrace.classification(rejection) {
                    self.trace(classification.0, classification.1, event: metadata)
                }
            })
        switch decision {
        case .gap(let reason): discard(reason)
        case .ignored: break
        case .sample(let sample):
            guard active else { trace(.receive, .inactive, event: metadata); discard(.stale); return }
            guard metadata.timestampNanoseconds > acceptAfterNanoseconds else { trace(.receive, .eventBeforeBoundary, event: metadata); discard(.stale); return }
            if let pending = accumulator.pending {
                guard pending.context == sample.context else {
                    trace(.receive, .contextChanged, event: metadata)
                    discard(.contextMismatch(pending.context, sample.context)); return
                }
                if accumulator.isDue(nowMs: sample.callbackTimeMs) || pending.eventKind != sample.eventKind || pending.modifiers != sample.modifiers {
                    if let previous = accumulator.takeSegment(approvedContext: sample.context) { enqueue(previous) }
                    guard active else { trace(.receive, .inactive, event: metadata); return }
                    guard metadata.timestampNanoseconds > acceptAfterNanoseconds else { trace(.receive, .eventBeforeBoundary, event: metadata); return }
                }
            }
            if let reason = accumulator.add(sample, source: .cgUnicode) {
                let observed: InputDebugTrace.Reason
                switch reason {
                case .stale: observed = .accumulatorStale
                case .budget: observed = .accumulatorBudget
                default: observed = .accumulatorInvalid
                }
                trace(.receive, observed, event: metadata); discard(reason)
            } else if sample.eventKind == .return {
                // Seal Return immediately into completed instead of waiting for the
                // 50ms/debounce timer, and signal the parent for a fast focused read
                // without running any synchronous AX IPC inside the CGEventTap callback.
                if let sealed = accumulator.takeSegment(approvedContext: sample.context) {
                    enqueue(sealed)
                }
                guard active, !secureInputBlocked, metadata.timestampNanoseconds > acceptAfterNanoseconds else { return }
                submitTrigger()
            }
        }
    }
}

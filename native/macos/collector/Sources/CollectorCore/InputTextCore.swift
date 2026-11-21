import Foundation
import AccessContract

/// Closed, normalized evidence vocabulary. No key codes, CGEvents or coordinates.
public enum InputTextSource: String, Codable { case cgUnicode = "cg.unicode", fixture }
public enum InputTextKind: String, Codable { case text, `return`, shortcut }
public enum InputTextModifier: String, Codable, CaseIterable { case command, control, option, shift }
public enum InputTextPrivateState: String, Codable { case normal, userAuthorized = "user-authorized" }
public enum InputTextFieldRole: String, Codable { case textField = "AXTextField", textArea = "AXTextArea" }
public enum InputTextGapReason: String, Codable, Error {
    case stale, budget, backpressure, readError = "read-error", policyBoundary = "policy-boundary"
    // Private worker values carry detail; the public Gap.reason remains stale.
    case targetMismatch = "input-target-mismatch"
    case roleNotEditable = "input-role-not-editable"
    case verificationTimeout = "input-verification-timeout"
    case fieldSecurityUnknown = "input-field-security-unknown"

    private var broadReason: Self {
        switch self {
        case .targetMismatch, .roleNotEditable, .verificationTimeout, .fieldSecurityUnknown: return .stale
        default: return self
        }
    }
    public var gapReason: String { broadReason.rawValue }
    public var diagnostic: ReadDiagnostic {
        let code: ReadDiagnostic.Code
        switch self {
        case .stale: code = .inputContextUnverified
        case .budget: code = .inputTextBudget
        case .backpressure: code = .inputTextBackpressure
        case .readError: code = .inputTextReadUnavailable
        case .policyBoundary: code = .inputPolicyBoundary
        case .targetMismatch: code = .inputTargetMismatch
        case .roleNotEditable: code = .inputRoleNotEditable
        case .verificationTimeout: code = .inputVerificationTimeout
        case .fieldSecurityUnknown: code = .inputFieldSecurityUnknown
        }
        return ReadDiagnostic(code: code)
    }
    /// Valid and different PID facts are distinguishable from an absent/invalid target.
    public static func processMismatch(expected: Int32, observed: Int64) -> Self {
        expected > 1 && observed > 1 && observed <= Int64(Int32.max) && Int64(expected) != observed ? .targetMismatch : .stale
    }
    /// Use only on contexts already established by the caller. Scope changes and
    /// authority mismatches are generic stale, not positive target disagreement.
    public static func contextMismatch(_ before: InputTextContext, _ after: InputTextContext) -> Self {
        guard before.isValid, after.isValid, before.captureEpoch == after.captureEpoch,
              before.policyRevision == after.policyRevision, before.fieldSecurityMode == after.fieldSecurityMode,
              before.privateState == after.privateState, before.target.deviceId == after.target.deviceId,
              before.target.osSessionId == after.target.osSessionId, before.target.desktopId == after.target.desktopId else { return .stale }
        return before.target != after.target || before.surfaceId != after.surfaceId || before.focusGeneration != after.focusGeneration
            ? .targetMismatch : .stale
    }
}

public struct InputTextTarget: Codable, Equatable {
    public let application: ApplicationIdentity
    public let deviceId: String
    public let osSessionId: String
    public let desktopId: String
    public let windowId: String
    public let windowGeneration: Int64
    public init(application: ApplicationIdentity, deviceId: String, osSessionId: String, desktopId: String, windowId: String, windowGeneration: Int64) {
        self.application = application; self.deviceId = deviceId; self.osSessionId = osSessionId
        self.desktopId = desktopId; self.windowId = windowId; self.windowGeneration = windowGeneration
    }
    public var json: JSONValue { .object(["kind": .string("resolved"), "identity": .object([
        "deviceId": .string(deviceId), "osSessionId": .string(osSessionId), "desktopId": .string(desktopId),
        "applicationId": .string(application.applicationId), "processId": j(Int(application.processId)),
        "processStartTime": .string(application.processStartTime), "windowId": .string(windowId), "windowGeneration": j(windowGeneration),
    ])]) }
    fileprivate var isValid: Bool {
        application.processId > 1 && InputTextLimits.identifier(application.applicationId, max: 256) &&
        [deviceId, osSessionId, desktopId, windowId, application.processStartTime].allSatisfy { InputTextLimits.identifier($0) } &&
        InputTextLimits.integer(windowGeneration)
    }
}

/// Frozen when an event arrives. Field and window identities must be stable worker
/// identities verified against the actual focused AX objects, not app-only guesses.
public struct InputTextContext: Codable, Equatable {
    public let target: InputTextTarget
    public let surfaceId: String
    public let captureEpoch: Int64
    public let foregroundGeneration: Int64
    public let focusGeneration: Int64
    public let policyRevision: Int64
    public let privateState: InputTextPrivateState
    /// Frozen with the event; omitted older private frames remain strict.
    public let fieldSecurity: String?
    public var fieldSecurityMode: String { fieldSecurity ?? "strict" }
    public init(target: InputTextTarget, surfaceId: String, captureEpoch: Int64, foregroundGeneration: Int64, focusGeneration: Int64, policyRevision: Int64, privateState: InputTextPrivateState, fieldSecurity: String? = "strict") {
        self.target = target; self.surfaceId = surfaceId; self.captureEpoch = captureEpoch
        self.foregroundGeneration = foregroundGeneration; self.focusGeneration = focusGeneration
        self.policyRevision = policyRevision; self.privateState = privateState; self.fieldSecurity = fieldSecurity
    }
    public var stamp: JSONValue { .object([
        "captureEpoch": j(captureEpoch), "foregroundGeneration": j(foregroundGeneration),
        "focusGeneration": j(focusGeneration), "policyRevision": j(policyRevision),
    ]) }
    public var isValid: Bool {
        target.isValid && InputTextLimits.identifier(surfaceId) && ["strict", "denylist"].contains(fieldSecurityMode) &&
        [captureEpoch, foregroundGeneration, focusGeneration, policyRevision].allSatisfy { InputTextLimits.integer($0) }
    }
}

/// This is an injected provider assertion, not a substitute for fresh AX safety.
/// The worker constructs it only after safe-role/security/desktop/lease/identity
/// checks. Unknown or sensitive fields return nil BEFORE Unicode is accessed.
public struct InputTextApprovedContext: Equatable {
    public let context: InputTextContext
    public let metadataMonotonicNanoseconds: UInt64
    public let role: InputTextFieldRole
    public init(context: InputTextContext, metadataMonotonicNanoseconds: UInt64, role: InputTextFieldRole) {
        self.context = context; self.metadataMonotonicNanoseconds = metadataMonotonicNanoseconds; self.role = role
    }
}
public struct InputTextEventMetadata {
    public let targetProcessId: Int32
    public let timestampNanoseconds: UInt64
    public let callbackTimeMs: Int64
    public init(targetProcessId: Int32, timestampNanoseconds: UInt64, callbackTimeMs: Int64) {
        self.targetProcessId = targetProcessId; self.timestampNanoseconds = timestampNanoseconds; self.callbackTimeMs = callbackTimeMs
    }
}
public enum InputTextSafetyRequest { case event(InputTextEventMetadata), flush(InputTextContext) }
public enum InputTextUnicodeRead { case text(String), unavailable, saturated }
public enum InputTextCaptureDecision { case sample(InputTextSample), ignored, gap(InputTextGapReason) }

/// Only the observed guard is classified; this is not a permission diagnosis.
/// The production tap and fake-only tests use this same synchronous seam.
public struct InputTextReadRejection: Equatable {
    public enum Stage: String { case receive, preReadSafety = "pre-read-safety", unicodeRead = "unicode-read", postReadSafety = "post-read-safety" }
    public enum Reason: String {
        case policyDisabled = "policy-disabled", targetPidInvalid = "target-pid-invalid", eventTimeInvalid = "event-time-invalid"
        case eventBeforeBoundary = "event-before-boundary", eventInFuture = "event-in-future", eventAgeExceeded = "event-age-exceeded"
        case safetyUnavailable = "safety-unavailable", approvalNotFresh = "approval-not-fresh", targetPidMismatch = "target-pid-mismatch"
        case contextChanged = "context-changed", roleChanged = "role-changed"
        case unicodeUnavailable = "unicode-unavailable", unicodeSaturated = "unicode-saturated", unicodeBudget = "unicode-budget"
    }
    public let stage: Stage
    public let reason: Reason
    public init(stage: Stage, reason: Reason) { self.stage = stage; self.reason = reason }
}

public enum InputTextLimits {
    public static let maxCodeUnits = 2_048
    public static let maxEvents = 256
    public static let debounceMs: Int64 = 500
    public static let maxWaitMs: Int64 = 2_000
    public static let maxPending = 4
    public static func integer(_ value: Int64) -> Bool { value >= 0 && value <= 9_007_199_254_740_991 }
    public static func codeUnitBudget(_ policy: CapturePolicy) -> Int { max(0, min(maxCodeUnits, policy.maxTextCodeUnits)) }
    static func identifier(_ value: String, max: Int = 128) -> Bool { !value.isEmpty && value.utf16.count <= max }
    public static func eventRejection(_ event: InputTextEventMetadata, nowNanoseconds: UInt64, afterNanoseconds: UInt64) -> InputTextReadRejection.Reason? {
        guard event.targetProcessId > 1 else { return .targetPidInvalid }
        guard integer(event.callbackTimeMs) else { return .eventTimeInvalid }
        guard event.timestampNanoseconds > afterNanoseconds else { return .eventBeforeBoundary }
        guard event.timestampNanoseconds <= nowNanoseconds else { return .eventInFuture }
        guard nowNanoseconds - event.timestampNanoseconds <= 200_000_000 else { return .eventAgeExceeded }
        return nil
    }
    public static func eventIsFresh(_ event: InputTextEventMetadata, nowNanoseconds: UInt64, afterNanoseconds: UInt64) -> Bool {
        eventRejection(event, nowNanoseconds: nowNanoseconds, afterNanoseconds: afterNanoseconds) == nil
    }
    static func approvalRejection(_ approval: InputTextApprovedContext, sinceNanoseconds: UInt64, nowNanoseconds: UInt64, policy: CapturePolicy) -> InputTextGapReason? {
        guard policy.enabled, policy.inputText == true, policy.hasValidTextSettings, approval.context.isValid,
              approval.context.fieldSecurityMode == policy.fieldSecurityMode,
              BrowserGate.allows(approval.context.target.application.applicationId, policy: policy),
              nowNanoseconds >= sinceNanoseconds,
              approval.metadataMonotonicNanoseconds >= sinceNanoseconds,
              approval.metadataMonotonicNanoseconds <= nowNanoseconds else { return .stale }
        // Bound the whole safety read, not just the age of fresh completion
        // metadata (which is within this interval). Cached/future/invalid
        // evidence above is not evidence that verification itself timed out.
        guard nowNanoseconds - sinceNanoseconds <= 200_000_000 else { return .verificationTimeout }
        return nil
    }
    public static func approvalIsFresh(_ approval: InputTextApprovedContext, sinceNanoseconds: UInt64, nowNanoseconds: UInt64, policy: CapturePolicy) -> Bool {
        approvalRejection(approval, sinceNanoseconds: sinceNanoseconds, nowNanoseconds: nowNanoseconds, policy: policy) == nil
    }
    public static func canonicalModifiers(_ values: [InputTextModifier]) -> [InputTextModifier] {
        InputTextModifier.allCases.filter { values.contains($0) }
    }
}

/// Pure ordering seam used by the actual native tap and fake-only tests. All
/// readers are synchronous: an event cannot be queued for a later Unicode read.
public enum InputTextReadGate {
    public static func capture(metadata: InputTextEventMetadata, modifiers: [InputTextModifier], policy: CapturePolicy,
                               afterNanoseconds: UInt64, nowNanoseconds: () -> UInt64,
                               safetyProvider: (InputTextSafetyRequest) -> InputTextApprovedContext?,
                               readUnicode: () -> InputTextUnicodeRead,
                               onRejection: (InputTextReadRejection) -> Void = { _ in }) -> InputTextCaptureDecision {
        capture(metadata: metadata, modifiers: modifiers, policy: policy, afterNanoseconds: afterNanoseconds,
                nowNanoseconds: nowNanoseconds, typedSafetyProvider: { request in
                    if let approval = safetyProvider(request) { return .success(approval) }
                    return .failure(.stale)
                }, readUnicode: readUnicode, onRejection: onRejection)
    }
    public static func capture(metadata: InputTextEventMetadata, modifiers: [InputTextModifier], policy: CapturePolicy,
                               afterNanoseconds: UInt64, nowNanoseconds: () -> UInt64,
                               typedSafetyProvider: (InputTextSafetyRequest) -> Result<InputTextApprovedContext, InputTextGapReason>,
                               readUnicode: () -> InputTextUnicodeRead,
                               onRejection: (InputTextReadRejection) -> Void = { _ in }) -> InputTextCaptureDecision {
        func reject(_ stage: InputTextReadRejection.Stage, _ reason: InputTextReadRejection.Reason,
                    _ gap: InputTextGapReason = .stale) -> InputTextCaptureDecision {
            onRejection(.init(stage: stage, reason: reason)); return .gap(gap)
        }
        guard policy.enabled, policy.inputText == true else { return reject(.receive, .policyDisabled, .policyBoundary) }
        let beforeStart = nowNanoseconds()
        if let reason = InputTextLimits.eventRejection(metadata, nowNanoseconds: beforeStart, afterNanoseconds: afterNanoseconds) {
            return reject(.receive, reason)
        }
        let before: InputTextApprovedContext
        switch typedSafetyProvider(.event(metadata)) {
        case .success(let value): before = value
        case .failure(let reason): return reject(.preReadSafety, .safetyUnavailable, reason)
        }
        if let reason = InputTextLimits.approvalRejection(before, sinceNanoseconds: beforeStart, nowNanoseconds: nowNanoseconds(), policy: policy) {
            return reject(.preReadSafety, .approvalNotFresh, reason)
        }
        guard before.context.target.application.processId == metadata.targetProcessId else {
            return reject(.preReadSafety, .targetPidMismatch,
                .processMismatch(expected: metadata.targetProcessId, observed: Int64(before.context.target.application.processId)))
        }
        if let reason = InputTextLimits.eventRejection(metadata, nowNanoseconds: nowNanoseconds(), afterNanoseconds: afterNanoseconds) {
            return reject(.preReadSafety, reason, reason == .eventAgeExceeded ? .verificationTimeout : .stale)
        }
        let canonical = InputTextLimits.canonicalModifiers(modifiers)
        let shortcut = canonical.contains(.command) || canonical.contains(.control)
        // Shortcut evidence never needs Unicode and never reads a clipboard.
        let read: InputTextUnicodeRead = shortcut ? .text("") : readUnicode()
        let afterStart = nowNanoseconds()
        let after: InputTextApprovedContext
        switch typedSafetyProvider(.event(metadata)) {
        case .success(let value): after = value
        case .failure(let reason): return reject(.postReadSafety, .safetyUnavailable, reason)
        }
        if let reason = InputTextLimits.approvalRejection(after, sinceNanoseconds: afterStart, nowNanoseconds: nowNanoseconds(), policy: policy) {
            return reject(.postReadSafety, .approvalNotFresh, reason)
        }
        guard after.context == before.context else {
            return reject(.postReadSafety, .contextChanged, .contextMismatch(before.context, after.context))
        }
        guard after.role == before.role else { return reject(.postReadSafety, .roleChanged) }
        if let reason = InputTextLimits.eventRejection(metadata, nowNanoseconds: nowNanoseconds(), afterNanoseconds: afterNanoseconds) {
            return reject(.postReadSafety, reason, reason == .eventAgeExceeded ? .verificationTimeout : .stale)
        }
        switch read {
        case .unavailable: return reject(.unicodeRead, .unicodeUnavailable, .readError)
        case .saturated: return reject(.unicodeRead, .unicodeSaturated, .budget)
        case .text(let text):
            guard text.utf16.count <= InputTextLimits.codeUnitBudget(policy) else { return reject(.unicodeRead, .unicodeBudget, .budget) }
            let kind: InputTextKind
            let normalized: String
            if shortcut { kind = .shortcut; normalized = "" }
            else if text == "\r" || text == "\n" || text == "\u{3}" { kind = .return; normalized = "" }
            else {
                guard !text.isEmpty else { return .ignored }
                // Unsupported control characters are not invented editing actions.
                guard !text.unicodeScalars.contains(where: { $0.value < 32 || (127...159).contains($0.value) }) else { return .ignored }
                kind = .text; normalized = text
            }
            return .sample(InputTextSample(context: before.context, eventKind: kind, text: normalized,
                modifiers: canonical, callbackTimeMs: metadata.callbackTimeMs))
        }
    }

    /// Pure ordering seam for the original poll and final-drain revalidation.
    /// A failure carries detail only, never any buffered text to commit.
    public static func revalidateBufferedContext(_ expected: InputTextContext, policy: CapturePolicy,
              nowNanoseconds: () -> UInt64,
              typedSafetyProvider: (InputTextSafetyRequest) -> Result<InputTextApprovedContext, InputTextGapReason>,
              onRejection: (InputTextReadRejection.Reason) -> Void = { _ in }) -> Result<InputTextContext, InputTextGapReason> {
        let started = nowNanoseconds()
        let approval: InputTextApprovedContext
        switch typedSafetyProvider(.flush(expected)) {
        case .success(let value): approval = value
        case .failure(let reason): onRejection(.safetyUnavailable); return .failure(reason)
        }
        guard approval.context == expected else {
            // Match precedes the original freshness check. Don't infer a verified
            // target change from an allegedly successful but unvalidated approval.
            onRejection(.contextChanged); return .failure(.stale)
        }
        if let reason = InputTextLimits.approvalRejection(approval, sinceNanoseconds: started, nowNanoseconds: nowNanoseconds(), policy: policy) {
            onRejection(.approvalNotFresh); return .failure(reason)
        }
        return .success(approval.context)
    }

    /// Causal read-barrier drain: revalidates each distinct context once, seals
    /// any buffered pending segment in the verified context without waiting for
    /// the standalone debounce timer, and returns all emissions in order so the
    /// enclosing read cannot publish a later snapshot ahead of earlier keystrokes.
    public static func drainAtBarrier(
        completed: inout [InputTextEmission],
        accumulator: inout InputTextAccumulator,
        nowMs: Int64,
        policy: CapturePolicy,
        nowNanoseconds: () -> UInt64,
        typedSafetyProvider: (InputTextSafetyRequest) -> Result<InputTextApprovedContext, InputTextGapReason>,
        onRejection: (InputTextReadRejection.Reason) -> Void = { _ in }
    ) -> Result<[InputTextEmission], InputTextGapReason> {
        func fail(_ reason: InputTextGapReason) -> Result<[InputTextEmission], InputTextGapReason> {
            accumulator.clear()
            completed.removeAll(keepingCapacity: false)
            return .failure(reason)
        }
        if completed.isEmpty && accumulator.pending == nil { return .success([]) }
        guard completed.allSatisfy(\.isValid) else { return fail(.readError) }
        if let pending = accumulator.pending {
            guard nowMs >= pending.intervalEndMs, nowMs - pending.intervalStartMs <= 5_000 else {
                return fail(.stale)
            }
        }
        var approvedContexts: [InputTextContext] = []
        let candidateContexts = completed.map(\.context) + (accumulator.pending.map { [$0.context] } ?? [])
        for ctx in candidateContexts {
            if approvedContexts.contains(ctx) { continue }
            switch revalidateBufferedContext(
                ctx,
                policy: policy,
                nowNanoseconds: nowNanoseconds,
                typedSafetyProvider: typedSafetyProvider,
                onRejection: onRejection
            ) {
            case .failure(let reason):
                return fail(reason)
            case .success(let approved):
                approvedContexts.append(approved)
            }
        }
        if let pending = accumulator.pending {
            guard approvedContexts.contains(pending.context),
                  let sealed = accumulator.takeAtBarrier(nowMs: nowMs, approvedContext: pending.context),
                  sealed.isValid else {
                return fail(.stale)
            }
            guard completed.count < InputTextLimits.maxPending else {
                return fail(.backpressure)
            }
            completed.append(sealed)
        }
        let drained = completed
        completed.removeAll(keepingCapacity: false)
        return .success(drained)
    }
}

public struct InputTextSample: Equatable {
    public let context: InputTextContext
    public let eventKind: InputTextKind
    public let text: String
    public let modifiers: [InputTextModifier]
    public let callbackTimeMs: Int64
    public init(context: InputTextContext, eventKind: InputTextKind, text: String, modifiers: [InputTextModifier], callbackTimeMs: Int64) {
        self.context = context; self.eventKind = eventKind; self.text = text
        self.modifiers = InputTextLimits.canonicalModifiers(modifiers); self.callbackTimeMs = callbackTimeMs
    }
    fileprivate var isValid: Bool {
        context.isValid && InputTextLimits.integer(callbackTimeMs) && text.utf16.count <= InputTextLimits.maxCodeUnits &&
        (eventKind == .text ? (!text.isEmpty && !modifiers.contains(.command) && !modifiers.contains(.control) &&
            !text.unicodeScalars.contains(where: { $0.value < 32 || (127...159).contains($0.value) })) : text.isEmpty) &&
        (eventKind != .shortcut || modifiers.contains(.command) || modifiers.contains(.control))
    }
}

/// Immutable, bounded, normalized worker IPC data; raw event metadata is absent.
public struct InputTextEmission: Codable, Equatable {
    public let context: InputTextContext
    public let source: InputTextSource
    public let eventKind: InputTextKind
    public let text: String
    public let modifiers: [InputTextModifier]
    public let intervalStartMs: Int64
    public let intervalEndMs: Int64
    public let eventCount: Int
    fileprivate init(sample: InputTextSample, source: InputTextSource, text: String, intervalStartMs: Int64, eventCount: Int) {
        context = sample.context; self.source = source; eventKind = sample.eventKind; self.text = text
        modifiers = sample.modifiers; self.intervalStartMs = intervalStartMs; intervalEndMs = sample.callbackTimeMs; self.eventCount = eventCount
    }
    public var isValid: Bool {
        InputTextSample(context: context, eventKind: eventKind, text: text, modifiers: modifiers, callbackTimeMs: intervalEndMs).isValid &&
        InputTextLimits.integer(intervalStartMs) && intervalEndMs >= intervalStartMs && intervalEndMs - intervalStartMs <= 5_000 &&
        (1...InputTextLimits.maxEvents).contains(eventCount) && modifiers == InputTextLimits.canonicalModifiers(modifiers)
    }
    public func payload() -> JSONValue { .object([
        "kind": .string("input.text"), "source": .string(source.rawValue), "scope": .string("field"),
        "eventKind": .string(eventKind.rawValue), "text": .string(text), "modifiers": .array(modifiers.map { .string($0.rawValue) }),
        "intervalStartMs": j(intervalStartMs), "intervalEndMs": j(intervalEndMs), "eventCount": j(eventCount), "surfaceId": .string(context.surfaceId),
        "gate": .object(["secure": .string(CapturePolicy(fieldSecurity: context.fieldSecurity).contentGateSecure), "privateState": .string(context.privateState.rawValue), "policyRevision": j(context.policyRevision)]),
        "secureInput": .string("inactive"), "effect": .string("unverified"),
        "coverage": .object(["status": .string("partial"), "truncated": .bool(false),
            "missingReasons": .array(["input-events-partial", "event-unicode-not-ime-commit", "effect-unverified", "non-atomic-field-gate"].map(JSONValue.string))]),
    ]) }
}

/// Single bounded buffer. Context changes discard, never flush. Capacity overflow
/// drops the whole unflushed text and reports a gap; it does not claim a redacted
/// prefix or reconstruct text edits, IME commits, paste, submit or app effects.
public struct InputTextAccumulator {
    public private(set) var pending: InputTextEmission?
    private let maxCodeUnits: Int
    public init(maxCodeUnits: Int = InputTextLimits.maxCodeUnits) { self.maxCodeUnits = max(0, min(InputTextLimits.maxCodeUnits, maxCodeUnits)) }
    public mutating func clear() { pending = nil }
    @discardableResult public mutating func add(_ sample: InputTextSample, source: InputTextSource) -> InputTextGapReason? {
        guard sample.isValid else { clear(); return .readError }
        guard sample.text.utf16.count <= maxCodeUnits else { clear(); return .budget }
        if let current = pending {
            guard current.context == sample.context else { clear(); return .stale }
            guard sample.callbackTimeMs >= current.intervalEndMs else { clear(); return .stale }
            guard sample.callbackTimeMs - current.intervalStartMs <= InputTextLimits.maxWaitMs,
                  current.eventCount < InputTextLimits.maxEvents,
                  current.text.utf16.count + sample.text.utf16.count <= maxCodeUnits else { clear(); return .budget }
            guard current.source == source, current.eventKind == sample.eventKind, current.modifiers == sample.modifiers else { clear(); return .stale }
            pending = InputTextEmission(sample: sample, source: source, text: current.text + sample.text,
                intervalStartMs: current.intervalStartMs, eventCount: current.eventCount + 1)
        } else {
            pending = InputTextEmission(sample: sample, source: source, text: sample.text, intervalStartMs: sample.callbackTimeMs, eventCount: 1)
        }
        return nil
    }
    public func isDue(nowMs: Int64) -> Bool {
        guard let pending, nowMs >= pending.intervalEndMs else { return false }
        return nowMs - pending.intervalEndMs >= InputTextLimits.debounceMs || nowMs - pending.intervalStartMs >= InputTextLimits.maxWaitMs
    }
    /// Freshly approved exact context is mandatory, even when the timer fired.
    public mutating func takeDue(nowMs: Int64, approvedContext: InputTextContext?) -> InputTextEmission? {
        guard let current = pending else { return nil }
        guard current.context == approvedContext, nowMs >= current.intervalEndMs, nowMs - current.intervalStartMs <= 5_000 else { clear(); return nil }
        guard isDue(nowMs: nowMs) else { return nil }
        clear(); return current
    }
    /// Causal barrier flush: seals the pending buffer for a freshly approved
    /// context at snapshot drain time without waiting for the standalone debounce.
    public mutating func takeAtBarrier(nowMs: Int64, approvedContext: InputTextContext?) -> InputTextEmission? {
        guard let current = pending else { return nil }
        guard current.context == approvedContext, nowMs >= current.intervalEndMs, nowMs - current.intervalStartMs <= 5_000 else { clear(); return nil }
        clear(); return current
    }
    /// Segmentation within one safe context (e.g. text then Return) is not a
    /// lifecycle boundary. Caller has just revalidated that same exact context.
    public mutating func takeSegment(approvedContext: InputTextContext) -> InputTextEmission? {
        guard pending?.context == approvedContext else { clear(); return nil }
        let result = pending; clear(); return result
    }
}

import Foundation
import AccessContract

public enum DesktopStatus: String { case unlocked, locked, unknown }
public enum SecureStatus: String { case safe, notDeclaredSensitive = "not-declared-sensitive", sensitive, unknown }

public struct CapturePolicy: Codable, Equatable {
    public var enabled: Bool
    /// Absent in older policies; only an explicit true enables coarse input metrics.
    public var inputActivity: Bool?
    /// Omission preserves the original bounded focused-field prefix scope.
    public var textRange: String?
    /// Delay after a read completes; absent policies retain the native default.
    public var sampleIntervalMs: Int?
    public var allowedApplicationIds: [String]
    public var applicationScope: String?
    public var excludedApplicationIds: [String]?
    public var allowBrowserContent: Bool?
    public var axCompatibility: Bool?
    public var textMarkers: Bool?
    public var captureScope: String?
    public var maxTreeNodes: Int?
    public var inputText: Bool?
    public var selectionCapture: Bool?
    /// Omission preserves legacy strict field classification; denylist is explicit.
    public var fieldSecurity: String?
    public var maxTextCodeUnits: Int
    public var maxPending: Int
    public var debounceMs: Int
    public var maxWaitMs: Int
    public var readTimeoutMs: Int

    public init(_ json: JSONValue) throws {
        self = try JSONDecoder().decode(Self.self, from: json.canonicalData())
    }
    public init(enabled: Bool = true, inputActivity: Bool? = false, textRange: String? = nil, sampleIntervalMs: Int? = nil, allowedApplicationIds: [String] = ["test.allowed"], maxTextCodeUnits: Int = 128, maxPending: Int = 8, debounceMs: Int = 10, maxWaitMs: Int = 50, readTimeoutMs: Int = 200, applicationScope: String? = nil, excludedApplicationIds: [String]? = nil, allowBrowserContent: Bool? = nil, axCompatibility: Bool? = nil, textMarkers: Bool? = nil, captureScope: String? = nil, maxTreeNodes: Int? = nil, inputText: Bool? = nil, selectionCapture: Bool? = nil, fieldSecurity: String? = nil) {
        self.enabled = enabled; self.inputActivity = inputActivity; self.textRange = textRange; self.sampleIntervalMs = sampleIntervalMs
        self.allowedApplicationIds = allowedApplicationIds
        self.applicationScope = applicationScope; self.excludedApplicationIds = excludedApplicationIds
        self.allowBrowserContent = allowBrowserContent; self.axCompatibility = axCompatibility; self.textMarkers = textMarkers
        self.captureScope = captureScope; self.maxTreeNodes = maxTreeNodes; self.inputText = inputText; self.selectionCapture = selectionCapture
        self.fieldSecurity = fieldSecurity
        self.maxTextCodeUnits = maxTextCodeUnits; self.maxPending = maxPending
        self.debounceMs = debounceMs; self.maxWaitMs = maxWaitMs; self.readTimeoutMs = readTimeoutMs
    }
    /// Also checked at the one-shot worker boundary, which decodes its private
    /// ticket rather than the public Configure schema. Unknown scopes never widen.
    public var hasValidTextSettings: Bool {
        (textRange == nil || textRange == "prefix" || textRange == "visible") &&
            (sampleIntervalMs == nil || (1_000...30_000).contains(sampleIntervalMs!)) &&
            (applicationScope == nil || ["allowlist", "denylist"].contains(applicationScope!)) &&
            (captureScope == nil || ["focused", "region", "window"].contains(captureScope!)) &&
            (fieldSecurity == nil || ["strict", "denylist"].contains(fieldSecurity!)) &&
            (maxTreeNodes == nil || (1...96).contains(maxTreeNodes!))
    }
    public var fieldSecurityMode: String { fieldSecurity ?? "strict" }
    /// Central permission decision: provider failures never become absence.
    public func allows(_ status: SecureStatus) -> Bool {
        guard ["strict", "denylist"].contains(fieldSecurityMode) else { return false }
        return status == .safe || (fieldSecurityMode == "denylist" && status == .notDeclaredSensitive)
    }
    /// Uniform conservative evidence, including ordinary fields under denylist.
    public var contentGateSecure: String { fieldSecurityMode == "denylist" ? SecureStatus.notDeclaredSensitive.rawValue : SecureStatus.safe.rawValue }
    public var usesSessionWorker: Bool {
        axCompatibility == true || textMarkers == true || inputText == true || selectionCapture == true || (captureScope != nil && captureScope != "focused")
    }
}

/// Shared native policy gate. Mandatory families and System UI overlays cannot
/// be opted back in; matching uses a dot boundary, never substrings.
public enum ApplicationPolicy {
    public static let mandatoryDeniedFamilies: [String] = [
        "com.1password",
        "com.agilebits.onepassword",
        "com.agilebits.onepassword7",
        "com.agilebits.onepassword-osx",
        "com.apple.safari",
        "com.apple.passwords",
        "com.apple.keychainaccess",
        "com.bitwarden.desktop",
        "com.dashlane.dashlanephonefinal",
        "com.lastpass.lastpass",
        "com.nordsec.nordpass",
        "me.proton.pass",
    ]

    public static let systemUIFamilies: [String] = [
        "com.apple.windowmanager",
        "com.apple.controlcenter",
        "com.apple.notificationcenterui",
        "com.apple.securityagent",
        "com.apple.localauthentication.uiagent",
        "com.apple.localauthenticationremoteservice",
        "com.apple.loginwindow",
        "com.apple.usernotificationcenter",
    ]

    private static func matchesFamily(_ value: String, family: String) -> Bool {
        value == family || value.hasPrefix(family + ".")
    }

    public static func isMandatoryDenied(_ id: String) -> Bool {
        let value = id.lowercased()
        return mandatoryDeniedFamilies.contains { matchesFamily(value, family: $0) }
    }

    public static func isSystemUI(_ id: String) -> Bool {
        let value = id.lowercased()
        return systemUIFamilies.contains { matchesFamily(value, family: $0) }
    }

    public static func allows(_ id: String, policy: CapturePolicy) -> Bool {
        guard policy.enabled, !id.isEmpty, !isMandatoryDenied(id), !isSystemUI(id) else { return false }
        let value = id.lowercased()
        if (policy.excludedApplicationIds ?? []).contains(where: { matchesFamily(value, family: $0.lowercased()) }) { return false }
        if policy.applicationScope == "denylist" { return true }
        guard policy.applicationScope == nil || policy.applicationScope == "allowlist" else { return false }
        return policy.allowedApplicationIds.contains { $0.lowercased() == value }
    }
    public static func allows(applicationId: String, policy: CapturePolicy) -> Bool { allows(applicationId, policy: policy) }
}


public struct ApplicationIdentity: Codable, Equatable {
    public var applicationId: String
    public var processId: Int32
    public var processStartTime: String
    public init(applicationId: String, processId: Int32, processStartTime: String) {
        self.applicationId = applicationId; self.processId = processId; self.processStartTime = processStartTime
    }
}

/// An AppKit activation notification's identity is retained; it is not replaced
/// with a later current application. Reconciliation requests deliberately have no hint.
public struct SourceHint: Codable, Equatable {
    public var application: ApplicationIdentity
    public var eventTimeMs: Int64
    public init(application: ApplicationIdentity, eventTimeMs: Int64) {
        self.application = application; self.eventTimeMs = eventTimeMs
    }
}

public struct ReadTicket: Codable, Equatable {
    public var token: String
    public var policyRevision: Int64
    public var captureEpoch: Int64
    public var policy: CapturePolicy
    public var hint: SourceHint?
    public var deadlineMonotonicMs: Int64
    public var deviceId: String
    public var osSessionId: String
    public var desktopId: String
    public var foregroundGeneration: Int64? = nil
    public var focusGeneration: Int64? = nil
    /// Local diagnostic correlation only; omitted by old internal DTOs and never
    /// copied to public observations, content gates or persistent evidence.
    public var debugRequestId: Int64? = nil
    /// Recovery never replays an AX compatibility setting write with an unknown
    /// outcome. The next worker may inspect but not change the app's settings.
    public var readOnlyAXEnablement: Bool? = nil
    /// When true, read focused field + pending input only, skipping selection and surface tree.
    public var focusedFastOnly: Bool? = nil
}

public struct TextRead: Codable, Equatable {
    public var text: String
    public var source: String
    public var totalLength: Int?
    public var selection: TextSelection?
    public var rangeStart: Int
    public var rangeBasis: String
    public var complete: Bool
    public var truncated: Bool
    public var missingReasons: [String]
    /// Worker-internal accounting of returned UTF-16, including discarded probe
    /// prefixes. Never exported as a text-evidence field or refunded by selection.
    public var readUnits: Int?
    public var chargedUnits: Int { max(text.utf16.count, readUnits ?? 0) }
    public init(text: String, source: String, totalLength: Int?, selection: TextSelection? = nil, rangeStart: Int = 0, rangeBasis: String = "prefix", complete: Bool, truncated: Bool? = nil, missingReasons: [String], readUnits: Int? = nil) {
        self.text = text; self.source = source; self.totalLength = totalLength; self.selection = selection
        self.rangeStart = rangeStart; self.rangeBasis = rangeBasis
        self.complete = complete; self.truncated = truncated ?? !complete; self.missingReasons = missingReasons
        self.readUnits = readUnits
    }
}
public struct TextSelection: Codable, Equatable {
    public var start: Int
    public var length: Int
    public init(start: Int, length: Int) { self.start = start; self.length = length }
}
/// Pure bounded slicing for the synthetic provider: never fabricate replacement
/// glyphs when a requested UTF-16 boundary bisects a surrogate pair.
public func boundedUTF16Slice(_ text: String, start: Int, length: Int) -> String? {
    let units = Array(text.utf16)
    guard start >= 0, length >= 0, start <= units.count, length <= units.count - start else { return nil }
    guard start == units.count || !(0xDC00...0xDFFF).contains(units[start]) else { return nil }
    var end = start + length
    if end > start && (0xD800...0xDBFF).contains(units[end - 1]) { end -= 1 }
    return String(decoding: units[start..<end], as: UTF16.self)
}

/// Fixed vocabulary only: no provider strings, field content or identifying metadata.
/// Unknown wire values fail decoding instead of reaching a public gap.
public struct ReadDiagnostic: Codable, Equatable {
    public enum Code: String, Codable, CaseIterable {
        case applicationNotAllowed = "application-not-allowed"
        case applicationUnavailable = "application-unavailable"
        case browserExcluded = "browser-excluded"
        case focusedFieldUnavailable = "focused-field-unavailable"
        case focusedRoleNotText = "focused-role-not-text"
        case secureField = "secure-field"
        case fieldSecurityUnknown = "field-security-unknown"
        case visibleRangeUnavailable = "visible-range-unavailable"
        case textReadUnavailable = "text-read-unavailable"
        case textResultInvalid = "text-result-invalid"
        case focusChanged = "focus-changed"
        case invalidSamplingPolicy = "invalid-sampling-policy"
        case readDeadline = "read-deadline"
        case inputContextUnverified = "input-context-unverified"
        case inputTargetMismatch = "input-target-mismatch"
        case inputRoleNotEditable = "input-role-not-editable"
        case inputVerificationTimeout = "input-verification-timeout"
        case inputFieldSecurityUnknown = "input-field-security-unknown"
        case inputTextBudget = "input-text-budget"
        case inputTextBackpressure = "input-text-backpressure"
        case inputTextReadUnavailable = "input-text-read-unavailable"
        case inputPolicyBoundary = "input-policy-boundary"
        case captureAuthorityChanged = "capture-authority-changed"
        case workerRetirementPending = "worker-retirement-pending"
        case accessibilityDenied = "accessibility-denied"
        case desktopUnavailable = "desktop-unavailable"
        case surfaceNotStartedBudget = "surface-not-started-budget"
        case surfaceCallBudget = "surface-call-budget"
        case surfaceTimeBudget = "surface-time-budget"
        case surfaceAnchorUnavailable = "surface-anchor-unavailable"
        case surfaceBoundaryUnverified = "surface-boundary-unverified"
        case surfaceBoundaryMismatch = "surface-boundary-mismatch"
        case surfaceBoundaryAXFailed = "surface-boundary-ax-failed"
        case surfaceBoundaryIncomplete = "surface-boundary-incomplete"
        case surfaceSecurityExcluded = "surface-security-excluded"
        case surfaceProviderUnavailable = "surface-provider-unavailable"
    }
    public enum Role: String, Codable, CaseIterable {
        case textField = "AXTextField"
        case textArea = "AXTextArea"
        case staticText = "AXStaticText"
        case secureTextField = "AXSecureTextField"
        case menuItem = "AXMenuItem"
        case menu = "AXMenu"
        case webArea = "AXWebArea"
        case group = "AXGroup"
        case button = "AXButton"
        case other, unavailable

        public init(normalizing role: String?) {
            self = role.map { Role(rawValue: $0) ?? .other } ?? .unavailable
        }
    }
    public var code: Code
    public var role: Role?
    public init(code: Code, role: Role? = nil) { self.code = code; self.role = role }
    public var json: JSONValue {
        var value: [String: JSONValue] = ["code": .string(code.rawValue)]
        if let role { value["role"] = .string(role.rawValue) }
        return .object(value)
    }
}

public struct ReadResult: Codable {
    public var token: String
    public var application: ApplicationIdentity?
    /// Current read-attempt provider only. Never a content/identity admission permit.
    public var diagnosticApplication: ApplicationIdentity? = nil
    public var text: TextRead?
    public var reason: String?
    public var diagnostic: ReadDiagnostic?
    public var enablement: AXEnablementResult? = nil
    public var sessionIdentity: WorkerSurfaceIdentity? = nil
    public var surface: SurfaceReadResult? = nil
    public var selection: SelectionReadResult? = nil
    public var inputRecords: [InputTextEmission]? = nil
    public var inputGaps: [String]? = nil
    public var privateState: String? = nil
    public var observerStatus: String? = nil
    /// Explicitly observed AX focus absence; never inferred from failed queries.
    /// This private worker marker authorizes no field, selection or input channel.
    public var focusAbsent: Bool? = nil
    /// Only an actually requested, unsuccessful surface attempt reports this.
    /// Independent focused text can still succeed; geometry-only gaps stay coverage.
    public var surfaceFailure: SurfaceReadFailure? = nil
    /// One eligibility predicate is shared by no-focus admission and actual
    /// surface emission, so an identity-only reply cannot masquerade as a surface.
    public func validSurface(policy: CapturePolicy) -> Bool {
        guard let sessionIdentity, let surface, policy.captureScope == surface.scope,
              surface.surfaceId == sessionIdentity.surfaceId,
              surface.nodes.count <= (policy.maxTreeNodes ?? 64), surface.nodes.count <= 96,
              surface.nodes.allSatisfy({ $0.observedAtMs >= captureStartMs && $0.observedAtMs <= captureEndMs }) else { return false }
        var remaining = min(8192, max(0, policy.maxTextCodeUnits))
        for node in surface.nodes {
            let units = node.text?.utf16.count ?? 0
            guard units <= remaining else { return false }; remaining -= units
        }
        return true
    }
    public func validWindowOnlyChannels(policy: CapturePolicy) -> Bool {
        guard focusAbsent == true else { return true }
        guard policy.captureScope == "window", reason == nil, surfaceFailure == nil,
              diagnostic?.code == .focusedFieldUnavailable,
              text == nil, selection == nil, (inputRecords ?? []).isEmpty,
              validSurface(policy: policy), let surface, surface.scope == "window",
              !surface.nodes.isEmpty, surface.nodes.allSatisfy({ $0.focused != true }) else { return false }
        return true
    }
    public var captureStartMs: Int64
    public var captureEndMs: Int64
    public init(token: String, application: ApplicationIdentity? = nil, text: TextRead? = nil, reason: String? = nil, diagnostic: ReadDiagnostic? = nil, captureStartMs: Int64, captureEndMs: Int64) {
        self.token = token; self.application = application; self.text = text; self.reason = reason; self.diagnostic = diagnostic
        self.captureStartMs = captureStartMs; self.captureEndMs = captureEndMs
    }
}

public protocol CollectorClock: AnyObject {
    var monotonicMs: Int64 { get }
    var unixMs: Int64 { get }
}
public final class SystemCollectorClock: CollectorClock {
    public init() {}
    public var monotonicMs: Int64 { Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000) }
    public var unixMs: Int64 { Int64(Date().timeIntervalSince1970 * 1_000) }
}

/// Ownership result from the private transport, not debug output or a child reply.
public enum ReadTimeoutCleanup: Equatable { case awaitingExit, reaped, unconfirmed, ineligible }

public protocol CollectorEnvironment: AnyObject {
    var desktopReason: String { get }
    /// Result of the same fresh native validation; never a cached content permit.
    var secureInputBlocked: Bool { get }
    /// Called only after an enabled configure ACK followed by start/resume.
    func beginMonitoring() -> (desktop: DesktopStatus, accessibility: Bool)
    /// Fresh check at result acceptance, not the prior poll or worker snapshot.
    func validateBeforeAccept() -> (desktop: DesktopStatus, accessibility: Bool)
    func endMonitoring()
    var inputActivityReason: String { get }
    /// Non-prompting permission check, including before a temporary block clears.
    func inputMonitoringGranted() -> Bool
    /// An owned start/resume, or its deferred first setup after Secure Input,
    /// may create a listener. Never recreate a failed tap or prompt/post events.
    func beginInputActivity(policy: CapturePolicy) -> Bool
    func endInputActivity()
    func clearInputActivity()
    /// Fresh post-gate for the exact app identity frozen in a completed bucket.
    func validateInputActivity(application: ApplicationIdentity) -> Bool
    func configurePolicy(_ policy: CapturePolicy)
    func launch(_ ticket: ReadTicket)
    /// Must kill and reap any outstanding worker before returning.
    func cancelRead()
    /// App boundary only: input-bearing sessions require a healthy retirement ACK.
    func retireRead()
    /// Exact delivered, still-owned active ticket only. Seal its pipes first,
    /// then terminate without waiting on provider code. No output may be replayed.
    func abortTimedOutRead(_ ticket: ReadTicket) -> ReadTimeoutCleanup
    func timedOutReadCleanup() -> ReadTimeoutCleanup
    /// Read-only check of the existing coarse listener; never creates a new tap.
    var inputActivityHealthy: Bool { get }
    func readyForRead() -> Bool
}

public extension CollectorEnvironment {
    var desktopReason: String { "desktop-unavailable" }
    var secureInputBlocked: Bool { false }
    func configurePolicy(_ policy: CapturePolicy) {}
    func retireRead() { cancelRead() }
    func abortTimedOutRead(_ ticket: ReadTicket) -> ReadTimeoutCleanup { .ineligible }
    func timedOutReadCleanup() -> ReadTimeoutCleanup { .ineligible }
    var inputActivityHealthy: Bool { false }
    func readyForRead() -> Bool { true }
    var inputActivityReason: String { "input-monitoring-unavailable" }
    func inputMonitoringGranted() -> Bool { false }
    func beginInputActivity(policy: CapturePolicy) -> Bool { false }
    func endInputActivity() {}
    func clearInputActivity() {}
    func validateInputActivity(application: ApplicationIdentity) -> Bool { false }
}

public func j(_ value: Int64) -> JSONValue { .number(Double(value)) }
public func j(_ value: Int) -> JSONValue { .number(Double(value)) }
public func textRange(start: Int = 0, length: Int) -> JSONValue {
    .object(["unit": .string("utf16"), "start": j(start), "length": j(length)])
}

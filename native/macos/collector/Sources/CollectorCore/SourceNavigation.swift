import Foundation
import AccessContract

/// One-shot application activation protocol.
public enum SourceNavigationReason: String, CaseIterable, Codable, Error {
    case activated
    case invalidRequest = "invalid-request"
    case inputTooLarge = "input-too-large"
    case inputTimeout = "input-timeout"
    case inputUnavailable = "input-unavailable"
    case parentUnavailable = "parent-unavailable"
    case deadlineExceeded = "deadline-exceeded"
    case sessionUnavailable = "session-unavailable"
    case sessionMismatch = "session-mismatch"
    case desktopUnavailable = "desktop-unavailable"
    case applicationUnavailable = "application-unavailable"
    case applicationMismatch = "application-mismatch"
    case applicationBlocked = "application-blocked"
    case activationRejected = "activation-rejected"
    case activationUnconfirmed = "activation-unconfirmed"
    case postconditionChanged = "postcondition-changed"
    case internalError = "internal-error"
}

public enum SourceNavigationOutcome: String, Codable {
    case activated
    case refused
    case uncertain
}

public struct SourceNavigationReceipt: Encodable, Equatable {
    public let version = 1
    public let outcome: SourceNavigationOutcome
    public let reason: SourceNavigationReason
    public let captured = false
    public let launched = false
    public static let maximumOutputBytes = 1_024

    public init(reason: SourceNavigationReason, afterDispatch: Bool = false) {
        self.reason = reason
        switch reason {
        case .activated:
            outcome = .activated
        case .activationRejected, .activationUnconfirmed, .postconditionChanged:
            outcome = .uncertain
        case .parentUnavailable, .deadlineExceeded:
            outcome = afterDispatch ? .uncertain : .refused
        default:
            outcome = .refused
        }
    }

    public func encodedLine() -> Data {
        Data(("{\"version\":1,\"outcome\":\"" + outcome.rawValue + "\",\"reason\":\"" + reason.rawValue +
              "\",\"captured\":false,\"launched\":false}\n").utf8)
    }

    public var exitCode: Int32 {
        switch reason {
        case .invalidRequest, .inputTooLarge: return 64
        case .internalError: return 70
        case .inputUnavailable: return 74
        case .inputTimeout, .parentUnavailable, .deadlineExceeded: return 75
        default: return 0
        }
    }
}

public struct SourceNavigationRequest: Equatable {
    public static let maximumInputBytes = 2_048
    private static let requiredKeys: Set<String> = [
        "version", "applicationId", "processId", "processStartTime", "osSessionId", "desktopId"
    ]

    public let applicationId: String
    public let processId: Int32
    public let processStartTime: String
    public let osSessionId: String
    public let desktopId: String
    public let auditSessionId: UInt32

    public var application: ApplicationIdentity {
        ApplicationIdentity(applicationId: applicationId, processId: processId, processStartTime: processStartTime)
    }

    public static func acceptsArguments(_ arguments: [String]) -> Bool {
        arguments == ["--navigate-source"]
    }

    public static func parse(_ data: Data) throws -> Self {
        guard data.count <= maximumInputBytes else { throw SourceNavigationReason.inputTooLarge }
        guard !data.isEmpty,
              let root = try? JSONValue.parse(data),
              let fields = root.objectValue,
              Set(fields.keys) == requiredKeys,
              data.filter({ $0 == 0x2c }).count == requiredKeys.count - 1,
              fields["version"] == .number(1),
              let rawProcess = fields["processId"]?.numberValue,
              rawProcess.isFinite,
              rawProcess.rounded(.towardZero) == rawProcess,
              rawProcess >= 2,
              rawProcess <= Double(Int32.max),
              let application = fields["applicationId"]?.stringValue,
              !application.isEmpty,
              application.utf8.count <= 256,
              application.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]*$", options: .regularExpression) == application.startIndex..<application.endIndex,
              let birth = fields["processStartTime"]?.stringValue,
              validBirth(birth),
              let session = fields["osSessionId"]?.stringValue,
              session.hasPrefix("audit-"),
              let audit = UInt32(session.dropFirst(6)),
              audit != UInt32.max,
              session == "audit-" + String(audit),
              let desktop = fields["desktopId"]?.stringValue,
              desktop == "console-" + session else {
            throw SourceNavigationReason.invalidRequest
        }
        return Self(
            applicationId: application,
            processId: Int32(rawProcess),
            processStartTime: birth,
            osSessionId: session,
            desktopId: desktop,
            auditSessionId: audit
        )
    }

    private static func validBirth(_ value: String) -> Bool {
        guard value.hasPrefix("unix-ms:"), value.utf8.count <= 40 else { return false }
        let parts = value.dropFirst(8).split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, parts[0].count <= 16, parts[1].count == 3,
              parts.allSatisfy({ $0.utf8.allSatisfy { (48...57).contains($0) } }),
              parts[0].count == 1 || parts[0].first != "0",
              let number = Double(value.dropFirst(8)), number.isFinite, number > 0, number <= 9_007_199_254_740_991 else {
            return false
        }
        return true
    }
}

public struct SourceNavigationSessionEvidence {
    public let userId: UInt32
    public let effectiveUserId: UInt32
    public let auditSessionId: UInt32?
    public let consoleUserId: UInt32?
    public let consoleAuditSessionId: UInt32?
    public let desktop: DesktopStatus

    public init(
        userId: UInt32,
        effectiveUserId: UInt32,
        auditSessionId: UInt32?,
        consoleUserId: UInt32?,
        consoleAuditSessionId: UInt32?,
        desktop: DesktopStatus
    ) {
        self.userId = userId
        self.effectiveUserId = effectiveUserId
        self.auditSessionId = auditSessionId
        self.consoleUserId = consoleUserId
        self.consoleAuditSessionId = consoleAuditSessionId
        self.desktop = desktop
    }
}

public struct SourceNavigationApplicationEvidence {
    public let identity: ApplicationIdentity
    public let permittedNonBrowser: Bool

    public init(identity: ApplicationIdentity, permittedNonBrowser: Bool) {
        self.identity = identity
        self.permittedNonBrowser = permittedNonBrowser
    }
}

public enum SourceNavigationGate {
    public static func session(_ request: SourceNavigationRequest, _ evidence: SourceNavigationSessionEvidence) -> SourceNavigationReason? {
        guard let audit = evidence.auditSessionId, audit != UInt32.max,
              let consoleUser = evidence.consoleUserId, let consoleAudit = evidence.consoleAuditSessionId else {
            return .sessionUnavailable
        }
        guard evidence.userId == evidence.effectiveUserId, consoleUser == evidence.userId,
              consoleAudit == audit, request.auditSessionId == audit else {
            return .sessionMismatch
        }
        guard evidence.desktop == .unlocked else { return .desktopUnavailable }
        return nil
    }

    public static func application(_ request: SourceNavigationRequest, _ evidence: SourceNavigationApplicationEvidence?) -> SourceNavigationReason? {
        guard let evidence else { return .applicationUnavailable }
        guard evidence.identity == request.application else { return .applicationMismatch }
        guard evidence.permittedNonBrowser else { return .applicationBlocked }
        return nil
    }
}

public enum SourceNavigationDispatch {
    case notDispatched(SourceNavigationReason)
    case submitted(accepted: Bool)
}

public protocol SourceNavigationProvider {
    func sessionEvidence() -> SourceNavigationSessionEvidence
    func runningApplication(processId: Int32) -> SourceNavigationApplicationEvidence?
    func activate(_ request: SourceNavigationRequest, markDispatched: () -> SourceNavigationReason?) -> SourceNavigationDispatch
    func frontmostApplication() -> SourceNavigationApplicationEvidence?
}

public enum SourceNavigation {
    public static func navigate(
        _ request: SourceNavigationRequest,
        provider: SourceNavigationProvider,
        markDispatched: () -> SourceNavigationReason? = { nil }
    ) -> SourceNavigationReceipt {
        if let reason = SourceNavigationGate.session(request, provider.sessionEvidence()) {
            return SourceNavigationReceipt(reason: reason)
        }
        if let reason = SourceNavigationGate.application(request, provider.runningApplication(processId: request.processId)) {
            return SourceNavigationReceipt(reason: reason)
        }
        switch provider.activate(request, markDispatched: markDispatched) {
        case .notDispatched(let reason):
            let allowed: [SourceNavigationReason] = [
                .parentUnavailable, .deadlineExceeded, .sessionUnavailable, .sessionMismatch,
                .desktopUnavailable, .applicationUnavailable, .applicationMismatch, .applicationBlocked, .internalError,
            ]
            return SourceNavigationReceipt(reason: allowed.contains(reason) ? reason : .internalError)
        case .submitted(accepted: false):
            return SourceNavigationReceipt(reason: .activationRejected)
        case .submitted(accepted: true):
            break
        }
        // NSRunningApplication.activate returns dispatch acceptance, not guaranteed focus shift; verify postconditions once.
        guard SourceNavigationGate.session(request, provider.sessionEvidence()) == nil,
              SourceNavigationGate.application(request, provider.runningApplication(processId: request.processId)) == nil else {
            return SourceNavigationReceipt(reason: .postconditionChanged)
        }
        guard SourceNavigationGate.application(request, provider.frontmostApplication()) == nil else {
            return SourceNavigationReceipt(reason: .activationUnconfirmed)
        }
        guard SourceNavigationGate.application(request, provider.runningApplication(processId: request.processId)) == nil,
              SourceNavigationGate.session(request, provider.sessionEvidence()) == nil else {
            return SourceNavigationReceipt(reason: .postconditionChanged)
        }
        return SourceNavigationReceipt(reason: .activated)
    }
}

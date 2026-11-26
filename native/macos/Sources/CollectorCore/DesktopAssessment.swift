import Foundation

/// Only fixed, non-content fields may leave the native process for onboarding.
public struct DesktopAssessment: Codable, Equatable {
    public let status: String
    public let reason: String
    public let sessionAvailable: Bool
    public let onConsole: Bool?
    public let loginDone: Bool?
    public let screenLocked: Bool?
    public let consoleLocked: Bool?
    public let registryScreenLocked: Bool?
    public let registrySessionMatched: Bool
    public let sessionMatchesProcess: Bool
    public let sessionStable: Bool
    public let signalsValid: Bool
    public let lockTransition: Bool
    public let lockSource: String

    public init(sessionAvailable: Bool, onConsole: Bool?, loginDone: Bool?, screenLocked: Bool?,
                consoleLocked: Bool? = nil, registryScreenLocked: Bool? = nil,
                registrySessionMatched: Bool = false, sessionMatchesProcess: Bool = true,
                sessionStable: Bool = true, signalsValid: Bool = true, lockTransition: Bool = false, secureInputMarker: Bool = false) {
        self.sessionAvailable = sessionAvailable
        self.onConsole = onConsole; self.loginDone = loginDone; self.screenLocked = screenLocked
        self.consoleLocked = consoleLocked; self.registryScreenLocked = registryScreenLocked
        self.registrySessionMatched = registrySessionMatched; self.sessionMatchesProcess = sessionMatchesProcess
        self.sessionStable = sessionStable; self.signalsValid = signalsValid; self.lockTransition = lockTransition || secureInputMarker
        // Any positive lock indication wins, including console sleep/boot lock.
        let locked = screenLocked == true || registryScreenLocked == true || consoleLocked == true
        let source = screenLocked == false ? "cg-session" : registryScreenLocked == false && registrySessionMatched ? "io-session" :
            consoleLocked == false && registrySessionMatched ? "io-console-compat" : "unknown"
        lockSource = locked ? "locked-signal" : source
        if locked { status = "locked"; reason = "screen-locked" }
        else if !sessionAvailable { status = "unknown"; reason = "session-unavailable" }
        else if !signalsValid { status = "unknown"; reason = "desktop-signal-invalid" }
        else if !sessionStable { status = "unknown"; reason = "desktop-session-changed" }
        else if !sessionMatchesProcess { status = "unknown"; reason = "desktop-session-mismatch" }
        else if onConsole != true { status = "unknown"; reason = "console-unavailable" }
        else if loginDone != true { status = "unknown"; reason = "login-incomplete" }
        else if lockTransition { status = "unknown"; reason = "desktop-lock-transition" }
        else if source == "unknown" { status = "unknown"; reason = "lock-state-unavailable" }
        else if secureInputMarker { status = "unknown"; reason = "secure-input-indicated" }
        else { status = "unlocked"; reason = source == "io-console-compat" ? "ready-console-compat" : "ready" }
    }
    public var desktopStatus: DesktopStatus { DesktopStatus(rawValue: status) ?? .unknown }
    /// Only a fully verified desktop with a Secure Input marker and no lock-time
    /// or other unsafe evidence may recover without an owner resume.
    public var isSecureInputOnly: Bool { reason == "secure-input-indicated" }
}

/// Lock/sleep/session boundaries stay sticky until explicit start/resume.
/// Secure Input alone blocks this sample but does not latch a desktop lock.
public struct DesktopBoundaryLatch {
    public private(set) var isLatched = false
    public init() {}
    public mutating func block() { isLatched = true }
    public mutating func resetForUserAction() { isLatched = false }
    public mutating func observe(_ value: DesktopAssessment) -> DesktopStatus {
        // Also latch when sessionAvailable is false to prevent 4Hz SkyLight polling
        // if WindowServer crashes while the collector stays alive (an extreme edge
        // case that does not occur under normal desktop operation).
        if value.desktopStatus == .locked || !value.sessionAvailable || (value.lockTransition && !value.isSecureInputOnly) {
            isLatched = true
        }
        return isLatched ? (value.desktopStatus == .locked ? .locked : .unknown) : value.desktopStatus
    }
}

/// Separate from serve/worker: an onboarding click cannot become a capture request.
public enum PermissionAction: String, Codable {
    case check
    case requestAccessibility = "request-accessibility"
    case openAccessibilitySettings = "open-accessibility-settings"
    case requestInputMonitoring = "request-input-monitoring"
    case openInputMonitoringSettings = "open-input-monitoring-settings"
    public static func parse(_ args: [String]) -> PermissionAction? {
        guard args.count == 2, args[0] == "--permissions" else { return nil }
        return PermissionAction(rawValue: args[1])
    }
}

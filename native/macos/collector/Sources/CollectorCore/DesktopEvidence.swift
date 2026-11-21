import Foundation
import CoreFoundation

/// Private OS dictionaries are projected immediately; no usernames or raw values
/// are emitted, cached, or persisted. Boolean types are never loosely coerced.
public struct DesktopSessionEvidence: Equatable {
    public let available: Bool
    public let uid: UInt32?
    public let audit: UInt32?
    public let onConsole: Bool?
    public let loginDone: Bool?
    public let screenLocked: Bool?
    public let transition: Bool
    /// Presence only: no PID value is exposed, and this is not an API-active claim.
    public let secureInputMarker: Bool
    public let lockTimeMarker: Bool
    public let valid: Bool

    public init(_ dictionary: [String: Any]?) {
        available = dictionary != nil
        uid = Self.number(dictionary?["kCGSSessionUserIDKey"])
        audit = Self.number(dictionary?["kCGSSessionAuditIDKey"])
        onConsole = Self.boolean(dictionary?["kCGSSessionOnConsoleKey"])
        loginDone = Self.boolean(dictionary?["kCGSessionLoginDoneKey"])
        screenLocked = Self.boolean(dictionary?["CGSSessionScreenIsLocked"])
        secureInputMarker = dictionary?["kCGSSessionSecureInputPID"] != nil
        lockTimeMarker = dictionary?["CGSSessionScreenLockedTime"] != nil
        transition = lockTimeMarker || secureInputMarker
        valid = ["kCGSSessionOnConsoleKey", "kCGSessionLoginDoneKey", "CGSSessionScreenIsLocked"].allSatisfy { key in
            dictionary?[key] == nil || Self.boolean(dictionary?[key]) != nil
        } && ["kCGSSessionUserIDKey", "kCGSSessionAuditIDKey"].allSatisfy { key in
            dictionary?[key] == nil || Self.number(dictionary?[key]) != nil
        }
    }
    /// Secure Input appearing/disappearing is not a graphical identity change.
    /// Every other projected desktop/security field must still match exactly.
    public func sameDesktop(as other: Self) -> Bool {
        available == other.available && uid == other.uid && audit == other.audit &&
            onConsole == other.onConsole && loginDone == other.loginDone &&
            screenLocked == other.screenLocked && lockTimeMarker == other.lockTimeMarker && valid == other.valid
    }
    public static func boolean(_ value: Any?) -> Bool? {
        guard let value, CFGetTypeID(value as CFTypeRef) == CFBooleanGetTypeID(), let number = value as? NSNumber else { return nil }
        return number.boolValue
    }
    public static func number(_ value: Any?) -> UInt32? {
        guard let value, CFGetTypeID(value as CFTypeRef) == CFNumberGetTypeID(), let number = value as? NSNumber,
              number.doubleValue.isFinite, number.doubleValue >= 0, number.doubleValue <= Double(UInt32.max),
              number.doubleValue.rounded() == number.doubleValue else { return nil }
        return number.uint32Value
    }
}

public struct RegistryDesktopEvidence: Equatable {
    public let consoleLocked: Bool?
    public let matched: DesktopSessionEvidence?
    public let sessionMatched: Bool
    public let valid: Bool

    public func sameDesktop(as other: Self) -> Bool {
        consoleLocked == other.consoleLocked && sessionMatched == other.sessionMatched && valid == other.valid &&
            ((matched == nil && other.matched == nil) || matched.flatMap { first in other.matched.map { first.sameDesktop(as: $0) } } == true)
    }
    public init(rootLock: Any?, rows: Any?, session: DesktopSessionEvidence) {
        consoleLocked = DesktopSessionEvidence.boolean(rootLock)
        let dictionaries = rows as? [[String: Any]]
        let entries = (dictionaries?.count ?? 0) <= 64 ? dictionaries?.map(DesktopSessionEvidence.init) : nil
        let matches = entries?.filter { session.uid != nil && session.audit != nil && $0.uid == session.uid && $0.audit == session.audit } ?? []
        let selected = matches.count == 1 ? matches.first : nil
        matched = selected
        let active = entries?.filter { $0.onConsole == true } ?? []
        let uniqueActive = active.count == 1 && selected != nil && active[0] == selected
        sessionMatched = uniqueActive && selected?.loginDone == true && selected?.onConsole == true
        valid = (rootLock == nil || consoleLocked != nil) && (rows == nil || entries != nil) &&
            (entries?.allSatisfy { $0.valid && $0.onConsole != nil && $0.uid != nil && $0.audit != nil } ?? true) &&
            (entries == nil || (matches.count == 1 && uniqueActive && selected?.loginDone == true))
    }
}

import Foundation
import ApplicationServices
import CollectorCore

/// Only constructed in the worker after application/desktop/security gates.
final class NativeAXEnablementProvider: AXEnablementProvider {
    /// Production defaults are public AX APIs. Tests inject all remote operations;
    /// constructing an application handle alone does not query its process.
    struct API {
        var setTimeout: (AXUIElement, Float) -> AXError = { AXUIElementSetMessagingTimeout($0, $1) }
        var names: (AXUIElement, UnsafeMutablePointer<CFArray?>) -> AXError = { AXUIElementCopyAttributeNames($0, $1) }
        var current: (AXUIElement, CFString, UnsafeMutablePointer<CFTypeRef?>) -> AXError = { AXUIElementCopyAttributeValue($0, $1, $2) }
        var settable: (AXUIElement, CFString, UnsafeMutablePointer<DarwinBoolean>) -> AXError = { AXUIElementIsAttributeSettable($0, $1, $2) }
        var enable: (AXUIElement, CFString, CFTypeRef) -> AXError = { AXUIElementSetAttributeValue($0, $1, $2) }
    }

    let application: AXUIElement
    private var names: [String]?
    private let api: API
    private let preparationDeadlineMs: Int64
    private let configuredSeconds: Float
    private let nowMs: () -> Int64
    private var unavailable = false
    private var writeAttempted = false
    private(set) var writeReportedSuccess = false

    init(pid: pid_t, timeoutMs: Int, hardDeadlineMs: Int64,
         nowMs: @escaping () -> Int64 = { SystemCollectorClock().monotonicMs }, api: API = API()) {
        // One shared, optional preparation allowance, not a fresh cap per IPC.
        // The OS owns whether a synchronous call honors the requested timeout.
        let started = nowMs()
        preparationDeadlineMs = started >= 0 && hardDeadlineMs > started
            ? started + min(100, hardDeadlineMs - started) : started
        application = AXUIElementCreateApplication(pid)
        configuredSeconds = Float(max(1, min(timeoutMs, 5_000))) / 1000
        self.api = api; self.nowMs = nowMs
    }

    var isAvailable: Bool {
        let now = nowMs()
        guard !unavailable, now >= 0, now < preparationDeadlineMs else { unavailable = true; return false }
        return true
    }
    private func perform(_ operation: () -> AXError) -> Bool {
        guard isAvailable,
              let timeout = AXPhaseBudget.messagingTimeout(configuredSeconds: configuredSeconds,
                  nowMs: nowMs(), deadlineMs: preparationDeadlineMs),
              WorkerProgress.withCall(api: 1, { api.setTimeout(application, timeout) }) == .success, isAvailable else {
            unavailable = true; return false
        }
        let status = operation()
        // A late success is not a verified capability, original value or write.
        // Latch failure so manual/enhanced negotiation cannot start another IPC.
        guard isAvailable, status == .success else { unavailable = true; return false }
        return true
    }
    private func name(_ attribute: AXEnablementResult.Attribute) -> CFString {
        (attribute == .manual ? "AXManualAccessibility" : "AXEnhancedUserInterface") as CFString
    }
    func supports(_ attribute: AXEnablementResult.Attribute) -> Bool {
        guard isAvailable else { return false }
        if names == nil {
            var raw: CFArray?
            guard perform({ WorkerProgress.withCall(api: 2, { api.names(application, &raw) }) }), let read = raw as? [String] else {
                unavailable = true; return false
            }
            names = read
        }
        return names!.contains(name(attribute) as String)
    }
    func current(_ attribute: AXEnablementResult.Attribute) -> Bool? {
        var value: CFTypeRef?
        guard perform({ WorkerProgress.withCall(api: 3, attribute: attribute == .manual ? 1 : 2, { api.current(application, name(attribute), &value) }) }),
              let value, CFGetTypeID(value) == CFBooleanGetTypeID() else {
            unavailable = true; return nil
        }
        return CFBooleanGetValue((value as! CFBoolean))
    }
    func settable(_ attribute: AXEnablementResult.Attribute) -> Bool? {
        var value = DarwinBoolean(false)
        guard perform({ WorkerProgress.withCall(api: 4, attribute: attribute == .manual ? 1 : 2, { api.settable(application, name(attribute), &value) }) }) else { return nil }
        return value.boolValue
    }
    func enable(_ attribute: AXEnablementResult.Attribute) -> Bool {
        guard !writeAttempted else { unavailable = true; return false }
        return perform {
            writeAttempted = true
            let status = WorkerProgress.withCall(api: 5, attribute: attribute == .manual ? 1 : 2) {
                api.enable(application, name(attribute), kCFBooleanTrue)
            }
            writeReportedSuccess = status == .success
            return status
        }
    }
}

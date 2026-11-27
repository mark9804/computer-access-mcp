import Foundation
import AppKit
import ApplicationServices
import CollectorCore

enum ApplicationAvailability {
    enum Phase: Int64 {
        case sessionApplication = 1, sessionIdentity = 2, activation = 3
    }
    enum Rejection: Int64, Error {
        case applicationMissing = 1, bundleMissing = 2, launchDateMissing = 3
        case processIdentifierInvalid = 4, bundleEmpty = 5, bundleOverLimit = 6
        case activationApplicationMissing = 7
    }
    static func application<Application>(_ value: Application?, bundleIdentifier: (Application) -> String?)
        -> Result<(application: Application, applicationId: String), Rejection> {
        guard let value else { return .failure(.applicationMissing) }
        guard let bundle = bundleIdentifier(value) else { return .failure(.bundleMissing) }
        return .success((value, bundle))
    }
    static func identity(bundleIdentifier: () -> String?, launchDate: () -> Date?, processIdentifier: () -> Int32)
        -> Result<ApplicationIdentity, Rejection> {
        guard let bundle = bundleIdentifier() else { return .failure(.bundleMissing) }
        guard let launch = launchDate() else { return .failure(.launchDateMissing) }
        guard processIdentifier() > 1 else { return .failure(.processIdentifierInvalid) }
        guard !bundle.isEmpty else { return .failure(.bundleEmpty) }
        guard bundle.utf16.count <= 256 else { return .failure(.bundleOverLimit) }
        return .success(ApplicationIdentity(
            applicationId: bundle,
            processId: processIdentifier(),
            processStartTime: String(format: "unix-ms:%.3f", launch.timeIntervalSince1970 * 1_000)
        ))
    }
    static func record(_ rejection: Rejection, phase: Phase, readId: Int64? = nil) {
        var numbers = ["phase": phase.rawValue, "rejection": rejection.rawValue]
        if let readId { numbers["readId"] = readId }
        CollectorDebugTrace.record("application-availability", numbers: numbers)
    }
}

/// Runtime application identity and browser-capability gate bound to a specific
/// `NSRunningApplication` without falling back to `NSRunningApplication.current`.
enum AppIdentityGate {
    static func identityObservation(_ app: NSRunningApplication?) -> Result<ApplicationIdentity, ApplicationAvailability.Rejection> {
        guard let app else { return .failure(.applicationMissing) }
        return ApplicationAvailability.identity(
            bundleIdentifier: { app.bundleIdentifier },
            launchDate: { app.launchDate },
            processIdentifier: { app.processIdentifier }
        )
    }

    static func identity(_ app: NSRunningApplication?) -> ApplicationIdentity? {
        try? identityObservation(app).get()
    }

    static func permittedNonBrowser(_ app: NSRunningApplication) -> Bool {
        guard let id = app.bundleIdentifier, !BrowserGate.isKnownBrowser(id),
              let url = app.bundleURL, let bundle = Bundle(url: url), let info = bundle.infoDictionary else { return false }
        for entry in info["CFBundleURLTypes"] as? [[String: Any]] ?? [] {
            for scheme in entry["CFBundleURLSchemes"] as? [String] ?? [] where ["http", "https"].contains(scheme.lowercased()) {
                return false
            }
        }
        return true
    }

    static func permittedApplication(_ app: NSRunningApplication, policy: CapturePolicy) -> Bool {
        guard let id = app.bundleIdentifier, ApplicationPolicy.allows(id, policy: policy) else { return false }
        if policy.applicationScope == "denylist", policy.allowBrowserContent == true { return true }
        return permittedNonBrowser(app)
    }

    static func privateState(for app: NSRunningApplication) -> String {
        permittedNonBrowser(app) ? "normal" : "user-authorized"
    }

    static func privateState(for expected: ApplicationIdentity) -> String {
        if let running = NSRunningApplication(processIdentifier: expected.processId),
           identity(running) == expected {
            return privateState(for: running)
        }
        // Fail closed when the process is gone or PID was reused so private-window
        // gates remain active rather than downgrading an unknown browser to "normal".
        return "user-authorized"
    }
}

/// Native AX adapter for `BrowserChromeGate.inspect`, using its own local
/// deadline and per-element timeout without touching surface `ReadBudget`.
enum BrowserChromeInspector {
    static func inspect(
        window: AXUIElement,
        expectedPid: pid_t,
        timeoutSeconds: Float,
        deadlineMs: Int64
    ) -> BrowserChromeVerdict {
        let chromeDeadline = min(deadlineMs, SystemCollectorClock().monotonicMs + 80)

        func configureTimeout(on element: AXUIElement) -> Bool {
            let now = SystemCollectorClock().monotonicMs
            guard now < chromeDeadline,
                  let seconds = AXPhaseBudget.messagingTimeout(
                      configuredSeconds: timeoutSeconds,
                      nowMs: now,
                      deadlineMs: chromeDeadline
                  ) else { return false }
            return NativeOperation.setTimeout(element, seconds) == .success &&
                SystemCollectorClock().monotonicMs < chromeDeadline
        }

        return BrowserChromeGate.inspect(
            window: window,
            deadlineMs: chromeDeadline,
            nowMs: { SystemCollectorClock().monotonicMs },
            matchesProcess: { element in
                var pid: pid_t = 0
                guard NativeOperation.getPid(element, &pid) == .success else { return nil }
                return pid == expectedPid
            },
            readNode: { element in
                guard configureTimeout(on: element) else { return nil }
                let facts = AXMetadataBatch.read(element: element, permit: {
                    SystemCollectorClock().monotonicMs < chromeDeadline
                })
                guard facts.status == .success else { return nil }
                return BrowserChromeNode(
                    role: facts.role,
                    subrole: facts.subroleRead,
                    protectedContent: facts.protectedRead,
                    hasSensitiveEvidence: facts.hasSensitiveEvidence,
                    safeTitle: facts.safeTitle,
                    safeDescription: facts.safeDescription,
                    safeIdentifier: facts.safeIdentifier
                )
            },
            readChildren: { element, limit in
                guard configureTimeout(on: element) else { return .error }
                var values: CFArray?
                // Request limit + 1 so any truncation beyond maxChildren fails closed.
                let status = NativeOperation.copyValues(
                    element,
                    kAXChildrenAttribute as CFString,
                    0,
                    limit + 1,
                    &values
                )
                switch status {
                case .noValue, .attributeUnsupported:
                    return .none
                case .success:
                    guard let children = values as? [AXUIElement] else { return .error }
                    if children.count > limit {
                        return .children([], truncated: true)
                    }
                    return .children(children, truncated: false)
                default:
                    return .error
                }
            }
        )
    }
}

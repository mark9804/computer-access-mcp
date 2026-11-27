import Foundation
import AppKit
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
        return BrowserGate.isKnownBrowser(expected.applicationId) ? "user-authorized" : "normal"
    }
}

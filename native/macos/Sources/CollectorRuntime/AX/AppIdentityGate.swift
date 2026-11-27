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

enum BrowserChromeVerdict: Equatable {
    case verifiedNormal
    case privateDetected
    case inconclusive
}

/// Bounded, fail-closed inspection of top-level non-document browser chrome
/// controls (e.g. Chromium/Arc/Firefox private-mode toolbar badges) shared by
/// focused/surface reads and menu-action privacy gates. Never enters web
/// content, tabs, address bars, or menus, and uses its own local call budget so
/// it never drains surface final-validation reserves or pollutes `extraReasons`.
enum BrowserChromeInspector {
    private static let excludedRoles: Set<String> = [
        "AXWebArea", "AXDocument", "AXScrollArea", "AXSheet", "AXDrawer",
        "AXTabGroup", "AXRadioButton", "AXTabButton",
        "AXTextField", "AXTextArea", "AXLink",
        "AXMenuBar", "AXMenu", "AXMenuItem", "AXScrollBar",
    ]

    private static let containerRoles: Set<String> = [
        "AXWindow", "AXToolbar", "AXGroup", "AXSplitGroup",
    ]

    private static let skippedBookmarkIdentifiers: Set<String> = [
        "BookmarkBarView", "PersonalToolbar",
    ]

    static func inspect(
        window: AXUIElement,
        expectedPid: pid_t,
        timeoutSeconds: Float,
        deadlineMs: Int64
    ) -> BrowserChromeVerdict {
        let chromeDeadline = min(deadlineMs, SystemCollectorClock().monotonicMs + 80)
        var remainingCalls = 160

        func configureTimeout(on element: AXUIElement) -> Bool {
            let now = SystemCollectorClock().monotonicMs
            guard now < chromeDeadline, remainingCalls > 0 else { return false }
            remainingCalls -= 1
            guard let seconds = AXPhaseBudget.messagingTimeout(
                configuredSeconds: timeoutSeconds,
                nowMs: now,
                deadlineMs: chromeDeadline
            ) else { return false }
            return NativeOperation.setTimeout(element, seconds) == .success &&
                SystemCollectorClock().monotonicMs < chromeDeadline
        }

        var queue: [(element: AXUIElement, depth: Int, role: String?)] = [(window, 0, "AXWindow")]
        var cursor = 0
        var inspected = 0
        let maxDepth = 6
        let maxNodes = 96
        let maxChildren = 64

        while cursor < queue.count {
            guard SystemCollectorClock().monotonicMs < chromeDeadline else { return .inconclusive }
            let current = queue[cursor]
            cursor += 1
            let currentRole: String

            if current.depth > 0 {
                var pid: pid_t = 0
                let pidStatus = NativeOperation.getPid(current.element, &pid)
                guard pidStatus == .success else { return .inconclusive }
                guard pid == expectedPid else { continue }
                guard configureTimeout(on: current.element) else { return .inconclusive }
                let nodeFacts = AXMetadataBatch.read(element: current.element, permit: {
                    SystemCollectorClock().monotonicMs < chromeDeadline
                })
                guard nodeFacts.status == .success else { return .inconclusive }
                if nodeFacts.hasSensitiveEvidence { return .privateDetected }
                guard let role = nodeFacts.role else { return .inconclusive }
                if excludedRoles.contains(role) { continue }
                if (role == "AXGroup" || role == "AXToolbar"),
                   let identifier = nodeFacts.safeIdentifier,
                   skippedBookmarkIdentifiers.contains(identifier) {
                    continue
                }
                guard inspected < maxNodes else { return .inconclusive }
                inspected += 1
                if let title = nodeFacts.safeTitle, BrowserGate.isPrivateChromeLabel(title) {
                    return .privateDetected
                }
                if let desc = nodeFacts.safeDescription, BrowserGate.isPrivateChromeLabel(desc) {
                    return .privateDetected
                }
                guard containerRoles.contains(role) else { continue }
                currentRole = role
            } else {
                guard configureTimeout(on: current.element) else { return .inconclusive }
                currentRole = "AXWindow"
            }

            guard current.depth < maxDepth else { return .inconclusive }
            guard SystemCollectorClock().monotonicMs < chromeDeadline, remainingCalls > 0 else {
                return .inconclusive
            }
            remainingCalls -= 1
            var values: CFArray?
            let childStatus = NativeOperation.copyValues(
                current.element,
                kAXChildrenAttribute as CFString,
                0,
                maxChildren,
                &values
            )
            switch childStatus {
            case .noValue, .attributeUnsupported:
                continue
            case .success:
                guard let children = values as? [AXUIElement] else { return .inconclusive }
                // On toolbars, Chromium/Edge/Firefox place the Incognito/Profile badge near the trailing edge.
                let ordered = currentRole == "AXToolbar" ? Array(children.reversed()) : children
                for child in ordered {
                    queue.append((child, current.depth + 1, nil))
                }
            default:
                return .inconclusive
            }
        }
        return .verifiedNormal
    }
}

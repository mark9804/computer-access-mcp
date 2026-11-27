import Foundation
import AppKit
import ApplicationServices
import CollectorCore
import Darwin
import Carbon

struct AXBoundaryDiagnostic {
    private var evidence = SurfaceReadDiagnostics()
    private(set) var deadlineExceeded = false
    var failure: SurfaceReadFailure? { evidence.failure }

    func failureIfRejected(_ accepted: Bool) -> SurfaceReadFailure? {
        accepted ? nil : failure ?? .boundaryUnverified
    }

    mutating func note(_ failure: SurfaceReadFailure, deadlineExceeded: Bool = false) {
        guard failure.isRequiredBoundaryFailure else { return }
        evidence.note(failure)
        self.deadlineExceeded = self.deadlineExceeded || deadlineExceeded
    }

    mutating func noteComparison<Value: Equatable>(_ actual: Value?, expected: Value) {
        if let actual, actual != expected { note(.boundaryMismatch) }
    }

    mutating func noteAXStatus(_ status: AXError) {
        switch status {
        case .success, .noValue, .attributeUnsupported: break
        default: note(.boundaryAXFailed)
        }
    }

    mutating func noteAttribute<Value>(_ read: AXMetadataBatch.AttributeRead<Value>) {
        switch read {
        case .apiFailure(let error): noteAXStatus(error)
        case .null, .malformed: note(.boundaryAXFailed)
        case .value, .attributeUnsupported, .noValue, .notRead: break
        }
    }
}

/// Worker-process AX client implementing both focused-field reading and `AXSurfaceBackend`.
final class AXFieldProvider: TextFieldProvider, AXSurfaceBackend {
    let expected: ApplicationIdentity
    let policy: CapturePolicy
    let adapter: any AppAdapter
    let privateState: String
    var debugReadId: Int64 = 0
    var recoverableFocusDeadline: Int64?
    private let timeout: Float
    private(set) var app: AXUIElement?
    private(set) var field: AXUIElement?
    private(set) var window: AXUIElement?
    private var anchorField: AXUIElement?
    private var verifiedNormalBrowserWindow: AXUIElement?
    private(set) var focusObservation: FocusElementRead<AXUIElement> = .failure
    private(set) var isWindowOnly = false
    private(set) var privateWindowBlocked = false
    private var requiresAbsentFocusAnchor = false
    private var windowBoundaryFailed = false
    private var topLevelOwnership = false
    private var ownershipBoundaryFailed = false
    private var surfaceFailures = SurfaceReadDiagnostics()
    private var requiredSurfaceBoundary = false
    private var boundaryDiagnostic: AXBoundaryDiagnostic?

    var canFallbackToUnfocusedWindow: Bool {
        guard !privateWindowBlocked, !secureInputObserved, surfaceFailure != .securityExcluded else { return false }
        if focusObservation.isExplicitlyAbsent { return true }
        return lastFocusResolveStatus != .notPermitted && !lastFocusResolveDeadlineExceeded
    }

    var deadlineMonotonicMs: Int64 = Int64.max
    private var sampleTextBudget = ReadBudget(maxTextUnits: 8192)
    private var activeBudget: ReadBudget?
    private weak var activeSurfaceContext: SafeAXContext?
    private(set) var surfaceReadUnits = 0

    // Per-surface traversal state
    private struct CachedStaticLabels {
        let title: String?
        let description: String?
    }
    private var surfaceHandles: [AXUIElement] = []
    private var surfaceRootIndex = 0
    private var surfaceRects: [Int: SurfaceAbsoluteRect] = [:]
    private var surfaceStaticLabels: [Int: CachedStaticLabels] = [:]
    private var surfaceFocusRole: String?
    private var surfaceFocusIsText = false
    private var surfaceInitialRoleFailure: SurfaceReadFailure?

    private func cacheStaticLabels(for index: Int, facts: AXMetadataBatch.Snapshot) {
        guard !facts.hasSensitiveEvidence, facts.role == "AXStaticText" else {
            surfaceStaticLabels.removeValue(forKey: index)
            return
        }
        if facts.safeTitle != nil || facts.safeDescription != nil {
            surfaceStaticLabels[index] = CachedStaticLabels(title: facts.safeTitle, description: facts.safeDescription)
        } else {
            surfaceStaticLabels.removeValue(forKey: index)
        }
    }

    var surfaceFailure: SurfaceReadFailure? { surfaceFailures.failure }
    func noteSurfaceFailure(_ failure: SurfaceReadFailure) { surfaceFailures.note(failure) }
    var actualTextReadUnits: Int { sampleTextBudget.textUnits }

    init(
        expected: ApplicationIdentity,
        timeoutMs: Int,
        policy: CapturePolicy? = nil,
        adapter: (any AppAdapter)? = nil,
        privateState: String? = nil
    ) {
        self.expected = expected
        self.policy = policy ?? CapturePolicy(allowedApplicationIds: [expected.applicationId])
        self.adapter = adapter ?? AppAdapterRegistry.shared.adapter(for: expected.applicationId)
        self.timeout = Float(max(1, min(timeoutMs, 5_000))) / 1_000
        self.privateState = privateState ?? AppIdentityGate.privateState(for: expected)
    }

    private func captureBoundaryDiagnostic<Value>(_ check: () -> Value) -> (Value, AXBoundaryDiagnostic) {
        let outer = boundaryDiagnostic
        boundaryDiagnostic = AXBoundaryDiagnostic()
        defer { boundaryDiagnostic = outer }
        let result = check()
        return (result, boundaryDiagnostic ?? AXBoundaryDiagnostic())
    }

    @discardableResult
    private func checkRequiredBoundary(_ check: () -> Bool) -> Bool {
        let (accepted, evidence) = captureBoundaryDiagnostic(check)
        if !accepted {
            surfaceFailures.noteRequiredBoundaryFailure(evidence: evidence.failure)
            if let failure = evidence.failure {
                boundaryDiagnostic?.note(failure, deadlineExceeded: evidence.deadlineExceeded)
            }
        }
        return accepted
    }

    private func sameBoundaryHandle(_ lhs: AXUIElement, _ rhs: AXUIElement) -> Bool {
        let equal = CFEqual(lhs, rhs)
        if !equal { boundaryDiagnostic?.note(.boundaryMismatch) }
        return equal
    }

    private var currentDeadlineMs: Int64 {
        if let ctx = activeSurfaceContext { return min(deadlineMonotonicMs, ctx.effectiveDeadlineMs) }
        if let budget = activeBudget { return min(deadlineMonotonicMs, budget.activeDeadlineMs) }
        return deadlineMonotonicMs
    }

    private func boundaryBeforeDeadline() -> Bool {
        if SystemCollectorClock().monotonicMs < currentDeadlineMs { return true }
        boundaryDiagnostic?.note(.boundaryIncomplete, deadlineExceeded: true)
        return false
    }

    private func accountText(_ value: String?, requested: Int? = nil) -> String? {
        if let value {
            let units = value.utf16.count
            _ = sampleTextBudget.consumeText(units, requested: requested)
            if let ctx = activeSurfaceContext {
                _ = ctx.recordBackendText(units, requested: requested)
            }
        }
        return sampleTextBudget.textViolated ? nil : value
    }

    var secureInput: () -> Void = {}
    private var secureInputObserved = false

    func application() -> ApplicationIdentity? {
        guard !secureInputObserved else { return nil }
        guard !WorkerProgress.withValue(api: 17, { IsSecureEventInputEnabled() }) else {
            secureInputObserved = true
            secureInput()
            return nil
        }
        guard let current = WorkerProgress.withValue(api: 18, { NSWorkspace.shared.frontmostApplication }),
              AppIdentityGate.permittedApplication(current, policy: policy),
              let identity = WorkerProgress.withValue(api: 19, { AppIdentityGate.identity(current) }) else { return nil }
        guard identity == expected else {
            boundaryDiagnostic?.note(.boundaryMismatch)
            return nil
        }
        return expected
    }

    func permitCall(_ attributeCost: Int = 1) -> Bool {
        guard attributeCost > 0 else { return false }
        let now = SystemCollectorClock().monotonicMs
        guard boundaryBeforeDeadline() else {
            if activeSurfaceContext != nil || activeBudget != nil { noteSurfaceFailure(.timeBudget) }
            return false
        }
        if sampleTextBudget.textViolated { return false }
        if let ctx = activeSurfaceContext {
            let allowed = ctx.recordBackendCalls(attributeCost)
            if !allowed {
                boundaryDiagnostic?.note(.boundaryIncomplete)
                noteSurfaceFailure(.callBudget)
            }
            return allowed
        }
        if activeBudget != nil {
            let allowed = activeBudget!.consumeCalls(attributeCost, nowMs: now)
            if !allowed {
                boundaryDiagnostic?.note(.boundaryIncomplete)
                noteSurfaceFailure(.callBudget)
            }
            return allowed
        }
        return true
    }

    func permitCall(on element: AXUIElement, attributeCost: Int = 1, onFailure: ((AXError?) -> Void)? = nil) -> Bool {
        guard permitCall(attributeCost) else { onFailure?(nil); return false }
        let now = SystemCollectorClock().monotonicMs
        let cutoff = currentDeadlineMs
        guard let seconds = AXPhaseBudget.messagingTimeout(configuredSeconds: timeout, nowMs: now, deadlineMs: cutoff) else {
            if now >= cutoff { boundaryDiagnostic?.note(.boundaryIncomplete, deadlineExceeded: true) }
            onFailure?(nil)
            return false
        }
        let status = NativeOperation.setTimeout(element, seconds)
        guard status == .success else {
            boundaryDiagnostic?.note(.boundaryAXFailed)
            onFailure?(status)
            return false
        }
        guard boundaryBeforeDeadline() else { onFailure?(nil); return false }
        return true
    }

    private func metadata(_ element: AXUIElement) -> AXMetadataBatch.Snapshot {
        let snapshot = AXMetadataBatch.read(element: element, permit: {
            self.permitCall(on: element, attributeCost: AXMetadataBatch.requestCost)
        })
        if requiredSurfaceBoundary && snapshot.hasSensitiveEvidence {
            noteSurfaceFailure(.securityExcluded)
        }
        switch snapshot.status {
        case .apiFailure(let error): boundaryDiagnostic?.noteAXStatus(error)
        case .malformed: boundaryDiagnostic?.note(.boundaryAXFailed)
        case .notPermitted, .success: break
        }
        boundaryDiagnostic?.noteAttribute(snapshot.roleStatus)
        boundaryDiagnostic?.noteAttribute(snapshot.subroleStatus)
        boundaryDiagnostic?.noteAttribute(snapshot.protectedStatus)
        if snapshot.hasSensitiveEvidence { boundaryDiagnostic?.note(.securityExcluded) }
        return snapshot
    }

    private static let browserChromeWalkRoles: Set<String> = [
        "AXWindow", "AXToolbar", "AXGroup", "AXTabGroup", "AXSplitGroup",
        "AXMenuButton", "AXButton", "AXStaticText", "AXPopUpButton", "AXImage",
    ]

    private static let browserChromeExcludedRoles: Set<String> = [
        "AXWebArea", "AXDocument", "AXScrollArea", "AXSheet", "AXDrawer",
    ]

    private func isPrivateBrowserWindow(_ windowElement: AXUIElement, facts: AXMetadataBatch.Snapshot) -> Bool {
        guard BrowserGate.shouldBlockPrivateWindows(applicationId: expected.applicationId, spec: adapter.spec) else {
            return false
        }
        // Fail closed when a browser window title cannot be read or is empty (matching BrowserMenuWindowGate).
        guard let title = facts.safeTitle, !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return true
        }
        if BrowserGate.isPrivateWindowTitle(title) {
            return true
        }
        if let verifiedNormalBrowserWindow, CFEqual(verifiedNormalBrowserWindow, windowElement) {
            return false
        }
        let chrome = inspectBrowserChromeForPrivateBadge(windowElement)
        if chrome.isPrivate {
            return true
        }
        if chrome.completed {
            verifiedNormalBrowserWindow = windowElement
        }
        return false
    }

    /// Bounded inspection of top-level non-document browser chrome controls
    /// (e.g. Chromium/Arc/Firefox private-mode toolbar badges) when window title
    /// alone lacks an incognito suffix. Never enters web/document subtrees and
    /// never pollutes outer boundary diagnostics.
    private func inspectBrowserChromeForPrivateBadge(_ windowElement: AXUIElement) -> (isPrivate: Bool, completed: Bool) {
        let chromeDeadline = min(currentDeadlineMs, SystemCollectorClock().monotonicMs + 40)
        func permitChromeCall(on element: AXUIElement) -> Bool {
            let now = SystemCollectorClock().monotonicMs
            guard now < chromeDeadline, !sampleTextBudget.textViolated else { return false }
            if let ctx = activeSurfaceContext {
                guard ctx.budget.remainingCalls > 1, ctx.recordBackendCalls(1) else { return false }
            } else if activeBudget != nil {
                guard activeBudget!.remainingCalls > 1, activeBudget!.consumeCalls(1, nowMs: now) else { return false }
            }
            guard let seconds = AXPhaseBudget.messagingTimeout(configuredSeconds: timeout, nowMs: now, deadlineMs: chromeDeadline) else {
                return false
            }
            return NativeOperation.setTimeout(element, seconds) == .success && SystemCollectorClock().monotonicMs < chromeDeadline
        }

        var queue: [(element: AXUIElement, depth: Int)] = [(windowElement, 0)]
        var cursor = 0
        var inspected = 0
        let maxDepth = 3
        let maxNodes = 24
        let maxChildren = 16
        var completed = true

        while cursor < queue.count, inspected < maxNodes {
            guard SystemCollectorClock().monotonicMs < chromeDeadline else {
                completed = false
                break
            }
            let current = queue[cursor]
            cursor += 1
            if current.depth > 0 {
                inspected += 1
                var pid: pid_t = 0
                guard permitChromeCall(on: current.element),
                      NativeOperation.getPid(current.element, &pid) == .success,
                      pid == expected.processId else { continue }
                let nodeFacts = AXMetadataBatch.read(element: current.element, permit: {
                    permitChromeCall(on: current.element)
                })
                guard let role = nodeFacts.role else { continue }
                if Self.browserChromeExcludedRoles.contains(role) { continue }
                if let title = nodeFacts.safeTitle, BrowserGate.isPrivateChromeLabel(title) {
                    return (true, true)
                }
                if let desc = nodeFacts.safeDescription, BrowserGate.isPrivateChromeLabel(desc) {
                    return (true, true)
                }
                guard current.depth < maxDepth, Self.browserChromeWalkRoles.contains(role) else { continue }
            }
            guard permitChromeCall(on: current.element) else {
                completed = false
                break
            }
            var values: CFArray?
            guard NativeOperation.copyValues(current.element, kAXChildrenAttribute as CFString, 0, maxChildren, &values) == .success,
                  let children = values as? [AXUIElement] else { continue }
            for child in children {
                guard queue.count < maxNodes + 1 else { break }
                queue.append((child, current.depth + 1))
            }
        }
        return (false, completed)
    }

    private func isExplorationBudgetExhausted() -> Bool {
        guard let ctx = activeSurfaceContext else {
            return SystemCollectorClock().monotonicMs >= currentDeadlineMs
        }
        return !ctx.isAborted && !ctx.budget.textViolated && !ctx.canContinue
    }

    private func budgetExhaustionReason() -> String {
        if let ctx = activeSurfaceContext {
            return SystemCollectorClock().monotonicMs >= ctx.effectiveDeadlineMs ? "tree-time-budget" : "tree-call-budget"
        }
        return SystemCollectorClock().monotonicMs >= currentDeadlineMs ? "tree-time-budget" : "tree-call-budget"
    }

    private func activeWindowAttribute(_ application: AXUIElement, allowMainFallback: Bool) -> AXUIElement? {
        switch windowReference(application, kAXFocusedWindowAttribute as CFString) {
        case .value(let win):
            return win
        case .absent where allowMainFallback:
            return elementAttribute(application, kAXMainWindowAttribute as CFString)
        case .absent, .rejected:
            return nil
        }
    }

    private func focusWindowWithFallback(
        _ application: AXUIElement,
        allowMainFallback: Bool,
        onFailure: @escaping FocusResolveFailure
    ) -> AXUIElement? {
        switch windowReference(application, kAXFocusedWindowAttribute as CFString, onFailure: onFailure) {
        case .value(let win):
            return win
        case .absent where allowMainFallback:
            guard let mainWindow = focusWindowRead(application, kAXMainWindowAttribute as CFString, onFailure: onFailure) else {
                return nil
            }
            guard verifyOwnershipWindow(mainWindow, fatalOnFailure: false) else {
                onFailure(.unavailable, nil)
                return nil
            }
            return mainWindow
        case .absent, .rejected:
            return nil
        }
    }

    func attribute(_ element: AXUIElement, _ name: CFString) -> CFTypeRef? {
        guard permitCall(on: element) else { return nil }
        var value: CFTypeRef?
        let status = NativeOperation.copyValue(element, name, &value)
        guard status == .success else {
            boundaryDiagnostic?.noteAXStatus(status)
            return nil
        }
        if value == nil { boundaryDiagnostic?.note(.boundaryAXFailed) }
        return value
    }

    private func elementAttribute(_ element: AXUIElement, _ name: CFString) -> AXUIElement? {
        guard let value = attribute(element, name) else { return nil }
        guard CFGetTypeID(value) == AXUIElementGetTypeID() else {
            boundaryDiagnostic?.note(.boundaryAXFailed)
            return nil
        }
        return (value as! AXUIElement)
    }

    private enum FocusResolveStage: String {
        case application, focusedElement = "focused-element", focusedWindow = "focused-window"
        case elementWindow = "element-window", windowMatch = "window-match", fieldPID = "field-pid"
    }
    enum FocusResolveStatus: String {
        case unavailable, notPermitted = "not-permitted", noValue = "no-value", unsupported
        case apiError = "api-error", malformed, mismatch
        static func axFailure(_ error: AXError) -> Self {
            switch error { case .noValue: return .noValue; case .attributeUnsupported: return .unsupported; default: return .apiError }
        }
    }
    private typealias FocusResolveFailure = (FocusResolveStatus, AXError?) -> Void

    private func focusedElementRead(
        _ application: AXUIElement,
        onFailure: FocusResolveFailure? = nil,
        recoverableDeadline: Int64? = nil
    ) -> FocusElementRead<AXUIElement> {
        guard permitCall(on: application, onFailure: { onFailure?($0 == nil ? .notPermitted : .apiError, $0) }) else { return .failure }
        var value: CFTypeRef?
        let copy = { NativeOperation.copyValue(application, kAXFocusedUIElementAttribute as CFString, &value) }
        let status = recoverableDeadline.map { WorkerProgress.initialFocus(deadlineMs: $0, copy) } ?? copy()
        switch status {
        case .success:
            guard let value, CFGetTypeID(value) == AXUIElementGetTypeID() else {
                boundaryDiagnostic?.note(.boundaryAXFailed)
                onFailure?(.malformed, status)
                return .malformed
            }
            return .element(value as! AXUIElement)
        case .noValue:
            onFailure?(.noValue, status); return .noValue
        case .attributeUnsupported:
            onFailure?(.unsupported, status); return .attributeUnsupported
        default:
            boundaryDiagnostic?.noteAXStatus(status)
            onFailure?(.apiError, status)
            return .failure
        }
    }

    private func focusWindowRead(_ element: AXUIElement, _ name: CFString, onFailure: @escaping FocusResolveFailure) -> AXUIElement? {
        guard permitCall(on: element, onFailure: { onFailure($0 == nil ? .notPermitted : .apiError, $0) }) else { return nil }
        var value: CFTypeRef?
        let status = NativeOperation.copyValue(element, name, &value)
        guard status == .success else {
            boundaryDiagnostic?.noteAXStatus(status)
            onFailure(.axFailure(status), status)
            return nil
        }
        guard let value, CFGetTypeID(value) == AXUIElementGetTypeID() else {
            boundaryDiagnostic?.note(.boundaryAXFailed)
            onFailure(.malformed, status)
            return nil
        }
        return (value as! AXUIElement)
    }

    private func windowReference(_ element: AXUIElement, _ name: CFString, onFailure: FocusResolveFailure? = nil) -> WindowReference<AXUIElement> {
        guard permitCall(on: element, onFailure: { onFailure?($0 == nil ? .notPermitted : .apiError, $0) }) else { return .rejected }
        var value: CFTypeRef?
        let status = NativeOperation.copyValue(element, name, &value)
        switch status {
        case .success:
            guard let value, CFGetTypeID(value) == AXUIElementGetTypeID() else {
                boundaryDiagnostic?.note(.boundaryAXFailed)
                onFailure?(.malformed, status)
                return .rejected
            }
            return .value(value as! AXUIElement)
        case .noValue, .attributeUnsupported:
            onFailure?(.axFailure(status), status)
            return .absent
        default:
            boundaryDiagnostic?.noteAXStatus(status)
            onFailure?(.apiError, status)
            return .rejected
        }
    }

    private func parentChainElement(_ element: AXUIElement, onFailure: FocusResolveFailure? = nil) -> AXUIElement? {
        guard permitCall(on: element, onFailure: { onFailure?($0 == nil ? .notPermitted : .apiError, $0) }) else { return nil }
        var value: CFTypeRef?
        let status = NativeOperation.copyValue(element, kAXParentAttribute as CFString, &value)
        switch status {
        case .success:
            guard let value, CFGetTypeID(value) == AXUIElementGetTypeID() else {
                boundaryDiagnostic?.note(.boundaryAXFailed)
                onFailure?(.malformed, status)
                return nil
            }
            return (value as! AXUIElement)
        case .noValue, .attributeUnsupported:
            onFailure?(.axFailure(status), status)
            return nil
        default:
            boundaryDiagnostic?.noteAXStatus(status)
            onFailure?(.apiError, status)
            return nil
        }
    }

    private func matchesWindow(
        _ element: AXUIElement,
        _ expectedWindow: AXUIElement,
        allowTopLevel: Bool,
        fatalOnTopLevelFailure: Bool = true,
        onFailure: FocusResolveFailure? = nil
    ) -> WindowOwnership.Route? {
        WindowOwnership.match(
            expectedWindow: expectedWindow,
            allowTopLevel: allowTopLevel,
            direct: { self.windowReference(element, kAXWindowAttribute as CFString, onFailure: onFailure) },
            topLevel: { self.windowReference(element, kAXTopLevelUIElementAttribute as CFString, onFailure: onFailure) },
            same: {
                let same = self.sameBoundaryHandle($0, $1)
                if !same { onFailure?(.mismatch, nil) }
                return same
            },
            verifyTopLevelWindow: {
                let valid = self.verifyOwnershipWindow($0, fatalOnFailure: fatalOnTopLevelFailure)
                if !valid { onFailure?(.unavailable, nil) }
                return valid
            },
            shouldContinue: { !self.ownershipBoundaryFailed && self.boundaryBeforeDeadline() },
            parentChain: {
                WindowOwnership.walkParentChain(
                    from: element,
                    expectedWindow: expectedWindow,
                    parent: { self.parentChainElement($0, onFailure: onFailure) },
                    same: { CFEqual($0, $1) },
                    verifyHop: { ancestor in
                        guard let pid = self.readBoundaryPID(ancestor) else {
                            onFailure?(.unavailable, nil)
                            return false
                        }
                        guard self.boundaryPIDMatches(pid) else {
                            onFailure?(pid > 1 ? .mismatch : .malformed, nil)
                            return false
                        }
                        return true
                    },
                    shouldContinue: { !self.ownershipBoundaryFailed && self.boundaryBeforeDeadline() }
                )
            }
        )
    }

    private func readBoundaryPID(_ element: AXUIElement) -> pid_t? {
        var pid: pid_t = 0
        guard permitCall(on: element) else { return nil }
        let status = NativeOperation.getPid(element, &pid)
        guard status == .success else {
            boundaryDiagnostic?.note(.boundaryAXFailed)
            return nil
        }
        return pid
    }

    private func boundaryPIDMatches(_ pid: pid_t) -> Bool {
        if pid != expected.processId {
            boundaryDiagnostic?.note(pid > 1 ? .boundaryMismatch : .boundaryAXFailed)
            return false
        }
        return true
    }

    private func boundaryRole(_ role: String?, matches expected: String) -> Bool {
        if let role, role != expected {
            boundaryDiagnostic?.note(role.isEmpty || expected.isEmpty ? .boundaryAXFailed : .boundaryMismatch)
        }
        return role == expected
    }

    private func verifyOwnershipWindow(_ element: AXUIElement, fatalOnFailure: Bool = true) -> Bool {
        let accepted = checkRequiredBoundary {
            guard application() != nil, let pid = readBoundaryPID(element), boundaryPIDMatches(pid) else { return false }
            let facts = metadata(element)
            let privateBrowser = isPrivateBrowserWindow(element, facts: facts)
            if facts.hasSensitiveEvidence || privateBrowser {
                if privateBrowser { privateWindowBlocked = true }
                noteSurfaceFailure(.securityExcluded)
                return false
            }
            return boundaryRole(facts.role, matches: "AXWindow") &&
                TextSecurityGate.mayTraverse(subrole: facts.subroleRead, protectedContent: facts.protectedRead)
        }
        if !accepted && fatalOnFailure { ownershipBoundaryFailed = true }
        return accepted
    }

    private(set) var lastFocusResolveStatus: FocusResolveStatus?
    private(set) var lastFocusResolveDeadlineExceeded = false

    func resolveFocusedField() -> Bool {
        let (resolved, evidence) = captureBoundaryDiagnostic { resolveFocusedFieldCore() }
        lastFocusResolveDeadlineExceeded = !resolved && evidence.deadlineExceeded
        return resolved
    }

    private func resolveFocusedFieldCore() -> Bool {
        field = nil; anchorField = nil; window = nil; isWindowOnly = false
        privateWindowBlocked = false; requiresAbsentFocusAnchor = false
        windowBoundaryFailed = false; focusObservation = .failure
        topLevelOwnership = false; ownershipBoundaryFailed = false
        var resolved = false
        var failure: (stage: FocusResolveStage, status: FocusResolveStatus, error: AXError?) = (.application, .unavailable, nil)
        func failed(_ stage: FocusResolveStage) -> FocusResolveFailure {
            { status, error in failure = (stage, status, error) }
        }
        defer {
            lastFocusResolveStatus = resolved ? nil : (boundaryDiagnostic?.failure == .boundaryMismatch ? .mismatch : failure.status)
        }
        guard application() != nil else { return false }
        let application = AXUIElementCreateApplication(expected.processId)
        app = application
        focusObservation = focusedElementRead(application, onFailure: failed(.focusedElement), recoverableDeadline: recoverableFocusDeadline)
        guard case let .element(focused) = focusObservation else { return false }
        let allowTopLevel = policy.captureScope == "window" && adapter.spec.windowAnchor.allowsTopLevelFallback
        guard let focusedWindow = focusWindowWithFallback(application, allowMainFallback: allowTopLevel, onFailure: failed(.focusedWindow)) else { return false }
        if BrowserGate.shouldBlockPrivateWindows(applicationId: expected.applicationId, spec: adapter.spec) {
            let windowFacts = metadata(focusedWindow)
            let privateBrowser = isPrivateBrowserWindow(focusedWindow, facts: windowFacts)
            if windowFacts.hasSensitiveEvidence || privateBrowser {
                if privateBrowser { privateWindowBlocked = true }
                noteSurfaceFailure(.securityExcluded)
                return false
            }
        }
        guard let route = matchesWindow(focused, focusedWindow, allowTopLevel: allowTopLevel, onFailure: failed(.elementWindow)) else { return false }
        var fieldPID: pid_t = 0
        guard permitCall(on: focused, onFailure: { failure = (.fieldPID, $0 == nil ? .notPermitted : .apiError, $0) }) else { return false }
        let pidStatus = NativeOperation.getPid(focused, &fieldPID)
        guard pidStatus == .success else { failure = (.fieldPID, .apiError, pidStatus); return false }
        guard boundaryPIDMatches(fieldPID) else {
            failure = (.fieldPID, fieldPID > 1 ? .mismatch : .malformed, pidStatus)
            return false
        }
        field = focused; anchorField = focused; window = focusedWindow
        topLevelOwnership = route == .topLevel || route == .parentChain
        resolved = true
        return true
    }

    private func readAbsentBoundaryFocus(_ application: AXUIElement) -> FocusElementRead<AXUIElement> {
        let observed = focusedElementRead(application)
        if case .element = observed { boundaryDiagnostic?.note(.boundaryMismatch) }
        return observed
    }

    func resolveUnfocusedWindow() -> Bool {
        guard policy.captureScope == "window",
              adapter.spec.windowAnchor.allowsUnfocusedWindow,
              canFallbackToUnfocusedWindow,
              field == nil, anchorField == nil, let app else { return false }
        activeBudget = ReadBudget(
            deadlineMs: deadlineMonotonicMs,
            finalValidationReserveMs: 0,
            maxCalls: 768,
            validationReserveCalls: 32,
            maxTextUnits: min(8192, policy.maxTextCodeUnits)
        )
        if case .element(let focused) = focusObservation {
            let focusedFacts = metadata(focused)
            if focusedFacts.hasSensitiveEvidence {
                noteSurfaceFailure(.securityExcluded)
                activeBudget = nil
                return false
            }
        }
        noteSurfaceFailure(.anchorUnavailable)
        let allowMainFallback = adapter.spec.windowAnchor.allowsTopLevelFallback
        let shouldContinueWindowCheck: () -> Bool = {
            guard self.boundaryBeforeDeadline() else { return false }
            guard (self.activeBudget?.remainingCalls ?? 0) > 0 else {
                self.boundaryDiagnostic?.note(.boundaryIncomplete)
                return false
            }
            return true
        }
        let (candidate, evidence) = captureBoundaryDiagnostic { () -> AXUIElement? in
            if focusObservation.isExplicitlyAbsent {
                requiresAbsentFocusAnchor = true
                return WindowFocusAnchor.resolve(
                    policy: policy,
                    expectedApplication: expected,
                    application: { self.application() },
                    focus: { self.readAbsentBoundaryFocus(app) },
                    window: { self.activeWindowAttribute(app, allowMainFallback: allowMainFallback) },
                    inspectWindow: { self.validUnfocusedWindow($0) },
                    sameWindow: { self.sameBoundaryHandle($0, $1) },
                    shouldContinue: shouldContinueWindowCheck
                )
            }
            // Fallback for windows whose focused element cannot be resolved to a
            // text field while the foreground window itself is valid and non-sensitive.
            requiresAbsentFocusAnchor = false
            guard shouldContinueWindowCheck(), application() == expected,
                  shouldContinueWindowCheck(),
                  let first = activeWindowAttribute(app, allowMainFallback: allowMainFallback),
                  shouldContinueWindowCheck(),
                  validUnfocusedWindow(first),
                  shouldContinueWindowCheck(),
                  let final = activeWindowAttribute(app, allowMainFallback: allowMainFallback),
                  shouldContinueWindowCheck(),
                  sameBoundaryHandle(first, final),
                  shouldContinueWindowCheck(),
                  application() == expected else { return nil }
            return first
        }
        guard let resolved = candidate else {
            if let failure = evidence.failure { noteSurfaceFailure(failure) }
            activeBudget = nil; window = nil
            return false
        }
        surfaceFailures = SurfaceReadDiagnostics()
        window = resolved; isWindowOnly = true
        return true
    }

    func finishWindowSampling() {
        activeBudget = nil
        field = nil
    }

    private func validUnfocusedWindow(_ element: AXUIElement) -> Bool {
        inspectValidUnfocusedWindow(element).valid
    }

    private func inspectValidUnfocusedWindow(_ element: AXUIElement) -> (valid: Bool, rect: SurfaceAbsoluteRect?) {
        var safeRect: SurfaceAbsoluteRect?
        let accepted = checkRequiredBoundary {
            guard !windowBoundaryFailed, !privateWindowBlocked, application() != nil,
                  let pid = readBoundaryPID(element), boundaryPIDMatches(pid) else { return false }
            let facts = metadata(element)
            let privateBrowser = isPrivateBrowserWindow(element, facts: facts)
            if facts.hasSensitiveEvidence || privateBrowser {
                if privateBrowser { privateWindowBlocked = true }
                noteSurfaceFailure(.securityExcluded)
                return false
            }
            guard boundaryRole(facts.role, matches: "AXWindow"),
                  TextSecurityGate.mayTraverse(subrole: facts.subroleRead, protectedContent: facts.protectedRead) else {
                return false
            }
            safeRect = facts.safeRect
            return true
        }
        if !accepted && isWindowOnly { windowBoundaryFailed = true }
        return (accepted, accepted ? safeRect : nil)
    }

    func role() -> String? {
        guard let field, let value = attribute(field, kAXRoleAttribute as CFString) else { return nil }
        guard let role = value as? String else { boundaryDiagnostic?.note(.boundaryAXFailed); return nil }
        if requiredSurfaceBoundary && role == "AXSecureTextField" { noteSurfaceFailure(.securityExcluded) }
        return role
    }

    func finalSurfaceRole(onBoundaryFailure: (SurfaceReadFailure) -> Void) -> String? {
        let (role, evidence) = captureBoundaryDiagnostic { self.role() }
        if let failure = evidence.failureIfRejected(role != nil) { onBoundaryFailure(failure) }
        return role
    }

    func finalSurfaceSecurity(onBoundaryFailure: (SurfaceReadFailure) -> Void) -> SecureStatus {
        let (security, evidence) = captureBoundaryDiagnostic { secureStatus() }
        if security == .sensitive { onBoundaryFailure(.securityExcluded) }
        else if let failure = evidence.failureIfRejected(policy.allows(security)) { onBoundaryFailure(failure) }
        return security
    }

    func secureStatus() -> SecureStatus {
        guard let field else { return .unknown }
        return secureStatus(metadata(field), on: field)
    }

    func inputEligibility() -> TextSecurityGate.InputEligibility {
        guard let field else { return .unknown }
        let facts = metadata(field)
        return TextSecurityGate.classifyInputMetadata(
            role: facts.role,
            subrole: facts.subroleRead,
            protectedContent: facts.protectedRead,
            policy: policy
        ) {
            let security = self.strictSecurityStatus(field: field, role: facts.role ?? "", subrole: facts.subroleRead)
            guard self.policy.allows(security) else { return security }
            let finalRole = self.role()
            if finalRole == "AXSecureTextField" { return .sensitive }
            guard finalRole == facts.role else { return .unknown }
            return security
        }
    }

    private func secureStatus(_ facts: AXMetadataBatch.Snapshot, on element: AXUIElement) -> SecureStatus {
        if facts.hasSensitiveEvidence {
            if requiredSurfaceBoundary { noteSurfaceFailure(.securityExcluded) }
            return .sensitive
        }
        guard let role = facts.role else { return .unknown }
        let status = TextSecurityGate.classifyMetadata(
            role: role,
            subrole: facts.subroleRead,
            protectedContent: facts.protectedRead,
            policy: policy
        ) {
            self.strictSecurityStatus(field: element, role: role, subrole: facts.subroleRead)
        }
        if status == .sensitive && requiredSurfaceBoundary { noteSurfaceFailure(.securityExcluded) }
        return status
    }

    private func fieldMetadataMatches(_ expectedRole: String) -> Bool {
        guard let field else { return false }
        let facts = metadata(field)
        return boundaryRole(facts.role, matches: expectedRole) && policy.allows(secureStatus(facts, on: field))
    }

    private func boundaryAXSucceeded(_ status: AXError) -> Bool {
        if status != .success { boundaryDiagnostic?.noteAXStatus(status) }
        return status == .success
    }

    private func strictSecurityStatus(field: AXUIElement, role: String, subrole: TextSecurityGate.SubroleRead) -> SecureStatus {
        if case .value(let subrole) = subrole {
            if !subrole.isEmpty { return TextSecurityGate.classify(role: role, subrole: subrole) }
            guard ["AXTextField", "AXTextArea"].contains(role),
                  let editable = attribute(field, "AXEditable" as CFString) else { return .unknown }
            guard CFGetTypeID(editable) == CFBooleanGetTypeID() else { boundaryDiagnostic?.note(.boundaryAXFailed); return .unknown }
            guard CFBooleanGetValue((editable as! CFBoolean)) else { return .unknown }
            var parameters: CFArray?
            guard permitCall(on: field), boundaryAXSucceeded(NativeOperation.parameterizedNames(field, &parameters)) else { return .unknown }
            guard let parameters = parameters as? [String] else { boundaryDiagnostic?.note(.boundaryAXFailed); return .unknown }
            guard parameters.contains(kAXStringForRangeParameterizedAttribute as String), numberOfCharacters() != nil else { return .unknown }
            return TextSecurityGate.classifyEmptySubrole(role: role, editable: true, boundedRangeAdvertised: true, characterCountKnown: true)
        }
        guard subrole == .attributeUnsupported else { return .unknown }
        var attributes: CFArray?
        var parameterized: CFArray?
        guard permitCall(on: field), boundaryAXSucceeded(NativeOperation.copyNames(field, &attributes)) else { return .unknown }
        guard let names = attributes as? [String] else { boundaryDiagnostic?.note(.boundaryAXFailed); return .unknown }
        guard permitCall(on: field), boundaryAXSucceeded(NativeOperation.parameterizedNames(field, &parameterized)) else { return .unknown }
        guard let ranges = parameterized as? [String] else { boundaryDiagnostic?.note(.boundaryAXFailed); return .unknown }
        return TextSecurityGate.classify(
            role: role,
            subrole: nil,
            subroleUnsupported: true,
            attributeListKnown: true,
            subroleAdvertised: names.contains(kAXSubroleAttribute as String),
            boundedRangeAdvertised: ranges.contains(kAXStringForRangeParameterizedAttribute as String),
            characterCountKnown: numberOfCharacters() != nil
        )
    }

    func numberOfCharacters() -> Int? {
        guard let field, let value = attribute(field, kAXNumberOfCharactersAttribute as CFString) else { return nil }
        guard CFGetTypeID(value) == CFNumberGetTypeID(),
              let number = value as? NSNumber, number.doubleValue.isFinite, number.doubleValue.rounded() == number.doubleValue,
              number.doubleValue >= 0, number.doubleValue <= 9_007_199_254_740_991 else {
            boundaryDiagnostic?.note(.boundaryAXFailed)
            return nil
        }
        return number.intValue
    }

    func stringForRange(start: Int, length: Int) -> String? {
        stringForRangeWithStatus(start: start, length: length).value
    }

    private func stringForRangeWithStatus(start: Int, length: Int) -> (value: String?, status: AXError?) {
        guard let field else { return (nil, nil) }
        var range = CFRange(location: start, length: length)
        guard let parameter = AXValueCreate(.cfRange, &range) else { return (nil, nil) }
        var value: CFTypeRef?
        guard permitCall(on: field) else { return (nil, nil) }
        let status = NativeOperation.parameterizedValue(field, kAXStringForRangeParameterizedAttribute as CFString, parameter, &value)
        guard status == .success else { return (nil, status) }
        return (accountText(value as? String, requested: length), status)
    }

    func leafStillOwned() -> Bool {
        guard !ownershipBoundaryFailed, let field, let window, application() != nil else { return false }
        guard let pid = readBoundaryPID(field), boundaryPIDMatches(pid) else { return false }
        return matchesWindow(field, window, allowTopLevel: topLevelOwnership) != nil
    }

    func markerStringForRange(start: Int, length: Int) -> String? {
        markerStringForRange(start: start, length: length, boundaryFailed: { _ in })
    }

    private func markerStringForRange(start: Int, length: Int, boundaryFailed: (SurfaceReadFailure) -> Void) -> String? {
        guard policy.textMarkers == true, let field else { return nil }
        func verifyBoundary() -> Bool {
            let (verified, evidence) = captureBoundaryDiagnostic {
                remainsSameFocusAndWindow() && leafStillOwned() && policy.allows(secureStatus())
            }
            if let failure = evidence.failureIfRejected(verified) { boundaryFailed(failure) }
            return verified
        }
        guard verifyBoundary() else { return nil }
        return TextMarkerBridge.shared.string(
            field: field,
            start: start,
            length: length,
            permit: { self.permitCall(on: field) },
            permitText: {
                guard verifyBoundary() else { return false }
                return self.permitCall(on: field)
            },
            received: { units in
                _ = self.sampleTextBudget.consumeText(units, requested: length)
                if let ctx = self.activeSurfaceContext {
                    return ctx.recordBackendText(units, requested: length)
                }
                return !self.sampleTextBudget.textViolated
            }
        )
    }

    private enum LocalLeafSafety {
        case ok
        case budgetExhausted
        case sensitive
        case unavailable
    }

    private func surfaceMarkerStringForRange(
        start: Int,
        length: Int,
        verifyLocal: () -> LocalLeafSafety,
        onSensitive: () -> Void
    ) -> String? {
        guard policy.textMarkers == true, let field else { return nil }
        func verify() -> Bool {
            switch verifyLocal() {
            case .ok: return true
            case .sensitive: onSensitive(); return false
            case .budgetExhausted, .unavailable: return false
            }
        }
        guard verify() else { return nil }
        return TextMarkerBridge.shared.string(
            field: field,
            start: start,
            length: length,
            permit: { self.permitCall(on: field) },
            permitText: {
                guard verify() else { return false }
                return self.permitCall(on: field)
            },
            received: { units in
                _ = self.sampleTextBudget.consumeText(units, requested: length)
                if let ctx = self.activeSurfaceContext {
                    return ctx.recordBackendText(units, requested: length)
                }
                return !self.sampleTextBudget.textViolated
            }
        )
    }

    func boundedKnownLengthValue() -> String? {
        guard let field else { return nil }
        return accountText(attribute(field, kAXValueAttribute as CFString) as? String)
    }

    func visibleRange() -> TextSelection? {
        guard let field, let value = attribute(field, kAXVisibleCharacterRangeAttribute as CFString),
              CFGetTypeID(value) == AXValueGetTypeID() else { return nil }
        let typed = value as! AXValue
        guard AXValueGetType(typed) == .cfRange else { return nil }
        var range = CFRange(location: 0, length: 0)
        guard AXValueGetValue(typed, .cfRange, &range),
              range.location >= 0, range.length >= 0,
              range.location <= 9_007_199_254_740_991, range.length <= 9_007_199_254_740_991 else { return nil }
        return TextSelection(start: range.location, length: range.length)
    }

    func selectedRange() -> TextSelection? {
        guard let field, let value = attribute(field, kAXSelectedTextRangeAttribute as CFString),
              CFGetTypeID(value) == AXValueGetTypeID() else { return nil }
        let typed = value as! AXValue
        guard AXValueGetType(typed) == .cfRange else { return nil }
        var range = CFRange(location: 0, length: 0)
        guard AXValueGetValue(typed, .cfRange, &range),
              range.location >= 0, range.length >= 0,
              range.location <= 9_007_199_254_740_991, range.length <= 9_007_199_254_740_991 else { return nil }
        return TextSelection(start: range.location, length: range.length)
    }

    private func surfaceRect(_ element: AXUIElement) -> SurfaceAbsoluteRect? {
        let savedDeadline = deadlineMonotonicMs
        deadlineMonotonicMs = min(savedDeadline, SystemCollectorClock().monotonicMs + 20)
        defer { deadlineMonotonicMs = savedDeadline }
        guard let position = attribute(element, kAXPositionAttribute as CFString), CFGetTypeID(position) == AXValueGetTypeID(),
              let size = attribute(element, kAXSizeAttribute as CFString), CFGetTypeID(size) == AXValueGetTypeID() else { return nil }
        let positionValue = position as! AXValue, sizeValue = size as! AXValue
        guard AXValueGetType(positionValue) == .cgPoint, AXValueGetType(sizeValue) == .cgSize else { return nil }
        var point = CGPoint.zero, extent = CGSize.zero
        guard AXValueGetValue(positionValue, .cgPoint, &point), AXValueGetValue(sizeValue, .cgSize, &extent) else { return nil }
        return SurfaceAbsoluteRect(x: Double(point.x), y: Double(point.y), width: Double(extent.width), height: Double(extent.height))
    }

    private func internSurfaceHandle(_ element: AXUIElement) -> Int? {
        if let existing = surfaceHandles.firstIndex(where: { CFEqual($0, element) }) {
            return existing
        }
        guard surfaceHandles.count < 576 else { return nil }
        surfaceHandles.append(element)
        return surfaceHandles.count - 1
    }

    private func elementOwnedByWindow(_ element: AXUIElement, isRoot: Bool) -> Bool {
        guard !ownershipBoundaryFailed, let window else { return false }
        if !isRoot {
            // Non-root descendants come from walking kAXChildrenAttribute of an
            // already-verified root window; verify local PID match without
            // redundant per-child window/workspace IPCs.
            guard !secureInputObserved, !privateWindowBlocked else { return false }
            guard let pid = readBoundaryPID(element), boundaryPIDMatches(pid) else { return false }
            return true
        }
        guard application() != nil else { return false }
        guard let pid = readBoundaryPID(element), boundaryPIDMatches(pid) else { return false }
        if CFEqual(element, window) {
            return true
        }
        let allowTopLevel = topLevelOwnership || (policy.captureScope == "window" && adapter.spec.windowAnchor.allowsTopLevelFallback)
        return matchesWindow(element, window, allowTopLevel: allowTopLevel, fatalOnTopLevelFailure: true) != nil
    }

    // MARK: - AXSurfaceBackend

    func bindSurfaceContext(_ context: SafeAXContext?) {
        activeSurfaceContext = context
    }

    func verifyDesktopAndApplication() -> SurfaceReadFailure? {
        if privateWindowBlocked { return .securityExcluded }
        if ownershipBoundaryFailed || windowBoundaryFailed { return .boundaryUnverified }
        let (current, evidence) = captureBoundaryDiagnostic { application() }
        guard current != nil else {
            return evidence.failure ?? (secureInputObserved ? .securityExcluded : .boundaryUnverified)
        }
        return nil
    }

    func resolveRegionParentRoot() -> Int? {
        guard let anchor = anchorField,
              let parent = elementAttribute(anchor, kAXParentAttribute as CFString),
              let parentRole = attribute(parent, kAXRoleAttribute as CFString) as? String,
              ["AXGroup", "AXScrollArea", "AXSplitGroup", "AXList", "AXTable", "AXOutline", "AXRow", "AXCell"].contains(parentRole) else {
            return nil
        }
        if surfaceHandles.count == 1 {
            surfaceHandles[0] = parent
            surfaceRects.removeValue(forKey: 0)
            surfaceStaticLabels.removeValue(forKey: 0)
            surfaceRootIndex = 0
            return 0
        }
        guard let resolved = internSurfaceHandle(parent) else { return nil }
        surfaceRootIndex = resolved
        return resolved
    }

    func readBackendWindowRect() -> SurfaceAbsoluteRect? {
        guard let window else { return nil }
        let phaseCutoff = currentDeadlineMs
        var verifiedRect: SurfaceAbsoluteRect?
        return AXPhaseBudget.readOptionalGeometry(
            nowMs: { SystemCollectorClock().monotonicMs },
            phaseDeadlineMs: phaseCutoff,
            verifyBoundary: {
                if self.isWindowOnly {
                    let inspected = self.inspectValidUnfocusedWindow(window)
                    verifiedRect = inspected.rect
                    return inspected.valid
                }
                guard self.elementOwnedByWindow(window, isRoot: true) else { return false }
                let facts = self.metadata(window)
                let privateBrowser = self.isPrivateBrowserWindow(window, facts: facts)
                if facts.hasSensitiveEvidence || privateBrowser {
                    if privateBrowser { self.privateWindowBlocked = true }
                    self.noteSurfaceFailure(.securityExcluded)
                    return false
                }
                guard TextSecurityGate.mayTraverse(subrole: facts.subroleRead, protectedContent: facts.protectedRead) else {
                    return false
                }
                verifiedRect = facts.safeRect
                return true
            },
            read: { geometryDeadline in
                if let verifiedRect { return verifiedRect }
                let saved = self.deadlineMonotonicMs
                self.deadlineMonotonicMs = min(saved, geometryDeadline)
                defer { self.deadlineMonotonicMs = saved }
                return self.surfaceRect(window)
            }
        )
    }

    func inspectBackendNode(_ index: Int, isRoot: Bool) -> AXBackendInspection {
        guard index >= 0, index < surfaceHandles.count else { return .pruned(.providerRefused) }
        if secureInputObserved || privateWindowBlocked {
            surfaceRects.removeValue(forKey: index)
            surfaceStaticLabels.removeValue(forKey: index)
            return .fatal(.securityExcluded)
        }
        let element = surfaceHandles[index]
        let (factsResult, evidence) = captureBoundaryDiagnostic { () -> AXMetadataBatch.Snapshot? in
            guard elementOwnedByWindow(element, isRoot: isRoot) else { return nil }
            return metadata(element)
        }
        guard let facts = factsResult, let role = facts.role else {
            surfaceRects.removeValue(forKey: index)
            surfaceStaticLabels.removeValue(forKey: index)
            if secureInputObserved || privateWindowBlocked {
                return .fatal(.securityExcluded)
            }
            if isRoot {
                if isWindowOnly {
                    return .fatal(evidence.failure ?? .boundaryUnverified)
                }
                if let failure = evidence.failure, failure == .boundaryMismatch || failure == .securityExcluded {
                    return .fatal(failure)
                }
                return .pruned(.providerRefused)
            }
            if isExplorationBudgetExhausted() {
                return .pruned(budgetExhaustionReason() == "tree-time-budget" ? .timeBudget : .workBudget)
            }
            // Non-root child belonging to a helper renderer PID or unowned subtree
            // is pruned individually rather than aborting the whole window tree.
            if evidence.failure == .boundaryMismatch || evidence.failure == .securityExcluded {
                return .pruned(.securityPruned)
            }
            return .pruned(.providerRefused)
        }
        if facts.hasSensitiveEvidence {
            surfaceRects.removeValue(forKey: index)
            surfaceStaticLabels.removeValue(forKey: index)
            if isRoot { return .fatal(.securityExcluded) }
            return .pruned(.securityPruned)
        }
        if isRoot && (role == "AXWindow" || (window.map { CFEqual(element, $0) } ?? false)) &&
            isPrivateBrowserWindow(element, facts: facts) {
            surfaceRects.removeValue(forKey: index)
            surfaceStaticLabels.removeValue(forKey: index)
            privateWindowBlocked = true
            noteSurfaceFailure(.securityExcluded)
            return .fatal(.securityExcluded)
        }
        if isRoot && isWindowOnly && role != "AXWindow" {
            surfaceRects.removeValue(forKey: index)
            surfaceStaticLabels.removeValue(forKey: index)
            return .fatal(role.isEmpty ? .boundaryAXFailed : .boundaryMismatch)
        }
        var childCount: CFIndex = 0
        if WeightedSurfaceTraversal.rolePolicy(for: role)?.readsText == false {
            guard permitCall(on: element) else {
                return .pruned(budgetExhaustionReason() == "tree-time-budget" ? .timeBudget : .workBudget)
            }
            guard NativeOperation.getCount(element, kAXChildrenAttribute as CFString, &childCount) == .success else {
                return .pruned(.providerRefused)
            }
        }
        let safeRect = facts.safeRect
        if let safeRect {
            surfaceRects[index] = safeRect
        } else {
            surfaceRects.removeValue(forKey: index)
        }
        cacheStaticLabels(for: index, facts: facts)
        let isFocused = anchorField.map { CFEqual(element, $0) } ?? false
        let displayText = SafeAXDisplayText.compose(
            role: role,
            title: facts.safeTitle,
            description: facts.safeDescription,
            url: facts.safeURL,
            maxUnits: adapter.spec.maxNodeTextUnits
        )
        let label = SafeAXDisplayText.label(
            title: facts.safeTitle,
            description: facts.safeDescription,
            maxUnits: adapter.spec.maxNodeTextUnits
        )
        return .allowed(
            role: role,
            subrole: facts.subroleRead,
            protectedContent: facts.protectedRead,
            childCount: childCount,
            isFocused: isFocused,
            observedAtMs: SystemCollectorClock().unixMs,
            isEnabled: facts.isEnabled,
            displayText: displayText,
            windowTitle: isRoot ? facts.safeTitle : nil,
            absoluteRect: safeRect,
            identifier: facts.safeIdentifier,
            label: label
        )
    }

    func parentBackendNode(of index: Int) -> Int? {
        guard index >= 0, index < surfaceHandles.count,
              let parent = elementAttribute(surfaceHandles[index], kAXParentAttribute as CFString) else {
            return nil
        }
        return internSurfaceHandle(parent)
    }

    func childrenBackendPage(of index: Int, expectedRole: String, offset: Int, limit: Int) -> WeightedSurfaceChildrenRead<Int> {
        guard index >= 0, index < surfaceHandles.count else { return .unavailable(.providerRefused) }
        let element = surfaceHandles[index]
        guard elementOwnedByWindow(element, isRoot: index == surfaceRootIndex) else {
            if isExplorationBudgetExhausted() {
                return .unavailable(budgetExhaustionReason() == "tree-time-budget" ? .timeBudget : .workBudget)
            }
            return .unavailable(.securityPruned)
        }
        let facts = metadata(element)
        if facts.status == .notPermitted || isExplorationBudgetExhausted() {
            return .unavailable(budgetExhaustionReason() == "tree-time-budget" ? .timeBudget : .workBudget)
        }
        guard !facts.hasSensitiveEvidence,
              let role = facts.role, role == expectedRole,
              (WeightedSurfaceTraversal.rolePolicy(for: role)?.readsText == false || role == "AXStaticText"),
              TextSecurityGate.mayTraverse(subrole: facts.subroleRead, protectedContent: facts.protectedRead) else {
            return .unavailable(.securityPruned)
        }
        var values: CFArray?
        guard permitCall(on: element) else {
            return .unavailable(budgetExhaustionReason() == "tree-time-budget" ? .timeBudget : .workBudget)
        }
        guard NativeOperation.copyValues(element, kAXChildrenAttribute as CFString, offset, limit, &values) == .success,
              let children = values as? [AXUIElement], children.count <= limit else {
            return .unavailable(.providerRefused)
        }
        var indices: [Int] = []
        for child in children {
            guard let childIndex = internSurfaceHandle(child) else { return .unavailable(.pendingBudget) }
            indices.append(childIndex)
        }
        return .values(indices)
    }

    func readBackendNodeText(_ index: Int, expectedRole: String, maxUnits: Int, staticTextProbe: StaticTextPolicy) -> AXBackendTextRead {
        guard index >= 0, index < surfaceHandles.count else { return .unavailable(reasons: ["node-text-unavailable"]) }
        if secureInputObserved || privateWindowBlocked { return .fatal(.securityExcluded) }
        let element = surfaceHandles[index]
        let isRootOrFocus = (index == surfaceRootIndex) || (anchorField.map { CFEqual(element, $0) } ?? false)
        let savedField = field
        field = element
        defer { field = savedField }

        // Window/focus/desktop verification runs at readSurface entry and in
        // verifyFinalSurfaceBoundary using reserved calls; per-leaf reads check
        // only local element safety and budget/deadline so one leaf never aborts the tree.
        func verifyLocalLeafSafety() -> LocalLeafSafety {
            if secureInputObserved || privateWindowBlocked {
                surfaceStaticLabels.removeValue(forKey: index)
                return .sensitive
            }
            if isExplorationBudgetExhausted() { return .budgetExhausted }
            let facts = metadata(element)
            if facts.hasSensitiveEvidence {
                surfaceStaticLabels.removeValue(forKey: index)
                return .sensitive
            }
            if facts.status == .notPermitted || isExplorationBudgetExhausted() { return .budgetExhausted }
            guard facts.role == expectedRole else {
                surfaceStaticLabels.removeValue(forKey: index)
                return .unavailable
            }
            let status = secureStatus(facts, on: element)
            if status == .sensitive {
                surfaceStaticLabels.removeValue(forKey: index)
                return .sensitive
            }
            if isExplorationBudgetExhausted() { return .budgetExhausted }
            guard policy.allows(status) else {
                surfaceStaticLabels.removeValue(forKey: index)
                return .unavailable
            }
            if expectedRole == "AXStaticText" {
                cacheStaticLabels(for: index, facts: facts)
            }
            return .ok
        }

        func runStaticTextFallback(maxUnits fallbackMaxUnits: Int? = nil, defaultReasons: [String]) -> AXBackendTextRead? {
            guard expectedRole == "AXStaticText" else { return nil }
            guard !secureInputObserved, !privateWindowBlocked else { return .fatal(.securityExcluded) }
            if isExplorationBudgetExhausted() {
                return .unavailable(reasons: [budgetExhaustionReason()] + defaultReasons)
            }
            let unitCap = min(maxUnits, fallbackMaxUnits ?? maxUnits)
            let effectiveMaxUnits = min(
                unitCap,
                sampleTextBudget.remainingTextUnits,
                activeSurfaceContext?.budget.remainingTextUnits ?? unitCap
            )
            guard effectiveMaxUnits > 0 else {
                return .unavailable(reasons: ["text-budget"] + defaultReasons)
            }
            let cached = surfaceStaticLabels[index]
            let outcome = StaticTextFallback.resolve(
                maxUnits: effectiveMaxUnits,
                cachedTitle: cached?.title,
                cachedDescription: cached?.description,
                verifySafety: {
                    switch verifyLocalLeafSafety() {
                    case .ok: return .ok
                    case .sensitive: return .sensitive
                    case .budgetExhausted: return .budgetExhausted
                    case .unavailable: return .unavailable
                    }
                },
                readValue: {
                    self.attribute(element, kAXValueAttribute as CFString) as? String
                },
                charge: { units in
                    let okSample = self.sampleTextBudget.consumeText(units, requested: effectiveMaxUnits)
                    let okContext = self.activeSurfaceContext?.recordBackendText(units, requested: effectiveMaxUnits) ?? true
                    return okSample && okContext && !self.sampleTextBudget.textViolated
                }
            )
            switch outcome {
            case let .text(value, truncated):
                var reasons = defaultReasons
                if truncated && !reasons.contains("text-budget") { reasons.append("text-budget") }
                return .text(value: value, complete: false, reasons: reasons)
            case .empty:
                return .text(value: "", complete: false, reasons: defaultReasons)
            case .sensitive:
                surfaceStaticLabels.removeValue(forKey: index)
                return isRootOrFocus ? .fatal(.securityExcluded) : .unavailable(reasons: ["node-security-excluded"])
            case .budgetExhausted:
                return .unavailable(reasons: [budgetExhaustionReason()] + defaultReasons)
            case .textBudgetViolated:
                return .fatal(.boundaryUnverified)
            case .unavailable:
                if isExplorationBudgetExhausted() {
                    return .unavailable(reasons: [budgetExhaustionReason()] + defaultReasons)
                }
                return nil
            }
        }

        if isExplorationBudgetExhausted() {
            return .unavailable(reasons: [budgetExhaustionReason()])
        }

        let total = numberOfCharacters()
        if isExplorationBudgetExhausted() {
            return .unavailable(reasons: [budgetExhaustionReason()])
        }

        let probeLimit: Int?
        if case .boundedRangeProbe(let limit) = staticTextProbe {
            probeLimit = min(maxUnits, max(1, min(StaticTextRangeProbe.maximumPrefixUnits, limit)))
        } else {
            probeLimit = nil
        }

        if expectedRole == "AXStaticText", (total == nil || total == 0), let probeLimit {
            // Fast path (0-1 IPC): reuse batched safeTitle/safeDescription or read one
            // verified bounded AXValue before falling back to multi-round range probing.
            if let fallback = runStaticTextFallback(maxUnits: probeLimit, defaultReasons: ["static-text-length-unverified"]) {
                return fallback
            }
            var sensitiveDetected = false
            var desktopFailed = false
            var budgetHit = false
            var rangeAttributeUnsupported = false
            func checkProbeLeaf() -> Bool {
                guard !secureInputObserved, !privateWindowBlocked else { sensitiveDetected = true; return false }
                guard application() != nil else {
                    if secureInputObserved { sensitiveDetected = true } else { desktopFailed = true }
                    return false
                }
                switch verifyLocalLeafSafety() {
                case .ok: return true
                case .sensitive: sensitiveDetected = true; return false
                case .budgetExhausted: budgetHit = true; return false
                case .unavailable: return false
                }
            }
            let probe = SurfaceStaticTextRead.read(
                budget: probeLimit,
                initialPrefixUnits: min(probeLimit, StaticTextRangeProbe.maximumPrefixUnits),
                stopAfterNonempty: false,
                sampleGeometry: {},
                canStartAttempt: { !rangeAttributeUnsupported && (self.activeSurfaceContext?.canContinue ?? true) },
                shouldContinue: { self.activeSurfaceContext.map { !$0.isAborted && self.boundaryBeforeDeadline() } ?? true },
                precheck: { checkProbeLeaf() },
                readRange: { start, length in
                    let read = self.stringForRangeWithStatus(start: start, length: length)
                    if read.status == .attributeUnsupported || read.status == .notImplemented {
                        rangeAttributeUnsupported = true
                    }
                    return read.value
                },
                charge: { _ in !(self.activeSurfaceContext?.budget.textViolated ?? false) && !self.sampleTextBudget.textViolated },
                postcheck: {
                    let lengthOk = total == nil || self.numberOfCharacters() == total
                    if !lengthOk && self.isExplorationBudgetExhausted() { budgetHit = true }
                    return lengthOk && checkProbeLeaf()
                }
            )
            if sensitiveDetected {
                return isRootOrFocus ? .fatal(.securityExcluded) : .unavailable(reasons: ["node-security-excluded"])
            }
            if probe.failure == .oversizedResponse || sampleTextBudget.textViolated || (activeSurfaceContext?.budget.textViolated ?? false) {
                return .fatal(.boundaryUnverified)
            }
            if desktopFailed || secureInputObserved {
                return .fatal(secureInputObserved ? .securityExcluded : .boundaryUnverified)
            }
            if probe.failure != nil {
                if budgetHit || isExplorationBudgetExhausted() {
                    return .unavailable(reasons: [budgetExhaustionReason(), "static-text-length-unverified"])
                }
                return .unavailable(reasons: ["static-text-length-unverified", "node-text-unavailable"])
            }
            if let text = probe.text {
                return .text(value: text, complete: false, reasons: ["static-text-length-unverified"])
            }
            return .unavailable(reasons: ["static-text-length-unverified", "node-text-unavailable"])
        }

        switch verifyLocalLeafSafety() {
        case .ok: break
        case .budgetExhausted:
            return .unavailable(reasons: [budgetExhaustionReason()])
        case .sensitive:
            return isRootOrFocus ? .fatal(.securityExcluded) : .unavailable(reasons: ["node-security-excluded"])
        case .unavailable:
            return .unavailable(reasons: ["node-text-unavailable"])
        }

        let requested = min(total ?? maxUnits, maxUnits)
        var text: String? = total == 0 ? "" : stringForRange(start: 0, length: requested)
        if sampleTextBudget.textViolated || (activeSurfaceContext?.budget.textViolated ?? false) {
            return .fatal(.boundaryUnverified)
        }
        if text == nil && isExplorationBudgetExhausted() {
            return .unavailable(reasons: [budgetExhaustionReason()])
        }
        if text == nil, policy.textMarkers == true {
            var markerSensitive = false
            text = surfaceMarkerStringForRange(
                start: 0,
                length: requested,
                verifyLocal: verifyLocalLeafSafety,
                onSensitive: { markerSensitive = true }
            )
            if markerSensitive {
                return isRootOrFocus ? .fatal(.securityExcluded) : .unavailable(reasons: ["node-security-excluded"])
            }
            if sampleTextBudget.textViolated || (activeSurfaceContext?.budget.textViolated ?? false) {
                return .fatal(.boundaryUnverified)
            }
            if text == nil && isExplorationBudgetExhausted() {
                return .unavailable(reasons: [budgetExhaustionReason()])
            }
        }
        if text == nil, let total, total <= maxUnits {
            guard numberOfCharacters() == total else {
                return .unavailable(reasons: [isExplorationBudgetExhausted() ? budgetExhaustionReason() : "node-text-unavailable"])
            }
            switch verifyLocalLeafSafety() {
            case .ok:
                text = boundedKnownLengthValue()
            case .budgetExhausted:
                return .unavailable(reasons: [budgetExhaustionReason()])
            case .sensitive:
                return isRootOrFocus ? .fatal(.securityExcluded) : .unavailable(reasons: ["node-security-excluded"])
            case .unavailable:
                return .unavailable(reasons: ["node-text-unavailable"])
            }
        }
        if text == nil, expectedRole == "AXStaticText" {
            if let fallback = runStaticTextFallback(defaultReasons: total == nil ? ["static-text-length-unverified"] : []) {
                return fallback
            }
        }
        guard let text else {
            return .unavailable(reasons: [isExplorationBudgetExhausted() ? budgetExhaustionReason() : "node-text-unavailable"])
        }
        guard text.utf16.count <= requested, !sampleTextBudget.textViolated else {
            return .fatal(.boundaryUnverified)
        }
        switch verifyLocalLeafSafety() {
        case .ok: break
        case .budgetExhausted:
            return .unavailable(reasons: [budgetExhaustionReason()])
        case .sensitive:
            return isRootOrFocus ? .fatal(.securityExcluded) : .unavailable(reasons: ["node-security-excluded"])
        case .unavailable:
            return .unavailable(reasons: ["node-text-unavailable"])
        }
        if let total, numberOfCharacters() != total {
            return .unavailable(reasons: [isExplorationBudgetExhausted() ? budgetExhaustionReason() : "node-text-unavailable"])
        }
        var reasons: [String] = []
        if total == nil || total! > text.utf16.count { reasons.append("text-budget") }
        return .text(value: text, complete: total == text.utf16.count, reasons: reasons)
    }

    func readBackendNodeBounds(_ index: Int, windowRect: SurfaceAbsoluteRect) -> (SurfaceBounds, Int64)? {
        guard index >= 0, index < surfaceHandles.count, application() != nil else {
            return nil
        }
        let absolute: SurfaceAbsoluteRect
        if let cached = surfaceRects[index] {
            absolute = cached
        } else if let fetched = surfaceRect(surfaceHandles[index]) {
            absolute = fetched
        } else {
            return nil
        }
        guard let relative = absolute.relative(to: windowRect) else {
            return nil
        }
        return (relative, SystemCollectorClock().unixMs)
    }

    func verifyFinalSurfaceBoundary() -> SurfaceReadFailure? {
        let savedField = field
        field = anchorField
        defer { field = savedField }
        let (ok, evidence) = captureBoundaryDiagnostic { () -> Bool in
            guard remainsSameFocusAndWindow() else { return false }
            guard anchorField != nil else { return true }
            guard let expectedRole = surfaceFocusRole else {
                if let failure = surfaceInitialRoleFailure { boundaryDiagnostic?.note(failure) }
                return false
            }
            if surfaceFocusIsText { return fieldMetadataMatches(expectedRole) }
            return boundaryRole(role(), matches: expectedRole)
        }
        return ok ? nil : (evidence.failure ?? .boundaryUnverified)
    }

    // MARK: - Surface & Selection Entrypoints

    func readSurface(scope: String, maxNodes: Int, maxText: Int) -> AXSurfaceCapture? {
        surfaceReadUnits = 0
        if !ownershipBoundaryFailed { surfaceFailures = SurfaceReadDiagnostics() }
        guard let window, let rootAnchor = anchorField ?? (isWindowOnly && scope == "window" ? window : nil) else {
            noteSurfaceFailure(.anchorUnavailable)
            return nil
        }
        let focused = anchorField
        let savedField = field
        guard !isWindowOnly || (focused == nil && scope == "window") else { return nil }
        let optionalDeadline = deadlineMonotonicMs

        let alreadyUsedCalls = isWindowOnly ? (activeBudget?.calls ?? 0) : 0
        let surfaceBudget = ReadBudget(
            deadlineMs: optionalDeadline,
            finalValidationReserveMs: ReadBudget.defaultFinalValidationReserveMs,
            maxCalls: max(1, 768 - alreadyUsedCalls),
            validationReserveCalls: ReadBudget.defaultFinalValidationReserveCalls,
            maxTextUnits: maxText
        )
        guard surfaceBudget.hasExplorationHeadroom(nowMs: SystemCollectorClock().monotonicMs) else {
            noteSurfaceFailure(.notStartedBudget)
            return nil
        }

        requiredSurfaceBoundary = true
        defer {
            requiredSurfaceBoundary = false
            field = savedField
            surfaceHandles.removeAll()
            surfaceRootIndex = 0
            surfaceRects.removeAll()
            surfaceStaticLabels.removeAll()
        }

        guard checkRequiredBoundary({ remainsSameFocusAndWindow() }) else { return nil }
        if BrowserGate.shouldBlockPrivateWindows(applicationId: expected.applicationId, spec: adapter.spec) {
            let windowFacts = metadata(window)
            let privateBrowser = isPrivateBrowserWindow(window, facts: windowFacts)
            if windowFacts.hasSensitiveEvidence || privateBrowser {
                if privateBrowser { privateWindowBlocked = true }
                noteSurfaceFailure(.securityExcluded)
                return nil
            }
        }
        let beforeSurfaceSampleUnits = sampleTextBudget.textUnits
        let (focusedRole, initialRoleEvidence) = captureBoundaryDiagnostic { focused == nil ? nil : role() }
        let focusedIsText = ["AXTextField", "AXTextArea", "AXStaticText"].contains(focusedRole)
        if focused != nil {
            let (security, initialSecurityEvidence) = captureBoundaryDiagnostic { secureStatus() }
            guard security != .sensitive, !focusedIsText || policy.allows(security),
                  scope == "window" || focusedIsText else {
                if security == .sensitive { noteSurfaceFailure(.securityExcluded) }
                else if focusedRole == nil { surfaceFailures.noteRequiredBoundaryFailure(evidence: initialRoleEvidence.failure) }
                else if focusedIsText { surfaceFailures.noteRequiredBoundaryFailure(evidence: initialSecurityEvidence.failure) }
                else { noteSurfaceFailure(.boundaryUnverified) }
                return nil
            }
        }
        surfaceFocusRole = focusedRole
        surfaceFocusIsText = focusedIsText
        surfaceInitialRoleFailure = initialRoleEvidence.failure
        surfaceHandles = [scope == "window" ? window : rootAnchor]
        surfaceRootIndex = 0
        surfaceRects.removeAll()
        surfaceStaticLabels.removeAll()
        let focusIndex = (scope == "window" ? focused : nil).flatMap { internSurfaceHandle($0) }

        let outcome = SurfaceCaptureRunner.run(
            adapter: adapter,
            application: expected,
            policy: policy,
            scope: scope,
            maxOutputNodes: maxNodes,
            focus: focusIndex.map(AXNodeHandle.init(index:)),
            budget: surfaceBudget,
            clock: SystemCollectorClock(),
            backend: self
        )

        switch outcome {
        case .failure(let failure):
            noteSurfaceFailure(failure)
            return nil
        case .success(let captured):
            surfaceReadUnits = captured.nodes.reduce(0) { $0 + ($1.text?.utf16.count ?? 0) }
            let alreadyAccounted = max(0, sampleTextBudget.textUnits - beforeSurfaceSampleUnits)
            let displayOnlyUnits = max(0, surfaceReadUnits - alreadyAccounted)
            if displayOnlyUnits > 0 {
                _ = sampleTextBudget.consumeText(displayOnlyUnits)
            }
            surfaceFailures = SurfaceReadDiagnostics()
            let references = captured.handles.compactMap { pair -> (String, AXUIElement)? in
                guard pair.1 >= 0, pair.1 < surfaceHandles.count else { return nil }
                return (pair.0, surfaceHandles[pair.1])
            }
            guard references.count == captured.nodes.count else {
                noteSurfaceFailure(.providerUnavailable)
                return nil
            }
            return AXSurfaceCapture(
                nodes: captured.nodes,
                truncated: captured.truncated,
                reasons: captured.reasons,
                complete: captured.complete,
                geometry: captured.geometry,
                adapterId: captured.adapterId,
                references: references
            )
        }
    }

    func readSelection(maxUnits: Int) -> SelectionReadResult? {
        guard maxUnits > 0, policy.allows(secureStatus()), let range = selectedRange(),
              let total = numberOfCharacters(), range.start >= 0, range.length >= 0,
              range.start <= total, range.length <= total - range.start, remainsSameFocusAndWindow() else { return nil }
        let requested = min(range.length, maxUnits)
        var source = "ax.range"
        guard remainsSameFocusAndWindow(), leafStillOwned(), policy.allows(secureStatus()) else { return nil }
        var text = requested == 0 ? "" : stringForRange(start: range.start, length: requested)
        if text == nil, policy.textMarkers == true {
            source = "ax.marker"
            text = markerStringForRange(start: range.start, length: requested)
        }
        guard let text, text.utf16.count <= requested, selectedRange() == range,
              numberOfCharacters() == total, remainsSameFocusAndWindow(), leafStillOwned(), policy.allows(secureStatus()) else { return nil }
        var reasons = ["selection-only", "non-atomic"]
        if range.length > requested { reasons.append("text-budget") }
        if text.utf16.count < requested { reasons.append("range-short-read") }
        return .init(
            text: text,
            source: source,
            rangeStart: range.start,
            truncated: range.length > requested || text.utf16.count < requested,
            missingReasons: reasons
        )
    }

    func remainsSameFocusAndWindow(onBoundaryFailure: (SurfaceReadFailure) -> Void) -> Bool {
        let (accepted, evidence) = captureBoundaryDiagnostic { remainsSameFocusAndWindow() }
        if let failure = evidence.failureIfRejected(accepted) { onBoundaryFailure(failure) }
        return accepted
    }

    func remainsSameFocusAndWindow() -> Bool {
        let allowMainFallback = policy.captureScope == "window" && adapter.spec.windowAnchor.allowsTopLevelFallback
        if isWindowOnly {
            guard !windowBoundaryFailed, !privateWindowBlocked, anchorField == nil, let app, let window else {
                windowBoundaryFailed = true
                return false
            }
            let valid: Bool
            if requiresAbsentFocusAnchor {
                valid = WindowFocusAnchor.validate(
                    window: window,
                    policy: policy,
                    expectedApplication: expected,
                    application: { self.application() },
                    focus: { self.readAbsentBoundaryFocus(app) },
                    window: { self.activeWindowAttribute(app, allowMainFallback: allowMainFallback) },
                    inspectWindow: { self.validUnfocusedWindow($0) },
                    sameWindow: { self.sameBoundaryHandle($0, $1) },
                    shouldContinue: { !self.windowBoundaryFailed && !self.privateWindowBlocked && self.boundaryBeforeDeadline() }
                )
            } else {
                // Revalidate unfocused fallback window and ensure no sensitive field gained focus.
                valid = {
                    guard self.boundaryBeforeDeadline(), self.application() == self.expected else { return false }
                    if case .element(let currentFocus) = self.focusedElementRead(app) {
                        let facts = self.metadata(currentFocus)
                        if facts.hasSensitiveEvidence {
                            self.noteSurfaceFailure(.securityExcluded)
                            return false
                        }
                    }
                    guard self.boundaryBeforeDeadline(),
                          let freshWindow = self.activeWindowAttribute(app, allowMainFallback: allowMainFallback),
                          self.sameBoundaryHandle(window, freshWindow),
                          self.validUnfocusedWindow(freshWindow),
                          self.boundaryBeforeDeadline(),
                          self.application() == self.expected else { return false }
                    return true
                }()
            }
            if !valid {
                windowBoundaryFailed = true
                noteSurfaceFailure(.boundaryUnverified)
            }
            return valid
        }
        guard !ownershipBoundaryFailed, !privateWindowBlocked, application() != nil, let app, let field = anchorField, let window,
              let freshField = elementAttribute(app, kAXFocusedUIElementAttribute as CFString),
              let freshWindow = activeWindowAttribute(app, allowMainFallback: allowMainFallback),
              sameBoundaryHandle(field, freshField), sameBoundaryHandle(window, freshWindow) else { return false }
        return matchesWindow(freshField, window, allowTopLevel: topLevelOwnership) != nil
    }
}

final class SyntheticFieldProvider: TextFieldProvider {
    let scenario: String
    var content: String {
        scenario == "empty" ? "" : (scenario == "partial" ? String(repeating: "Synthetic \u{1F9EA} ", count: 1000) : "Synthetic \u{1F9EA} text")
    }
    init(_ scenario: String) { self.scenario = scenario }
    func application() -> ApplicationIdentity? {
        ApplicationIdentity(applicationId: scenario == "browser" ? "com.apple.Safari" : "test.allowed", processId: 4242, processStartTime: "fixture-birth-1")
    }
    func resolveFocusedField() -> Bool { scenario != "focus-loss" }
    func role() -> String? { "AXTextField" }
    func secureStatus() -> SecureStatus { scenario == "sensitive" ? .sensitive : .safe }
    func numberOfCharacters() -> Int? { content.utf16.count }
    func visibleRange() -> TextSelection? {
        if scenario == "partial" { return TextSelection(start: 130, length: 260) }
        let start = content.isEmpty ? 0 : 10
        return TextSelection(start: start, length: content.utf16.count - start)
    }
    func stringForRange(start: Int, length: Int) -> String? {
        guard scenario != "value", scenario != "readerror" else { return nil }
        return boundedUTF16Slice(content, start: start, length: length)
    }
    func boundedKnownLengthValue() -> String? { scenario == "readerror" ? nil : content }
    func selectedRange() -> TextSelection? { TextSelection(start: 0, length: 0) }
    func remainsSameFocusAndWindow() -> Bool { true }
}

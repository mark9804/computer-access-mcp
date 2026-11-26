import Foundation

/// Unified budget metering AX queries, text code units, and monotonic deadlines.
public struct ReadBudget: Equatable {
    public static let defaultFinalValidationReserveCalls = 32
    public static let defaultFinalValidationReserveMs: Int64 = 150
    public static let minimumExplorationWindowMs: Int64 = 25

    public let deadlineMs: Int64
    public let finalValidationReserveMs: Int64
    public let maxCalls: Int
    public let validationReserveCalls: Int
    public let maxTextUnits: Int

    public private(set) var calls = 0
    public private(set) var textUnits = 0
    public private(set) var textViolated = false
    public private(set) var isFinalValidation = false

    public init(
        deadlineMs: Int64 = Int64.max,
        finalValidationReserveMs: Int64 = Self.defaultFinalValidationReserveMs,
        maxCalls: Int = 768,
        validationReserveCalls: Int = Self.defaultFinalValidationReserveCalls,
        maxTextUnits: Int = 8192
    ) {
        self.deadlineMs = deadlineMs
        self.finalValidationReserveMs = max(0, finalValidationReserveMs)
        self.maxCalls = min(2048, max(1, maxCalls))
        self.validationReserveCalls = min(max(0, validationReserveCalls), self.maxCalls)
        self.maxTextUnits = min(8192, max(0, maxTextUnits))
    }

    public var explorationDeadlineMs: Int64 {
        deadlineMs == Int64.max ? Int64.max : deadlineMs - finalValidationReserveMs
    }

    public var activeDeadlineMs: Int64 {
        isFinalValidation ? deadlineMs : explorationDeadlineMs
    }

    public var activeCallLimit: Int {
        isFinalValidation ? maxCalls : max(0, maxCalls - validationReserveCalls)
    }

    public var remainingCalls: Int {
        max(0, activeCallLimit - calls)
    }

    public var remainingTextUnits: Int {
        textViolated ? 0 : max(0, maxTextUnits - textUnits)
    }

    public func hasExplorationHeadroom(nowMs: Int64) -> Bool {
        guard !textViolated, remainingCalls > 0 else { return false }
        if explorationDeadlineMs == Int64.max { return nowMs >= 0 }
        let minimum = finalValidationReserveMs > 0 ? Self.minimumExplorationWindowMs : 1
        return nowMs >= 0 && explorationDeadlineMs - nowMs >= minimum
    }

    @discardableResult
    public mutating func consumeCalls(_ count: Int = 1, nowMs: Int64) -> Bool {
        guard count > 0, !textViolated, nowMs < activeDeadlineMs, calls <= activeCallLimit - count else {
            return false
        }
        calls += count
        return true
    }

    @discardableResult
    public mutating func consumeText(_ units: Int, requested: Int? = nil) -> Bool {
        guard !textViolated else { return false }
        guard units >= 0,
              requested.map({ $0 >= 0 && units <= $0 }) != false,
              units <= maxTextUnits - textUnits else {
            textViolated = true
            textUnits = maxTextUnits + 1
            return false
        }
        textUnits += units
        return true
    }

    public mutating func beginFinalValidation() {
        isFinalValidation = true
    }
}

public enum AXActivationMode: String, Codable, Equatable, Sendable {
    case none
    case manualAccessibility = "manual"
    case enhancedUI = "enhanced"
}

public enum WindowAnchorPolicy: String, Codable, Equatable, Sendable {
    case focusedOnly
    case allowTopLevelFallback
    case allowUnfocusedWindow

    public var allowsTopLevelFallback: Bool {
        self == .allowTopLevelFallback || self == .allowUnfocusedWindow
    }

    public var allowsUnfocusedWindow: Bool {
        self == .allowUnfocusedWindow
    }
}

public enum StaticTextPolicy: Equatable, Sendable {
    case standard
    case boundedRangeProbe(maxUnits: Int)
}

/// Declarative adapter specification covering standard per-app AX differences.
public struct AppAdapterSpec: Equatable, Sendable {
    public let id: String
    public let displayName: String
    public let matchBundleIds: Set<String>
    public let activation: AXActivationMode
    public let windowAnchor: WindowAnchorPolicy
    public let staticTextProbe: StaticTextPolicy
    public let preferredRoles: Set<String>
    public let ignoredRoles: Set<String>
    public let ignoredSubroles: Set<String>
    public let pageSize: Int
    public let maxNodeTextUnits: Int
    public let blockPrivateWindows: Bool
    public let collapseEmptyContainers: Bool

    public init(
        id: String,
        displayName: String,
        matchBundleIds: Set<String> = [],
        activation: AXActivationMode = .none,
        windowAnchor: WindowAnchorPolicy = .focusedOnly,
        staticTextProbe: StaticTextPolicy = .standard,
        preferredRoles: Set<String> = [],
        ignoredRoles: Set<String> = [],
        ignoredSubroles: Set<String> = [],
        pageSize: Int = 8,
        maxNodeTextUnits: Int = 128,
        blockPrivateWindows: Bool = false,
        collapseEmptyContainers: Bool = false
    ) {
        self.id = id
        self.displayName = displayName
        self.matchBundleIds = matchBundleIds
        self.activation = activation
        self.windowAnchor = windowAnchor
        self.staticTextProbe = staticTextProbe
        self.preferredRoles = preferredRoles
        self.ignoredRoles = ignoredRoles
        self.ignoredSubroles = ignoredSubroles
        self.pageSize = min(64, max(1, pageSize))
        self.maxNodeTextUnits = min(8192, max(1, maxNodeTextUnits))
        self.blockPrivateWindows = blockPrivateWindows
        self.collapseEmptyContainers = collapseEmptyContainers
    }
}

/// Bounded display text extraction from pre-fetched non-sensitive AX metadata.
public enum SafeAXDisplayText {
    public static let allowedRoles: Set<String> = [
        "AXHeading",
        "AXLink",
        "AXButton",
        "AXTabButton",
        "AXRadioButton",
        "AXCell",
        "AXWebArea",
    ]

    public static func compose(
        role: String,
        title: String?,
        description: String?,
        url: String?,
        maxUnits: Int
    ) -> String? {
        guard allowedRoles.contains(role), maxUnits > 0 else { return nil }
        let cleanTitle = clean(title)
        let cleanDescription = clean(description)
        let cleanURL = clean(url)
        let raw: String?
        switch role {
        case "AXWebArea":
            if let cleanTitle, let cleanURL {
                raw = cleanTitle.contains(cleanURL) ? cleanTitle : "\(cleanTitle) (\(cleanURL))"
            } else {
                raw = cleanTitle ?? cleanURL ?? cleanDescription
            }
        case "AXLink":
            let label = cleanTitle ?? cleanDescription
            if let label, let cleanURL, label != cleanURL {
                raw = "\(label) (\(cleanURL))"
            } else {
                raw = label ?? cleanURL
            }
        default:
            raw = cleanTitle ?? cleanDescription ?? cleanURL
        }
        guard let raw, !raw.isEmpty else { return nil }
        let length = min(raw.utf16.count, maxUnits)
        guard let bounded = boundedUTF16Slice(raw, start: 0, length: length), !bounded.isEmpty else { return nil }
        return bounded
    }

    /// Bounded non-sensitive label (`title ?? description`) excluding pure PUA icon glyphs.
    public static func label(
        title: String?,
        description: String?,
        maxUnits: Int
    ) -> String? {
        guard maxUnits > 0, let raw = clean(title) ?? clean(description) else { return nil }
        let length = min(raw.utf16.count, maxUnits)
        guard let bounded = boundedUTF16Slice(raw, start: 0, length: length), !bounded.isEmpty else { return nil }
        return bounded
    }

    private static func clean(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty,
              !isPrivateUseOnlyText(trimmed) else {
            return nil
        }
        return trimmed
    }
}

public struct AXNodeHandle: Hashable, Sendable {
    public let index: Int
    public init(index: Int) { self.index = index }
}

public struct AXNodeInfo: Equatable, Sendable {
    public let handle: AXNodeHandle
    public let role: String
    public let subrole: String?
    public let childCount: Int
    public let isFocused: Bool
    public let observedAtMs: Int64
    public let identifier: String?
    public let label: String?

    public init(
        handle: AXNodeHandle,
        role: String,
        childCount: Int,
        isFocused: Bool,
        observedAtMs: Int64,
        identifier: String? = nil,
        subrole: String? = nil,
        label: String? = nil
    ) {
        self.handle = handle
        self.role = role
        self.subrole = subrole
        self.childCount = childCount
        self.isFocused = isFocused
        self.observedAtMs = observedAtMs
        self.identifier = identifier
        self.label = label
    }
}

public struct CustomSurfaceNode: Equatable, Sendable {
    public let handle: AXNodeHandle
    public let parent: AXNodeHandle?
    public let role: String
    public let axRole: String?
    public let text: String?
    public let isFocused: Bool
    public let observedAtMs: Int64
    public let bounds: SurfaceBounds?
    public let boundsObservedAtMs: Int64?

    public init(
        handle: AXNodeHandle,
        parent: AXNodeHandle? = nil,
        role: String,
        axRole: String? = nil,
        text: String? = nil,
        isFocused: Bool = false,
        observedAtMs: Int64,
        bounds: SurfaceBounds? = nil,
        boundsObservedAtMs: Int64? = nil
    ) {
        self.handle = handle
        self.parent = parent
        self.role = role
        self.axRole = axRole
        self.text = text
        self.isFocused = isFocused
        self.observedAtMs = observedAtMs
        self.bounds = bounds
        self.boundsObservedAtMs = boundsObservedAtMs
    }
}

public struct CustomSurfaceResult: Equatable, Sendable {
    public let nodes: [CustomSurfaceNode]
    public let complete: Bool
    public let missingReasons: [String]

    public init(nodes: [CustomSurfaceNode], complete: Bool = false, missingReasons: [String] = []) {
        self.nodes = nodes
        self.complete = complete
        self.missingReasons = missingReasons
    }
}

/// Pluggable application adapter: pure declarative `spec` by default, optional custom `extractSurface`.
public protocol AppAdapter: Sendable {
    var spec: AppAdapterSpec { get }
    func extractSurface(context: SafeAXContext) -> CustomSurfaceResult?
}

public extension AppAdapter {
    func extractSurface(context: SafeAXContext) -> CustomSurfaceResult? { nil }
}

/// Registry matching exact bundle IDs case-insensitively and falling back to `GenericAdapter`.
public struct AppAdapterRegistry: Sendable {
    public static let shared = AppAdapterRegistry()

    public let adapters: [any AppAdapter]
    public let fallback: any AppAdapter
    private let byBundleId: [String: any AppAdapter]

    public init(adapters: [any AppAdapter] = BuiltInAdapters.specialized, fallback: any AppAdapter = GenericAdapter()) {
        self.adapters = adapters
        self.fallback = fallback
        var table: [String: any AppAdapter] = [:]
        for adapter in adapters {
            for bundleId in adapter.spec.matchBundleIds {
                let normalized = bundleId.lowercased()
                if table[normalized] == nil {
                    table[normalized] = adapter
                }
            }
        }
        self.byBundleId = table
    }

    public func adapter(for bundleId: String) -> any AppAdapter {
        byBundleId[bundleId.lowercased()] ?? fallback
    }
}

public enum AXBackendInspection {
    case allowed(
        role: String,
        subrole: TextSecurityGate.SubroleRead,
        protectedContent: TextSecurityGate.ProtectedContentRead,
        childCount: Int,
        isFocused: Bool,
        observedAtMs: Int64,
        isEnabled: Bool? = nil,
        displayText: String? = nil,
        windowTitle: String? = nil,
        absoluteRect: SurfaceAbsoluteRect? = nil,
        identifier: String? = nil,
        label: String? = nil
    )
    case pruned(WeightedSurfaceTraversalReason)
    case fatal(SurfaceReadFailure)
}

public enum AXBackendTextRead {
    case text(value: String, complete: Bool, reasons: [String])
    case unavailable(reasons: [String])
    case fatal(SurfaceReadFailure)
}

/// Platform backend supplying raw element observations behind `SafeAXContext` invariants.
public protocol AXSurfaceBackend: AnyObject {
    func bindSurfaceContext(_ context: SafeAXContext?)
    func verifyDesktopAndApplication() -> SurfaceReadFailure?
    func inspectBackendNode(_ index: Int, isRoot: Bool) -> AXBackendInspection
    func parentBackendNode(of index: Int) -> Int?
    func childrenBackendPage(of index: Int, expectedRole: String, offset: Int, limit: Int) -> WeightedSurfaceChildrenRead<Int>
    func readBackendNodeText(_ index: Int, expectedRole: String, maxUnits: Int, staticTextProbe: StaticTextPolicy) -> AXBackendTextRead
    func readBackendNodeBounds(_ index: Int, windowRect: SurfaceAbsoluteRect) -> (SurfaceBounds, Int64)?
    func readBackendWindowRect() -> SurfaceAbsoluteRect?
    func verifyFinalSurfaceBoundary() -> SurfaceReadFailure?
    func resolveRegionParentRoot() -> Int?
}

public extension AXSurfaceBackend {
    func bindSurfaceContext(_ context: SafeAXContext?) {}
    func resolveRegionParentRoot() -> Int? { nil }
}

/// Kernel-enforced AX execution context. No adapter can bypass app denylist, desktop/Secure Input,
/// password/protected field blocking, or `ReadBudget` limits.
public final class SafeAXContext {
    public let application: ApplicationIdentity
    public let policy: CapturePolicy
    public let spec: AppAdapterSpec
    public let scope: String
    public let maxOutputNodes: Int
    public private(set) var root: AXNodeHandle
    public let focus: AXNodeHandle?
    public private(set) var budget: ReadBudget
    public let clock: CollectorClock

    private unowned let backend: AXSurfaceBackend
    private var callCeilingOverride: Int?
    private var deadlineOverrideMs: Int64?
    fileprivate private(set) var abortFailure: SurfaceReadFailure?
    fileprivate private(set) var extraReasons = Set<String>()
    fileprivate private(set) var inspectedNodes: [AXNodeHandle: AXNodeInfo] = [:]
    fileprivate private(set) var sampledBounds: [AXNodeHandle: (SurfaceBounds, Int64)] = [:]
    fileprivate private(set) var chargedDisplayText: [AXNodeHandle: String] = [:]
    fileprivate var initialWindowRect: SurfaceAbsoluteRect?

    public init(
        application: ApplicationIdentity,
        policy: CapturePolicy,
        spec: AppAdapterSpec,
        scope: String,
        maxOutputNodes: Int = 96,
        root: AXNodeHandle = AXNodeHandle(index: 0),
        focus: AXNodeHandle? = nil,
        budget: ReadBudget,
        clock: CollectorClock,
        backend: AXSurfaceBackend
    ) {
        self.application = application
        self.policy = policy
        self.spec = spec
        self.scope = scope
        self.maxOutputNodes = min(96, max(1, maxOutputNodes))
        self.root = root
        self.focus = focus
        self.budget = budget
        self.clock = clock
        self.backend = backend
    }

    public var isAborted: Bool { abortFailure != nil }

    public var effectiveDeadlineMs: Int64 {
        min(budget.activeDeadlineMs, deadlineOverrideMs ?? Int64.max)
    }

    public var canContinue: Bool {
        guard abortFailure == nil, !budget.textViolated else { return false }
        let now = clock.monotonicMs
        let limit = min(budget.activeCallLimit, callCeilingOverride ?? Int.max)
        return now < effectiveDeadlineMs && budget.calls < limit
    }

    @discardableResult
    public func recordBackendCalls(_ count: Int = 1) -> Bool {
        guard abortFailure == nil, !budget.textViolated else { return false }
        let now = clock.monotonicMs
        guard now < effectiveDeadlineMs else {
            if !budget.isFinalValidation { extraReasons.insert("tree-time-budget") }
            return false
        }
        if let ceiling = callCeilingOverride, budget.calls + count > ceiling {
            return false
        }
        let ok = budget.consumeCalls(count, nowMs: now)
        if !ok && !budget.isFinalValidation {
            extraReasons.insert("tree-call-budget")
        }
        return ok
    }

    @discardableResult
    public func recordBackendText(_ units: Int, requested: Int? = nil) -> Bool {
        let ok = budget.consumeText(units, requested: requested)
        if !ok { abort(.boundaryUnverified) }
        return ok
    }

    private func verifyKernelGates() -> Bool {
        guard abortFailure == nil, !budget.textViolated else { return false }
        guard policy.enabled,
              ApplicationPolicy.allows(application.applicationId, policy: policy),
              BrowserGate.allows(application.applicationId, policy: policy) else {
            abort(.securityExcluded)
            return false
        }
        if let failure = backend.verifyDesktopAndApplication() {
            abort(failure)
            return false
        }
        return true
    }

    fileprivate func abort(_ failure: SurfaceReadFailure) {
        var diagnostics = SurfaceReadDiagnostics()
        if let existing = abortFailure { diagnostics.note(existing) }
        diagnostics.note(failure)
        abortFailure = diagnostics.failure ?? failure
        inspectedNodes.removeAll()
        sampledBounds.removeAll()
        chargedDisplayText.removeAll()
    }

    fileprivate func withPreparationWindow<T>(maxCalls: Int, maxDurationMs: Int64, _ body: () -> T) -> T {
        let savedCeiling = callCeilingOverride
        let savedDeadline = deadlineOverrideMs
        let now = clock.monotonicMs
        callCeilingOverride = min(budget.activeCallLimit, budget.calls + max(0, maxCalls))
        deadlineOverrideMs = min(budget.activeDeadlineMs, now + max(0, maxDurationMs))
        defer {
            callCeilingOverride = savedCeiling
            deadlineOverrideMs = savedDeadline
        }
        return body()
    }

    fileprivate func promoteRegionRootIfApplicable() {
        guard scope == "region", inspectedNodes.isEmpty, verifyKernelGates(), canContinue else { return }
        let before = budget.calls
        if let parentIndex = backend.resolveRegionParentRoot() {
            if budget.calls == before { _ = recordBackendCalls(1) }
            root = AXNodeHandle(index: parentIndex)
        }
    }

    fileprivate func sampleWindowRect() -> SurfaceAbsoluteRect? {
        guard verifyKernelGates(), canContinue else { return nil }
        let before = budget.calls
        let rect = backend.readBackendWindowRect()
        if budget.calls == before { _ = recordBackendCalls(1) }
        return abortFailure == nil ? rect : nil
    }

    fileprivate func beginFinalValidation() {
        callCeilingOverride = nil
        deadlineOverrideMs = nil
        budget.beginFinalValidation()
    }

    public func inspect(_ node: AXNodeHandle) -> AXNodeInfo? {
        switch inspectForTraversal(node) {
        case .allowed:
            return inspectedNodes[node]
        case .pruned:
            return nil
        }
    }

    fileprivate func inspectForTraversal(_ node: AXNodeHandle) -> WeightedSurfaceInspection {
        guard verifyKernelGates() else { return .pruned(.securityPruned) }
        guard canContinue else {
            return .pruned(clock.monotonicMs >= effectiveDeadlineMs ? .timeBudget : .workBudget)
        }
        let isRoot = node == root
        let before = budget.calls
        let outcome = backend.inspectBackendNode(node.index, isRoot: isRoot)
        if budget.calls == before, !recordBackendCalls(1) {
            return .pruned(.workBudget)
        }
        switch outcome {
        case .fatal(let failure):
            abort(failure)
            return .pruned(.securityPruned)
        case .pruned(let reason):
            return .pruned(reason)
        case let .allowed(role, subrole, protectedContent, childCount, isFocused, observedAtMs, isEnabled, displayText, windowTitle, absoluteRect, identifier, label):
            if role == "AXSecureTextField" || protectedContent == .value(true) {
                if isRoot || node == focus { abort(.securityExcluded) }
                return .pruned(.securityPruned)
            }
            if case .value(let sub) = subrole, TextSecurityGate.isSensitiveSubrole(sub) {
                if isRoot || node == focus { abort(.securityExcluded) }
                return .pruned(.securityPruned)
            }
            guard TextSecurityGate.mayTraverse(subrole: subrole, protectedContent: protectedContent) else {
                if isRoot { abort(.boundaryUnverified) }
                return .pruned(.securityPruned)
            }
            if isRoot,
               BrowserGate.shouldBlockPrivateWindows(applicationId: application.applicationId, spec: spec),
               let title = windowTitle,
               BrowserGate.isPrivateWindowTitle(title) {
                abort(.securityExcluded)
                return .pruned(.securityPruned)
            }
            let safeSubrole: String?
            if case .value(let sub) = subrole, !sub.isEmpty {
                safeSubrole = sub
            } else {
                safeSubrole = nil
            }
            if !isRoot, !isFocused,
               spec.ignoredRoles.contains(role)
                || (safeSubrole.map { spec.ignoredSubroles.contains($0) } ?? false) {
                return .pruned(.unsupportedRole)
            }
            var boundedDisplayText: String? = chargedDisplayText[node]
            if boundedDisplayText == nil,
               let raw = displayText,
               !raw.isEmpty,
               !isPrivateUseOnlyText(raw),
               SafeAXDisplayText.allowedRoles.contains(role) {
                let cap = min(spec.maxNodeTextUnits, budget.remainingTextUnits)
                if cap > 0,
                   let sliced = boundedUTF16Slice(raw, start: 0, length: min(raw.utf16.count, cap)),
                   !sliced.isEmpty {
                    if budget.consumeText(sliced.utf16.count, requested: cap) {
                        boundedDisplayText = sliced
                        chargedDisplayText[node] = sliced
                    }
                } else if cap == 0 {
                    extraReasons.insert("text-budget")
                }
            }
            let safeLabel = SafeAXDisplayText.label(
                title: label,
                description: boundedDisplayText,
                maxUnits: spec.maxNodeTextUnits
            )
            var relativeBounds: SurfaceBounds?
            if let rect = absoluteRect,
               let windowRect = initialWindowRect,
               let relative = rect.relative(to: windowRect) {
                sampledBounds[node] = (relative, observedAtMs)
                relativeBounds = relative
            }
            let info = AXNodeInfo(
                handle: node,
                role: role,
                childCount: childCount,
                isFocused: isFocused,
                observedAtMs: observedAtMs,
                identifier: identifier,
                subrole: safeSubrole,
                label: safeLabel
            )
            inspectedNodes[node] = info
            return .allowed(WeightedSurfaceMetadata(
                role: role,
                childCount: childCount,
                isFocused: isFocused,
                observedAtMs: observedAtMs,
                isEnabled: isEnabled,
                displayText: boundedDisplayText,
                bounds: relativeBounds,
                subrole: safeSubrole
            ))
        }
    }

    public func parent(of node: AXNodeHandle) -> AXNodeHandle? {
        guard verifyKernelGates(), canContinue else { return nil }
        let before = budget.calls
        guard let parentIndex = backend.parentBackendNode(of: node.index) else {
            if budget.calls == before { _ = recordBackendCalls(1) }
            return nil
        }
        if budget.calls == before, !recordBackendCalls(1) { return nil }
        return abortFailure == nil ? AXNodeHandle(index: parentIndex) : nil
    }

    public func children(of node: AXNodeHandle, offset: Int = 0, limit: Int? = nil) -> [AXNodeHandle]? {
        switch childrenForTraversal(of: node, offset: offset, limit: limit ?? spec.pageSize) {
        case .values(let handles): return handles
        case .unavailable: return nil
        }
    }

    fileprivate func childrenForTraversal(of node: AXNodeHandle, offset: Int, limit: Int) -> WeightedSurfaceChildrenRead<AXNodeHandle> {
        guard verifyKernelGates() else { return .unavailable(.securityPruned) }
        guard offset >= 0, limit > 0 else { return .unavailable(.inconsistentChildren) }
        guard canContinue else {
            return .unavailable(clock.monotonicMs >= effectiveDeadlineMs ? .timeBudget : .workBudget)
        }
        let expectedInfo: AXNodeInfo
        if let cached = inspectedNodes[node] {
            expectedInfo = cached
        } else if let fresh = inspect(node) {
            expectedInfo = fresh
        } else {
            return .unavailable(.securityPruned)
        }
        let clampedLimit = min(64, limit)
        let before = budget.calls
        let page = backend.childrenBackendPage(of: node.index, expectedRole: expectedInfo.role, offset: offset, limit: clampedLimit)
        if budget.calls == before, !recordBackendCalls(1) {
            return .unavailable(.workBudget)
        }
        if abortFailure != nil { return .unavailable(.securityPruned) }
        switch page {
        case .unavailable(let reason):
            return .unavailable(reason)
        case .values(let rawHandles):
            guard rawHandles.count <= clampedLimit else { return .unavailable(.inconsistentChildren) }
            return .values(rawHandles.map(AXNodeHandle.init(index:)))
        }
    }

    public func text(of node: AXNodeHandle, maxUnits: Int? = nil) -> String? {
        readText(of: node, maxUnits: maxUnits)?.text
    }

    public func readText(of node: AXNodeHandle, maxUnits: Int? = nil) -> (text: String, complete: Bool, reasons: [String])? {
        guard verifyKernelGates(), canContinue else { return nil }
        let beforeInspectCalls = budget.calls
        let check = backend.inspectBackendNode(node.index, isRoot: node == root)
        if budget.calls == beforeInspectCalls, !recordBackendCalls(1) { return nil }

        let verifiedRole: String
        let subrole: TextSecurityGate.SubroleRead
        let protectedContent: TextSecurityGate.ProtectedContentRead
        let childCount: Int
        let isFocused: Bool
        let observedAtMs: Int64
        let freshAbsoluteRect: SurfaceAbsoluteRect?
        let freshIdentifier: String?
        let freshLabel: String?
        switch check {
        case .fatal(let failure):
            abort(failure)
            return nil
        case .pruned(let reason):
            switch reason {
            case .workBudget: extraReasons.insert("tree-call-budget")
            case .timeBudget: extraReasons.insert("tree-time-budget")
            case .securityPruned: extraReasons.insert("node-security-excluded")
            default: extraReasons.insert("node-text-unavailable")
            }
            return nil
        case let .allowed(r, sub, prot, count, focused, observed, _, _, windowTitle, absoluteRect, identifier, label):
            if node == root,
               BrowserGate.shouldBlockPrivateWindows(applicationId: application.applicationId, spec: spec),
               let title = windowTitle,
               BrowserGate.isPrivateWindowTitle(title) {
                abort(.securityExcluded)
                return nil
            }
            verifiedRole = r
            subrole = sub
            protectedContent = prot
            childCount = count
            isFocused = focused
            observedAtMs = observed
            freshAbsoluteRect = absoluteRect
            freshIdentifier = identifier
            freshLabel = label
        }

        let security = TextSecurityGate.classifyMetadata(
            role: verifiedRole,
            subrole: subrole,
            protectedContent: protectedContent,
            policy: policy
        )
        if security == .sensitive {
            if node == root || node == focus { abort(.securityExcluded) }
            extraReasons.insert("node-security-excluded")
            return nil
        }
        if let prior = inspectedNodes[node], prior.role != verifiedRole {
            if node == root { abort(.boundaryMismatch) }
            else { extraReasons.insert("node-role-changed") }
            return nil
        }
        guard ["AXTextField", "AXTextArea", "AXStaticText"].contains(verifiedRole),
              policy.allows(security) else {
            extraReasons.insert("node-security-excluded")
            return nil
        }
        let safeSubrole: String?
        if case .value(let sub) = subrole, !sub.isEmpty {
            safeSubrole = sub
        } else {
            safeSubrole = nil
        }
        let safeLabel = SafeAXDisplayText.label(
            title: freshLabel,
            description: chargedDisplayText[node],
            maxUnits: spec.maxNodeTextUnits
        )
        inspectedNodes[node] = AXNodeInfo(
            handle: node,
            role: verifiedRole,
            childCount: childCount,
            isFocused: isFocused,
            observedAtMs: observedAtMs,
            identifier: freshIdentifier,
            subrole: safeSubrole,
            label: safeLabel
        )

        let nodeLimit = min(maxUnits ?? (scope == "window" ? spec.maxNodeTextUnits : budget.maxTextUnits), budget.remainingTextUnits)
        guard nodeLimit > 0 else {
            extraReasons.insert("text-budget")
            return nil
        }
        guard canContinue else { return nil }

        let beforeCalls = budget.calls
        let beforeText = budget.textUnits
        let result = backend.readBackendNodeText(
            node.index,
            expectedRole: verifiedRole,
            maxUnits: nodeLimit,
            staticTextProbe: spec.staticTextProbe
        )
        if budget.calls == beforeCalls, !recordBackendCalls(1) { return nil }

        switch result {
        case .fatal(let failure):
            abort(failure)
            return nil
        case .unavailable(let reasons):
            extraReasons.formUnion(reasons)
            return nil
        case let .text(value, complete, reasons):
            if budget.textUnits == beforeText {
                guard recordBackendText(value.utf16.count, requested: nodeLimit) else { return nil }
            } else if value.utf16.count > nodeLimit || budget.textViolated {
                abort(.boundaryUnverified)
                return nil
            }
            guard verifyKernelGates() else { return nil }
            extraReasons.formUnion(reasons)
            if let windowRect = initialWindowRect, canContinue {
                if let rect = freshAbsoluteRect, let relative = rect.relative(to: windowRect) {
                    sampledBounds[node] = (relative, observedAtMs)
                } else {
                    let beforeBoundsCalls = budget.calls
                    if let sampled = backend.readBackendNodeBounds(node.index, windowRect: windowRect) {
                        if budget.calls == beforeBoundsCalls { _ = recordBackendCalls(1) }
                        sampledBounds[node] = sampled
                    } else {
                        extraReasons.insert("geometry-unavailable")
                    }
                }
            }
            return (value, complete, reasons)
        }
    }

    /// Returns already-charged display text (such as `AXWebArea` title + URL) or charges
    /// and bounds the node's pre-fetched, security-gated `label` against `ReadBudget`.
    public func displayText(of node: AXNodeHandle, maxUnits: Int? = nil) -> String? {
        guard abortFailure == nil, !budget.textViolated else { return nil }
        if let existing = chargedDisplayText[node] {
            return existing
        }
        guard let raw = inspectedNodes[node]?.label, !raw.isEmpty else { return nil }
        let cap = min(maxUnits ?? spec.maxNodeTextUnits, budget.remainingTextUnits)
        guard cap > 0 else {
            extraReasons.insert("text-budget")
            return nil
        }
        guard let sliced = boundedUTF16Slice(raw, start: 0, length: min(raw.utf16.count, cap)),
              !sliced.isEmpty else { return nil }
        guard budget.consumeText(sliced.utf16.count, requested: cap) else {
            abort(.boundaryUnverified)
            return nil
        }
        chargedDisplayText[node] = sliced
        return sliced
    }

    public func bounds(of node: AXNodeHandle) -> (bounds: SurfaceBounds, observedAtMs: Int64)? {
        if let cached = sampledBounds[node] {
            return (cached.0, cached.1)
        }
        guard let windowRect = initialWindowRect, verifyKernelGates(), canContinue, inspectedNodes[node] != nil else {
            return nil
        }
        let before = budget.calls
        guard let sampled = backend.readBackendNodeBounds(node.index, windowRect: windowRect) else {
            extraReasons.insert("geometry-unavailable")
            return nil
        }
        if budget.calls == before, !recordBackendCalls(1) { return nil }
        sampledBounds[node] = sampled
        return (sampled.0, sampled.1)
    }

    fileprivate func noteExtraReason(_ reason: String) {
        extraReasons.insert(reason)
    }
}

public struct SurfaceCapturedTree: Equatable {
    public let nodes: [SurfaceNodeRead]
    public let handles: [(String, Int)]
    public let geometry: SurfaceGeometry?
    public let complete: Bool
    public let truncated: Bool
    public let reasons: [String]
    public let adapterId: String

    public static func == (lhs: SurfaceCapturedTree, rhs: SurfaceCapturedTree) -> Bool {
        lhs.nodes == rhs.nodes &&
            lhs.handles.map(\.0) == rhs.handles.map(\.0) &&
            lhs.handles.map(\.1) == rhs.handles.map(\.1) &&
            lhs.geometry == rhs.geometry &&
            lhs.complete == rhs.complete &&
            lhs.truncated == rhs.truncated &&
            lhs.reasons == rhs.reasons &&
            lhs.adapterId == rhs.adapterId
    }
}

public enum SurfaceCaptureOutcome: Equatable {
    case success(SurfaceCapturedTree)
    case failure(SurfaceReadFailure)
}

/// Shared surface capture runner enforcing kernel gates before, during, and after adapter execution.
public enum SurfaceCaptureRunner {
    public static func run(
        adapter: any AppAdapter,
        application: ApplicationIdentity,
        policy: CapturePolicy,
        scope: String,
        maxOutputNodes: Int,
        focus: AXNodeHandle?,
        budget: ReadBudget,
        clock: CollectorClock,
        backend: AXSurfaceBackend
    ) -> SurfaceCaptureOutcome {
        guard policy.enabled,
              ApplicationPolicy.allows(application.applicationId, policy: policy),
              BrowserGate.allows(application.applicationId, policy: policy) else {
            return .failure(.securityExcluded)
        }
        let clampedMaxNodes = min(96, max(1, maxOutputNodes))
        guard budget.hasExplorationHeadroom(nowMs: clock.monotonicMs) else {
            return .failure(.notStartedBudget)
        }
        if let preflightFailure = backend.verifyDesktopAndApplication() {
            return .failure(preflightFailure)
        }

        let context = SafeAXContext(
            application: application,
            policy: policy,
            spec: adapter.spec,
            scope: scope,
            maxOutputNodes: clampedMaxNodes,
            root: AXNodeHandle(index: 0),
            focus: focus,
            budget: budget,
            clock: clock,
            backend: backend
        )
        backend.bindSurfaceContext(context)
        defer { backend.bindSurfaceContext(nil) }
        if scope == "window",
           BrowserGate.shouldBlockPrivateWindows(applicationId: application.applicationId, spec: adapter.spec) {
            _ = context.inspectForTraversal(context.root)
            if let failure = context.abortFailure {
                return .failure(failure)
            }
        }
        context.promoteRegionRootIfApplicable()
        context.initialWindowRect = context.sampleWindowRect()
        if context.initialWindowRect == nil {
            context.noteExtraReason("geometry-unavailable")
        }
        if let failure = context.abortFailure {
            return .failure(failure)
        }

        let extractedNodes: [CustomSurfaceNode]
        let extractionComplete: Bool
        var reasons = Set<String>()

        if let custom = adapter.extractSurface(context: context) {
            if let failure = context.abortFailure { return .failure(failure) }
            guard !context.budget.textViolated,
                  validateCustomResult(custom, context: context, maxOutputNodes: clampedMaxNodes) else {
                return .failure(.boundaryUnverified)
            }
            extractedNodes = custom.nodes
            extractionComplete = custom.complete
            reasons.formUnion(custom.missingReasons)
        } else {
            let limits = WeightedSurfaceTraversalLimits(
                maxOutputNodes: clampedMaxNodes,
                pageSize: adapter.spec.pageSize
            )
            var anchorPlan: SurfaceFocusAnchorPlan<AXNodeHandle>?
            var prepWork = 0
            var prepProbes = 0
            if scope == "window", let focusHandle = context.focus {
                let now = clock.monotonicMs
                let prepDuration = context.budget.explorationDeadlineMs == Int64.max
                    ? 160
                    : min(160, max(0, (context.budget.explorationDeadlineMs - now) / 3))
                let prepCalls = min(192, context.budget.remainingCalls / 4)
                if prepCalls >= 4, prepDuration > 0 {
                    let prep = context.withPreparationWindow(maxCalls: prepCalls, maxDurationMs: prepDuration) {
                        SurfaceFocusAnchors.collect(
                            root: context.root,
                            focus: focusHandle,
                            maxHops: SurfaceFocusAnchors.maximumHops,
                            maxWork: min(SurfaceFocusAnchors.maximumWork, limits.maxWork / 2),
                            maxProbes: min(SurfaceFocusAnchors.maximumProbes, limits.maxProbes / 4),
                            inspect: { handle in
                                let res = context.inspectForTraversal(handle)
                                if case .allowed(let meta) = res,
                                   handle != focusHandle,
                                   WeightedSurfaceTraversal.rolePolicy(for: meta.role)?.readsText == true {
                                    return .pruned(.unsupportedRole)
                                }
                                return res
                            },
                            parent: { context.parent(of: $0) },
                            shouldContinue: { context.canContinue }
                        )
                    }
                    anchorPlan = prep.plan
                    prepWork = prep.work
                    prepProbes = prep.probes
                }
            }
            if let failure = context.abortFailure { return .failure(failure) }

            let walked = WeightedSurfaceTraversal.run(
                root: context.root,
                limits: limits,
                preferredRoles: adapter.spec.preferredRoles,
                ignoredRoles: adapter.spec.ignoredRoles,
                ignoredSubroles: adapter.spec.ignoredSubroles,
                collapseEmptyContainers: adapter.spec.collapseEmptyContainers,
                preparationWork: prepWork,
                preparationProbes: prepProbes,
                focusAnchors: anchorPlan,
                inspect: { context.inspectForTraversal($0) },
                children: { context.childrenForTraversal(of: $0, offset: $1, limit: $2) },
                text: { handle in
                    guard let info = context.inspectedNodes[handle],
                          let read = context.readText(of: handle) else { return nil }
                    let mappedRole = info.role == "AXStaticText" ? "text" : "editable"
                    return SurfaceNodeRead(
                        id: "sample-\(handle.index)",
                        role: mappedRole,
                        text: read.text,
                        observedAtMs: clock.unixMs
                    )
                },
                shouldContinue: { context.canContinue },
                shouldContinueAfterWork: { !context.isAborted && !context.budget.textViolated && clock.monotonicMs < context.effectiveDeadlineMs }
            )
            if let failure = context.abortFailure { return .failure(failure) }
            guard !context.budget.textViolated else { return .failure(.boundaryUnverified) }

            extractedNodes = walked.nodes.map { sample in
                let boundsEntry = context.sampledBounds[sample.handle]
                let nodeText = sample.textRead?.text ?? sample.metadata.displayText
                let wireRole: String
                if let textRead = sample.textRead {
                    wireRole = textRead.role
                } else if sample.metadata.role == "AXStaticText" || sample.metadata.role == "AXHeading" {
                    wireRole = "text"
                } else if WeightedSurfaceTraversal.rolePolicy(for: sample.metadata.role)?.readsText == true {
                    wireRole = "editable"
                } else {
                    wireRole = "container"
                }
                return CustomSurfaceNode(
                    handle: sample.handle,
                    parent: sample.parent,
                    role: wireRole,
                    axRole: sample.metadata.role,
                    text: nodeText,
                    isFocused: sample.metadata.isFocused,
                    observedAtMs: sample.textRead?.observedAtMs ?? sample.metadata.observedAtMs,
                    bounds: boundsEntry?.0,
                    boundsObservedAtMs: boundsEntry?.1
                )
            }
            extractionComplete = walked.complete
            reasons.formUnion(walked.reasons.map(\.rawValue))
        }

        reasons.formUnion(context.extraReasons)
        if context.budget.remainingCalls == 0 { reasons.insert("tree-call-budget") }
        if clock.monotonicMs >= context.budget.explorationDeadlineMs { reasons.insert("tree-time-budget") }

        // Final kernel validation phase using reserved calls and time.
        context.beginFinalValidation()
        var geometry: SurfaceGeometry?
        if let initialRect = context.initialWindowRect, context.budget.remainingCalls >= 8 {
            let finalRect = context.sampleWindowRect()
            if let failure = context.abortFailure { return .failure(failure) }
            geometry = initialRect.geometry(ifUnchanged: finalRect, observedAtMs: clock.unixMs)
            if geometry == nil {
                reasons.insert(finalRect == nil ? "geometry-unavailable" : "geometry-window-moved")
            }
        }
        if let desktopFailure = backend.verifyDesktopAndApplication() {
            return .failure(desktopFailure)
        }
        if let boundaryFailure = backend.verifyFinalSurfaceBoundary() {
            return .failure(boundaryFailure)
        }
        guard clock.monotonicMs < context.budget.deadlineMs else {
            return .failure(.timeBudget)
        }

        let idsByHandle = Dictionary(uniqueKeysWithValues: extractedNodes.map { ($0.handle, "sample-\($0.handle.index)") })
        let nodes = extractedNodes.map { item -> SurfaceNodeRead in
            SurfaceNodeRead(
                id: idsByHandle[item.handle]!,
                parentId: item.parent.flatMap { idsByHandle[$0] },
                role: item.role,
                text: item.text,
                observedAtMs: item.observedAtMs,
                bounds: geometry == nil ? nil : item.bounds,
                boundsObservedAtMs: geometry == nil ? nil : item.boundsObservedAtMs,
                axRole: item.axRole,
                focused: item.isFocused
            )
        }
        let complete = extractionComplete && reasons.isEmpty
        if !complete { reasons.insert("bounded-ax-tree") }
        let orderedReasons = complete
            ? []
            : ["bounded-ax-tree"] + reasons.filter { $0 != "bounded-ax-tree" }.sorted().prefix(15)

        return .success(SurfaceCapturedTree(
            nodes: nodes,
            handles: extractedNodes.map { (idsByHandle[$0.handle]!, $0.handle.index) },
            geometry: geometry,
            complete: complete,
            truncated: !complete,
            reasons: Array(orderedReasons),
            adapterId: adapter.spec.id
        ))
    }

    private static func validateCustomResult(_ result: CustomSurfaceResult, context: SafeAXContext, maxOutputNodes: Int) -> Bool {
        guard result.nodes.count <= maxOutputNodes, result.nodes.count <= 96 else { return false }
        let validRoles: Set<String> = ["text", "editable", "container", "terminal", "other"]
        var byHandle: [AXNodeHandle: CustomSurfaceNode] = [:]
        var focusCount = 0
        for node in result.nodes {
            guard validRoles.contains(node.role),
                  context.inspectedNodes[node.handle] != nil,
                  byHandle[node.handle] == nil else {
                return false
            }
            if node.isFocused { focusCount += 1 }
            byHandle[node.handle] = node
        }
        guard focusCount <= 1 else { return false }
        for node in result.nodes {
            var seen: Set<AXNodeHandle> = [node.handle]
            var current = node.parent
            while let parent = current {
                guard seen.insert(parent).inserted, let ancestor = byHandle[parent] else {
                    return false
                }
                current = ancestor.parent
            }
        }
        return true
    }
}

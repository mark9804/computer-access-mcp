import Foundation
import AccessContract

/// Shared structural and wire bounds for foreground top menu bar observations.
public enum MenuPathLimits {
    public static let maxParentHops = 12
    public static let minSegments = 2
    public static let maxSegments = 8
    public static let maxSegmentUTF16Units = 128
    public static let maxTotalUTF16Units = 512
    public static let maxOpenMenus = 8
    public static let maxPendingRecords = 8
    public static let maxSelectionAgeMs: Int64 = 10_000
    public static let maxMenuTrackingMs: Int64 = 10_000
    public static let maxSafeInteger: Int64 = 9_007_199_254_740_991

    /// Matches JS String.prototype.trim() and ContractValidator whitespace parity.
    public static func isWhitespace(_ scalar: UnicodeScalar) -> Bool {
        scalar.properties.isWhitespace || scalar.value == 0xFEFF
    }

    /// C0 (< 0x20) and C1 (0x7F...0x9F) control scalars rejected on the wire.
    public static func isControl(_ scalar: UnicodeScalar) -> Bool {
        scalar.value < 0x20 || (scalar.value >= 0x7F && scalar.value <= 0x9F)
    }

    /// Collapses CR/LF/TAB runs to a single space, strips remaining C0/C1 controls,
    /// and trims JS-compatible whitespace (including U+FEFF). Returns nil if empty.
    public static func sanitizeSegment(_ raw: String) -> String? {
        var scalars = String.UnicodeScalarView()
        scalars.reserveCapacity(raw.unicodeScalars.count)
        var pendingSpace = false
        for scalar in raw.unicodeScalars {
            if scalar.value == 0x09 || scalar.value == 0x0A || scalar.value == 0x0D {
                pendingSpace = true
                continue
            }
            if isControl(scalar) {
                continue
            }
            if pendingSpace {
                if !scalars.isEmpty {
                    scalars.append(UnicodeScalar(0x20))
                }
                pendingSpace = false
            }
            scalars.append(scalar)
        }
        return trimWhitespace(scalars)
    }

    private static func trimWhitespace(_ scalars: String.UnicodeScalarView) -> String? {
        var start = scalars.startIndex
        while start < scalars.endIndex, isWhitespace(scalars[start]) {
            start = scalars.index(after: start)
        }
        var end = scalars.endIndex
        while end > start {
            let prev = scalars.index(before: end)
            if isWhitespace(scalars[prev]) {
                end = prev
            } else {
                break
            }
        }
        guard start < end else { return nil }
        return String(scalars[start..<end])
    }

    private static func trimTrailingWhitespace(_ text: String) -> String? {
        let scalars = text.unicodeScalars
        var end = scalars.endIndex
        while end > scalars.startIndex {
            let prev = scalars.index(before: end)
            if isWhitespace(scalars[prev]) {
                end = prev
            } else {
                break
            }
        }
        guard end > scalars.startIndex else { return nil }
        return String(scalars[scalars.startIndex..<end])
    }

    public static func isValidSegment(_ segment: String) -> Bool {
        let units = segment.utf16.count
        guard units >= 1, units <= maxSegmentUTF16Units else { return false }
        guard !segment.unicodeScalars.contains(where: isControl) else { return false }
        guard !segment.unicodeScalars.allSatisfy(isWhitespace) else { return false }
        return true
    }

    public static func isValidPath(_ path: [String]) -> Bool {
        guard path.count >= minSegments, path.count <= maxSegments else { return false }
        var total = 0
        for segment in path {
            guard isValidSegment(segment) else { return false }
            total += segment.utf16.count
            guard total <= maxTotalUTF16Units else { return false }
        }
        return true
    }

    /// Bounds already-sanitized segments to 128 UTF-16 units each and 512 total
    /// without bisecting surrogate pairs. Reserves each remaining segment's first
    /// scalar so deeper valid paths cannot starve later segments to zero units.
    public static func boundPath(_ sanitizedSegments: [String]) -> ResolvedMenuPath? {
        guard sanitizedSegments.count >= minSegments,
              sanitizedSegments.count <= maxSegments else { return nil }
        var minUnits: [Int] = []
        minUnits.reserveCapacity(sanitizedSegments.count)
        for segment in sanitizedSegments {
            guard let first = segment.unicodeScalars.first, !isControl(first), !isWhitespace(first) else {
                return nil
            }
            minUnits.append(first.utf16.count)
        }

        var remaining = maxTotalUTF16Units
        var suffixMin = minUnits.reduce(0, +)
        var bounded: [String] = []
        bounded.reserveCapacity(sanitizedSegments.count)
        var truncated = false

        for (index, segment) in sanitizedSegments.enumerated() {
            suffixMin -= minUnits[index]
            let cap = min(maxSegmentUTF16Units, remaining - suffixMin)
            guard cap >= minUnits[index] else { return nil }
            let units = segment.utf16.count
            if units <= cap {
                bounded.append(segment)
                remaining -= units
            } else {
                truncated = true
                guard let sliced = boundedUTF16Slice(segment, start: 0, length: cap),
                      let cleaned = trimTrailingWhitespace(sliced),
                      !cleaned.isEmpty else { return nil }
                bounded.append(cleaned)
                remaining -= cleaned.utf16.count
            }
        }
        guard isValidPath(bounded) else { return nil }
        return ResolvedMenuPath(path: bounded, truncated: truncated)
    }
}

/// Immutable worker-to-engine IPC record for one committed foreground menu bar action.
public struct MenuActionRecord: Codable, Equatable {
    public var application: ApplicationIdentity
    public var path: [String]
    public var truncated: Bool
    public var observedAtMs: Int64
    public var privateState: String
    public var captureEpoch: Int64
    public var foregroundGeneration: Int64
    public var focusGeneration: Int64
    public var policyRevision: Int64
    public var fieldSecurity: String

    public init(
        application: ApplicationIdentity,
        path: [String],
        truncated: Bool,
        observedAtMs: Int64,
        privateState: String,
        captureEpoch: Int64,
        foregroundGeneration: Int64,
        focusGeneration: Int64,
        policyRevision: Int64,
        fieldSecurity: String
    ) {
        self.application = application
        self.path = path
        self.truncated = truncated
        self.observedAtMs = observedAtMs
        self.privateState = privateState
        self.captureEpoch = captureEpoch
        self.foregroundGeneration = foregroundGeneration
        self.focusGeneration = focusGeneration
        self.policyRevision = policyRevision
        self.fieldSecurity = fieldSecurity
    }

    public var isValid: Bool {
        application.processId > 0 &&
            !application.applicationId.isEmpty &&
            application.applicationId.utf16.count <= 256 &&
            !application.processStartTime.isEmpty &&
            application.processStartTime.utf16.count <= 128 &&
            MenuPathLimits.isValidPath(path) &&
            (0...MenuPathLimits.maxSafeInteger).contains(observedAtMs) &&
            ["normal", "user-authorized"].contains(privateState) &&
            (0...MenuPathLimits.maxSafeInteger).contains(captureEpoch) &&
            (0...MenuPathLimits.maxSafeInteger).contains(foregroundGeneration) &&
            (0...MenuPathLimits.maxSafeInteger).contains(focusGeneration) &&
            (1...MenuPathLimits.maxSafeInteger).contains(policyRevision) &&
            ["strict", "denylist"].contains(fieldSecurity)
    }

    public var stamp: JSONValue {
        .object([
            "captureEpoch": j(captureEpoch),
            "foregroundGeneration": j(foregroundGeneration),
            "focusGeneration": j(focusGeneration),
            "policyRevision": j(policyRevision),
        ])
    }

    public func payload(fixture: Bool) -> JSONValue {
        var reasons = ["menu-bar-only", "effect-unverified"]
        if truncated { reasons.append("menu-title-truncated") }
        let secure = CapturePolicy(fieldSecurity: fieldSecurity).contentGateSecure
        return .object([
            "kind": .string("menu.action"),
            "source": .string(fixture ? "fixture" : "ax.menu"),
            "scope": .string("menu-bar"),
            "path": .array(path.map(JSONValue.string)),
            "observedAtMs": j(observedAtMs),
            "gate": .object([
                "secure": .string(secure),
                "privateState": .string(privateState),
                "policyRevision": j(policyRevision),
            ]),
            "secureInput": .string("inactive"),
            "coverage": .object([
                "status": .string("partial"),
                "truncated": .bool(truncated),
                "missingReasons": .array(reasons.map(JSONValue.string)),
            ]),
            "effect": .string("unverified"),
        ])
    }
}

/// Sanitized, bounded menu path resolved from a leaf AXMenuItem up to appMenuBar.
public struct ResolvedMenuPath: Equatable {
    public let path: [String]
    public let truncated: Bool

    public init(path: [String], truncated: Bool) {
        self.path = path
        self.truncated = truncated
    }
}

/// Platform-free metadata snapshot for one node in a menu parent chain.
public struct MenuNodeMetadata: Equatable {
    public let pid: Int32
    public let role: String?
    public let subrole: TextSecurityGate.SubroleRead
    public let protectedContent: TextSecurityGate.ProtectedContentRead
    public let enabled: Bool?
    public let title: String?
    public let description: String?
    /// Required on leaf AXMenuItem (must be 0 so submenu openers are never emitted).
    public let childCount: Int?

    public init(
        pid: Int32,
        role: String?,
        subrole: TextSecurityGate.SubroleRead = .noValue,
        protectedContent: TextSecurityGate.ProtectedContentRead = .noValue,
        enabled: Bool? = true,
        title: String? = nil,
        description: String? = nil,
        childCount: Int? = nil
    ) {
        self.pid = pid
        self.role = role
        self.subrole = subrole
        self.protectedContent = protectedContent
        self.enabled = enabled
        self.title = title
        self.description = description
        self.childCount = childCount
    }
}

/// Classification of an opened AXMenu under the foreground application's top menu bar.
public enum OpenedMenuKind: Equatable {
    case topLevel
    case submenu
}

/// Platform-free AXParent chain resolver proving top-menu-bar ownership without
/// screen coordinates, hit-testing, or full AXChildren enumeration.
public enum MenuPathResolver {
    private static func isSafeMenuNode(_ meta: MenuNodeMetadata, expectedPid: Int32) -> Bool {
        meta.pid == expectedPid &&
            meta.role != "AXSecureTextField" &&
            TextSecurityGate.mayTraverse(subrole: meta.subrole, protectedContent: meta.protectedContent)
    }

    private static func preferredTitle(title: String?, description: String?) -> String? {
        if let title, let clean = MenuPathLimits.sanitizeSegment(title) { return clean }
        if let description, let clean = MenuPathLimits.sanitizeSegment(description) { return clean }
        return nil
    }

    /// Walks AXParent from a leaf AXMenuItem up to `appMenuBar` (max 12 hops).
    /// Rejects non-leaf submenu openers, disabled items, Apple menu (index 0),
    /// extras menu bars, context menus, cycles, cross-PID hops, and sensitive nodes.
    public static func resolve<Handle>(
        leaf: Handle,
        expectedPid: Int32,
        appMenuBar: Handle,
        appleMenuBarItem: Handle,
        same: (Handle, Handle) -> Bool,
        inspect: (Handle, _ isLeaf: Bool) -> MenuNodeMetadata?,
        parent: (Handle) -> Handle?,
        shouldContinue: () -> Bool
    ) -> ResolvedMenuPath? {
        guard expectedPid > 0, shouldContinue() else { return nil }
        guard let leafMeta = inspect(leaf, true), shouldContinue() else { return nil }
        guard isSafeMenuNode(leafMeta, expectedPid: expectedPid),
              leafMeta.role == "AXMenuItem",
              leafMeta.enabled != false,
              leafMeta.childCount == 0,
              let leafTitle = preferredTitle(title: leafMeta.title, description: leafMeta.description) else {
            return nil
        }

        var reversedSegments: [String] = [leafTitle]
        var visited: [Handle] = [leaf]
        var current = leaf
        var sawBarItem = false
        var reachedAppMenuBar = false

        for _ in 0..<MenuPathLimits.maxParentHops {
            guard shouldContinue() else { return nil }
            guard let ancestor = parent(current), shouldContinue() else { return nil }
            if visited.contains(where: { same($0, ancestor) }) { return nil }
            visited.append(ancestor)

            guard let meta = inspect(ancestor, false), shouldContinue() else { return nil }
            guard isSafeMenuNode(meta, expectedPid: expectedPid) else { return nil }

            if meta.role == "AXMenuBar" {
                guard same(ancestor, appMenuBar) else { return nil }
                reachedAppMenuBar = true
                break
            }

            switch meta.role {
            case "AXMenu":
                break
            case "AXMenuItem":
                guard meta.enabled != false,
                      let title = preferredTitle(title: meta.title, description: meta.description) else {
                    return nil
                }
                reversedSegments.append(title)
            case "AXMenuBarItem":
                guard !same(ancestor, appleMenuBarItem),
                      meta.enabled != false,
                      let title = preferredTitle(title: meta.title, description: meta.description) else {
                    return nil
                }
                sawBarItem = true
                reversedSegments.append(title)
            default:
                return nil
            }
            current = ancestor
        }

        guard reachedAppMenuBar, sawBarItem else { return nil }
        let ordered = Array(reversedSegments.reversed())
        return MenuPathLimits.boundPath(ordered)
    }

    /// Classifies an opened AXMenu as either a top-level menu bar dropdown or a
    /// nested submenu under `appMenuBar` (excluding Apple menu, extras menu bar,
    /// and context/popup menus).
    public static func classifyOpenedMenu<Handle>(
        menu: Handle,
        expectedPid: Int32,
        appMenuBar: Handle,
        appleMenuBarItem: Handle,
        openMenus: [Handle],
        same: (Handle, Handle) -> Bool,
        inspect: (Handle) -> MenuNodeMetadata?,
        parent: (Handle) -> Handle?,
        shouldContinue: () -> Bool
    ) -> OpenedMenuKind? {
        guard expectedPid > 0, shouldContinue() else { return nil }
        guard let menuMeta = inspect(menu), shouldContinue(),
              isSafeMenuNode(menuMeta, expectedPid: expectedPid),
              menuMeta.role == "AXMenu" else { return nil }

        guard let firstParent = parent(menu), shouldContinue(),
              !same(firstParent, menu),
              let firstMeta = inspect(firstParent), shouldContinue(),
              isSafeMenuNode(firstMeta, expectedPid: expectedPid) else { return nil }

        if firstMeta.role == "AXMenuBarItem" {
            guard !same(firstParent, appleMenuBarItem) else { return nil }
            guard let bar = parent(firstParent), shouldContinue(),
                  !same(bar, menu), !same(bar, firstParent),
                  let barMeta = inspect(bar), shouldContinue(),
                  isSafeMenuNode(barMeta, expectedPid: expectedPid),
                  barMeta.role == "AXMenuBar",
                  same(bar, appMenuBar) else { return nil }
            return .topLevel
        }

        guard firstMeta.role == "AXMenuItem" else { return nil }

        var visited: [Handle] = [menu, firstParent]
        var current = firstParent
        for _ in 0..<(MenuPathLimits.maxParentHops - 1) {
            guard shouldContinue() else { return nil }
            guard let ancestor = parent(current), shouldContinue() else { return nil }
            if visited.contains(where: { same($0, ancestor) }) { return nil }
            visited.append(ancestor)

            if openMenus.contains(where: { same($0, ancestor) }) {
                return .submenu
            }

            guard let meta = inspect(ancestor), shouldContinue(),
                  isSafeMenuNode(meta, expectedPid: expectedPid) else { return nil }

            switch meta.role {
            case "AXMenu", "AXMenuItem":
                break
            case "AXMenuBarItem":
                guard !same(ancestor, appleMenuBarItem) else { return nil }
            case "AXMenuBar":
                return same(ancestor, appMenuBar) ? .submenu : nil
            default:
                return nil
            }
            current = ancestor
        }
        return nil
    }
}

/// Pure tracking state machine for open menus and a single volatile highlighted item.
/// Never emits on hover; `commit(nowMs:)` consumes the active highlight at most once.
public struct MenuTrackingStateMachine<MenuHandle, Selection> {
    public struct Transition {
        public let trackingChanged: Bool?
        public let removed: [MenuHandle]
        public init(trackingChanged: Bool?, removed: [MenuHandle]) {
            self.trackingChanged = trackingChanged
            self.removed = removed
        }
    }

    private struct Highlight {
        let menu: MenuHandle
        let selection: Selection
        let updatedAtMs: Int64
    }

    private let same: (MenuHandle, MenuHandle) -> Bool
    private let maxOpenMenus: Int
    private let maxSelectionAgeMs: Int64
    public private(set) var openMenus: [MenuHandle] = []
    private var highlighted: Highlight?

    public init(
        maxOpenMenus: Int = MenuPathLimits.maxOpenMenus,
        maxSelectionAgeMs: Int64 = MenuPathLimits.maxSelectionAgeMs,
        same: @escaping (MenuHandle, MenuHandle) -> Bool
    ) {
        self.maxOpenMenus = max(1, maxOpenMenus)
        self.maxSelectionAgeMs = max(1, maxSelectionAgeMs)
        self.same = same
    }

    public var isTracking: Bool { !openMenus.isEmpty }
    public var hasSelection: Bool { highlighted != nil }

    @discardableResult
    public mutating func menuOpened(_ menu: MenuHandle, isTopLevel: Bool) -> Transition {
        let wasTracking = !openMenus.isEmpty
        var evicted: [MenuHandle] = []

        if isTopLevel {
            // Idempotent when AXObserver delivers the same top-level open on both app and menuBar.
            if openMenus.count == 1 && same(openMenus[0], menu) {
                return Transition(trackingChanged: nil, removed: [])
            }
            evicted = openMenus.filter { !same($0, menu) }
            openMenus = [menu]
            highlighted = nil
        } else {
            if openMenus.contains(where: { same($0, menu) }) {
                return Transition(trackingChanged: nil, removed: [])
            }
            if openMenus.count >= maxOpenMenus {
                let dropped = openMenus.removeFirst()
                evicted.append(dropped)
                if let current = highlighted, same(current.menu, dropped) {
                    highlighted = nil
                }
            }
            openMenus.append(menu)
        }

        let nowTracking = !openMenus.isEmpty
        let changed: Bool? = (wasTracking != nowTracking) ? nowTracking : nil
        return Transition(trackingChanged: changed, removed: evicted)
    }

    @discardableResult
    public mutating func menuClosed(_ menu: MenuHandle) -> Transition {
        let wasTracking = !openMenus.isEmpty
        guard let index = openMenus.firstIndex(where: { same($0, menu) }) else {
            return Transition(trackingChanged: nil, removed: [])
        }
        // Closing a menu also invalidates any nested submenus stacked above it.
        let removed = Array(openMenus[index...])
        openMenus.removeSubrange(index...)
        if openMenus.isEmpty {
            highlighted = nil
        } else if let current = highlighted, removed.contains(where: { same($0, current.menu) }) {
            highlighted = nil
        }
        let nowTracking = !openMenus.isEmpty
        let changed: Bool? = (wasTracking != nowTracking) ? nowTracking : nil
        return Transition(trackingChanged: changed, removed: removed)
    }

    /// Prunes a stale menu handle (e.g. after AX -25202 / -25204).
    @discardableResult
    public mutating func prune(_ menu: MenuHandle) -> Transition {
        menuClosed(menu)
    }

    /// Updates or clears the single volatile highlighted selection for an open menu.
    public mutating func updateSelection(_ selection: Selection?, from menu: MenuHandle, nowMs: Int64) {
        guard let selection else {
            highlighted = nil
            return
        }
        guard openMenus.contains(where: { same($0, menu) }) else {
            return
        }
        highlighted = Highlight(menu: menu, selection: selection, updatedAtMs: nowMs)
    }

    /// Clears the highlighted selection (Esc, empty selection, submenu hover, or failed gate).
    public mutating func cancel() {
        highlighted = nil
    }

    /// Resets the entire open menu stack and highlight on boundary, Secure Input, or teardown.
    @discardableResult
    public mutating func reset() -> Transition {
        let wasTracking = !openMenus.isEmpty
        let removed = openMenus
        openMenus.removeAll()
        highlighted = nil
        return Transition(trackingChanged: wasTracking ? false : nil, removed: removed)
    }

    /// Consumes the volatile highlighted selection at most once if a menu is open
    /// and the highlight is within `maxSelectionAgeMs`.
    public mutating func commit(nowMs: Int64) -> Selection? {
        guard !openMenus.isEmpty, let current = highlighted else { return nil }
        highlighted = nil
        guard nowMs >= current.updatedAtMs, nowMs - current.updatedAtMs <= maxSelectionAgeMs else {
            return nil
        }
        return current.selection
    }
}

/// Typed window handle lookup for fail-closed browser pre-read checks.
public enum BrowserWindowReference<Handle> {
    case window(Handle)
    case absent
    case failure
}

/// Typed `AXWindows` count read distinguishing positive zero windows from AX failures.
public enum BrowserWindowCountRead: Equatable {
    case count(Int)
    case failure
}

/// Typed browser window metadata snapshot used to verify non-private `AXWindow` state.
public enum BrowserWindowInspection: Equatable {
    case inspected(role: String?, hasSensitiveEvidence: Bool, safeTitle: String?)
    case failure
}

/// Fail-closed pre-read privacy gate for browsers (known and unlisted http/https
/// handlers) before reading any menu titles or starting menu tracking.
public enum BrowserMenuWindowGate {
    public static func allowsMenuRead<Handle>(
        applicationId: String,
        isBrowserCandidate: Bool,
        spec: AppAdapterSpec,
        policy: CapturePolicy,
        same: (Handle, Handle) -> Bool,
        focusedWindow: () -> BrowserWindowReference<Handle>,
        mainWindow: () -> BrowserWindowReference<Handle>,
        windowCount: () -> BrowserWindowCountRead,
        inspectWindow: (Handle) -> BrowserWindowInspection
    ) -> Bool {
        let isBrowser = isBrowserCandidate || BrowserGate.shouldBlockPrivateWindows(applicationId: applicationId, spec: spec)
        guard isBrowser else { return true }
        guard policy.applicationScope == "denylist", policy.allowBrowserContent == true else { return false }

        func windowSafe(_ handle: Handle) -> Bool {
            switch inspectWindow(handle) {
            case .failure:
                return false
            case .inspected(let role, let hasSensitiveEvidence, let safeTitle):
                guard role == "AXWindow", !hasSensitiveEvidence, let safeTitle else { return false }
                return !BrowserGate.isPrivateWindowTitle(safeTitle)
            }
        }

        let focusedHandle: Handle?
        switch focusedWindow() {
        case .failure:
            return false
        case .absent:
            focusedHandle = nil
        case .window(let win):
            guard windowSafe(win) else { return false }
            focusedHandle = win
        }

        let mainHandle: Handle?
        switch mainWindow() {
        case .failure:
            return false
        case .absent:
            mainHandle = nil
        case .window(let win):
            if let focusedHandle, same(win, focusedHandle) {
                mainHandle = win
            } else {
                guard windowSafe(win) else { return false }
                mainHandle = win
            }
        }

        if focusedHandle != nil || mainHandle != nil {
            return true
        }
        // Require positive proof of zero windows so transient absent focus/main
        // during modal menu tracking cannot fail open over an Incognito window.
        if case .count(0) = windowCount() {
            return true
        }
        return false
    }
}

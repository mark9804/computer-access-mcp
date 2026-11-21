/// Typed AXFocusedUIElement observation distinguishing explicit absence from errors.
public enum FocusElementRead<Handle> {
    case element(Handle)
    case noValue
    case attributeUnsupported
    case failure
    case malformed

    public var isExplicitlyAbsent: Bool {
        switch self {
        case .noValue, .attributeUnsupported: return true
        case .element, .failure, .malformed: return false
        }
    }
}

/// Typed window containment evidence (`AXWindow` with optional `AXTopLevelUIElement` fallback).
public enum WindowReference<Handle> {
    case value(Handle)
    case absent
    case rejected
}

public enum WindowOwnership {
    public enum Route: Equatable {
        case direct
        case topLevel
        case parentChain
    }

    public static let maxParentChainHops = 16

    /// Walks `AXParent` up to `maxParentChainHops` hops, enforcing cycle detection,
    /// per-hop verification (PID match), and cancellation checks at every step.
    public static func walkParentChain<Handle>(
        from start: Handle,
        expectedWindow: Handle,
        maxHops: Int = maxParentChainHops,
        parent: (Handle) -> Handle?,
        same: (Handle, Handle) -> Bool,
        verifyHop: (Handle) -> Bool,
        shouldContinue: () -> Bool
    ) -> WindowReference<Handle> {
        let hopLimit = min(max(0, maxHops), maxParentChainHops)
        var visited: [Handle] = [start]
        var current = start
        for _ in 0..<hopLimit {
            guard shouldContinue() else { return .rejected }
            guard let ancestor = parent(current) else { return .absent }
            guard shouldContinue() else { return .rejected }
            if visited.contains(where: { same($0, ancestor) }) {
                return .rejected
            }
            guard verifyHop(ancestor) else { return .rejected }
            guard shouldContinue() else { return .rejected }
            if same(ancestor, expectedWindow) {
                return .value(ancestor)
            }
            visited.append(ancestor)
            current = ancestor
        }
        return .absent
    }

    public static func match<Handle>(
        expectedWindow: Handle,
        allowTopLevel: Bool,
        direct: () -> WindowReference<Handle>,
        topLevel: () -> WindowReference<Handle>,
        same: (Handle, Handle) -> Bool,
        verifyTopLevelWindow: (Handle) -> Bool,
        shouldContinue: () -> Bool,
        parentChain: (() -> WindowReference<Handle>)? = nil
    ) -> Route? {
        guard shouldContinue() else { return nil }
        let reference = direct()
        guard shouldContinue() else { return nil }
        switch reference {
        case .value(let window):
            return same(window, expectedWindow) ? .direct : nil
        case .rejected:
            return nil
        case .absent:
            break
        }
        guard allowTopLevel, shouldContinue() else { return nil }
        let alternate = topLevel()
        guard shouldContinue() else { return nil }
        switch alternate {
        case .value(let window):
            guard same(window, expectedWindow), shouldContinue(),
                  verifyTopLevelWindow(window), shouldContinue() else { return nil }
            return .topLevel
        case .rejected:
            return nil
        case .absent:
            break
        }
        guard let parentChain, shouldContinue(),
              case .value(let window) = parentChain(), shouldContinue(),
              same(window, expectedWindow), shouldContinue(),
              verifyTopLevelWindow(window), shouldContinue() else { return nil }
        return .parentChain
    }
}

/// Resolves and revalidates a focused window when AXFocusedUIElement is explicitly absent.
public enum WindowFocusAnchor {
    public static func resolve<Handle>(
        policy: CapturePolicy,
        expectedApplication: ApplicationIdentity,
        application: () -> ApplicationIdentity?,
        focus: () -> FocusElementRead<Handle>,
        window: () -> Handle?,
        inspectWindow: (Handle) -> Bool,
        sameWindow: (Handle, Handle) -> Bool,
        shouldContinue: () -> Bool
    ) -> Handle? {
        checkedWindow(
            expectedWindow: nil,
            policy: policy,
            expectedApplication: expectedApplication,
            application: application,
            focus: focus,
            window: window,
            inspectWindow: inspectWindow,
            sameWindow: sameWindow,
            shouldContinue: shouldContinue
        )
    }

    public static func validate<Handle>(
        window frozenWindow: Handle,
        policy: CapturePolicy,
        expectedApplication: ApplicationIdentity,
        application: () -> ApplicationIdentity?,
        focus: () -> FocusElementRead<Handle>,
        window: () -> Handle?,
        inspectWindow: (Handle) -> Bool,
        sameWindow: (Handle, Handle) -> Bool,
        shouldContinue: () -> Bool
    ) -> Bool {
        checkedWindow(
            expectedWindow: frozenWindow,
            policy: policy,
            expectedApplication: expectedApplication,
            application: application,
            focus: focus,
            window: window,
            inspectWindow: inspectWindow,
            sameWindow: sameWindow,
            shouldContinue: shouldContinue
        ) != nil
    }

    private static func checkedWindow<Handle>(
        expectedWindow: Handle?,
        policy: CapturePolicy,
        expectedApplication: ApplicationIdentity,
        application: () -> ApplicationIdentity?,
        focus: () -> FocusElementRead<Handle>,
        window: () -> Handle?,
        inspectWindow: (Handle) -> Bool,
        sameWindow: (Handle, Handle) -> Bool,
        shouldContinue: () -> Bool
    ) -> Handle? {
        func step<T>(_ body: () -> T?) -> T? {
            guard shouldContinue() else { return nil }
            let result = body()
            guard shouldContinue() else { return nil }
            return result
        }
        guard policy.hasValidTextSettings,
              policy.captureScope == "window",
              ApplicationPolicy.allows(expectedApplication.applicationId, policy: policy),
              BrowserGate.allows(expectedApplication.applicationId, policy: policy) else { return nil }
        guard step({ application() }) == expectedApplication else { return nil }
        guard step({ focus() })?.isExplicitlyAbsent == true else { return nil }
        guard let candidate = step({ window() }) else { return nil }
        if let expectedWindow {
            guard step({ sameWindow(candidate, expectedWindow) ? true : nil }) == true else { return nil }
        }
        guard step({ inspectWindow(candidate) ? true : nil }) == true else { return nil }
        guard step({ focus() })?.isExplicitlyAbsent == true else { return nil }
        guard let finalWindow = step({ window() }) else { return nil }
        guard step({ sameWindow(candidate, finalWindow) ? true : nil }) == true else { return nil }
        guard step({ application() }) == expectedApplication else { return nil }
        return candidate
    }
}

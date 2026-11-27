import Foundation

public enum AppAccessDecision: Equatable, Sendable {
    case allowed
    case denied(reason: String, code: ReadDiagnostic.Code)
}

/// Shared native application policy gate. Mandatory families and System UI
/// overlays cannot be opted back in; matching uses a dot boundary, never substrings.
public enum ApplicationPolicy {
    public static let mandatoryDeniedFamilies: [String] = GeneratedPolicyCatalog.mandatoryExcludedFamilies

    public static let systemUIFamilies: [String] = GeneratedPolicyCatalog.systemUIFamilies

    public static func matchesFamily(_ value: String, family: String) -> Bool {
        let normalizedValue = value.lowercased()
        let normalizedFamily = family.lowercased()
        guard !normalizedValue.isEmpty, !normalizedFamily.isEmpty else { return false }
        return normalizedValue == normalizedFamily || normalizedValue.hasPrefix(normalizedFamily + ".")
    }

    public static func isMandatoryDenied(_ id: String) -> Bool {
        mandatoryDeniedFamilies.contains { matchesFamily(id, family: $0) }
    }

    public static func isSystemUI(_ id: String) -> Bool {
        systemUIFamilies.contains { matchesFamily(id, family: $0) }
    }

    public static func allows(_ id: String, policy: CapturePolicy) -> Bool {
        guard policy.enabled, !id.isEmpty, !isMandatoryDenied(id), !isSystemUI(id) else { return false }
        let value = id.lowercased()
        if (policy.excludedApplicationIds ?? []).contains(where: { matchesFamily(value, family: $0) }) { return false }
        if policy.applicationScope == "denylist" { return true }
        guard policy.applicationScope == nil || policy.applicationScope == "allowlist" else { return false }
        return policy.allowedApplicationIds.contains { $0.lowercased() == value }
    }

    public static func allows(applicationId: String, policy: CapturePolicy) -> Bool {
        allows(applicationId, policy: policy)
    }

    public static func evaluate(_ id: String, policy: CapturePolicy, isBrowserCandidate: Bool = false) -> AppAccessDecision {
        guard policy.enabled else {
            return .denied(reason: "policy-boundary", code: .applicationNotAllowed)
        }
        guard allows(id, policy: policy) else {
            let silentExclude = policy.applicationScope == "denylist" || isMandatoryDenied(id) || isSystemUI(id)
            return .denied(reason: silentExclude ? "application-excluded" : "policy-boundary", code: .applicationNotAllowed)
        }
        guard BrowserGate.allows(id, policy: policy, isBrowserCandidate: isBrowserCandidate) else {
            return .denied(reason: "policy-boundary", code: .browserExcluded)
        }
        return .allowed
    }
}

public enum BrowserGate {
    public static let privateWindowIndicators: [String] = GeneratedPolicyCatalog.privateWindowIndicators
    public static let privateChromeIndicators: [String] = GeneratedPolicyCatalog.privateChromeIndicators
    public static let privateChromeExactLabels: [String] = GeneratedPolicyCatalog.privateChromeExactLabels

    public static func allows(_ id: String, policy: CapturePolicy, isBrowserCandidate: Bool = false) -> Bool {
        guard ApplicationPolicy.allows(id, policy: policy) else { return false }
        return !(isBrowserCandidate || isKnownBrowser(id)) || (policy.applicationScope == "denylist" && policy.allowBrowserContent == true)
    }

    public static func isKnownBrowser(_ id: String) -> Bool {
        GeneratedPolicyCatalog.browserFamilies.contains { ApplicationPolicy.matchesFamily(id, family: $0) }
    }

    public static func isPrivateWindowTitle(_ title: String) -> Bool {
        let normalized = title.lowercased()
        return privateWindowIndicators.contains { normalized.contains($0) }
    }

    /// Matches native browser toolbar/chrome control labels that indicate a
    /// private/incognito window without matching broad page/UI substrings like
    /// "Privacy settings" or "Private repository".
    public static func isPrivateChromeLabel(_ label: String) -> Bool {
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        let lower = trimmed.lowercased()
        if privateChromeIndicators.contains(where: { lower.contains($0) }) { return true }
        return privateChromeExactLabels.contains { exact in
            if lower == exact { return true }
            guard lower.hasPrefix(exact) else { return false }
            let rest = lower.dropFirst(exact.count).drop(while: { $0.isWhitespace })
            return rest.first == "("
        }
    }

    public static func shouldBlockPrivateWindows(
        applicationId: String,
        spec: AppAdapterSpec,
        isBrowserCandidate: Bool = false
    ) -> Bool {
        isBrowserCandidate || spec.blockPrivateWindows || isKnownBrowser(applicationId)
    }
}

public enum BrowserChromeVerdict: Equatable, Sendable {
    case verifiedNormal
    case privateDetected
    case inconclusive
}

public struct BrowserChromeNode: Equatable, Sendable {
    public let role: String?
    public let subrole: TextSecurityGate.SubroleRead
    public let protectedContent: TextSecurityGate.ProtectedContentRead
    public let hasSensitiveEvidence: Bool
    public let safeTitle: String?
    public let safeDescription: String?
    public let safeIdentifier: String?

    public init(
        role: String?,
        subrole: TextSecurityGate.SubroleRead,
        protectedContent: TextSecurityGate.ProtectedContentRead,
        hasSensitiveEvidence: Bool,
        safeTitle: String? = nil,
        safeDescription: String? = nil,
        safeIdentifier: String? = nil
    ) {
        self.role = role
        self.subrole = subrole
        self.protectedContent = protectedContent
        self.hasSensitiveEvidence = hasSensitiveEvidence
        self.safeTitle = safeTitle
        self.safeDescription = safeDescription
        self.safeIdentifier = safeIdentifier
    }
}

public enum BrowserChromeChildrenRead<Handle> {
    case children([Handle], truncated: Bool)
    case none
    case error
}

/// Pure, bounded, fail-closed browser chrome traversal shared by focused/surface
/// reads and menu-action privacy gates. Never enters web content, tabs, address
/// bars, menus, or bookmark bars; any error, truncation, metadata failure, or
/// budget expiry returns `.inconclusive` so callers fail closed.
public enum BrowserChromeGate {
    public static let excludedRoles: Set<String> = [
        "AXWebArea", "AXDocument", "AXScrollArea", "AXSheet", "AXDrawer",
        "AXTabGroup", "AXRadioButton", "AXTabButton",
        "AXTextField", "AXTextArea", "AXLink",
        "AXMenuBar", "AXMenu", "AXMenuItem", "AXScrollBar",
    ]

    public static let containerRoles: Set<String> = [
        "AXWindow", "AXToolbar", "AXGroup", "AXSplitGroup",
    ]

    public static let skippedBookmarkIdentifiers: Set<String> = [
        "BookmarkBarView", "PersonalToolbar",
    ]

    public static let defaultMaxDepth = 10
    public static let defaultMaxNodes = 128
    public static let defaultMaxChildren = 64
    public static let defaultMaxCalls = 240

    public static func inspect<Handle>(
        window: Handle,
        deadlineMs: Int64,
        maxDepth: Int = defaultMaxDepth,
        maxNodes: Int = defaultMaxNodes,
        maxChildren: Int = defaultMaxChildren,
        maxCalls: Int = defaultMaxCalls,
        nowMs: () -> Int64,
        matchesProcess: (Handle) -> Bool?,
        readNode: (Handle) -> BrowserChromeNode?,
        readChildren: (Handle, Int) -> BrowserChromeChildrenRead<Handle>
    ) -> BrowserChromeVerdict {
        var remainingCalls = max(1, maxCalls)
        var queue: [(handle: Handle, depth: Int)] = [(window, 0)]
        var cursor = 0
        var inspected = 0

        while cursor < queue.count {
            guard nowMs() < deadlineMs else { return .inconclusive }
            let current = queue[cursor]
            cursor += 1
            let currentRole: String

            if current.depth > 0 {
                guard let sameProcess = matchesProcess(current.handle) else { return .inconclusive }
                guard sameProcess else { continue }
                guard nowMs() < deadlineMs, remainingCalls > 0 else { return .inconclusive }
                remainingCalls -= 1
                guard let node = readNode(current.handle) else { return .inconclusive }
                if node.hasSensitiveEvidence { return .privateDetected }
                guard let role = node.role else { return .inconclusive }
                if excludedRoles.contains(role) { continue }
                // Require readable subrole/protected attributes so AXMetadataBatch cannot
                // silently nil out safeTitle/safeDescription on a private-mode badge.
                guard TextSecurityGate.mayTraverse(subrole: node.subrole, protectedContent: node.protectedContent) else {
                    return .inconclusive
                }
                if (role == "AXGroup" || role == "AXToolbar"),
                   let identifier = node.safeIdentifier,
                   skippedBookmarkIdentifiers.contains(identifier) {
                    continue
                }
                guard inspected < maxNodes else { return .inconclusive }
                inspected += 1
                if let title = node.safeTitle, BrowserGate.isPrivateChromeLabel(title) {
                    return .privateDetected
                }
                if let desc = node.safeDescription, BrowserGate.isPrivateChromeLabel(desc) {
                    return .privateDetected
                }
                guard containerRoles.contains(role) else { continue }
                currentRole = role
            } else {
                currentRole = "AXWindow"
            }

            let atDepthLimit = current.depth >= maxDepth
            guard nowMs() < deadlineMs, remainingCalls > 0 else { return .inconclusive }
            remainingCalls -= 1
            // At maxDepth, probe at most 1 child: an empty leaf AXGroup does not
            // invalidate a normal window, while unexpanded children fail closed.
            let limit = atDepthLimit ? 1 : maxChildren
            switch readChildren(current.handle, limit) {
            case .none:
                continue
            case .error:
                return .inconclusive
            case .children(let children, let truncated):
                if atDepthLimit {
                    if !children.isEmpty || truncated { return .inconclusive }
                    continue
                }
                if truncated { return .inconclusive }
                let ordered = currentRole == "AXToolbar" ? Array(children.reversed()) : children
                for child in ordered {
                    queue.append((child, current.depth + 1))
                }
            }
        }
        return .verifiedNormal
    }
}

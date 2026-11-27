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

    public static func shouldBlockPrivateWindows(applicationId: String, spec: AppAdapterSpec) -> Bool {
        spec.blockPrivateWindows || isKnownBrowser(applicationId)
    }
}

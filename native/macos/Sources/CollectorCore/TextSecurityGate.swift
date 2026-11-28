import Foundation

/// Subrole is optional for ordinary AppKit text controls. An absent optional
/// subrole is distinct from a failed/malformed AX response. No content is read
/// while collecting these metadata facts. This is provider evidence, not secret
/// detection: an application that lies about secure semantics remains a limit.
public enum TextSecurityGate {
    /// Success-without-a-typed-value is malformed, never optional absence.
    public enum SubroleRead: Equatable, Sendable {
        case value(String), attributeUnsupported, noValue, failure, malformed
    }
    public enum ProtectedContentRead: Equatable, Sendable {
        case value(Bool), attributeUnsupported, noValue, failure, malformed
    }
    /// Input-role classification is not a field permission or a replacement for
    /// fresh identity/window/desktop checks. Non-editable roles never allow input.
    public enum InputEligibility: Equatable {
        case roleNotEditable, sensitive, unknown
        case allowed(InputTextFieldRole)
    }
    public static func isSensitiveSubrole(_ value: String) -> Bool {
        let normalized = value.lowercased()
        return ["secure", "password", "protected"].contains { normalized.contains($0) }
    }
    /// This authorizes traversal only, never reading a container's value. Optional
    /// absent declarations permit structure; errors and positive declarations prune.
    public static func mayTraverse(subrole: SubroleRead, protectedContent: ProtectedContentRead) -> Bool {
        switch subrole {
        case .failure, .malformed: return false
        case .value(let value): if isSensitiveSubrole(value) { return false }
        case .attributeUnsupported, .noValue: break
        }
        switch protectedContent {
        case .value(false), .attributeUnsupported, .noValue: return true
        case .value(true), .failure, .malformed: return false
        }
    }
    /// Normalized metadata seam: AX transport failures and malformed successful
    /// replies cannot be mistaken for a provider's absent optional declaration.
    public static func classifyMetadata(role: String?, subrole: SubroleRead, protectedContent: ProtectedContentRead,
                                        policy: CapturePolicy, strictFallback: (() -> SecureStatus)? = nil) -> SecureStatus {
        if role == "AXSecureTextField" { return .sensitive }
        if case .value(let value) = subrole, isSensitiveSubrole(value) { return .sensitive }
        if protectedContent == .value(true) { return .sensitive }
        guard protectedContent != .failure, protectedContent != .malformed,
              ["AXTextField", "AXTextArea", "AXStaticText"].contains(role) else { return .unknown }
        switch subrole {
        case .failure, .malformed: return .unknown
        case .value, .attributeUnsupported, .noValue: break
        }
        if policy.fieldSecurityMode == "denylist" { return .notDeclaredSensitive }
        guard policy.fieldSecurityMode == "strict" else { return .unknown }
        if let strictFallback { return strictFallback() }
        if case .value(let value) = subrole { return classify(role: role, subrole: value) }
        return .unknown
    }
    /// Classifies one already-typed, fresh metadata snapshot for input only.
    /// Explicit sensitive evidence wins even for a non-editable or missing role;
    /// transport/type failures remain unknown before normal non-input diagnosis.
    /// Only the existing two input roles can reach the unchanged field policy.
    public static func classifyInputMetadata(role: String?, subrole: SubroleRead, protectedContent: ProtectedContentRead,
                                            policy: CapturePolicy, strictFallback: (() -> SecureStatus)? = nil) -> InputEligibility {
        if role == "AXSecureTextField" { return .sensitive }
        if case .value(let value) = subrole, isSensitiveSubrole(value) { return .sensitive }
        if protectedContent == .value(true) { return .sensitive }
        guard let role, !role.isEmpty,
              mayTraverse(subrole: subrole, protectedContent: protectedContent) else { return .unknown }
        // This is a rejection category, including when the policy is invalid.
        // AXStaticText is readable by other channels but is never an input role.
        guard let inputRole = InputTextFieldRole(rawValue: role) else { return .roleNotEditable }
        let security = classifyMetadata(role: role, subrole: subrole, protectedContent: protectedContent,
                                        policy: policy, strictFallback: strictFallback)
        if security == .sensitive { return .sensitive }
        return policy.allows(security) ? .allowed(inputRole) : .unknown
    }
    public static func classifyEmptySubrole(role: String?, editable: Bool?, boundedRangeAdvertised: Bool, characterCountKnown: Bool) -> SecureStatus {
        guard ["AXTextField", "AXTextArea"].contains(role), editable == true,
              boundedRangeAdvertised, characterCountKnown else { return .unknown }
        return .safe
    }
    public static func classify(role: String?, subrole: String?, subroleUnsupported: Bool = false,
                                attributeListKnown: Bool = false, subroleAdvertised: Bool = false,
                                boundedRangeAdvertised: Bool = false, characterCountKnown: Bool = false) -> SecureStatus {
        if role == "AXSecureTextField" { return .sensitive }
        if let subrole {
            if isSensitiveSubrole(subrole) { return .sensitive }
            guard ["AXTextField", "AXTextArea", "AXStaticText"].contains(role) else { return .unknown }
            return ["AXStandardTextField", "AXTextArea", "AXStaticText", "AXSearchField"].contains(subrole) ? .safe : .unknown
        }
        // NSSecureTextField advertises a secure subrole and does not expose these
        // bounded text capabilities. Never use AXValue to establish safety.
        guard ["AXTextField", "AXTextArea", "AXStaticText"].contains(role), subroleUnsupported,
              attributeListKnown, !subroleAdvertised, boundedRangeAdvertised, characterCountKnown else { return .unknown }
        return .safe
    }
}

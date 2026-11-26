/// Closed, content-free explanations for a requested surface that was not
/// returned. These are diagnostics only: they never authorize retaining content
/// or turn a failed identity/security check into a resource-only failure.
public enum SurfaceReadFailure: String, Codable, CaseIterable {
    case notStartedBudget = "surface-not-started-budget"
    case callBudget = "surface-call-budget"
    case timeBudget = "surface-time-budget"
    case anchorUnavailable = "surface-anchor-unavailable"
    case boundaryUnverified = "surface-boundary-unverified"
    case boundaryMismatch = "surface-boundary-mismatch"
    case boundaryAXFailed = "surface-boundary-ax-failed"
    case boundaryIncomplete = "surface-boundary-incomplete"
    case securityExcluded = "surface-security-excluded"
    case providerUnavailable = "surface-provider-unavailable"

    /// These explain the refused boundary, never reclassify the broad Gap or
    /// authorize using failed, late or otherwise unconfirmed evidence.
    public var gapReason: String {
        switch self {
        case .notStartedBudget, .callBudget: return "budget"
        case .timeBudget: return "timeout"
        case .anchorUnavailable, .boundaryUnverified, .boundaryMismatch, .boundaryAXFailed,
             .boundaryIncomplete, .securityExcluded, .providerUnavailable:
            return "read-error"
        }
    }

    public var isRequiredBoundaryFailure: Bool {
        switch self {
        case .boundaryUnverified, .boundaryMismatch, .boundaryAXFailed, .boundaryIncomplete, .securityExcluded: return true
        default: return false
        }
    }

    fileprivate var precedence: Int {
        switch self {
        case .providerUnavailable: return 0
        case .notStartedBudget: return 1
        case .callBudget: return 2
        case .timeBudget: return 3
        case .anchorUnavailable: return 4
        case .boundaryUnverified: return 5
        case .boundaryIncomplete: return 6
        case .boundaryAXFailed: return 7
        case .boundaryMismatch: return 8
        case .securityExcluded: return 9
        }
    }
}

/// Reduces explicitly observed failure branches to one fixed wire code. Callers
/// must note a resource failure only at its proven resource-only branch, never
/// infer it from a nil compound gate or a low/exhausted call counter. In
/// particular, any failed mandatory boundary check outranks all budget notes;
/// positive sensitive evidence outranks unavailable or uncertain observations.
///
/// Optional geometry loss and successful partial trees belong to coverage, not
/// this accumulator. A fresh instance is required for each surface attempt.
public struct SurfaceReadDiagnostics {
    public private(set) var failure: SurfaceReadFailure?

    public init() {}

    /// Attach only the evidence from a failed mandatory guard. A successful
    /// guard, optional branch, or a resource-only traversal refusal cannot
    /// leave a cause for a later check to inherit.
    public mutating func noteRequiredBoundaryFailure(evidence: SurfaceReadFailure?) {
        if let evidence, evidence.isRequiredBoundaryFailure { note(evidence) }
        else { note(.boundaryUnverified) }
    }

    public mutating func note(_ failure: SurfaceReadFailure) {
        if self.failure == nil || failure.precedence > self.failure!.precedence {
            self.failure = failure
        }
    }
}

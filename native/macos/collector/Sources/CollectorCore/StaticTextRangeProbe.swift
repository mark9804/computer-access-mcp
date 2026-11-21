/// Bounded prefix probing for AXStaticText elements whose reported length is zero or unavailable.
public enum StaticTextRangeProbe {
    public enum Failure: Equatable {
        case interrupted
        case oversizedResponse
    }

    public struct Result: Equatable {
        public let text: String?
        public let consumedUnits: Int
        public let attempts: Int
        public let failure: Failure?
    }

    // 1 initial probe at 256 plus 8 bisections resolves every length in 1...256 (including odd lengths).
    public static let maximumAttempts = 9
    public static let maximumPrefixUnits = 256

    public static func read(
        budget: Int,
        maxAttempts: Int = maximumAttempts,
        initialPrefixUnits: Int = 2,
        stopAfterNonempty: Bool = false,
        shouldContinue: () -> Bool,
        canStartAttempt: () -> Bool = { true },
        readRange: (Int, Int) -> String?
    ) -> Result {
        let attemptLimit = min(max(0, maxAttempts), maximumAttempts)
        guard budget > 0, attemptLimit > 0 else {
            return Result(text: nil, consumedUnits: 0, attempts: 0, failure: nil)
        }
        var consumed = 0
        var attempts = 0
        var best: String?
        var bestUnits = -1
        let maxTarget = min(budget, maximumPrefixUnits)
        var requested = min(max(1, min(maximumPrefixUnits, initialPrefixUnits)), budget)
        var successfulRequest = 0
        var failedRequest: Int?

        func result(_ failure: Failure? = nil) -> Result {
            Result(text: failure == nil ? best : nil, consumedUnits: consumed, attempts: attempts, failure: failure)
        }

        while attempts < attemptLimit {
            guard shouldContinue() else { return result(.interrupted) }
            guard canStartAttempt() else { break }
            let remaining = budget - consumed
            guard requested > 0, requested <= remaining, requested <= maximumPrefixUnits else { break }
            attempts += 1
            let response = readRange(0, requested)
            let units = response?.utf16.count ?? 0
            let (sum, overflow) = consumed.addingReportingOverflow(units)
            consumed = overflow ? Int.max : sum
            let mayContinue = shouldContinue()
            guard !overflow, units <= requested, units <= remaining else {
                return result(.oversizedResponse)
            }
            guard mayContinue else { return result(.interrupted) }

            if let response {
                if response.isEmpty { failedRequest = requested }
                else { successfulRequest = requested }
                let uncertainEnd = response.unicodeScalars.last?.value == 0xFFFD
                if !uncertainEnd, units > bestUnits {
                    best = response
                    bestUnits = units
                }
                if stopAfterNonempty, !response.isEmpty, !uncertainEnd { break }
                if requested >= maxTarget, !response.isEmpty, !uncertainEnd { break }
            } else {
                failedRequest = requested
            }

            let available = budget - consumed
            let next: Int
            if let failedRequest {
                let upper = min(failedRequest - 1, available)
                guard upper > successfulRequest else { break }
                next = successfulRequest + (upper - successfulRequest + 1) / 2
            } else {
                next = min(requested * 2, maximumPrefixUnits, available)
                guard next > requested else { break }
            }
            requested = next
        }
        return result()
    }
}

/// Surface leaf wrapper around StaticTextRangeProbe with pre/post security checks and text charging.
public enum SurfaceStaticTextRead {
    public static func read(
        budget: Int,
        maxAttempts: Int = StaticTextRangeProbe.maximumAttempts,
        initialPrefixUnits: Int? = nil,
        stopAfterNonempty: Bool = false,
        sampleGeometry: () -> Void,
        canStartAttempt: () -> Bool,
        shouldContinue: () -> Bool,
        precheck: () -> Bool,
        readRange: (Int, Int) -> String?,
        charge: (Int) -> Bool,
        postcheck: () -> Bool
    ) -> StaticTextRangeProbe.Result {
        var rejected = false
        func continuation() -> Bool { !rejected && shouldContinue() }
        guard budget > 0, maxAttempts > 0 else {
            return .init(text: nil, consumedUnits: 0, attempts: 0, failure: nil)
        }
        guard continuation() else {
            return .init(text: nil, consumedUnits: 0, attempts: 0, failure: .interrupted)
        }
        guard canStartAttempt() else {
            return .init(text: nil, consumedUnits: 0, attempts: 0, failure: nil)
        }
        sampleGeometry()
        return StaticTextRangeProbe.read(
            budget: budget,
            maxAttempts: maxAttempts,
            initialPrefixUnits: initialPrefixUnits ?? min(budget, StaticTextRangeProbe.maximumPrefixUnits),
            stopAfterNonempty: stopAfterNonempty,
            shouldContinue: continuation,
            canStartAttempt: canStartAttempt,
            readRange: { start, length in
                guard precheck() else { rejected = true; return nil }
                let value = readRange(start, length)
                let charged = value.map { charge($0.utf16.count) } ?? true
                let accepted = postcheck()
                if !charged || !accepted { rejected = true }
                return value
            }
        )
    }
}

/// Safe fallback for already-verified non-sensitive `AXStaticText` leaves when
/// `AXStringForRange` yields no text: checks cached batch title/description first
/// (zero extra IPCs), then performs at most one bounded `AXValue` read.
public enum StaticTextFallback {
    public enum Safety: Equatable {
        case ok
        case sensitive
        case budgetExhausted
        case unavailable
    }

    public enum Outcome: Equatable {
        case text(value: String, truncated: Bool)
        case empty
        case sensitive
        case budgetExhausted
        case textBudgetViolated
        case unavailable
    }

    public static func resolve(
        maxUnits: Int,
        cachedTitle: String?,
        cachedDescription: String?,
        verifySafety: () -> Safety,
        readValue: () -> String?,
        charge: (Int) -> Bool
    ) -> Outcome {
        guard maxUnits > 0 else { return .unavailable }

        func accept(_ raw: String) -> Outcome {
            guard !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return .empty
            }
            let sliceLength = min(raw.utf16.count, maxUnits)
            guard let bounded = boundedUTF16Slice(raw, start: 0, length: sliceLength), !bounded.isEmpty else {
                return .unavailable
            }
            guard charge(bounded.utf16.count) else {
                return .textBudgetViolated
            }
            return .text(value: bounded, truncated: bounded.utf16.count < raw.utf16.count)
        }

        for candidate in [cachedTitle, cachedDescription] {
            if let candidate, !candidate.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                return accept(candidate)
            }
        }

        switch verifySafety() {
        case .ok: break
        case .sensitive: return .sensitive
        case .budgetExhausted: return .budgetExhausted
        case .unavailable: return .unavailable
        }

        guard let rawValue = readValue() else { return .unavailable }

        switch verifySafety() {
        case .ok: break
        case .sensitive: return .sensitive
        case .budgetExhausted: return .budgetExhausted
        case .unavailable: return .unavailable
        }

        return accept(rawValue)
    }
}

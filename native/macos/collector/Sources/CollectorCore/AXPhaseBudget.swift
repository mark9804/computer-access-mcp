/// Pure monotonic scheduling for best-effort AX channels. The hard deadline is
/// never extended: optional work must leave time for fresh identity/security
/// checks, and an AX call must never receive the zero (default) timeout.
public enum AXPhaseBudget {
    public static let finalValidationReserveMs: Int64 = 350
    public static let minimumOptionalMs: Int64 = 200

    public static func optionalDeadline(nowMs: Int64, hardDeadlineMs: Int64) -> Int64? {
        guard nowMs >= 0, hardDeadlineMs > nowMs else { return nil }
        let remaining = hardDeadlineMs - nowMs
        let reserve = min(finalValidationReserveMs, remaining / 2)
        guard remaining - reserve >= minimumOptionalMs else { return nil }
        return hardDeadlineMs - reserve
    }

    /// Window traversal must leave its own validation room INSIDE the optional
    /// phase. It never consumes or extends the session's later hard-phase reserve.
    public static func surfaceExplorationDeadline(nowMs: Int64, optionalDeadlineMs: Int64) -> Int64? {
        guard nowMs >= 0, optionalDeadlineMs > nowMs else { return nil }
        let remaining = optionalDeadlineMs - nowMs
        let reserve: Int64 = 150
        guard remaining - reserve >= 25 else { return nil }
        return optionalDeadlineMs - reserve
    }

    /// Window identity/security checks retain their active phase deadline. Only
    /// optional position/size IPC receives the short geometry deadline, computed
    /// AFTER those checks. A failed boundary never invokes the geometry reader.
    public static func readOptionalGeometry<Value>(nowMs: () -> Int64, phaseDeadlineMs: Int64,
                                                   verifyBoundary: () -> Bool,
                                                   read: (Int64) -> Value?) -> Value? {
        func geometryDeadline() -> Int64? {
            let now = nowMs()
            guard now >= 0, phaseDeadlineMs > now, phaseDeadlineMs - now > 50 else { return nil }
            return min(phaseDeadlineMs - 50, now + 20)
        }
        guard geometryDeadline() != nil, verifyBoundary(), let deadline = geometryDeadline() else { return nil }
        return read(deadline)
    }

    /// Best-effort observer rebinding shares one short deadline, including old
    /// removals and new registrations. Preserve the existing final-validation
    /// reserve and any earlier active phase; no new budget per notification.
    public static func observerDeadline(nowMs: Int64, hardDeadlineMs: Int64, phaseDeadlineMs: Int64) -> Int64? {
        guard let optional = optionalDeadline(nowMs: nowMs, hardDeadlineMs: hardDeadlineMs),
              phaseDeadlineMs > nowMs else { return nil }
        return min(optional, phaseDeadlineMs, nowMs + min(100, hardDeadlineMs - nowMs))
    }

    /// Configure the exact receiver, then recheck the same fixed deadline before
    /// starting its notification IPC. Rejection is optional subscription loss,
    /// never content authority. The OS still owns whether its call honors timeout.
    public static func observerCall(nowMs: () -> Int64, deadlineMs: Int64,
                                    setTimeout: (Float) -> Bool, perform: () -> Bool) -> Bool {
        guard let timeout = messagingTimeout(configuredSeconds: 0.1, nowMs: nowMs(), deadlineMs: deadlineMs),
              setTimeout(timeout), nowMs() < deadlineMs else { return false }
        return perform()
    }

    /// Int64.max means no phase cutoff, not an infinite messaging timeout.
    /// Reject an exhausted phase rather than rounding it up or passing zero.
    public static func messagingTimeout(configuredSeconds: Float, nowMs: Int64, deadlineMs: Int64) -> Float? {
        guard configuredSeconds.isFinite, configuredSeconds >= 0.001,
              nowMs >= 0, deadlineMs > nowMs else { return nil }
        let remainingMs = deadlineMs - nowMs
        guard remainingMs >= 1 else { return nil }
        return min(configuredSeconds, Float(Double(remainingMs) / 1_000))
    }
}

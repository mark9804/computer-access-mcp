import Foundation

/// Focused-field AX surface interface.
public protocol TextFieldProvider: AnyObject {
    func application() -> ApplicationIdentity?
    func resolveFocusedField() -> Bool
    func role() -> String?
    func secureStatus() -> SecureStatus
    func numberOfCharacters() -> Int?
    func visibleRange() -> TextSelection?
    func stringForRange(start: Int, length: Int) -> String?
    func markerStringForRange(start: Int, length: Int) -> String?
    func boundedKnownLengthValue() -> String?
    func selectedRange() -> TextSelection?
    func remainsSameFocusAndWindow() -> Bool
}

public extension TextFieldProvider {
    func visibleRange() -> TextSelection? { nil }
    func markerStringForRange(start: Int, length: Int) -> String? { nil }
}

public enum BrowserGate {
    public static let privateWindowIndicators: [String] = GeneratedPolicyCatalog.privateWindowIndicators

    public static func allows(_ id: String, policy: CapturePolicy, isBrowserCandidate: Bool = false) -> Bool {
        guard ApplicationPolicy.allows(id, policy: policy) else { return false }
        return !(isBrowserCandidate || isKnownBrowser(id)) || (policy.applicationScope == "denylist" && policy.allowBrowserContent == true)
    }

    public static func isKnownBrowser(_ id: String) -> Bool {
        let name = id.lowercased()
        return GeneratedPolicyCatalog.browserFamilies.contains {
            let family = $0.lowercased()
            return name == family || name.hasPrefix(family + ".")
        }
    }

    public static func isPrivateWindowTitle(_ title: String) -> Bool {
        let normalized = title.lowercased()
        return privateWindowIndicators.contains { normalized.contains($0) }
    }

    public static func shouldBlockPrivateWindows(applicationId: String, spec: AppAdapterSpec) -> Bool {
        spec.blockPrivateWindows || isKnownBrowser(applicationId)
    }
}

public struct BoundedTextReader {
    public init() {}

    public func read(
        ticket: ReadTicket,
        provider: TextFieldProvider,
        clock: CollectorClock,
        staticTextProbe: StaticTextPolicy = .boundedRangeProbe(maxUnits: StaticTextRangeProbe.maximumPrefixUnits)
    ) -> ReadResult {
        let start = clock.unixMs
        func failure(_ reason: String, _ code: ReadDiagnostic.Code, _ role: ReadDiagnostic.Role? = nil) -> ReadResult {
            ReadResult(
                token: ticket.token,
                reason: reason,
                diagnostic: ReadDiagnostic(code: code, role: role),
                captureStartMs: start,
                captureEndMs: max(start, clock.unixMs)
            )
        }
        func securityFailure(_ status: SecureStatus) -> ReadDiagnostic.Code {
            status == .sensitive ? .secureField : .fieldSecurityUnknown
        }
        guard ticket.policy.enabled else { return failure("stale", .invalidSamplingPolicy) }
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline) }
        guard ticket.policy.hasValidTextSettings else { return failure("policy-boundary", .invalidSamplingPolicy) }
        guard let app = provider.application() else { return failure("policy-boundary", .applicationUnavailable) }
        guard ApplicationPolicy.allows(app.applicationId, policy: ticket.policy) else {
            return failure(ApplicationPolicy.isSystemUI(app.applicationId) ? "application-excluded" : "policy-boundary", .applicationNotAllowed)
        }
        guard BrowserGate.allows(app.applicationId, policy: ticket.policy) else { return failure("policy-boundary", .browserExcluded) }
        if let hint = ticket.hint, hint.application != app { return failure("stale", .focusChanged) }
        guard provider.resolveFocusedField() else { return failure("focus-unavailable", .focusedFieldUnavailable) }

        let textRoles = ["AXTextField", "AXTextArea", "AXStaticText"]
        let observedRole = provider.role()
        let diagnosticRole = ReadDiagnostic.Role(normalizing: observedRole)
        guard let role = observedRole, textRoles.contains(role) else {
            return failure("policy-boundary", diagnosticRole == .secureTextField ? .secureField : .focusedRoleNotText, diagnosticRole)
        }
        let security = provider.secureStatus()
        guard ticket.policy.allows(security) else { return failure("policy-boundary", securityFailure(security), diagnosticRole) }

        let budget = min(max(1, ticket.policy.maxTextCodeUnits), 8192)
        let rawLength = provider.numberOfCharacters()
        let length = rawLength.flatMap { $0 >= 0 && $0 <= 9_007_199_254_740_991 ? $0 : nil }
        let visible = ticket.policy.textRange == "visible"
        let basis = visible ? "visible" : "prefix"
        let sampled: TextSelection
        if visible {
            guard let length, let range = provider.visibleRange(),
                  range.start >= 0, range.length >= 0, range.start <= length,
                  range.length <= length - range.start,
                  range.length > 0 || length == 0 else { return failure("read-error", .visibleRangeUnavailable, diagnosticRole) }
            sampled = range
        } else {
            sampled = TextSelection(start: 0, length: length ?? budget)
        }

        let probeMaxUnits: Int?
        if case .boundedRangeProbe(let maxUnits) = staticTextProbe {
            probeMaxUnits = max(1, min(StaticTextRangeProbe.maximumPrefixUnits, maxUnits))
        } else {
            probeMaxUnits = nil
        }
        let probeStaticText = !visible && role == "AXStaticText" && (length == nil || length == 0) && probeMaxUnits != nil
        let requested = probeStaticText ? min(budget, probeMaxUnits!) : min(sampled.length, budget)

        guard provider.remainsSameFocusAndWindow() else { return failure("stale", .focusChanged, diagnosticRole) }
        let beforeRole = provider.role()
        guard beforeRole == role else { return failure("stale", .focusChanged, .init(normalizing: beforeRole)) }
        let beforeSecurity = provider.secureStatus()
        guard ticket.policy.allows(beforeSecurity) else { return failure("stale", securityFailure(beforeSecurity), diagnosticRole) }
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline, diagnosticRole) }

        var text: String?
        var source = "ax.range"
        var staticProbe: StaticTextRangeProbe.Result?
        if probeStaticText {
            var probeFailure: ReadResult?
            func mayProbe() -> Bool {
                guard probeFailure == nil else { return false }
                guard clock.monotonicMs < ticket.deadlineMonotonicMs else {
                    probeFailure = failure("stale", .readDeadline, diagnosticRole); return false
                }
                guard provider.remainsSameFocusAndWindow(), provider.application() == app else {
                    probeFailure = failure("stale", .focusChanged, diagnosticRole); return false
                }
                let currentRole = provider.role()
                guard currentRole == role else {
                    probeFailure = failure("stale", .focusChanged, .init(normalizing: currentRole)); return false
                }
                let currentSecurity = provider.secureStatus()
                guard ticket.policy.allows(currentSecurity) else {
                    probeFailure = failure("stale", securityFailure(currentSecurity), diagnosticRole); return false
                }
                guard clock.monotonicMs < ticket.deadlineMonotonicMs else {
                    probeFailure = failure("stale", .readDeadline, diagnosticRole); return false
                }
                return true
            }
            let probe = StaticTextRangeProbe.read(budget: requested, shouldContinue: mayProbe) { start, length in
                provider.stringForRange(start: start, length: length)
            }
            if let probeFailure { return probeFailure }
            guard probe.failure == nil else { return failure("read-error", .textResultInvalid, diagnosticRole) }
            guard let probeText = probe.text else { return failure("read-error", .textReadUnavailable, diagnosticRole) }
            staticProbe = probe
            text = probeText
        } else if length == 0 {
            text = ""
        } else {
            text = provider.stringForRange(start: sampled.start, length: requested)
        }

        if !probeStaticText, text == nil, ticket.policy.textMarkers == true {
            guard provider.remainsSameFocusAndWindow(), provider.application() == app, provider.role() == role else { return failure("stale", .focusChanged, diagnosticRole) }
            let markerSecurity = provider.secureStatus()
            guard ticket.policy.allows(markerSecurity) else { return failure("stale", securityFailure(markerSecurity), diagnosticRole) }
            guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline, diagnosticRole) }
            source = "ax.marker"
            text = provider.markerStringForRange(start: sampled.start, length: requested)
        }
        if !probeStaticText, !visible, text == nil, let length, length <= budget {
            // AX lacks an atomic length+value read; verify character count before and after fallback.
            guard provider.numberOfCharacters() == length else { return failure("read-error", .textResultInvalid, diagnosticRole) }
            guard provider.remainsSameFocusAndWindow() else { return failure("read-error", .focusChanged, diagnosticRole) }
            let fallbackSecurity = provider.secureStatus()
            guard ticket.policy.allows(fallbackSecurity) else { return failure("read-error", securityFailure(fallbackSecurity), diagnosticRole) }
            guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("read-error", .readDeadline, diagnosticRole) }
            source = "ax.value"
            text = provider.boundedKnownLengthValue()
        }
        guard let text else { return failure("read-error", .textReadUnavailable, diagnosticRole) }
        guard text.utf16.count <= requested,
              probeStaticText || length == nil || text.utf16.count <= length! - sampled.start,
              !visible || !text.isEmpty || length == 0 else { return failure("read-error", .textResultInvalid, diagnosticRole) }
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline, diagnosticRole) }
        guard provider.remainsSameFocusAndWindow() else { return failure("stale", .focusChanged, diagnosticRole) }
        let afterRole = provider.role()
        guard afterRole == role else { return failure("stale", .focusChanged, .init(normalizing: afterRole)) }
        let afterSecurity = provider.secureStatus()
        guard ticket.policy.allows(afterSecurity) else { return failure("stale", securityFailure(afterSecurity), diagnosticRole) }

        let actualLength = text.utf16.count
        let complete = !probeStaticText && !visible && sampled.start == 0 && length == actualLength
        var reasons: [String] = []
        let truncated: Bool
        if probeStaticText {
            reasons.append("static-text-length-unverified")
            truncated = true
        } else if visible {
            reasons.append("visible-range-only")
            if sampled.length > budget { reasons.append("text-budget") }
            if actualLength < requested { reasons.append("range-short-read") }
            truncated = sampled.length > budget || actualLength < requested
        } else {
            if length == nil { reasons.append("length-unknown") }
            else if !complete { reasons.append(length! > budget ? "text-budget" : "range-short-read") }
            truncated = !complete
        }

        var selection = provider.selectedRange()
        if let s = selection {
            if s.start < sampled.start || s.length < 0 || s.start - sampled.start > actualLength ||
                s.length > actualLength - (s.start - sampled.start) { selection = nil }
        }
        if let length, provider.numberOfCharacters() != length { return failure("stale", .textResultInvalid, diagnosticRole) }
        if visible, provider.visibleRange() != sampled { return failure("stale", .visibleRangeUnavailable, diagnosticRole) }
        guard provider.remainsSameFocusAndWindow(), !probeStaticText || provider.application() == app else { return failure("stale", .focusChanged, diagnosticRole) }
        let finalRole = provider.role()
        guard finalRole == role else { return failure("stale", .focusChanged, .init(normalizing: finalRole)) }
        let finalSecurity = provider.secureStatus()
        guard ticket.policy.allows(finalSecurity) else { return failure("stale", securityFailure(finalSecurity), diagnosticRole) }
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline, diagnosticRole) }

        return ReadResult(
            token: ticket.token,
            application: app,
            text: TextRead(
                text: text,
                source: source,
                totalLength: probeStaticText ? nil : length,
                selection: selection,
                rangeStart: sampled.start,
                rangeBasis: basis,
                complete: complete,
                truncated: truncated,
                missingReasons: reasons,
                readUnits: staticProbe?.consumedUnits
            ),
            captureStartMs: start,
            captureEndMs: max(start, clock.unixMs)
        )
    }
}

import XCTest
import HistoryContract
@testable import CollectorCore

/// Records the existing narrow surface, never a real AX provider.
private final class DiagnosticProvider: TextFieldProvider {
    let base = FakeProvider()
    var applicationAvailable = true
    var calls: [String] = []
    func application() -> ApplicationIdentity? { calls.append("application"); return applicationAvailable ? base.application() : nil }
    func resolveFocusedField() -> Bool { calls.append("resolve"); return base.resolveFocusedField() }
    func role() -> String? { calls.append("role"); return base.role() }
    func secureStatus() -> SecureStatus { calls.append("security"); return base.secureStatus() }
    func numberOfCharacters() -> Int? { calls.append("length"); return base.numberOfCharacters() }
    func visibleRange() -> TextSelection? { calls.append("visible"); return base.visibleRange() }
    func stringForRange(start: Int, length: Int) -> String? { calls.append("range"); return base.stringForRange(start: start, length: length) }
    func boundedKnownLengthValue() -> String? { calls.append("value"); return base.boundedKnownLengthValue() }
    func selectedRange() -> TextSelection? { calls.append("selection"); return base.selectedRange() }
    func remainsSameFocusAndWindow() -> Bool { calls.append("stable"); return base.remainsSameFocusAndWindow() }
}

final class ReadDiagnosticTests: XCTestCase {
    func testMenuItemRefusalPreservesCoarseReasonAndDoesNotReadSecurityOrText() {
        let clock = FakeClock(); let provider = DiagnosticProvider()
        provider.base.fieldRole = "AXMenuItem"; provider.base.secure = .unknown
        let result = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
        XCTAssertEqual(result.reason, "policy-boundary")
        XCTAssertEqual(result.diagnostic, ReadDiagnostic(code: .focusedRoleNotText, role: .menuItem))
        XCTAssertNil(result.text)
        XCTAssertEqual(provider.calls, ["application", "resolve", "role"])
    }

    func testRoleNormalizationNeverCopiesUnknownOrSensitiveProviderText() throws {
        for (raw, expected) in [("private paragraph and title", ReadDiagnostic.Role.other), (nil, .unavailable)] as [(String?, ReadDiagnostic.Role)] {
            let clock = FakeClock(); let provider = FakeProvider(); provider.fieldRole = raw
            let result = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
            XCTAssertEqual(result.diagnostic, ReadDiagnostic(code: .focusedRoleNotText, role: expected))
            XCTAssertEqual(provider.textCalls, 0); XCTAssertEqual(provider.lengthCalls, 0)
            let data = try JSONEncoder().encode(XCTUnwrap(result.diagnostic))
            XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("private paragraph"))
        }
        for role in ReadDiagnostic.Role.allCases {
            XCTAssertEqual(ReadDiagnostic.Role(normalizing: role.rawValue), role)
        }
    }

    func testSensitiveAndUnknownSecurityHaveDifferentFixedDiagnostics() {
        for (security, code) in [(SecureStatus.sensitive, ReadDiagnostic.Code.secureField), (.unknown, .fieldSecurityUnknown)] {
            let clock = FakeClock(); let provider = DiagnosticProvider(); provider.base.secure = security
            let result = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
            XCTAssertEqual(result.reason, "policy-boundary")
            XCTAssertEqual(result.diagnostic, ReadDiagnostic(code: code, role: .textField))
            XCTAssertEqual(provider.calls, ["application", "resolve", "role", "security"])
        }
        let clock = FakeClock(); let provider = DiagnosticProvider(); provider.base.fieldRole = "AXSecureTextField"
        let result = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
        XCTAssertEqual(result.diagnostic, ReadDiagnostic(code: .secureField, role: .secureTextField))
        XCTAssertEqual(provider.calls, ["application", "resolve", "role"])
    }

    func testApplicationAndBrowserRejectionsRemainBeforeAnyAXCall() {
        for (app, allowed, code) in [("denied.app", false, ReadDiagnostic.Code.applicationNotAllowed), ("com.apple.Safari", true, .applicationNotAllowed), ("com.google.Chrome", true, .browserExcluded), ("com.google.Chrome.canary", true, .browserExcluded), ("org.mozilla.firefox", true, .browserExcluded)] {
            let clock = FakeClock(); let provider = DiagnosticProvider(); provider.base.app.applicationId = app
            var policy = CapturePolicy(); if allowed { policy.allowedApplicationIds = [app] }
            let result = BoundedTextReader().read(ticket: ticket(clock, policy: policy), provider: provider, clock: clock)
            XCTAssertEqual(result.reason, "policy-boundary")
            XCTAssertEqual(result.diagnostic, ReadDiagnostic(code: code))
            XCTAssertEqual(provider.calls, ["application"])
        }
    }

    func testUnavailableApplicationDoesNotClaimBrowserExclusion() {
        let clock = FakeClock(); let provider = DiagnosticProvider(); provider.applicationAvailable = false
        let result = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
        XCTAssertEqual(result.reason, "policy-boundary")
        XCTAssertEqual(result.diagnostic, ReadDiagnostic(code: .applicationUnavailable))
        XCTAssertEqual(provider.calls, ["application"])
    }

    func testUnavailableFocusDoesNotReadRoleOrText() {
        let clock = FakeClock(); let provider = DiagnosticProvider(); provider.base.found = false
        let result = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
        XCTAssertEqual(result.reason, "focus-unavailable")
        XCTAssertEqual(result.diagnostic, ReadDiagnostic(code: .focusedFieldUnavailable))
        XCTAssertEqual(provider.calls, ["application", "resolve"])
    }

    func testUnavailableAndInvalidBoundedTextAreDistinctAndNeverCopyBody() throws {
        for (value, code) in [(nil, ReadDiagnostic.Code.textReadUnavailable), ("private oversized paragraph", .textResultInvalid)] as [(String?, ReadDiagnostic.Code)] {
            let clock = FakeClock(); let provider = FakeProvider(); provider.rangeValue = value; provider.fullValue = nil
            let result = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
            XCTAssertEqual(result.reason, "read-error")
            XCTAssertEqual(result.diagnostic, ReadDiagnostic(code: code, role: .textField))
            XCTAssertNil(result.text)
            let encoded = try JSONEncoder().encode(result)
            XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("private oversized paragraph"))
            let diagnostic = try XCTUnwrap(result.diagnostic)
            XCTAssertEqual(diagnostic.json, .object(["code": .string(code.rawValue), "role": .string("AXTextField")]))
        }
    }

    func testFocusChangeAndDeadlineDiscardBodyWithUnchangedCoarseReason() {
        for deadline in [false, true] {
            let clock = FakeClock(); let provider = FakeProvider()
            provider.onRange = { if deadline { clock.advance(101) } else { provider.stable = false } }
            let result = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
            XCTAssertEqual(result.reason, "stale")
            XCTAssertEqual(result.diagnostic, ReadDiagnostic(code: deadline ? .readDeadline : .focusChanged, role: .textField))
            XCTAssertNil(result.text)
        }
    }

    func testFallbackRejectionsPreserveReadErrorAndShortCircuitOrder() {
        for security in [SecureStatus.sensitive, .unknown] {
            let clock = FakeClock(); let provider = DiagnosticProvider(); provider.base.rangeValue = nil
            provider.base.onRange = { provider.base.secure = security }
            let result = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
            XCTAssertEqual(result.reason, "read-error")
            XCTAssertEqual(result.diagnostic?.code, security == .sensitive ? .secureField : .fieldSecurityUnknown)
            XCTAssertEqual(provider.base.valueCalls, 0)
            XCTAssertEqual(provider.calls, ["application", "resolve", "role", "security", "length", "stable", "role", "security", "range", "length", "stable", "security"])
        }
    }

    func testInvalidPolicyAndInitialDeadlineDoNotReachProvider() {
        let clock = FakeClock(); let provider = DiagnosticProvider()
        let invalid = BoundedTextReader().read(ticket: ticket(clock, policy: CapturePolicy(textRange: "whole-field")), provider: provider, clock: clock)
        XCTAssertEqual(invalid.reason, "policy-boundary"); XCTAssertEqual(invalid.diagnostic?.code, .invalidSamplingPolicy)
        var expired = ticket(clock); expired.deadlineMonotonicMs = clock.monotonicMs
        let late = BoundedTextReader().read(ticket: expired, provider: provider, clock: clock)
        XCTAssertEqual(late.reason, "stale"); XCTAssertEqual(late.diagnostic?.code, .readDeadline)
        XCTAssertTrue(provider.calls.isEmpty)
    }

    func testTypedDiagnosticRejectsUnknownWireValuesAndLegacyResultStillDecodes() throws {
        for raw in ["{\"code\":\"private text\"}", "{\"code\":\"focused-role-not-text\",\"role\":\"private title\"}"] {
            XCTAssertThrowsError(try JSONDecoder().decode(ReadDiagnostic.self, from: Data(raw.utf8)))
        }
        let legacy = Data("{\"token\":\"token\",\"reason\":\"read-error\",\"captureStartMs\":1,\"captureEndMs\":1}".utf8)
        XCTAssertNil(try JSONDecoder().decode(ReadResult.self, from: legacy).diagnostic)
        let extra = Data("{\"code\":\"focused-role-not-text\",\"role\":\"AXMenuItem\",\"title\":\"private title\"}".utf8)
        let normalized = try JSONDecoder().decode(ReadDiagnostic.self, from: extra)
        XCTAssertEqual(normalized.json, .object(["code": .string("focused-role-not-text"), "role": .string("AXMenuItem")]))
    }

    func testPublicUnresolvedGapPreservesFixedDiagnosticAndValidates() throws {
        let h = Harness(); h.start(); let current = try XCTUnwrap(h.env.launched.last)
        let provider = FakeProvider(); provider.fieldRole = "AXMenuItem"
        let result = BoundedTextReader().read(ticket: current, provider: provider, clock: h.clock)
        h.engine.complete(result)
        let frame = try XCTUnwrap(h.frames.last)
        XCTAssertEqual(frame["payload"]?["kind"], .string("gap"))
        XCTAssertEqual(frame["payload"]?["reason"], .string("policy-boundary"))
        XCTAssertEqual(frame["payload"]?["diagnostic"], .object(["code": .string("focused-role-not-text"), "role": .string("AXMenuItem")]))
        XCTAssertEqual(frame["target"]?["kind"], .string("unresolved"))
        let validator = try ContractValidator()
        for frame in h.frames { XCTAssertNoThrow(try validator.encodeFrame(frame)) }
    }

    func testNativeDiagnosticVocabularyMatchesThePublicWireSchema() throws {
        let validator = try ContractValidator()
        let variants = ReadDiagnostic.Code.allCases.map { ReadDiagnostic(code: $0) } +
            ReadDiagnostic.Role.allCases.map { ReadDiagnostic(code: .focusedRoleNotText, role: $0) }
        // Code and role enum membership are independent. Cover each once rather
        // than the old code × (all roles + nil) Cartesian product.
        for diagnostic in variants {
            let h = Harness(); h.start()
            h.engine.complete(ReadResult(token: h.env.launched.last!.token, reason: "read-error", diagnostic: diagnostic,
                captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs))
            XCTAssertNoThrow(try validator.encodeFrame(XCTUnwrap(h.frames.last)))
        }
    }

    func testReadErrorAndUnknownReasonNeverSynthesizeOrCopyFreeformDiagnostic() throws {
        for reason in ["read-error", "private paragraph and window title"] {
            let h = Harness(); h.start()
            h.engine.complete(ReadResult(token: h.env.launched.last!.token, reason: reason, captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs))
            let gap = try XCTUnwrap(h.frames.last)
            XCTAssertEqual(gap["payload"]?["reason"], .string("read-error")); XCTAssertNil(gap["payload"]?["diagnostic"])
            XCTAssertFalse(String(decoding: try gap.canonicalData(), as: UTF8.self).contains("private paragraph"))
        }
    }

    func testGoodResultIgnoresAttachedDiagnostic() throws {
        let h = Harness(); h.start(); var result = h.goodResult(h.env.launched.last!)
        result.diagnostic = ReadDiagnostic(code: .focusedRoleNotText, role: .menuItem)
        h.engine.complete(result)
        XCTAssertEqual(h.textFrames.count, 1)
        XCTAssertFalse(h.frames.contains { $0["payload"]?["diagnostic"] != nil })
        let validator = try ContractValidator()
        for frame in h.frames { XCTAssertNoThrow(try validator.encodeFrame(frame)) }
    }

    func testBoundaryStaleAndFreshLockDiscardDiagnosticWithoutPublishingIt() {
        for boundary in ["pause", "application", "lock", "fresh-lock", "fresh-permission"] {
            let h = Harness(); h.start(); let current = h.env.launched.last!
            let result = ReadResult(token: current.token, reason: "policy-boundary", diagnostic: ReadDiagnostic(code: .focusedRoleNotText, role: .menuItem), captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
            switch boundary {
            case "pause": h.control("pause")
            case "application": h.engine.applicationEvent(SourceHint(application: FakeProvider().app, eventTimeMs: h.clock.unixMs))
            case "lock": h.engine.desktopChanged(.locked, accessibility: true)
            case "fresh-lock": h.env.desktop = .locked
            default: h.env.accessibility = false
            }
            let observations = h.frames.filter { $0["type"] == .string("observation") }.count
            h.engine.complete(result)
            XCTAssertEqual(h.frames.filter { $0["type"] == .string("observation") }.count, observations)
            XCTAssertFalse(h.frames.contains { $0["payload"]?["diagnostic"] != nil })
            XCTAssertTrue(h.textFrames.isEmpty)
        }
    }

    func testTimeoutHasFixedDeadlineDiagnosticAndLateReplyCannotReplaceIt() throws {
        let h = Harness(); h.start(); let current = h.env.launched.last!
        h.clock.advance(201); h.engine.tick()
        XCTAssertEqual(h.frames.last?["payload"]?["reason"], .string("timeout"))
        XCTAssertEqual(h.frames.last?["payload"]?["diagnostic"], ReadDiagnostic(code: .readDeadline).json)
        let count = h.frames.count
        h.engine.complete(ReadResult(token: current.token, reason: "read-error", diagnostic: ReadDiagnostic(code: .textReadUnavailable), captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs))
        XCTAssertEqual(h.frames.count, count)
        XCTAssertNoThrow(try ContractValidator().encodeFrame(XCTUnwrap(h.frames.last)))
    }
}

import XCTest
import HistoryContract
@testable import CollectorCore

/// All text, identities, clocks and providers are synthetic. No AppKit, AX,
/// CGEvent, tap, clipboard, desktop access or permission prompts in these tests.
final class InputTextTests: XCTestCase {
    private let baseNanos: UInt64 = 1_000_000_000
    private func context(app: String = "test.allowed", pid: Int32 = 42, birth: String = "fixture-birth", window: String = "fixture-window", windowGeneration: Int64 = 1, surface: String = "fixture-field", epoch: Int64 = 1, revision: Int64 = 1, foreground: Int64 = 1, focus: Int64 = 1, privacy: InputTextPrivateState = .normal) -> InputTextContext {
        InputTextContext(target: InputTextTarget(application: ApplicationIdentity(applicationId: app, processId: pid, processStartTime: birth),
            deviceId: "fixture-device", osSessionId: "fixture-session", desktopId: "fixture-desktop", windowId: window, windowGeneration: windowGeneration),
            surfaceId: surface, captureEpoch: epoch, foregroundGeneration: foreground, focusGeneration: focus, policyRevision: revision, privateState: privacy)
    }
    private func policy(inputText: Bool? = true, inputActivity: Bool? = false) -> CapturePolicy {
        CapturePolicy(inputActivity: inputActivity, applicationScope: "denylist", inputText: inputText)
    }
    private func metadata(pid: Int32 = 42, nanos: UInt64 = 1_000_000_000, time: Int64 = 1_000) -> InputTextEventMetadata {
        InputTextEventMetadata(targetProcessId: pid, timestampNanoseconds: nanos, callbackTimeMs: time)
    }
    private func sample(text: String = "synthetic", time: Int64 = 1_000, context: InputTextContext? = nil, kind: InputTextKind = .text, modifiers: [InputTextModifier] = []) -> InputTextSample {
        InputTextSample(context: context ?? self.context(), eventKind: kind, text: text, modifiers: modifiers, callbackTimeMs: time)
    }
    private func record(_ sample: InputTextSample? = nil, source: InputTextSource = .fixture) -> InputTextEmission {
        var buffer = InputTextAccumulator(); buffer.add(sample ?? self.sample(), source: source)
        return buffer.takeDue(nowMs: 1_500, approvedContext: (sample ?? self.sample()).context)!
    }
    private func observation(_ record: InputTextEmission) -> JSONValue { .object([
        "protocolVersion": j(1), "type": .string("observation"), "eventId": .string("fixture:1"), "instanceId": .string("fixture"), "seq": j(1),
        "eventTimeMs": j(record.intervalEndMs), "monotonicMs": j(1_500), "target": record.context.target.json, "stamp": record.context.stamp,
        "actor": .string("unknown"), "relatedActionIds": .array([]), "payload": record.payload(),
    ]) }
    private func assertGap(_ value: InputTextCaptureDecision, _ expected: InputTextGapReason, file: StaticString = #filePath, line: UInt = #line) {
        guard case .gap(let reason) = value else { return XCTFail("Expected fixed gap", file: file, line: line) }
        XCTAssertEqual(reason, expected, file: file, line: line)
    }
    private func capture(text: String, modifiers: [InputTextModifier] = []) -> InputTextCaptureDecision {
        InputTextReadGate.capture(metadata: metadata(), modifiers: modifiers, policy: policy(), afterNanoseconds: 0,
            nowNanoseconds: { self.baseNanos }, safetyProvider: { _ in InputTextApprovedContext(context: self.context(), metadataMonotonicNanoseconds: self.baseNanos, role: .textArea) },
            readUnicode: { .text(text) })
    }

    func testDefaultOffIndependentFromInputActivity() throws {
        XCTAssertNil(CapturePolicy().inputText)
        for value: Bool? in [nil, false] {
            var providerCalls = 0; var unicodeCalls = 0
            let decision = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy(inputText: value, inputActivity: true), afterNanoseconds: 0,
                nowNanoseconds: { self.baseNanos }, safetyProvider: { _ in providerCalls += 1; return nil }, readUnicode: { unicodeCalls += 1; return .text("fixture") })
            assertGap(decision, .policyBoundary); XCTAssertEqual(providerCalls, 0); XCTAssertEqual(unicodeCalls, 0)
        }
        guard case .sample = capture(text: "fixture") else { return XCTFail("inputText alone must be independent") }
    }
    func testMissingSafetyApprovalBlocksBeforeUnicode() {
        var reads = 0
        let result = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy(), afterNanoseconds: 0,
            nowNanoseconds: { self.baseNanos }, safetyProvider: { _ in nil }, readUnicode: { reads += 1; return .text("never-read") })
        assertGap(result, .stale); XCTAssertEqual(reads, 0)
    }
    func testMandatoryApplicationFamiliesBlockBeforeUnicode() {
        let ids = ["com.1password", "COM.1PASSWORD.1password", "com.1password.1password.autofill-extension", "com.1password.safari.extension", "com.agilebits.onepassword", "Com.Apple.Safari", "com.apple.safari.extension"]
        for id in ids {
            var reads = 0
            let result = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy(), afterNanoseconds: 0,
                nowNanoseconds: { self.baseNanos }, safetyProvider: { _ in InputTextApprovedContext(context: self.context(app: id), metadataMonotonicNanoseconds: self.baseNanos, role: .textField) },
                readUnicode: { reads += 1; return .text("never-read") })
            assertGap(result, .stale); XCTAssertEqual(reads, 0)
        }
        XCTAssertTrue(ApplicationPolicy.allows("com.1passwordish.fixture", policy: policy()))
        XCTAssertTrue(ApplicationPolicy.allows("com.apple.safarish.fixture", policy: policy()))
    }
    func testBrowserContentNeedsIndependentExplicitPolicyBeforeUnicode() {
        for id in ["com.google.Chrome", "org.mozilla.firefox", "com.apple.safari"] {
            var reads = 0
            let result = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy(), afterNanoseconds: 0, nowNanoseconds: { self.baseNanos },
                safetyProvider: { _ in InputTextApprovedContext(context: self.context(app: id), metadataMonotonicNanoseconds: self.baseNanos, role: .textArea) },
                readUnicode: { reads += 1; return .text("never-read") })
            assertGap(result, .stale); XCTAssertEqual(reads, 0)
        }
    }
    func testMissingFutureDelayedAndPreBoundaryEventsDoNotRead() {
        for timestamp in [UInt64(0), baseNanos + 1, baseNanos - 200_000_001, UInt64(900_000_000)] {
            var reads = 0; var providers = 0
            let result = InputTextReadGate.capture(metadata: metadata(nanos: timestamp), modifiers: [], policy: policy(), afterNanoseconds: 900_000_000,
                nowNanoseconds: { self.baseNanos }, safetyProvider: { _ in providers += 1; return nil }, readUnicode: { reads += 1; return .text("never-read") })
            assertGap(result, .stale); XCTAssertEqual(reads, 0); XCTAssertEqual(providers, 0)
        }
        XCTAssertTrue(InputTextLimits.eventIsFresh(metadata(nanos: 800_000_000), nowNanoseconds: baseNanos, afterNanoseconds: 0))
    }
    func testPIDMismatchAndInvalidContextBlockBeforeRead() {
        for (bad, expected) in [(context(pid: 99), InputTextGapReason.targetMismatch), (context(window: ""), .stale),
                                (context(surface: ""), .stale), (context(epoch: -1), .stale), (context(pid: 0), .stale)] {
            var reads = 0
            let result = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy(), afterNanoseconds: 0,
                nowNanoseconds: { self.baseNanos }, safetyProvider: { _ in InputTextApprovedContext(context: bad, metadataMonotonicNanoseconds: self.baseNanos, role: .textField) },
                readUnicode: { reads += 1; return .text("never-read") })
            assertGap(result, expected); XCTAssertEqual(reads, 0)
        }
    }
    func testCachedOrFutureSafetyMetadataCannotApproveRead() {
        for timestamp in [baseNanos - 1, baseNanos + 1] {
            var reads = 0
            let result = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy(), afterNanoseconds: 0,
                nowNanoseconds: { self.baseNanos }, safetyProvider: { _ in InputTextApprovedContext(context: self.context(), metadataMonotonicNanoseconds: timestamp, role: .textField) },
                readUnicode: { reads += 1; return .text("never-read") })
            assertGap(result, .stale); XCTAssertEqual(reads, 0)
        }
    }
    func testFlushApprovalBoundsEntireSafetyReadDespiteFreshCompletionTimestamp() {
        for elapsed: UInt64 in [0, 199_999_999, 200_000_000, 200_000_001, 1_000_000_000] {
            let finished = baseNanos + elapsed
            let approval = InputTextApprovedContext(context: context(), metadataMonotonicNanoseconds: finished, role: .textField)
            XCTAssertEqual(InputTextLimits.approvalIsFresh(approval, sinceNanoseconds: baseNanos, nowNanoseconds: finished, policy: policy()), elapsed <= 200_000_000)
        }
        let approval = InputTextApprovedContext(context: context(), metadataMonotonicNanoseconds: baseNanos, role: .textField)
        XCTAssertFalse(InputTextLimits.approvalIsFresh(approval, sinceNanoseconds: baseNanos + 1, nowNanoseconds: baseNanos, policy: policy()))
    }
    func testSafetyDelayOverEventFreshnessBudgetBlocksUnicode() {
        var now = baseNanos; var reads = 0
        let result = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy(), afterNanoseconds: 0, nowNanoseconds: { now },
            safetyProvider: { _ in now += 200_000_001; return InputTextApprovedContext(context: self.context(), metadataMonotonicNanoseconds: now, role: .textField) },
            readUnicode: { reads += 1; return .text("never-read") })
        assertGap(result, .verificationTimeout); XCTAssertEqual(reads, 0)
    }
    func testUnicodeReadOrderingAndFrozenContext() {
        var order: [String] = []; var calls = 0
        let original = context()
        let result = InputTextReadGate.capture(metadata: metadata(), modifiers: [.shift], policy: policy(), afterNanoseconds: 0, nowNanoseconds: { self.baseNanos },
            safetyProvider: { _ in calls += 1; order.append(calls == 1 ? "before" : "after"); return InputTextApprovedContext(context: original, metadataMonotonicNanoseconds: self.baseNanos, role: .textArea) },
            readUnicode: { order.append("unicode"); return .text("合成\u{1F9EA}") })
        XCTAssertEqual(order, ["before", "unicode", "after"])
        guard case .sample(let value) = result else { return XCTFail("Expected normalized synthetic sample") }
        XCTAssertEqual(value.context, original); XCTAssertEqual(value.text, "合成\u{1F9EA}"); XCTAssertEqual(value.modifiers, [.shift])
    }
    func testPostReadFocusPolicyEpochOrIdentityChangeDiscardsResult() {
        let mismatch: InputTextGapReason = .targetMismatch
        for (changed, expected) in [(context(surface: "other"), mismatch), (context(window: "other"), mismatch),
                                    (context(birth: "new-birth"), mismatch), (context(focus: 2), mismatch),
                                    (context(foreground: 2), .stale), (context(epoch: 2), .stale),
                                    (context(window: "other", epoch: 2), .stale), (context(revision: 2), .stale),
                                    (context(privacy: .userAuthorized), .stale)] {
            var calls = 0
            let result = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy(), afterNanoseconds: 0, nowNanoseconds: { self.baseNanos },
                safetyProvider: { _ in calls += 1; return InputTextApprovedContext(context: calls == 1 ? self.context() : changed, metadataMonotonicNanoseconds: self.baseNanos, role: .textField) },
                readUnicode: { .text("discard-fixture") })
            assertGap(result, expected); XCTAssertEqual(calls, 2)
        }
    }
    func testPostReadSafetyFailureOrEventExpiryDiscardsResult() {
        var calls = 0
        let failed = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy(), afterNanoseconds: 0, nowNanoseconds: { self.baseNanos },
            safetyProvider: { _ in calls += 1; return calls == 1 ? InputTextApprovedContext(context: self.context(), metadataMonotonicNanoseconds: self.baseNanos, role: .textArea) : nil },
            readUnicode: { .text("discard-fixture") })
        assertGap(failed, .stale)
        var now = baseNanos
        let expired = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy(), afterNanoseconds: 0, nowNanoseconds: { now },
            safetyProvider: { _ in InputTextApprovedContext(context: self.context(), metadataMonotonicNanoseconds: now, role: .textArea) },
            readUnicode: { now += 200_000_001; return .text("discard-fixture") })
        assertGap(expired, .verificationTimeout)
    }
    func testEachTypedVerificationFailureReportsOnlyADiagnosticWithoutDeliveringAnyInput() {
        let cases: [(InputTextGapReason, ReadDiagnostic.Code)] = [
            (.targetMismatch, .inputTargetMismatch), (.roleNotEditable, .inputRoleNotEditable),
            (.verificationTimeout, .inputVerificationTimeout), (.fieldSecurityUnknown, .inputFieldSecurityUnknown),
        ]
        for (reason, code) in cases {
            XCTAssertEqual(reason.rawValue, code.rawValue)
            XCTAssertEqual(reason.gapReason, "stale")
            XCTAssertEqual(reason.diagnostic.code, code)
            XCTAssertNil(reason.diagnostic.role)
            for isPostRead in [false, true] {
                var safetyCount = 0, unicodeCount = 0, rejections: [InputTextReadRejection] = []
                let decision = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy(),
                    afterNanoseconds: 0, nowNanoseconds: { self.baseNanos }, typedSafetyProvider: { _ in
                        safetyCount += 1
                        if isPostRead && safetyCount == 1 {
                            return .success(.init(context: self.context(), metadataMonotonicNanoseconds: self.baseNanos, role: .textField))
                        }
                        return .failure(reason)
                    }, readUnicode: { unicodeCount += 1; return .text("synthetic discard") }, onRejection: { rejections.append($0) })
                assertGap(decision, reason)
                XCTAssertEqual(safetyCount, isPostRead ? 2 : 1)
                XCTAssertEqual(unicodeCount, isPostRead ? 1 : 0)
                XCTAssertEqual(rejections, [.init(stage: isPostRead ? .postReadSafety : .preReadSafety, reason: .safetyUnavailable)])
            }
        }
        XCTAssertEqual(InputTextGapReason.stale.diagnostic.code, .inputContextUnverified)
        XCTAssertEqual(InputTextGapReason.readError.gapReason, "read-error")
        XCTAssertEqual(InputTextGapReason.budget.gapReason, "budget")
    }
    func testBufferedVerificationDistinctTimeoutAndUnknownNeverReturnAnApprovedContext() {
        let old = context()
        for expected in [InputTextGapReason.roleNotEditable, .fieldSecurityUnknown, .targetMismatch, .stale] {
            var calls: [String] = [], trace: [InputTextReadRejection.Reason] = []
            let result = InputTextReadGate.revalidateBufferedContext(old, policy: policy(), nowNanoseconds: { calls.append("clock"); return self.baseNanos },
                typedSafetyProvider: { request in
                    calls.append("safety")
                    guard case .flush(let frozen) = request else { XCTFail("Expected flush"); return .failure(.stale) }
                    XCTAssertEqual(frozen, old)
                    return .failure(expected)
                }, onRejection: { trace.append($0) })
            XCTAssertEqual(result, .failure(expected))
            XCTAssertEqual(calls, ["clock", "safety"]); XCTAssertEqual(trace, [.safetyUnavailable])
        }
        var now = baseNanos
        let elapsed = InputTextReadGate.revalidateBufferedContext(old, policy: policy(), nowNanoseconds: { now },
            typedSafetyProvider: { _ in
                now += 200_000_001
                return .success(.init(context: old, metadataMonotonicNanoseconds: now, role: .textField))
            })
        XCTAssertEqual(elapsed, .failure(.verificationTimeout))
        now = baseNanos
        let cached = InputTextReadGate.revalidateBufferedContext(old, policy: policy(), nowNanoseconds: { now },
            typedSafetyProvider: { _ in
                now += 200_000_001
                return .success(.init(context: old, metadataMonotonicNanoseconds: self.baseNanos - 1, role: .textField))
            })
        XCTAssertEqual(cached, .failure(.stale))
    }
    func testCommandControlShortcutNeverCallsUnicodeGetter() {
        for modifiers: [InputTextModifier] in [[.command], [.control], [.shift, .command, .command, .option, .control]] {
            var reads = 0
            let result = InputTextReadGate.capture(metadata: metadata(), modifiers: modifiers, policy: policy(), afterNanoseconds: 0, nowNanoseconds: { self.baseNanos },
                safetyProvider: { _ in InputTextApprovedContext(context: self.context(), metadataMonotonicNanoseconds: self.baseNanos, role: .textField) },
                readUnicode: { reads += 1; return .text("never-read") })
            guard case .sample(let value) = result else { return XCTFail("Expected shortcut evidence") }
            XCTAssertEqual(reads, 0); XCTAssertEqual(value.eventKind, .shortcut); XCTAssertEqual(value.text, "")
            XCTAssertEqual(value.modifiers, InputTextLimits.canonicalModifiers(modifiers))
        }
    }
    func testOptionOnlyRemainsUnicodeTextNotShortcut() {
        guard case .sample(let value) = capture(text: "é", modifiers: [.option]) else { return XCTFail("Expected text") }
        XCTAssertEqual(value.eventKind, .text); XCTAssertEqual(value.text, "é")
    }
    func testReturnIsEmptyEvidenceNotSubmitOrCompositionCommit() {
        for text in ["\r", "\n", "\u{3}"] {
            guard case .sample(let value) = capture(text: text) else { return XCTFail("Expected return evidence") }
            XCTAssertEqual(value.eventKind, .return); XCTAssertEqual(value.text, "")
            let payload = record(value).payload()
            XCTAssertEqual(payload["effect"], .string("unverified")); XCTAssertNil(payload["composition"])
            XCTAssertTrue(payload["coverage"]?["missingReasons"]?.arrayValue?.contains(.string("event-unicode-not-ime-commit")) == true)
        }
    }
    func testUnsupportedControlAndEmptyUnicodeAreIgnored() {
        for text in ["", "\t", "\u{7f}", "\u{1b}", "a\nb"] {
            guard case .ignored = capture(text: text) else { return XCTFail("Control text must not invent an editing action") }
        }
    }
    func testUnicodeSaturationEmitsGapNotTruncatedText() {
        assertGap(capture(text: String(repeating: "\u{1F9EA}", count: 1_025)), .budget)
        let result = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy(), afterNanoseconds: 0, nowNanoseconds: { self.baseNanos },
            safetyProvider: { _ in InputTextApprovedContext(context: self.context(), metadataMonotonicNanoseconds: self.baseNanos, role: .textArea) }, readUnicode: { .saturated })
        assertGap(result, .budget)
    }
    func testDebounceAggregatesUnicodeWithOriginalEventInterval() {
        var buffer = InputTextAccumulator()
        XCTAssertNil(buffer.add(sample(text: "合成", time: 1_000), source: .fixture))
        XCTAssertNil(buffer.add(sample(text: "\u{1F9EA}", time: 1_300), source: .fixture))
        XCTAssertNil(buffer.takeDue(nowMs: 1_799, approvedContext: context()))
        let value = buffer.takeDue(nowMs: 1_800, approvedContext: context())!
        XCTAssertEqual(value.text, "合成\u{1F9EA}"); XCTAssertEqual(value.eventCount, 2)
        XCTAssertEqual(value.intervalStartMs, 1_000); XCTAssertEqual(value.intervalEndMs, 1_300); XCTAssertNil(buffer.pending)
    }
    func testMaximumWaitFlushesDespiteOngoingTyping() {
        var buffer = InputTextAccumulator()
        for time: Int64 in stride(from: 1_000, through: 2_900, by: 100) { buffer.add(sample(text: "x", time: time), source: .fixture) }
        XCTAssertFalse(buffer.isDue(nowMs: 2_999)); XCTAssertTrue(buffer.isDue(nowMs: 3_000))
        let value = buffer.takeDue(nowMs: 3_000, approvedContext: context())!
        XCTAssertEqual(value.eventCount, 20); XCTAssertEqual(value.intervalEndMs, 2_900)
    }
    func testUTF16LimitAndCountLimitDropWholePendingOnOverflow() {
        var buffer = InputTextAccumulator()
        buffer.add(sample(text: String(repeating: "\u{1F9EA}", count: 1_024)), source: .fixture)
        XCTAssertEqual(buffer.pending?.text.utf16.count, 2_048)
        XCTAssertEqual(buffer.add(sample(text: "x"), source: .fixture), .budget); XCTAssertNil(buffer.pending)
        for _ in 0..<256 { XCTAssertNil(buffer.add(sample(text: "x"), source: .fixture)) }
        XCTAssertEqual(buffer.pending?.eventCount, 256)
        XCTAssertEqual(buffer.add(sample(text: "x"), source: .fixture), .budget); XCTAssertNil(buffer.pending)
        XCTAssertNil(buffer.takeDue(nowMs: 2_000, approvedContext: context()))
    }
    func testAllContextBoundariesClearInsteadOfFlushOrRelabel() {
        for changed in [context(app: "test.other"), context(pid: 99), context(birth: "new-birth"), context(window: "other"), context(windowGeneration: 2), context(surface: "other"), context(epoch: 2), context(revision: 2), context(foreground: 2), context(focus: 2)] {
            var buffer = InputTextAccumulator(); buffer.add(sample(), source: .fixture)
            XCTAssertEqual(buffer.add(sample(context: changed), source: .fixture), .stale)
            XCTAssertNil(buffer.pending); XCTAssertNil(buffer.takeDue(nowMs: 1_500, approvedContext: changed))
        }
    }
    func testClearAndFailedFlushApprovalDiscardPendingText() {
        var buffer = InputTextAccumulator(); buffer.add(sample(), source: .fixture); buffer.clear()
        XCTAssertNil(buffer.takeDue(nowMs: 1_500, approvedContext: context()))
        buffer.add(sample(), source: .fixture)
        XCTAssertNil(buffer.takeDue(nowMs: 1_500, approvedContext: nil)); XCTAssertNil(buffer.pending)
    }
    func testPolicyBudgetIsStricterThanGlobalLimitWithoutTruncation() {
        var restricted = policy(); restricted.maxTextCodeUnits = 3
        let result = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: restricted, afterNanoseconds: 0, nowNanoseconds: { self.baseNanos },
            safetyProvider: { _ in InputTextApprovedContext(context: self.context(), metadataMonotonicNanoseconds: self.baseNanos, role: .textArea) }, readUnicode: { .text("abcd") })
        assertGap(result, .budget)
        var buffer = InputTextAccumulator(maxCodeUnits: 3)
        XCTAssertNil(buffer.add(sample(text: "abc"), source: .fixture))
        XCTAssertEqual(buffer.add(sample(text: "d"), source: .fixture), .budget); XCTAssertNil(buffer.pending)
    }
    func testClockDiscontinuityAndOverdueBufferFailClosed() {
        var buffer = InputTextAccumulator(); buffer.add(sample(), source: .fixture)
        XCTAssertEqual(buffer.add(sample(time: 999), source: .fixture), .stale); XCTAssertNil(buffer.pending)
        buffer.add(sample(), source: .fixture)
        XCTAssertNil(buffer.takeDue(nowMs: 6_001, approvedContext: context())); XCTAssertNil(buffer.pending)
        buffer.add(sample(), source: .fixture)
        XCTAssertNil(buffer.takeDue(nowMs: 999, approvedContext: context())); XCTAssertNil(buffer.pending)
    }
    func testSameContextTextThenReturnSegmentationDoesNotMergeKinds() {
        var buffer = InputTextAccumulator(); buffer.add(sample(text: "synthetic"), source: .fixture)
        let first = buffer.takeSegment(approvedContext: context())!
        buffer.add(sample(text: "", time: 1_100, kind: .return), source: .fixture)
        let second = buffer.takeDue(nowMs: 1_600, approvedContext: context())!
        XCTAssertEqual(first.eventKind, .text); XCTAssertEqual(first.text, "synthetic")
        XCTAssertEqual(second.eventKind, .return); XCTAssertEqual(second.text, ""); XCTAssertEqual(second.eventCount, 1)
    }
    func testClosedImmutableDTOCodableRoundTripAndUnknownEnumRejection() throws {
        let original = record(sample(text: "合成\u{1F9EA}", modifiers: [.shift]))
        let bytes = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(InputTextEmission.self, from: bytes)
        XCTAssertEqual(original, decoded); XCTAssertTrue(decoded.isValid)
        let string = String(decoding: bytes, as: UTF8.self)
        XCTAssertFalse(string.contains("timestampNanoseconds")); XCTAssertFalse(string.contains("keycode")); XCTAssertFalse(string.contains("CGEvent"))
        let corrupted = string.replacingOccurrences(of: "\"fixture\"", with: "\"unknown-source\"")
        XCTAssertThrowsError(try JSONDecoder().decode(InputTextEmission.self, from: Data(corrupted.utf8)))
    }
    func testPublicGeneratedContractValidatesRealAndFixturePayloads() throws {
        let validator = try ContractValidator()
        for source: InputTextSource in [.fixture, .cgUnicode] {
            for item in [sample(text: "合成\u{1F9EA}"), sample(text: "", kind: .return), sample(text: "", kind: .shortcut, modifiers: [.command, .control, .option, .shift])] {
                let value = record(item, source: source)
                XCTAssertNoThrow(try validator.validateMessage(observation(value)))
                XCTAssertEqual(value.payload()["coverage"]?["status"], .string("partial"))
                XCTAssertEqual(value.payload()["coverage"]?["truncated"], .bool(false))
                XCTAssertEqual(value.context.target.json["kind"], .string("resolved"))
            }
        }
        XCTAssertNoThrow(try validator.validateMessage(observation(record(sample(context: context(privacy: .userAuthorized)), source: .cgUnicode))))
    }

    func testCausalDrainAtBarrierSealsSubDebouncePendingAndDeduplicatesContextChecks() {
        let ctx = context()
        var buffer = InputTextAccumulator()
        XCTAssertNil(buffer.add(sample(text: "nashi ", time: 1_000, context: ctx), source: .fixture))
        // Completed earlier segment + still-pending segment (< 500ms debounce) share the same context.
        var completed: [InputTextEmission] = [record(sample(text: "prior", time: 900, context: ctx), source: .fixture)]
        var safetyCalls = 0
        let drained = InputTextReadGate.drainAtBarrier(
            completed: &completed,
            accumulator: &buffer,
            nowMs: 1_250, // Only 250ms after intervalEndMs=1000 (< 500ms standalone debounce).
            policy: policy(),
            nowNanoseconds: { self.baseNanos },
            typedSafetyProvider: { request in
                safetyCalls += 1
                guard case .flush(let expected) = request, expected == ctx else { return .failure(.stale) }
                return .success(.init(context: ctx, metadataMonotonicNanoseconds: self.baseNanos, role: .textArea))
            }
        )
        guard case .success(let records) = drained else { return XCTFail("Expected barrier drain success") }
        XCTAssertEqual(safetyCalls, 1, "Distinct identical context across completed + pending must validate once")
        XCTAssertEqual(records.map(\.text), ["prior", "nashi "])
        XCTAssertEqual(records.map(\.intervalEndMs), [900, 1_000])
        XCTAssertTrue(records.allSatisfy { $0.intervalEndMs <= 1_250 })
        XCTAssertTrue(completed.isEmpty)
        XCTAssertNil(buffer.pending)
    }

    func testCausalDrainAtBarrierFailsClosedOnSafetyFailureClockBackstepOrBackpressure() {
        let ctx = context()

        // 1. Safety rejection clears both completed and pending.
        var buffer1 = InputTextAccumulator()
        XCTAssertNil(buffer1.add(sample(text: "abc", time: 1_000, context: ctx), source: .fixture))
        var completed1: [InputTextEmission] = [record(sample(text: "old", time: 900, context: ctx), source: .fixture)]
        let rejected = InputTextReadGate.drainAtBarrier(
            completed: &completed1,
            accumulator: &buffer1,
            nowMs: 1_100,
            policy: policy(),
            nowNanoseconds: { self.baseNanos },
            typedSafetyProvider: { _ in .failure(.targetMismatch) }
        )
        XCTAssertEqual(rejected, .failure(.targetMismatch))
        XCTAssertTrue(completed1.isEmpty)
        XCTAssertNil(buffer1.pending)

        // 2. Clock backstep before pending.intervalEndMs fails closed without calling safety.
        var buffer2 = InputTextAccumulator()
        XCTAssertNil(buffer2.add(sample(text: "abc", time: 1_000, context: ctx), source: .fixture))
        var completed2: [InputTextEmission] = []
        var calls2 = 0
        let backstep = InputTextReadGate.drainAtBarrier(
            completed: &completed2,
            accumulator: &buffer2,
            nowMs: 999,
            policy: policy(),
            nowNanoseconds: { self.baseNanos },
            typedSafetyProvider: { _ in calls2 += 1; return .success(.init(context: ctx, metadataMonotonicNanoseconds: self.baseNanos, role: .textArea)) }
        )
        XCTAssertEqual(backstep, .failure(.stale))
        XCTAssertEqual(calls2, 0)
        XCTAssertNil(buffer2.pending)

        // 3. Sealing pending when completed is already at maxPending reports backpressure and clears.
        var buffer3 = InputTextAccumulator()
        XCTAssertNil(buffer3.add(sample(text: "5th", time: 1_400, context: ctx), source: .fixture))
        var completed3 = (0..<InputTextLimits.maxPending).map { idx in
            record(sample(text: "s\(idx)", time: Int64(900 + idx * 10), context: ctx), source: .fixture)
        }
        let full = InputTextReadGate.drainAtBarrier(
            completed: &completed3,
            accumulator: &buffer3,
            nowMs: 1_450,
            policy: policy(),
            nowNanoseconds: { self.baseNanos },
            typedSafetyProvider: { _ in .success(.init(context: ctx, metadataMonotonicNanoseconds: self.baseNanos, role: .textArea)) }
        )
        XCTAssertEqual(full, .failure(.backpressure))
        XCTAssertTrue(completed3.isEmpty)
        XCTAssertNil(buffer3.pending)
    }
}

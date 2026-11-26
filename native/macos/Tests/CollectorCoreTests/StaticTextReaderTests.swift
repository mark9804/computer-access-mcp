import XCTest
@testable import CollectorCore

/// Synthetic provider only. No AX APIs, desktop/QQ probes, or History access.
private final class StaticProbeProvider: TextFieldProvider {
    var app = ApplicationIdentity(applicationId: "test.allowed", processId: 123, processStartTime: "birth")
    var fieldRole: String? = "AXStaticText"
    var security: SecureStatus = .safe
    var declaredLength: Int? = 0
    var content = "abcdefghij"
    var stable = true
    var visible: TextSelection? = nil
    var selection: TextSelection? = nil
    var ranges: [TextSelection] = []
    var retrievedUnits = 0
    var valueCalls = 0
    var markerCalls = 0
    var visibleCalls = 0
    var lengthCalls = 0
    var onRange: (() -> Void)?
    var onSecurity: (() -> Void)?
    var onSelection: (() -> Void)?
    var rangeResult: ((Int, Int) -> String?)?

    func application() -> ApplicationIdentity? { app }
    func resolveFocusedField() -> Bool { true }
    func role() -> String? { fieldRole }
    func secureStatus() -> SecureStatus { onSecurity?(); return security }
    func numberOfCharacters() -> Int? { lengthCalls += 1; return declaredLength }
    func visibleRange() -> TextSelection? { visibleCalls += 1; return visible }
    func stringForRange(start: Int, length: Int) -> String? {
        ranges.append(TextSelection(start: start, length: length))
        let result: String?
        if let rangeResult { result = rangeResult(start, length) }
        else { result = boundedUTF16Slice(content, start: start, length: length) }
        retrievedUnits += result?.utf16.count ?? 0
        onRange?()
        return result
    }
    func markerStringForRange(start: Int, length: Int) -> String? { markerCalls += 1; return "forbidden" }
    func boundedKnownLengthValue() -> String? { valueCalls += 1; return "forbidden" }
    func selectedRange() -> TextSelection? { onSelection?(); return selection }
    func remainsSameFocusAndWindow() -> Bool { stable }
}

final class StaticTextReaderTests: XCTestCase {
    private func read(_ provider: StaticProbeProvider, clock: FakeClock = FakeClock(),
                      budget: Int = 128, textRange: String = "prefix", fieldSecurity: String? = nil) -> ReadResult {
        let policy = CapturePolicy(textRange: textRange, maxTextCodeUnits: budget, textMarkers: true,
                                   fieldSecurity: fieldSecurity)
        return BoundedTextReader().read(ticket: ticket(clock, policy: policy), provider: provider, clock: clock)
    }

    private func assertNoFallback(_ provider: StaticProbeProvider, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(provider.valueCalls, 0, file: file, line: line)
        XCTAssertEqual(provider.markerCalls, 0, file: file, line: line)
    }

    func testZeroAndMissingStaticLengthsProducePartialRangeEvidence() {
        for length in [0, nil] as [Int?] {
            let provider = StaticProbeProvider(); provider.declaredLength = length
            let result = read(provider)
            XCTAssertNil(result.reason)
            XCTAssertEqual(result.text?.text, "abcdefghij")
            XCTAssertEqual(result.text?.source, "ax.range")
            XCTAssertEqual(result.text?.rangeStart, 0)
            XCTAssertEqual(result.text?.rangeBasis, "prefix")
            XCTAssertNil(result.text?.totalLength)
            XCTAssertEqual(result.text?.complete, false)
            XCTAssertEqual(result.text?.truncated, true)
            XCTAssertEqual(result.text?.missingReasons, ["static-text-length-unverified"])
            XCTAssertEqual(result.text?.readUnits, provider.retrievedUnits)
            XCTAssertEqual(result.text?.readUnits, 24)
            XCTAssertEqual(provider.ranges.first, TextSelection(start: 0, length: 2))
            XCTAssertEqual(provider.lengthCalls, length == nil ? 1 : 2)
            assertNoFallback(provider)
        }
    }

    func testSmallAndLongContentNeverClaimCompleteAndChargeAllSupersets() {
        for content in ["a", "界面", "\u{1F9EA}", "A\u{1F9EA}", String(repeating: "x", count: 500)] {
            let provider = StaticProbeProvider(); provider.content = content
            let result = read(provider, budget: 16)
            XCTAssertNil(result.reason)
            XCTAssertNotNil(result.text)
            XCTAssertEqual(result.text?.complete, false)
            XCTAssertNil(result.text?.totalLength)
            XCTAssertTrue(content.hasPrefix(result.text!.text))
            XCTAssertLessThanOrEqual(provider.retrievedUnits, 16)
            XCTAssertLessThanOrEqual(provider.ranges.count, 8)
            XCTAssertEqual(result.text?.readUnits, provider.retrievedUnits)
            assertNoFallback(provider)
        }
        let provider = StaticProbeProvider(); provider.content = String(repeating: "x", count: 500)
        let result = read(provider, budget: 9)
        XCTAssertEqual(result.text?.text, "xxxx")
        XCTAssertEqual(result.text?.readUnits, 6)
        XCTAssertEqual(provider.ranges, [TextSelection(start: 0, length: 2), TextSelection(start: 0, length: 4)],
                       "The remaining three units cannot fund another overlapping prefix larger than four")
    }

    func testNilRangeAndEmptyRangeAreNotConflatedOrClaimedComplete() {
        for mode in 0..<3 {
            let provider = StaticProbeProvider()
            if mode == 0 { provider.rangeResult = { _, _ in nil } }
            if mode == 1 { provider.rangeResult = { _, _ in "" } }
            if mode == 2 { provider.content = "" }
            let result = read(provider)
            if mode == 1 {
                // An actual successful empty range is retained, never complete.
                XCTAssertNil(result.reason)
                XCTAssertEqual(result.text?.text, "")
                XCTAssertEqual(result.text?.complete, false)
                XCTAssertEqual(result.text?.truncated, true)
                XCTAssertNil(result.text?.totalLength)
                XCTAssertEqual(result.text?.readUnits, 0)
                XCTAssertEqual(result.text?.missingReasons, ["static-text-length-unverified"])
            } else {
                // No successful positive range cannot establish empty content,
                // even when this synthetic provider's backing string is empty.
                XCTAssertNil(result.text)
                XCTAssertEqual(result.reason, "read-error")
                XCTAssertEqual(result.diagnostic?.code, .textReadUnavailable)
            }
            XCTAssertEqual(provider.ranges.map(\.length), [2, 1])
            assertNoFallback(provider)
        }
    }

    func testAmbiguousRepairedSurrogateIsUnavailableRatherThanFabricatedEmpty() {
        let provider = StaticProbeProvider(); provider.rangeResult = { _, _ in "\u{FFFD}" }
        let result = read(provider, budget: 1)
        XCTAssertNil(result.text)
        XCTAssertEqual(result.reason, "read-error")
        XCTAssertEqual(result.diagnostic?.code, .textReadUnavailable)
        XCTAssertEqual(provider.retrievedUnits, 1)
        assertNoFallback(provider)
    }

    func testMalformedOversizedProviderResponseFailsWithoutFallbackOrFurtherRead() {
        let provider = StaticProbeProvider()
        provider.rangeResult = { _, length in length == 2 ? "ab" : "oversized" }
        let result = read(provider, budget: 6)
        XCTAssertNil(result.text)
        XCTAssertEqual(result.reason, "read-error")
        XCTAssertEqual(result.diagnostic?.code, .textResultInvalid)
        XCTAssertEqual(provider.ranges.map(\.length), [2, 4])
        XCTAssertEqual(provider.retrievedUnits, 11)
        assertNoFallback(provider)
    }

    func testSafetyFocusRoleApplicationOrDeadlineChangeAfterReadDiscardsAllText() {
        for mutation in 0..<5 {
            let clock = FakeClock(); let provider = StaticProbeProvider()
            provider.onRange = {
                switch mutation {
                case 0: provider.security = .sensitive
                case 1: provider.stable = false
                case 2: provider.fieldRole = "AXTextField"
                case 3: provider.app.processStartTime = "different-birth"
                default: clock.advance(101)
                }
            }
            let result = read(provider, clock: clock)
            XCTAssertNil(result.text)
            XCTAssertEqual(result.reason, "stale")
            XCTAssertEqual(provider.ranges.count, 1)
            assertNoFallback(provider)
        }
    }

    func testSafetyChangeAfterSuccessfulPrefixAndLaterUnavailableRangeCannotSalvagePrefix() {
        let provider = StaticProbeProvider(); provider.content = "ab"
        provider.onRange = { if provider.ranges.count == 2 { provider.security = .unknown } }
        let result = read(provider)
        XCTAssertNil(result.text)
        XCTAssertEqual(result.reason, "stale")
        XCTAssertEqual(result.diagnostic?.code, .fieldSecurityUnknown)
        XCTAssertEqual(provider.ranges.map(\.length), [2, 4])
        assertNoFallback(provider)
    }

    func testDeadlineCrossingDuringPreReadSecurityGateDoesNotRead() {
        let provider = StaticProbeProvider(); let clock = FakeClock()
        var checks = 0
        provider.onSecurity = {
            checks += 1
            if checks == 3 { clock.advance(101) }
        }
        let result = read(provider, clock: clock)
        XCTAssertNil(result.text)
        XCTAssertEqual(result.reason, "stale")
        XCTAssertEqual(result.diagnostic?.code, .readDeadline)
        XCTAssertTrue(provider.ranges.isEmpty)
        assertNoFallback(provider)
    }

    func testFinalSelectionPhaseCannotBypassIdentityRoleSafetyTimeOrLengthValidation() {
        for mutation in 0..<6 {
            let clock = FakeClock(); let provider = StaticProbeProvider()
            provider.onSelection = {
                switch mutation {
                case 0: provider.stable = false
                case 1: provider.security = .sensitive
                case 2: provider.fieldRole = "AXTextArea"
                case 3: provider.app.processStartTime = "changed"
                case 4: clock.advance(101)
                default: provider.declaredLength = 10
                }
            }
            let result = read(provider, clock: clock)
            XCTAssertNil(result.text)
            XCTAssertEqual(result.reason, "stale")
            assertNoFallback(provider)
        }
    }

    func testSelectionMustFitReturnedPrefixNotUnverifiedTotal() {
        let provider = StaticProbeProvider(); provider.content = "A\u{1F9EA}B"
        provider.selection = TextSelection(start: 1, length: 2)
        XCTAssertEqual(read(provider).text?.selection, provider.selection)
        for selection in [TextSelection(start: -1, length: 1), TextSelection(start: 4, length: 1),
                          TextSelection(start: 1, length: Int.max)] {
            provider.selection = selection
            XCTAssertNil(read(provider).text?.selection)
        }
        assertNoFallback(provider)
    }

    func testVisibleModeNeverWidensIntoStaticPrefixProbe() {
        let provider = StaticProbeProvider()
        provider.visible = TextSelection(start: 0, length: 0)
        let empty = read(provider, textRange: "visible")
        XCTAssertEqual(empty.text?.text, "")
        XCTAssertEqual(empty.text?.totalLength, 0)
        XCTAssertEqual(empty.text?.complete, false)
        XCTAssertEqual(empty.text?.missingReasons, ["visible-range-only"])
        XCTAssertTrue(provider.ranges.isEmpty)
        provider.declaredLength = nil
        let unknown = read(provider, textRange: "visible")
        XCTAssertNil(unknown.text)
        XCTAssertEqual(unknown.diagnostic?.code, .visibleRangeUnavailable)
        XCTAssertTrue(provider.ranges.isEmpty)
        assertNoFallback(provider)
    }

    func testEditableZeroRemainsCompleteEmptyWithoutProbe() {
        for role in ["AXTextField", "AXTextArea"] {
            let provider = StaticProbeProvider(); provider.fieldRole = role
            let result = read(provider)
            XCTAssertEqual(result.text?.text, "")
            XCTAssertEqual(result.text?.totalLength, 0)
            XCTAssertEqual(result.text?.complete, true)
            XCTAssertEqual(result.text?.missingReasons, [])
            XCTAssertNil(result.text?.readUnits)
            XCTAssertTrue(provider.ranges.isEmpty)
            assertNoFallback(provider)
        }
    }

    func testPositiveStaticLengthRetainsOrdinarySingleBoundedRead() {
        let provider = StaticProbeProvider(); provider.declaredLength = provider.content.utf16.count
        let result = read(provider)
        XCTAssertEqual(result.text?.text, provider.content)
        XCTAssertEqual(result.text?.complete, true)
        XCTAssertEqual(result.text?.totalLength, 10)
        XCTAssertEqual(provider.ranges, [TextSelection(start: 0, length: 10)])
        assertNoFallback(provider)
    }

    func testSecurityGateBeforeCountAndProbeStillUsesFieldPolicy() {
        for security in [SecureStatus.sensitive, .unknown, .notDeclaredSensitive] {
            let provider = StaticProbeProvider(); provider.security = security
            let result = read(provider)
            XCTAssertNil(result.text)
            XCTAssertEqual(result.reason, "policy-boundary")
            XCTAssertEqual(provider.lengthCalls, 0)
            XCTAssertTrue(provider.ranges.isEmpty)
            assertNoFallback(provider)
        }
        let provider = StaticProbeProvider(); provider.security = .notDeclaredSensitive
        let allowed = read(provider, fieldSecurity: "denylist")
        XCTAssertEqual(allowed.text?.text, provider.content)
        XCTAssertEqual(allowed.text?.complete, false)
        assertNoFallback(provider)
    }
}

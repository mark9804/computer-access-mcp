import XCTest
@testable import CollectorCore

final class StaticTextRangeProbeTests: XCTestCase {
    private func probe(_ content: String, budget: Int = 128) -> StaticTextRangeProbe.Result {
        StaticTextRangeProbe.read(budget: budget, shouldContinue: { true }) { start, length in
            boundedUTF16Slice(content, start: start, length: length)
        }
    }

    func testFixedEightUnitStartFindsShortLabelsWithinFourAttempts() {
        let cases: [(Int, [Int], Int)] = [
            (1, [8, 4, 2, 1], 1),
            (5, [8, 4, 6, 5], 5),
            (58, [8, 16, 32, 64], 32),
        ]
        for (length, expectedRequests, expectedPrefix) in cases {
            let content = String(repeating: "界", count: length)
            var requests: [Int] = []
            var charged = 0
            let result = StaticTextRangeProbe.read(budget: 128, maxAttempts: 4, initialPrefixUnits: 8,
                                                  shouldContinue: { true }) { start, count in
                XCTAssertEqual(start, 0)
                XCTAssertLessThanOrEqual(count, 128 - charged)
                requests.append(count)
                let value = boundedUTF16Slice(content, start: start, length: count)
                charged += value?.utf16.count ?? 0
                return value
            }
            XCTAssertEqual(requests, expectedRequests)
            XCTAssertEqual(result.text, String(content.prefix(expectedPrefix)))
            XCTAssertEqual(result.consumedUnits, charged)
            XCTAssertLessThanOrEqual(charged, 128)
            XCTAssertEqual(result.attempts, 4)
            XCTAssertNil(result.failure)
        }
    }

    func testInitialPrefixIsClampedAndEightUnitStartPreservesSurrogates() {
        for initial in [Int.min, 0, 1, 2, 8, 16, Int.max] {
            var requests: [Int] = []
            _ = StaticTextRangeProbe.read(budget: 7, maxAttempts: 1, initialPrefixUnits: initial,
                                          shouldContinue: { true }) { _, length in
                requests.append(length)
                return String(repeating: "x", count: length)
            }
            XCTAssertEqual(requests, [min(7, max(1, min(16, initial)))])
        }
        for content in ["\u{1F9EA}", "A\u{1F9EA}B", "ABCDE\u{1F9EA}Z", "1234567\u{1F9EA}"] {
            let result = StaticTextRangeProbe.read(budget: 128, maxAttempts: 4, initialPrefixUnits: 8,
                                                  shouldContinue: { true }) { start, length in
                boundedUTF16Slice(content, start: start, length: length)
            }
            XCTAssertNotNil(result.text)
            XCTAssertTrue(content.hasPrefix(result.text!))
            XCTAssertFalse(result.text!.contains("\u{FFFD}"))
            XCTAssertLessThanOrEqual(result.consumedUnits, 128)
            XCTAssertLessThanOrEqual(result.attempts, 4)
            XCTAssertNil(result.failure)
        }
    }

    func testLongContentIsCappedAtEightCallsAnd256UnitPrefix() {
        var requested: [Int] = []
        let content = String(repeating: "x", count: 2000)
        let result = StaticTextRangeProbe.read(budget: 8192, shouldContinue: { true }) { start, length in
            requested.append(length)
            return boundedUTF16Slice(content, start: start, length: length)
        }
        XCTAssertEqual(requested, [2, 4, 8, 16, 32, 64, 128, 256])
        XCTAssertEqual(result.text, String(repeating: "x", count: 256))
        XCTAssertEqual(result.consumedUnits, 510)
        XCTAssertEqual(result.attempts, 8)
        XCTAssertNil(result.failure)
    }

    func testSurrogatePairsAreNotSplitOrReconstructedAcrossReads() {
        XCTAssertEqual(probe("\u{1F9EA}", budget: 8).text, "\u{1F9EA}")
        XCTAssertEqual(probe("A\u{1F9EA}B", budget: 16).text, "A\u{1F9EA}B")
        XCTAssertEqual(probe("A\u{1F9EA}", budget: 16).text, "A\u{1F9EA}")
        XCTAssertEqual(probe("\u{1F9EA}", budget: 1).text, "")
        var calls = 0
        let repaired = StaticTextRangeProbe.read(budget: 16, shouldContinue: { true }) { _, length in
            calls += 1
            if length == 2 { return "A\u{FFFD}" }
            if length == 3 { return "A\u{1F9EA}" }
            return nil
        }
        XCTAssertEqual(repaired.text, "A\u{1F9EA}")
        XCTAssertEqual(repaired.consumedUnits, 5)
        XCTAssertEqual(calls, 3)
        let uncertain = StaticTextRangeProbe.read(budget: 1, shouldContinue: { true }) { _, _ in "\u{FFFD}" }
        XCTAssertNil(uncertain.text) // Could be literal, but cannot verify the bridge boundary.
        XCTAssertEqual(uncertain.consumedUnits, 1)
        XCTAssertNil(uncertain.failure)
    }

    func testWholeReturnedPrefixesAreSelectedInsteadOfConcatenated() {
        var calls = 0
        let result = StaticTextRangeProbe.read(budget: 6, shouldContinue: { true }) { _, _ in
            calls += 1
            return calls == 1 ? "ab" : "WXYZ"
        }
        XCTAssertEqual(result.text, "WXYZ")
        XCTAssertEqual(result.consumedUnits, 6)
        XCTAssertEqual(result.attempts, 2)
    }

    func testPostReadInterruptionChargesReturnedUnitsAndDiscardsEarlierPrefix() {
        var allowed = true
        var calls = 0
        let result = StaticTextRangeProbe.read(budget: 128, shouldContinue: { allowed }) { _, length in
            calls += 1
            if calls == 2 { allowed = false }
            return String(repeating: "x", count: length)
        }
        XCTAssertEqual(result.failure, .interrupted)
        XCTAssertNil(result.text)
        XCTAssertEqual(result.consumedUnits, 6)
        XCTAssertEqual(result.attempts, 2)
        XCTAssertEqual(calls, 2)
    }

    func testLargeInitialPrefixReadsTruncatingControlInSingleIPCCallAndShrinksOnStrictControl() {
        // Truncating control (QQ/Feishu/WeChat style): 25-char and 200-char strings finish in 1 call.
        for message in [
            String(repeating: "好", count: 25),
            String(repeating: "a", count: 200),
            String(repeating: "z", count: 400),
        ] {
            var requests: [Int] = []
            let result = StaticTextRangeProbe.read(
                budget: 256,
                initialPrefixUnits: 256,
                stopAfterNonempty: false,
                shouldContinue: { true }
            ) { start, length in
                requests.append(length)
                let clamped = min(length, message.utf16.count)
                return boundedUTF16Slice(message, start: start, length: clamped)
            }
            let expected = String(message.prefix(256))
            XCTAssertEqual(requests, [256])
            XCTAssertEqual(result.attempts, 1)
            XCTAssertEqual(result.text, expected)
            XCTAssertEqual(result.consumedUnits, expected.utf16.count)
            XCTAssertNil(result.failure)
        }

        // Strict control rejecting requests > actual length automatically shrinks via binary search,
        // resolving both even and odd lengths across [1...256] without 1-character tail truncation.
        for (length, budget) in [(1, 256), (3, 256), (5, 256), (7, 256), (11, 256), (12, 256), (13, 256), (127, 2048), (255, 2048), (256, 2048)] {
            let strictContent = String(repeating: "界", count: length)
            var strictRequests: [Int] = []
            let strictResult = StaticTextRangeProbe.read(
                budget: budget,
                initialPrefixUnits: 256,
                stopAfterNonempty: false,
                shouldContinue: { true }
            ) { start, requestedLength in
                strictRequests.append(requestedLength)
                return boundedUTF16Slice(strictContent, start: start, length: requestedLength)
            }
            XCTAssertEqual(strictRequests.first, 256)
            XCTAssertEqual(strictResult.text, strictContent, "Strict binary search failed for length \(length)")
            XCTAssertLessThanOrEqual(strictResult.attempts, StaticTextRangeProbe.maximumAttempts)
            XCTAssertNil(strictResult.failure)
        }
    }
}

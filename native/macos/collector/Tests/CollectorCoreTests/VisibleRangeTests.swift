import Foundation
import XCTest
@testable import CollectorCore

final class VisibleRangeTests: XCTestCase {
    private func visibleProvider() -> FakeProvider {
        let provider = FakeProvider()
        provider.length = 200
        provider.visible = TextSelection(start: 100, length: 4)
        provider.rangeValue = "A\u{1F9EA}B"
        provider.selected = TextSelection(start: 101, length: 2)
        return provider
    }
    private func read(_ provider: FakeProvider, clock: FakeClock = FakeClock(), budget: Int = 128) -> ReadResult {
        BoundedTextReader().read(ticket: ticket(clock, policy: CapturePolicy(textRange: "visible", maxTextCodeUnits: budget)), provider: provider, clock: clock)
    }
    func testVisibleUTF16OffsetAndSelectionAreFieldRelativeAndOnlyPartial() {
        let provider = visibleProvider()
        let result = read(provider)
        XCTAssertNil(result.reason)
        XCTAssertEqual(provider.requestedRanges, [TextSelection(start: 100, length: 4)])
        XCTAssertEqual(result.text?.text, "A\u{1F9EA}B")
        XCTAssertEqual(result.text?.rangeStart, 100)
        XCTAssertEqual(result.text?.rangeBasis, "visible")
        XCTAssertEqual(result.text?.selection, TextSelection(start: 101, length: 2))
        XCTAssertEqual(result.text?.totalLength, 200)
        XCTAssertEqual(result.text?.complete, false)
        XCTAssertEqual(result.text?.truncated, false)
        XCTAssertEqual(result.text?.missingReasons, ["visible-range-only"])
        XCTAssertEqual(provider.visibleCalls, 2)
        XCTAssertEqual(provider.valueCalls, 0)
        provider.length = 4; provider.visible = TextSelection(start: 0, length: 4)
        let fullVisible = read(provider)
        XCTAssertEqual(fullVisible.text?.complete, false)
        XCTAssertEqual(fullVisible.text?.truncated, false)
    }
    func testZeroLengthFieldIsObservedButNonemptyHiddenViewportIsNotEmptyText() {
        let provider = visibleProvider()
        provider.length = 0; provider.visible = TextSelection(start: 0, length: 0)
        provider.rangeValue = nil
        let empty = read(provider)
        XCTAssertEqual(empty.text?.text, "")
        XCTAssertEqual(empty.text?.truncated, false)
        XCTAssertEqual(empty.text?.complete, false)
        XCTAssertEqual(provider.textCalls, 0)
        provider.length = 200
        let hidden = read(provider)
        XCTAssertNil(hidden.text); XCTAssertEqual(hidden.reason, "read-error")
        XCTAssertEqual(provider.textCalls, 0); XCTAssertEqual(provider.valueCalls, 0)
    }
    func testUnknownInvalidOverflowAndOutOfBoundsRangesNeverReadContent() {
        let ranges: [TextSelection?] = [nil, TextSelection(start: -1, length: 1), TextSelection(start: 0, length: -1),
            TextSelection(start: 201, length: 0), TextSelection(start: 199, length: 2),
            TextSelection(start: Int.max, length: Int.max), TextSelection(start: 1, length: Int.max)]
        for range in ranges {
            let provider = visibleProvider(); provider.visible = range
            let result = read(provider)
            XCTAssertEqual(result.reason, "read-error"); XCTAssertNil(result.text)
            XCTAssertEqual(provider.textCalls, 0); XCTAssertEqual(provider.valueCalls, 0)
        }
        for total in [nil, -1, Int.max] as [Int?] {
            let provider = visibleProvider(); provider.length = total
            XCTAssertEqual(read(provider).reason, "read-error")
            XCTAssertEqual(provider.visibleCalls, 0); XCTAssertEqual(provider.textCalls, 0); XCTAssertEqual(provider.valueCalls, 0)
        }
    }
    func testVisibleReadFailureNeverFallsBackToPrefixOrWholeValue() {
        let provider = visibleProvider(); provider.rangeValue = nil
        provider.fullValue = "SHOULD_NOT_READ"
        XCTAssertEqual(read(provider).reason, "read-error")
        XCTAssertEqual(provider.requestedRanges, [TextSelection(start: 100, length: 4)])
        XCTAssertEqual(provider.valueCalls, 0)
        let oversized = visibleProvider(); oversized.rangeValue = "oversized"
        XCTAssertEqual(read(oversized).reason, "read-error")
        XCTAssertEqual(oversized.valueCalls, 0)
        let emptyShortRead = visibleProvider(); emptyShortRead.rangeValue = ""
        XCTAssertEqual(read(emptyShortRead).reason, "read-error")
        XCTAssertNil(read(emptyShortRead).text); XCTAssertEqual(emptyShortRead.valueCalls, 0)
    }
    func testBudgetAndShortReadHaveSeparateHonestTruncation() {
        let budgeted = visibleProvider(); budgeted.visible = TextSelection(start: 100, length: 20)
        let capped = read(budgeted, budget: 4)
        XCTAssertEqual(capped.text?.truncated, true)
        XCTAssertEqual(capped.text?.missingReasons, ["visible-range-only", "text-budget"])
        XCTAssertEqual(budgeted.requestedRanges, [TextSelection(start: 100, length: 4)])
        let shorter = visibleProvider(); shorter.rangeValue = "A\u{1F9EA}"
        let short = read(shorter)
        XCTAssertEqual(short.text?.truncated, true)
        XCTAssertEqual(short.text?.missingReasons, ["visible-range-only", "range-short-read"])
        let both = visibleProvider(); both.visible = TextSelection(start: 100, length: 20); both.rangeValue = "A"
        XCTAssertEqual(read(both, budget: 4).text?.missingReasons, ["visible-range-only", "text-budget", "range-short-read"])
    }
    func testSelectionMustFitActualVisibleReturnNotRequestedViewport() {
        for selection in [TextSelection(start: 99, length: 1), TextSelection(start: 100, length: -1),
                          TextSelection(start: 104, length: 1), TextSelection(start: 102, length: 3),
                          TextSelection(start: Int.max, length: Int.max)] {
            let provider = visibleProvider(); provider.selected = selection
            XCTAssertNil(read(provider).text?.selection)
        }
        let short = visibleProvider(); short.rangeValue = "A"; short.selected = TextSelection(start: 101, length: 2)
        XCTAssertNil(read(short).text?.selection)
        let caret = visibleProvider(); caret.selected = TextSelection(start: 104, length: 0)
        XCTAssertEqual(read(caret).text?.selection, caret.selected)
    }
    func testSecurityMetadataGateRunsBeforeVisibleMetadataAndContent() {
        for status in [SecureStatus.unknown, .sensitive] {
            let provider = visibleProvider(); provider.secure = status
            XCTAssertEqual(read(provider).reason, "policy-boundary")
            XCTAssertEqual(provider.visibleCalls, 0); XCTAssertEqual(provider.lengthCalls, 0)
            XCTAssertEqual(provider.textCalls, 0); XCTAssertEqual(provider.valueCalls, 0)
        }
        let changedBeforeRead = visibleProvider()
        changedBeforeRead.onVisible = { changedBeforeRead.secure = .unknown }
        XCTAssertEqual(read(changedBeforeRead).reason, "stale")
        XCTAssertEqual(changedBeforeRead.textCalls, 0); XCTAssertEqual(changedBeforeRead.valueCalls, 0)
    }
    func testVisibleRangeLengthFocusSecurityAndDeadlineChangesDiscardResult() {
        for mutation in 0..<7 {
            let provider = visibleProvider(); let clock = FakeClock()
            provider.onRange = {
                switch mutation {
                case 0: provider.visible = TextSelection(start: 101, length: 4)
                case 1: provider.visible = nil
                case 2: provider.length = 201
                case 3: provider.length = nil
                case 4: provider.stable = false
                case 5: provider.secure = .sensitive
                default: clock.advance(101)
                }
            }
            let result = read(provider, clock: clock)
            XCTAssertNil(result.text); XCTAssertEqual(result.reason, "stale")
            XCTAssertEqual(provider.valueCalls, 0)
        }
        let finalGate = visibleProvider()
        finalGate.onVisible = { if finalGate.visibleCalls == 2 { finalGate.secure = .unknown } }
        XCTAssertEqual(read(finalGate).reason, "stale")
        let afterSelection = visibleProvider()
        afterSelection.onSelection = { afterSelection.visible = TextSelection(start: 102, length: 4) }
        XCTAssertEqual(read(afterSelection).reason, "stale")
    }
    func testPrefixFreshLengthCannotProduceFalseCompleteAndDoesNotReadVisibility() {
        for after in [nil, 5] as [Int?] {
            let clock = FakeClock(); let provider = FakeProvider()
            provider.onRange = { provider.length = after }
            XCTAssertEqual(BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock).reason, "stale")
            XCTAssertEqual(provider.visibleCalls, 0)
        }
        let clock = FakeClock(); let provider = FakeProvider()
        let prefix = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
        XCTAssertEqual(prefix.text?.rangeBasis, "prefix"); XCTAssertEqual(prefix.text?.rangeStart, 0)
        XCTAssertEqual(prefix.text?.complete, true); XCTAssertEqual(prefix.text?.truncated, false)
        XCTAssertEqual(provider.visibleCalls, 0)
    }
    func testSyntheticUTF16SliceKeepsAbsoluteOffsetsAndSurrogateBoundaries() {
        let text = "甲A\u{1F9EA}B乙"
        XCTAssertEqual(boundedUTF16Slice(text, start: 2, length: 3), "\u{1F9EA}B")
        XCTAssertNil(boundedUTF16Slice(text, start: 3, length: 2))
        XCTAssertEqual(boundedUTF16Slice(text, start: 1, length: 2), "A")
        XCTAssertEqual(boundedUTF16Slice(text, start: text.utf16.count, length: 0), "")
        XCTAssertNil(boundedUTF16Slice(text, start: Int.max, length: Int.max))
        XCTAssertNil(boundedUTF16Slice(text, start: -1, length: 1))
        let content = String(repeating: "Synthetic \u{1F9EA} ", count: 1000)
        XCTAssertEqual(boundedUTF16Slice(content, start: 130, length: 260), String(repeating: "Synthetic \u{1F9EA} ", count: 20))
        let provider = visibleProvider(); provider.sliceContent = text; provider.length = text.utf16.count
        provider.visible = TextSelection(start: 2, length: 3); provider.selected = nil
        XCTAssertEqual(read(provider).text?.text, "\u{1F9EA}B")
    }
    func testWorkerSettingsRejectUnknownScopeAndInvalidIntervalsBeforeProviderUse() throws {
        for policy in [CapturePolicy(textRange: "window"), CapturePolicy(textRange: "Visible"), CapturePolicy(sampleIntervalMs: 999), CapturePolicy(sampleIntervalMs: 30_001)] {
            let encoded = try JSONEncoder().encode(policy)
            let decoded = try JSONDecoder().decode(CapturePolicy.self, from: encoded)
            XCTAssertFalse(decoded.hasValidTextSettings)
            let clock = FakeClock(); let provider = FakeProvider()
            XCTAssertEqual(BoundedTextReader().read(ticket: ticket(clock, policy: decoded), provider: provider, clock: clock).reason, "policy-boundary")
            XCTAssertEqual(provider.resolveCalls, 0); XCTAssertEqual(provider.textCalls, 0)
        }
        for policy in [CapturePolicy(), CapturePolicy(textRange: "prefix", sampleIntervalMs: 1_000), CapturePolicy(textRange: "visible", sampleIntervalMs: 30_000)] {
            XCTAssertTrue(policy.hasValidTextSettings)
        }
        let legacy = try JSONDecoder().decode(CapturePolicy.self, from: JSONEncoder().encode(CapturePolicy()))
        XCTAssertNil(legacy.textRange); XCTAssertNil(legacy.sampleIntervalMs)
    }
}

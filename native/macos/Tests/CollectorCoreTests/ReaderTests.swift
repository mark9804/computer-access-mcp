import XCTest
@testable import CollectorCore

final class FakeClock: CollectorClock {
    var monotonicMs: Int64 = 100
    var unixMs: Int64 = 1_700_000_000_000
    func advance(_ ms: Int64) { monotonicMs += ms; unixMs += ms }
}
final class FakeProvider: TextFieldProvider {
    var app = ApplicationIdentity(applicationId: "test.allowed", processId: 123, processStartTime: "birth")
    var found = true
    var fieldRole: String? = "AXTextField"
    var secure: SecureStatus = .safe
    var length: Int? = 4
    var rangeValue: String? = "test"
    var fullValue: String? = "test"
    var selected: TextSelection? = nil
    var visible: TextSelection? = nil
    var requestedRanges: [TextSelection] = []
    var sliceContent: String?
    var visibleCalls = 0
    var stable = true
    var resolveCalls = 0
    var textCalls = 0
    var lengthCalls = 0
    var valueCalls = 0
    var onRange: (() -> Void)?
    var onVisible: (() -> Void)?
    var onSelection: (() -> Void)?
    func application() -> ApplicationIdentity? { app }
    func resolveFocusedField() -> Bool { resolveCalls += 1; return found }
    func role() -> String? { fieldRole }
    func secureStatus() -> SecureStatus { secure }
    func numberOfCharacters() -> Int? { lengthCalls += 1; return length }
    func visibleRange() -> TextSelection? { visibleCalls += 1; onVisible?(); return visible }
    func stringForRange(start: Int, length: Int) -> String? {
        textCalls += 1; requestedRanges.append(TextSelection(start: start, length: length)); onRange?()
        if let sliceContent { return boundedUTF16Slice(sliceContent, start: start, length: length) }
        return rangeValue
    }
    func boundedKnownLengthValue() -> String? { valueCalls += 1; return fullValue }
    func selectedRange() -> TextSelection? { onSelection?(); return selected }
    func remainsSameFocusAndWindow() -> Bool { stable }
}
func ticket(_ clock: FakeClock, policy: CapturePolicy = CapturePolicy()) -> ReadTicket {
    ReadTicket(token: "token", policyRevision: 1, captureEpoch: 1, policy: policy, deadlineMonotonicMs: clock.monotonicMs + 100, deviceId: "device", osSessionId: "session", desktopId: "desktop")
}

final class ReaderTests: XCTestCase {
    func testUTF16EmptyAndPartialAreNotConflated() {
        let clock = FakeClock(); let provider = FakeProvider()
        provider.length = 4; provider.rangeValue = "A\u{1F9EA}B"; provider.selected = TextSelection(start: 1, length: 2)
        let unicode = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
        XCTAssertEqual(unicode.text?.text.utf16.count, 4); XCTAssertEqual(unicode.text?.selection?.length, 2); XCTAssertEqual(unicode.text?.complete, true)
        provider.length = 0; provider.rangeValue = nil
        let empty = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
        XCTAssertEqual(empty.text?.text, ""); XCTAssertEqual(empty.text?.complete, true)
        provider.length = 1000; provider.rangeValue = "partial"; provider.selected = TextSelection(start: 100, length: 1)
        let partial = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
        XCTAssertEqual(partial.text?.complete, false); XCTAssertEqual(partial.text?.totalLength, 1000)
        XCTAssertEqual(partial.text?.missingReasons, ["text-budget"]); XCTAssertNil(partial.text?.selection)
    }
    func testUnknownOrOversizedLengthNeverUsesWholeValue() {
        let clock = FakeClock()
        for length in [nil, 10000] as [Int?] {
            let provider = FakeProvider(); provider.length = length; provider.rangeValue = nil
            XCTAssertEqual(BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock).reason, "read-error")
            XCTAssertEqual(provider.valueCalls, 0)
        }
        let provider = FakeProvider(); provider.rangeValue = nil
        let value = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
        XCTAssertEqual(value.text?.source, "ax.value"); XCTAssertEqual(provider.lengthCalls, 3)
    }
    func testUnknownLengthRangeRemainsPartialEvenForEmpty() {
        let clock = FakeClock(); let provider = FakeProvider(); provider.length = nil; provider.rangeValue = ""
        let read = BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock)
        XCTAssertEqual(read.text?.text, ""); XCTAssertEqual(read.text?.complete, false); XCTAssertEqual(read.text?.missingReasons, ["length-unknown"])
    }
    func testFocusChangeTimeoutAndSourceHintMismatchDiscardContent() {
        let clock = FakeClock(); let provider = FakeProvider()
        provider.onRange = { provider.stable = false }
        XCTAssertEqual(BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock).reason, "stale")
        provider.stable = true; provider.onRange = { clock.advance(101) }
        XCTAssertEqual(BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock).reason, "stale")
        var request = ticket(clock)
        request.hint = SourceHint(application: ApplicationIdentity(applicationId: "old.app", processId: 123, processStartTime: "birth"), eventTimeMs: clock.unixMs)
        let source = FakeProvider()
        XCTAssertEqual(BoundedTextReader().read(ticket: request, provider: source, clock: clock).reason, "stale")
        XCTAssertEqual(source.resolveCalls, 0)
    }
    func testReadCannotCrossGateDuringRangeOrFallback() {
        let clock = FakeClock(); let provider = FakeProvider(); provider.onRange = { provider.secure = .sensitive }
        XCTAssertEqual(BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock).reason, "stale")
        let changing = FakeProvider(); changing.rangeValue = nil; changing.onRange = { changing.length = 100000 }
        XCTAssertEqual(BoundedTextReader().read(ticket: ticket(clock), provider: changing, clock: clock).reason, "read-error")
        XCTAssertEqual(changing.valueCalls, 0)
    }
}

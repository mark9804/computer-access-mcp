import XCTest
import AccessContract
@testable import CollectorCore

final class VisibleRangeEngineTests: XCTestCase {
    private func visibleResult(_ h: Harness) -> ReadResult {
        var result = h.goodResult(h.env.launched.last!)
        result.text = TextRead(text: "A\u{1F9EA}B", source: "ax.range", totalLength: 200,
                               selection: TextSelection(start: 101, length: 2), rangeStart: 100, rangeBasis: "visible",
                               complete: false, truncated: false, missingReasons: ["visible-range-only"])
        return result
    }
    private func startVisible(_ h: Harness, interval: Int? = nil) {
        h.configure(textRange: "visible", sampleIntervalMs: interval)
        h.control("start", lease: 30_000); h.clock.advance(50); h.engine.tick()
    }
    func testHelloAdvertisesVisibleRangeWithoutStartingAnyEnvironment() throws {
        let h = Harness(); h.engine.hello()
        let capabilities = h.frames.last?["capabilities"]?.arrayValue ?? []
        XCTAssertTrue(capabilities.contains { $0["name"] == .string("text.visible-range") && $0["support"] == .string("supported") })
        XCTAssertEqual(h.env.beginCalls, 0); XCTAssertTrue(h.env.launched.isEmpty); XCTAssertEqual(h.env.inputBegins, 0)
        let validator = try ContractValidator()
        for frame in h.frames { XCTAssertNoThrow(try validator.encodeFrame(frame)) }
    }
    func testVisibleSnapshotPreservesOffsetBasisPartialAndNontruncatedCoverage() throws {
        let h = Harness(fixture: false); startVisible(h)
        h.engine.complete(visibleResult(h))
        let frame = try XCTUnwrap(h.textFrames.last)
        let payload = try XCTUnwrap(frame["payload"])
        XCTAssertEqual(payload["rangeBasis"], .string("visible"))
        XCTAssertEqual(payload["range"]?["start"], j(100)); XCTAssertEqual(payload["range"]?["length"], j(4))
        XCTAssertEqual(payload["selection"]?["start"], j(101))
        XCTAssertEqual(payload["scope"], .string("accessible-range"))
        XCTAssertEqual(payload["coverage"]?["status"], .string("partial"))
        XCTAssertEqual(payload["coverage"]?["truncated"], .bool(false))
        XCTAssertEqual(payload["coverage"]?["missingReasons"], .array([.string("visible-range-only")]))
        XCTAssertEqual(frame["actor"], .string("unknown")); XCTAssertEqual(payload["composition"], .string("unknown"))
        let validator = try ContractValidator()
        for frame in h.frames { XCTAssertNoThrow(try validator.encodeFrame(frame)) }
    }
    func testMalformedOrWrongScopeWorkerResultsNeverEnterSnapshotStream() {
        for mutation in 0..<9 {
            let h = Harness(); startVisible(h)
            var result = visibleResult(h)
            switch mutation {
            case 0: result.text?.rangeBasis = "prefix"
            case 1: result.text?.rangeStart = -1
            case 2: result.text?.rangeStart = Int.max
            case 3: result.text?.totalLength = nil
            case 4: result.text?.complete = true
            case 5: result.text?.source = "ax.value"
            case 6: result.text?.selection = TextSelection(start: 0, length: 1)
            case 7: result.text?.missingReasons = []
            default: result.text?.text = ""; result.text?.selection = nil
            }
            h.engine.complete(result)
            XCTAssertTrue(h.textFrames.isEmpty)
            XCTAssertEqual(h.frames.last?["payload"]?["reason"], .string("read-error"))
        }
        let h = Harness(); h.start()
        h.engine.complete(visibleResult(h)) // Prefix authorization cannot accept visible evidence.
        XCTAssertTrue(h.textFrames.isEmpty)
    }
    func testVisiblePartialSnapshotsKeepFreshIdentityWithoutClaimingDiffOrActor() {
        let h = Harness(); startVisible(h)
        h.engine.complete(visibleResult(h))
        let first = h.textFrames.last!
        h.clock.advance(150); h.engine.tick()
        var second = visibleResult(h); second.text?.text = "C\u{1F9EA}D"
        h.engine.complete(second)
        XCTAssertEqual(h.textFrames.count, 2)
        XCTAssertNotEqual(first["target"], h.textFrames.last?["target"])
        XCTAssertNotEqual(first["payload"]?["nodeId"], h.textFrames.last?["payload"]?["nodeId"])
        XCTAssertNotEqual(first["payload"]?["editSessionId"], h.textFrames.last?["payload"]?["editSessionId"])
        XCTAssertFalse(h.frames.contains { $0["payload"]?["kind"] == .string("text.changed") })
        XCTAssertEqual(h.textFrames.last?["actor"], .string("unknown"))
        XCTAssertEqual(h.env.inputBegins, 0)
    }
    func testExplicitOneAndThirtySecondIntervalsStartWithExistingDebounceThenWaitAfterCompletion() {
        for interval in [1_000, 30_000] {
            let h = Harness()
            h.configure(sampleIntervalMs: interval); h.control("start", lease: 30_000)
            h.clock.advance(49); h.engine.tick(); XCTAssertTrue(h.env.launched.isEmpty)
            h.clock.advance(1); h.engine.tick(); XCTAssertEqual(h.env.launched.count, 1)
            h.clock.advance(25) // Worker time must not shorten the after-completion delay.
            h.engine.complete(h.goodResult(h.env.launched.last!))
            if interval == 30_000 { h.clock.advance(15_000); h.control("heartbeat", lease: 30_000); h.clock.advance(14_999) }
            else { h.clock.advance(Int64(interval - 1)) }
            h.engine.tick(); XCTAssertEqual(h.env.launched.count, 1)
            h.clock.advance(1); h.engine.tick(); XCTAssertEqual(h.env.launched.count, 2)
            XCTAssertEqual(h.env.launched.last?.policy.sampleIntervalMs, interval)
            XCTAssertEqual(h.env.inputBegins, 0)
        }
    }
    func testAbsentIntervalPreservesFixtureAndProductionDefaults() {
        for (fixture, expected) in [(true, 150), (false, 1_000)] {
            let h = Harness(fixture: fixture)
            h.configure(); h.control("start", lease: 10_000); h.clock.advance(50); h.engine.tick()
            h.engine.complete(h.goodResult(h.env.launched.last!))
            h.clock.advance(Int64(expected - 1)); h.engine.tick(); XCTAssertEqual(h.env.launched.count, 1)
            h.clock.advance(1); h.engine.tick(); XCTAssertEqual(h.env.launched.count, 2)
        }
    }
    func testExplicitIntervalAlsoBoundsTimeoutRetriesAndNeverDuplicatesOutstandingWorker() {
        let h = Harness(); h.configure(sampleIntervalMs: 1_000)
        h.control("start", lease: 10_000); h.clock.advance(50); h.engine.tick()
        h.engine.tick(); XCTAssertEqual(h.env.launched.count, 1)
        h.clock.advance(200); h.engine.tick(); XCTAssertNil(h.engine.outstanding)
        XCTAssertEqual(h.frames.last?["payload"]?["reason"], .string("timeout"))
        h.clock.advance(999); h.engine.tick(); XCTAssertEqual(h.env.launched.count, 1)
        h.clock.advance(1); h.engine.tick(); XCTAssertEqual(h.env.launched.count, 2)
    }
    func testVisibleScopeAndIntervalDoNotStartOnConfigureOrRestartAcrossPause() {
        let h = Harness(); h.engine.hello(); h.configure(textRange: "visible", sampleIntervalMs: 1_000)
        h.clock.advance(2_000); h.engine.tick()
        XCTAssertTrue(h.env.launched.isEmpty); XCTAssertEqual(h.env.beginCalls, 0); XCTAssertEqual(h.env.inputBegins, 0)
        h.control("start", lease: 10_000); h.clock.advance(50); h.engine.tick()
        let pending = visibleResult(h)
        h.control("pause"); h.clock.advance(2_000); h.engine.complete(pending); h.engine.tick()
        XCTAssertEqual(h.env.launched.count, 1); XCTAssertTrue(h.textFrames.isEmpty)
        h.control("stop"); h.clock.advance(2_000); h.engine.tick(); XCTAssertEqual(h.env.launched.count, 1)
    }
    func testUnknownNativeTextSettingsFailConfigurationWithoutMonitoring() {
        for (scope, interval) in [("window", 1_000), ("visible", 999), ("prefix", 30_001)] {
            let h = Harness(); h.configure(textRange: scope, sampleIntervalMs: interval)
            XCTAssertEqual(h.engine.state, "unconfigured")
            XCTAssertEqual(h.frames.last?["code"], .string("invalid-message"))
            h.control("start"); XCTAssertEqual(h.env.beginCalls, 0); XCTAssertTrue(h.env.launched.isEmpty)
        }
    }
}

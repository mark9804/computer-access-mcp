import XCTest
import HistoryContract
@testable import CollectorCore

final class InputActivityTests: XCTestCase {
    private let app = ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "birth")
    private let stamp = InputActivityStamp(captureEpoch: 1, foregroundGeneration: 2, focusGeneration: 3, policyRevision: 1)
    private func sample(_ category: InputActivityCategory = .pointerRelease, time: Int64 = 1_100) -> InputActivitySample {
        InputActivitySample(application: app, category: category, callbackTimeMs: time)
    }
    private func start() -> Harness {
        let h = Harness(); h.env.inputAvailable = true
        h.configure(inputActivity: true); h.control("start", lease: 10_000)
        return h
    }
    private func add(_ h: Harness, app: ApplicationIdentity? = nil, category: InputActivityCategory = .pointerRelease) {
        h.engine.inputActivity(InputActivitySample(application: app ?? self.app, category: category, callbackTimeMs: h.clock.unixMs))
    }
    private func activities(_ h: Harness) -> [JSONValue] { h.frames.filter { $0["payload"]?["kind"] == .string("input.activity") } }

    func testPolicyAbsentAndExplicitFalseNeverStartInput() throws {
        for value: Bool? in [nil, false] {
            let h = Harness(); h.configure(inputActivity: value); h.control("start")
            XCTAssertEqual(h.env.inputBegins, 0)
            add(h); h.clock.advance(999); h.engine.tick()
            XCTAssertTrue(activities(h).isEmpty)
        }
        var old = try JSONValue.parse(JSONEncoder().encode(CapturePolicy(inputActivity: nil)))
        XCTAssertNil(old["inputActivity"])
        let decoded = try CapturePolicy(old)
        XCTAssertNil(decoded.inputActivity)
        old = try JSONValue.parse(JSONEncoder().encode(CapturePolicy()))
        XCTAssertEqual(old["inputActivity"], .bool(false))
    }
    func testInputStartupFailurePausesAndDoesNotAutoRetry() {
        let h = Harness(); h.configure(inputActivity: true); h.control("start")
        XCTAssertEqual(h.engine.state, "paused")
        XCTAssertEqual(h.frames.last?["reason"], .string("input-monitoring-unavailable"))
        h.env.inputAvailable = true; h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.env.inputBegins, 1); XCTAssertEqual(h.engine.state, "paused")
        h.control("resume"); XCTAssertEqual(h.env.inputBegins, 2); XCTAssertEqual(h.engine.state, "running")
    }
    func testInputOptInInitialDesktopFailureRequiresExplicitResume() {
        let h = Harness(); h.env.inputAvailable = true; h.env.desktop = .unknown
        h.configure(inputActivity: true); h.control("start", lease: 10_000)
        XCTAssertEqual(h.env.inputBegins, 0); XCTAssertEqual(h.engine.state, "paused")
        h.env.desktop = .unlocked; h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.env.inputBegins, 0)
        h.control("resume", lease: 10_000)
        XCTAssertEqual(h.engine.state, "running"); XCTAssertEqual(h.env.inputBegins, 1)
    }
    func testAccumulatorFixedBucketsCountsAndCap() {
        var accumulator = InputActivityAccumulator()
        for index in 0..<300 { accumulator.add(sample(InputActivityCategory.allCases[index % 4]), stamp: stamp) }
        XCTAssertNil(accumulator.takeCompleted(nowMs: 1_999))
        let bucket = accumulator.takeCompleted(nowMs: 2_000)!
        XCTAssertEqual(bucket.intervalStartMs, 1_000); XCTAssertEqual(bucket.intervalEndMs, 2_000)
        XCTAssertEqual(bucket.total, 256); XCTAssertTrue(bucket.capped)
        XCTAssertEqual(bucket.pointerReleases, 64); XCTAssertEqual(bucket.dragSamples, 64)
        XCTAssertEqual(bucket.scrollSamples, 64); XCTAssertEqual(bucket.shortcutPresses, 64)
        XCTAssertTrue(bucket.payload(fixture: true)["coverage"]?["missingReasons"]?.arrayValue?.contains(.string("input-events-capped")) == true)
        XCTAssertNil(accumulator.takeCompleted(nowMs: 2_001))
    }
    func testEventFreshnessRejectsMissingFutureAndDelayedCallbacks() {
        XCTAssertFalse(InputActivityFreshness.accepts(timestampNanoseconds: 0, nowNanoseconds: 1_000_000_000))
        XCTAssertFalse(InputActivityFreshness.accepts(timestampNanoseconds: 1_000_000_001, nowNanoseconds: 1_000_000_000))
        XCTAssertTrue(InputActivityFreshness.accepts(timestampNanoseconds: 800_000_000, nowNanoseconds: 1_000_000_000))
        XCTAssertFalse(InputActivityFreshness.accepts(timestampNanoseconds: 799_999_999, nowNanoseconds: 1_000_000_000))
        XCTAssertFalse(InputActivityFreshness.accepts(timestampNanoseconds: 800_000_000, nowNanoseconds: 1_000_000_001))
    }
    func testEventFreshnessRejectsPreBoundaryEventsEvenWithinAgeBudget() {
        XCTAssertFalse(InputActivityFreshness.accepts(timestampNanoseconds: 900_000_000, nowNanoseconds: 1_000_000_000, afterNanoseconds: 950_000_000))
        XCTAssertFalse(InputActivityFreshness.accepts(timestampNanoseconds: 950_000_000, nowNanoseconds: 1_000_000_000, afterNanoseconds: 950_000_000))
        XCTAssertTrue(InputActivityFreshness.accepts(timestampNanoseconds: 950_000_001, nowNanoseconds: 1_000_000_000, afterNanoseconds: 950_000_000))
    }
    func testInputDetectedApplicationBoundaryDropsTriggeringEvent() {
        let h = start(); add(h)
        let other = ApplicationIdentity(applicationId: app.applicationId, processId: 99, processStartTime: "new-birth")
        let epoch = h.engine.captureEpoch
        add(h, app: other)
        XCTAssertGreaterThan(h.engine.captureEpoch, epoch)
        h.clock.advance(1_000); h.engine.tick()
        XCTAssertTrue(activities(h).isEmpty)
    }
    func testAccumulatorDropsClockDiscontinuityOrStaleBucket() {
        var accumulator = InputActivityAccumulator(); accumulator.add(sample(), stamp: stamp)
        XCTAssertNil(accumulator.takeCompleted(nowMs: 900)); XCTAssertNil(accumulator.pending)
        accumulator.add(sample(), stamp: stamp)
        XCTAssertNil(accumulator.takeCompleted(nowMs: 3_001)); XCTAssertNil(accumulator.pending)
        accumulator.add(sample(time: -1), stamp: stamp); XCTAssertNil(accumulator.pending)
    }
    func testActivityHasApplicationTargetAndFixedFirstStampAcrossText() throws {
        let h = start(); add(h, category: .scrollSample)
        let firstStamp = h.engine.stamp
        h.clock.advance(51); h.engine.tick()
        h.engine.complete(h.goodResult(h.env.launched.last!))
        XCTAssertNotEqual(h.engine.stamp, firstStamp)
        add(h, category: .shortcutPress)
        h.clock.advance(949); h.engine.tick()
        let activity = try XCTUnwrap(activities(h).first)
        XCTAssertEqual(activity["stamp"], firstStamp)
        XCTAssertEqual(activity["target"]?["kind"], .string("application"))
        XCTAssertNil(activity["target"]?["identity"]?["windowId"])
        XCTAssertEqual(activity["payload"]?["counts"]?["scrollSamples"], j(1))
        XCTAssertEqual(activity["payload"]?["counts"]?["shortcutPresses"], j(1))
        XCTAssertEqual(activity["actor"], .string("unknown"))
        XCTAssertEqual(activity["eventTimeMs"], activity["payload"]?["intervalEndMs"])
        XCTAssertNil(activity["payload"]?["text"])
        let validator = try ContractValidator()
        for frame in h.frames { XCTAssertNoThrow(try validator.encodeFrame(frame)) }
    }
    func testPausePolicyStopDesktopAndDisabledDiscardWithoutFlush() {
        for boundary in ["pause", "stop", "configure", "desktop", "disabled"] {
            let h = start(); add(h)
            if boundary == "configure" { h.configure(revision: 2, inputActivity: true) }
            else if boundary == "desktop" { h.engine.desktopChanged(.locked, accessibility: false) }
            else if boundary == "disabled" { h.engine.inputActivityUnavailable("input-monitoring-disabled") }
            else { h.control(boundary, lease: 10_000) }
            h.clock.advance(1_000); h.engine.tick()
            XCTAssertTrue(activities(h).isEmpty, boundary)
            XCTAssertGreaterThan(h.env.inputEnds, 0)
            h.engine.desktopChanged(.unlocked, accessibility: true)
            XCTAssertEqual(h.env.inputBegins, 1)
        }
    }
    func testApplicationChangeClearsButDoesNotRestartListener() {
        let h = start(); add(h)
        let priorEpoch = h.engine.captureEpoch
        let other = ApplicationIdentity(applicationId: app.applicationId, processId: 43, processStartTime: "new-birth")
        h.engine.applicationEvent(SourceHint(application: other, eventTimeMs: h.clock.unixMs))
        XCTAssertGreaterThan(h.engine.captureEpoch, priorEpoch)
        h.clock.advance(1_000); h.engine.tick()
        XCTAssertTrue(activities(h).isEmpty); XCTAssertEqual(h.env.inputBegins, 1)
        // A temporary absence of application identity is not a desktop failure.
        add(h, app: other)
        let unattributedEpoch = h.engine.captureEpoch, inputEnds = h.env.inputEnds
        h.engine.excludedApplicationEvent()
        XCTAssertGreaterThan(h.engine.captureEpoch, unattributedEpoch)
        XCTAssertEqual(h.engine.state, "running"); XCTAssertEqual(h.engine.desktop, .unlocked)
        XCTAssertEqual(h.env.inputEnds, inputEnds); XCTAssertEqual(h.env.inputBegins, 1)
        h.clock.advance(1_000); h.engine.tick()
        XCTAssertTrue(activities(h).isEmpty)
    }
    func testMissedApplicationChangeDuringTextClearsInputBucket() {
        let h = start(); add(h)
        h.clock.advance(51); h.engine.tick()
        let ticket = h.env.launched.last!
        var result = h.goodResult(ticket)
        result.application = ApplicationIdentity(applicationId: app.applicationId, processId: 99, processStartTime: "new")
        let before = h.engine.captureEpoch
        h.engine.complete(result)
        XCTAssertGreaterThan(h.engine.captureEpoch, before)
        h.clock.advance(949); h.engine.tick()
        XCTAssertTrue(activities(h).isEmpty)
    }
    func testFreshPostGateFailureDropsEntireBucket() {
        let h = start(); add(h); h.env.inputValid = false
        h.clock.advance(1_000); h.engine.tick()
        XCTAssertTrue(activities(h).isEmpty)
        h.env.inputValid = true; h.clock.advance(1_000); h.engine.tick()
        XCTAssertTrue(activities(h).isEmpty)
    }
    func testInvalidSampleAndExplicitInvalidationClearPending() {
        let h = start(); add(h)
        add(h, app: ApplicationIdentity(applicationId: "test.denied", processId: 77, processStartTime: "birth"))
        h.clock.advance(1_000); h.engine.tick(); XCTAssertTrue(activities(h).isEmpty)
        add(h); h.engine.clearInputActivity()
        h.clock.advance(1_000); h.engine.tick(); XCTAssertTrue(activities(h).isEmpty)
    }
}

import Foundation
import XCTest
import HistoryContract
@testable import CollectorCore

private final class UnavailableEnvironment: CollectorEnvironment {
    var desktop: DesktopStatus = .unlocked
    var accessibility = true
    var secureInputBlocked = false
    var validationCalls = 0
    var validation: (() -> Void)?
    var launched: [ReadTicket] = []
    var inputBegins = 0
    var inputClears = 0
    var retireCalls = 0
    func beginMonitoring() -> (desktop: DesktopStatus, accessibility: Bool) { (desktop, accessibility) }
    func validateBeforeAccept() -> (desktop: DesktopStatus, accessibility: Bool) {
        validationCalls += 1; validation?()
        return (desktop, accessibility)
    }
    func endMonitoring() {}
    func beginInputActivity(policy: CapturePolicy) -> Bool { inputBegins += 1; return true }
    func clearInputActivity() { inputClears += 1 }
    func validateInputActivity(application: ApplicationIdentity) -> Bool { desktop == .unlocked && accessibility }
    func inputMonitoringGranted() -> Bool { true }
    func launch(_ ticket: ReadTicket) { launched.append(ticket) }
    func cancelRead() {}
    func retireRead() { retireCalls += 1 }
}

private final class UnavailableHarness {
    let clock = FakeClock()
    let environment = UnavailableEnvironment()
    let engine: CollectorEngine
    let application = ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "birth")
    var frames: [JSONValue] = []
    var policy: CapturePolicy
    init(inputText: Bool = false) throws {
        policy = CapturePolicy(inputActivity: true, sampleIntervalMs: 1000, readTimeoutMs: 1500, axCompatibility: true,
            captureScope: "window", inputText: inputText, selectionCapture: true)
        engine = CollectorEngine(ownerId: "owner", instanceId: "instance", deviceId: "device",
            osSessionId: "session", desktopId: "desktop", fixture: false, environment: environment, clock: clock)
        engine.emit = { [weak self] in self?.frames.append($0) }
        try configure()
        control("start"); clock.advance(51); engine.tick()
    }
    func configure(revision: Int64 = 1) throws {
        engine.receive(.object(["protocolVersion": j(1), "type": .string("configure"), "requestId": .string("config"),
            "ownerId": .string("owner"), "instanceId": .string("instance"), "policyRevision": j(revision),
            "policy": try JSONValue.parse(JSONEncoder().encode(policy))]))
    }
    func control(_ command: String) {
        engine.receive(.object(["protocolVersion": j(1), "type": .string("control"), "requestId": .string(command),
            "ownerId": .string("owner"), "instanceId": .string("instance"), "policyRevision": j(engine.policyRevision),
            "command": .string(command), "leaseDurationMs": j(30000)]))
    }
    func next() throws {
        clock.advance(1000); engine.tick()
        _ = try XCTUnwrap(engine.outstanding)
    }
    func unavailable(focus: Bool = false) throws -> ReadResult {
        ReadResult(token: try XCTUnwrap(engine.outstanding).token, reason: focus ? "focus-unavailable" : "policy-boundary",
            diagnostic: .init(code: focus ? .focusedFieldUnavailable : .applicationUnavailable),
            captureStartMs: clock.unixMs, captureEndMs: clock.unixMs)
    }
    func success() throws -> ReadResult {
        var result = ReadResult(token: try XCTUnwrap(engine.outstanding).token, application: application,
            text: .init(text: "synthetic", source: "ax.range", totalLength: 9, complete: true, missingReasons: []),
            captureStartMs: clock.unixMs, captureEndMs: clock.unixMs)
        result.sessionIdentity = .init(sessionId: "worker", windowId: "window", nodeId: "field",
            surfaceId: "surface", windowGeneration: 1, focusGeneration: 1)
        return result
    }
    func observations(_ kind: String) -> [JSONValue] { frames.filter { $0["payload"]?["kind"] == .string(kind) } }
    var gaps: [JSONValue] { observations("gap") }
    var contexts: [JSONValue] { observations("context.changed") }
    func validate() throws {
        let validator = try ContractValidator()
        var previous: Double = 0
        for frame in frames {
            XCTAssertNoThrow(try validator.encodeFrame(frame))
            if frame["type"] == .string("observation") {
                let seq = try XCTUnwrap(frame["seq"]?.numberValue)
                XCTAssertGreaterThan(seq, previous); previous = seq
            }
        }
    }
}

/// Pure production-Engine/fake-clock regressions; no AX, tap, real History or key access.
final class RepeatedUnavailableTests: XCTestCase {
    func testApplicationUnavailableKeepsFirstStateWithoutMovingClockOrPollSchedule() throws {
        let h = try UnavailableHarness()
        h.engine.complete(try h.unavailable())
        let first = h.frames, stamp = h.engine.stamp, clears = h.environment.inputClears
        XCTAssertEqual(h.gaps.count, 1); XCTAssertEqual(h.contexts.count, 1)
        XCTAssertEqual(h.gaps[0]["target"]?["reason"], .string("policy-boundary"))
        XCTAssertNil(h.gaps[0]["payload"]?["providerApplicationId"])
        h.clock.advance(999); h.engine.tick()
        XCTAssertNil(h.engine.outstanding)
        h.clock.advance(1); h.engine.tick()
        h.engine.complete(try h.unavailable())
        XCTAssertEqual(h.frames, first, "An unchanged failed poll is not a new observed state")
        XCTAssertEqual(h.engine.stamp, stamp)
        try h.next(); h.engine.complete(try h.unavailable())
        XCTAssertEqual(h.frames, first)
        XCTAssertEqual(h.environment.validationCalls, 3, "Every app-unavailable reply still runs the original fresh gate")
        XCTAssertEqual(h.environment.launched.count, 3)
        XCTAssertGreaterThan(h.environment.inputClears, clears)
        XCTAssertEqual(h.environment.inputBegins, 1)
        XCTAssertEqual(h.engine.state, "running")
        XCTAssertEqual(h.gaps[0]["payload"]?["count"], j(1))
        h.control("heartbeat"); XCTAssertEqual(h.frames.last?["state"], .string("running"))
        try h.validate()
    }

    func testExactNegativeFocusKeepsFirstButStillRejectsWithoutBlockingAdmissionGate() throws {
        let h = try UnavailableHarness(inputText: true)
        h.environment.validation = { h.clock.advance(2000) }
        var first = try h.unavailable(focus: true)
        first.surfaceFailure = .anchorUnavailable; first.diagnosticApplication = h.application
        h.engine.complete(first)
        let frames = h.frames, stamp = h.engine.stamp
        try h.next()
        var repeated = try h.unavailable(focus: true)
        repeated.surfaceFailure = .anchorUnavailable; repeated.diagnosticApplication = h.application
        h.engine.complete(repeated)
        XCTAssertEqual(h.frames, frames); XCTAssertEqual(h.engine.stamp, stamp)
        XCTAssertEqual(h.gaps.count, 1)
        XCTAssertEqual(h.gaps.first?["payload"]?["providerApplicationId"], .string("test.allowed"))
        XCTAssertEqual(h.environment.validationCalls, 0)
        XCTAssertEqual(h.engine.state, "running")
        h.environment.validation = nil
        try h.next(); h.engine.complete(try h.success())
        XCTAssertEqual(h.observations("text.snapshot").count, 1)
        try h.validate()
    }

    func testUnavailableReasonChangesAndReturnAreNewStates() throws {
        let h = try UnavailableHarness()
        h.engine.complete(try h.unavailable())
        try h.next(); h.engine.complete(try h.unavailable(focus: true))
        try h.next(); h.engine.complete(try h.unavailable())
        XCTAssertEqual(h.gaps.count, 3)
        XCTAssertEqual(h.gaps.map { $0["payload"]?["diagnostic"]?["code"] },
            [.string("application-unavailable"), .string("focused-field-unavailable"), .string("application-unavailable")])
        try h.next(); h.engine.complete(try h.unavailable())
        XCTAssertEqual(h.gaps.count, 3)
        try h.validate()
    }

    func testSuccessfulRecoveryBreaksUnavailableBaselineAndReestablishesSnapshot() throws {
        let h = try UnavailableHarness()
        h.engine.complete(try h.success())
        try h.next(); h.engine.complete(try h.unavailable())
        try h.next(); h.engine.complete(try h.unavailable())
        XCTAssertEqual(h.gaps.count, 1)
        try h.next(); h.engine.complete(try h.success())
        XCTAssertEqual(h.observations("text.snapshot").count, 2)
        try h.next(); h.engine.complete(try h.unavailable())
        XCTAssertEqual(h.gaps.count, 2, "Unavailable → recovered → unavailable must report the new failure")
        try h.validate()
    }

    func testProviderIdentityAvailabilityAndBirthRemainStateChangesWithoutGuessingAnApp() throws {
        let h = try UnavailableHarness()
        var value = try h.unavailable(focus: true); value.diagnosticApplication = h.application
        h.engine.complete(value)
        try h.next(); value = try h.unavailable(focus: true); value.diagnosticApplication = h.application
        h.engine.complete(value); XCTAssertEqual(h.gaps.count, 1)
        try h.next(); value = try h.unavailable(focus: true)
        value.diagnosticApplication = .init(applicationId: h.application.applicationId, processId: 42, processStartTime: "new-birth")
        h.engine.complete(value); XCTAssertEqual(h.gaps.count, 2)
        try h.next(); h.engine.complete(try h.unavailable(focus: true))
        XCTAssertEqual(h.gaps.count, 3); XCTAssertNil(h.gaps.last?["payload"]?["providerApplicationId"])
        try h.next(); value = try h.unavailable(focus: true); value.surfaceFailure = .anchorUnavailable
        h.engine.complete(value); XCTAssertEqual(h.gaps.count, 4, "An independently changed failure shape is not discarded")
        try h.validate()
    }

    func testDirtyAndAdmittedActivityBreakPollingBaselineWithoutRestartingListener() throws {
        let h = try UnavailableHarness()
        h.engine.complete(try h.unavailable())
        h.engine.workerDirty(); h.clock.advance(10); h.engine.tick()
        h.engine.complete(try h.unavailable()); XCTAssertEqual(h.gaps.count, 2)
        h.engine.inputActivity(.init(application: h.application, category: .pointerRelease, callbackTimeMs: h.clock.unixMs))
        try h.next(); h.engine.complete(try h.unavailable()); XCTAssertEqual(h.gaps.count, 3)
        // Delayed rejected callbacks do not manufacture a new observed activity.
        h.engine.inputActivity(.init(application: h.application, category: .scrollSample, callbackTimeMs: h.clock.unixMs - 201))
        try h.next(); h.engine.complete(try h.unavailable()); XCTAssertEqual(h.gaps.count, 3)
        XCTAssertEqual(h.environment.inputBegins, 1)
        h.engine.reportBackpressure(); h.engine.reportBackpressure()
        XCTAssertEqual(h.gaps.suffix(2).map { $0["payload"]?["reason"] }, [.string("backpressure"), .string("backpressure")])
        try h.next(); h.engine.complete(try h.unavailable()); XCTAssertEqual(h.gaps.count, 6)
        try h.validate()
    }

    func testPolicyActivationAndExplicitResumeCannotReuseUnavailableBaseline() throws {
        let h = try UnavailableHarness(inputText: true)
        h.engine.complete(try h.unavailable())
        h.engine.applicationEvent(.init(application: h.application, eventTimeMs: h.clock.unixMs))
        h.clock.advance(51); h.engine.tick(); h.engine.complete(try h.unavailable())
        XCTAssertEqual(h.gaps.count, 2); XCTAssertEqual(h.environment.retireCalls, 1)
        h.control("pause"); h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "paused")
        h.control("resume"); h.clock.advance(51); h.engine.tick(); h.engine.complete(try h.unavailable())
        XCTAssertEqual(h.gaps.count, 3)
        try h.configure(revision: 2); h.control("start")
        h.clock.advance(51); h.engine.tick(); h.engine.complete(try h.unavailable())
        XCTAssertEqual(h.gaps.count, 4); XCTAssertEqual(h.engine.policyRevision, 2)
        try h.validate()
    }

    func testRepeatedApplicationFailureCannotHideFreshDeadlineOrDesktopRejection() throws {
        let h = try UnavailableHarness(inputText: true)
        h.engine.complete(try h.unavailable()); try h.next()
        h.environment.validation = { h.clock.advance(1500) }
        h.engine.complete(try h.unavailable())
        XCTAssertEqual(h.environment.validationCalls, 2)
        XCTAssertEqual(h.engine.state, "paused")
        XCTAssertEqual(h.frames.last?["reason"], .string("read-timeout-unrecoverable"))
        XCTAssertEqual(h.gaps.count, 1)
        h.environment.validation = nil
        h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "paused")
        h.control("resume"); h.clock.advance(51); h.engine.tick(); h.engine.complete(try h.unavailable())
        XCTAssertEqual(h.gaps.count, 2)
        try h.next(); h.environment.desktop = .locked
        h.engine.complete(try h.unavailable())
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.gaps.count, 2)
        XCTAssertEqual(h.frames.last?["reason"], .string("desktop-unavailable"))
        try h.validate()
    }

    func testUnavailableRecoveryRequiresRebuiltWorkerIdentityForSubsequentInputGeneration() throws {
        // This is the Engine/worker stamp contract, not a native Session/AX test.
        // Compare the old same-handle changed=false reply with the rebuilt reply
        // in independent runs; never relax the Engine's exact input stamp gate.
        for rebuilt in [false, true] {
            let h = try UnavailableHarness(inputText: true)
            h.engine.complete(try h.success())
            try h.next(); h.engine.complete(try h.unavailable())
            try h.next(); h.engine.complete(try h.unavailable())
            XCTAssertEqual(h.gaps.count, 1)
            try h.next()
            let ticket = try XCTUnwrap(h.engine.outstanding)
            var restored = try h.success()
            if rebuilt {
                restored.sessionIdentity = .init(sessionId: "worker", windowId: "rebuilt-window", nodeId: "rebuilt-field",
                    surfaceId: "rebuilt-surface", windowGeneration: 2, focusGeneration: 2)
            }
            let identity = try XCTUnwrap(restored.sessionIdentity)
            let generationDelta: Int64 = rebuilt ? 1 : 0
            let context = InputTextContext(target: .init(application: h.application, deviceId: ticket.deviceId,
                osSessionId: ticket.osSessionId, desktopId: ticket.desktopId,
                windowId: identity.windowId, windowGeneration: identity.windowGeneration), surfaceId: identity.surfaceId,
                captureEpoch: ticket.captureEpoch,
                foregroundGeneration: try XCTUnwrap(ticket.foregroundGeneration) + generationDelta,
                focusGeneration: try XCTUnwrap(ticket.focusGeneration) + generationDelta,
                policyRevision: ticket.policyRevision, privateState: .normal)
            restored.inputRecords = [] // The failure cleared all pre-recovery input.
            h.engine.complete(restored)
            XCTAssertTrue(h.observations("input.text").isEmpty)
            XCTAssertEqual(context.stamp == h.engine.stamp, rebuilt)

            // An event occurs only after the empty recovery read. The following
            // read drains it under the context established by that recovery.
            h.clock.advance(1)
            var accumulator = InputTextAccumulator()
            accumulator.add(.init(context: context, eventKind: .text, text: "after recovery", modifiers: [],
                callbackTimeMs: h.clock.unixMs), source: .cgUnicode)
            let record = try XCTUnwrap(accumulator.takeSegment(approvedContext: context))
            XCTAssertTrue(record.isValid)
            try h.next()
            var following = try h.success(); following.sessionIdentity = identity; following.inputRecords = [record]
            h.engine.complete(following)
            XCTAssertEqual(h.observations("input.text").count, rebuilt ? 1 : 0)
            if rebuilt {
                XCTAssertEqual(h.observations("input.text").first?["payload"]?["text"], .string("after recovery"))
                XCTAssertEqual(h.observations("input.text").first?["stamp"], context.stamp)
            }
            XCTAssertEqual(h.engine.state, "running")
            try h.validate()
        }
    }

    func testIndependentSurfaceFailureAndInputGapAreNotCoalescingCandidates() throws {
        let h = try UnavailableHarness(inputText: true)
        for _ in 0..<2 {
            var value = try h.unavailable(focus: true); value.surfaceFailure = .boundaryUnverified
            h.engine.complete(value)
            try h.next()
        }
        XCTAssertEqual(h.environment.validationCalls, 2)
        XCTAssertEqual(h.gaps.filter { $0["payload"]?["diagnostic"]?["code"] == .string("surface-boundary-unverified") }.count, 2)
        let count = h.gaps.count
        for _ in 0..<2 {
            var value = try h.success(); value.inputGaps = ["stale"]
            h.engine.complete(value)
            try h.next()
        }
        XCTAssertEqual(h.gaps.count, count + 2)
        XCTAssertEqual(h.gaps.suffix(2).map { $0["payload"]?["diagnostic"]?["code"] },
            [.string("input-context-unverified"), .string("input-context-unverified")])
        try h.validate()
    }
}

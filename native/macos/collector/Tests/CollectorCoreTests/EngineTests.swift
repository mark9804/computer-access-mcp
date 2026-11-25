import XCTest
import HistoryContract
@testable import CollectorCore

final class FakeEnvironment: CollectorEnvironment {
    var beginCalls = 0
    var endCalls = 0
    var cancelCalls = 0
    var desktop: DesktopStatus = .unlocked
    var accessibility = true
    var desktopReason = "desktop-unavailable"
    var secureInputBlocked = false
    var workerReady = true
    var retireCalls = 0
    func readyForRead() -> Bool { workerReady }
    func retireRead() { retireCalls += 1; cancelRead() }
    var inputAvailable = false
    var inputValid = true
    var inputPermission = true
    func inputMonitoringGranted() -> Bool { inputPermission }
    var inputBegins = 0
    var inputEnds = 0
    var inputClears = 0
    var inputActivityReason = "input-monitoring-unavailable"
    func beginInputActivity(policy: CapturePolicy) -> Bool { inputBegins += 1; return inputAvailable }
    func endInputActivity() { inputEnds += 1 }
    func clearInputActivity() { inputClears += 1 }
    func validateInputActivity(application: ApplicationIdentity) -> Bool { inputValid && inputAvailable && desktop == .unlocked }
    var launched: [ReadTicket] = []
    func beginMonitoring() -> (desktop: DesktopStatus, accessibility: Bool) { beginCalls += 1; return (desktop, accessibility) }
    func validateBeforeAccept() -> (desktop: DesktopStatus, accessibility: Bool) { (desktop, accessibility) }
    func endMonitoring() { endCalls += 1 }
    func launch(_ ticket: ReadTicket) { launched.append(ticket) }
    func cancelRead() { cancelCalls += 1 }
}
final class Harness {
    let clock = FakeClock()
    let env = FakeEnvironment()
    let engine: CollectorEngine
    var frames: [JSONValue] = []
    init(fixture: Bool = true) {
        engine = CollectorEngine(ownerId: "owner", instanceId: "instance", deviceId: "device", osSessionId: "session", desktopId: "desktop", fixture: fixture, environment: env, clock: clock)
        engine.emit = { [weak self] in self?.frames.append($0) }
    }
    func configure(revision: Int64 = 1, enabled: Bool = true, inputActivity: Bool? = false, textRange: String? = nil, sampleIntervalMs: Int? = nil) {
        let policy = CapturePolicy(enabled: enabled, inputActivity: inputActivity, textRange: textRange, sampleIntervalMs: sampleIntervalMs)
        engine.receive(.object(["protocolVersion": j(1), "type": .string("configure"), "requestId": .string("config"), "ownerId": .string("owner"), "instanceId": .string("instance"), "policyRevision": j(revision), "policy": try! JSONValue.parse(JSONEncoder().encode(policy))]))
    }
    func control(_ command: String, lease: Int = 1000, revision: Int64 = 1, owner: String = "owner") {
        engine.receive(.object(["protocolVersion": j(1), "type": .string("control"), "requestId": .string(command), "ownerId": .string(owner), "instanceId": .string("instance"), "policyRevision": j(revision), "command": .string(command), "leaseDurationMs": j(lease)]))
    }
    func start() { configure(); control("start"); clock.advance(51); engine.tick() }
    func goodResult(_ ticket: ReadTicket) -> ReadResult {
        ReadResult(token: ticket.token, application: ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "birth"), text: TextRead(text: "\u{1F9EA}", source: "ax.range", totalLength: 2, complete: true, missingReasons: []), captureStartMs: clock.unixMs, captureEndMs: clock.unixMs)
    }
    var textFrames: [JSONValue] { frames.filter { $0["payload"]?["kind"] == .string("text.snapshot") } }
}

final class EngineTests: XCTestCase {
    func testHelloConfigureDoNotRegisterAndDisabledCannotStart() {
        let h = Harness(); h.engine.hello()
        XCTAssertEqual(h.env.beginCalls, 0)
        h.control("start"); XCTAssertEqual(h.env.beginCalls, 0)
        h.configure(enabled: false); h.control("start"); XCTAssertEqual(h.env.beginCalls, 0)
        h.configure(revision: 2); XCTAssertEqual(h.env.beginCalls, 0)
        h.control("start", revision: 2); XCTAssertEqual(h.env.beginCalls, 1)
    }
    func testOwnerRevisionAndBoundedLeaseCannotBeForged() {
        let h = Harness(); h.configure(); h.control("start", owner: "other")
        XCTAssertEqual(h.env.beginCalls, 0); XCTAssertEqual(h.frames.last?["code"], .string("permission-denied"))
        h.control("start", revision: 2); XCTAssertEqual(h.env.beginCalls, 0)
        h.control("start", lease: 30001); XCTAssertEqual(h.env.beginCalls, 0)
        h.control("start", lease: 200); h.clock.advance(201); h.engine.tick()
        XCTAssertTrue(h.engine.shouldExit); XCTAssertEqual(h.engine.state, "stopped")
    }
    func testUnknownLockedAndNoPermissionFailClosed() {
        for desktop in [DesktopStatus.unknown, .locked] {
            let h = Harness(); h.env.desktop = desktop; h.start()
            XCTAssertEqual(h.engine.state, "paused"); XCTAssertTrue(h.env.launched.isEmpty)
        }
        let h = Harness(); h.env.accessibility = false; h.start()
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertTrue(h.env.launched.isEmpty)
        h.engine.desktopChanged(.unlocked, accessibility: false)
        XCTAssertEqual(h.engine.state, "paused")
    }
    func testUserPausePersistsAcrossUnlockAndRepeatedStart() {
        let h = Harness(); h.start(); let ticket = h.env.launched.last!
        h.control("pause"); h.engine.desktopChanged(.locked, accessibility: false)
        h.engine.desktopChanged(.unlocked, accessibility: true); h.control("start")
        XCTAssertEqual(h.engine.state, "paused")
        h.engine.complete(h.goodResult(ticket)); XCTAssertTrue(h.textFrames.isEmpty)
        h.control("resume"); XCTAssertEqual(h.engine.state, "running")
    }
    func testSourceStampedContextPrecedesSnapshotAndAllWireValidates() throws {
        let h = Harness(fixture: false); h.engine.hello(); h.start()
        h.engine.complete(h.goodResult(h.env.launched.last!))
        let tail = h.frames.suffix(2)
        XCTAssertEqual(tail.first?["payload"]?["kind"], .string("context.changed"))
        XCTAssertEqual(tail.last?["payload"]?["kind"], .string("text.snapshot"))
        XCTAssertEqual(tail.first?["target"], tail.last?["target"])
        XCTAssertEqual(tail.first?["stamp"], tail.last?["stamp"])
        XCTAssertEqual(tail.last?["payload"]?["range"]?["length"], j(2))
        XCTAssertEqual(tail.last?["payload"]?["gate"]?["policyRevision"], j(1))
        let validator = try ContractValidator()
        for frame in h.frames { XCTAssertNoThrow(try validator.encodeFrame(frame)) }
        let snapshotId = h.textFrames[0]["payload"]?["snapshotId"]
        h.clock.advance(1001); h.control("heartbeat", lease: 5000)
        // Prior lease expiration is fail-closed, even if heartbeat arrives later.
        XCTAssertTrue(h.engine.shouldExit)
        XCTAssertNotNil(snapshotId)
    }
    func testFreshBaselinesUniqueAndHeartbeatUsesCurrentStamp() {
        let h = Harness(); h.start(); h.engine.complete(h.goodResult(h.env.launched.last!))
        let first = h.textFrames[0]
        h.clock.advance(151); h.engine.tick(); h.engine.complete(h.goodResult(h.env.launched.last!))
        XCTAssertNotEqual(first["payload"]?["snapshotId"], h.textFrames.last?["payload"]?["snapshotId"])
        XCTAssertNotEqual(first["target"], h.textFrames.last?["target"])
        h.control("heartbeat")
        XCTAssertEqual(h.frames.last?["stamp"], h.textFrames.last?["stamp"])
    }
    func testLateResultAfterAppChangePolicyAndLockCannotRegainContext() {
        let h = Harness(); h.start(); let old = h.env.launched.last!
        h.engine.applicationEvent(SourceHint(application: ApplicationIdentity(applicationId: "second", processId: 52, processStartTime: "new"), eventTimeMs: h.clock.unixMs))
        h.engine.complete(h.goodResult(old)); XCTAssertTrue(h.textFrames.isEmpty)
        h.configure(revision: 2); h.engine.complete(h.goodResult(old)); XCTAssertTrue(h.textFrames.isEmpty)
        h.control("start", revision: 2); h.clock.advance(51); h.engine.tick()
        let new = h.env.launched.last!
        h.engine.desktopChanged(.unknown, accessibility: false); h.engine.complete(h.goodResult(new))
        XCTAssertTrue(h.textFrames.isEmpty)
    }
    func testBufferedWorkerReplyCannotCrossLockBeforeNextPeriodicPoll() {
        for fresh in [DesktopStatus.locked, .unknown] {
            let h = Harness(); h.start(); let ticket = h.env.launched.last!
            XCTAssertEqual(h.engine.desktop, .unlocked)
            h.env.desktop = fresh // No desktopChanged notification or poll yet.
            h.engine.complete(h.goodResult(ticket))
            XCTAssertTrue(h.textFrames.isEmpty); XCTAssertEqual(h.engine.state, "paused")
        }
        let h = Harness(); h.start(); let ticket = h.env.launched.last!
        h.env.accessibility = false
        h.engine.complete(h.goodResult(ticket))
        XCTAssertTrue(h.textFrames.isEmpty); XCTAssertEqual(h.engine.state, "paused")
    }
    func testParentDeathEOFStopAndTimeoutCancelWork() {
        let h = Harness(); h.start(); let old = h.env.launched.last!
        h.clock.advance(201); h.engine.tick()
        XCTAssertEqual(h.frames.last?["payload"]?["reason"], .string("timeout"))
        XCTAssertNil(h.engine.outstanding)
        h.engine.complete(h.goodResult(old)); XCTAssertTrue(h.textFrames.isEmpty)
        h.engine.tick(parentAlive: false)
        XCTAssertTrue(h.engine.shouldExit); XCTAssertEqual(h.frames.last?["reason"], .string("parent-death"))
        XCTAssertGreaterThan(h.env.cancelCalls, 0)
        XCTAssertGreaterThan(h.env.endCalls, 0)
    }
    func testReconciliationSpacingHonorsDebounceAndMaxWait() {
        let h = Harness(); h.configure(); h.control("start")
        h.clock.advance(49); h.engine.tick(); XCTAssertTrue(h.env.launched.isEmpty)
        h.clock.advance(1); h.engine.tick(); XCTAssertEqual(h.env.launched.count, 1)
        h.engine.tick(); XCTAssertEqual(h.env.launched.count, 1)
    }
    func testActionNeverStartsEnvironment() {
        let h = Harness(); h.engine.receive(.object(["type": .string("action.request"), "requestId": .string("action")]))
        XCTAssertEqual(h.frames.last?["code"], .string("unsupported")); XCTAssertEqual(h.env.beginCalls, 0)
    }
}

import XCTest
import AccessContract
@testable import CollectorCore

// The cleanup result is the transport's claim about the exact aborted child.
// Readiness is deliberately independent: empty pipes are not proof of reap.
private final class TimeoutRecoveryEnvironment: CollectorEnvironment {
    var desktop: DesktopStatus = .unlocked
    var desktopReason = "desktop-unavailable"
    var accessibility = true
    var secureInputBlocked = false
    var inputPermission = true
    var coarseHealthy = true
    var ready = true
    var abortResult: ReadTimeoutCleanup = .reaped
    var cleanupResult: ReadTimeoutCleanup = .reaped
    var duringValidation: (() -> Void)?
    var duringAbort: (() -> Void)?
    var aborted: [ReadTicket] = []
    var launched: [ReadTicket] = []
    private var owned: ReadTicket?
    var beginCalls = 0
    var validationCalls = 0
    var coarseBegins = 0
    var coarseEnds = 0
    var coarseActive = false
    var clearCalls = 0

    var inputActivityHealthy: Bool { coarseActive && coarseHealthy }
    func inputMonitoringGranted() -> Bool { inputPermission }
    func beginMonitoring() -> (desktop: DesktopStatus, accessibility: Bool) {
        beginCalls += 1
        return (desktop, accessibility)
    }
    func validateBeforeAccept() -> (desktop: DesktopStatus, accessibility: Bool) {
        validationCalls += 1
        duringValidation?()
        return (desktop, accessibility)
    }
    func endMonitoring() {}
    func beginInputActivity(policy: CapturePolicy) -> Bool {
        coarseBegins += 1; coarseActive = true
        return true
    }
    func endInputActivity() { coarseEnds += 1; coarseActive = false }
    func clearInputActivity() { clearCalls += 1 }
    func validateInputActivity(application: ApplicationIdentity) -> Bool { inputActivityHealthy }
    func readyForRead() -> Bool { ready }
    func launch(_ ticket: ReadTicket) { launched.append(ticket); owned = ticket }
    func cancelRead() { owned = nil }
    func abortTimedOutRead(_ ticket: ReadTicket) -> ReadTimeoutCleanup {
        aborted.append(ticket)
        guard owned == ticket else { return .ineligible }
        owned = nil // Once sealed, this fake transport cannot issue it again.
        duringAbort?()
        return abortResult
    }
    func timedOutReadCleanup() -> ReadTimeoutCleanup { cleanupResult }
}

private final class TimeoutRecoveryHarness {
    let clock = FakeClock()
    let env = TimeoutRecoveryEnvironment()
    let engine: CollectorEngine
    let app = ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "synthetic-birth")
    var frames: [JSONValue] = []
    var queued: [JSONValue] = []

    init(inputActivity: Bool = false, sampleIntervalMs: Int = 1_000, lease: Int = 30_000) throws {
        engine = CollectorEngine(ownerId: "owner", instanceId: "instance", deviceId: "device", osSessionId: "session",
                                 desktopId: "desktop", fixture: true, environment: env, clock: clock)
        engine.emit = { [weak self] frame in
            self?.frames.append(frame)
            if frame["type"] == .string("observation") { self?.queued.append(frame) }
        }
        engine.discardQueuedObservations = { [weak self] in self?.queued.removeAll() }
        try configure(CapturePolicy(inputActivity: inputActivity, sampleIntervalMs: sampleIntervalMs,
                                    readTimeoutMs: 1_500, inputText: true), revision: 1)
        control("start", lease: lease)
        tick(after: 50)
    }

    func configure(_ policy: CapturePolicy, revision: Int64) throws {
        engine.receive(.object(["protocolVersion": j(1), "type": .string("configure"), "requestId": .string("configure"),
            "ownerId": .string("owner"), "instanceId": .string("instance"), "policyRevision": j(revision),
            "policy": try JSONValue.parse(JSONEncoder().encode(policy))]))
    }
    func control(_ command: String, lease: Int = 30_000) {
        engine.receive(.object(["protocolVersion": j(1), "type": .string("control"), "requestId": .string(command),
            "ownerId": .string("owner"), "instanceId": .string("instance"), "policyRevision": j(engine.policyRevision),
            "command": .string(command), "leaseDurationMs": j(lease)]))
    }
    func tick(after delay: Int64 = 0) {
        clock.advance(delay); engine.tick()
    }
    func expire(_ ticket: ReadTicket) {
        tick(after: ticket.deadlineMonotonicMs - clock.monotonicMs)
    }
    func observations(_ kind: String) -> [JSONValue] {
        frames.filter { $0["payload"]?["kind"] == .string(kind) }
    }
    var stateFrames: [JSONValue] { frames.filter { $0["type"] == .string("state") } }
    var reason: JSONValue? { stateFrames.last?["reason"] }

    func reply(_ ticket: ReadTicket, text: String = "synthetic field", session: String = "synthetic-worker") -> ReadResult {
        var result = ReadResult(token: ticket.token, application: app,
            text: TextRead(text: text, source: "ax.range", totalLength: text.utf16.count, complete: true, missingReasons: []),
            captureStartMs: clock.unixMs, captureEndMs: clock.unixMs)
        result.sessionIdentity = .init(sessionId: session, windowId: "synthetic-window", nodeId: "synthetic-node",
                                       surfaceId: "synthetic-field", windowGeneration: 1, focusGeneration: 1)
        return result
    }
    func input(_ ticket: ReadTicket, text: String, epoch: Int64? = nil) throws -> InputTextEmission {
        // Used only alongside the first result from a new synthetic worker, when
        // the engine advances both generations for its newly resolved identity.
        let context = InputTextContext(target: .init(application: app, deviceId: "device", osSessionId: "session",
            desktopId: "desktop", windowId: "synthetic-window", windowGeneration: 1), surfaceId: "synthetic-field",
            captureEpoch: epoch ?? ticket.captureEpoch, foregroundGeneration: engine.foregroundGeneration + 1,
            focusGeneration: engine.focusGeneration + 1, policyRevision: ticket.policyRevision, privateState: .normal)
        var accumulator = InputTextAccumulator()
        accumulator.add(.init(context: context, eventKind: .text, text: text, modifiers: [], callbackTimeMs: clock.unixMs), source: .fixture)
        return try XCTUnwrap(accumulator.takeSegment(approvedContext: context))
    }
    func coarseSample() {
        engine.inputActivity(.init(application: app, category: .pointerRelease, callbackTimeMs: clock.unixMs))
    }
}

final class ReadTimeoutRecoveryTests: XCTestCase {
    func testExactReapStartsFreshEpochWithoutReplayingOldObservationsOrRestartingCoarseTap() throws {
        let h = try TimeoutRecoveryHarness(inputActivity: true)
        let first = try XCTUnwrap(h.engine.outstanding)
        let previousInput = try h.input(first, text: "prior input")
        var prior = h.reply(first)
        prior.inputRecords = [previousInput]
        h.engine.complete(prior)
        XCTAssertEqual(h.observations("text.snapshot").count, 1)
        XCTAssertEqual(h.observations("input.text").count, 1)
        XCTAssertFalse(h.queued.isEmpty)

        h.tick(after: 1_000)
        let expired = try XCTUnwrap(h.engine.outstanding)
        var lateReply = h.reply(expired, text: "expired material")
        lateReply.inputRecords = [previousInput]
        h.coarseSample() // An old bucket could complete on the deadline tick.
        let clears = h.env.clearCalls, tapEnds = h.env.coarseEnds, tapBegins = h.env.coarseBegins
        h.env.duringAbort = { [weak h] in
            guard let h else { return }
            XCTAssertNil(h.engine.outstanding)
            XCTAssertFalse(h.queued.contains { $0["payload"]?["kind"] != .string("gap") })
            let frameCount = h.frames.count
            h.engine.complete(lateReply)
            XCTAssertEqual(h.frames.count, frameCount, "Ingress closes before the transport handles abort")
        }
        h.expire(expired)
        h.env.duringAbort = nil
        XCTAssertEqual(h.env.aborted, [expired])
        XCTAssertEqual(h.engine.state, "paused")
        XCTAssertEqual(h.stateFrames.last?["requestId"], .string("read-recovery"))
        XCTAssertEqual(h.reason, .string("read-timeout-recovering"))
        XCTAssertGreaterThan(h.engine.captureEpoch, expired.captureEpoch)
        XCTAssertNil(h.engine.outstanding)
        XCTAssertGreaterThan(h.env.clearCalls, clears)
        XCTAssertEqual(h.env.coarseEnds, tapEnds)
        XCTAssertFalse(h.queued.contains { $0["payload"]?["kind"] != .string("gap") })
        XCTAssertTrue(h.observations("input.activity").isEmpty)

        let validationCalls = h.env.validationCalls
        let beforeLate = h.frames.count
        h.engine.complete(lateReply)
        XCTAssertEqual(h.frames.count, beforeLate)
        h.engine.workerDirty()
        h.tick(after: 999)
        XCTAssertEqual(h.env.launched.count, 2)
        h.tick(after: 1)
        let retry = try XCTUnwrap(h.engine.outstanding)
        XCTAssertEqual(h.env.launched.count, 3)
        XCTAssertEqual(h.engine.state, "running")
        XCTAssertEqual(h.reason, .string("read-timeout-recovered"))
        XCTAssertGreaterThan(h.env.validationCalls, validationCalls)
        XCTAssertEqual(h.env.beginCalls, 1, "Recovery is not a new user start/resume")
        XCTAssertEqual(h.env.coarseBegins, tapBegins)
        XCTAssertNotEqual(retry.token, expired.token)
        XCTAssertGreaterThan(retry.captureEpoch, expired.captureEpoch)
        XCTAssertNil(retry.hint)
        XCTAssertEqual(retry.policy, expired.policy)
        XCTAssertEqual(retry.policyRevision, expired.policyRevision)
        XCTAssertEqual(retry.deadlineMonotonicMs, h.clock.monotonicMs + 1_500)
        let gaps = h.observations("gap")
        XCTAssertEqual(gaps.count, 1)
        XCTAssertEqual(gaps.first?["payload"]?["reason"], .string("timeout"))
        XCTAssertEqual(gaps.first?["payload"]?["diagnostic"]?["code"], .string("read-deadline"))
        XCTAssertEqual(gaps.first?["target"]?["kind"], .string("unresolved"))
        XCTAssertNil(gaps.first?["payload"]?["providerApplicationId"])
        XCTAssertEqual(gaps.first?["stamp"]?["captureEpoch"], j(retry.captureEpoch))
        let reopenedAt = try XCTUnwrap(h.frames.lastIndex { $0["reason"] == .string("read-timeout-recovered") })
        let gapAt = try XCTUnwrap(h.frames.firstIndex { $0["payload"]?["kind"] == .string("gap") })
        XCTAssertLessThan(reopenedAt, gapAt, "The Host must see the new running epoch before the gap")

        let beforeReplay = h.frames.count
        h.engine.complete(lateReply)
        h.engine.complete(ReadResult(token: expired.token, reason: "input-monitoring-disabled",
            captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs))
        h.engine.workerReadDeadlineReached(expired)
        XCTAssertEqual(h.frames.count, beforeReplay)
        XCTAssertEqual(h.engine.outstanding, retry)
        var fresh = h.reply(retry, session: "replacement-worker")
        // Match every other current stamp/identity field so the old epoch is
        // what rejects this input nested inside an otherwise fresh reply.
        fresh.inputRecords = [try h.input(retry, text: "old epoch", epoch: expired.captureEpoch),
                              try h.input(retry, text: "fresh input")]
        h.engine.complete(fresh)
        XCTAssertEqual(h.observations("text.snapshot").compactMap { $0["payload"]?["text"]?.stringValue },
                       ["synthetic field", "synthetic field"])
        XCTAssertEqual(h.observations("input.text").compactMap { $0["payload"]?["text"]?.stringValue },
                       ["prior input", "fresh input"])
        XCTAssertTrue(h.observations("input.activity").isEmpty)
        h.coarseSample()
        h.tick(after: 1_000)
        XCTAssertEqual(h.observations("input.activity").count, 1)
        let validator = try ContractValidator()
        for frame in h.frames { XCTAssertNoThrow(try validator.encodeFrame(frame)) }
    }

    func testDeadlineNotificationRequiresLiveCurrentTicketAndBoundedExactReap() throws {
        let h = try TimeoutRecoveryHarness()
        let ticket = try XCTUnwrap(h.engine.outstanding)
        h.env.abortResult = .awaitingExit
        h.env.cleanupResult = .awaitingExit
        h.engine.workerReadDeadlineReached(ticket)
        XCTAssertTrue(h.env.aborted.isEmpty, "An early callback is not a hard timeout")
        XCTAssertEqual(h.engine.outstanding, ticket)
        h.clock.advance(ticket.deadlineMonotonicMs - h.clock.monotonicMs)
        var wrongEpoch = ticket
        wrongEpoch.captureEpoch -= 1
        h.engine.workerReadDeadlineReached(wrongEpoch)
        XCTAssertTrue(h.env.aborted.isEmpty)
        h.engine.workerReadDeadlineReached(ticket)
        XCTAssertEqual(h.env.aborted, [ticket])
        XCTAssertEqual(h.reason, .string("read-timeout-recovering"))
        h.tick(after: 999)
        XCTAssertEqual(h.env.launched.count, 1, "Ready, but exact exit is still unproved")
        h.env.cleanupResult = .reaped
        h.tick()
        XCTAssertEqual(h.env.launched.count, 1, "Exact reap does not shorten the backoff")
        h.control("heartbeat")
        XCTAssertEqual(h.reason, .string("read-timeout-recovering"))
        h.tick(after: 1)
        XCTAssertEqual(h.env.launched.count, 2, "Reap wait and backoff overlap from timeout detection")
        XCTAssertEqual(h.reason, .string("read-timeout-recovered"))
    }

    func testUnconfirmedOrIneligibleCleanupRequiresManualResumeEvenIfReadinessReturns() throws {
        for (abort, cleanup, reason): (ReadTimeoutCleanup, ReadTimeoutCleanup, String) in [
            (.unconfirmed, .reaped, "worker-exit-unconfirmed"),
            (.awaitingExit, .awaitingExit, "worker-exit-unconfirmed"),
            (.awaitingExit, .ineligible, "read-timeout-unrecoverable"),
            (.ineligible, .reaped, "read-timeout-unrecoverable"),
        ] {
            let h = try TimeoutRecoveryHarness()
            h.env.abortResult = abort; h.env.cleanupResult = cleanup
            let ticket = try XCTUnwrap(h.engine.outstanding)
            h.expire(ticket)
            h.tick(after: 1_000)
            XCTAssertEqual(h.reason, .string(reason))
            h.env.cleanupResult = .reaped
            h.engine.complete(h.reply(ticket))
            h.engine.desktopChanged(.unlocked, accessibility: true)
            h.engine.workerDirty()
            h.control("start")
            h.tick(after: 5_000)
            XCTAssertEqual(h.reason, .string(reason))
            XCTAssertEqual(h.engine.state, "paused")
            XCTAssertEqual(h.env.launched.count, 1)
            XCTAssertTrue(h.observations("text.snapshot").isEmpty)
        }
    }

    func testBackoffRespectsSamplingIntervalAndNoReadStartsWhileTransportIsNotReady() throws {
        let h = try TimeoutRecoveryHarness(sampleIntervalMs: 3_000)
        h.expire(try XCTUnwrap(h.engine.outstanding))
        h.engine.workerDirty()
        h.tick(after: 2_999)
        XCTAssertEqual(h.env.launched.count, 1)
        h.env.ready = false
        h.tick(after: 1)
        XCTAssertEqual(h.reason, .string("read-timeout-unrecoverable"))
        h.control("resume")
        h.tick(after: 50)
        XCTAssertEqual(h.engine.state, "paused", "Even owner Resume cannot overlap an unready transport")
        XCTAssertEqual(h.env.launched.count, 1)
        h.env.ready = true
        h.tick(after: 3_000)
        XCTAssertEqual(h.engine.state, "paused")
        XCTAssertEqual(h.env.launched.count, 1)
        XCTAssertNil(h.engine.outstanding)
        h.control("resume")
        h.tick(after: 50)
        XCTAssertEqual(h.engine.state, "running", "Only the owner's explicit resume lifts this pause")
        XCTAssertEqual(h.env.launched.count, 2)
    }

    func testThreeRecoveriesPerSlidingWindowDoNotResetOnSuccessOrAppSwitch() throws {
        let h = try TimeoutRecoveryHarness()
        for (attempt, delay): (Int, Int64) in [(1, 1_000), (2, 2_000), (3, 4_000)] {
            let expired = try XCTUnwrap(h.engine.outstanding)
            h.expire(expired)
            let count = h.env.launched.count
            h.engine.workerDirty()
            if attempt == 2 {
                let count = h.frames.count
                h.engine.applicationEvent(.init(application: h.app, eventTimeMs: h.clock.unixMs))
                XCTAssertEqual(h.frames.count, count, "No context is published during the recovery pause")
            }
            h.tick(after: delay - 1)
            XCTAssertEqual(h.env.launched.count, count)
            h.tick(after: 1)
            XCTAssertEqual(h.env.launched.count, count + 1)
            let retry = try XCTUnwrap(h.engine.outstanding)
            if attempt == 1 {
                h.engine.complete(h.reply(retry))
                XCTAssertEqual(h.observations("text.snapshot").count, 1)
                h.engine.applicationEvent(.init(application: .init(applicationId: "test.allowed", processId: 99,
                    processStartTime: "synthetic-other-birth"), eventTimeMs: h.clock.unixMs))
                h.tick(after: 50)
                XCTAssertEqual(h.engine.outstanding?.hint?.application.processId, 99)
            } else if attempt == 2 {
                h.engine.complete(h.reply(retry))
                h.tick(after: 1_000)
            }
        }
        h.expire(try XCTUnwrap(h.engine.outstanding))
        XCTAssertEqual(h.reason, .string("read-timeout-exhausted"))
        let count = h.env.launched.count
        h.engine.desktopChanged(.unlocked, accessibility: true)
        h.engine.workerDirty()
        for _ in 0..<3 { h.control("heartbeat"); h.tick(after: 23_000) }
        XCTAssertEqual(h.engine.state, "paused")
        XCTAssertEqual(h.reason, .string("read-timeout-exhausted"), "Aging out must not clear a latched pause")
        XCTAssertEqual(h.env.launched.count, count)
        XCTAssertEqual(h.stateFrames.filter { $0["reason"] == .string("read-timeout-recovered") }.count, 3)
    }

    func testSlidingWindowExpiresOnlyOlderRecoveryAttempts() throws {
        let h = try TimeoutRecoveryHarness()
        for (pause, delay): (Int64, Int64) in [(20_000, 1_000), (20_000, 2_000), (13_000, 4_000)] {
            h.expire(try XCTUnwrap(h.engine.outstanding))
            h.tick(after: delay)
            h.engine.complete(h.reply(try XCTUnwrap(h.engine.outstanding)))
            h.clock.advance(pause)
            h.control("heartbeat")
            h.tick()
        }
        // The first recovery has aged out; the next two have not.
        h.expire(try XCTUnwrap(h.engine.outstanding))
        let count = h.env.launched.count
        h.tick(after: 4_000)
        XCTAssertEqual(h.env.launched.count, count + 1)
        h.expire(try XCTUnwrap(h.engine.outstanding))
        XCTAssertEqual(h.reason, .string("read-timeout-exhausted"), "Expiry must not reset the whole window")
    }

    func testRecoveryUsesFreshDesktopPermissionPrivacyAndListenerGates() throws {
        let denials: [(String, (TimeoutRecoveryEnvironment) -> Void)] = [
            ("screen-locked", { $0.desktop = .locked; $0.desktopReason = "screen-locked" }),
            ("desktop-unavailable", { $0.desktop = .unknown }),
            ("permission-denied", { $0.accessibility = false }),
            ("secure-input-active", { $0.secureInputBlocked = true }),
            ("input-monitoring-required", { $0.inputPermission = false }),
            ("input-monitoring-disabled", { $0.coarseHealthy = false }),
        ]
        for (reason, deny) in denials {
            let h = try TimeoutRecoveryHarness(inputActivity: true)
            h.expire(try XCTUnwrap(h.engine.outstanding))
            let tapBegins = h.env.coarseBegins
            deny(h.env) // Without an intervening desktop- or listener-event callback.
            h.tick(after: 1_000)
            XCTAssertEqual(h.engine.state, "paused", reason)
            XCTAssertEqual(h.reason, .string(reason))
            XCTAssertNil(h.engine.outstanding, reason)
            h.env.desktop = .unlocked; h.env.accessibility = true; h.env.secureInputBlocked = false
            h.env.inputPermission = true; h.env.coarseHealthy = true
            h.engine.desktopChanged(.unlocked, accessibility: true)
            h.tick(after: 3_000)
            XCTAssertEqual(h.engine.state, "paused", reason)
            XCTAssertEqual(h.env.launched.count, 1, reason)
            XCTAssertEqual(h.env.coarseBegins, tapBegins, reason)
        }
    }

    func testPendingRecoveryCannotOutliveOwnerOrObservedFaultBoundary() throws {
        for boundary in ["pause", "stop", "configure", "lock", "secure", "AX revoked", "Input Monitoring revoked", "worker-fault", "coarse-fault", "parent", "lease"] {
            // With inputText alone there is no surviving coarse tap to report revocation.
            let h = try TimeoutRecoveryHarness(inputActivity: boundary != "Input Monitoring revoked",
                                               lease: boundary == "lease" ? 2_000 : 30_000)
            let old = try XCTUnwrap(h.engine.outstanding)
            h.expire(old)
            var expected = "paused"
            switch boundary {
            case "pause": h.control("pause")
            case "stop": h.control("stop"); expected = "stopped"
            case "configure": try h.configure(CapturePolicy(enabled: false), revision: 2); expected = "ready"
            case "lock": h.engine.desktopChanged(.locked, accessibility: false)
            case "secure": h.engine.secureInputDetected()
            case "AX revoked": h.engine.desktopChanged(.unlocked, accessibility: false)
            case "Input Monitoring revoked":
                h.env.inputPermission = false
                h.engine.desktopChanged(.unlocked, accessibility: true)
                h.env.inputPermission = true
            case "worker-fault": h.engine.inputSessionUnavailable("input-monitoring-disabled")
            case "coarse-fault": h.engine.inputActivityUnavailable("input-monitoring-disabled")
            case "parent": h.engine.tick(parentAlive: false); expected = "stopped"
            case "lease": expected = "stopped"
            default: XCTFail("Unhandled boundary")
            }
            h.engine.complete(h.reply(old))
            h.engine.desktopChanged(.unlocked, accessibility: true)
            h.tick(after: 5_000)
            XCTAssertEqual(h.engine.state, expected, boundary)
            XCTAssertEqual(h.env.launched.count, 1, boundary)
            XCTAssertTrue(h.observations("text.snapshot").isEmpty, boundary)
            XCTAssertFalse(h.stateFrames.contains { $0["reason"] == .string("read-timeout-recovered") }, boundary)
        }
    }

    func testFreshValidationCannotOverrunLeaseOrReopenReentrantOwnerPause() throws {
        for leaseExpires in [true, false] {
            let h = try TimeoutRecoveryHarness(lease: leaseExpires ? 2_600 : 30_000)
            h.expire(try XCTUnwrap(h.engine.outstanding))
            h.env.duringValidation = { [weak h] in
                if leaseExpires { h?.clock.advance(100) }
                else { h?.control("pause") }
            }
            h.tick(after: 1_000) // Clock is 2,650 before the gate; the short lease expires at 2,700.
            XCTAssertEqual(h.env.launched.count, 1)
            XCTAssertNil(h.engine.outstanding)
            h.tick()
            XCTAssertEqual(h.engine.state, leaseExpires ? "stopped" : "paused")
            XCTAssertEqual(h.reason, .string(leaseExpires ? "lease-expired" : "user-paused"))
        }
    }

    func testLateCompletionOrGenuineInputFailureNeverEntersTimeoutRecovery() throws {
        for (reason, late): (String?, Bool) in [(nil, true), ("input-monitoring-disabled", false), ("input-monitoring-required", true)] {
            let h = try TimeoutRecoveryHarness()
            let ticket = try XCTUnwrap(h.engine.outstanding)
            var result = h.reply(ticket)
            if let reason {
                result = ReadResult(token: ticket.token, reason: reason, captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
            }
            if late { h.clock.advance(1_500) }
            h.engine.complete(result)
            XCTAssertEqual(h.engine.state, "paused")
            XCTAssertEqual(h.reason, .string(reason ?? "read-timeout-unrecoverable"))
            h.engine.desktopChanged(.unlocked, accessibility: true)
            h.engine.workerDirty()
            h.tick(after: 5_000)
            XCTAssertTrue(h.env.aborted.isEmpty, "A completion or listener failure is not an active hard timeout")
            XCTAssertEqual(h.env.launched.count, 1)
            XCTAssertTrue(h.observations("text.snapshot").isEmpty)
        }
    }
}

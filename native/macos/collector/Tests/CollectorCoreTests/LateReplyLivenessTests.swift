import XCTest
import AccessContract
@testable import CollectorCore

private final class LateReplyEnvironment: CollectorEnvironment {
    var desktop: DesktopStatus = .unlocked
    var accessibility = true
    var secureInputBlocked = false
    var launched: [ReadTicket] = []
    var cancelCalls = 0
    var validationCalls = 0
    var clearInputCalls = 0
    func clearInputActivity() { clearInputCalls += 1 }
    var validation: (() -> Void)?
    func beginMonitoring() -> (desktop: DesktopStatus, accessibility: Bool) { (desktop, accessibility) }
    func validateBeforeAccept() -> (desktop: DesktopStatus, accessibility: Bool) {
        validationCalls += 1; validation?()
        return (desktop, accessibility)
    }
    func endMonitoring() {}
    func launch(_ ticket: ReadTicket) { launched.append(ticket) }
    func cancelRead() { cancelCalls += 1 }
}

private final class LateReplyHarness {
    let clock = FakeClock()
    let environment = LateReplyEnvironment()
    let engine: CollectorEngine
    var frames: [JSONValue] = []
    init(inputText: Bool = false, lease: Int = 30_000, readTimeoutMs: Int = 200) {
        engine = CollectorEngine(ownerId: "owner", instanceId: "instance", deviceId: "device", osSessionId: "session", desktopId: "desktop", fixture: true, environment: environment, clock: clock)
        engine.emit = { [weak self] in self?.frames.append($0) }
        configure(inputText: inputText, readTimeoutMs: readTimeoutMs)
        control("start", lease: lease)
        clock.advance(51)
        engine.tick()
    }
    func configure(inputText: Bool = false, revision: Int64 = 1, readTimeoutMs: Int = 200) {
        let policy = CapturePolicy(readTimeoutMs: readTimeoutMs, inputText: inputText)
        engine.receive(.object(["protocolVersion": j(1), "type": .string("configure"), "requestId": .string("config"), "ownerId": .string("owner"), "instanceId": .string("instance"), "policyRevision": j(revision), "policy": try! JSONValue.parse(JSONEncoder().encode(policy))]))
    }
    func control(_ command: String, lease: Int = 30_000) {
        engine.receive(.object(["protocolVersion": j(1), "type": .string("control"), "requestId": .string(command), "ownerId": .string("owner"), "instanceId": .string("instance"), "policyRevision": j(engine.policyRevision), "command": .string(command), "leaseDurationMs": j(lease)]))
    }
    func result(_ ticket: ReadTicket) -> ReadResult {
        // Deliberately contains a new app identity; rejection must not adopt it.
        ReadResult(token: ticket.token, application: ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "late-birth"), text: TextRead(text: "late synthetic text", source: "ax.range", totalLength: 19, complete: true, missingReasons: []), captureStartMs: clock.unixMs, captureEndMs: clock.unixMs)
    }
    var content: [JSONValue] { frames.filter { ["text.snapshot", "surface.snapshot", "selection.snapshot", "input.text"].contains($0["payload"]?["kind"]?.stringValue ?? "") } }
    var gaps: [JSONValue] { frames.filter { $0["payload"]?["kind"] == .string("gap") } }
}

final class LateReplyLivenessTests: XCTestCase {
    func testSecureInputObservedDuringSlowFreshGateCannotHideReadDeadlineFailure() throws {
        let h = LateReplyHarness(inputText: true)
        let ticket = try XCTUnwrap(h.engine.outstanding)
        h.environment.validation = { h.environment.secureInputBlocked = true; h.clock.advance(201) }
        h.engine.complete(h.result(ticket))
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.frames.last?["reason"], .string("read-timeout-unrecoverable"))
        XCTAssertTrue(h.content.isEmpty)
        h.environment.secureInputBlocked = false; h.environment.validation = nil
        h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "paused", "An expired completion is not an eligible owned-worker timeout")
    }
    func testNegativeFocusReplySkipsOnlyEvidenceAdmissionAndDoesNotManufactureInputTimeout() throws {
        let h = LateReplyHarness(inputText: true, readTimeoutMs: 1500)
        h.engine.complete(h.result(try XCTUnwrap(h.engine.outstanding)))
        XCTAssertEqual(h.content.count, 1)
        h.clock.advance(150); h.engine.tick()
        let ticket = try XCTUnwrap(h.engine.outstanding)
        h.clock.advance(970)
        let calls = h.environment.validationCalls
        h.environment.validation = { h.clock.advance(2360) }
        func negative(_ ticket: ReadTicket) -> ReadResult {
            var value = ReadResult(token: ticket.token, reason: "focus-unavailable", diagnostic: .init(code: .focusedFieldUnavailable), captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
            value.surfaceFailure = .anchorUnavailable
            value.diagnosticApplication = .init(applicationId: "test.allowed", processId: 42, processStartTime: "this-read")
            return value
        }
        let cleared = h.environment.clearInputCalls
        h.engine.complete(negative(ticket))
        XCTAssertEqual(h.environment.validationCalls, calls)
        XCTAssertEqual(h.engine.state, "running"); XCTAssertEqual(h.content.count, 1)
        XCTAssertGreaterThan(h.environment.clearInputCalls, cleared)
        XCTAssertEqual(h.gaps.count, 1)
        XCTAssertEqual(h.gaps.first?["payload"]?["diagnostic"]?["code"], .string("focused-field-unavailable"))
        XCTAssertEqual(h.gaps.first?["payload"]?["providerApplicationId"], .string("test.allowed"))
        XCTAssertEqual(h.gaps.first?["target"]?["kind"], .string("unresolved"))
        let stamp = h.engine.stamp
        let contexts = h.frames.filter { $0["payload"]?["kind"] == .string("context.changed") }.count
        h.clock.advance(150); h.engine.tick()
        let retry = try XCTUnwrap(h.engine.outstanding)
        h.engine.complete(negative(retry))
        XCTAssertEqual(h.engine.stamp, stamp)
        XCTAssertEqual(h.frames.filter { $0["payload"]?["kind"] == .string("context.changed") }.count, contexts)
        XCTAssertEqual(h.gaps.count, 1) // One unchanged unavailable state, not repeated failed-poll events.
        XCTAssertEqual(h.environment.validationCalls, calls) // Repetition cannot add a blocking content-admission gate.
        h.environment.validation = nil
        h.clock.advance(150); h.engine.tick()
        h.engine.complete(h.result(try XCTUnwrap(h.engine.outstanding)))
        XCTAssertEqual(h.content.count, 2) // Negative reads reset accepted snapshot baselines.
        let validator = try ContractValidator()
        for frame in h.frames { XCTAssertNoThrow(try validator.encodeFrame(frame)) }
    }

    func testDiagnosticProviderNeverAttributesExcludedHintMismatchedOrOldReplies() throws {
        for id in ["com.1password.1password", "com.apple.Safari", "com.google.Chrome"] {
            let h = LateReplyHarness(), ticket = try XCTUnwrap(h.engine.outstanding)
            var value = ReadResult(token: ticket.token, reason: "focus-unavailable", diagnostic: .init(code: .focusedFieldUnavailable), captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
            value.diagnosticApplication = .init(applicationId: id, processId: 42, processStartTime: "birth")
            h.engine.complete(value)
            XCTAssertEqual(h.gaps.count, 1); XCTAssertNil(h.gaps.first?["payload"]?["providerApplicationId"])
            XCTAssertTrue(h.content.isEmpty)
        }
        let h = LateReplyHarness(), old = try XCTUnwrap(h.engine.outstanding)
        let hinted = ApplicationIdentity(applicationId: "test.allowed", processId: 99, processStartTime: "hint-birth")
        h.engine.applicationEvent(.init(application: hinted, eventTimeMs: h.clock.unixMs))
        let before = h.frames.count
        var oldReply = ReadResult(token: old.token, reason: "focus-unavailable", diagnostic: .init(code: .focusedFieldUnavailable), captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
        oldReply.diagnosticApplication = hinted
        h.engine.complete(oldReply); XCTAssertEqual(h.frames.count, before)
        h.clock.advance(51); h.engine.tick()
        let ticket = try XCTUnwrap(h.engine.outstanding)
        XCTAssertEqual(ticket.hint?.application, hinted)
        var mismatch = oldReply; mismatch.token = ticket.token
        mismatch.diagnosticApplication = .init(applicationId: "test.allowed", processId: 42, processStartTime: "other-birth")
        h.engine.complete(mismatch)
        XCTAssertNil(h.gaps.last?["payload"]?["providerApplicationId"]); XCTAssertTrue(h.content.isEmpty)
    }

    func testNegativeLabelCannotSkipFreshGateWhenAnyContentOrIdentityIsPresent() throws {
        for addition in ["text", "surface", "selection", "input", "inputGap", "application", "identity", "focusAbsent", "failure"] {
            let h = LateReplyHarness(inputText: true), ticket = try XCTUnwrap(h.engine.outstanding)
            var value = ReadResult(token: ticket.token, reason: "focus-unavailable", diagnostic: .init(code: .focusedFieldUnavailable), captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
            switch addition {
            case "text": value.text = h.result(ticket).text
            case "application": value.application = h.result(ticket).application
            case "identity": value.sessionIdentity = .init(sessionId: "worker", windowId: "window", nodeId: "node", surfaceId: "surface", windowGeneration: 1, focusGeneration: 1)
            case "focusAbsent": value.focusAbsent = true
            case "failure": value.surfaceFailure = .securityExcluded
            case "surface": value.surface = SurfaceBaseline().snapshot(surfaceId: "s", scope: "window", nodes: [], complete: false, matchingKnown: true, truncated: false, missingReasons: ["bounded-ax-tree"])
            case "selection": value.selection = .init(text: "", source: "ax.range", rangeStart: 0, truncated: false, missingReasons: ["selection-only"])
            case "input":
                let app = ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "birth")
                let context = InputTextContext(target: .init(application: app, deviceId: "device", osSessionId: "session", desktopId: "desktop", windowId: "window", windowGeneration: 1), surfaceId: "surface", captureEpoch: ticket.captureEpoch, foregroundGeneration: try XCTUnwrap(ticket.foregroundGeneration), focusGeneration: try XCTUnwrap(ticket.focusGeneration), policyRevision: 1, privateState: .normal)
                var input = InputTextAccumulator()
                input.add(.init(context: context, eventKind: .text, text: "synthetic", modifiers: [], callbackTimeMs: h.clock.unixMs), source: .fixture)
                value.inputRecords = [try XCTUnwrap(input.takeSegment(approvedContext: context))]
            default: value.inputGaps = ["stale"]
            }
            let calls = h.environment.validationCalls
            h.environment.validation = { h.clock.advance(1501) }
            h.engine.complete(value)
            XCTAssertEqual(h.environment.validationCalls, calls + 1, addition)
            XCTAssertEqual(h.engine.state, "paused", addition); XCTAssertTrue(h.content.isEmpty)
        }
    }

    func testAlreadyExpiredNegativeFocusStillLatchesAndPausedReplyCannotRevive() throws {
        let h = LateReplyHarness(inputText: true), ticket = try XCTUnwrap(h.engine.outstanding)
        var value = ReadResult(token: ticket.token, reason: "focus-unavailable", diagnostic: .init(code: .focusedFieldUnavailable), captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
        value.surfaceFailure = .anchorUnavailable
        h.clock.advance(ticket.deadlineMonotonicMs - h.clock.monotonicMs)
        h.engine.complete(value)
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertTrue(h.content.isEmpty)
        let count = h.frames.count
        h.engine.complete(value); h.clock.advance(1000); h.engine.tick()
        XCTAssertEqual(h.frames.count, count); XCTAssertEqual(h.environment.launched.count, 1)
    }

    func testExpiredCurrentReplyRejectsContentAndReconcilesWithoutObserver() throws {
        for lateness: Int64 in [0, 1] {
            let h = LateReplyHarness()
            let current = try XCTUnwrap(h.engine.outstanding)
            h.clock.advance(current.deadlineMonotonicMs - h.clock.monotonicMs + lateness)
            let stamp = h.engine.stamp, cancellations = h.environment.cancelCalls
            h.engine.complete(h.result(current)) // No timeout tick/observer runs first.
            XCTAssertTrue(h.content.isEmpty)
            XCTAssertNil(h.engine.outstanding)
            XCTAssertEqual(h.engine.state, "running")
            XCTAssertEqual(h.engine.stamp, stamp)
            XCTAssertGreaterThan(h.environment.cancelCalls, cancellations)
            XCTAssertEqual(h.gaps.last?["payload"]?["diagnostic"]?["code"], .string("read-deadline"))
            XCTAssertEqual(h.gaps.last?["target"]?["kind"], .string("unresolved"))
            h.clock.advance(149); h.engine.tick()
            XCTAssertEqual(h.environment.launched.count, 1)
            h.clock.advance(1); h.engine.tick()
            XCTAssertEqual(h.environment.launched.count, 2)
            let retry = try XCTUnwrap(h.engine.outstanding)
            XCTAssertNotEqual(retry.token, current.token)
            XCTAssertNil(retry.hint)
            XCTAssertEqual(retry.captureEpoch, current.captureEpoch)
            XCTAssertGreaterThan(retry.deadlineMonotonicMs, h.clock.monotonicMs)
            let validator = try ContractValidator()
            for frame in h.frames { XCTAssertNoThrow(try validator.encodeFrame(frame)) }
        }
    }

    func testReplyJustBeforeDeadlineStillPassesFreshGates() throws {
        let h = LateReplyHarness(), current = try XCTUnwrap(h.engine.outstanding)
        h.clock.advance(current.deadlineMonotonicMs - h.clock.monotonicMs - 1)
        h.engine.complete(h.result(current))
        XCTAssertEqual(h.content.count, 1)
        XCTAssertTrue(h.gaps.isEmpty)
        h.clock.advance(150); h.engine.tick()
        XCTAssertEqual(h.environment.launched.count, 2)
    }

    func testFreshValidationCrossingDeadlineRejectsAndReconciles() throws {
        let h = LateReplyHarness(), current = try XCTUnwrap(h.engine.outstanding)
        h.clock.advance(current.deadlineMonotonicMs - h.clock.monotonicMs - 1)
        h.environment.validation = { h.clock.advance(1) }
        h.engine.complete(h.result(current))
        XCTAssertTrue(h.content.isEmpty)
        XCTAssertEqual(h.gaps.last?["payload"]?["diagnostic"]?["code"], .string("read-deadline"))
        h.environment.validation = nil
        h.clock.advance(150); h.engine.tick()
        XCTAssertEqual(h.environment.launched.count, 2)
    }

    func testExpiredInputReplyUsesStickyPauseInsteadOfAutomaticRetry() throws {
        let h = LateReplyHarness(inputText: true), current = try XCTUnwrap(h.engine.outstanding)
        h.clock.advance(current.deadlineMonotonicMs - h.clock.monotonicMs)
        h.engine.complete(h.result(current))
        XCTAssertTrue(h.content.isEmpty)
        XCTAssertEqual(h.engine.state, "paused")
        h.engine.workerDirty()
        h.engine.applicationEvent(.init(application: .init(applicationId: "test.allowed", processId: 43, processStartTime: "new"), eventTimeMs: h.clock.unixMs))
        h.engine.desktopChanged(.unlocked, accessibility: true)
        h.clock.advance(1000); h.engine.tick(); h.control("start")
        XCTAssertEqual(h.engine.state, "paused")
        XCTAssertEqual(h.environment.launched.count, 1)
    }

    func testPauseStopAndPolicyBoundaryNeverReviveLateReply() throws {
        for action in ["pause", "stop", "configure"] {
            let h = LateReplyHarness(), current = try XCTUnwrap(h.engine.outstanding)
            if action == "configure" { h.configure(revision: 2) } else { h.control(action) }
            let state = h.engine.state, count = h.frames.count
            h.clock.advance(201); h.engine.complete(h.result(current))
            h.clock.advance(1000); h.engine.tick()
            XCTAssertEqual(h.engine.state, state)
            XCTAssertEqual(h.environment.launched.count, 1)
            XCTAssertTrue(h.content.isEmpty)
            XCTAssertEqual(h.frames.count, count)
        }
    }

    func testApplicationBoundaryKeepsOnlyNewHintAndSchedule() throws {
        let h = LateReplyHarness(), current = try XCTUnwrap(h.engine.outstanding)
        let newApp = ApplicationIdentity(applicationId: "test.allowed", processId: 99, processStartTime: "new-birth")
        h.engine.applicationEvent(.init(application: newApp, eventTimeMs: h.clock.unixMs))
        let stamp = h.engine.stamp, frames = h.frames.count
        h.clock.advance(201); h.engine.complete(h.result(current))
        XCTAssertEqual(h.engine.stamp, stamp)
        XCTAssertEqual(h.frames.count, frames)
        h.engine.tick()
        XCTAssertEqual(h.environment.launched.count, 2)
        XCTAssertEqual(h.engine.outstanding?.hint?.application, newApp)
        XCTAssertTrue(h.content.isEmpty)
    }

    func testExpiredLeaseCannotBeRearmedByCompletion() throws {
        let h = LateReplyHarness(lease: 200), current = try XCTUnwrap(h.engine.outstanding)
        h.clock.advance(150) // Lease expired; this read's own deadline is still ahead.
        h.engine.complete(h.result(current))
        XCTAssertTrue(h.content.isEmpty)
        h.engine.tick()
        XCTAssertEqual(h.engine.state, "stopped")
        XCTAssertEqual(h.environment.launched.count, 1)
    }

    func testValidationCrossingLeaseOrPolicyBoundaryDoesNotAcceptOrRearm() throws {
        for boundary in ["lease", "policy"] {
            let h = LateReplyHarness(lease: boundary == "lease" ? 200 : 30_000), current = try XCTUnwrap(h.engine.outstanding)
            h.environment.validation = {
                if boundary == "lease" { h.clock.advance(150) }
                else { h.configure(revision: 2) }
            }
            h.engine.complete(h.result(current))
            h.environment.validation = nil
            XCTAssertTrue(h.content.isEmpty)
            h.clock.advance(150); h.engine.tick()
            XCTAssertEqual(h.environment.launched.count, 1)
            XCTAssertEqual(h.engine.state, boundary == "lease" ? "stopped" : "ready")
        }
    }

    func testExpiredReplyCannotRearmAfterFreshDesktopOrPermissionFailure() throws {
        for denied in ["desktop", "permission"] {
            let h = LateReplyHarness(), current = try XCTUnwrap(h.engine.outstanding)
            h.clock.advance(current.deadlineMonotonicMs - h.clock.monotonicMs)
            if denied == "desktop" { h.environment.desktop = .locked } else { h.environment.accessibility = false }
            h.engine.complete(h.result(current))
            XCTAssertEqual(h.engine.state, "paused")
            XCTAssertTrue(h.content.isEmpty)
            h.clock.advance(1000); h.engine.tick()
            XCTAssertEqual(h.environment.launched.count, 1)
        }
    }
}

import Foundation
import XCTest
import HistoryContract
@testable import CollectorCore

final class SubmitFastReadEngineTests: XCTestCase {
    private func start(
        captureScope: String = "window",
        sampleIntervalMs: Int? = 1_000,
        debounceMs: Int = 150,
        maxWaitMs: Int = 500,
        inputText: Bool = true
    ) throws -> Harness {
        let h = Harness(fixture: false)
        let policy = CapturePolicy(
            sampleIntervalMs: sampleIntervalMs,
            debounceMs: debounceMs,
            maxWaitMs: maxWaitMs,
            captureScope: captureScope,
            inputText: inputText,
            selectionCapture: true
        )
        h.engine.receive(.object([
            "protocolVersion": j(1),
            "type": .string("configure"),
            "requestId": .string("config"),
            "ownerId": .string("owner"),
            "instanceId": .string("instance"),
            "policyRevision": j(1),
            "policy": try JSONValue.parse(JSONEncoder().encode(policy)),
        ]))
        h.control("start", lease: 30_000)
        h.clock.advance(Int64(maxWaitMs) + 1)
        h.engine.tick()
        XCTAssertEqual(h.env.launched.count, 1)
        return h
    }

    private func identity() -> WorkerSurfaceIdentity {
        WorkerSurfaceIdentity(
            sessionId: "worker",
            windowId: "window-1",
            nodeId: "node-1",
            surfaceId: "surface-1",
            windowGeneration: 1,
            focusGeneration: 1
        )
    }

    private func fullResult(_ h: Harness, ticket: ReadTicket, text: String, surfaceText: String, baseline: SurfaceBaseline) -> ReadResult {
        var result = ReadResult(
            token: ticket.token,
            application: ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "birth"),
            text: TextRead(text: text, source: "ax.range", totalLength: text.utf16.count, complete: true, missingReasons: []),
            captureStartMs: h.clock.unixMs,
            captureEndMs: h.clock.unixMs
        )
        let id = identity()
        result.sessionIdentity = id
        result.surface = baseline.snapshot(
            surfaceId: id.surfaceId,
            scope: "window",
            nodes: [
                SurfaceNodeRead(id: "root", role: "container", observedAtMs: h.clock.unixMs, axRole: "AXWindow", focused: false),
                SurfaceNodeRead(id: "leaf", parentId: "root", role: "text", text: surfaceText, observedAtMs: h.clock.unixMs, axRole: "AXStaticText", focused: false),
            ],
            complete: true,
            matchingKnown: true,
            truncated: false,
            missingReasons: []
        )
        return result
    }

    private func surfaces(_ h: Harness) -> [JSONValue] {
        h.frames.filter { $0["payload"]?["kind"] == .string("surface.snapshot") }
    }

    private func gaps(_ h: Harness) -> [JSONValue] {
        h.frames.filter { $0["payload"]?["kind"] == .string("gap") }
    }

    func testWorkerSubmitDirtySchedulesImmediateFastReadPreservesSurfaceStateAndSchedules200msFullFollowUp() throws {
        let h = try start()
        let baseline = SurfaceBaseline()
        let first = try XCTUnwrap(h.env.launched.last)
        XCTAssertNil(first.focusedFastOnly)
        h.engine.complete(fullResult(h, ticket: first, text: "draft", surfaceText: "old bubble", baseline: baseline))
        XCTAssertEqual(surfaces(h).count, 1)
        XCTAssertEqual(h.textFrames.count, 1)

        // Advance only 10ms (far below 150ms debounce and 1000ms reconciliation spacing).
        h.clock.advance(10)
        h.engine.workerSubmitDirty()
        h.engine.tick()
        XCTAssertEqual(h.env.launched.count, 2, "workerSubmitDirty must fire immediately without debounce delay")
        let fast = try XCTUnwrap(h.env.launched.last)
        XCTAssertEqual(fast.focusedFastOnly, true)
        XCTAssertEqual(h.engine.outstanding, fast)

        // Fast read omits surface and selection; must not emit surfaceFailure or clear lastSurfaceState.
        var fastResult = ReadResult(
            token: fast.token,
            application: ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "birth"),
            text: TextRead(text: "draft sent", source: "ax.range", totalLength: 10, complete: true, missingReasons: []),
            captureStartMs: h.clock.unixMs,
            captureEndMs: h.clock.unixMs
        )
        fastResult.sessionIdentity = identity()
        fastResult.surfaceFailure = .providerUnavailable // Must be ignored for focusedFastOnly tickets.
        h.engine.complete(fastResult)
        XCTAssertEqual(h.textFrames.count, 2)
        XCTAssertTrue(gaps(h).isEmpty, "Omitted surface on focusedFastOnly must not emit a surface failure gap")

        // Follow-up full read must not fire before 200ms, and must fire at 200ms.
        h.clock.advance(199)
        h.engine.tick()
        XCTAssertEqual(h.env.launched.count, 2)
        h.clock.advance(1)
        h.engine.tick()
        XCTAssertEqual(h.env.launched.count, 3)
        let followUp = try XCTUnwrap(h.env.launched.last)
        XCTAssertNil(followUp.focusedFastOnly)

        // Identical surface in the follow-up proves lastSurfaceState was preserved across the fast read.
        h.engine.complete(fullResult(h, ticket: followUp, text: "draft sent", surfaceText: "old bubble", baseline: baseline))
        XCTAssertEqual(surfaces(h).count, 1, "Unchanged surface must stay deduplicated because fast read preserved lastSurfaceState")

        // When the 200ms follow-up immediately carries a new chat bubble after a fast read,
        // lastSurfaceRevision is preserved so the diff chains cleanly onto the prior revision.
        let h2 = try start()
        let baseline2 = SurfaceBaseline()
        let first2 = try XCTUnwrap(h2.env.launched.last)
        h2.engine.complete(fullResult(h2, ticket: first2, text: "draft", surfaceText: "old bubble", baseline: baseline2))
        XCTAssertEqual(surfaces(h2).count, 1)

        h2.clock.advance(10)
        h2.engine.workerSubmitDirty()
        h2.engine.tick()
        let fast2 = try XCTUnwrap(h2.env.launched.last)
        XCTAssertEqual(fast2.focusedFastOnly, true)
        var fastResult2 = ReadResult(
            token: fast2.token,
            application: ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "birth"),
            text: TextRead(text: "", source: "ax.range", totalLength: 0, complete: true, missingReasons: []),
            captureStartMs: h2.clock.unixMs,
            captureEndMs: h2.clock.unixMs
        )
        fastResult2.sessionIdentity = identity()
        h2.engine.complete(fastResult2)

        h2.clock.advance(200)
        h2.engine.tick()
        let followUp2 = try XCTUnwrap(h2.env.launched.last)
        XCTAssertNil(followUp2.focusedFastOnly)
        h2.engine.complete(fullResult(h2, ticket: followUp2, text: "", surfaceText: "new bubble", baseline: baseline2))
        XCTAssertEqual(surfaces(h2).count, 2)
        XCTAssertEqual(surfaces(h2).last?["payload"]?["mode"], .string("diff"))
        XCTAssertEqual(surfaces(h2).last?["payload"]?["baseRevision"], j(1))
    }

    func testWorkerSubmitDirtyQueuesBehindInFlightReadWithoutConcurrentOverlap() throws {
        let h = try start()
        let baseline = SurfaceBaseline()
        let inFlight = try XCTUnwrap(h.env.launched.last)
        XCTAssertEqual(h.engine.outstanding, inFlight)

        // Submit arrives while the first read is still in flight.
        h.engine.workerSubmitDirty()
        h.engine.tick()
        XCTAssertEqual(h.env.launched.count, 1, "Must never launch a concurrent second read")
        XCTAssertEqual(h.engine.outstanding, inFlight)

        // Completing the in-flight read immediately schedules the queued fast read.
        h.engine.complete(fullResult(h, ticket: inFlight, text: "typing", surfaceText: "chat", baseline: baseline))
        XCTAssertNil(h.engine.outstanding)
        h.engine.tick()
        XCTAssertEqual(h.env.launched.count, 2)
        let fast = try XCTUnwrap(h.env.launched.last)
        XCTAssertEqual(fast.focusedFastOnly, true)
    }

    func testPauseAndBoundaryClearPendingFastReadState() throws {
        let h = try start()
        let inFlight = try XCTUnwrap(h.env.launched.last)
        h.engine.workerSubmitDirty() // Sets pendingSubmitFastRead while in flight.

        // Pause clears pendingSubmitFastRead and nextReadFastOnly.
        h.control("pause", lease: 30_000)
        h.engine.workerSubmitDirty() // Ignored while paused.
        h.control("resume", lease: 30_000)
        h.clock.advance(501)
        h.engine.tick()
        XCTAssertEqual(h.env.launched.count, 2)
        XCTAssertNil(h.env.launched.last?.focusedFastOnly, "Resumed read after pause must be a normal full read")
        XCTAssertNotEqual(h.env.launched.last?.token, inFlight.token)

        // App boundary also clears queued fast read state.
        h.engine.workerSubmitDirty()
        h.engine.applicationEvent(SourceHint(
            application: ApplicationIdentity(applicationId: "test.allowed", processId: 99, processStartTime: "birth-2"),
            eventTimeMs: h.clock.unixMs
        ))
        h.clock.advance(501)
        h.engine.tick()
        XCTAssertEqual(h.env.launched.count, 3)
        XCTAssertNil(h.env.launched.last?.focusedFastOnly, "Read after application boundary must be a normal full read")
    }
}

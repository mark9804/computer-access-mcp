import Foundation
import XCTest
import HistoryContract
@testable import CollectorCore

/// Synthetic private worker replies exercise the actual control-engine path.
/// No AX objects, desktop reads, existing History, or Keychain are involved.
final class SurfaceFailureEngineTests: XCTestCase {
    private func start(scope: String? = "window") throws -> Harness {
        let h = Harness(fixture: false)
        let policy = CapturePolicy(captureScope: scope)
        h.engine.receive(.object([
            "protocolVersion": j(1), "type": .string("configure"), "requestId": .string("config"),
            "ownerId": .string("owner"), "instanceId": .string("instance"), "policyRevision": j(1),
            "policy": try JSONValue.parse(JSONEncoder().encode(policy)),
        ]))
        h.control("start", lease: 30000)
        h.clock.advance(51)
        h.engine.tick()
        XCTAssertNotNil(h.env.launched.last)
        return h
    }

    private func gaps(_ h: Harness) -> [JSONValue] {
        h.frames.filter { $0["payload"]?["kind"] == .string("gap") }
    }

    private func surfaceGaps(_ h: Harness) -> [JSONValue] {
        gaps(h).filter { $0["payload"]?["diagnostic"]?["code"]?.stringValue?.hasPrefix("surface-") == true }
    }

    private func surfaces(_ h: Harness) -> [JSONValue] {
        h.frames.filter { $0["payload"]?["kind"] == .string("surface.snapshot") }
    }

    private func identity() -> WorkerSurfaceIdentity {
        WorkerSurfaceIdentity(sessionId: "worker", windowId: "window", nodeId: "focused", surfaceId: "surface",
            windowGeneration: 1, focusGeneration: 1)
    }

    private func withPartialSurface(_ h: Harness, reason: String = "geometry-unavailable") throws -> ReadResult {
        var worker = h.goodResult(try XCTUnwrap(h.env.launched.last))
        worker.sessionIdentity = identity()
        worker.surface = SurfaceBaseline().snapshot(surfaceId: "surface", scope: "window", nodes: [
            SurfaceNodeRead(id: "leaf", role: "text", text: "synthetic retained surface", observedAtMs: h.clock.unixMs,
                axRole: "AXStaticText", focused: false),
        ], complete: false, matchingKnown: true, truncated: false, missingReasons: [reason])
        return worker
    }

    private func validateWire(_ h: Harness) throws {
        let validator = try ContractValidator()
        for frame in h.frames {
            XCTAssertNoThrow(try validator.encodeFrame(frame))
            XCTAssertNil(frame["surfaceFailure"])
            XCTAssertNil(frame["payload"]?["surfaceFailure"])
        }
    }

    func testFocusedSuccessStillEmitsOneIndependentSurfaceFailure() throws {
        for scope in ["region", "window"] {
            let h = try start(scope: scope)
            var worker = h.goodResult(try XCTUnwrap(h.env.launched.last))
            worker.surfaceFailure = .providerUnavailable
            h.engine.complete(worker)
            XCTAssertEqual(h.textFrames.count, 1)
            XCTAssertEqual(surfaceGaps(h).count, 1)
            XCTAssertEqual(gaps(h).count, 1)
            XCTAssertTrue(surfaces(h).isEmpty)
            XCTAssertEqual(gaps(h).first?["payload"]?["diagnostic"]?["code"], .string("surface-provider-unavailable"))
            try validateWire(h)
        }
    }

    func testSurfaceFailuresUseClosedCodeAndExactGapReason() throws {
        let cases: [(SurfaceReadFailure, String, String)] = [
            (.notStartedBudget, "surface-not-started-budget", "budget"),
            (.callBudget, "surface-call-budget", "budget"),
            (.timeBudget, "surface-time-budget", "timeout"),
            (.anchorUnavailable, "surface-anchor-unavailable", "read-error"),
            (.boundaryUnverified, "surface-boundary-unverified", "stale"),
            (.boundaryMismatch, "surface-boundary-mismatch", "stale"),
            (.boundaryAXFailed, "surface-boundary-ax-failed", "read-error"),
            (.boundaryIncomplete, "surface-boundary-incomplete", "read-error"),
            (.securityExcluded, "surface-security-excluded", "policy-boundary"),
            (.providerUnavailable, "surface-provider-unavailable", "read-error"),
        ]
        for (failure, code, reason) in cases {
            let h = try start()
            var worker = h.goodResult(try XCTUnwrap(h.env.launched.last))
            worker.surfaceFailure = failure
            h.engine.complete(worker)
            let frame = try XCTUnwrap(surfaceGaps(h).first)
            XCTAssertEqual(frame["payload"]?["reason"], .string(reason))
            XCTAssertEqual(frame["payload"]?["count"], j(1))
            XCTAssertEqual(frame["payload"]?["diagnostic"]?["code"], .string(code))
            XCTAssertNil(frame["payload"]?["diagnostic"]?["role"])
            XCTAssertEqual(h.textFrames.count, 1)
            try validateWire(h)
        }
    }

    func testWholeSampleFailurePreservesBroadAndObservedSurfaceDiagnosticsOnly() throws {
        let h = try start()
        let ticket = try XCTUnwrap(h.env.launched.last)
        var worker = ReadResult(token: ticket.token, reason: "stale", diagnostic: .init(code: .readDeadline),
            captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
        worker.surfaceFailure = .boundaryUnverified
        h.engine.complete(worker)
        XCTAssertEqual(gaps(h).count, 2)
        XCTAssertEqual(gaps(h).map { $0["payload"]?["diagnostic"]?["code"] }, [
            .string("read-deadline"), .string("surface-boundary-unverified"),
        ])
        XCTAssertEqual(gaps(h).map { $0["payload"]?["reason"] }, [.string("stale"), .string("stale")])
        XCTAssertTrue(h.textFrames.isEmpty)
        XCTAssertTrue(surfaces(h).isEmpty)
        XCTAssertFalse(h.frames.contains { $0["payload"]?["kind"] == .string("selection.snapshot") })
        XCTAssertFalse(h.frames.contains {
            $0["payload"]?["kind"] == .string("context.changed") && $0["target"]?["kind"] == .string("resolved")
        })
        try validateWire(h)
    }

    func testUnfocusedSurfaceFailureDoesNotEmitDuplicateGap() throws {
        let h = try start()
        let ticket = try XCTUnwrap(h.env.launched.last)
        var worker = ReadResult(token: ticket.token, reason: "stale", diagnostic: .init(code: .surfaceBoundaryMismatch),
            captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
        worker.surfaceFailure = .boundaryMismatch
        h.engine.complete(worker)
        XCTAssertEqual(gaps(h).count, 1)
        XCTAssertEqual(gaps(h).first?["payload"]?["reason"], .string("stale"))
        XCTAssertEqual(gaps(h).first?["payload"]?["diagnostic"]?["code"], .string("surface-boundary-mismatch"))
        try validateWire(h)
    }

    func testSecurityExcludedBrowserOrFieldFailureDoesNotEmitDuplicateSurfaceGap() throws {
        for code: ReadDiagnostic.Code in [.browserExcluded, .secureField] {
            let h = try start()
            let ticket = try XCTUnwrap(h.env.launched.last)
            var worker = ReadResult(token: ticket.token, reason: "policy-boundary", diagnostic: .init(code: code),
                captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
            worker.surfaceFailure = .securityExcluded
            h.engine.complete(worker)
            XCTAssertEqual(gaps(h).count, 1, code.rawValue)
            XCTAssertEqual(gaps(h).first?["payload"]?["reason"], .string("policy-boundary"))
            XCTAssertEqual(gaps(h).first?["payload"]?["diagnostic"]?["code"], .string(code.rawValue))
            try validateWire(h)
        }
    }

    func testFocusedOrOmittedScopeDoesNotReportUnrequestedSurfaceFailure() throws {
        for scope: String? in [nil, "focused"] {
            let h = try start(scope: scope)
            var worker = h.goodResult(try XCTUnwrap(h.env.launched.last))
            worker.surfaceFailure = .notStartedBudget
            h.engine.complete(worker)
            XCTAssertEqual(h.textFrames.count, 1)
            XCTAssertTrue(gaps(h).isEmpty)
            try validateWire(h)
        }
    }

    func testGeometryOnlyPartialSurfaceDoesNotBecomeWholeSurfaceFailure() throws {
        let h = try start()
        let worker = try withPartialSurface(h)
        h.engine.complete(worker)
        XCTAssertEqual(surfaces(h).count, 1)
        XCTAssertEqual(surfaces(h).first?["payload"]?["coverage"]?["status"], .string("partial"))
        XCTAssertNil(surfaces(h).first?["payload"]?["geometry"])
        XCTAssertTrue(surfaceGaps(h).isEmpty)
        try validateWire(h)
    }

    func testReturnedSurfaceSuppressesStaleOptionalFailureMetadata() throws {
        let h = try start()
        var worker = try withPartialSurface(h)
        worker.surfaceFailure = .providerUnavailable
        h.engine.complete(worker)
        XCTAssertEqual(surfaces(h).count, 1)
        XCTAssertTrue(surfaceGaps(h).isEmpty)
        try validateWire(h)
    }

    func testWindowOnlySurfaceCannotClaimSuccessAlongsideAttemptFailure() throws {
        let h = try start()
        var worker = try withPartialSurface(h)
        worker.text = nil
        worker.focusAbsent = true
        worker.diagnostic = .init(code: .focusedFieldUnavailable)
        worker.surfaceFailure = .boundaryUnverified
        XCTAssertFalse(worker.validWindowOnlyChannels(policy: CapturePolicy(captureScope: "window")))
        h.engine.complete(worker)
        XCTAssertTrue(surfaces(h).isEmpty)
        XCTAssertTrue(h.textFrames.isEmpty)
        XCTAssertFalse(h.frames.contains {
            $0["payload"]?["kind"] == .string("context.changed") && $0["target"]?["kind"] == .string("resolved")
        })
    }

    func testWorkerDTOCarriesOnlyClosedSurfaceFailureCode() throws {
        let h = try start()
        for failure in SurfaceReadFailure.allCases {
            var worker = h.goodResult(try XCTUnwrap(h.env.launched.last))
            worker.surfaceFailure = failure
            let data = try JSONEncoder().encode(worker)
            XCTAssertEqual(try JSONValue.parse(data)["surfaceFailure"], .string(failure.rawValue))
            XCTAssertEqual(try JSONDecoder().decode(ReadResult.self, from: data).surfaceFailure, failure)
        }
    }

    func testUnrelatedOldGapIsNotRelabeledAsSurfaceFailure() throws {
        let h = try start()
        let ticket = try XCTUnwrap(h.env.launched.last)
        let worker = ReadResult(token: ticket.token, reason: "read-error", diagnostic: .init(code: .textReadUnavailable),
            captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
        h.engine.complete(worker)
        XCTAssertEqual(gaps(h).count, 1)
        XCTAssertEqual(gaps(h).first?["payload"]?["diagnostic"]?["code"], .string("text-read-unavailable"))
        XCTAssertTrue(surfaceGaps(h).isEmpty)
        try validateWire(h)
    }

    func testPermissionOrDesktopBoundaryDiscardsBufferedSurfaceFailure() throws {
        for locked in [false, true] {
            let h = try start()
            var worker = h.goodResult(try XCTUnwrap(h.env.launched.last))
            worker.surfaceFailure = .securityExcluded
            if locked { h.env.desktop = .locked } else { h.env.accessibility = false }
            h.engine.complete(worker)
            XCTAssertTrue(h.textFrames.isEmpty)
            XCTAssertTrue(surfaces(h).isEmpty)
            XCTAssertTrue(surfaceGaps(h).isEmpty)
        }
    }

    func testExpiredReplyDoesNotPublishBufferedSurfaceFailure() throws {
        let h = try start()
        let ticket = try XCTUnwrap(h.env.launched.last)
        var worker = h.goodResult(ticket)
        worker.surfaceFailure = .callBudget
        h.clock.advance(ticket.deadlineMonotonicMs - h.clock.monotonicMs + 1)
        h.engine.complete(worker)
        XCTAssertTrue(h.textFrames.isEmpty)
        XCTAssertTrue(surfaceGaps(h).isEmpty)
        XCTAssertEqual(gaps(h).last?["payload"]?["diagnostic"]?["code"], .string("read-deadline"))
    }

    func testExcludedApplicationDoesNotEmitAttributedSurfaceFailure() throws {
        let h = try start()
        let ticket = try XCTUnwrap(h.env.launched.last)
        var worker = ReadResult(token: ticket.token, reason: "application-excluded",
            diagnostic: .init(code: .applicationNotAllowed), captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
        worker.surfaceFailure = .providerUnavailable
        h.engine.complete(worker)
        XCTAssertTrue(gaps(h).isEmpty)
        XCTAssertTrue(h.textFrames.isEmpty)
        XCTAssertTrue(surfaces(h).isEmpty)
    }

    func testFocusChangedEmitsSingleGapWithoutDuplicateSurfaceBoundaryMismatch() throws {
        for surfaceFailure in [SurfaceReadFailure.boundaryMismatch, .boundaryUnverified] {
            let h = try start()
            let ticket = try XCTUnwrap(h.env.launched.last)
            var worker = ReadResult(
                token: ticket.token,
                reason: "stale",
                diagnostic: .init(code: .focusChanged),
                captureStartMs: h.clock.unixMs,
                captureEndMs: h.clock.unixMs
            )
            worker.surfaceFailure = surfaceFailure
            h.engine.complete(worker)
            XCTAssertEqual(gaps(h).count, 1)
            XCTAssertEqual(gaps(h).first?["payload"]?["reason"], .string("stale"))
            XCTAssertEqual(gaps(h).first?["payload"]?["diagnostic"]?["code"], .string("focus-changed"))
            XCTAssertTrue(surfaceGaps(h).isEmpty)
            try validateWire(h)
        }
    }
}

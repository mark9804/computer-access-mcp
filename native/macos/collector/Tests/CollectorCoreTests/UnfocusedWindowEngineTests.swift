import Foundation
import XCTest
import AccessContract
@testable import CollectorCore

/// Synthetic worker DTOs exercise the real admission/emission path only. These
/// tests do not create AX objects, read a desktop, or open any retained history.
final class UnfocusedWindowEngineTests: XCTestCase {
    private func start(scope: String? = "window", maxTreeNodes: Int? = nil, inputText: Bool = false, selection: Bool = true) throws -> Harness {
        let h = Harness(fixture: false)
        let policy = CapturePolicy(captureScope: scope, maxTreeNodes: maxTreeNodes, inputText: inputText, selectionCapture: selection)
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

    private func identity(_ generation: Int64 = 1) -> WorkerSurfaceIdentity {
        WorkerSurfaceIdentity(sessionId: "worker", windowId: "window-\(generation)",
            nodeId: "opaque-window-root-\(generation)", surfaceId: "surface-\(generation)",
            windowGeneration: generation, focusGeneration: generation)
    }

    private func result(_ h: Harness, generation: Int64 = 1, includeTextLeaf: Bool = true) throws -> ReadResult {
        let ticket = try XCTUnwrap(h.env.launched.last)
        var result = ReadResult(token: ticket.token,
            application: ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "birth"),
            diagnostic: ReadDiagnostic(code: .focusedFieldUnavailable),
            captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
        let workerIdentity = identity(generation)
        result.sessionIdentity = workerIdentity
        result.focusAbsent = true
        var nodes = [SurfaceNodeRead(id: "root", role: "container", observedAtMs: h.clock.unixMs,
            axRole: "AXWindow", focused: false)]
        if includeTextLeaf {
            nodes.append(SurfaceNodeRead(id: "leaf", parentId: "root", role: "text", text: "synthetic window text",
                observedAtMs: h.clock.unixMs, axRole: "AXStaticText", focused: false))
        }
        result.surface = SurfaceBaseline().snapshot(surfaceId: workerIdentity.surfaceId, scope: "window", nodes: nodes,
            complete: true, matchingKnown: true, truncated: false, missingReasons: [])
        return result
    }

    private func surfaces(_ h: Harness) -> [JSONValue] {
        h.frames.filter { $0["payload"]?["kind"] == .string("surface.snapshot") }
    }

    private func assertNoContent(_ h: Harness, file: StaticString = #filePath, line: UInt = #line) {
        for kind in ["text.snapshot", "surface.snapshot", "selection.snapshot", "input.text"] {
            XCTAssertFalse(h.frames.contains { $0["payload"]?["kind"] == .string(kind) }, kind, file: file, line: line)
        }
    }

    private func assertUnresolvedWithoutContent(_ h: Harness, file: StaticString = #filePath, line: UInt = #line) {
        assertNoContent(h, file: file, line: line)
        XCTAssertFalse(h.frames.contains {
            $0["payload"]?["kind"] == .string("context.changed") && $0["target"]?["kind"] == .string("resolved")
        }, file: file, line: line)
    }

    private func validateWire(_ h: Harness) throws {
        let validator = try ContractValidator()
        for frame in h.frames {
            XCTAssertNoThrow(try validator.encodeFrame(frame))
            // focusAbsent is private worker evidence, not a public wire addition.
            XCTAssertNil(frame["focusAbsent"])
            XCTAssertNil(frame["payload"]?["focusAbsent"])
        }
    }

    func testLegacyWorkerDTOOmitsFocusMarkerAndRoundTripsWithoutIt() throws {
        let h = try start()
        var worker = try result(h)
        worker.focusAbsent = nil
        let encoded = try JSONEncoder().encode(worker)
        XCTAssertNil(try JSONValue.parse(encoded)["focusAbsent"])
        XCTAssertNil(try JSONDecoder().decode(ReadResult.self, from: encoded).focusAbsent)
        worker.focusAbsent = false
        let explicit = try JSONEncoder().encode(worker)
        XCTAssertEqual(try JSONValue.parse(explicit)["focusAbsent"], .bool(false))
        XCTAssertEqual(try JSONDecoder().decode(ReadResult.self, from: explicit).focusAbsent, false)
    }

    func testTrueAbsenceEmitsOnlyActualWindowSurfaceAndClosedDiagnosticAsValidWire() throws {
        for inputEnabled in [false, true] {
            let h = try start(inputText: inputEnabled)
            let worker = try JSONDecoder().decode(ReadResult.self, from: JSONEncoder().encode(result(h)))
            XCTAssertEqual(worker.focusAbsent, true)
            h.engine.complete(worker)
            let surface = try XCTUnwrap(surfaces(h).first)
            XCTAssertEqual(surfaces(h).count, 1)
            XCTAssertEqual(surface["target"]?["kind"], .string("resolved"))
            XCTAssertEqual(surface["target"]?["identity"]?["windowId"], .string("window-1"))
            XCTAssertNil(surface["target"]?["identity"]?["nodeId"])
            XCTAssertEqual(surface["payload"]?["scope"], .string("window"))
            XCTAssertEqual(surface["payload"]?["coverage"]?["status"], .string("complete"))
            let nodes = try XCTUnwrap(surface["payload"]?["nodes"]?.arrayValue)
            XCTAssertTrue(nodes.allSatisfy { $0["focused"] != .bool(true) })
            XCTAssertEqual(nodes.last?["text"], .string("synthetic window text"))
            for kind in ["text.snapshot", "selection.snapshot", "input.text"] {
                XCTAssertFalse(h.frames.contains { $0["payload"]?["kind"] == .string(kind) }, kind)
            }
            XCTAssertFalse(h.frames.contains {
                $0["payload"]?["kind"] == .string("gap") &&
                    $0["payload"]?["diagnostic"]?["code"] == .string("focused-field-unavailable")
            }, "Successful window-only capture must not emit a bogus focused-field-unavailable gap")
            try validateWire(h)
        }
    }

    func testRootOnlyWindowIsNotReplacedWithFakeEmptyFocusedText() throws {
        let h = try start(inputText: true)
        h.engine.complete(try result(h, includeTextLeaf: false))
        let surface = try XCTUnwrap(surfaces(h).first)
        let nodes = try XCTUnwrap(surface["payload"]?["nodes"]?.arrayValue)
        XCTAssertEqual(nodes.count, 1)
        XCTAssertEqual(nodes[0]["axRole"], .string("AXWindow"))
        XCTAssertEqual(nodes[0]["focused"], .bool(false))
        XCTAssertNil(nodes[0]["text"])
        XCTAssertTrue(h.textFrames.isEmpty)
        try validateWire(h)
    }

    func testIdentityOnlyCannotUseInputEnabledAcceptanceEscape() throws {
        let h = try start(inputText: true)
        var worker = try result(h)
        worker.surface = nil
        h.engine.complete(worker)
        assertNoContent(h)
        XCTAssertFalse(h.frames.contains {
            $0["payload"]?["kind"] == .string("context.changed") && $0["target"]?["kind"] == .string("resolved")
        })
        try validateWire(h)
    }

    func testNodeCountOverAuthorizedLimitCannotResolveNoFocusContext() throws {
        let h = try start(maxTreeNodes: 1, inputText: true)
        let worker = try result(h)
        XCTAssertEqual(worker.surface?.nodes.count, 2)
        h.engine.complete(worker)
        assertUnresolvedWithoutContent(h)
        try validateWire(h)
    }

    func testTextOverAuthorizedBudgetCannotResolveNoFocusContext() throws {
        let h = try start(inputText: true)
        var worker = try result(h)
        worker.surface!.nodes[1].text = String(repeating: "x", count: 129)
        h.engine.complete(worker)
        assertUnresolvedWithoutContent(h)
        try validateWire(h)
    }

    func testNodeOutsideCaptureIntervalCannotResolveNoFocusContext() throws {
        let offsets: [Int64] = [-1, 1]
        for offset in offsets {
            let h = try start(inputText: true)
            var worker = try result(h)
            worker.surface!.nodes[1].observedAtMs = h.clock.unixMs + offset
            h.engine.complete(worker)
            assertUnresolvedWithoutContent(h)
            try validateWire(h)
        }
    }

    func testEmptySurfaceCannotResolveNoFocusContext() throws {
        let h = try start(inputText: true)
        var worker = try result(h)
        worker.surface!.nodes = []
        h.engine.complete(worker)
        assertUnresolvedWithoutContent(h)
        try validateWire(h)
    }

    func testMissingSessionIdentityRefusesWindowSurface() throws {
        let h = try start(inputText: true)
        var worker = try result(h)
        worker.sessionIdentity = nil
        h.engine.complete(worker)
        assertNoContent(h)
        try validateWire(h)
    }

    func testForgedFocusedTextCannotRideAlongWithNoFocusSurface() throws {
        let h = try start(inputText: true)
        var worker = try result(h)
        let text = "synthetic forbidden focused text"
        worker.text = TextRead(text: text, source: "ax.range", totalLength: text.utf16.count,
            complete: true, missingReasons: [])
        h.engine.complete(worker)
        assertNoContent(h)
        try validateWire(h)
    }

    func testForgedSelectionCannotRideAlongWithNoFocusSurface() throws {
        let h = try start(inputText: true)
        var worker = try result(h)
        worker.selection = SelectionReadResult(text: "synthetic forbidden selection", source: "ax.range", rangeStart: 0,
            truncated: false, missingReasons: ["selection-only"])
        h.engine.complete(worker)
        assertNoContent(h)
        try validateWire(h)
    }

    func testForgedValidInputRecordCannotRideAlongWithNoFocusSurface() throws {
        let h = try start(inputText: true)
        var worker = try result(h)
        let app = try XCTUnwrap(worker.application)
        let context = InputTextContext(target: InputTextTarget(application: app, deviceId: "device", osSessionId: "session",
            desktopId: "desktop", windowId: "window-1", windowGeneration: 1), surfaceId: "surface-1",
            captureEpoch: h.engine.captureEpoch, foregroundGeneration: h.engine.foregroundGeneration + 1,
            focusGeneration: h.engine.focusGeneration + 1, policyRevision: 1, privateState: .normal)
        var accumulator = InputTextAccumulator()
        accumulator.add(InputTextSample(context: context, eventKind: .text, text: "synthetic forbidden input",
            modifiers: [], callbackTimeMs: h.clock.unixMs), source: .cgUnicode)
        let record = try XCTUnwrap(accumulator.takeSegment(approvedContext: context))
        XCTAssertTrue(record.isValid)
        worker.inputRecords = [record]
        h.engine.complete(worker)
        assertNoContent(h)
        try validateWire(h)
    }

    func testAnyClaimedFocusedNodeRefusesWholeNoFocusWindow() throws {
        for nodeIndex in [0, 1] {
            let h = try start()
            var worker = try result(h)
            worker.surface!.nodes[nodeIndex].focused = true
            h.engine.complete(worker)
            assertNoContent(h)
            try validateWire(h)
        }
    }

    func testNoFocusWindowRequiresExplicitWindowPolicyNotFocusedOrRegion() throws {
        let scopes: [String?] = [nil, "focused", "region"]
        for scope in scopes {
            let h = try start(scope: scope, inputText: true)
            h.engine.complete(try result(h))
            assertNoContent(h)
            try validateWire(h)
        }
    }

    func testAnyFailureReasonRefusesNoFocusSurfaceInsteadOfSalvagingIt() throws {
        for reason in ["stale", "focus-unavailable", "read-error", "policy-boundary", "desktop-unavailable"] {
            let h = try start(inputText: true)
            var worker = try result(h)
            worker.reason = reason
            h.engine.complete(worker)
            assertNoContent(h)
            try validateWire(h)
        }
    }

    func testSurfaceIdentityMustMatchWindowOnlyWorkerIdentity() throws {
        let h = try start(inputText: true)
        var worker = try result(h)
        worker.surface!.surfaceId = "other-surface"
        h.engine.complete(worker)
        assertNoContent(h)
        try validateWire(h)
    }

    func testEmptyInputRecordsAreAbsenceNotAClaimedInputChannel() throws {
        let h = try start(inputText: true)
        var worker = try result(h)
        worker.inputRecords = []
        h.engine.complete(worker)
        XCTAssertEqual(surfaces(h).count, 1)
        XCTAssertFalse(h.frames.contains { $0["payload"]?["kind"] == .string("input.text") })
        try validateWire(h)
    }

    func testRegionSurfaceCannotClaimIndependentWindowAnchor() throws {
        let h = try start()
        var worker = try result(h)
        worker.surface!.scope = "region"
        h.engine.complete(worker)
        assertNoContent(h)
        try validateWire(h)
    }

    func testMissingOrDifferentDiagnosticCannotAssertGenuineAbsence() throws {
        let codes: [ReadDiagnostic.Code?] = [nil, .focusChanged, .fieldSecurityUnknown, .focusedRoleNotText]
        for code in codes {
            let h = try start()
            var worker = try result(h)
            worker.diagnostic = code.map { ReadDiagnostic(code: $0) }
            h.engine.complete(worker)
            assertNoContent(h)
            try validateWire(h)
        }
    }

    func testLegacyPresentWebAreaFocusWithNilOrFalseMarkerRemainsSupported() throws {
        let markers: [Bool?] = [nil, false]
        for marker in markers {
            let h = try start()
            var worker = try result(h)
            worker.focusAbsent = marker
            worker.diagnostic = ReadDiagnostic(code: .focusedRoleNotText, role: .webArea)
            worker.surface!.nodes[0].axRole = "AXWebArea"
            worker.surface!.nodes[0].focused = true
            h.engine.complete(worker)
            let surface = try XCTUnwrap(surfaces(h).first)
            XCTAssertEqual(surface["payload"]?["nodes"]?.arrayValue?.first?["focused"], .bool(true))
            XCTAssertFalse(h.frames.contains {
                $0["payload"]?["kind"] == .string("gap") &&
                    $0["payload"]?["diagnostic"]?["code"] == .string("focused-field-unavailable")
            })
            try validateWire(h)
        }
    }

    func testFailedWindowReadDoesNotResolveOrInventFieldContext() throws {
        let h = try start(inputText: true)
        let ticket = try XCTUnwrap(h.env.launched.last)
        h.engine.complete(ReadResult(token: ticket.token, reason: "focus-unavailable",
            diagnostic: ReadDiagnostic(code: .focusedFieldUnavailable),
            captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs))
        assertNoContent(h)
        XCTAssertFalse(h.frames.contains {
            $0["payload"]?["kind"] == .string("context.changed") && $0["target"]?["kind"] == .string("resolved")
        })
        let gapFrame = try XCTUnwrap(h.frames.first {
            $0["payload"]?["kind"] == .string("gap") &&
                $0["payload"]?["diagnostic"]?["code"] == .string("focused-field-unavailable")
        })
        XCTAssertEqual(gapFrame["payload"]?["reason"], .string("read-error"))
        try validateWire(h)
    }

    func testStableWindowOnlyIdentityDoesNotInventFocusChanges() throws {
        let h = try start()
        h.engine.complete(try result(h))
        let stamp = h.engine.stamp
        let target = try XCTUnwrap(surfaces(h).last?["target"])
        let changes = h.frames.filter { $0["payload"]?["kind"] == .string("context.changed") }.count
        h.clock.advance(1001)
        h.engine.tick()
        h.engine.complete(try result(h))
        XCTAssertEqual(h.engine.stamp, stamp)
        XCTAssertEqual(surfaces(h).last?["target"], target)
        XCTAssertEqual(h.frames.filter { $0["payload"]?["kind"] == .string("context.changed") }.count, changes)
        try validateWire(h)
    }

    func testPresentAbsentPresentWorkerIdentitiesRotateContextStamps() throws {
        let h = try start()
        var present = try result(h)
        present.focusAbsent = nil
        present.diagnostic = ReadDiagnostic(code: .focusedRoleNotText, role: .webArea)
        present.surface!.nodes[0].focused = true
        h.engine.complete(present)
        let presentStamp = h.engine.stamp
        h.clock.advance(1001)
        h.engine.tick()
        h.engine.complete(try result(h, generation: 2))
        let absentStamp = h.engine.stamp
        XCTAssertNotEqual(absentStamp, presentStamp)
        h.clock.advance(1001)
        h.engine.tick()
        var returned = try result(h, generation: 3)
        returned.focusAbsent = nil
        returned.diagnostic = ReadDiagnostic(code: .focusedRoleNotText, role: .webArea)
        returned.surface!.nodes[0].focused = true
        h.engine.complete(returned)
        XCTAssertNotEqual(h.engine.stamp, absentStamp)
        XCTAssertEqual(surfaces(h).count, 3)
        for surface in surfaces(h) {
            XCTAssertEqual(surface["payload"]?["mode"], .string("full"))
            XCTAssertNil(surface["payload"]?["changes"])
        }
        try validateWire(h)
    }
}

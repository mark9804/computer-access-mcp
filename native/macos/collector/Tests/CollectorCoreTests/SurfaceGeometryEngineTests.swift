import Foundation
import XCTest
import AccessContract
@testable import CollectorCore

/// Fake worker DTOs pass through the production CollectorEngine and wire validator.
/// This never creates an AX provider or reads desktop/history data.
final class SurfaceGeometryEngineTests: XCTestCase {
    private func start() throws -> Harness {
        let h = Harness(fixture: false)
        let policy = CapturePolicy(captureScope: "window")
        h.engine.receive(.object(["protocolVersion": j(1), "type": .string("configure"), "requestId": .string("config"),
            "ownerId": .string("owner"), "instanceId": .string("instance"), "policyRevision": j(1),
            "policy": try JSONValue.parse(JSONEncoder().encode(policy))]))
        h.control("start", lease: 30000); h.clock.advance(51); h.engine.tick()
        return h
    }
    private func result(_ h: Harness, nodes: [SurfaceNodeRead], geometry: SurfaceGeometry?, reasons: [String] = []) throws -> ReadResult {
        let ticket = try XCTUnwrap(h.env.launched.last)
        var result = ReadResult(token: ticket.token,
            application: ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "birth"),
            captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
        result.sessionIdentity = WorkerSurfaceIdentity(sessionId: "worker", windowId: "window", nodeId: "focused", surfaceId: "surface", windowGeneration: 1, focusGeneration: 1)
        result.surface = SurfaceBaseline().snapshot(surfaceId: "surface", scope: "window", nodes: nodes,
            complete: reasons.isEmpty, matchingKnown: true, truncated: false, missingReasons: reasons, geometry: geometry)
        return result
    }
    private func emittedSurface(_ h: Harness) throws -> JSONValue {
        try XCTUnwrap(h.frames.first { $0["payload"]?["kind"] == .string("surface.snapshot") })
    }
    func testEngineEmitsFractionalGeometryAndActualFocusedEmptyNodeAsValidWire() throws {
        let h = try start(), observed = h.clock.unixMs
        let bounds = SurfaceBounds(x: -12.5, y: 720.25, width: 120.5, height: 24.75)
        let node = SurfaceNodeRead(id: "focused", role: "editable", text: "", observedAtMs: observed,
            bounds: bounds, boundsObservedAtMs: observed, axRole: "AXTextArea", focused: true)
        let geometry = SurfaceGeometry(windowSize: .init(width: 800.5, height: 600.25), observedAtMs: observed)
        // Exercise the private worker DTO's Codable roundtrip before acceptance.
        let worker = try result(h, nodes: [node], geometry: geometry)
        let decoded = try JSONDecoder().decode(ReadResult.self, from: JSONEncoder().encode(worker))
        h.engine.complete(decoded)
        let frame = try emittedSurface(h), payload = try XCTUnwrap(frame["payload"])
        XCTAssertEqual(payload["source"], .string("ax.tree"))
        XCTAssertEqual(payload["geometry"], geometry.json)
        if case .object(let emittedGeometry)? = payload["geometry"] {
            XCTAssertEqual(Set(emittedGeometry.keys), ["coordinateSpace", "windowSize", "observedAtMs"])
        } else { XCTFail("Geometry must be an object without any absolute-origin fields") }
        XCTAssertEqual(payload["geometry"]?["coordinateSpace"], .string("window-top-left-point"))
        let outputNode = try XCTUnwrap(payload["nodes"]?.arrayValue?.first)
        XCTAssertEqual(outputNode["bounds"], bounds.json)
        XCTAssertEqual(outputNode["boundsObservedAtMs"], j(observed))
        XCTAssertEqual(outputNode["focused"], .bool(true)); XCTAssertEqual(outputNode["text"], .string(""))
        XCTAssertEqual(outputNode["axRole"], .string("AXTextArea"))
        XCTAssertNil(payload["windowOrigin"]); XCTAssertNil(payload["geometry"]?["x"])
        let validator = try ContractValidator()
        for frame in h.frames { XCTAssertNoThrow(try validator.encodeFrame(frame)) }
    }
    func testEngineRetainsSafeTextWithoutUnavailableGeometryAndWireRemainsPartial() throws {
        let h = try start()
        let node = SurfaceNodeRead(id: "focused", role: "editable", text: "synthetic retained text", observedAtMs: h.clock.unixMs,
            axRole: "AXTextArea", focused: true)
        h.engine.complete(try result(h, nodes: [node], geometry: nil, reasons: ["geometry-window-moved"]))
        let frame = try emittedSurface(h), payload = try XCTUnwrap(frame["payload"])
        XCTAssertNil(payload["geometry"])
        let outputNode = try XCTUnwrap(payload["nodes"]?.arrayValue?.first)
        XCTAssertNil(outputNode["bounds"]); XCTAssertNil(outputNode["boundsObservedAtMs"])
        XCTAssertEqual(outputNode["text"], .string("synthetic retained text"))
        XCTAssertEqual(payload["coverage"]?["status"], .string("partial"))
        XCTAssertEqual(payload["mode"], .string("full")); XCTAssertNil(payload["changes"])
        XCTAssertNoThrow(try ContractValidator().encodeFrame(frame))
    }
    func testEngineOldSurfaceDoesNotSynthesizeGeometryOrFocus() throws {
        let h = try start()
        let node = SurfaceNodeRead(id: "old", role: "text", text: "synthetic old text", observedAtMs: h.clock.unixMs)
        h.engine.complete(try result(h, nodes: [node], geometry: nil))
        let frame = try emittedSurface(h), payload = try XCTUnwrap(frame["payload"])
        XCTAssertNil(payload["geometry"])
        let outputNode = try XCTUnwrap(payload["nodes"]?.arrayValue?.first)
        for key in ["bounds", "boundsObservedAtMs", "focused", "axRole"] { XCTAssertNil(outputNode[key], key) }
        XCTAssertNoThrow(try ContractValidator().encodeFrame(frame))
    }
}

import Foundation
import XCTest
import HistoryContract
@testable import CollectorCore

final class SurfaceGeometryTests: XCTestCase {
    private func rect(_ x: Double = 100, _ y: Double = 200, _ width: Double = 800, _ height: Double = 600) -> SurfaceAbsoluteRect {
        SurfaceAbsoluteRect(x: x, y: y, width: width, height: height)!
    }
    private func geometry(_ width: Double = 800, at: Int64 = 10) -> SurfaceGeometry {
        SurfaceGeometry(windowSize: .init(width: width, height: 600), observedAtMs: at)
    }
    private func node(_ id: String = "a", x: Double = 1, focused: Bool = false, axRole: String = "AXStaticText", at: Int64 = 10) -> SurfaceNodeRead {
        SurfaceNodeRead(id: id, role: "text", text: "fixture", observedAtMs: at,
            bounds: .init(x: x, y: 2, width: 3.5, height: 4.25), boundsObservedAtMs: at, axRole: axRole, focused: focused)
    }
    private func snapshot(_ baseline: SurfaceBaseline, nodes: [SurfaceNodeRead], geometry: SurfaceGeometry? = nil,
                          complete: Bool = true, reasons: [String] = []) -> SurfaceReadResult {
        baseline.snapshot(surfaceId: "s", scope: "window", nodes: nodes, complete: complete, matchingKnown: true,
            truncated: false, missingReasons: reasons, geometry: geometry)
    }
    func testTopLeftRelativeTransformPreservesFractionalPoints() {
        XCTAssertEqual(rect(110.5, 220.25, 40.5, 20.25).relative(to: rect()),
                       SurfaceBounds(x: 10.5, y: 20.25, width: 40.5, height: 20.25))
    }
    func testNegativeDesktopAndOffWindowOffsetsAreNotClipped() {
        let window = rect(-900, -300)
        XCTAssertEqual(rect(-910, -320, 0, 20).relative(to: window), .init(x: -10, y: -20, width: 0, height: 20))
        XCTAssertEqual(rect(5000, 4000).relative(to: rect())?.x, 4900)
    }
    func testNonfiniteAndOutOfRangeAbsoluteValuesAreRejected() {
        for invalid in [Double.nan, .infinity, -.infinity, 1_000_001, -1_000_001] {
            XCTAssertNil(SurfaceAbsoluteRect(x: invalid, y: 0, width: 0, height: 0))
            XCTAssertNil(SurfaceAbsoluteRect(x: 0, y: invalid, width: 0, height: 0))
        }
        for invalid in [Double.nan, .infinity, -.infinity, -1, 1_000_001] {
            XCTAssertNil(SurfaceAbsoluteRect(x: 0, y: 0, width: invalid, height: 0))
            XCTAssertNil(SurfaceAbsoluteRect(x: 0, y: 0, width: 0, height: invalid))
        }
    }
    func testExactLimitsAndZeroSizesAreAcceptedButRelativeOverflowIsNot() {
        XCTAssertNotNil(SurfaceAbsoluteRect(x: -1_000_000, y: 1_000_000, width: 1_000_000, height: 0))
        XCTAssertNil(rect(1_000_000, 0).relative(to: rect(-1_000_000, 0)))
    }
    func testMovedResizedOrMissingWindowInvalidatesGeometry() {
        let initial = rect()
        XCTAssertNil(initial.geometry(ifUnchanged: rect(101), observedAtMs: 20))
        XCTAssertNil(initial.geometry(ifUnchanged: rect(100, 201), observedAtMs: 20))
        XCTAssertNil(initial.geometry(ifUnchanged: rect(100, 200, 801), observedAtMs: 20))
        XCTAssertNil(initial.geometry(ifUnchanged: rect(100, 200, 800, 601), observedAtMs: 20))
        XCTAssertNil(initial.geometry(ifUnchanged: nil, observedAtMs: 20))
        XCTAssertEqual(initial.geometry(ifUnchanged: initial, observedAtMs: 20), geometry(at: 20))
    }
    func testBoundsOnlyChangeIsUpdatedAndCurrentSetIsRetained() {
        let baseline = SurfaceBaseline()
        _ = snapshot(baseline, nodes: [node()], geometry: geometry())
        let current = snapshot(baseline, nodes: [node(x: 9)], geometry: geometry(at: 20))
        XCTAssertEqual(current.mode, "diff"); XCTAssertEqual(current.updated, ["a"])
        XCTAssertEqual(current.nodes, [node(x: 9)])
    }
    func testFocusAndRawRoleChangesAreUpdated() {
        let baseline = SurfaceBaseline()
        _ = snapshot(baseline, nodes: [node()], geometry: geometry())
        XCTAssertEqual(snapshot(baseline, nodes: [node(focused: true)], geometry: geometry()).updated, ["a"])
        XCTAssertEqual(snapshot(baseline, nodes: [node(focused: true, axRole: "AXTextField")], geometry: geometry()).updated, ["a"])
    }
    func testFreshTimestampsAloneDoNotCreateSpatialChanges() {
        let baseline = SurfaceBaseline()
        _ = snapshot(baseline, nodes: [node()], geometry: geometry())
        XCTAssertEqual(snapshot(baseline, nodes: [node(at: 20)], geometry: geometry(at: 20)).updated, [])
    }
    func testWindowSizeChangeUpdatesExistingNodes() {
        let baseline = SurfaceBaseline()
        _ = snapshot(baseline, nodes: [node()], geometry: geometry())
        XCTAssertEqual(snapshot(baseline, nodes: [node()], geometry: geometry(900)).updated, ["a"])
    }
    func testGeometryGapCannotAssertRemovalsEvenWithIncorrectCompleteFlag() {
        let baseline = SurfaceBaseline()
        _ = snapshot(baseline, nodes: [node(), node("b")], geometry: geometry())
        let partial = snapshot(baseline, nodes: [node()], reasons: ["geometry-window-moved"])
        XCTAssertFalse(partial.complete); XCTAssertEqual(partial.mode, "full"); XCTAssertEqual(partial.removed, [])
        XCTAssertEqual(snapshot(baseline, nodes: [node()], geometry: geometry()).mode, "full")
    }
}

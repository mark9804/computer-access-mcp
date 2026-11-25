import XCTest
import Foundation
@testable import CollectorCore
@testable import computer_history_collector

final class AXSurfaceCaptureTests: XCTestCase {
    private let genericId = GenericAdapter().spec.id
    private let vscodeId = VSCodeFamilyAdapter().spec.id

    private func capture(_ adapterId: String, child: Int = 2, text: String = "synthetic") -> AXSurfaceCaptureValue<Int> {
        .init(
            nodes: [
                .init(id: "root", role: "container", observedAtMs: 1),
                .init(id: "leaf", parentId: "root", role: "text", text: text, observedAtMs: 1),
            ],
            truncated: false,
            reasons: [],
            complete: true,
            geometry: nil,
            adapterId: adapterId,
            references: [("root", 1), ("leaf", child)]
        )
    }

    func testAdapterBoundaryResetsOnlySurfaceMapAndPinsFocusedIdentityNode() throws {
        var next = 0
        var map = AXSurfaceNodeMap<Int>(equal: ==, makeID: { next += 1; return "id-\(next)" })
        let focus = try XCTUnwrap(map.identifier(for: 7))
        let initial = capture(genericId)
        XCTAssertTrue(map.prepareCommit(adapterId: genericId, selecting: initial.selectedHandles, pin: (7, focus)))
        let before = try XCTUnwrap(initial.materializeNodes(nodeID: { map.identifier(for: $0) }))
        XCTAssertEqual(before[1].parentId, before[0].id)

        let changed = capture(vscodeId)
        XCTAssertTrue(map.prepareCommit(adapterId: vscodeId, selecting: changed.selectedHandles, pin: (7, focus)))
        let after = try XCTUnwrap(changed.materializeNodes(nodeID: { map.identifier(for: $0) }))
        XCTAssertNotEqual(after[0].id, before[0].id)
        XCTAssertEqual(map.identifier(for: 7), focus)
        XCTAssertEqual(after[1].parentId, after[0].id)
        XCTAssertFalse(map.prepareCommit(adapterId: vscodeId, selecting: changed.selectedHandles, pin: (7, focus)))
        XCTAssertEqual(map.adapterId, vscodeId)
    }

    func testFailedPreparedCandidateDoesNotAdvanceMapAdapterOrSuccessfulBaseline() throws {
        var next = 0
        var live = AXSurfaceNodeMap<Int>(equal: ==, makeID: { next += 1; return "id-\(next)" })
        let baseline = SurfaceBaseline()
        let first = capture(genericId)
        XCTAssertTrue(live.prepareCommit(adapterId: genericId, selecting: first.selectedHandles, pin: nil))
        let firstNodes = try XCTUnwrap(first.materializeNodes(nodeID: { live.identifier(for: $0) }))
        let initial = baseline.snapshot(surfaceId: "surface", scope: "window", nodes: firstNodes, complete: true,
            matchingKnown: true, truncated: false, missingReasons: [])
        XCTAssertEqual(initial.mode, "full")
        XCTAssertEqual(initial.revision, 1)

        var rejected = live
        let failed = capture(vscodeId, child: 3, text: "never committed")
        XCTAssertTrue(rejected.prepareCommit(adapterId: vscodeId, selecting: failed.selectedHandles, pin: nil))
        XCTAssertNotNil(failed.materializeNodes(nodeID: { rejected.identifier(for: $0) }))
        XCTAssertEqual(live.adapterId, genericId)

        let again = capture(genericId)
        XCTAssertFalse(live.prepareCommit(adapterId: genericId, selecting: again.selectedHandles, pin: nil))
        let againNodes = try XCTUnwrap(again.materializeNodes(nodeID: { live.identifier(for: $0) }))
        let accepted = baseline.snapshot(surfaceId: "surface", scope: "window", nodes: againNodes, complete: true,
            matchingKnown: true, truncated: false, missingReasons: [])
        XCTAssertEqual(accepted.mode, "diff")
        XCTAssertEqual(accepted.baseRevision, 1)
        XCTAssertTrue(accepted.added.isEmpty)
        XCTAssertTrue(accepted.updated.isEmpty)
        XCTAssertTrue(accepted.removed.isEmpty)
    }

    func testBatchRolloverIsBoundedAndKeepsParentAndFocusReferencesStable() throws {
        var next = 0
        var map = AXSurfaceNodeMap<Int>(equal: ==, makeID: { next += 1; return "id-\(next)" })
        let focus = try XCTUnwrap(map.identifier(for: 999))
        _ = map.prepareCommit(adapterId: genericId, selecting: [], pin: (999, focus))
        for index in 0..<191 { XCTAssertNotNil(map.identifier(for: index)) }
        XCTAssertNil(map.identifier(for: 1000))
        let batch = capture(genericId, child: 1001)
        XCTAssertTrue(map.prepareCommit(adapterId: genericId, selecting: batch.selectedHandles, pin: (999, focus)))
        let nodes = try XCTUnwrap(batch.materializeNodes(nodeID: { map.identifier(for: $0) }))
        XCTAssertEqual(map.identifier(for: 999), focus)
        XCTAssertEqual(nodes[1].parentId, nodes[0].id)
    }

    func testMalformedNativeCaptureRejectsBeforeAllocatingAnyStableIDs() {
        let invalid = AXSurfaceCaptureValue<Int>(
            nodes: [.init(id: "leaf", parentId: "unseen", role: "text", text: "synthetic", observedAtMs: 1)],
            truncated: false,
            reasons: [],
            complete: true,
            geometry: nil,
            adapterId: genericId,
            references: [("leaf", 2)]
        )
        var allocations = 0
        XCTAssertNil(invalid.materializeNodes(nodeID: { _ in allocations += 1; return "id" }))
        XCTAssertEqual(allocations, 0)
    }
}

import XCTest
import CollectorCore

final class SurfaceFocusAnchorsTests: XCTestCase {
    private func metadata(_ role: String = "AXGroup", children: Int = 1,
                          focused: Bool = false, time: Int64 = 0) -> WeightedSurfaceMetadata {
        .init(role: role, childCount: children, isFocused: focused, observedAtMs: time)
    }

    func testDeniedAncestorDiscardsDescendantsAndNeverReadsItsParent() {
        var inspected: [Int] = [], parentCalls: [Int] = []
        let result = SurfaceFocusAnchors.collect(root: 0, focus: 4, inspect: {
            inspected.append($0)
            return $0 == 2 ? .pruned(.securityPruned) : .allowed(self.metadata())
        }, parent: { parentCalls.append($0); return $0 - 1 })
        XCTAssertNil(result.plan)
        XCTAssertEqual(result.reason, .unavailable)
        XCTAssertEqual(inspected, [4, 3, 2])
        XCTAssertEqual(parentCalls, [4, 3])
        XCTAssertEqual(result.work, 5)
        XCTAssertEqual(result.probes, 3)
    }

    func testMissingParentCannotYieldPartialPlanAndParentAttemptIsCharged() {
        var parentCalls = 0
        let result = SurfaceFocusAnchors.collect(root: 0, focus: 1, inspect: { _ in
            .allowed(self.metadata("AXButton", children: 4))
        }, parent: { _ in parentCalls += 1; return Optional<Int>.none })
        XCTAssertNil(result.plan)
        XCTAssertEqual(result.reason, .unavailable)
        XCTAssertEqual(result.work, 5)
        XCTAssertEqual(result.probes, 1)
        XCTAssertEqual(parentCalls, 1)
    }

    func testCycleAndSelfParentNeverReinspectDuplicate() {
        for selfParent in [false, true] {
            var inspected: [Int] = [], parentCalls: [Int] = []
            let result = SurfaceFocusAnchors.collect(root: 0, focus: 2, inspect: {
                inspected.append($0)
                return .allowed(self.metadata())
            }, parent: {
                parentCalls.append($0)
                return selfParent ? 2 : ($0 == 2 ? 1 : 2)
            })
            XCTAssertNil(result.plan)
            XCTAssertEqual(result.reason, .cycle)
            XCTAssertEqual(inspected, selfParent ? [2] : [2, 1])
            XCTAssertEqual(parentCalls, selfParent ? [2] : [2, 1])
            XCTAssertEqual(result.work, selfParent ? 2 : 4)
            XCTAssertEqual(result.probes, selfParent ? 1 : 2)
        }
    }

    func testTextAncestorIncludingTextRootIsRejectedButTextFocusIsAllowed() {
        for ancestor in [0, 1] {
            var inspected: [Int] = [], parentCalls: [Int] = []
            let result = SurfaceFocusAnchors.collect(root: 0, focus: 2, inspect: {
                inspected.append($0)
                return .allowed(self.metadata($0 == ancestor || $0 == 2 ? "AXTextArea" : "AXGroup",
                                              children: $0 == 2 ? 0 : 1))
            }, parent: { parentCalls.append($0); return $0 - 1 })
            XCTAssertNil(result.plan)
            XCTAssertEqual(result.reason, .unavailable)
            XCTAssertEqual(inspected, ancestor == 1 ? [2, 1] : [2, 1, 0])
            XCTAssertEqual(parentCalls, ancestor == 1 ? [2] : [2, 1])
            XCTAssertEqual(result.work, ancestor == 1 ? 4 : 6)
            XCTAssertEqual(result.probes, ancestor == 1 ? 2 : 3)
        }
    }

    func testUnknownRoleAndMalformedCountsRejectBeforeParent() {
        let invalid: [WeightedSurfaceMetadata] = [
            metadata("AXUnreviewedRole"), metadata(children: -1),
            metadata(children: 1_000_001), metadata(children: Int.max),
        ]
        for actual in invalid {
            var parentCalls = 0
            let result = SurfaceFocusAnchors.collect(root: 0, focus: 1,
                                                     inspect: { _ in .allowed(actual) },
                                                     parent: { _ in parentCalls += 1; return 0 })
            XCTAssertNil(result.plan)
            XCTAssertEqual(result.reason, .unavailable)
            XCTAssertEqual(result.work, 1)
            XCTAssertEqual(result.probes, 1)
            XCTAssertEqual(parentCalls, 0)
        }
        let upperBoundary = SurfaceFocusAnchors.collect(root: 0, focus: 0,
                                                        inspect: { _ in .allowed(self.metadata(children: 1_000_000)) },
                                                        parent: { _ in Optional<Int>.none })
        XCTAssertNotNil(upperBoundary.plan)
        XCTAssertEqual(upperBoundary.work, 3)
    }

    func testHalfTraversalWorkBudgetIsHardCappedAtMaximumWork() {
        var inspected = 0, parentCalls = 0
        let result = SurfaceFocusAnchors.collect(root: 0, focus: 100,
                                                 maxHops: Int.max, maxWork: Int.max, maxProbes: Int.max,
                                                 inspect: { _ in
            inspected += 1
            return .allowed(self.metadata("AXButton", children: 2))
        }, parent: { parentCalls += 1; return $0 - 1 })
        XCTAssertNil(result.plan)
        XCTAssertEqual(result.reason, .budget)
        // Each AXButton hop costs 4 inspect + 1 parent = 5 work; 32 hops consume exact 160 work.
        XCTAssertEqual(result.work, SurfaceFocusAnchors.maximumWork)
        XCTAssertEqual(result.probes, 32)
        XCTAssertEqual(inspected, 32)
        XCTAssertEqual(parentCalls, 32)
    }

    func testHopsAndProbesAreHardCappedAtFortyEight() {
        var inspected = 0, parentCalls = 0
        let result = SurfaceFocusAnchors.collect(root: 0, focus: 60,
                                                 maxHops: Int.max, maxWork: Int.max, maxProbes: Int.max,
                                                 inspect: { _ in
            inspected += 1
            return .allowed(self.metadata())
        }, parent: { parentCalls += 1; return $0 - 1 })
        XCTAssertNil(result.plan)
        XCTAssertEqual(result.reason, .budget)
        XCTAssertEqual(result.work, 95)
        XCTAssertEqual(result.probes, SurfaceFocusAnchors.maximumProbes)
        XCTAssertEqual(inspected, SurfaceFocusAnchors.maximumHops)
        XCTAssertEqual(parentCalls, SurfaceFocusAnchors.maximumHops - 1)
    }

    func testBudgetAfterActualInspectionIsNotRefundedAndCannotCallParent() {
        var parents = 0
        let result = SurfaceFocusAnchors.collect(root: 0, focus: 1, maxWork: 3,
                                                 inspect: { _ in .allowed(self.metadata("AXButton")) },
                                                 parent: { _ in parents += 1; return 0 })
        XCTAssertNil(result.plan)
        XCTAssertEqual(result.reason, .budget)
        XCTAssertEqual(result.work, 1)
        XCTAssertEqual(result.probes, 1)
        XCTAssertEqual(parents, 0)
    }

    func testParentConsumesLastWorkAndProbeLimitStillPreservesAllAttemptCosts() {
        for (workCap, probeCap) in [(2, 24), (96, 1)] {
            var inspected: [Int] = [], parents: [Int] = []
            let result = SurfaceFocusAnchors.collect(root: 0, focus: 1,
                                                     maxWork: workCap, maxProbes: probeCap,
                                                     inspect: { inspected.append($0); return .allowed(self.metadata()) },
                                                     parent: { parents.append($0); return 0 })
            XCTAssertNil(result.plan)
            XCTAssertEqual(result.reason, .budget)
            XCTAssertEqual(result.work, 2)
            XCTAssertEqual(result.probes, 1)
            XCTAssertEqual(inspected, [1])
            XCTAssertEqual(parents, [1])
        }
    }

    func testPreAndPostInspectionDeadlineGatesCannotGrantPlan() {
        var inspected = 0, parents = 0
        let closed = SurfaceFocusAnchors.collect(root: 0, focus: 0, inspect: { _ in
            inspected += 1
            return .allowed(self.metadata())
        }, parent: { _ in parents += 1; return 0 }, shouldContinue: { false })
        XCTAssertNil(closed.plan)
        XCTAssertEqual(closed.reason, .budget)
        XCTAssertEqual(closed.work, 0)
        XCTAssertEqual(inspected, 0)
        XCTAssertEqual(parents, 0)

        var live = true
        let late = SurfaceFocusAnchors.collect(root: 0, focus: 0, inspect: { _ in
            live = false
            return .allowed(self.metadata("AXButton"))
        }, parent: { _ in parents += 1; return 0 }, shouldContinue: { live })
        XCTAssertNil(late.plan)
        XCTAssertEqual(late.reason, .budget)
        XCTAssertEqual(late.work, 1)
        XCTAssertEqual(late.probes, 1)
        XCTAssertEqual(parents, 0)
    }

    func testPreAndPostParentDeadlineGatesCannotInspectReturnedAncestor() {
        var gates = 0, parents = 0
        let preParent = SurfaceFocusAnchors.collect(root: 0, focus: 1, inspect: { _ in
            .allowed(self.metadata())
        }, parent: { _ in parents += 1; return 0 }, shouldContinue: {
            gates += 1
            return gates < 3
        })
        XCTAssertNil(preParent.plan)
        XCTAssertEqual(preParent.reason, .budget)
        XCTAssertEqual(preParent.work, 1)
        XCTAssertEqual(preParent.probes, 1)
        XCTAssertEqual(parents, 0)

        var live = true, inspected: [Int] = []
        let lateParent = SurfaceFocusAnchors.collect(root: 0, focus: 1, inspect: {
            inspected.append($0)
            return .allowed(self.metadata("AXButton"))
        }, parent: { _ in
            parents += 1
            live = false
            return 0
        }, shouldContinue: { live })
        XCTAssertNil(lateParent.plan)
        XCTAssertEqual(lateParent.reason, .budget)
        XCTAssertEqual(lateParent.work, 5)
        XCTAssertEqual(lateParent.probes, 1)
        XCTAssertEqual(inspected, [1])
        XCTAssertEqual(parents, 1)
    }
}

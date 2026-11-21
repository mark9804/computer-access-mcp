import XCTest
import CollectorCore

/// Synthetic provider graphs exercise the production planner and closed-plan
/// factory together. No AX calls, application fixtures or duplicate scheduler.
final class SurfaceTextCoverageTests: XCTestCase {
    private struct Node {
        var role = "AXGroup"
        var children: [Int] = []
        var parent: Int?
        var value: String?
        var displayText: String? = nil
        var bounds: SurfaceBounds? = nil
        var focused = false
        var denied = false
        var reportedCount: Int?
    }

    private struct Page: Equatable {
        let handle: Int
        let offset: Int
        let count: Int
    }

    private final class Provider {
        var nodes: [Int: Node]
        var inspections: [Int] = []
        var parentCalls: [Int] = []
        var pages: [Page] = []
        var textCalls: [Int] = []
        var reads: [Int] = []
        var pageOverride: ((Int, Int, Int) -> WeightedSurfaceChildrenRead<Int>?)?
        var afterInspection: (() -> Void)?
        var afterPage: (() -> Void)?
        var afterText: (() -> Void)?

        init(_ nodes: [Int: Node]) { self.nodes = nodes }

        func inspect(_ handle: Int) -> WeightedSurfaceInspection {
            inspections.append(handle)
            afterInspection?()
            guard let node = nodes[handle] else { return .pruned(.providerRefused) }
            guard !node.denied else { return .pruned(.securityPruned) }
            return .allowed(.init(role: node.role,
                                  childCount: node.reportedCount ?? node.children.count,
                                  isFocused: node.focused, observedAtMs: Int64(100 + handle),
                                  displayText: node.displayText, bounds: node.bounds))
        }

        func collect(root: Int = 0, focus: Int,
                     shouldContinue: () -> Bool = { true }) -> SurfaceFocusAnchorResult<Int> {
            SurfaceFocusAnchors.collect(root: root, focus: focus, maxWork: 96,
                                        inspect: inspect, parent: { handle in
                self.parentCalls.append(handle)
                return self.nodes[handle]?.parent
            }, shouldContinue: shouldContinue)
        }

        func run(root: Int = 0, limits: WeightedSurfaceTraversalLimits = .init(),
                 preparation: SurfaceFocusAnchorResult<Int>? = nil,
                 shouldContinue: () -> Bool = { true }) -> WeightedSurfaceTraversalResult<Int> {
            WeightedSurfaceTraversal.run(root: root, limits: limits,
                                         preparationWork: preparation?.work ?? 0,
                                         preparationProbes: preparation?.probes ?? 0,
                                         focusAnchors: preparation?.plan, inspect: inspect,
                                         children: { handle, offset, count in
                self.pages.append(.init(handle: handle, offset: offset, count: count))
                self.afterPage?()
                // Preparation metadata is not a permission cache: each operation
                // performs the provider's current security/role gate again.
                guard let node = self.nodes[handle], !node.denied,
                      let policy = WeightedSurfaceTraversal.rolePolicy(for: node.role),
                      !policy.readsText else { return .unavailable(.securityPruned) }
                if let page = self.pageOverride?(handle, offset, count) { return page }
                return .values(Array(node.children.dropFirst(offset).prefix(count)))
            }, text: { handle in
                self.textCalls.append(handle)
                self.afterText?()
                guard let node = self.nodes[handle], !node.denied,
                      WeightedSurfaceTraversal.rolePolicy(for: node.role)?.readsText == true,
                      let value = node.value else { return nil }
                self.reads.append(handle)
                return SurfaceNodeRead(id: "synthetic-\(handle)", role: node.role,
                                       text: value, observedAtMs: Int64(500 + handle))
            }, shouldContinue: shouldContinue)
        }
    }

    private func simple() -> Provider {
        Provider([0: Node(role: "AXWindow", children: [1]),
                  1: Node(children: [2], parent: 0),
                  2: Node(role: "AXTextArea", parent: 1, value: "caret", focused: true)])
    }

    /// The body is depth 27, below a mixed wrapper/semantic content spine;
    /// identifiers only identify synthetic nodes, never influence priorities.
    private func deep(focusWebArea: Bool, reverse: Bool) -> Provider {
        var nodes: [Int: Node] = [
            0: Node(role: "AXWindow", children: reverse ? [3, 2, 1] : [1, 2, 3]),
            1: Node(role: "AXToolbar", children: Array(100..<180), parent: 0),
            2: Node(role: "AXList", children: Array(200..<240), parent: 0)
        ]
        for handle in 100..<180 { nodes[handle] = Node(role: "AXButton", parent: 1) }
        for handle in 200..<240 { nodes[handle] = Node(parent: 2) }
        for handle in 3...14 {
            nodes[handle] = Node(role: handle == 8 ? "AXWebArea" : "AXGroup",
                                 children: [handle + 1], parent: handle == 3 ? 0 : handle - 1)
        }
        nodes[15] = Node(children: reverse ? [17, 16] : [16, 17], parent: 14)
        nodes[16] = Node(role: focusWebArea ? "AXWebArea" : "AXTextArea", parent: 15,
                         value: focusWebArea ? nil : "", focused: true)
        for handle in 17..<30 {
            nodes[handle] = Node(children: [handle + 1], parent: handle == 17 ? 15 : handle - 1)
        }
        nodes[30] = Node(role: "AXStaticText", parent: 29, value: "synthetic deep body")
        return Provider(nodes)
    }

    private func assertBounded(_ result: WeightedSurfaceTraversalResult<Int>,
                               _ limits: WeightedSurfaceTraversalLimits,
                               file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertLessThanOrEqual(result.counters.work, limits.maxWork, file: file, line: line)
        XCTAssertLessThanOrEqual(result.counters.probes, limits.maxProbes, file: file, line: line)
        XCTAssertLessThanOrEqual(result.counters.peakPending, limits.maxPending, file: file, line: line)
        XCTAssertLessThanOrEqual(result.nodes.count, limits.maxOutputNodes, file: file, line: line)
        let retained = Set(result.nodes.map(\.handle))
        XCTAssertEqual(retained.count, result.nodes.count, file: file, line: line)
        for node in result.nodes {
            if let parent = node.parent { XCTAssertTrue(retained.contains(parent), file: file, line: line) }
        }
    }

    func testDeepBodyReachedWithEditableAnchorAndSameTotalBudgetInBothChildOrders() throws {
        let limits = WeightedSurfaceTraversalLimits(maxOutputNodes: 48)
        for reverse in [false, true] {
            let provider = deep(focusWebArea: false, reverse: reverse)
            let preparation = provider.collect(focus: 16)
            let plan = try XCTUnwrap(preparation.plan)
            XCTAssertEqual(plan.nodes.first?.handle, 0)
            XCTAssertEqual(plan.nodes.last?.handle, 16)
            // Fifteen inspections: root 3 + content spine 13 + split 3 +
            // editable 2, plus fourteen parent calls. All preparation is spent.
            XCTAssertEqual(preparation.probes, 15)
            XCTAssertEqual(preparation.probes, plan.nodes.count)
            XCTAssertEqual(preparation.work, 35)
            XCTAssertEqual(provider.parentCalls.count, 14)
            let result = provider.run(limits: limits, preparation: preparation)
            XCTAssertTrue(provider.reads.contains(30), "Depth-27 body must not lose to wide empty toolbar")
            XCTAssertTrue(result.nodes.contains { $0.handle == 30 && $0.textRead?.text == "synthetic deep body" })
            XCTAssertEqual(provider.inspections.filter { $0 == 16 }.count, 1)
            assertBounded(result, limits)
        }
    }

    func testDeepBodyReachedWithWebAreaAnchorWithoutApplicationSemantics() throws {
        let provider = deep(focusWebArea: true, reverse: true)
        let preparation = provider.collect(focus: 16)
        XCTAssertEqual(try XCTUnwrap(preparation.plan).nodes.last?.metadata.role, "AXWebArea")
        let limits = WeightedSurfaceTraversalLimits(maxOutputNodes: 48)
        let result = provider.run(limits: limits, preparation: preparation)
        XCTAssertTrue(provider.reads.contains(30))
        XCTAssertFalse(provider.textCalls.contains(16), "WebArea is navigation, not a value-reading role")
        assertBounded(result, limits)
    }

    func testBidirectionalPagesAreDisjointBoundedAndEventuallyCoverEveryChild() throws {
        var nodes = [0: Node(role: "AXWindow", children: Array(1...11), focused: true)]
        for handle in 1...11 { nodes[handle] = Node(parent: 0) }
        let provider = Provider(nodes)
        let preparation = provider.collect(focus: 0)
        _ = try XCTUnwrap(preparation.plan)
        let result = provider.run(preparation: preparation)
        XCTAssertTrue(result.complete)
        XCTAssertEqual(provider.pages.map(\.offset), [7, 0, 4])
        XCTAssertEqual(provider.pages.map(\.count), [4, 4, 3])
        let positions = provider.pages.flatMap { Array($0.offset..<($0.offset + $0.count)) }
        XCTAssertEqual(positions.count, Set(positions).count)
        XCTAssertEqual(Set(positions), Set(0..<11))
        XCTAssertEqual(Set(provider.inspections), Set(0...11))
        XCTAssertTrue(provider.pages.allSatisfy { $0.count <= 4 })
    }

    func testPriorityBurstStillServicesUnrelatedRootBranchUnderAmpleBudget() throws {
        var nodes = [0: Node(role: "AXWindow", children: [1, 2]),
                     1: Node(role: "AXWebArea", children: Array(10..<30), parent: 0, focused: true),
                     2: Node(children: [3], parent: 0),
                     3: Node(role: "AXStaticText", parent: 2, value: "unrelated branch")]
        for handle in 10..<30 { nodes[handle] = Node(role: "AXStaticText", parent: 1, value: "body") }
        let provider = Provider(nodes)
        let preparation = provider.collect(focus: 1)
        _ = try XCTUnwrap(preparation.plan)
        let limits = WeightedSurfaceTraversalLimits(maxOutputNodes: 96, maxPriorityBurst: 99)
        XCTAssertEqual(limits.maxPriorityBurst, 4)
        let result = provider.run(limits: limits, preparation: preparation)
        XCTAssertTrue(provider.inspections.contains(2))
        XCTAssertTrue(provider.reads.contains(3))
        XCTAssertTrue(result.complete)
        assertBounded(result, limits)
    }

    func testSeededParentOnlyAppearsAfterRealChildPageReturnsThatChild() throws {
        let provider = simple()
        let preparation = provider.collect(focus: 2)
        _ = try XCTUnwrap(preparation.plan)
        provider.pageOverride = { handle, _, _ in handle == 1 ? .values([]) : nil }
        let result = provider.run(preparation: preparation)
        XCTAssertTrue(provider.reads.contains(2))
        XCTAssertNil(try XCTUnwrap(result.nodes.first { $0.handle == 2 }).parent)
        XCTAssertEqual(result.nodes.first { $0.handle == 1 }?.parent, 0)
        XCTAssertTrue(result.reasons.contains(.anchorParentUnconfirmed))
        XCTAssertTrue(result.reasons.contains(.inconsistentChildren))
        XCTAssertFalse(result.complete)
    }

    func testFailedParentPageRetainsTextButMarksMissingEdgePartial() throws {
        let provider = simple()
        let preparation = provider.collect(focus: 2)
        _ = try XCTUnwrap(preparation.plan)
        provider.pageOverride = { handle, _, _ in handle == 1 ? .unavailable(.providerRefused) : nil }
        let result = provider.run(preparation: preparation)
        let focused = try XCTUnwrap(result.nodes.first { $0.handle == 2 })
        XCTAssertEqual(focused.textRead?.text, "caret")
        XCTAssertNil(focused.parent)
        XCTAssertTrue(result.reasons.contains(.providerRefused))
        XCTAssertTrue(result.reasons.contains(.anchorParentUnconfirmed))
        XCTAssertFalse(result.complete)
    }

    func testSkippedActualParentNeverBecomesFabricatedGrandparentEdge() throws {
        let provider = simple()
        let preparation = provider.collect(focus: 2)
        _ = try XCTUnwrap(preparation.plan)
        provider.pageOverride = { handle, _, _ in
            if handle == 0 { return .values([2]) } // Wrong edge cannot confirm 1 -> 2.
            if handle == 1 { return .unavailable(.providerRefused) }
            return nil
        }
        let result = provider.run(preparation: preparation)
        XCTAssertNil(try XCTUnwrap(result.nodes.first { $0.handle == 2 }).parent)
        XCTAssertTrue(result.reasons.contains(.anchorParentUnconfirmed))
        XCTAssertFalse(result.complete)
    }

    func testWrongRootPlanCannotSeedButPreparationRemainsSpent() throws {
        let provider = simple()
        provider.nodes[90] = Node(role: "AXWindow")
        let preparation = provider.collect(focus: 2)
        _ = try XCTUnwrap(preparation.plan)
        let before = provider.inspections.count
        let result = provider.run(root: 90, preparation: preparation)
        XCTAssertEqual(Array(provider.inspections.dropFirst(before)), [90])
        XCTAssertEqual(result.nodes.map(\.handle), [90])
        XCTAssertEqual(result.counters.work, preparation.work + 1)
        XCTAssertEqual(result.counters.probes, preparation.probes + 1)
        XCTAssertTrue(provider.textCalls.isEmpty)
    }

    func testDepthAndPendingCapsCannotBeBypassedBySeedingPlan() throws {
        for limits in [WeightedSurfaceTraversalLimits(maxDepth: 0),
                       WeightedSurfaceTraversalLimits(maxPending: 1)] {
            let provider = simple()
            let preparation = provider.collect(focus: 2)
            _ = try XCTUnwrap(preparation.plan)
            let result = provider.run(limits: limits, preparation: preparation)
            XCTAssertGreaterThan(provider.inspections.filter { $0 == 0 }.count, 1)
            // A one-slot queue may still walk this chain normally; refusing the
            // oversized seed plan must not manufacture a traversal failure.
            if limits.maxDepth == 0 {
                XCTAssertFalse(result.complete)
                XCTAssertFalse(provider.reads.contains(2))
            }
            assertBounded(result, limits)
        }
    }

    func testSeedAtExactDepthCapCannotEnumerateChildrenBeyondCap() throws {
        let provider = Provider([0: Node(role: "AXWindow", children: [1]),
                                 1: Node(role: "AXWebArea", children: [2], parent: 0, focused: true),
                                 2: Node(role: "AXStaticText", parent: 1, value: "past cap")])
        let preparation = provider.collect(focus: 1)
        _ = try XCTUnwrap(preparation.plan)
        let result = provider.run(limits: .init(maxDepth: 1), preparation: preparation)
        XCTAssertFalse(provider.pages.contains { $0.handle == 1 })
        XCTAssertFalse(provider.inspections.contains(2)); XCTAssertTrue(provider.textCalls.isEmpty)
        XCTAssertTrue(result.reasons.contains(.depthBudget)); XCTAssertFalse(result.complete)
    }

    func testSeededTextWithReportedChildrenRemainsLeafButExplicitlyPartial() throws {
        let provider = Provider([0: Node(role: "AXTextArea", children: [1], value: "anchor", focused: true),
                                 1: Node(role: "AXStaticText", parent: 0, value: "never read")])
        let preparation = provider.collect(focus: 0)
        _ = try XCTUnwrap(preparation.plan)
        let result = provider.run(preparation: preparation)
        XCTAssertEqual(provider.reads, [0]); XCTAssertTrue(provider.pages.isEmpty)
        XCTAssertTrue(result.reasons.contains(.inconsistentChildren)); XCTAssertFalse(result.complete)
    }

    func testChildCyclesDoNotReinspectKnownSeedsOrInventParentCycles() throws {
        let provider = simple()
        provider.nodes[1]?.children = [2, 0, 1]
        let preparation = provider.collect(focus: 2)
        _ = try XCTUnwrap(preparation.plan)
        let result = provider.run(preparation: preparation)
        XCTAssertEqual(provider.inspections.count, preparation.probes)
        XCTAssertEqual(provider.reads, [2])
        XCTAssertEqual(result.nodes.first { $0.handle == 2 }?.parent, 1)
        XCTAssertNil(result.nodes.first { $0.handle == 0 }?.parent)
        XCTAssertTrue(result.reasons.contains(.repeatedNode))
        XCTAssertFalse(result.complete)
    }

    func testEmptyAndWhitespaceCannotDisplaceNonemptyTextAtSmallOutputCap() throws {
        let provider = Provider([0: Node(role: "AXWindow", children: [1, 2, 3, 4, 5]),
                                 1: Node(role: "AXTextArea", parent: 0, value: "", focused: true),
                                 2: Node(role: "AXStaticText", parent: 0, value: ""),
                                 3: Node(role: "AXStaticText", parent: 0, value: " \n\t"),
                                 4: Node(role: "AXStaticText", parent: 0, value: "actual body"),
                                 5: Node(role: "AXStaticText", parent: 0, value: "\u{2003}")])
        let preparation = provider.collect(focus: 1)
        _ = try XCTUnwrap(preparation.plan)
        let limits = WeightedSurfaceTraversalLimits(maxOutputNodes: 2, maxWork: 96, maxProbes: 96)
        let result = provider.run(limits: limits, preparation: preparation)
        XCTAssertEqual(Set(provider.reads), Set(1...5))
        XCTAssertEqual(Set(result.nodes.map(\.handle)), Set([1, 4]))
        XCTAssertEqual(result.nodes.first { $0.handle == 1 }?.textRead?.text, "")
        XCTAssertTrue(result.reasons.contains(.outputBudget))
        assertBounded(result, limits)
    }

    func testUnfocusedEmptyEvidenceStillRetainedWhenThereIsRoom() throws {
        let provider = Provider([0: Node(role: "AXWindow", children: [1, 2], focused: true),
                                 1: Node(role: "AXStaticText", parent: 0, value: ""),
                                 2: Node(role: "AXStaticText", parent: 0, value: "body")])
        let preparation = provider.collect(focus: 0)
        _ = try XCTUnwrap(preparation.plan)
        let result = provider.run(preparation: preparation)
        XCTAssertEqual(result.nodes.first { $0.handle == 1 }?.textRead?.text, "")
        XCTAssertTrue(result.complete)
    }

    func testPreparationCostsCountAgainstRunAndExhaustionPreventsLateCallbacks() throws {
        let provider = simple()
        let preparation = provider.collect(focus: 2)
        _ = try XCTUnwrap(preparation.plan)
        let before = provider.inspections.count
        let limits = WeightedSurfaceTraversalLimits(maxWork: preparation.work, maxProbes: preparation.probes)
        let result = provider.run(limits: limits, preparation: preparation)
        XCTAssertEqual(result.counters.work, preparation.work)
        XCTAssertEqual(result.counters.probes, preparation.probes)
        XCTAssertEqual(provider.inspections.count, before)
        XCTAssertTrue(provider.pages.isEmpty)
        XCTAssertTrue(provider.textCalls.isEmpty)
        XCTAssertFalse(result.complete)
    }

    func testAlreadyExpiredAndBlockingCallbacksNeverPermitFollowupReads() throws {
        let expired = simple()
        let preparation = expired.collect(focus: 2)
        _ = try XCTUnwrap(preparation.plan)
        let before = expired.inspections.count
        let result = expired.run(preparation: preparation, shouldContinue: { false })
        XCTAssertEqual(expired.inspections.count, before)
        XCTAssertTrue(expired.pages.isEmpty)
        XCTAssertTrue(expired.textCalls.isEmpty)
        XCTAssertTrue(result.reasons.contains(.timeBudget))

        for phase in 0...2 {
            let provider = simple()
            var live = true
            if phase == 0 { provider.afterInspection = { live = false } }
            if phase == 1 { provider.afterPage = { live = false } }
            if phase == 2 { provider.afterText = { live = false } }
            let read = provider.run(shouldContinue: { live })
            XCTAssertTrue(read.reasons.contains(.timeBudget))
            if phase < 2 { XCTAssertTrue(provider.textCalls.isEmpty) }
            if phase == 0 { XCTAssertTrue(provider.pages.isEmpty) }
            if phase == 2 { XCTAssertFalse(read.nodes.contains { $0.textRead != nil }) }
        }
    }

    func testUnknownAndSensitiveBranchesCannotAuthorizeTheirDescendants() {
        let provider = Provider([0: Node(role: "AXWindow", children: [1, 2, 3]),
                                 1: Node(role: "AXMystery", children: [11], parent: 0),
                                 2: Node(role: "AXGroup", children: [12], parent: 0, denied: true),
                                 3: Node(role: "AXStaticText", children: [13], parent: 0, value: "leaf"),
                                 11: Node(role: "AXStaticText", parent: 1, value: "blocked"),
                                 12: Node(role: "AXStaticText", parent: 2, value: "blocked"),
                                 13: Node(role: "AXStaticText", parent: 3, value: "not a text descendant")])
        let result = provider.run()
        XCTAssertEqual(Set(provider.inspections), Set([0, 1, 2, 3]))
        XCTAssertEqual(provider.reads, [3])
        XCTAssertEqual(provider.pages.map(\.handle), [0])
        XCTAssertTrue(result.reasons.contains(.unsupportedRole))
        XCTAssertTrue(result.reasons.contains(.securityPruned))
        XCTAssertTrue(result.reasons.contains(.inconsistentChildren))
        XCTAssertFalse(result.complete)
    }

    func testRootedCertificateFreezesMetadataButNeverCachesTextPermission() throws {
        let provider = simple()
        let preparation = provider.collect(focus: 2)
        let plan = try XCTUnwrap(preparation.plan)
        let original = try XCTUnwrap(plan.nodes.last?.metadata)
        provider.nodes[2]?.denied = true
        provider.nodes[2]?.role = "AXSecureTextField"
        let result = provider.run(preparation: preparation)
        let focused = try XCTUnwrap(result.nodes.first { $0.handle == 2 })
        XCTAssertEqual(focused.metadata, original)
        XCTAssertEqual(focused.metadata.role, "AXTextArea")
        XCTAssertEqual(provider.textCalls, [2])
        XCTAssertTrue(provider.reads.isEmpty)
        XCTAssertNil(focused.textRead)
        XCTAssertTrue(result.reasons.contains(.providerRefused))
        XCTAssertFalse(result.complete)
    }

    func testRootedCertificateDoesNotBypassFreshChildrenSecurityGate() throws {
        let provider = simple()
        let preparation = provider.collect(focus: 2)
        _ = try XCTUnwrap(preparation.plan)
        provider.nodes[1]?.denied = true
        let result = provider.run(preparation: preparation)
        XCTAssertTrue(provider.pages.contains { $0.handle == 1 })
        XCTAssertNil(result.nodes.first { $0.handle == 2 }?.parent)
        XCTAssertTrue(result.reasons.contains(.securityPruned))
        XCTAssertTrue(result.reasons.contains(.anchorParentUnconfirmed))
        XCTAssertFalse(result.complete)
    }

    func testDeepElectronFocusAtDepth32AnchorsComposerAndSiblingChatBubbles() throws {
        // Simulates deep Electron/Feishu chat DOM: left nav + session WebArea + 32-hop chat composer.
        var nodes: [Int: Node] = [
            0: Node(role: "AXWindow", children: [1, 2, 3]),
            1: Node(role: "AXToolbar", children: Array(100..<140), parent: 0),
            2: Node(role: "AXWebArea", children: Array(200..<240), parent: 0),
        ]
        for id in 100..<140 { nodes[id] = Node(role: "AXButton", parent: 1) }
        for id in 200..<240 { nodes[id] = Node(role: "AXStaticText", parent: 2, value: "sidebar \(id)") }

        // Spine from depth 1 (id 3) down to depth 20 (id 22, chat pane split).
        for id in 3...21 {
            nodes[id] = Node(role: id == 10 ? "AXWebArea" : "AXGroup", children: [id + 1], parent: id == 3 ? 0 : id - 1)
        }
        // Split at depth 20 into message list (300) and deep composer branch (23...34).
        nodes[22] = Node(role: "AXGroup", children: [300, 23], parent: 21)
        nodes[300] = Node(role: "AXList", children: [301, 302, 303], parent: 22)
        nodes[301] = Node(role: "AXStaticText", parent: 300, value: "earlier message")
        nodes[302] = Node(role: "AXStaticText", parent: 300, value: "latest teammate reply")
        nodes[303] = Node(role: "AXStaticText", parent: 300, value: "just sent bubble")

        for id in 23...33 {
            nodes[id] = Node(role: "AXGroup", children: [id + 1], parent: id - 1)
        }
        // Focused AXTextArea at depth 32 (33 nodes in anchor chain > old 24-hop cap).
        nodes[34] = Node(role: "AXTextArea", parent: 33, value: "composer draft", focused: true)

        let provider = Provider(nodes)
        let preparation = SurfaceFocusAnchors.collect(
            root: 0,
            focus: 34,
            inspect: provider.inspect,
            parent: { nodes[$0]?.parent }
        )
        let plan = try XCTUnwrap(preparation.plan, "32-hop deep Electron focus must resolve an anchor plan")
        XCTAssertEqual(plan.nodes.count, 33)
        XCTAssertEqual(plan.nodes.first?.handle, 0)
        XCTAssertEqual(plan.nodes.last?.handle, 34)

        let limits = WeightedSurfaceTraversalLimits(maxOutputNodes: 48)
        let result = provider.run(limits: limits, preparation: preparation)
        XCTAssertTrue(result.nodes.contains { $0.handle == 34 && $0.textRead?.text == "composer draft" })
        XCTAssertTrue(result.nodes.contains { $0.handle == 303 && $0.textRead?.text == "just sent bubble" })
        XCTAssertTrue(result.nodes.contains { $0.handle == 302 && $0.textRead?.text == "latest teammate reply" })
        assertBounded(result, limits)
    }

    func testPaneHeaderBandCapturesChatTitleAheadOfDeepMessageListAndSkipsToolbar() throws {
        // Reproduces QQ / Feishu split-pane geometry:
        //   aio / chatContainer_contentWrapper (y=40, h=686)
        //     [0] chat-header (y=40, h=52) -> [0] title group -> AXButton("Project Alpha") + AXStaticText
        //                                  -> [1] AXToolbar (action icons that must not flood output)
        //     [1] chat-body (y=92, h=634) -> [0] 60 deep message bubbles, [1] composer (y=529, h=197) -> AXTextArea
        //     [2] group-sidebar (x=812, y=92, h=634)
        var nodes: [Int: Node] = [
            0: Node(role: "AXWindow", children: [1], bounds: .init(x: 0, y: 0, width: 996, height: 730)),
            1: Node(role: "AXWebArea", children: [2], parent: 0, bounds: .init(x: 0, y: 0, width: 996, height: 730)),
            2: Node(role: "AXGroup", children: [10, 20, 30], parent: 1, bounds: .init(x: 284, y: 40, width: 708, height: 686)),
            // Child 0: top header band (y=40..92, height=52)
            10: Node(role: "AXGroup", children: [11, 15], parent: 2, bounds: .init(x: 284, y: 40, width: 708, height: 52)),
            11: Node(role: "AXGroup", children: [12], parent: 10, bounds: .init(x: 300, y: 57, width: 444, height: 22)),
            12: Node(role: "AXButton", children: [13, 14], parent: 11, displayText: "Project Alpha", bounds: .init(x: 300, y: 57, width: 157, height: 22)),
            13: Node(role: "AXStaticText", parent: 12, value: "Project Alpha", bounds: .init(x: 302, y: 58, width: 115, height: 19)),
            14: Node(role: "AXStaticText", parent: 12, value: "(86)", bounds: .init(x: 422, y: 58, width: 33, height: 19)),
            15: Node(role: "AXToolbar", children: [16, 17, 18], parent: 10, bounds: .init(x: 760, y: 52, width: 220, height: 32)),
            16: Node(role: "AXButton", parent: 15, displayText: "语音通话", bounds: .init(x: 760, y: 52, width: 32, height: 32)),
            17: Node(role: "AXButton", parent: 15, displayText: "视频通话", bounds: .init(x: 796, y: 52, width: 32, height: 32)),
            18: Node(role: "AXButton", parent: 15, displayText: "屏幕共享", bounds: .init(x: 832, y: 52, width: 32, height: 32)),
            // Child 1: tall chat body (y=92, height=634 >= 200)
            20: Node(role: "AXGroup", children: [21, 25], parent: 2, bounds: .init(x: 284, y: 92, width: 528, height: 634)),
            21: Node(role: "AXList", children: Array(200..<260), parent: 20, bounds: .init(x: 284, y: 92, width: 528, height: 437)),
            // Composer area with its own 40px icon bar above AXTextArea (height=157 < 200, must NOT hijack header)
            25: Node(role: "AXGroup", children: [26, 27], parent: 20, bounds: .init(x: 284, y: 529, width: 528, height: 197)),
            26: Node(role: "AXGroup", children: [28], parent: 25, bounds: .init(x: 284, y: 529, width: 528, height: 40)),
            28: Node(role: "AXButton", parent: 26, displayText: "表情", bounds: .init(x: 290, y: 535, width: 24, height: 24)),
            27: Node(role: "AXTextArea", parent: 25, value: "draft message", bounds: .init(x: 284, y: 569, width: 528, height: 157), focused: true),
            // Child 2: right group sidebar (y=92..726, outside header band)
            30: Node(role: "AXList", children: Array(300..<330), parent: 2, bounds: .init(x: 812, y: 92, width: 180, height: 634)),
        ]
        for id in 200..<260 {
            nodes[id] = Node(role: "AXStaticText", parent: 21, value: "chat bubble \(id)", bounds: .init(x: 354, y: 200, width: 180, height: 16))
        }
        for id in 300..<330 {
            nodes[id] = Node(role: "AXStaticText", parent: 30, value: "member \(id)", bounds: .init(x: 820, y: 150, width: 100, height: 16))
        }

        let provider = Provider(nodes)
        let preparation = SurfaceFocusAnchors.collect(root: 0, focus: 27, inspect: provider.inspect, parent: { nodes[$0]?.parent })
        _ = try XCTUnwrap(preparation.plan)
        let limits = WeightedSurfaceTraversalLimits(maxOutputNodes: 24, pageSize: 16)
        let result = provider.run(limits: limits, preparation: preparation)

        // Both focused composer and top pane header title must be captured and retained ahead of 60 bubbles.
        XCTAssertTrue(result.nodes.contains { $0.handle == 27 && $0.textRead?.text == "draft message" })
        XCTAssertTrue(result.nodes.contains { ($0.handle == 12 || $0.handle == 13) && ($0.textRead?.text == "Project Alpha" || $0.metadata.displayText == "Project Alpha") })
        // Latest chat bubbles must still be captured alongside the header.
        XCTAssertTrue(result.nodes.contains { $0.handle == 259 && $0.textRead?.text == "chat bubble 259" })
        // Header toolbar action icons must not crowd out the snapshot.
        XCTAssertFalse(result.nodes.contains { $0.handle == 16 || $0.handle == 17 || $0.handle == 18 })
        assertBounded(result, limits)

        // Under a tight output cap, the true pane header (rank 1) must outrank the short composer icon bar ("表情", rank 2),
        // proving the 157px composer did not hijack PaneHeaderBand from the 634px chat pane.
        let tightLimits = WeightedSurfaceTraversalLimits(maxOutputNodes: 3, maxWork: 128, maxProbes: 96, pageSize: 16)
        let tightResult = provider.run(limits: tightLimits, preparation: preparation)
        XCTAssertTrue(tightResult.nodes.contains { $0.handle == 27 && $0.textRead?.text == "draft message" })
        XCTAssertTrue(tightResult.nodes.contains { ($0.handle == 12 || $0.handle == 13) && ($0.textRead?.text == "Project Alpha" || $0.metadata.displayText == "Project Alpha") })
        XCTAssertFalse(tightResult.nodes.contains { $0.handle == 28 })
        assertBounded(tightResult, tightLimits)
    }

    func testPaneHeaderBandPreservesCompletenessOnSmallWindowTrees() throws {
        let nodes: [Int: Node] = [
            0: Node(role: "AXWindow", children: [1, 2], bounds: .init(x: 0, y: 0, width: 600, height: 500)),
            1: Node(role: "AXGroup", children: [10], parent: 0, bounds: .init(x: 0, y: 0, width: 600, height: 48)),
            10: Node(role: "AXStaticText", parent: 1, value: "Direct Message", bounds: .init(x: 16, y: 12, width: 120, height: 20)),
            2: Node(role: "AXGroup", children: [20], parent: 0, bounds: .init(x: 0, y: 48, width: 600, height: 452)),
            20: Node(role: "AXTextArea", parent: 2, value: "hello", bounds: .init(x: 16, y: 420, width: 560, height: 60), focused: true),
        ]
        let provider = Provider(nodes)
        let preparation = SurfaceFocusAnchors.collect(root: 0, focus: 20, inspect: provider.inspect, parent: { nodes[$0]?.parent })
        _ = try XCTUnwrap(preparation.plan)
        let result = provider.run(limits: WeightedSurfaceTraversalLimits(maxOutputNodes: 48), preparation: preparation)
        XCTAssertTrue(result.complete, "Small window with pane header must remain complete")
        XCTAssertTrue(result.nodes.contains { $0.handle == 10 && $0.textRead?.text == "Direct Message" })
        XCTAssertTrue(result.nodes.contains { $0.handle == 20 && $0.textRead?.text == "hello" })
    }
}

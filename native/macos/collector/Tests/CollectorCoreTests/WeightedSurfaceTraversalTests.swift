import XCTest
@testable import CollectorCore

final class WeightedSurfaceTraversalTests: XCTestCase {
    private struct Node {
        var role = "AXGroup"
        var children: [Int] = []
        var count: Int?
        var focused = false
        var denied: WeightedSurfaceTraversalReason?
        var value: String? = nil
    }

    /// Tests call the production planner, never a duplicate traversal algorithm.
    private final class Provider {
        var nodes: [Int: Node]
        var inspections: [Int] = []
        var pages: [(Int, Int, Int)] = []
        var reads: [Int] = []
        var childOverride: ((Int, Int, Int) -> WeightedSurfaceChildrenRead<Int>)?
        var afterInspect: (() -> Void)?
        var afterChildren: (() -> Void)?
        var afterText: (() -> Void)?

        init(_ nodes: [Int: Node]) { self.nodes = nodes }

        func run(_ limits: WeightedSurfaceTraversalLimits = .init(),
                 shouldContinue: () -> Bool = { true }) -> WeightedSurfaceTraversalResult<Int> {
            WeightedSurfaceTraversal.run(root: 0, limits: limits, inspect: { id in
                self.inspections.append(id)
                self.afterInspect?()
                guard let node = self.nodes[id] else { return .pruned(.providerRefused) }
                if let denied = node.denied { return .pruned(denied) }
                return .allowed(.init(role: node.role, childCount: node.count ?? node.children.count,
                                      isFocused: node.focused, observedAtMs: Int64(100 + id)))
            }, children: { id, offset, limit in
                self.pages.append((id, offset, limit))
                self.afterChildren?()
                if let override = self.childOverride { return override(id, offset, limit) }
                guard let node = self.nodes[id] else { return .unavailable(.providerRefused) }
                return .values(Array(node.children.dropFirst(offset).prefix(limit)))
            }, text: { id in
                self.reads.append(id)
                self.afterText?()
                guard let node = self.nodes[id], let value = node.value else { return nil }
                return SurfaceNodeRead(id: "node-\(id)", role: node.role, text: value, observedAtMs: Int64(500 + id))
            }, shouldContinue: shouldContinue)
        }
    }

    private func assertValidForest(_ result: WeightedSurfaceTraversalResult<Int>, file: StaticString = #filePath, line: UInt = #line) {
        let handles = Set(result.nodes.map(\.handle))
        XCTAssertEqual(handles.count, result.nodes.count, file: file, line: line)
        let parents = Dictionary(uniqueKeysWithValues: result.nodes.compactMap { node in node.parent.map { (node.handle, $0) } })
        for node in result.nodes {
            var seen: Set<Int> = [node.handle]
            var current = node.parent
            while let parent = current {
                XCTAssertTrue(handles.contains(parent), file: file, line: line)
                guard seen.insert(parent).inserted else {
                    XCTFail("Output parent cycle", file: file, line: line)
                    break
                }
                current = parents[parent]
            }
        }
    }

    func testWideFirstBranchDoesNotStarveSiblingText() {
        var nodes: [Int: Node] = [0: Node(children: [1, 2]), 1: Node(children: Array(10..<110)),
                                  2: Node(role: "AXStaticText", value: "important sibling")]
        for id in 10..<110 { nodes[id] = Node(role: "AXStaticText", value: "synthetic \(id)") }
        let provider = Provider(nodes)
        let result = provider.run(.init(maxWork: 40))
        XCTAssertTrue(provider.reads.contains(2))
        XCTAssertLessThan(provider.inspections.firstIndex(of: 2) ?? Int.max, 10)
        XCTAssertTrue(result.nodes.contains { $0.handle == 2 && $0.textRead?.text == "important sibling" })
        XCTAssertLessThanOrEqual(result.counters.work, 40)
        XCTAssertEqual(result.counters.maxFanout, 100)
        XCTAssertGreaterThanOrEqual(result.counters.maxDepth, 1)
        XCTAssertEqual(result.counters.inspectedChildren, 102, "Only inspected root and branch child counts, not a fabricated whole-tree total")
        XCTAssertFalse(result.complete)
        assertValidForest(result)
    }

    func testDeniedRootHasNoChildrenOrTextCallbacks() {
        let provider = Provider([0: Node(role: "AXTextField", children: [1], denied: .securityPruned, value: "never read"),
                                 1: Node(role: "AXStaticText", value: "never reached")])
        let result = provider.run()
        XCTAssertEqual(provider.inspections, [0])
        XCTAssertTrue(provider.pages.isEmpty)
        XCTAssertTrue(provider.reads.isEmpty)
        XCTAssertTrue(result.nodes.isEmpty)
        XCTAssertEqual(result.reasons, [.securityPruned])
        XCTAssertEqual(result.counters.work, 1)
    }

    func testUnknownAndSensitiveRolesNeverReadOrTraverse() {
        for role in ["AXUnknown", "AXUnreviewedWrapper", "AXSecureTextField", "AXPasswordField", "AXProtectedContent"] {
            let provider = Provider([0: Node(role: role, children: [1], value: "never read"), 1: Node()])
            let result = provider.run()
            XCTAssertNil(WeightedSurfaceTraversal.rolePolicy(for: role))
            XCTAssertTrue(provider.pages.isEmpty)
            XCTAssertTrue(provider.reads.isEmpty)
            XCTAssertEqual(result.reasons, [.unsupportedRole])
        }
    }

    func testTextRolesNeverAuthorizeChildrenEvenIfProviderReportsThem() {
        for role in ["AXTextField", "AXTextArea", "AXStaticText"] {
            let provider = Provider([0: Node(role: role, children: [1], value: "allowed text"),
                                     1: Node(role: "AXStaticText", value: "must not traverse")])
            let result = provider.run()
            XCTAssertEqual(provider.inspections, [0])
            XCTAssertEqual(provider.reads, [0])
            XCTAssertTrue(provider.pages.isEmpty)
            XCTAssertEqual(result.nodes.first?.textRead?.text, "allowed text")
            XCTAssertEqual(result.reasons, [.inconsistentChildren])
            XCTAssertFalse(result.complete)
        }
    }

    func testReviewedCompositesTraverseButNeverReadValues() {
        for role in ["AXButton", "AXToolbar", "AXPopUpButton", "AXCheckBox", "AXLink", "AXTabGroup", "AXRadioGroup"] {
            let provider = Provider([0: Node(role: role, children: [1], value: "composite value forbidden"),
                                     1: Node(role: "AXStaticText", value: "permitted child")])
            let result = provider.run()
            XCTAssertEqual(provider.reads, [1])
            XCTAssertNil(result.nodes.first?.textRead)
            XCTAssertEqual(WeightedSurfaceTraversal.rolePolicy(for: role), .composite)
            XCTAssertTrue(result.complete)
        }
    }

    func testMalformedChildCountsPruneBeforeAnyFurtherCallback() {
        for count in [-1, Int.min, 1_000_001, Int.max] {
            let provider = Provider([0: Node(count: count)])
            let result = provider.run()
            XCTAssertEqual(result.reasons, [.invalidChildCount])
            XCTAssertTrue(provider.pages.isEmpty)
            XCTAssertTrue(provider.reads.isEmpty)
            XCTAssertTrue(result.nodes.isEmpty)
        }
    }

    func testTextOutputSurvivesWrapperCountAboveOutputCapWithoutFakeParents() {
        var nodes: [Int: Node] = [:]
        for id in 0..<30 { nodes[id] = Node(children: [id + 1]) }
        nodes[30] = Node(role: "AXStaticText", value: "retained")
        let provider = Provider(nodes)
        let result = provider.run(.init(maxOutputNodes: 4, maxWork: 192, maxProbes: 192))
        XCTAssertEqual(Set(result.nodes.map(\.handle)), Set([27, 28, 29, 30]))
        XCTAssertNil(result.nodes.first?.parent)
        XCTAssertEqual(result.nodes.last?.parent, 29)
        XCTAssertEqual(result.nodes.last?.textRead?.text, "retained")
        XCTAssertTrue(result.reasons.contains(.outputBudget))
        XCTAssertFalse(result.complete)
        assertValidForest(result)
    }

    func testProbeWeightedPendingAndDepthBudgetsReportFiniteReasons() {
        let graph: [Int: Node] = [0: Node(children: [1, 2]), 1: Node(children: [3]), 2: Node(), 3: Node()]
        let probe = Provider(graph).run(.init(maxProbes: 1))
        XCTAssertEqual(probe.counters.probes, 1)
        XCTAssertTrue(probe.reasons.contains(.probeBudget))
        let work = Provider(graph).run(.init(maxWork: 1))
        XCTAssertEqual(work.counters.work, 1)
        XCTAssertTrue(work.reasons.contains(.workBudget))
        let pending = Provider(graph).run(.init(maxPending: 1))
        XCTAssertLessThanOrEqual(pending.counters.peakPending, 1)
        XCTAssertTrue(pending.reasons.contains(.pendingBudget))
        let depth = Provider(graph).run(.init(maxDepth: 0))
        XCTAssertTrue(depth.reasons.contains(.depthBudget))
        for result in [probe, work, pending, depth] {
            XCTAssertFalse(result.complete)
            XCTAssertLessThanOrEqual(result.reasons.count, WeightedSurfaceTraversalReason.allCases.count)
        }
    }

    func testEmergencyDepthNeverTraversesPast64() {
        var nodes: [Int: Node] = [:]
        for id in 0..<70 { nodes[id] = Node(children: [id + 1]) }
        nodes[70] = Node(role: "AXStaticText", value: "too deep")
        let provider = Provider(nodes)
        let result = provider.run(.init(maxOutputNodes: 96, maxWork: 384, maxProbes: 384, maxDepth: Int.max))
        XCTAssertEqual(provider.inspections.max(), 64)
        XCTAssertTrue(provider.reads.isEmpty)
        XCTAssertTrue(result.reasons.contains(.depthBudget))
    }

    func testProviderRefusalsAndShortOrOversizedPagesArePartial() {
        let missing = Provider([:]).run()
        XCTAssertEqual(missing.reasons, [.providerRefused])
        let unavailable = Provider([0: Node(children: [1]), 1: Node()])
        unavailable.childOverride = { _, _, _ in .unavailable(.providerRefused) }
        XCTAssertEqual(unavailable.run().reasons, [.providerRefused])
        XCTAssertEqual(unavailable.inspections, [0])
        for response: [Int] in [[], [1, 2, 3]] {
            let malformed = Provider([0: Node(children: [1]), 1: Node()])
            malformed.childOverride = { _, _, _ in .values(response) }
            let result = malformed.run()
            XCTAssertEqual(result.reasons, [.inconsistentChildren])
            XCTAssertFalse(result.complete)
        }
        let noText = Provider([0: Node(role: "AXTextArea")]).run()
        XCTAssertEqual(noText.reasons, [.providerRefused])
    }

    func testIgnoredSubrolesPruneSubtreeAndPUAStaticTextSkipsOutputSlots() {
        struct SubNode {
            var role = "AXGroup"
            var subrole: String? = nil
            var children: [Int] = []
            var text: String? = nil
        }
        let graph: [Int: SubNode] = [
            0: SubNode(role: "AXWindow", children: [1, 2, 3, 4]),
            1: SubNode(role: "AXGroup", subrole: "AXApplicationStatus", children: [10, 11]),
            10: SubNode(role: "AXStaticText", text: "WakaTime"),
            11: SubNode(role: "AXStaticText", text: "GitLens"),
            2: SubNode(role: "AXStaticText", text: "\u{EBB1}"),
            3: SubNode(role: "AXStaticText", text: " \u{EA60} "),
            4: SubNode(role: "AXStaticText", text: "Real code line"),
        ]
        var inspected: [Int] = []
        var childPages: [Int] = []
        let result = WeightedSurfaceTraversal.run(
            root: 0,
            limits: .init(maxOutputNodes: 2, maxWork: 64, maxProbes: 64),
            ignoredSubroles: ["AXApplicationStatus"],
            inspect: { id in
                inspected.append(id)
                guard let node = graph[id] else { return .pruned(.providerRefused) }
                return .allowed(.init(role: node.role, childCount: node.children.count, observedAtMs: Int64(id), subrole: node.subrole))
            },
            children: { id, offset, limit in
                childPages.append(id)
                guard let node = graph[id] else { return .unavailable(.providerRefused) }
                return .values(Array(node.children.dropFirst(offset).prefix(limit)))
            },
            text: { id in
                guard let text = graph[id]?.text else { return nil }
                return SurfaceNodeRead(id: "n-\(id)", role: "text", text: text, observedAtMs: Int64(id))
            }
        )
        XCTAssertFalse(childPages.contains(1), "Ignored subrole container must never fetch children")
        XCTAssertFalse(inspected.contains(10))
        XCTAssertFalse(inspected.contains(11))
        XCTAssertEqual(result.nodes.compactMap { $0.textRead?.text }, ["Real code line"])
        XCTAssertFalse(result.reasons.contains(.outputBudget), "Skipped PUA leaves must not burn output slots or trigger outputBudget")
        assertValidForest(result)
    }

    func testCollapseEmptyContainersOmitsEmptyWrappersAndReparentsChildrenCleanly() {
        struct Node {
            let role: String
            let children: [Int]
            let displayText: String?
            let text: String?
            let isFocused: Bool
            init(role: String, children: [Int] = [], displayText: String? = nil, text: String? = nil, isFocused: Bool = false) {
                self.role = role
                self.children = children
                self.displayText = displayText
                self.text = text
                self.isFocused = isFocused
            }
        }
        // Window(0) -> Group(1) -> Group(2) -> WebArea(3, labeled) -> Group(4) -> Group(5) -> StaticText(6) & Focused TextArea(7)
        let graph: [Int: Node] = [
            0: Node(role: "AXWindow", children: [1]),
            1: Node(role: "AXGroup", children: [2]),
            2: Node(role: "AXGroup", children: [3]),
            3: Node(role: "AXWebArea", children: [4], displayText: "workspace — main.swift"),
            4: Node(role: "AXGroup", children: [5]),
            5: Node(role: "AXScrollArea", children: [6, 7]),
            6: Node(role: "AXStaticText", text: "main.swift"),
            7: Node(role: "AXTextArea", text: "let x = 1", isFocused: true),
        ]
        let result = WeightedSurfaceTraversal.run(
            root: 0,
            limits: .init(maxOutputNodes: 4, maxWork: 64, maxProbes: 64),
            collapseEmptyContainers: true,
            inspect: { id in
                guard let node = graph[id] else { return .pruned(.providerRefused) }
                return .allowed(.init(role: node.role, childCount: node.children.count, isFocused: node.isFocused, observedAtMs: Int64(id), displayText: node.displayText))
            },
            children: { id, offset, limit in
                guard let node = graph[id] else { return .unavailable(.providerRefused) }
                return .values(Array(node.children.dropFirst(offset).prefix(limit)))
            },
            text: { id in
                guard let text = graph[id]?.text else { return nil }
                return SurfaceNodeRead(id: "n-\(id)", role: "text", text: text, observedAtMs: Int64(id))
            }
        )
        let handles = result.nodes.map(\.handle)
        XCTAssertEqual(handles, [0, 3, 6, 7], "Empty AXGroup/AXScrollArea wrappers must be collapsed out of output")
        XCTAssertFalse(result.reasons.contains(.outputBudget), "Collapsing empty wrappers must not flag outputBudget")
        let byHandle = Dictionary(uniqueKeysWithValues: result.nodes.map { ($0.handle, $0) })
        XCTAssertEqual(byHandle[3]?.parent, 0, "WebArea must re-parent past empty wrappers directly to AXWindow")
        XCTAssertEqual(byHandle[6]?.parent, 3, "StaticText must re-parent past empty wrappers directly to WebArea")
        XCTAssertEqual(byHandle[7]?.parent, 3, "Focused TextArea must re-parent past empty wrappers directly to WebArea")
        assertValidForest(result)
    }

}

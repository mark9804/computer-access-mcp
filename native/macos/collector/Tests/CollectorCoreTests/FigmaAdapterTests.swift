import XCTest
@testable import CollectorCore

private struct FigmaMockNode {
    var role: String = "AXGroup"
    var subrole: TextSecurityGate.SubroleRead = .noValue
    var protectedContent: TextSecurityGate.ProtectedContentRead = .value(false)
    var children: [Int] = []
    var parent: Int? = nil
    var text: String? = nil
    var reportedLength: Int? = nil
    var isFocused: Bool = false
    var isEnabled: Bool? = nil
    var displayText: String? = nil
    var windowTitle: String? = nil
    var bounds: SurfaceAbsoluteRect? = nil
    var identifier: String? = nil
    var label: String? = nil
}

private final class FigmaMockBackend: AXSurfaceBackend {
    var nodes: [Int: FigmaMockNode]
    var windowRect: SurfaceAbsoluteRect? = SurfaceAbsoluteRect(x: 0, y: 0, width: 1920, height: 1250)
    var inspectedIndices: [Int] = []
    var childRequests: [(index: Int, offset: Int, limit: Int)] = []
    var textReads: [Int] = []

    init(_ nodes: [Int: FigmaMockNode]) {
        self.nodes = nodes
    }

    func verifyDesktopAndApplication() -> SurfaceReadFailure? { nil }

    func inspectBackendNode(_ index: Int, isRoot: Bool) -> AXBackendInspection {
        inspectedIndices.append(index)
        guard let node = nodes[index] else { return .pruned(.providerRefused) }
        return .allowed(
            role: node.role,
            subrole: node.subrole,
            protectedContent: node.protectedContent,
            childCount: node.children.count,
            isFocused: node.isFocused,
            observedAtMs: Int64(2_000 + index),
            isEnabled: node.isEnabled,
            displayText: node.displayText,
            windowTitle: isRoot ? node.windowTitle : nil,
            absoluteRect: node.bounds,
            identifier: node.identifier,
            label: node.label
        )
    }

    func parentBackendNode(of index: Int) -> Int? {
        nodes[index]?.parent
    }

    func childrenBackendPage(of index: Int, expectedRole: String, offset: Int, limit: Int) -> WeightedSurfaceChildrenRead<Int> {
        childRequests.append((index, offset, limit))
        guard let node = nodes[index], node.role == expectedRole else {
            return .unavailable(.securityPruned)
        }
        return .values(Array(node.children.dropFirst(offset).prefix(limit)))
    }

    func readBackendNodeText(_ index: Int, expectedRole: String, maxUnits: Int, staticTextProbe: StaticTextPolicy) -> AXBackendTextRead {
        textReads.append(index)
        guard let node = nodes[index], let raw = node.text else {
            return .unavailable(reasons: ["node-text-unavailable"])
        }
        let declared = node.reportedLength ?? raw.utf16.count
        if expectedRole == "AXStaticText" && declared == 0 {
            switch staticTextProbe {
            case .standard:
                return .text(value: "", complete: true, reasons: [])
            case .boundedRangeProbe(let limit):
                let cap = min(maxUnits, limit)
                let slice = boundedUTF16Slice(raw, start: 0, length: min(raw.utf16.count, cap)) ?? ""
                return .text(value: slice, complete: false, reasons: ["static-text-length-unverified"])
            }
        }
        let slice = boundedUTF16Slice(raw, start: 0, length: min(raw.utf16.count, maxUnits)) ?? ""
        let complete = slice.utf16.count == raw.utf16.count
        return .text(value: slice, complete: complete, reasons: complete ? [] : ["text-budget"])
    }

    func readBackendNodeBounds(_ index: Int, windowRect: SurfaceAbsoluteRect) -> (SurfaceBounds, Int64)? {
        guard let rect = nodes[index]?.bounds, let rel = rect.relative(to: windowRect) else { return nil }
        return (rel, 2_050)
    }

    func readBackendWindowRect() -> SurfaceAbsoluteRect? { windowRect }

    func verifyFinalSurfaceBoundary() -> SurfaceReadFailure? { nil }
}

final class FigmaAdapterTests: XCTestCase {
    private let clock = FakeClock()
    private let figmaApp = ApplicationIdentity(applicationId: "com.figma.Desktop", processId: 900, processStartTime: "birth")
    private let figmaPolicy = CapturePolicy(
        allowedApplicationIds: ["com.figma.Desktop"],
        captureScope: "window",
        fieldSecurity: "denylist"
    )

    private func assertValidForest(_ tree: SurfaceCapturedTree, file: StaticString = #filePath, line: UInt = #line) {
        let ids = Set(tree.nodes.map(\.id))
        XCTAssertEqual(ids.count, tree.nodes.count, file: file, line: line)
        let byId = Dictionary(uniqueKeysWithValues: tree.nodes.map { ($0.id, $0) })
        for node in tree.nodes {
            var seen: Set<String> = [node.id]
            var current = node.parentId
            while let parentId = current {
                XCTAssertTrue(ids.contains(parentId), "Missing parent \(parentId)", file: file, line: line)
                guard seen.insert(parentId).inserted else {
                    XCTFail("Cycle detected in parent graph", file: file, line: line)
                    break
                }
                current = byId[parentId]?.parentId
            }
        }
    }

    func testFigmaAdapterExtractsFourZonesFromEightLevelElectronShellAndPrunesNoise() {
        var nodes: [Int: FigmaMockNode] = [:]

        // 8-level outer Electron shell: AXWindow(0) -> AXGroup(1..6) -> AXScrollArea(7) -> [WebArea #0(10), WebArea #1(20)]
        nodes[0] = FigmaMockNode(
            role: "AXWindow",
            children: [1],
            windowTitle: "Arco Design System – Figma",
            bounds: SurfaceAbsoluteRect(x: 0, y: 0, width: 1920, height: 1250)
        )
        for depth in 1...6 {
            nodes[depth] = FigmaMockNode(role: "AXGroup", children: [depth + 1], parent: depth - 1)
        }
        nodes[7] = FigmaMockNode(role: "AXScrollArea", children: [10, 20], parent: 6)

        // WebArea #0: Top Tab Bar [0, 0, 1920, 38]
        nodes[10] = FigmaMockNode(
            role: "AXWebArea",
            children: [11],
            parent: 7,
            displayText: "Figma",
            bounds: SurfaceAbsoluteRect(x: 0, y: 0, width: 1920, height: 38),
            label: "Figma"
        )
        nodes[11] = FigmaMockNode(role: "AXTabGroup", children: [12, 13, 14, 15, 16], parent: 10, label: "Tab bar")
        nodes[12] = FigmaMockNode(
            role: "AXRadioButton",
            parent: 11,
            displayText: "Arco Design System",
            bounds: SurfaceAbsoluteRect(x: 80, y: 4, width: 180, height: 30),
            label: "Arco Design System"
        )
        nodes[13] = FigmaMockNode(
            role: "AXTabButton",
            parent: 11,
            displayText: "Mobile Checkout Flow",
            bounds: SurfaceAbsoluteRect(x: 268, y: 4, width: 180, height: 30),
            label: "Mobile Checkout Flow"
        )
        nodes[14] = FigmaMockNode(
            role: "AXTabButton",
            parent: 11,
            displayText: "Close tab",
            bounds: SurfaceAbsoluteRect(x: 240, y: 8, width: 16, height: 16),
            label: "Close tab"
        )
        nodes[15] = FigmaMockNode(
            role: "AXTabButton",
            parent: 11,
            displayText: "New file",
            bounds: SurfaceAbsoluteRect(x: 456, y: 8, width: 24, height: 24),
            label: "New file"
        )
        nodes[16] = FigmaMockNode(
            role: "AXRadioButton",
            parent: 11,
            displayText: "Open tabs and recently closed items",
            bounds: SurfaceAbsoluteRect(x: 488, y: 8, width: 24, height: 24),
            label: "Open tabs and recently closed items"
        )

        // WebArea #1: Main Document [0, 38, 1920, 1212]
        let mainWebDisplay = SafeAXDisplayText.compose(
            role: "AXWebArea",
            title: "Arco Design System – Figma",
            description: nil,
            url: "https://www.figma.com/design/abc123/Arco-Design-System",
            maxUnits: 256
        )
        nodes[20] = FigmaMockNode(
            role: "AXWebArea",
            children: [21],
            parent: 7,
            displayText: mainWebDisplay,
            bounds: SurfaceAbsoluteRect(x: 0, y: 38, width: 1920, height: 1212),
            label: "Arco Design System – Figma"
        )
        // Main layout container with Left Sidebar(300), LandmarkMain(100), Right Sidebar(200), and bottom toolbelts(90, 91).
        nodes[21] = FigmaMockNode(role: "AXGroup", children: [300, 100, 200, 90, 91], parent: 20)
        nodes[90] = FigmaMockNode(role: "AXToolbar", children: [92], parent: 21, label: "Editor")
        nodes[92] = FigmaMockNode(role: "AXButton", parent: 90, displayText: "Rectangle", label: "Rectangle")
        nodes[91] = FigmaMockNode(role: "AXToolbar", children: [93], parent: 21, label: "Help/zoom toolbar")
        nodes[93] = FigmaMockNode(role: "AXButton", parent: 91, displayText: "Zoom help", label: "Zoom help")

        // Zone 2: AXLandmarkMain (virtualized canvas selection hierarchy)
        nodes[100] = FigmaMockNode(
            role: "AXGroup",
            subrole: .value("AXLandmarkMain"),
            children: [101],
            parent: 21,
            bounds: SurfaceAbsoluteRect(x: 240, y: 38, width: 1440, height: 1212),
            label: "Figma Design, 1 item selected"
        )
        nodes[101] = FigmaMockNode(role: "AXGroup", children: [102], parent: 100)
        nodes[102] = FigmaMockNode(
            role: "AXGroup",
            subrole: .value("AXApplicationGroup"),
            children: [103, 104, 105, 106],
            parent: 101,
            label: "item-list-2nd-level, Design frame"
        )
        nodes[103] = FigmaMockNode(role: "AXStaticText", parent: 102, text: "Dimensions", reportedLength: 0)
        nodes[104] = FigmaMockNode(role: "AXStaticText", parent: 102, text: "200 Fill × 32 Hug", reportedLength: 0)
        nodes[105] = FigmaMockNode(role: "AXStaticText", parent: 102, text: "\u{EBB1}", reportedLength: 0)
        nodes[106] = FigmaMockNode(
            role: "AXGroup",
            subrole: .value("AXApplicationGroup"),
            children: [107],
            parent: 102,
            isFocused: true,
            label: "treenode/2nd-level, Component instance"
        )
        nodes[107] = FigmaMockNode(role: "AXStaticText", parent: 106, text: "176 Fill × 32 Hug", reportedLength: 0)

        // Zone 3: Right Sidebar (Design/Prototype Inspector + 13 chrome noise controls + zero-size + slider)
        let rightNoiseLabels = [
            "Apply variable", "Add fill", "Add stroke", "Add effect",
            "Add layout guide", "Add export settings", "Resize handle",
            "Select matching layers", "More actions", "Present",
            "Share", "Help", "Multiplayer tools",
        ]
        var rightChildren = [201, 202, 203, 204, 205, 206, 208, 209, 210, 211, 212]
        for idx in rightNoiseLabels.indices {
            rightChildren.append(250 + idx)
        }
        nodes[200] = FigmaMockNode(
            role: "AXGroup",
            subrole: .value("AXLandmarkRegion"),
            children: rightChildren,
            parent: 21,
            bounds: SurfaceAbsoluteRect(x: 1680, y: 38, width: 240, height: 1212),
            label: "Right sidebar"
        )
        nodes[201] = FigmaMockNode(role: "AXRadioButton", parent: 200, displayText: "Design", bounds: SurfaceAbsoluteRect(x: 1690, y: 48, width: 60, height: 24), label: "Design")
        nodes[202] = FigmaMockNode(role: "AXRadioButton", parent: 200, displayText: "Prototype", bounds: SurfaceAbsoluteRect(x: 1756, y: 48, width: 72, height: 24), label: "Prototype")
        nodes[203] = FigmaMockNode(role: "AXButton", parent: 200, displayText: "73%", bounds: SurfaceAbsoluteRect(x: 1850, y: 48, width: 44, height: 24), label: "73%")
        nodes[204] = FigmaMockNode(role: "AXHeading", parent: 200, displayText: "TreeNode", bounds: SurfaceAbsoluteRect(x: 1690, y: 92, width: 180, height: 22), label: "TreeNode")
        nodes[205] = FigmaMockNode(role: "AXStaticText", parent: 200, text: "From this file", reportedLength: 0, bounds: SurfaceAbsoluteRect(x: 1690, y: 118, width: 120, height: 18))
        nodes[206] = FigmaMockNode(role: "AXComboBox", children: [207], parent: 200, bounds: SurfaceAbsoluteRect(x: 1690, y: 150, width: 180, height: 28), label: "Level")
        nodes[207] = FigmaMockNode(role: "AXStaticText", parent: 206, text: "2nd-level", reportedLength: 0, bounds: SurfaceAbsoluteRect(x: 1760, y: 154, width: 90, height: 20))
        nodes[208] = FigmaMockNode(role: "AXCheckBox", parent: 200, bounds: SurfaceAbsoluteRect(x: 1690, y: 186, width: 120, height: 24), label: "Show icon")
        nodes[209] = FigmaMockNode(role: "AXTextField", parent: 200, text: "200", bounds: SurfaceAbsoluteRect(x: 1690, y: 218, width: 64, height: 24), label: "Width")
        nodes[210] = FigmaMockNode(
            role: "AXButton",
            parent: 200,
            displayText: "Color Variable text/1 with value #1D2129 · 100%",
            bounds: SurfaceAbsoluteRect(x: 1690, y: 260, width: 210, height: 28),
            label: "Color Variable text/1 with value #1D2129 · 100%"
        )
        // Zero-size hidden inspector leaf and AXSlider must be pruned.
        nodes[211] = FigmaMockNode(role: "AXStaticText", parent: 200, text: "Hidden zero-size text", reportedLength: 0, bounds: SurfaceAbsoluteRect(x: 1690, y: 300, width: 0, height: 0))
        nodes[212] = FigmaMockNode(role: "AXSlider", parent: 200, bounds: SurfaceAbsoluteRect(x: 1690, y: 320, width: 120, height: 16), label: "Opacity slider")
        for (idx, noiseLabel) in rightNoiseLabels.enumerated() {
            nodes[250 + idx] = FigmaMockNode(
                role: "AXButton",
                parent: 200,
                displayText: noiseLabel,
                bounds: SurfaceAbsoluteRect(x: 1880, y: Double(100 + idx * 20), width: 24, height: 24),
                label: noiseLabel
            )
        }

        // Zone 4: Left Sidebar (file header + Pages AXTable + virtualized Layers AXColumn + Navigation Bar toolbar + chrome buttons)
        nodes[300] = FigmaMockNode(
            role: "AXGroup",
            subrole: .value("AXLandmarkRegion"),
            children: [301, 302, 303, 304, 305, 306, 310, 320],
            parent: 21,
            bounds: SurfaceAbsoluteRect(x: 0, y: 38, width: 240, height: 1212),
            label: "Left sidebar"
        )
        nodes[301] = FigmaMockNode(role: "AXToolbar", children: [307], parent: 300, bounds: SurfaceAbsoluteRect(x: 0, y: 38, width: 240, height: 36), label: "Navigation Bar")
        nodes[307] = FigmaMockNode(role: "AXButton", parent: 301, displayText: "Nav noise", label: "Nav noise")
        nodes[302] = FigmaMockNode(role: "AXButton", parent: 300, displayText: "Minimize UI", bounds: SurfaceAbsoluteRect(x: 200, y: 44, width: 24, height: 24), label: "Minimize UI")
        nodes[303] = FigmaMockNode(role: "AXButton", parent: 300, displayText: "Collapse layers", bounds: SurfaceAbsoluteRect(x: 170, y: 80, width: 24, height: 24), label: "Collapse layers")
        nodes[304] = FigmaMockNode(role: "AXButton", parent: 300, displayText: "Find", bounds: SurfaceAbsoluteRect(x: 140, y: 80, width: 24, height: 24), label: "Find")
        nodes[305] = FigmaMockNode(role: "AXButton", parent: 300, displayText: "Add new page", bounds: SurfaceAbsoluteRect(x: 200, y: 108, width: 24, height: 24), label: "Add new page")
        nodes[306] = FigmaMockNode(role: "AXHeading", parent: 300, displayText: "Arco File Header", bounds: SurfaceAbsoluteRect(x: 12, y: 52, width: 160, height: 24), label: "Arco File Header")

        // Pages AXTable
        nodes[310] = FigmaMockNode(role: "AXTable", children: [311], parent: 300, bounds: SurfaceAbsoluteRect(x: 0, y: 108, width: 240, height: 100))
        nodes[311] = FigmaMockNode(role: "AXRow", parent: 310, bounds: SurfaceAbsoluteRect(x: 0, y: 112, width: 240, height: 28), label: "Tree 树")

        // Virtualized Layers AXColumn (scrolled container y < 0 with offscreen, height <= 1, and visible rows)
        nodes[320] = FigmaMockNode(role: "AXColumn", children: [321, 322, 323, 324], parent: 300, bounds: SurfaceAbsoluteRect(x: 0, y: -200, width: 240, height: 1500))
        nodes[321] = FigmaMockNode(role: "AXRow", children: [331], parent: 320, bounds: SurfaceAbsoluteRect(x: 0, y: -32, width: 240, height: 28))
        nodes[331] = FigmaMockNode(role: "AXStaticText", parent: 321, text: "Offscreen Top Layer", reportedLength: 0)
        nodes[322] = FigmaMockNode(role: "AXRow", children: [332], parent: 320, bounds: SurfaceAbsoluteRect(x: 0, y: 220, width: 240, height: 1))
        nodes[332] = FigmaMockNode(role: "AXStaticText", parent: 322, text: "Collapsed Virtual Placeholder", reportedLength: 0)
        nodes[323] = FigmaMockNode(role: "AXRow", parent: 320, bounds: SurfaceAbsoluteRect(x: 0, y: 260, width: 240, height: 28), label: "item-list-2nd-level")
        nodes[324] = FigmaMockNode(role: "AXRow", children: [334], parent: 320, bounds: SurfaceAbsoluteRect(x: 0, y: 292, width: 240, height: 28))
        nodes[334] = FigmaMockNode(role: "AXStaticText", parent: 324, text: "treenode/2nd-level", reportedLength: 0, bounds: SurfaceAbsoluteRect(x: 24, y: 296, width: 180, height: 20))

        let backend = FigmaMockBackend(nodes)
        let outcome = SurfaceCaptureRunner.run(
            adapter: FigmaAdapter(),
            application: figmaApp,
            policy: figmaPolicy,
            scope: "window",
            maxOutputNodes: 64,
            focus: AXNodeHandle(index: 106),
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: backend
        )

        guard case .success(let tree) = outcome else {
            return XCTFail("Expected FigmaAdapter capture to succeed, got \(outcome)")
        }

        XCTAssertEqual(tree.adapterId, "figma")
        XCTAssertNotNil(tree.geometry)
        assertValidForest(tree)

        let texts = tree.nodes.compactMap(\.text)

        // Zone 1: Main WebArea title + URL and open tabs (without chrome noise).
        XCTAssertTrue(texts.contains("Arco Design System – Figma (https://www.figma.com/design/abc123/Arco-Design-System)"))
        XCTAssertTrue(texts.contains("Arco Design System"))
        XCTAssertTrue(texts.contains("Mobile Checkout Flow"))
        XCTAssertFalse(texts.contains("Close tab"))
        XCTAssertFalse(texts.contains("New file"))
        XCTAssertFalse(texts.contains("Open tabs and recently closed items"))

        // Zone 2: Selected canvas hierarchy with focus preserved and Dimensions/PUA skipped.
        XCTAssertTrue(texts.contains("Figma Design, 1 item selected"))
        XCTAssertTrue(texts.contains("item-list-2nd-level, Design frame"))
        XCTAssertTrue(texts.contains("200 Fill × 32 Hug"))
        XCTAssertTrue(texts.contains("treenode/2nd-level, Component instance"))
        XCTAssertTrue(texts.contains("176 Fill × 32 Hug"))
        XCTAssertFalse(texts.contains("Dimensions"))
        XCTAssertFalse(texts.contains("\u{EBB1}"))
        let focusedNodes = tree.nodes.filter { $0.focused == true }
        XCTAssertEqual(focusedNodes.count, 1)
        XCTAssertEqual(focusedNodes.first?.text, "treenode/2nd-level, Component instance")

        // Zone 3: Right inspector values kept; all 13 noise buttons, zero-size, slider, toolbars pruned.
        XCTAssertTrue(texts.contains("Design"))
        XCTAssertTrue(texts.contains("Prototype"))
        XCTAssertTrue(texts.contains("73%"))
        XCTAssertTrue(texts.contains("TreeNode"))
        XCTAssertTrue(texts.contains("From this file"))
        XCTAssertTrue(texts.contains("Level"))
        XCTAssertTrue(texts.contains("2nd-level"))
        XCTAssertTrue(texts.contains("Show icon"))
        XCTAssertTrue(texts.contains("200"))
        XCTAssertTrue(texts.contains("Color Variable text/1 with value #1D2129 · 100%"))
        XCTAssertFalse(texts.contains("Hidden zero-size text"))
        XCTAssertFalse(backend.textReads.contains(211), "Zero-size right inspector leaf must never be text-read")
        for noise in rightNoiseLabels {
            XCTAssertFalse(texts.contains(noise), "Right sidebar noise must be pruned: \(noise)")
        }

        // Zone 4: Left sidebar visible items kept; offscreen/height<=1 rows and chrome pruned without reading children.
        XCTAssertTrue(texts.contains("Arco File Header"))
        XCTAssertTrue(texts.contains("Tree 树"))
        XCTAssertTrue(texts.contains("item-list-2nd-level"))
        XCTAssertTrue(texts.contains("treenode/2nd-level"))
        XCTAssertFalse(texts.contains("Offscreen Top Layer"))
        XCTAssertFalse(texts.contains("Collapsed Virtual Placeholder"))
        XCTAssertFalse(backend.textReads.contains(331), "Negative-y offscreen row child must never be text-read")
        XCTAssertFalse(backend.textReads.contains(332), "Height<=1 virtual row child must never be text-read")
        for leftNoise in ["Minimize UI", "Collapse layers", "Find", "Add new page", "Navigation Bar", "Nav noise", "Rectangle", "Zoom help"] {
            XCTAssertFalse(texts.contains(leftNoise), "Chrome noise must be pruned: \(leftNoise)")
        }
    }

    func testFigmaAdapterBlocksProtectedFieldsAndFailsClosedOnSensitiveFocus() {
        var nodes: [Int: FigmaMockNode] = [
            0: FigmaMockNode(role: "AXWindow", children: [1], bounds: SurfaceAbsoluteRect(x: 0, y: 0, width: 1440, height: 900)),
            1: FigmaMockNode(role: "AXWebArea", children: [2, 3], parent: 0, bounds: SurfaceAbsoluteRect(x: 0, y: 38, width: 1440, height: 862), label: "Auth Mockup – Figma"),
            2: FigmaMockNode(role: "AXGroup", subrole: .value("AXLandmarkMain"), children: [10], parent: 1, label: "Figma Design, 1 item selected"),
            10: FigmaMockNode(role: "AXGroup", subrole: .value("AXApplicationGroup"), parent: 2, label: "Login Card, Design frame"),
            3: FigmaMockNode(role: "AXGroup", subrole: .value("AXLandmarkRegion"), children: [20, 21, 22], parent: 1, bounds: SurfaceAbsoluteRect(x: 1200, y: 38, width: 240, height: 862), label: "Right sidebar"),
            20: FigmaMockNode(role: "AXSecureTextField", parent: 3, text: "hunter2", bounds: SurfaceAbsoluteRect(x: 1210, y: 80, width: 180, height: 24), label: "API Secret"),
            21: FigmaMockNode(role: "AXTextField", protectedContent: .value(true), parent: 3, text: "tok_live_secret", bounds: SurfaceAbsoluteRect(x: 1210, y: 112, width: 180, height: 24), label: "Protected Token"),
            22: FigmaMockNode(role: "AXStaticText", parent: 3, text: "Public Label", reportedLength: 0, bounds: SurfaceAbsoluteRect(x: 1210, y: 144, width: 180, height: 20)),
        ]

        // 1. Non-focused protected fields are silently blocked while safe siblings succeed.
        let mixedBackend = FigmaMockBackend(nodes)
        mixedBackend.windowRect = SurfaceAbsoluteRect(x: 0, y: 0, width: 1440, height: 900)
        let mixedOutcome = SurfaceCaptureRunner.run(
            adapter: FigmaAdapter(),
            application: figmaApp,
            policy: figmaPolicy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: mixedBackend
        )
        guard case .success(let mixedTree) = mixedOutcome else {
            return XCTFail("Expected safe Figma siblings to succeed when protected fields are pruned, got \(mixedOutcome)")
        }
        XCTAssertFalse(mixedBackend.textReads.contains(20), "AXSecureTextField must never be text-read")
        XCTAssertFalse(mixedBackend.textReads.contains(21), "Protected field must never be text-read")
        let mixedTexts = mixedTree.nodes.compactMap(\.text)
        XCTAssertTrue(mixedTexts.contains("Public Label"))
        XCTAssertFalse(mixedTexts.contains("hunter2"))
        XCTAssertFalse(mixedTexts.contains("API Secret"))
        XCTAssertFalse(mixedTexts.contains("tok_live_secret"))
        XCTAssertFalse(mixedTexts.contains("Protected Token"))

        // 2. Focused protected field aborts the entire capture with .securityExcluded.
        nodes[20]?.isFocused = true
        let focusedSecretBackend = FigmaMockBackend(nodes)
        focusedSecretBackend.windowRect = SurfaceAbsoluteRect(x: 0, y: 0, width: 1440, height: 900)
        let focusedSecretOutcome = SurfaceCaptureRunner.run(
            adapter: FigmaAdapter(),
            application: figmaApp,
            policy: figmaPolicy,
            scope: "window",
            maxOutputNodes: 48,
            focus: AXNodeHandle(index: 20),
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: focusedSecretBackend
        )
        XCTAssertEqual(focusedSecretOutcome, .failure(.securityExcluded))
        XCTAssertFalse(focusedSecretBackend.textReads.contains(20))
    }

    func testFigmaAdapterFallsBackToWeightedTraversalOnHomeScreen() {
        let homeNodes: [Int: FigmaMockNode] = [
            0: FigmaMockNode(role: "AXWindow", children: [1], windowTitle: "Recents – Figma", bounds: SurfaceAbsoluteRect(x: 0, y: 0, width: 1440, height: 900)),
            1: FigmaMockNode(role: "AXScrollArea", children: [2, 3], parent: 0),
            2: FigmaMockNode(role: "AXWebArea", parent: 1, displayText: "Figma", bounds: SurfaceAbsoluteRect(x: 0, y: 0, width: 1440, height: 38), label: "Figma"),
            3: FigmaMockNode(role: "AXWebArea", children: [4, 5], parent: 1, displayText: "Recents – Figma", bounds: SurfaceAbsoluteRect(x: 0, y: 38, width: 1440, height: 862), label: "Recents – Figma"),
            4: FigmaMockNode(role: "AXHeading", parent: 3, displayText: "Recent files", label: "Recent files"),
            5: FigmaMockNode(role: "AXStaticText", parent: 3, text: "Arco Design System", reportedLength: 0),
        ]

        // Direct extractSurface returns nil when AXLandmarkMain is absent (File Browser / Home screen).
        let directBackend = FigmaMockBackend(homeNodes)
        directBackend.windowRect = SurfaceAbsoluteRect(x: 0, y: 0, width: 1440, height: 900)
        let context = SafeAXContext(
            application: figmaApp,
            policy: figmaPolicy,
            spec: FigmaAdapter().spec,
            scope: "window",
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: directBackend
        )
        XCTAssertNil(FigmaAdapter().extractSurface(context: context))

        // SurfaceCaptureRunner automatically falls back to weighted traversal and captures Home content.
        let fallbackBackend = FigmaMockBackend(homeNodes)
        fallbackBackend.windowRect = SurfaceAbsoluteRect(x: 0, y: 0, width: 1440, height: 900)
        let outcome = SurfaceCaptureRunner.run(
            adapter: FigmaAdapter(),
            application: figmaApp,
            policy: figmaPolicy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: fallbackBackend
        )
        guard case .success(let tree) = outcome else {
            return XCTFail("Expected weighted fallback on Figma Home screen to succeed, got \(outcome)")
        }
        XCTAssertEqual(tree.adapterId, "figma")
        XCTAssertTrue(tree.nodes.contains { $0.text == "Recent files" })
        XCTAssertTrue(tree.nodes.contains { $0.text == "Arco Design System" })
    }

    func testFigmaAdapterProportionalReservationAndTextBudgetStayBounded() {
        var nodes: [Int: FigmaMockNode] = [
            0: FigmaMockNode(role: "AXWindow", children: [1], bounds: SurfaceAbsoluteRect(x: 0, y: 0, width: 1440, height: 900)),
            1: FigmaMockNode(role: "AXWebArea", children: [2, 3, 4], parent: 0, bounds: SurfaceAbsoluteRect(x: 0, y: 38, width: 1440, height: 862), label: "Big Canvas – Figma"),
        ]
        // 30 canvas items + 15 right inspector items + 10 left sidebar items under maxOutputNodes = 32.
        let canvasChildren = Array(100..<130)
        nodes[2] = FigmaMockNode(role: "AXGroup", subrole: .value("AXLandmarkMain"), children: canvasChildren, parent: 1, label: "Figma Design, 30 items selected")
        for id in canvasChildren {
            nodes[id] = FigmaMockNode(role: "AXGroup", subrole: .value("AXApplicationGroup"), parent: 2, label: "Canvas Layer \(id), Frame")
        }
        let rightChildren = Array(200..<215)
        nodes[3] = FigmaMockNode(role: "AXGroup", subrole: .value("AXLandmarkRegion"), children: rightChildren, parent: 1, bounds: SurfaceAbsoluteRect(x: 1200, y: 38, width: 240, height: 862), label: "Right sidebar")
        for id in rightChildren {
            nodes[id] = FigmaMockNode(role: "AXStaticText", parent: 3, text: "Inspector Prop \(id)", reportedLength: 0, bounds: SurfaceAbsoluteRect(x: 1210, y: Double(60 + (id - 200) * 24), width: 180, height: 20))
        }
        let leftChildren = Array(300..<310)
        nodes[4] = FigmaMockNode(role: "AXGroup", subrole: .value("AXLandmarkRegion"), children: leftChildren, parent: 1, bounds: SurfaceAbsoluteRect(x: 0, y: 38, width: 240, height: 862), label: "Left sidebar")
        for id in leftChildren {
            nodes[id] = FigmaMockNode(role: "AXRow", parent: 4, bounds: SurfaceAbsoluteRect(x: 0, y: Double(60 + (id - 300) * 28), width: 240, height: 24), label: "Sidebar Row \(id)")
        }

        let backend = FigmaMockBackend(nodes)
        backend.windowRect = SurfaceAbsoluteRect(x: 0, y: 0, width: 1440, height: 900)
        let outcome = SurfaceCaptureRunner.run(
            adapter: FigmaAdapter(),
            application: figmaApp,
            policy: figmaPolicy,
            scope: "window",
            maxOutputNodes: 32,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: backend
        )
        guard case .success(let tree) = outcome else {
            return XCTFail("Expected bounded Figma capture under tight maxOutputNodes, got \(outcome)")
        }
        XCTAssertLessThanOrEqual(tree.nodes.count, 32)
        XCTAssertTrue(tree.reasons.contains("tree-output-budget"))
        assertValidForest(tree)
        let texts = tree.nodes.compactMap(\.text)
        XCTAssertTrue(texts.contains { $0.hasPrefix("Canvas Layer") }, "Canvas selection must be represented")
        XCTAssertTrue(texts.contains { $0.hasPrefix("Inspector Prop") }, "Right Inspector must not be starved by large selection")
        XCTAssertTrue(texts.contains { $0.hasPrefix("Sidebar Row") }, "Left Sidebar must not be starved by large selection")

        // Tight text budget must truncate cleanly without poisoning ReadBudget.
        let tightTextBackend = FigmaMockBackend(nodes)
        tightTextBackend.windowRect = SurfaceAbsoluteRect(x: 0, y: 0, width: 1440, height: 900)
        let tightTextOutcome = SurfaceCaptureRunner.run(
            adapter: FigmaAdapter(),
            application: figmaApp,
            policy: figmaPolicy,
            scope: "window",
            maxOutputNodes: 32,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000, maxTextUnits: 120),
            clock: clock,
            backend: tightTextBackend
        )
        guard case .success(let tightTree) = tightTextOutcome else {
            return XCTFail("Tight ReadBudget.maxTextUnits must degrade gracefully rather than aborting, got \(tightTextOutcome)")
        }
        let totalUnits = tightTree.nodes.reduce(0) { $0 + ($1.text?.utf16.count ?? 0) }
        XCTAssertLessThanOrEqual(totalUnits, 120)
        XCTAssertTrue(tightTree.reasons.contains("text-budget"))
    }

    func testFigmaAdapterCapturesDepthEightFileTabsSlidesAndHiddenSidebars() {
        var nodes: [Int: FigmaMockNode] = [:]
        nodes[0] = FigmaMockNode(role: "AXWindow", children: [1, 2], bounds: SurfaceAbsoluteRect(x: 0, y: 0, width: 1920, height: 1250))

        // Tab Bar AXWebArea mirroring real Electron nesting: Home at depth 6, design/slide file tabs at depth 8.
        nodes[1] = FigmaMockNode(
            role: "AXWebArea",
            children: [10],
            parent: 0,
            displayText: "Figma",
            bounds: SurfaceAbsoluteRect(x: 0, y: 0, width: 1920, height: 38),
            label: "Figma"
        )
        nodes[10] = FigmaMockNode(role: "AXGroup", children: [11], parent: 1, bounds: SurfaceAbsoluteRect(x: 0, y: 0, width: 1920, height: 38))
        nodes[11] = FigmaMockNode(role: "AXGroup", children: [12], parent: 10, bounds: SurfaceAbsoluteRect(x: 0, y: 0, width: 1920, height: 38))
        nodes[12] = FigmaMockNode(role: "AXGroup", children: [13], parent: 11, bounds: SurfaceAbsoluteRect(x: 0, y: 0, width: 1920, height: 38))
        nodes[13] = FigmaMockNode(role: "AXTabGroup", children: [14], parent: 12, bounds: SurfaceAbsoluteRect(x: 0, y: 0, width: 1920, height: 38), label: "Tab bar")
        nodes[14] = FigmaMockNode(role: "AXGroup", children: [15, 16], parent: 13, bounds: SurfaceAbsoluteRect(x: 0, y: 0, width: 1920, height: 38))
        // Depth 6 from Tab Bar AXWebArea: Home tab
        nodes[15] = FigmaMockNode(role: "AXRadioButton", parent: 14, displayText: "Home", bounds: SurfaceAbsoluteRect(x: 81, y: 0, width: 40, height: 38), label: "Home")
        // Depth 6 -> 7 -> 8 wrapper chain holding open file tabs
        nodes[16] = FigmaMockNode(role: "AXGroup", children: [17], parent: 14, bounds: SurfaceAbsoluteRect(x: 121, y: 0, width: 900, height: 38))
        nodes[17] = FigmaMockNode(role: "AXGroup", children: [18, 19], parent: 16, bounds: SurfaceAbsoluteRect(x: 121, y: 0, width: 900, height: 38))
        nodes[18] = FigmaMockNode(role: "AXRadioButton", parent: 17, displayText: "Sketchpad", bounds: SurfaceAbsoluteRect(x: 121, y: 0, width: 133, height: 38), label: "Sketchpad")
        nodes[19] = FigmaMockNode(role: "AXRadioButton", parent: 17, displayText: "Slide Deck Demo", bounds: SurfaceAbsoluteRect(x: 254, y: 0, width: 149, height: 38), label: "Slide Deck Demo")

        // Main Slides AXWebArea with sidebars hidden via Cmd+\ (no Left/Right sidebar landmarks)
        // plus one test verifying new Right Inspector chrome labels are pruned when visible.
        nodes[2] = FigmaMockNode(
            role: "AXWebArea",
            children: [30, 40],
            parent: 0,
            displayText: "Slide Deck Demo – Figma Slides (https://www.figma.com/slides/demo)",
            bounds: SurfaceAbsoluteRect(x: 0, y: 38, width: 1920, height: 1212),
            label: "Slide Deck Demo – Figma Slides"
        )
        nodes[30] = FigmaMockNode(
            role: "AXGroup",
            subrole: .value("AXLandmarkMain"),
            children: [31],
            parent: 2,
            bounds: SurfaceAbsoluteRect(x: 0, y: 38, width: 1920, height: 1212),
            label: "Figma Slides, 1 item selected"
        )
        nodes[31] = FigmaMockNode(
            role: "AXGroup",
            subrole: .value("AXApplicationGroup"),
            children: [32],
            parent: 30,
            bounds: SurfaceAbsoluteRect(x: 256, y: 135, width: 1407, height: 791),
            label: "Slide 6"
        )
        nodes[32] = FigmaMockNode(
            role: "AXHeading",
            parent: 31,
            displayText: "Architecture Overview",
            bounds: SurfaceAbsoluteRect(x: 350, y: 228, width: 600, height: 43),
            label: "Architecture Overview"
        )
        nodes[40] = FigmaMockNode(
            role: "AXGroup",
            subrole: .value("AXLandmarkRegion"),
            children: [41, 42, 43, 44],
            parent: 2,
            bounds: SurfaceAbsoluteRect(x: 1680, y: 38, width: 240, height: 1212),
            label: "Right sidebar"
        )
        nodes[41] = FigmaMockNode(role: "AXRadioButton", parent: 40, displayText: "Animate", bounds: SurfaceAbsoluteRect(x: 1745, y: 86, width: 61, height: 24), label: "Animate")
        nodes[42] = FigmaMockNode(role: "AXButton", parent: 40, displayText: "Align left", bounds: SurfaceAbsoluteRect(x: 1688, y: 127, width: 30, height: 24), label: "Align left")
        nodes[43] = FigmaMockNode(role: "AXPopUpButton", parent: 40, displayText: "Apply variable mode", bounds: SurfaceAbsoluteRect(x: 1888, y: 127, width: 24, height: 24), label: "Apply variable mode")
        nodes[44] = FigmaMockNode(role: "AXButton", parent: 40, displayText: "Edit template style", bounds: SurfaceAbsoluteRect(x: 1880, y: 176, width: 24, height: 24), label: "Edit template style")

        let backend = FigmaMockBackend(nodes)
        let outcome = SurfaceCaptureRunner.run(
            adapter: FigmaAdapter(),
            application: figmaApp,
            policy: figmaPolicy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: backend
        )
        guard case .success(let tree) = outcome else {
            return XCTFail("Expected successful Figma Slides capture, got \(outcome)")
        }
        assertValidForest(tree)
        let texts = tree.nodes.compactMap(\.text)
        XCTAssertTrue(texts.contains("Home"))
        XCTAssertTrue(texts.contains("Sketchpad"), "Depth-8 file tab must be captured")
        XCTAssertTrue(texts.contains("Slide Deck Demo"), "Depth-8 slide tab must be captured")
        XCTAssertTrue(texts.contains("Figma Slides, 1 item selected"))
        XCTAssertTrue(texts.contains("Slide 6"))
        XCTAssertTrue(texts.contains("Architecture Overview"))
        XCTAssertTrue(texts.contains("Animate"))
        XCTAssertFalse(texts.contains("Align left"), "Alignment chrome must be pruned")
        XCTAssertFalse(texts.contains("Apply variable mode"), "Variable mode chrome must be pruned")
        XCTAssertFalse(texts.contains("Edit template style"), "Template edit chrome must be pruned")

        // Verify sidebar-hidden mode (Cmd+\): removing Right sidebar still returns clean Slides capture.
        nodes[2] = FigmaMockNode(
            role: "AXWebArea",
            children: [30],
            parent: 0,
            displayText: "Slide Deck Demo – Figma Slides (https://www.figma.com/slides/demo)",
            bounds: SurfaceAbsoluteRect(x: 0, y: 38, width: 1920, height: 1212),
            label: "Slide Deck Demo – Figma Slides"
        )
        let hiddenOutcome = SurfaceCaptureRunner.run(
            adapter: FigmaAdapter(),
            application: figmaApp,
            policy: figmaPolicy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: FigmaMockBackend(nodes)
        )
        guard case .success(let hiddenTree) = hiddenOutcome else {
            return XCTFail("Expected clean capture when sidebars are hidden via Cmd+\\, got \(hiddenOutcome)")
        }
        assertValidForest(hiddenTree)
        let hiddenTexts = hiddenTree.nodes.compactMap(\.text)
        XCTAssertTrue(hiddenTexts.contains("Sketchpad"))
        XCTAssertTrue(hiddenTexts.contains("Slide 6"))
        XCTAssertTrue(hiddenTexts.contains("Architecture Overview"))
        XCTAssertFalse(hiddenTexts.contains("Right sidebar"))
    }
}

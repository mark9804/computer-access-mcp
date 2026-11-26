import XCTest
import Synchronization
import HistoryContract
@testable import CollectorCore

private final class MockEnablementProvider: AXEnablementProvider {
    var supported: Set<AXEnablementResult.Attribute> = [.manual, .enhanced]
    var values: [AXEnablementResult.Attribute: Bool] = [.manual: false, .enhanced: false]
    var calls: [String] = []

    func supports(_ attribute: AXEnablementResult.Attribute) -> Bool {
        calls.append("supports:\(attribute.rawValue)")
        return supported.contains(attribute)
    }

    func current(_ attribute: AXEnablementResult.Attribute) -> Bool? {
        calls.append("current:\(attribute.rawValue)")
        return values[attribute]
    }

    func settable(_ attribute: AXEnablementResult.Attribute) -> Bool? {
        calls.append("settable:\(attribute.rawValue)")
        return true
    }

    func enable(_ attribute: AXEnablementResult.Attribute) -> Bool {
        calls.append("enable:\(attribute.rawValue)")
        values[attribute] = true
        return true
    }
}

private struct MockNode {
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

private final class MockAXBackend: AXSurfaceBackend {
    var nodes: [Int: MockNode]
    var desktopFailure: SurfaceReadFailure?
    var finalBoundaryFailure: SurfaceReadFailure?
    var windowRect: SurfaceAbsoluteRect? = SurfaceAbsoluteRect(x: 100, y: 200, width: 800, height: 600)
    var inspectedIndices: [Int] = []
    var childRequests: [(index: Int, offset: Int, limit: Int)] = []
    var textReads: [Int] = []
    var onInspect: ((Int, Bool) -> AXBackendInspection?)?
    var onChildPage: (() -> Void)?
    var onTextRead: ((Int) -> String?)?
    var onTextReadOutcome: ((Int) -> AXBackendTextRead?)?

    init(_ nodes: [Int: MockNode]) {
        self.nodes = nodes
    }

    func verifyDesktopAndApplication() -> SurfaceReadFailure? {
        desktopFailure
    }

    func inspectBackendNode(_ index: Int, isRoot: Bool) -> AXBackendInspection {
        inspectedIndices.append(index)
        if let custom = onInspect?(index, isRoot) {
            return custom
        }
        guard let node = nodes[index] else { return .pruned(.providerRefused) }
        return .allowed(
            role: node.role,
            subrole: node.subrole,
            protectedContent: node.protectedContent,
            childCount: node.children.count,
            isFocused: node.isFocused,
            observedAtMs: Int64(1_000 + index),
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
        onChildPage?()
        guard let node = nodes[index], node.role == expectedRole else {
            return .unavailable(.securityPruned)
        }
        return .values(Array(node.children.dropFirst(offset).prefix(limit)))
    }

    func readBackendNodeText(_ index: Int, expectedRole: String, maxUnits: Int, staticTextProbe: StaticTextPolicy) -> AXBackendTextRead {
        textReads.append(index)
        if let customOutcome = onTextReadOutcome?(index) {
            return customOutcome
        }
        if let custom = onTextRead?(index) {
            return .text(value: custom, complete: false, reasons: ["text-budget"])
        }
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
        return (rel, 1_050)
    }

    func readBackendWindowRect() -> SurfaceAbsoluteRect? {
        windowRect
    }

    func verifyFinalSurfaceBoundary() -> SurfaceReadFailure? {
        finalBoundaryFailure
    }
}

final class AppAdapterTests: XCTestCase {
    private let clock = FakeClock()

    func testRegistryMatchesBuiltInAdaptersAndFallsBackToGeneric() {
        let registry = AppAdapterRegistry.shared
        XCTAssertEqual(BuiltInAdapters.all.map(\.spec.id), [
            "generic",
            "vscode-family",
            "browser-family",
            "terminal-family",
            "qq",
            "feishu",
            "wechat",
            "slack",
            "typora",
            "figma",
        ])

        for bundleId in [
            "com.google.antigravity",
            "COM.GOOGLE.ANTIGRAVITY",
            "com.google.antigravity-ide",
            "COM.GOOGLE.ANTIGRAVITY-IDE",
            "com.microsoft.VSCode",
            "com.microsoft.VSCodeInsiders",
            "com.todesktop.230313mzl4w4u92",
            "com.exafunction.windsurf",
        ] {
            let matched = registry.adapter(for: bundleId)
            XCTAssertEqual(matched.spec.id, "vscode-family", bundleId)
            XCTAssertEqual(matched.spec.activation, .manualAccessibility)
            XCTAssertEqual(matched.spec.windowAnchor, .allowUnfocusedWindow)
            XCTAssertEqual(matched.spec.staticTextProbe, .boundedRangeProbe(maxUnits: 256))
            XCTAssertEqual(matched.spec.ignoredSubroles, ["AXApplicationStatus"])
            XCTAssertTrue(matched.spec.preferredRoles.contains("AXTabGroup"))
            XCTAssertTrue(matched.spec.preferredRoles.contains("AXTabButton"))
            XCTAssertTrue(matched.spec.preferredRoles.contains("AXRadioButton"))
            XCTAssertTrue(matched.spec.preferredRoles.contains("AXHeading"))
            XCTAssertEqual(matched.spec.pageSize, 16)
            XCTAssertEqual(matched.spec.maxNodeTextUnits, 256)
        }

        for bundleId in [
            "com.google.Chrome",
            "com.google.Chrome.canary",
            "org.chromium.Chromium",
            "com.brave.Browser",
            "com.microsoft.edgemac",
            "company.thebrowser.Browser",
            "company.thebrowser.dia",
            "com.vivaldi.Vivaldi",
            "com.operasoftware.Opera",
            "org.mozilla.firefox",
            "org.mozilla.nightly",
            "app.zen-browser.zen",
            "app.floorp.Floorp",
            "ai.perplexity.comet",
            "com.openai.atlas",
            "net.imput.helium",
        ] {
            let matched = registry.adapter(for: bundleId)
            XCTAssertEqual(matched.spec.id, "browser-family", bundleId)
            XCTAssertEqual(matched.spec.activation, .manualAccessibility)
            XCTAssertEqual(matched.spec.windowAnchor, .allowUnfocusedWindow)
            XCTAssertTrue(matched.spec.blockPrivateWindows)
            XCTAssertEqual(matched.spec.pageSize, 16)
            XCTAssertEqual(matched.spec.maxNodeTextUnits, 256)
        }

        for bundleId in [
            "com.apple.Terminal",
            "com.googlecode.iterm2",
            "com.mitchellh.ghostty",
            "dev.warp.Warp-Stable",
            "net.kovidgoyal.kitty",
            "com.github.wez.wezterm",
            "com.raphaelamorim.rio",
            "dev.commandline.waveterm",
        ] {
            let matched = registry.adapter(for: bundleId)
            XCTAssertEqual(matched.spec.id, "terminal-family", bundleId)
            XCTAssertEqual(matched.spec.activation, .none)
            XCTAssertEqual(matched.spec.windowAnchor, .allowTopLevelFallback)
            XCTAssertFalse(matched.spec.blockPrivateWindows)
            XCTAssertEqual(matched.spec.pageSize, 16)
            XCTAssertEqual(matched.spec.maxNodeTextUnits, 1024)
        }

        for bundleId in ["com.tencent.qq", "COM.TENCENT.QQ"] {
            let matched = registry.adapter(for: bundleId)
            XCTAssertEqual(matched.spec.id, "qq")
            XCTAssertEqual(matched.spec.windowAnchor, .allowUnfocusedWindow)
            XCTAssertEqual(matched.spec.staticTextProbe, .boundedRangeProbe(maxUnits: 256))
            XCTAssertEqual(matched.spec.pageSize, 16)
        }

        for bundleId in ["com.electron.lark", "com.bytedance.feishu"] {
            let matched = registry.adapter(for: bundleId)
            XCTAssertEqual(matched.spec.id, "feishu")
            XCTAssertEqual(matched.spec.activation, .manualAccessibility)
            XCTAssertEqual(matched.spec.windowAnchor, .allowUnfocusedWindow)
            XCTAssertEqual(matched.spec.staticTextProbe, .boundedRangeProbe(maxUnits: 256))
            XCTAssertEqual(matched.spec.pageSize, 16)
        }

        for bundleId in ["com.tencent.xinWeChat", "COM.TENCENT.XINWECHAT"] {
            let matched = registry.adapter(for: bundleId)
            XCTAssertEqual(matched.spec.id, "wechat")
            XCTAssertEqual(matched.spec.displayName, "WeChat")
            XCTAssertEqual(matched.spec.activation, .none)
            XCTAssertEqual(matched.spec.windowAnchor, .allowUnfocusedWindow)
            XCTAssertEqual(matched.spec.staticTextProbe, .boundedRangeProbe(maxUnits: 256))
            XCTAssertEqual(matched.spec.pageSize, 16)
            XCTAssertEqual(matched.spec.maxNodeTextUnits, 256)
        }

        for bundleId in ["com.tinyspeck.slackmacgap", "COM.TINYSPECK.SLACKMACGAP"] {
            let matched = registry.adapter(for: bundleId)
            XCTAssertEqual(matched.spec.id, "slack")
            XCTAssertEqual(matched.spec.displayName, "Slack")
            XCTAssertEqual(matched.spec.activation, .manualAccessibility)
            XCTAssertEqual(matched.spec.windowAnchor, .allowUnfocusedWindow)
            XCTAssertEqual(matched.spec.staticTextProbe, .boundedRangeProbe(maxUnits: 256))
            XCTAssertEqual(matched.spec.pageSize, 16)
            XCTAssertEqual(matched.spec.maxNodeTextUnits, 256)
        }

        for bundleId in ["abnerworks.Typora", "ABNERWORKS.TYPORA"] {
            let matched = registry.adapter(for: bundleId)
            XCTAssertEqual(matched.spec.id, "typora")
            XCTAssertEqual(matched.spec.displayName, "Typora")
            XCTAssertEqual(matched.spec.activation, .enhancedUI)
            XCTAssertEqual(matched.spec.windowAnchor, .allowUnfocusedWindow)
            XCTAssertEqual(matched.spec.staticTextProbe, .standard)
            XCTAssertEqual(matched.spec.pageSize, 16)
            XCTAssertEqual(matched.spec.maxNodeTextUnits, 512)
            XCTAssertFalse(matched.spec.blockPrivateWindows)
            XCTAssertTrue(matched.spec.preferredRoles.contains("AXWebArea"))
            XCTAssertTrue(matched.spec.preferredRoles.contains("AXTextArea"))
            XCTAssertTrue(matched.spec.preferredRoles.contains("AXHeading"))
            XCTAssertTrue(matched.spec.ignoredRoles.contains("AXMenuItem"))
            XCTAssertTrue(matched.spec.ignoredRoles.contains("AXToolbar"))
        }

        for bundleId in ["com.figma.Desktop", "COM.FIGMA.DESKTOP"] {
            let matched = registry.adapter(for: bundleId)
            XCTAssertEqual(matched.spec.id, "figma")
            XCTAssertEqual(matched.spec.displayName, "Figma")
            XCTAssertEqual(matched.spec.activation, .enhancedUI)
            XCTAssertEqual(matched.spec.windowAnchor, .allowUnfocusedWindow)
            XCTAssertEqual(matched.spec.staticTextProbe, .boundedRangeProbe(maxUnits: 256))
            XCTAssertEqual(matched.spec.pageSize, 16)
            XCTAssertEqual(matched.spec.maxNodeTextUnits, 256)
            XCTAssertFalse(matched.spec.blockPrivateWindows)
            XCTAssertTrue(matched.spec.preferredRoles.contains("AXWebArea"))
            XCTAssertTrue(matched.spec.preferredRoles.contains("AXComboBox"))
            XCTAssertTrue(matched.spec.preferredRoles.contains("AXCheckBox"))
            XCTAssertTrue(matched.spec.ignoredRoles.contains("AXToolbar"))
            XCTAssertTrue(matched.spec.ignoredRoles.contains("AXSlider"))
        }

        for unknown in ["com.apple.Notes", "org.example.editor", "com.openai.codex"] {
            let fallback = registry.adapter(for: unknown)
            XCTAssertEqual(fallback.spec.id, "generic")
            XCTAssertEqual(fallback.spec.activation, .none)
            XCTAssertEqual(fallback.spec.windowAnchor, .focusedOnly)
            XCTAssertEqual(fallback.spec.staticTextProbe, .standard)
            XCTAssertFalse(fallback.spec.blockPrivateWindows)
        }
    }

    func testActivationSpecModesRespectOptInPolicyAndTargetAttribute() {
        let policy = CapturePolicy(allowedApplicationIds: ["com.google.antigravity-ide", "com.tencent.qq", "abnerworks.Typora", "com.figma.Desktop"], axCompatibility: true)

        let genericProvider = MockEnablementProvider()
        let noneResult = AXEnablementLease().acquire(
            applicationId: "com.tencent.qq",
            policy: policy,
            activation: QQAdapter().spec.activation,
            provider: genericProvider
        )
        XCTAssertEqual(noneResult.status, .disabled)
        XCTAssertTrue(genericProvider.calls.isEmpty)

        let manualProvider = MockEnablementProvider()
        let manualResult = AXEnablementLease().acquire(
            applicationId: "com.google.antigravity-ide",
            policy: policy,
            activation: VSCodeFamilyAdapter().spec.activation,
            provider: manualProvider
        )
        XCTAssertEqual(manualResult, AXEnablementResult(status: .enabled, attribute: .manual, changed: true))
        XCTAssertTrue(manualProvider.calls.contains("enable:manual"))

        let enhancedProvider = MockEnablementProvider()
        enhancedProvider.supported = [.enhanced]
        let enhancedResult = AXEnablementLease().acquire(
            applicationId: "abnerworks.Typora",
            policy: policy,
            activation: TyporaAdapter().spec.activation,
            provider: enhancedProvider
        )
        XCTAssertEqual(enhancedResult, AXEnablementResult(status: .enabled, attribute: .enhanced, changed: true))
        XCTAssertFalse(enhancedProvider.calls.contains("supports:manual"))
        XCTAssertTrue(enhancedProvider.calls.contains("enable:enhanced"))

        let figmaProvider = MockEnablementProvider()
        figmaProvider.supported = [.enhanced]
        figmaProvider.values[.enhanced] = true
        let figmaResult = AXEnablementLease().acquire(
            applicationId: "com.figma.Desktop",
            policy: policy,
            activation: FigmaAdapter().spec.activation,
            provider: figmaProvider
        )
        XCTAssertEqual(figmaResult, AXEnablementResult(status: .alreadyEnabled, attribute: .enhanced, changed: false))
    }

    func testWindowAnchorAndStaticTextPoliciesDriveDeclarativeBehavior() throws {
        XCTAssertFalse(GenericAdapter().spec.windowAnchor.allowsTopLevelFallback)
        XCTAssertFalse(GenericAdapter().spec.windowAnchor.allowsUnfocusedWindow)
        XCTAssertTrue(VSCodeFamilyAdapter().spec.windowAnchor.allowsTopLevelFallback)
        XCTAssertTrue(VSCodeFamilyAdapter().spec.windowAnchor.allowsUnfocusedWindow)
        XCTAssertTrue(BrowserFamilyAdapter().spec.windowAnchor.allowsUnfocusedWindow)
        XCTAssertTrue(TerminalFamilyAdapter().spec.windowAnchor.allowsTopLevelFallback)
        XCTAssertFalse(TerminalFamilyAdapter().spec.windowAnchor.allowsUnfocusedWindow)
        XCTAssertTrue(QQAdapter().spec.windowAnchor.allowsTopLevelFallback)
        XCTAssertTrue(QQAdapter().spec.windowAnchor.allowsUnfocusedWindow)
        XCTAssertTrue(FeishuAdapter().spec.windowAnchor.allowsUnfocusedWindow)
        XCTAssertTrue(WeChatAdapter().spec.windowAnchor.allowsUnfocusedWindow)
        XCTAssertTrue(SlackAdapter().spec.windowAnchor.allowsUnfocusedWindow)
        XCTAssertTrue(TyporaAdapter().spec.windowAnchor.allowsTopLevelFallback)
        XCTAssertTrue(TyporaAdapter().spec.windowAnchor.allowsUnfocusedWindow)
        XCTAssertTrue(FigmaAdapter().spec.windowAnchor.allowsTopLevelFallback)
        XCTAssertTrue(FigmaAdapter().spec.windowAnchor.allowsUnfocusedWindow)

        // QQ zero-length StaticText recovers text via boundedRangeProbe, whereas Generic standard policy reads empty.
        var children: [Int: MockNode] = [0: MockNode(role: "AXWindow", children: Array(1...16) + [99])]
        for id in 1...16 {
            children[id] = MockNode(
                role: "AXStaticText",
                parent: 0,
                text: "Message \(id)",
                reportedLength: 0,
                bounds: SurfaceAbsoluteRect(x: 110, y: Double(210 + id * 10), width: 200, height: 18)
            )
        }
        // Ignored menu bar branch must be pruned automatically.
        children[99] = MockNode(role: "AXMenuBar", children: [100], parent: 0)
        children[100] = MockNode(role: "AXStaticText", parent: 99, text: "Menu noise")

        let qqBackend = MockAXBackend(children)
        let qqPolicy = CapturePolicy(allowedApplicationIds: ["com.tencent.qq"], captureScope: "window", fieldSecurity: "denylist")
        let qqOutcome = SurfaceCaptureRunner.run(
            adapter: QQAdapter(),
            application: ApplicationIdentity(applicationId: "com.tencent.qq", processId: 200, processStartTime: "birth"),
            policy: qqPolicy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: qqBackend
        )
        guard case .success(let qqTree) = qqOutcome else {
            return XCTFail("Expected QQ surface capture to succeed, got \(qqOutcome)")
        }
        XCTAssertEqual(qqTree.adapterId, "qq")
        // Verify pageSize=16 fetched the first 16 children in one page without a 4-child or 8-child ceiling.
        XCTAssertEqual(qqBackend.childRequests.first?.limit, 16)
        XCTAssertTrue(qqTree.nodes.contains { $0.text == "Message 1" })
        XCTAssertTrue(qqTree.nodes.contains { $0.text == "Message 16" })
        XCTAssertFalse(qqTree.nodes.contains { $0.text == "Menu noise" })
        XCTAssertNotNil(qqTree.geometry)

        let genericBackend = MockAXBackend([
            0: MockNode(role: "AXWindow", children: [1]),
            1: MockNode(role: "AXStaticText", parent: 0, text: "Hidden behind zero length", reportedLength: 0),
        ])
        let genericPolicy = CapturePolicy(allowedApplicationIds: ["org.example.app"], captureScope: "window", fieldSecurity: "denylist")
        let genericOutcome = SurfaceCaptureRunner.run(
            adapter: GenericAdapter(),
            application: ApplicationIdentity(applicationId: "org.example.app", processId: 201, processStartTime: "birth"),
            policy: genericPolicy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: genericBackend
        )
        guard case .success(let genericTree) = genericOutcome else {
            return XCTFail("Expected generic capture to succeed")
        }
        XCTAssertEqual(genericTree.nodes.first(where: { $0.axRole == "AXStaticText" })?.text, "")
    }

    func testCustomExtractorHookSupportsLargePagesAndRejectsInvalidGraphs() {
        struct CustomChatAdapter: AppAdapter {
            let spec = AppAdapterSpec(
                id: "custom-chat",
                displayName: "Custom Chat",
                matchBundleIds: ["org.example.chat"],
                pageSize: 32,
                maxNodeTextUnits: 256
            )

            func extractSurface(context: SafeAXContext) -> CustomSurfaceResult? {
                guard let rootInfo = context.inspect(context.root),
                      let children = context.children(of: context.root, offset: 0, limit: 24) else { return nil }
                var nodes: [CustomSurfaceNode] = [
                    CustomSurfaceNode(handle: context.root, role: "container", axRole: rootInfo.role, observedAtMs: rootInfo.observedAtMs)
                ]
                for child in children {
                    guard let info = context.inspect(child),
                          let body = context.text(of: child) else { continue }
                    let bounds = context.bounds(of: child)
                    nodes.append(CustomSurfaceNode(
                        handle: child,
                        parent: context.root,
                        role: "text",
                        axRole: info.role,
                        text: body,
                        observedAtMs: info.observedAtMs,
                        bounds: bounds?.bounds,
                        boundsObservedAtMs: bounds?.observedAtMs
                    ))
                }
                return CustomSurfaceResult(nodes: nodes, complete: true)
            }
        }

        var graph: [Int: MockNode] = [0: MockNode(role: "AXWindow", children: Array(1...20))]
        for id in 1...20 {
            graph[id] = MockNode(role: "AXStaticText", parent: 0, text: "Row \(id)")
        }
        let backend = MockAXBackend(graph)
        let app = ApplicationIdentity(applicationId: "org.example.chat", processId: 300, processStartTime: "birth")
        let policy = CapturePolicy(allowedApplicationIds: ["org.example.chat"], captureScope: "window", fieldSecurity: "denylist")
        let outcome = SurfaceCaptureRunner.run(
            adapter: CustomChatAdapter(),
            application: app,
            policy: policy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: backend
        )
        guard case .success(let captured) = outcome else {
            return XCTFail("Expected custom extractor to succeed")
        }
        XCTAssertEqual(backend.childRequests.first?.limit, 24)
        XCTAssertEqual(captured.nodes.count, 21)
        XCTAssertEqual(captured.adapterId, "custom-chat")

        // A custom adapter returning uninspected or cyclic handles is rejected by the kernel.
        struct CyclicAdapter: AppAdapter {
            let spec = AppAdapterSpec(id: "cyclic", displayName: "Cyclic")
            func extractSurface(context: SafeAXContext) -> CustomSurfaceResult? {
                _ = context.inspect(context.root)
                let other = AXNodeHandle(index: 1)
                _ = context.inspect(other)
                return CustomSurfaceResult(nodes: [
                    CustomSurfaceNode(handle: context.root, parent: other, role: "container", observedAtMs: 1),
                    CustomSurfaceNode(handle: other, parent: context.root, role: "text", text: "bad", observedAtMs: 1),
                ])
            }
        }
        let cyclicOutcome = SurfaceCaptureRunner.run(
            adapter: CyclicAdapter(),
            application: app,
            policy: policy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: MockAXBackend(graph)
        )
        XCTAssertEqual(cyclicOutcome, .failure(.boundaryUnverified))
    }

    func testHardKernelDenylistDesktopAndProtectedFieldGatesAreUnbypassable() {
        struct RogueState: Sendable {
            var executed = false
            var leakedSecret: String?
        }
        let state = Mutex(RogueState())

        struct RogueAdapter: AppAdapter {
            let onRun: @Sendable (SafeAXContext) -> CustomSurfaceResult?
            let spec = AppAdapterSpec(id: "rogue", displayName: "Rogue", matchBundleIds: ["com.1password.1password", "org.example.app"])
            func extractSurface(context: SafeAXContext) -> CustomSurfaceResult? { onRun(context) }
        }

        let rogue = RogueAdapter { ctx in
            let leaked = ctx.text(of: AXNodeHandle(index: 1)) ?? ctx.text(of: AXNodeHandle(index: 2))
            state.withLock { box in
                box.executed = true
                box.leakedSecret = leaked
            }
            guard let rootInfo = ctx.inspect(ctx.root),
                  let safeInfo = ctx.inspect(AXNodeHandle(index: 3)),
                  let safeText = ctx.text(of: AXNodeHandle(index: 3)) else { return nil }
            return CustomSurfaceResult(nodes: [
                CustomSurfaceNode(handle: ctx.root, role: "container", axRole: rootInfo.role, observedAtMs: 1),
                CustomSurfaceNode(handle: AXNodeHandle(index: 3), parent: ctx.root, role: "text", axRole: safeInfo.role, text: safeText, observedAtMs: 1),
            ], complete: true)
        }

        let nodes: [Int: MockNode] = [
            0: MockNode(role: "AXWindow", children: [1, 2, 3]),
            1: MockNode(role: "AXSecureTextField", parent: 0, text: "hunter2"),
            2: MockNode(role: "AXTextField", protectedContent: .value(true), parent: 0, text: "secret-token"),
            3: MockNode(role: "AXTextField", parent: 0, text: "public-note"),
        ]

        // 1. Mandatory 1Password denylist blocks before adapter or backend runs even under broad denylist policy.
        let denylistPolicy = CapturePolicy(allowedApplicationIds: [], applicationScope: "denylist", allowBrowserContent: true, captureScope: "window", fieldSecurity: "denylist")
        let passwordBackend = MockAXBackend(nodes)
        let deniedAppOutcome = SurfaceCaptureRunner.run(
            adapter: rogue,
            application: ApplicationIdentity(applicationId: "com.1password.1password", processId: 99, processStartTime: "birth"),
            policy: denylistPolicy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: passwordBackend
        )
        XCTAssertEqual(deniedAppOutcome, .failure(.securityExcluded))
        XCTAssertFalse(state.withLock { $0.executed })
        XCTAssertTrue(passwordBackend.inspectedIndices.isEmpty)

        // 2. Protected fields (AXSecureTextField & containsProtectedContent) cannot be read even by direct context.text().
        let mixedBackend = MockAXBackend(nodes)
        let allowedApp = ApplicationIdentity(applicationId: "org.example.app", processId: 100, processStartTime: "birth")
        let mixedOutcome = SurfaceCaptureRunner.run(
            adapter: rogue,
            application: allowedApp,
            policy: denylistPolicy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: mixedBackend
        )
        XCTAssertTrue(state.withLock { $0.executed })
        XCTAssertNil(state.withLock { $0.leakedSecret })
        XCTAssertEqual(mixedBackend.textReads, [3], "Backend text reader must never be invoked for protected nodes 1 or 2")
        if case .success(let tree) = mixedOutcome {
            XCTAssertEqual(tree.nodes.compactMap(\.text), ["public-note"])
        } else {
            XCTFail("Safe sibling should still succeed when protected siblings are skipped")
        }

        // 3. Desktop lock / Secure Input mid-read wipes context and fails closed.
        let lockingBackend = MockAXBackend(nodes)
        lockingBackend.onChildPage = { lockingBackend.desktopFailure = .securityExcluded }
        let lockedOutcome = SurfaceCaptureRunner.run(
            adapter: GenericAdapter(),
            application: allowedApp,
            policy: denylistPolicy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: lockingBackend
        )
        XCTAssertEqual(lockedOutcome, .failure(.securityExcluded))
    }

    func testUnifiedReadBudgetEnforcesCallCeilingReserveAndOversizedTextPoisoning() {
        var graph: [Int: MockNode] = [0: MockNode(role: "AXWindow", children: Array(1...20))]
        for id in 1...20 {
            graph[id] = MockNode(role: "AXStaticText", parent: 0, text: "Item \(id)")
        }
        let backend = MockAXBackend(graph)
        let app = ApplicationIdentity(applicationId: "org.example.app", processId: 101, processStartTime: "birth")
        let policy = CapturePolicy(allowedApplicationIds: ["org.example.app"], captureScope: "window", fieldSecurity: "denylist")

        // Tight call budget: 14 total calls with 8 reserved for final validation -> only 6 exploration calls.
        let outcome = SurfaceCaptureRunner.run(
            adapter: GenericAdapter(),
            application: app,
            policy: policy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000, finalValidationReserveMs: 150, maxCalls: 14, validationReserveCalls: 8, maxTextUnits: 256),
            clock: clock,
            backend: backend
        )
        guard case .success(let partial) = outcome else {
            return XCTFail("Expected bounded partial tree with reserved final validation calls, got \(outcome)")
        }
        XCTAssertFalse(partial.complete)
        XCTAssertTrue(partial.reasons.contains("tree-call-budget"))
        XCTAssertLessThan(partial.nodes.count, 10)

        // Oversized text response poisons ReadBudget and aborts the surface immediately.
        let oversizedBackend = MockAXBackend([
            0: MockNode(role: "AXWindow", children: [1]),
            1: MockNode(role: "AXTextField", parent: 0, text: "short"),
        ])
        oversizedBackend.onTextRead = { _ in String(repeating: "X", count: 500) }
        let poisoned = SurfaceCaptureRunner.run(
            adapter: GenericAdapter(),
            application: app,
            policy: policy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000, maxTextUnits: 32),
            clock: clock,
            backend: oversizedBackend
        )
        XCTAssertEqual(poisoned, .failure(.boundaryUnverified))
    }

    func testNonRootLeafFailuresAndMismatchesPreserveCapturedNodesAsPartial() {
        let app = ApplicationIdentity(applicationId: "com.google.Chrome", processId: 500, processStartTime: "birth")
        let policy = CapturePolicy(
            allowedApplicationIds: [],
            applicationScope: "denylist",
            allowBrowserContent: true,
            captureScope: "window",
            fieldSecurity: "denylist"
        )

        // 1. Mid-read call budget exhaustion on a non-root leaf preserves prior captured siblings as partial.
        let budgetBackend = MockAXBackend([
            0: MockNode(role: "AXWindow", children: [1, 2], windowTitle: "Docs - Google Chrome"),
            1: MockNode(role: "AXStaticText", parent: 0, text: "First captured paragraph"),
            2: MockNode(role: "AXStaticText", parent: 0, text: "Second paragraph hits budget"),
        ])
        budgetBackend.onTextReadOutcome = { index in
            index == 2 ? .unavailable(reasons: ["tree-call-budget"]) : nil
        }
        let budgetOutcome = SurfaceCaptureRunner.run(
            adapter: BrowserFamilyAdapter(),
            application: app,
            policy: policy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: budgetBackend
        )
        guard case .success(let budgetTree) = budgetOutcome else {
            return XCTFail("Expected partial tree when leaf hits call budget, got \(budgetOutcome)")
        }
        XCTAssertFalse(budgetTree.complete)
        XCTAssertTrue(budgetTree.reasons.contains("tree-call-budget"))
        XCTAssertTrue(budgetTree.nodes.contains { $0.text == "First captured paragraph" })

        // 2. Single StaticText probe failure preserves other captured leaves as partial.
        let qqApp = ApplicationIdentity(applicationId: "com.tencent.qq", processId: 501, processStartTime: "birth")
        let probeBackend = MockAXBackend([
            0: MockNode(role: "AXWindow", children: [1, 2]),
            1: MockNode(role: "AXStaticText", parent: 0, text: "Hello from chat", reportedLength: 0),
            2: MockNode(role: "AXStaticText", parent: 0, text: "Broken probe leaf", reportedLength: 0),
        ])
        probeBackend.onTextReadOutcome = { index in
            index == 2 ? .unavailable(reasons: ["static-text-length-unverified", "node-text-unavailable"]) : nil
        }
        let probeOutcome = SurfaceCaptureRunner.run(
            adapter: QQAdapter(),
            application: qqApp,
            policy: policy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: probeBackend
        )
        guard case .success(let probeTree) = probeOutcome else {
            return XCTFail("Expected partial tree on single StaticText probe failure, got \(probeOutcome)")
        }
        XCTAssertFalse(probeTree.complete)
        XCTAssertTrue(probeTree.reasons.contains("static-text-length-unverified"))
        XCTAssertTrue(probeTree.nodes.contains { $0.text == "Hello from chat" })

        // 3. Non-root renderer child PID mismatch (pruned) + dynamic DOM role change between inspect & readText preserve siblings.
        let feishuApp = ApplicationIdentity(applicationId: "com.electron.lark", processId: 502, processStartTime: "birth")
        var node2Inspections = 0
        let mismatchBackend = MockAXBackend([
            0: MockNode(role: "AXWindow", children: [1, 2, 3]),
            1: MockNode(role: "AXStaticText", parent: 0, text: "Stable message"),
            2: MockNode(role: "AXStaticText", parent: 0, text: "Mutating DOM text"),
            3: MockNode(role: "AXStaticText", parent: 0, text: "Renderer child PID node"),
        ])
        mismatchBackend.onInspect = { index, _ in
            if index == 3 {
                return .pruned(.securityPruned)
            }
            if index == 2 {
                node2Inspections += 1
                // Second inspection (inside readText) sees the dynamic DOM node changed from AXStaticText to AXGroup.
                if node2Inspections >= 2 {
                    return .allowed(
                        role: "AXGroup",
                        subrole: .noValue,
                        protectedContent: .value(false),
                        childCount: 0,
                        isFocused: false,
                        observedAtMs: 1_002
                    )
                }
            }
            return nil
        }
        let mismatchOutcome = SurfaceCaptureRunner.run(
            adapter: FeishuAdapter(),
            application: feishuApp,
            policy: policy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: mismatchBackend
        )
        guard case .success(let mismatchTree) = mismatchOutcome else {
            return XCTFail("Expected partial tree on non-root PID/role mismatch, got \(mismatchOutcome)")
        }
        XCTAssertFalse(mismatchTree.complete)
        XCTAssertTrue(mismatchTree.reasons.contains("node-role-changed"))
        XCTAssertTrue(mismatchTree.reasons.contains("tree-security-pruned"))
        XCTAssertTrue(mismatchTree.nodes.contains { $0.text == "Stable message" })
        XCTAssertFalse(mismatchTree.nodes.contains { $0.text == "Mutating DOM text" })
        XCTAssertFalse(mismatchTree.nodes.contains { $0.text == "Renderer child PID node" })
    }

    func testPrivateAndIncognitoBrowserWindowsBlockCaptureWithZeroContentRead() {
        let chromeApp = ApplicationIdentity(applicationId: "com.google.Chrome", processId: 600, processStartTime: "birth")
        let policy = CapturePolicy(
            allowedApplicationIds: [],
            applicationScope: "denylist",
            allowBrowserContent: true,
            captureScope: "window",
            fieldSecurity: "denylist"
        )

        let privateTitles = [
            "GitHub - Google Chrome (Incognito)",
            "新标签页 - 无痕模式",
            "Mozilla Firefox (Private Browsing)",
            "InPrivate - Microsoft Edge",
            "Brave (Private)",
            "Fenster (Privat)",
            "Finestra (Privato)",
            "隐私浏览 - 浏览器",
            "私人浏览",
        ]
        for title in privateTitles {
            XCTAssertTrue(BrowserGate.isPrivateWindowTitle(title), title)
            let backend = MockAXBackend([
                0: MockNode(role: "AXWindow", children: [1], windowTitle: title),
                1: MockNode(role: "AXStaticText", parent: 0, text: "Private browsing content"),
            ])
            let outcome = SurfaceCaptureRunner.run(
                adapter: BrowserFamilyAdapter(),
                application: chromeApp,
                policy: policy,
                scope: "window",
                maxOutputNodes: 48,
                focus: AXNodeHandle(index: 1),
                budget: ReadBudget(deadlineMs: 5_000),
                clock: clock,
                backend: backend
            )
            XCTAssertEqual(outcome, .failure(.securityExcluded), title)
            XCTAssertTrue(backend.textReads.isEmpty, "Must read zero text for private window: \(title)")
            XCTAssertEqual(backend.inspectedIndices, [0], "Must abort on root window before inspecting children: \(title)")
        }

        // Ordinary browser window title proceeds normally and extracts display text + URLs while pruning empty disabled leaves.
        let normalTitle = "GitHub - Google Chrome"
        XCTAssertFalse(BrowserGate.isPrivateWindowTitle(normalTitle))
        XCTAssertFalse(BrowserGate.isPrivateWindowTitle("Private repository settings - GitHub"))
        let normalBackend = MockAXBackend([
            0: MockNode(role: "AXWindow", children: [1, 2, 3, 4], windowTitle: normalTitle),
            1: MockNode(
                role: "AXWebArea",
                parent: 0,
                displayText: SafeAXDisplayText.compose(
                    role: "AXWebArea",
                    title: "GitHub",
                    description: nil,
                    url: "https://github.com",
                    maxUnits: 256
                )
            ),
            2: MockNode(
                role: "AXHeading",
                parent: 0,
                displayText: SafeAXDisplayText.compose(
                    role: "AXHeading",
                    title: "Pull Requests",
                    description: nil,
                    url: nil,
                    maxUnits: 256
                )
            ),
            3: MockNode(role: "AXButton", parent: 0, isEnabled: false), // empty disabled leaf -> pruned
            4: MockNode(role: "AXStaticText", parent: 0, text: "Open 12"),
        ])
        let normalOutcome = SurfaceCaptureRunner.run(
            adapter: BrowserFamilyAdapter(),
            application: chromeApp,
            policy: policy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: normalBackend
        )
        guard case .success(let tree) = normalOutcome else {
            return XCTFail("Expected normal browser window to succeed, got \(normalOutcome)")
        }
        XCTAssertTrue(tree.nodes.contains { $0.axRole == "AXWebArea" && $0.text == "GitHub (https://github.com)" })
        XCTAssertTrue(tree.nodes.contains { $0.axRole == "AXHeading" && $0.role == "text" && $0.text == "Pull Requests" })
        XCTAssertTrue(tree.nodes.contains { $0.axRole == "AXStaticText" && $0.text == "Open 12" })
        XCTAssertFalse(tree.nodes.contains { $0.axRole == "AXButton" }, "Empty disabled leaf should be pruned")
    }

    func testExpandedPasswordManagersDeniedAndSystemUISilentlySkipped() {
        let denylistPolicy = CapturePolicy(
            allowedApplicationIds: [],
            applicationScope: "denylist",
            allowBrowserContent: true,
            captureScope: "window",
            fieldSecurity: "denylist"
        )

        for passwordApp in [
            "com.1password.1password",
            "com.agilebits.onepassword7",
            "com.apple.Safari",
            "com.apple.Passwords",
            "com.apple.keychainaccess",
            "com.bitwarden.desktop",
            "com.dashlane.dashlanephonefinal",
            "com.lastpass.LastPass",
            "com.nordsec.nordpass",
            "me.proton.pass.electron",
            "me.proton.pass.catalyst",
        ] {
            XCTAssertTrue(ApplicationPolicy.isMandatoryDenied(passwordApp), passwordApp)
            XCTAssertFalse(ApplicationPolicy.allows(passwordApp, policy: denylistPolicy), passwordApp)
            XCTAssertFalse(BrowserGate.allows(passwordApp, policy: denylistPolicy), passwordApp)
        }

        for systemUIApp in [
            "com.apple.WindowManager",
            "com.apple.controlcenter",
            "com.apple.notificationcenterui",
            "com.apple.SecurityAgent",
            "com.apple.LocalAuthentication.UIAgent",
            "com.apple.LocalAuthenticationRemoteService",
            "com.apple.loginwindow",
            "com.apple.UserNotificationCenter",
        ] {
            XCTAssertTrue(ApplicationPolicy.isSystemUI(systemUIApp), systemUIApp)
            XCTAssertFalse(ApplicationPolicy.allows(systemUIApp, policy: denylistPolicy), systemUIApp)
        }

        // System UI activation & excluded read produce zero gap records in CollectorEngine.
        let h = Harness()
        h.engine.receive(.object([
            "protocolVersion": j(1),
            "type": .string("configure"),
            "requestId": .string("cfg"),
            "ownerId": .string("owner"),
            "instanceId": .string("instance"),
            "policyRevision": j(1),
            "policy": try! JSONValue.parse(JSONEncoder().encode(denylistPolicy)),
        ]))
        h.control("start", lease: 30_000)
        h.clock.advance(51)
        h.engine.tick()
        let before = h.frames.count
        h.engine.applicationEvent(SourceHint(
            application: ApplicationIdentity(applicationId: "com.apple.controlcenter", processId: 77, processStartTime: "birth"),
            eventTimeMs: h.clock.unixMs
        ))
        XCTAssertEqual(h.frames.count, before, "System UI activation must not emit observations or gaps")
        h.clock.advance(51)
        h.engine.tick()
        let ticket = h.env.launched.last!
        h.engine.complete(ReadResult(
            token: ticket.token,
            reason: "application-excluded",
            diagnostic: ReadDiagnostic(code: .applicationNotAllowed),
            captureStartMs: h.clock.unixMs,
            captureEndMs: h.clock.unixMs
        ))
        XCTAssertEqual(h.frames.count, before, "System UI read skip must emit zero gap frames")
    }

    func testBatchedInspectionAbsoluteRectPopulatesBoundsWithZeroExtraBoundsCalls() {
        final class CountingRectBackend: AXSurfaceBackend {
            var boundsCalls = 0
            let windowRect = SurfaceAbsoluteRect(x: 100, y: 200, width: 800, height: 600)!

            func verifyDesktopAndApplication() -> SurfaceReadFailure? { nil }
            func inspectBackendNode(_ index: Int, isRoot: Bool) -> AXBackendInspection {
                if index == 0 {
                    return .allowed(
                        role: "AXWindow",
                        subrole: .noValue,
                        protectedContent: .value(false),
                        childCount: 1,
                        isFocused: false,
                        observedAtMs: 1_000,
                        absoluteRect: windowRect
                    )
                }
                return .allowed(
                    role: "AXStaticText",
                    subrole: .noValue,
                    protectedContent: .value(false),
                    childCount: 0,
                    isFocused: false,
                    observedAtMs: 1_001,
                    absoluteRect: SurfaceAbsoluteRect(x: 120, y: 250, width: 300, height: 24)
                )
            }
            func parentBackendNode(of index: Int) -> Int? { index == 1 ? 0 : nil }
            func childrenBackendPage(of index: Int, expectedRole: String, offset: Int, limit: Int) -> WeightedSurfaceChildrenRead<Int> {
                index == 0 && offset == 0 ? .values([1]) : .values([])
            }
            func readBackendNodeText(_ index: Int, expectedRole: String, maxUnits: Int, staticTextProbe: StaticTextPolicy) -> AXBackendTextRead {
                .text(value: "Batched bounds message", complete: true, reasons: [])
            }
            func readBackendNodeBounds(_ index: Int, windowRect: SurfaceAbsoluteRect) -> (SurfaceBounds, Int64)? {
                boundsCalls += 1
                return nil
            }
            func readBackendWindowRect() -> SurfaceAbsoluteRect? { windowRect }
            func verifyFinalSurfaceBoundary() -> SurfaceReadFailure? { nil }
        }

        let backend = CountingRectBackend()
        let app = ApplicationIdentity(applicationId: "com.tencent.xinWeChat", processId: 700, processStartTime: "birth")
        let policy = CapturePolicy(allowedApplicationIds: ["com.tencent.xinWeChat"], captureScope: "window", fieldSecurity: "denylist")
        let outcome = SurfaceCaptureRunner.run(
            adapter: WeChatAdapter(),
            application: app,
            policy: policy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: backend
        )
        guard case .success(let tree) = outcome else {
            return XCTFail("Expected WeChat surface capture to succeed, got \(outcome)")
        }
        XCTAssertEqual(backend.boundsCalls, 0, "Batched absoluteRect must avoid separate readBackendNodeBounds IPCs")
        let leaf = tree.nodes.first { $0.axRole == "AXStaticText" }
        XCTAssertEqual(leaf?.bounds, SurfaceBounds(x: 20, y: 50, width: 300, height: 24))
    }

    func testStaticTextFallbackUsesCachedTitleOrBoundedValueAndRejectsSensitiveNodes() {
        // 1. Cached batch safeTitle resolves with zero safety/value IPCs and enforces maxUnits + budget charging.
        var safetyCalls = 0
        var valueCalls = 0
        var chargedUnits = 0
        let fromTitle = StaticTextFallback.resolve(
            maxUnits: 12,
            cachedTitle: "WeChat message bubble text",
            cachedDescription: "Fallback desc",
            verifySafety: { safetyCalls += 1; return .ok },
            readValue: { valueCalls += 1; return "Should not read AXValue" },
            charge: { chargedUnits += $0; return true }
        )
        XCTAssertEqual(fromTitle, .text(value: "WeChat messa", truncated: true))
        XCTAssertEqual(safetyCalls, 0)
        XCTAssertEqual(valueCalls, 0)
        XCTAssertEqual(chargedUnits, 12)

        // 2. Empty or pure-PUA title falls back to cached description before touching AXValue.
        let fromDesc = StaticTextFallback.resolve(
            maxUnits: 64,
            cachedTitle: "   ",
            cachedDescription: "14:32",
            verifySafety: { safetyCalls += 1; return .ok },
            readValue: { valueCalls += 1; return "Unused" },
            charge: { chargedUnits += $0; return true }
        )
        XCTAssertEqual(fromDesc, .text(value: "14:32", truncated: false))
        let fromDescOverPUA = StaticTextFallback.resolve(
            maxUnits: 64,
            cachedTitle: "\u{EBB1}",
            cachedDescription: "Source Control",
            verifySafety: { safetyCalls += 1; return .ok },
            readValue: { valueCalls += 1; return "Unused" },
            charge: { chargedUnits += $0; return true }
        )
        XCTAssertEqual(fromDescOverPUA, .text(value: "Source Control", truncated: false))
        XCTAssertEqual(safetyCalls, 0)
        XCTAssertEqual(valueCalls, 0)

        // 3. Empty title and nil description verify safety before/after one bounded AXValue read.
        var headerCharged = 0
        let fromValue = StaticTextFallback.resolve(
            maxUnits: 6,
            cachedTitle: "",
            cachedDescription: nil,
            verifySafety: { safetyCalls += 1; return .ok },
            readValue: { valueCalls += 1; return "文件传输助手额外文字" },
            charge: { headerCharged += $0; return true }
        )
        XCTAssertEqual(fromValue, .text(value: "文件传输助手", truncated: true))
        XCTAssertEqual(safetyCalls, 2)
        XCTAssertEqual(valueCalls, 1)
        XCTAssertEqual(headerCharged, 6)

        // 4. Sensitive node detected pre-read must never invoke AXValue or charge text.
        var preSensitiveValueReads = 0
        var preSensitiveCharged = 0
        let blockedPre = StaticTextFallback.resolve(
            maxUnits: 64,
            cachedTitle: nil,
            cachedDescription: nil,
            verifySafety: { .sensitive },
            readValue: { preSensitiveValueReads += 1; return "secret" },
            charge: { preSensitiveCharged += $0; return true }
        )
        XCTAssertEqual(blockedPre, .sensitive)
        XCTAssertEqual(preSensitiveValueReads, 0)
        XCTAssertEqual(preSensitiveCharged, 0)

        // 5. Node turning sensitive during AXValue read discards value and never charges text.
        var checks = 0
        var postSensitiveCharged = 0
        let blockedPost = StaticTextFallback.resolve(
            maxUnits: 64,
            cachedTitle: nil,
            cachedDescription: nil,
            verifySafety: { checks += 1; return checks == 1 ? .ok : .sensitive },
            readValue: { "secret" },
            charge: { postSensitiveCharged += $0; return true }
        )
        XCTAssertEqual(blockedPost, .sensitive)
        XCTAssertEqual(postSensitiveCharged, 0)

        // 6. Text budget violation surfaces explicitly.
        let violated = StaticTextFallback.resolve(
            maxUnits: 64,
            cachedTitle: "Message",
            cachedDescription: nil,
            verifySafety: { .ok },
            readValue: { nil },
            charge: { _ in false }
        )
        XCTAssertEqual(violated, .textBudgetViolated)

        // 7. Explicitly empty AXValue returns .empty (avoiding multi-round range fallback),
        //    while nil AXValue returns .unavailable so callers can fall back to range probing.
        var emptySafetyChecks = 0
        let emptyValue = StaticTextFallback.resolve(
            maxUnits: 64,
            cachedTitle: "",
            cachedDescription: nil,
            verifySafety: { emptySafetyChecks += 1; return .ok },
            readValue: { "   " },
            charge: { _ in XCTFail("Empty value must not charge text"); return true }
        )
        XCTAssertEqual(emptyValue, .empty)
        XCTAssertEqual(emptySafetyChecks, 2)

        let missingValue = StaticTextFallback.resolve(
            maxUnits: 64,
            cachedTitle: nil,
            cachedDescription: nil,
            verifySafety: { .ok },
            readValue: { nil },
            charge: { _ in true }
        )
        XCTAssertEqual(missingValue, .unavailable)
    }

    func testWeChatAdapterExtractsChatPaneTailAndSkipsSessionListAndVirtualCells() {
        var nodes: [Int: MockNode] = [:]
        // Realistic WeChat 4.x Qt window layout from live AX probe.
        nodes[0] = MockNode(role: "AXWindow", children: [1], bounds: SurfaceAbsoluteRect(x: 100, y: 200, width: 1000, height: 700))
        nodes[1] = MockNode(role: "AXGroup", children: [2], parent: 0)
        nodes[2] = MockNode(role: "AXSplitGroup", children: [3, 4, 5], parent: 1, identifier: "main_window_main_splitter_view")
        // Left navigation buttons must be skipped.
        nodes[3] = MockNode(role: "AXButton", children: [30], parent: 2, displayText: "WeChat")
        nodes[30] = MockNode(role: "AXStaticText", parent: 3, text: "Left nav noise")
        nodes[4] = MockNode(role: "AXButton", parent: 2, displayText: "Contacts")
        // Sub-splitter holding left session_list and right chat pane.
        nodes[5] = MockNode(role: "AXSplitGroup", children: [6, 7], parent: 2, identifier: "main_window_sub_splitter_view")
        // Left session_list with 50 rows must never be expanded or read.
        let sessionRowIds = Array(500..<550)
        nodes[6] = MockNode(role: "AXList", children: sessionRowIds, parent: 5, identifier: "session_list")
        for rowId in sessionRowIds {
            nodes[rowId] = MockNode(role: "AXStaticText", parent: 6, text: "Session preview \(rowId)")
        }
        // Right chat pane: header + body splitter (chat_message_list + chat_input_field).
        nodes[7] = MockNode(role: "AXGroup", children: [8], parent: 5)
        nodes[8] = MockNode(role: "AXSplitGroup", children: [9, 12], parent: 7)
        nodes[9] = MockNode(role: "AXGroup", children: [10], parent: 8)
        nodes[10] = MockNode(role: "AXStaticText", children: [11], parent: 9, identifier: "big_title_line_h_view")
        nodes[11] = MockNode(
            role: "AXStaticText",
            parent: 10,
            text: "文件传输助手",
            reportedLength: 0,
            bounds: SurfaceAbsoluteRect(x: 360, y: 220, width: 200, height: 28),
            identifier: "current_chat_name_label"
        )
        nodes[12] = MockNode(role: "AXSplitGroup", children: [13, 14], parent: 8)

        // 120 children in chat_message_list: 0..87 old, 88..91 virtual_cell, 92 zero-size, 93 timestamp, 94..119 recent bubbles.
        let messageIds = Array(1000..<1120)
        nodes[13] = MockNode(
            role: "AXList",
            children: messageIds,
            parent: 12,
            bounds: SurfaceAbsoluteRect(x: 340, y: 260, width: 640, height: 480),
            identifier: "chat_message_list"
        )
        for offset in 0..<120 {
            let id = 1000 + offset
            if offset < 88 {
                nodes[id] = MockNode(
                    role: "AXStaticText",
                    parent: 13,
                    text: "Old msg \(offset)",
                    reportedLength: 0,
                    bounds: SurfaceAbsoluteRect(x: 360, y: 270, width: 220, height: 24),
                    identifier: "chat_bubble_item_view"
                )
            } else if offset < 92 {
                nodes[id] = MockNode(
                    role: "AXStaticText",
                    parent: 13,
                    text: "",
                    reportedLength: 0,
                    bounds: SurfaceAbsoluteRect(x: 100, y: 200, width: 0, height: 0),
                    identifier: "virtual_cell"
                )
            } else if offset == 92 {
                nodes[id] = MockNode(
                    role: "AXStaticText",
                    parent: 13,
                    text: "Hidden zero-size placeholder",
                    reportedLength: 0,
                    bounds: SurfaceAbsoluteRect(x: 100, y: 200, width: 0, height: 0)
                )
            } else if offset == 93 {
                nodes[id] = MockNode(
                    role: "AXStaticText",
                    parent: 13,
                    text: "14:20",
                    reportedLength: 0,
                    bounds: SurfaceAbsoluteRect(x: 600, y: 280, width: 60, height: 16)
                )
            } else {
                nodes[id] = MockNode(
                    role: "AXStaticText",
                    parent: 13,
                    text: "Recent msg \(offset)",
                    reportedLength: 0,
                    bounds: SurfaceAbsoluteRect(x: 360, y: Double(300 + (offset - 94) * 20), width: 260, height: 18),
                    identifier: "chat_bubble_item_view"
                )
            }
        }
        nodes[14] = MockNode(
            role: "AXTextArea",
            parent: 12,
            text: "Draft reply",
            isFocused: true,
            bounds: SurfaceAbsoluteRect(x: 340, y: 760, width: 640, height: 120),
            identifier: "chat_input_field"
        )

        let backend = MockAXBackend(nodes)
        backend.windowRect = SurfaceAbsoluteRect(x: 100, y: 200, width: 1000, height: 700)
        let app = ApplicationIdentity(applicationId: "com.tencent.xinWeChat", processId: 701, processStartTime: "birth")
        let policy = CapturePolicy(allowedApplicationIds: ["com.tencent.xinWeChat"], captureScope: "window", fieldSecurity: "denylist")
        let outcome = SurfaceCaptureRunner.run(
            adapter: WeChatAdapter(),
            application: app,
            policy: policy,
            scope: "window",
            maxOutputNodes: 48,
            focus: AXNodeHandle(index: 14),
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: backend
        )
        guard case .success(let tree) = outcome else {
            return XCTFail("Expected WeChat custom extraction to succeed, got \(outcome)")
        }
        XCTAssertEqual(tree.adapterId, "wechat")
        // Verify session_list was never expanded and left nav was never read.
        XCTAssertFalse(backend.childRequests.contains { $0.index == 6 }, "session_list children must never be requested")
        XCTAssertFalse(backend.textReads.contains(30), "Left nav button children must never be read")
        // Verify tail fetch requested exactly the last 32 children of the 120-item chat_message_list.
        let listPages = backend.childRequests.filter { $0.index == 13 }
        XCTAssertEqual(listPages.count, 1)
        XCTAssertEqual(listPages.first?.offset, 88)
        XCTAssertEqual(listPages.first?.limit, 32)
        // Verify virtual_cell and zero-size nodes were skipped without text reads.
        for skippedId in 1088...1092 {
            XCTAssertFalse(backend.textReads.contains(skippedId), "Virtual or zero-size cell \(skippedId) must not be text-read")
        }
        // Verify contact header, timestamp, chronological tail messages, and focused draft are extracted.
        let texts = tree.nodes.compactMap(\.text)
        XCTAssertEqual(texts.first, "文件传输助手")
        XCTAssertTrue(texts.contains("14:20"))
        XCTAssertTrue(texts.contains("Recent msg 94"))
        XCTAssertTrue(texts.contains("Recent msg 119"))
        XCTAssertFalse(texts.contains("Old msg 87"))
        XCTAssertFalse(texts.contains("Hidden zero-size placeholder"))
        XCTAssertFalse(texts.contains { $0.hasPrefix("Session preview") })
        let msg94Pos = texts.firstIndex(of: "Recent msg 94")!
        let msg119Pos = texts.firstIndex(of: "Recent msg 119")!
        XCTAssertLessThan(msg94Pos, msg119Pos, "Tail messages must stay in chronological order")
        let inputNode = tree.nodes.first { $0.axRole == "AXTextArea" }
        XCTAssertEqual(inputNode?.role, "editable")
        XCTAssertEqual(inputNode?.text, "Draft reply")
        XCTAssertEqual(inputNode?.focused, true)
        XCTAssertEqual(tree.nodes.filter { $0.focused == true }.count, 1)
        // Verify every emitted parentId resolves to another emitted node.
        let emittedIds = Set(tree.nodes.map(\.id))
        for node in tree.nodes {
            if let parentId = node.parentId {
                XCTAssertTrue(emittedIds.contains(parentId))
            }
        }
    }

    func testWeChatAdapterFallsBackToWeightedTraversalWhenIdentifiersAbsent() {
        let loginNodes: [Int: MockNode] = [
            0: MockNode(role: "AXWindow", children: [1]),
            1: MockNode(role: "AXGroup", children: [2, 3], parent: 0),
            2: MockNode(role: "AXStaticText", parent: 1, text: "Scan QR code to log in", reportedLength: 0),
            3: MockNode(role: "AXButton", parent: 1, displayText: "Switch Account"),
        ]
        let backend = MockAXBackend(loginNodes)
        let app = ApplicationIdentity(applicationId: "com.tencent.xinWeChat", processId: 702, processStartTime: "birth")
        let policy = CapturePolicy(allowedApplicationIds: ["com.tencent.xinWeChat"], captureScope: "window", fieldSecurity: "denylist")

        // Direct extractSurface returns nil when chat identifiers are absent.
        let context = SafeAXContext(
            application: app,
            policy: policy,
            spec: WeChatAdapter().spec,
            scope: "window",
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: backend
        )
        XCTAssertNil(WeChatAdapter().extractSurface(context: context))

        // SurfaceCaptureRunner automatically falls back to weighted traversal and captures login text.
        let outcome = SurfaceCaptureRunner.run(
            adapter: WeChatAdapter(),
            application: app,
            policy: policy,
            scope: "window",
            maxOutputNodes: 48,
            focus: nil,
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: MockAXBackend(loginNodes)
        )
        guard case .success(let tree) = outcome else {
            return XCTFail("Expected fallback traversal to succeed on WeChat login screen, got \(outcome)")
        }
        XCTAssertEqual(tree.adapterId, "wechat")
        XCTAssertTrue(tree.nodes.contains { $0.text == "Scan QR code to log in" })
    }

    func testTyporaAdapterExtractsWebKitMarkdownSurfaceAndProvesWindowOwnership() {
        // 1. WebKit focused elements omitting AXWindow fail under GenericAdapter (.focusedOnly)
        //    but resolve via AXTopLevelUIElement / AXParent chain under TyporaAdapter (.allowUnfocusedWindow).
        let windowHandle = 0
        let webAreaHandle = 1
        let focusedEditorHandle = 2
        let parents: [Int: Int] = [focusedEditorHandle: webAreaHandle, webAreaHandle: windowHandle]

        let genericOwnership = WindowOwnership.match(
            expectedWindow: windowHandle,
            allowTopLevel: GenericAdapter().spec.windowAnchor.allowsTopLevelFallback,
            direct: { .absent },
            topLevel: { .value(windowHandle) },
            same: ==,
            verifyTopLevelWindow: { $0 == windowHandle },
            shouldContinue: { true }
        )
        XCTAssertNil(genericOwnership, "GenericAdapter (.focusedOnly) must fail when focused WebKit node omits AXWindow")

        let typoraTopLevelOwnership = WindowOwnership.match(
            expectedWindow: windowHandle,
            allowTopLevel: TyporaAdapter().spec.windowAnchor.allowsTopLevelFallback,
            direct: { .absent },
            topLevel: { .value(windowHandle) },
            same: ==,
            verifyTopLevelWindow: { $0 == windowHandle },
            shouldContinue: { true }
        )
        XCTAssertEqual(typoraTopLevelOwnership, .topLevel)

        let typoraParentChainOwnership = WindowOwnership.match(
            expectedWindow: windowHandle,
            allowTopLevel: TyporaAdapter().spec.windowAnchor.allowsTopLevelFallback,
            direct: { .absent },
            topLevel: { .absent },
            same: ==,
            verifyTopLevelWindow: { $0 == windowHandle },
            shouldContinue: { true },
            parentChain: {
                WindowOwnership.walkParentChain(
                    from: focusedEditorHandle,
                    expectedWindow: windowHandle,
                    parent: { parents[$0] },
                    same: ==,
                    verifyHop: { _ in true },
                    shouldContinue: { true }
                )
            }
        )
        XCTAssertEqual(typoraParentChainOwnership, .parentChain)

        // 2. Declarative surface extraction preserves WebKit Markdown headings/paragraphs (up to 512 units),
        //    prunes HTML/native menu and toolbar chrome, allows local files titled "(Private)",
        //    and still enforces kernel protected-field blocking.
        let longParagraph = String(repeating: "Markdown paragraph content. ", count: 14) // 392 UTF-16 units (> 256, <= 512)
        let typoraNodes: [Int: MockNode] = [
            0: MockNode(role: "AXWindow", children: [1, 2, 3], windowTitle: "Architecture Notes (Private).md"),
            1: MockNode(role: "AXToolbar", children: [10], parent: 0),
            10: MockNode(role: "AXStaticText", parent: 1, text: "Toolbar noise"),
            2: MockNode(role: "AXScrollArea", children: [4], parent: 0),
            3: MockNode(role: "AXMenu", children: [11], parent: 0),
            11: MockNode(role: "AXMenuItem", parent: 3, displayText: "Hidden context menu"),
            4: MockNode(role: "AXWebArea", children: [5, 6, 7, 8], parent: 2, displayText: "Architecture Notes"),
            5: MockNode(role: "AXHeading", parent: 4, displayText: "Design Overview"),
            6: MockNode(role: "AXTextArea", parent: 4, text: "Active Markdown draft", isFocused: true),
            7: MockNode(role: "AXStaticText", parent: 4, text: longParagraph),
            8: MockNode(role: "AXSecureTextField", parent: 4, text: "must-never-read"),
        ]
        let backend = MockAXBackend(typoraNodes)
        let app = ApplicationIdentity(applicationId: "abnerworks.Typora", processId: 703, processStartTime: "birth")
        let policy = CapturePolicy(
            allowedApplicationIds: [],
            applicationScope: "denylist",
            allowBrowserContent: true,
            captureScope: "window",
            fieldSecurity: "denylist"
        )
        let outcome = SurfaceCaptureRunner.run(
            adapter: TyporaAdapter(),
            application: app,
            policy: policy,
            scope: "window",
            maxOutputNodes: 48,
            focus: AXNodeHandle(index: 6),
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: backend
        )
        guard case .success(let tree) = outcome else {
            return XCTFail("Expected Typora surface capture to succeed, got \(outcome)")
        }
        XCTAssertEqual(tree.adapterId, "typora")
        XCTAssertTrue(tree.nodes.contains { $0.axRole == "AXHeading" && $0.text == "Design Overview" })
        XCTAssertTrue(tree.nodes.contains { $0.axRole == "AXTextArea" && $0.text == "Active Markdown draft" && $0.focused == true })
        XCTAssertTrue(tree.nodes.contains { $0.axRole == "AXStaticText" && $0.text == longParagraph })
        XCTAssertFalse(tree.nodes.contains { $0.text == "Toolbar noise" })
        XCTAssertFalse(tree.nodes.contains { $0.text == "Hidden context menu" })
        XCTAssertFalse(backend.textReads.contains(8), "Protected field inside Typora must never be text-read")
        XCTAssertFalse(tree.nodes.contains { $0.text == "must-never-read" })
    }

    func testPrivateUseOnlyTextHelperAndSafeLabelSecurityGating() {
        XCTAssertFalse(isPrivateUseOnlyText(""))
        XCTAssertFalse(isPrivateUseOnlyText("   \t\n "))
        XCTAssertTrue(isPrivateUseOnlyText("\u{E000}"))
        XCTAssertTrue(isPrivateUseOnlyText("\u{EBB1}"))
        XCTAssertTrue(isPrivateUseOnlyText(" \u{EBB1} \u{F8FF} "))
        XCTAssertTrue(isPrivateUseOnlyText("\u{F0000}"))
        XCTAssertTrue(isPrivateUseOnlyText("\u{FFFFD}"))
        XCTAssertTrue(isPrivateUseOnlyText("\u{100000}"))
        XCTAssertTrue(isPrivateUseOnlyText("\u{10FFFD}"))
        XCTAssertFalse(isPrivateUseOnlyText("\u{EBB1} AppAdapter.swift"))
        XCTAssertFalse(isPrivateUseOnlyText("200 Fill × 32 Hug"))
        XCTAssertFalse(isPrivateUseOnlyText("Hello"))

        // SafeAXDisplayText.label drops pure PUA titles and falls back to non-PUA description.
        XCTAssertEqual(
            SafeAXDisplayText.label(title: "\u{EBB1}", description: "Source Control", maxUnits: 64),
            "Source Control"
        )
        XCTAssertNil(SafeAXDisplayText.label(title: "\u{EBB1}", description: " \u{EA60} ", maxUnits: 64))
        XCTAssertEqual(
            SafeAXDisplayText.label(title: "   ", description: "Right sidebar", maxUnits: 64),
            "Right sidebar"
        )

        // AXNodeInfo exposes subrole & label on safe nodes, and strictly blocks them on sensitive nodes.
        let backend = MockAXBackend([
            0: MockNode(role: "AXWindow", children: [1, 2, 3]),
            1: MockNode(role: "AXGroup", subrole: .value("AXLandmarkMain"), parent: 0, label: "Figma Design, 1 item selected"),
            2: MockNode(role: "AXSecureTextField", parent: 0, label: "Secret Password Field"),
            3: MockNode(role: "AXGroup", subrole: .value("AXLandmarkRegion"), protectedContent: .value(true), parent: 0, label: "Protected Vault"),
        ])
        let app = ApplicationIdentity(applicationId: "org.example.app", processId: 801, processStartTime: "birth")
        let policy = CapturePolicy(allowedApplicationIds: ["org.example.app"], captureScope: "window", fieldSecurity: "denylist")
        let context = SafeAXContext(
            application: app,
            policy: policy,
            spec: GenericAdapter().spec,
            scope: "window",
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: backend
        )
        XCTAssertNotNil(context.inspect(AXNodeHandle(index: 0)))
        let safeInfo = context.inspect(AXNodeHandle(index: 1))
        XCTAssertEqual(safeInfo?.subrole, "AXLandmarkMain")
        XCTAssertEqual(safeInfo?.label, "Figma Design, 1 item selected")
        XCTAssertNil(context.inspect(AXNodeHandle(index: 2)), "AXSecureTextField must never expose AXNodeInfo or label")
        XCTAssertNil(context.inspect(AXNodeHandle(index: 3)), "Protected content must never expose AXNodeInfo or label")
        XCTAssertNil(context.displayText(of: AXNodeHandle(index: 2)))
        XCTAssertNil(context.displayText(of: AXNodeHandle(index: 3)))
    }

    func testVSCodeFamilyAdapterProbesZeroLengthStaticTextPrunesStatusBarAndSkipsPUACodicons() {
        var nodes: [Int: MockNode] = [:]
        // Window -> WebArea containing:
        // - status bar (AXApplicationStatus) with 26 noisy extension buttons
        // - tab group with PUA Codicon glyphs + zero-length AXStaticText tab labels
        // - center code AXTextArea
        // - right nested Agent AXWebArea with zero-length AXStaticText chat reply
        let statusChildren = Array(100..<126)
        nodes[0] = MockNode(role: "AXWindow", children: [1], windowTitle: "computer-history-mcp — AppAdapter.swift")
        nodes[1] = MockNode(role: "AXWebArea", children: [2, 3, 4, 5], parent: 0, displayText: "Antigravity IDE")
        nodes[2] = MockNode(role: "AXGroup", subrole: .value("AXApplicationStatus"), children: statusChildren, parent: 1, identifier: "workbench.parts.statusbar")
        for (offset, childId) in statusChildren.enumerated() {
            let extName = ["WakaTime", "GitLens", "Prettier", "SQLTools", "SweetPad", "oxc"][offset % 6]
            nodes[childId] = MockNode(role: "AXButton", parent: 2, displayText: "\(extName) \(offset)")
        }

        nodes[3] = MockNode(role: "AXTabGroup", children: [10, 11, 12, 13], parent: 1)
        nodes[10] = MockNode(role: "AXStaticText", parent: 3, text: "\u{EBB1}", reportedLength: 0)
        nodes[11] = MockNode(role: "AXStaticText", parent: 3, text: "\u{EA60}", reportedLength: 0)
        nodes[12] = MockNode(role: "AXStaticText", parent: 3, text: "AppAdapter.swift", reportedLength: 0)
        nodes[13] = MockNode(role: "AXStaticText", parent: 3, text: "\u{EBB1} BuiltInAdapters.swift", reportedLength: 0)

        nodes[4] = MockNode(role: "AXTextArea", parent: 1, text: "public struct FigmaAdapter: AppAdapter {}", isFocused: true)

        nodes[5] = MockNode(role: "AXWebArea", children: [20, 21], parent: 1, displayText: "Agent")
        nodes[20] = MockNode(role: "AXStaticText", parent: 5, text: "\u{E001}", reportedLength: 0)
        nodes[21] = MockNode(role: "AXStaticText", parent: 5, text: "Agent response about Batch B", reportedLength: 0)

        let backend = MockAXBackend(nodes)
        let app = ApplicationIdentity(applicationId: "com.google.antigravity-ide", processId: 802, processStartTime: "birth")
        let policy = CapturePolicy(allowedApplicationIds: ["com.google.antigravity-ide"], captureScope: "window", fieldSecurity: "denylist")
        let outcome = SurfaceCaptureRunner.run(
            adapter: VSCodeFamilyAdapter(),
            application: app,
            policy: policy,
            scope: "window",
            maxOutputNodes: 24,
            focus: AXNodeHandle(index: 4),
            budget: ReadBudget(deadlineMs: 5_000),
            clock: clock,
            backend: backend
        )
        guard case .success(let tree) = outcome else {
            return XCTFail("Expected VSCodeFamilyAdapter capture to succeed, got \(outcome)")
        }
        XCTAssertEqual(tree.adapterId, "vscode-family")
        // Status bar subtree must be pruned at AXApplicationStatus without touching its 26 children.
        XCTAssertFalse(backend.childRequests.contains { $0.index == 2 }, "AXApplicationStatus children must never be requested")
        for statusChildId in statusChildren {
            XCTAssertFalse(backend.inspectedIndices.contains(statusChildId), "Status bar item \(statusChildId) must never be inspected")
        }
        let texts = tree.nodes.compactMap(\.text)
        XCTAssertFalse(texts.contains { $0.contains("WakaTime") || $0.contains("GitLens") || $0.contains("Prettier") })
        // Zero-length AXStaticText is recovered via .boundedRangeProbe(maxUnits: 256).
        XCTAssertTrue(texts.contains("AppAdapter.swift"))
        XCTAssertTrue(texts.contains("\u{EBB1} BuiltInAdapters.swift"))
        XCTAssertTrue(texts.contains("public struct FigmaAdapter: AppAdapter {}"))
        XCTAssertTrue(texts.contains("Agent response about Batch B"))
        // Pure PUA Codicon glyphs must not appear in emitted nodes or burn output slots.
        XCTAssertFalse(texts.contains("\u{EBB1}"))
        XCTAssertFalse(texts.contains("\u{EA60}"))
        XCTAssertFalse(texts.contains("\u{E001}"))
    }
}

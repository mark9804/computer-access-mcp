import Foundation
import XCTest
import HistoryContract
@testable import CollectorCore

final class MenuActionTests: XCTestCase {
    private final class SyntheticNode {
        let id: String
        var meta: MenuNodeMetadata
        weak var parent: SyntheticNode?
        init(_ id: String, meta: MenuNodeMetadata, parent: SyntheticNode? = nil) {
            self.id = id
            self.meta = meta
            self.parent = parent
        }
    }

    private func node(
        _ id: String,
        role: String?,
        title: String? = nil,
        description: String? = nil,
        pid: Int32 = 42,
        enabled: Bool? = true,
        subrole: TextSecurityGate.SubroleRead = .noValue,
        protectedContent: TextSecurityGate.ProtectedContentRead = .noValue,
        childCount: Int? = 0,
        parent: SyntheticNode? = nil
    ) -> SyntheticNode {
        SyntheticNode(
            id,
            meta: MenuNodeMetadata(
                pid: pid,
                role: role,
                subrole: subrole,
                protectedContent: protectedContent,
                enabled: enabled,
                title: title,
                description: description,
                childCount: childCount
            ),
            parent: parent
        )
    }

    private func resolve(
        leaf: SyntheticNode,
        expectedPid: Int32 = 42,
        appMenuBar: SyntheticNode,
        appleItem: SyntheticNode,
        shouldContinue: @escaping () -> Bool = { true }
    ) -> ResolvedMenuPath? {
        MenuPathResolver.resolve(
            leaf: leaf,
            expectedPid: expectedPid,
            appMenuBar: appMenuBar,
            appleMenuBarItem: appleItem,
            same: { $0 === $1 },
            inspect: { element, isLeaf in
                isLeaf ? element.meta : MenuNodeMetadata(
                    pid: element.meta.pid,
                    role: element.meta.role,
                    subrole: element.meta.subrole,
                    protectedContent: element.meta.protectedContent,
                    enabled: element.meta.enabled,
                    title: element.meta.title,
                    description: element.meta.description,
                    childCount: nil
                )
            },
            parent: { $0.parent },
            shouldContinue: shouldContinue
        )
    }

    // MARK: - MenuPathResolver Tests

    func testResolverBuildsTwoLevelAndMultiLevelSubmenuPaths() {
        let menuBar = node("bar", role: "AXMenuBar")
        let apple = node("apple", role: "AXMenuBarItem", title: "Apple", parent: menuBar)
        let fileBar = node("file-bar", role: "AXMenuBarItem", title: "File", parent: menuBar)
        let fileMenu = node("file-menu", role: "AXMenu", parent: fileBar)
        let save = node("save", role: "AXMenuItem", title: "Save", childCount: 0, parent: fileMenu)

        let twoLevel = resolve(leaf: save, appMenuBar: menuBar, appleItem: apple)
        XCTAssertEqual(twoLevel, ResolvedMenuPath(path: ["File", "Save"], truncated: false))

        let exportItem = node("export", role: "AXMenuItem", title: "Export", childCount: 1, parent: fileMenu)
        let exportMenu = node("export-menu", role: "AXMenu", parent: exportItem)
        let pdf = node("pdf", role: "AXMenuItem", title: "PDF...", childCount: 0, parent: exportMenu)
        let threeLevel = resolve(leaf: pdf, appMenuBar: menuBar, appleItem: apple)
        XCTAssertEqual(threeLevel, ResolvedMenuPath(path: ["File", "Export", "PDF..."], truncated: false))

        // 6-level path uses 11 parent hops (within the 12-hop limit).
        let s2 = node("s2", role: "AXMenuItem", title: "L2", childCount: 1, parent: fileMenu)
        let m2 = node("m2", role: "AXMenu", parent: s2)
        let s3 = node("s3", role: "AXMenuItem", title: "L3", childCount: 1, parent: m2)
        let m3 = node("m3", role: "AXMenu", parent: s3)
        let s4 = node("s4", role: "AXMenuItem", title: "L4", childCount: 1, parent: m3)
        let m4 = node("m4", role: "AXMenu", parent: s4)
        let s5 = node("s5", role: "AXMenuItem", title: "L5", childCount: 1, parent: m4)
        let m5 = node("m5", role: "AXMenu", parent: s5)
        let leaf6 = node("leaf6", role: "AXMenuItem", title: "L6", childCount: 0, parent: m5)
        XCTAssertEqual(
            resolve(leaf: leaf6, appMenuBar: menuBar, appleItem: apple),
            ResolvedMenuPath(path: ["File", "L2", "L3", "L4", "L5", "L6"], truncated: false)
        )

        // Direct-chained 8 segments (8 hops <= 12) succeed; 9 segments fail.
        var chain: [SyntheticNode] = [fileBar]
        for level in 2...8 {
            let next = node("d\(level)", role: "AXMenuItem", title: "L\(level)", childCount: level == 8 ? 0 : 1, parent: chain.last)
            chain.append(next)
        }
        XCTAssertEqual(
            resolve(leaf: chain.last!, appMenuBar: menuBar, appleItem: apple)?.path,
            ["File", "L2", "L3", "L4", "L5", "L6", "L7", "L8"]
        )
        let tooDeep = node("d9", role: "AXMenuItem", title: "L9", childCount: 0, parent: chain.last)
        XCTAssertNil(resolve(leaf: tooDeep, appMenuBar: menuBar, appleItem: apple))
    }

    func testResolverRejectsSubmenuOpenersDisabledNonLeafAndExceedingHopCap() {
        let menuBar = node("bar", role: "AXMenuBar")
        let apple = node("apple", role: "AXMenuBarItem", title: "Apple", parent: menuBar)
        let fileBar = node("file-bar", role: "AXMenuBarItem", title: "File", parent: menuBar)
        let fileMenu = node("file-menu", role: "AXMenu", parent: fileBar)

        // Submenu opener (childCount > 0) and failed count (nil) must be rejected.
        let opener = node("opener", role: "AXMenuItem", title: "Export", childCount: 1, parent: fileMenu)
        XCTAssertNil(resolve(leaf: opener, appMenuBar: menuBar, appleItem: apple))
        let unknownCount = node("unknown", role: "AXMenuItem", title: "Save", childCount: nil, parent: fileMenu)
        XCTAssertNil(resolve(leaf: unknownCount, appMenuBar: menuBar, appleItem: apple))

        // Disabled leaf rejected; absent enabled (nil) allowed.
        let disabled = node("disabled", role: "AXMenuItem", title: "Save", enabled: false, childCount: 0, parent: fileMenu)
        XCTAssertNil(resolve(leaf: disabled, appMenuBar: menuBar, appleItem: apple))
        let nilEnabled = node("nil-enabled", role: "AXMenuItem", title: "Save", enabled: nil, childCount: 0, parent: fileMenu)
        XCTAssertEqual(resolve(leaf: nilEnabled, appMenuBar: menuBar, appleItem: apple)?.path, ["File", "Save"])

        // Non-AXMenuItem leaf rejected.
        let barItemLeaf = node("bar-leaf", role: "AXMenuBarItem", title: "File", childCount: 0, parent: menuBar)
        XCTAssertNil(resolve(leaf: barItemLeaf, appMenuBar: menuBar, appleItem: apple))

        // > 12 parent hops rejected (while retaining every intermediate node in memory).
        var wrappers: [SyntheticNode] = [fileMenu]
        for i in 0..<11 {
            wrappers.append(node("wrap-\(i)", role: "AXMenu", parent: wrappers.last))
        }
        let beyondHopCap = node("far", role: "AXMenuItem", title: "Far", childCount: 0, parent: wrappers.last)
        XCTAssertNil(resolve(leaf: beyondHopCap, appMenuBar: menuBar, appleItem: apple))
        // Exact 12 hops (9 wrappers + fileMenu + fileBar + menuBar) accepted; 13 hops rejected.
        let exactHopCap = node("exact12", role: "AXMenuItem", title: "Exact12", childCount: 0, parent: wrappers[9])
        XCTAssertEqual(resolve(leaf: exactHopCap, appMenuBar: menuBar, appleItem: apple)?.path, ["File", "Exact12"])
        let overHopCap = node("over13", role: "AXMenuItem", title: "Over13", childCount: 0, parent: wrappers[10])
        XCTAssertNil(resolve(leaf: overHopCap, appMenuBar: menuBar, appleItem: apple))
    }

    func testResolverRejectsAppleMenuExtrasMenuBarContextMenusCyclesCrossPIDAndSensitiveNodes() {
        let menuBar = node("bar", role: "AXMenuBar")
        let apple = node("apple", role: "AXMenuBarItem", title: "苹果", parent: menuBar)
        let appleMenu = node("apple-menu", role: "AXMenu", parent: apple)
        let logOut = node("logout", role: "AXMenuItem", title: "Log Out User...", childCount: 0, parent: appleMenu)
        XCTAssertNil(resolve(leaf: logOut, appMenuBar: menuBar, appleItem: apple))

        // Submenu under Apple menu (e.g., Recent Items) must also be rejected.
        let recentItem = node("recent", role: "AXMenuItem", title: "Recent Items", childCount: 1, parent: appleMenu)
        let recentMenu = node("recent-menu", role: "AXMenu", parent: recentItem)
        let recentDoc = node("recent-doc", role: "AXMenuItem", title: "Secret.pdf", childCount: 0, parent: recentMenu)
        XCTAssertNil(resolve(leaf: recentDoc, appMenuBar: menuBar, appleItem: apple))

        // Extras menu bar (NSStatusItem on right side) fails CFEqual against appMenuBar.
        let extrasBar = node("extras-bar", role: "AXMenuBar")
        let statusItem = node("status", role: "AXMenuBarItem", title: "Wi-Fi", parent: extrasBar)
        let statusMenu = node("status-menu", role: "AXMenu", parent: statusItem)
        let statusLeaf = node("status-leaf", role: "AXMenuItem", title: "Settings...", childCount: 0, parent: statusMenu)
        XCTAssertNil(resolve(leaf: statusLeaf, appMenuBar: menuBar, appleItem: apple))

        // Right-click context menu under AXWindow / AXApplication / nil parent.
        let window = node("win", role: "AXWindow")
        let ctxMenu = node("ctx", role: "AXMenu", parent: window)
        let ctxLeaf = node("ctx-leaf", role: "AXMenuItem", title: "Copy", childCount: 0, parent: ctxMenu)
        XCTAssertNil(resolve(leaf: ctxLeaf, appMenuBar: menuBar, appleItem: apple))

        // Cycle protection.
        let cycA = node("cyc-a", role: "AXMenu")
        let cycB = node("cyc-b", role: "AXMenu", parent: cycA)
        cycA.parent = cycB
        let cycLeaf = node("cyc-leaf", role: "AXMenuItem", title: "Loop", childCount: 0, parent: cycB)
        XCTAssertNil(resolve(leaf: cycLeaf, appMenuBar: menuBar, appleItem: apple))

        // Cross-PID hop rejected.
        let fileBar = node("file-bar", role: "AXMenuBarItem", title: "File", parent: menuBar)
        let foreignMenu = node("foreign", role: "AXMenu", pid: 99, parent: fileBar)
        let foreignLeaf = node("foreign-leaf", role: "AXMenuItem", title: "Save", childCount: 0, parent: foreignMenu)
        XCTAssertNil(resolve(leaf: foreignLeaf, expectedPid: 42, appMenuBar: menuBar, appleItem: apple))

        // Sensitive subrole / protectedContent / malformed security metadata rejected on leaf and ancestors.
        let okMenu = node("ok-menu", role: "AXMenu", parent: fileBar)
        let protectedLeaf = node("prot", role: "AXMenuItem", title: "Secret", protectedContent: .value(true), childCount: 0, parent: okMenu)
        XCTAssertNil(resolve(leaf: protectedLeaf, appMenuBar: menuBar, appleItem: apple))

        let failedProtLeaf = node("fail-prot", role: "AXMenuItem", title: "Secret", protectedContent: .failure, childCount: 0, parent: okMenu)
        XCTAssertNil(resolve(leaf: failedProtLeaf, appMenuBar: menuBar, appleItem: apple))

        let sensitiveSubroleLeaf = node("sec-sub", role: "AXMenuItem", title: "Key", subrole: .value("AXPasswordItem"), childCount: 0, parent: okMenu)
        XCTAssertNil(resolve(leaf: sensitiveSubroleLeaf, appMenuBar: menuBar, appleItem: apple))

        let protectedMenu = node("prot-menu", role: "AXMenu", protectedContent: .value(true), parent: fileBar)
        let underProtected = node("under-prot", role: "AXMenuItem", title: "Open", childCount: 0, parent: protectedMenu)
        XCTAssertNil(resolve(leaf: underProtected, appMenuBar: menuBar, appleItem: apple))

        // Cancellation / deadline aborts immediately.
        let normalLeaf = node("normal", role: "AXMenuItem", title: "Save", childCount: 0, parent: okMenu)
        var calls = 0
        XCTAssertNil(resolve(leaf: normalLeaf, appMenuBar: menuBar, appleItem: apple, shouldContinue: {
            calls += 1
            return calls <= 2
        }))
    }

    func testSanitizationAndUTF16BudgetTruncationPreserveValidSurrogatePairs() {
        let menuBar = node("bar", role: "AXMenuBar")
        let apple = node("apple", role: "AXMenuBarItem", title: "Apple", parent: menuBar)
        let fileBar = node("file-bar", role: "AXMenuBarItem", title: " \u{FEFF}File\t\r\n ", parent: menuBar)
        let fileMenu = node("file-menu", role: "AXMenu", parent: fileBar)

        // Collapses CR/LF/TAB to space, strips C0 & C1 controls, trims U+FEFF.
        let messy = node("messy", role: "AXMenuItem", title: "\u{0000}Save\r\n\tAs\u{007F}\u{0085}\u{009F}\u{FEFF}", childCount: 0, parent: fileMenu)
        XCTAssertEqual(
            resolve(leaf: messy, appMenuBar: menuBar, appleItem: apple),
            ResolvedMenuPath(path: ["File", "Save As"], truncated: false)
        )

        // Blank title falls back to description; blank in both is rejected.
        let descFallback = node("desc", role: "AXMenuItem", title: " \u{00A0}\u{3000}\u{FEFF} ", description: "Print...", childCount: 0, parent: fileMenu)
        XCTAssertEqual(
            resolve(leaf: descFallback, appMenuBar: menuBar, appleItem: apple),
            ResolvedMenuPath(path: ["File", "Print..."], truncated: false)
        )
        let allBlank = node("blank", role: "AXMenuItem", title: "\u{00A0}\u{3000}\u{FEFF}", description: "\u{0000}\t", childCount: 0, parent: fileMenu)
        XCTAssertNil(resolve(leaf: allBlank, appMenuBar: menuBar, appleItem: apple))

        // Exact 128 UTF-16 units per segment and 512 total (4 * 64 supplementary scalars): NOT truncated.
        let pair = "\u{1D11E}"
        let exact128 = String(repeating: pair, count: 64)
        XCTAssertEqual(exact128.utf16.count, 128)
        let exactPath = MenuPathLimits.boundPath([exact128, exact128, exact128, exact128])
        XCTAssertEqual(exactPath, ResolvedMenuPath(path: [exact128, exact128, exact128, exact128], truncated: false))

        // Segment of 129 UTF-16 units ("a" + 64 supplementary pairs) truncates to 127 (never splits surrogate).
        let boundary129 = "a" + exact128
        let clippedLeaf = node("clip", role: "AXMenuItem", title: boundary129, childCount: 0, parent: fileMenu)
        let resolvedClip = resolve(leaf: clippedLeaf, appMenuBar: menuBar, appleItem: apple)
        XCTAssertEqual(resolvedClip?.truncated, true)
        XCTAssertEqual(resolvedClip?.path[1].utf16.count, 127)
        XCTAssertTrue(MenuPathLimits.isValidPath(resolvedClip?.path ?? []))

        // 6 segments of 120 UTF-16 units (total 720 > 512) fit within 512 with every segment non-empty.
        let seg120 = String(repeating: pair, count: 60)
        let sixLong = MenuPathLimits.boundPath(Array(repeating: seg120, count: 6))
        XCTAssertNotNil(sixLong)
        XCTAssertEqual(sixLong?.truncated, true)
        XCTAssertEqual(sixLong?.path.count, 6)
        XCTAssertLessThanOrEqual(sixLong!.path.reduce(0) { $0 + $1.utf16.count }, 512)
        XCTAssertTrue(MenuPathLimits.isValidPath(sixLong!.path))
    }

    func testClassifyOpenedMenuDistinguishesTopLevelSubmenuAndExcludedMenus() {
        let menuBar = node("bar", role: "AXMenuBar")
        let apple = node("apple", role: "AXMenuBarItem", title: "Apple", parent: menuBar)
        let appleMenu = node("apple-menu", role: "AXMenu", parent: apple)
        let fileBar = node("file-bar", role: "AXMenuBarItem", title: "File", parent: menuBar)
        let fileMenu = node("file-menu", role: "AXMenu", parent: fileBar)
        let exportItem = node("export", role: "AXMenuItem", title: "Export", childCount: 1, parent: fileMenu)
        let exportMenu = node("export-menu", role: "AXMenu", parent: exportItem)
        let extrasBar = node("extras-bar", role: "AXMenuBar")
        let extrasItem = node("extras-item", role: "AXMenuBarItem", title: "Status", parent: extrasBar)
        let extrasMenu = node("extras-menu", role: "AXMenu", parent: extrasItem)
        let window = node("win", role: "AXWindow")
        let contextMenu = node("ctx", role: "AXMenu", parent: window)

        func classify(_ menu: SyntheticNode, open: [SyntheticNode] = []) -> OpenedMenuKind? {
            MenuPathResolver.classifyOpenedMenu(
                menu: menu,
                expectedPid: 42,
                appMenuBar: menuBar,
                appleMenuBarItem: apple,
                openMenus: open,
                same: { $0 === $1 },
                inspect: { $0.meta },
                parent: { $0.parent },
                shouldContinue: { true }
            )
        }

        XCTAssertEqual(classify(fileMenu), .topLevel)
        XCTAssertEqual(classify(exportMenu, open: [fileMenu]), .submenu)
        XCTAssertEqual(classify(exportMenu, open: []), .submenu)
        XCTAssertNil(classify(appleMenu))
        XCTAssertNil(classify(extrasMenu))
        XCTAssertNil(classify(contextMenu))
    }

    // MARK: - MenuTrackingStateMachine Tests

    func testStateMachineTracksOpenMenusSingleConsumeCommitFreshnessAndStaleResets() {
        var sm = MenuTrackingStateMachine<String, ResolvedMenuPath>(same: ==)
        XCTAssertFalse(sm.isTracking)
        XCTAssertNil(sm.commit(nowMs: 1_000))

        // Opening top-level menu starts tracking.
        let openFile = sm.menuOpened("file", isTopLevel: true)
        XCTAssertEqual(openFile.trackingChanged, true)
        XCTAssertTrue(openFile.removed.isEmpty)
        XCTAssertTrue(sm.isTracking)

        // Hovering a leaf stores volatile selection without emitting.
        let savePath = ResolvedMenuPath(path: ["File", "Save"], truncated: false)
        sm.updateSelection(savePath, from: "file", nowMs: 1_000)
        XCTAssertTrue(sm.hasSelection)

        // Duplicate top-level open for same menu is idempotent and preserves selection.
        let dupFile = sm.menuOpened("file", isTopLevel: true)
        XCTAssertNil(dupFile.trackingChanged)
        XCTAssertTrue(dupFile.removed.isEmpty)
        XCTAssertTrue(sm.hasSelection)

        // Commit consumes selection ONCE (zero double-fire).
        XCTAssertEqual(sm.commit(nowMs: 1_500), savePath)
        XCTAssertFalse(sm.hasSelection)
        XCTAssertNil(sm.commit(nowMs: 1_501))

        // Selection freshness boundary: <= 10_000ms accepted, > 10_000ms or rollback rejected.
        sm.updateSelection(savePath, from: "file", nowMs: 2_000)
        XCTAssertEqual(sm.commit(nowMs: 12_000), savePath)
        sm.updateSelection(savePath, from: "file", nowMs: 2_000)
        XCTAssertNil(sm.commit(nowMs: 12_001))
        sm.updateSelection(savePath, from: "file", nowMs: 2_000)
        XCTAssertNil(sm.commit(nowMs: 1_999))

        // Submenu tracking & parent-selection preservation when submenu closes after parent hover.
        let openExport = sm.menuOpened("export", isTopLevel: false)
        XCTAssertNil(openExport.trackingChanged)
        XCTAssertEqual(sm.openMenus, ["file", "export"])
        let pdfPath = ResolvedMenuPath(path: ["File", "Export", "PDF"], truncated: false)
        sm.updateSelection(pdfPath, from: "export", nowMs: 3_000)
        let closeExport = sm.menuClosed("export")
        XCTAssertNil(closeExport.trackingChanged)
        XCTAssertEqual(closeExport.removed, ["export"])
        XCTAssertFalse(sm.hasSelection)

        // Esc / cancel clears selection without dropping openMenus.
        sm.updateSelection(savePath, from: "file", nowMs: 3_100)
        sm.cancel()
        XCTAssertFalse(sm.hasSelection)
        XCTAssertTrue(sm.isTracking)

        // New top-level menu resets stale menu stack and evicts old menus (handles missed -25204 MenuClosed).
        _ = sm.menuOpened("export", isTopLevel: false)
        sm.updateSelection(pdfPath, from: "export", nowMs: 3_200)
        let openEdit = sm.menuOpened("edit", isTopLevel: true)
        XCTAssertNil(openEdit.trackingChanged)
        XCTAssertEqual(openEdit.removed, ["file", "export"])
        XCTAssertEqual(sm.openMenus, ["edit"])
        XCTAssertFalse(sm.hasSelection)

        // Late close for already-evicted menu is ignored.
        let lateClose = sm.menuClosed("file")
        XCTAssertNil(lateClose.trackingChanged)
        XCTAssertTrue(lateClose.removed.isEmpty)
        XCTAssertEqual(sm.openMenus, ["edit"])

        // Prune on stale menu empties stack and emits trackingChanged == false.
        let pruned = sm.prune("edit")
        XCTAssertEqual(pruned.trackingChanged, false)
        XCTAssertEqual(pruned.removed, ["edit"])
        XCTAssertFalse(sm.isTracking)

        // Max 8 open menus cap evicts oldest when exceeded.
        for i in 1...9 {
            _ = sm.menuOpened("m\(i)", isTopLevel: i == 1)
        }
        XCTAssertEqual(sm.openMenus.count, MenuPathLimits.maxOpenMenus)
        XCTAssertEqual(sm.openMenus.first, "m2")
        XCTAssertEqual(sm.openMenus.last, "m9")

        // Reset clears all open menus and reports trackingChanged == false.
        let reset = sm.reset()
        XCTAssertEqual(reset.trackingChanged, false)
        XCTAssertEqual(reset.removed.count, 8)
        XCTAssertFalse(sm.isTracking)
        XCTAssertNil(sm.reset().trackingChanged)
    }

    // MARK: - CollectorEngine & ContractValidator Tests

    private func configureMenuEngine(
        fixture: Bool = false,
        menuActions: Bool? = true,
        applicationScope: String? = nil,
        allowedApplicationIds: [String] = ["test.allowed"],
        excludedApplicationIds: [String]? = nil,
        allowBrowserContent: Bool? = nil,
        fieldSecurity: String? = nil
    ) throws -> Harness {
        let h = Harness(fixture: fixture)
        let policy = CapturePolicy(
            enabled: true,
            inputActivity: false,
            sampleIntervalMs: 1_000,
            allowedApplicationIds: allowedApplicationIds,
            debounceMs: 50,
            maxWaitMs: 200,
            readTimeoutMs: 500,
            applicationScope: applicationScope,
            excludedApplicationIds: excludedApplicationIds,
            allowBrowserContent: allowBrowserContent,
            fieldSecurity: fieldSecurity,
            menuActions: menuActions
        )
        h.engine.receive(.object([
            "protocolVersion": j(1),
            "type": .string("configure"),
            "requestId": .string("config"),
            "ownerId": .string("owner"),
            "instanceId": .string("instance"),
            "policyRevision": j(1),
            "policy": try JSONValue.parse(JSONEncoder().encode(policy)),
        ]))
        h.control("start", lease: 30_000)
        return h
    }

    private func sampleRecord(
        _ h: Harness,
        appId: String = "test.allowed",
        pid: Int32 = 42,
        path: [String] = ["File", "Save"],
        truncated: Bool = false,
        observedAtMs: Int64? = nil,
        privateState: String = "normal",
        captureEpoch: Int64? = nil,
        foregroundGeneration: Int64? = nil,
        focusGeneration: Int64? = nil,
        policyRevision: Int64? = nil,
        fieldSecurity: String = "strict"
    ) -> MenuActionRecord {
        MenuActionRecord(
            application: ApplicationIdentity(applicationId: appId, processId: pid, processStartTime: "birth-1"),
            path: path,
            truncated: truncated,
            observedAtMs: observedAtMs ?? h.clock.unixMs,
            privateState: privateState,
            captureEpoch: captureEpoch ?? h.engine.captureEpoch,
            foregroundGeneration: foregroundGeneration ?? h.engine.foregroundGeneration,
            focusGeneration: focusGeneration ?? h.engine.focusGeneration,
            policyRevision: policyRevision ?? h.engine.policyRevision,
            fieldSecurity: fieldSecurity
        )
    }

    private func menuFrames(_ h: Harness) -> [JSONValue] {
        h.frames.filter { $0["payload"]?["kind"] == .string("menu.action") }
    }

    func testHelloCapabilityLegacyPolicyDecodingAndUsesSessionWorker() throws {
        let validator = try ContractValidator()
        let hello = CollectorEngine.helloMessage(instanceId: "instance", fixture: false)
        XCTAssertNoThrow(try validator.encodeFrame(hello))
        let caps = hello["capabilities"]?.arrayValue ?? []
        XCTAssertTrue(caps.contains {
            $0["name"] == .string("menu.action") &&
                $0["direction"] == .string("observe") &&
                $0["support"] == .string("supported") &&
                $0["reason"] == .string("foreground-menu-bar")
        })

        // Legacy policy without menuActions decodes cleanly with menuActions == nil and usesSessionWorker == false.
        let legacyJSON = try JSONValue.parse(Data(#"{"enabled":true,"allowedApplicationIds":["test.allowed"],"maxTextCodeUnits":128,"maxPending":8,"debounceMs":10,"maxWaitMs":50,"readTimeoutMs":200}"#.utf8))
        let legacyPolicy = try CapturePolicy(legacyJSON)
        XCTAssertNil(legacyPolicy.menuActions)
        XCTAssertFalse(legacyPolicy.usesSessionWorker)

        // Enabling menuActions alone routes capture through the isolated session worker.
        let menuPolicy = CapturePolicy(menuActions: true)
        XCTAssertEqual(menuPolicy.menuActions, true)
        XCTAssertTrue(menuPolicy.usesSessionWorker)
    }

    func testEngineEmitsContractValidMenuActionsAcrossModesAndBrowserAuthorization() throws {
        let validator = try ContractValidator()

        // Non-fixture, strict mode, normal + truncated paths, plus generation <= fencing.
        let h = try configureMenuEngine(fixture: false, menuActions: true, fieldSecurity: "strict")
        h.engine.menuAction(sampleRecord(h, path: ["File", "Save"], truncated: false))
        h.engine.menuAction(sampleRecord(
            h,
            path: ["File", "Export", "PDF..."],
            truncated: true,
            foregroundGeneration: 0,
            focusGeneration: 0
        ))
        let emitted = menuFrames(h)
        XCTAssertEqual(emitted.count, 2)
        for frame in h.frames {
            XCTAssertNoThrow(try validator.encodeFrame(frame))
        }
        XCTAssertEqual(emitted[0]["target"]?["kind"], .string("application"))
        XCTAssertNil(emitted[0]["relation"])
        XCTAssertEqual(emitted[0]["eventTimeMs"], emitted[0]["payload"]?["observedAtMs"])
        XCTAssertEqual(emitted[0]["payload"]?["source"], .string("ax.menu"))
        XCTAssertEqual(emitted[0]["payload"]?["scope"], .string("menu-bar"))
        XCTAssertEqual(emitted[0]["payload"]?["gate"]?["secure"], .string("safe"))
        XCTAssertEqual(emitted[0]["payload"]?["coverage"]?["truncated"], .bool(false))
        XCTAssertEqual(emitted[0]["payload"]?["coverage"]?["missingReasons"], .array([.string("menu-bar-only"), .string("effect-unverified")]))
        XCTAssertEqual(emitted[1]["payload"]?["coverage"]?["truncated"], .bool(true))
        XCTAssertEqual(emitted[1]["payload"]?["coverage"]?["missingReasons"], .array([.string("menu-bar-only"), .string("effect-unverified"), .string("menu-title-truncated")]))

        // Fixture source + denylist fieldSecurity + authorized browser.
        let h2 = try configureMenuEngine(
            fixture: true,
            menuActions: true,
            applicationScope: "denylist",
            allowedApplicationIds: [],
            allowBrowserContent: true,
            fieldSecurity: "denylist"
        )
        h2.engine.menuAction(sampleRecord(
            h2,
            appId: "com.google.Chrome",
            path: ["Tab", "New Tab"],
            privateState: "user-authorized",
            fieldSecurity: "denylist"
        ))
        let browserFrames = menuFrames(h2)
        XCTAssertEqual(browserFrames.count, 1)
        XCTAssertEqual(browserFrames[0]["payload"]?["source"], .string("fixture"))
        XCTAssertEqual(browserFrames[0]["payload"]?["gate"]?["secure"], .string("not-declared-sensitive"))
        XCTAssertEqual(browserFrames[0]["payload"]?["gate"]?["privateState"], .string("user-authorized"))
        for frame in h2.frames {
            XCTAssertNoThrow(try validator.encodeFrame(frame))
        }
    }

    func testEngineFailsClosedOnPolicyEpochPrivacyLockSecureInputAndBrowserBoundaries() throws {
        // Disabled menuActions policy drops record.
        let disabled = try configureMenuEngine(menuActions: false)
        disabled.engine.menuAction(sampleRecord(disabled))
        XCTAssertTrue(menuFrames(disabled).isEmpty)

        // Stale epoch, stale policy revision, future generation, fieldSecurity mismatch, invalid path/timestamps.
        let h = try configureMenuEngine(menuActions: true)
        h.engine.menuAction(sampleRecord(h, captureEpoch: h.engine.captureEpoch - 1))
        h.engine.menuAction(sampleRecord(h, policyRevision: 2))
        h.engine.menuAction(sampleRecord(h, foregroundGeneration: h.engine.foregroundGeneration + 1))
        h.engine.menuAction(sampleRecord(h, focusGeneration: h.engine.focusGeneration + 1))
        h.engine.menuAction(sampleRecord(h, fieldSecurity: "denylist"))
        h.engine.menuAction(sampleRecord(h, path: ["OnlyOne"]))
        h.engine.menuAction(sampleRecord(h, path: ["File", "Bad\nName"]))
        h.engine.menuAction(sampleRecord(h, observedAtMs: h.clock.unixMs + 1))
        h.engine.menuAction(sampleRecord(h, observedAtMs: h.clock.unixMs - 10_001))
        h.engine.menuAction(sampleRecord(h, pid: 0))
        // Mandatory denied families & System UI & non-allowlisted apps.
        h.engine.menuAction(sampleRecord(h, appId: "com.1password.1password"))
        h.engine.menuAction(sampleRecord(h, appId: "com.apple.Safari"))
        h.engine.menuAction(sampleRecord(h, appId: "com.apple.controlcenter"))
        h.engine.menuAction(sampleRecord(h, appId: "other.not.allowed"))
        // Browser privateState rejected under allowlist.
        h.engine.menuAction(sampleRecord(h, privateState: "user-authorized"))
        XCTAssertTrue(menuFrames(h).isEmpty)

        // Known browser spoofing privateState == "normal" under denylist + allowBrowserContent must be rejected.
        let browser = try configureMenuEngine(
            menuActions: true,
            applicationScope: "denylist",
            allowedApplicationIds: [],
            allowBrowserContent: true
        )
        browser.engine.menuAction(sampleRecord(browser, appId: "com.google.Chrome", privateState: "normal"))
        XCTAssertTrue(menuFrames(browser).isEmpty)

        // Known browser rejected when allowBrowserContent is false.
        let browserDenied = try configureMenuEngine(
            menuActions: true,
            applicationScope: "denylist",
            allowedApplicationIds: [],
            allowBrowserContent: false
        )
        browserDenied.engine.menuAction(sampleRecord(browserDenied, appId: "com.google.Chrome", privateState: "user-authorized"))
        XCTAssertTrue(menuFrames(browserDenied).isEmpty)

        // Fresh desktop lock at accept time pauses collector and drops menuAction.
        let lockH = try configureMenuEngine(menuActions: true)
        lockH.env.desktop = .locked
        lockH.engine.menuAction(sampleRecord(lockH))
        XCTAssertTrue(menuFrames(lockH).isEmpty)
        XCTAssertEqual(lockH.engine.state, "paused")

        // Unlock auto-resumes when only menuActions is enabled (no manual resume required).
        lockH.env.desktop = .unlocked
        lockH.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(lockH.engine.state, "running")

        // Fresh Secure Input at accept time suppresses and drops menuAction.
        let secH = try configureMenuEngine(menuActions: true)
        secH.env.secureInputBlocked = true
        secH.engine.menuAction(sampleRecord(secH))
        XCTAssertTrue(menuFrames(secH).isEmpty)
        XCTAssertEqual(secH.engine.state, "paused")

        // Mismatched observedApplication drops menuAction.
        let mismatchH = try configureMenuEngine(menuActions: true, allowedApplicationIds: ["app.one", "app.two"])
        mismatchH.engine.applicationEvent(SourceHint(
            application: ApplicationIdentity(applicationId: "app.one", processId: 10, processStartTime: "birth-1"),
            eventTimeMs: mismatchH.clock.unixMs
        ))
        mismatchH.engine.menuAction(sampleRecord(mismatchH, appId: "app.two", pid: 20))
        XCTAssertTrue(menuFrames(mismatchH).isEmpty)
    }

    func testWorkerMenuTrackingDefersPeriodicReadsEnforces10sCapResetsOnBoundaryAndWakesOnClose() throws {
        let h = try configureMenuEngine(menuActions: true)
        // Let initial schedule become due (maxWaitMs = 200).
        h.clock.advance(100)
        h.engine.workerMenuTracking(true)
        h.clock.advance(500)
        h.engine.tick()
        XCTAssertTrue(h.env.launched.isEmpty, "Periodic ReadTicket must be deferred while menu tracking is active")

        // Closing menu clears deferral and triggers workerDirty() (debounceMs = 50).
        h.engine.workerMenuTracking(false)
        h.clock.advance(49)
        h.engine.tick()
        XCTAssertEqual(h.env.launched.count, 1, "Already-overdue read resumes immediately on close")

        // Complete the first read so nextRead is scheduled 1000ms out.
        let first = try XCTUnwrap(h.env.launched.last)
        h.engine.complete(h.goodResult(first))
        h.clock.advance(100)
        h.engine.workerMenuTracking(true)
        h.clock.advance(9_999)
        h.engine.tick()
        XCTAssertEqual(h.env.launched.count, 1, "Deferral holds up to 9,999ms")

        // Hard 10s cap expires automatically even if menuTracking(false) never arrives.
        h.clock.advance(1)
        h.engine.tick()
        XCTAssertEqual(h.env.launched.count, 2, "Hard 10s cap must resume reads even if MenuClosed was missed")

        // Boundary (pause/resume or app switch) clears menuTracking deferral immediately.
        let second = try XCTUnwrap(h.env.launched.last)
        h.engine.complete(h.goodResult(second))
        h.engine.workerMenuTracking(true)
        h.engine.applicationEvent(SourceHint(
            application: ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "birth-2"),
            eventTimeMs: h.clock.unixMs
        ))
        h.clock.advance(201)
        h.engine.tick()
        XCTAssertEqual(h.env.launched.count, 3, "Boundary must reset menuTrackingUntilMs")
    }

    // MARK: - BrowserMenuWindowGate Tests

    func testBrowserMenuWindowGateFailsClosedForUnlistedBrowsersSheetsOverIncognitoAndUnprovenZeroWindows() {
        let genericSpec = GenericAdapter().spec
        let browserSpec = BrowserFamilyAdapter().spec
        let allowBrowser = CapturePolicy(
            enabled: true,
            allowedApplicationIds: [],
            applicationScope: "denylist",
            allowBrowserContent: true,
            menuActions: true
        )
        let denyBrowser = CapturePolicy(
            enabled: true,
            allowedApplicationIds: ["com.custom.browser"],
            applicationScope: "allowlist",
            allowBrowserContent: false,
            menuActions: true
        )

        // Non-browser app performs zero AX window lookups and succeeds immediately.
        var windowCalls = 0
        XCTAssertTrue(BrowserMenuWindowGate.allowsMenuRead(
            applicationId: "com.apple.TextEdit",
            isBrowserCandidate: false,
            spec: genericSpec,
            policy: denyBrowser,
            same: ==,
            focusedWindow: { windowCalls += 1; return .failure },
            mainWindow: { windowCalls += 1; return .failure },
            windowCount: { windowCalls += 1; return .failure },
            inspectWindow: { (_: String) in windowCalls += 1; return .failure }
        ))
        XCTAssertEqual(windowCalls, 0)

        // (a) Unlisted http/https browser (isBrowserCandidate: true) is gated just like a known browser.
        XCTAssertFalse(BrowserMenuWindowGate.allowsMenuRead(
            applicationId: "com.custom.browser",
            isBrowserCandidate: true,
            spec: genericSpec,
            policy: denyBrowser,
            same: ==,
            focusedWindow: { .window("w1") },
            mainWindow: { .window("w1") },
            windowCount: { .count(1) },
            inspectWindow: { _ in .inspected(role: "AXWindow", hasSensitiveEvidence: false, safeTitle: "Docs") }
        ))
        XCTAssertFalse(BrowserMenuWindowGate.allowsMenuRead(
            applicationId: "com.custom.browser",
            isBrowserCandidate: true,
            spec: genericSpec,
            policy: allowBrowser,
            same: ==,
            focusedWindow: { .window("w1") },
            mainWindow: { .window("w1") },
            windowCount: { .count(1) },
            inspectWindow: { _ in .inspected(role: "AXWindow", hasSensitiveEvidence: false, safeTitle: "Bank (Incognito)") }
        ))
        var inspectCalls = 0
        XCTAssertTrue(BrowserMenuWindowGate.allowsMenuRead(
            applicationId: "com.custom.browser",
            isBrowserCandidate: true,
            spec: genericSpec,
            policy: allowBrowser,
            same: ==,
            focusedWindow: { .window("w1") },
            mainWindow: { .window("w1") },
            windowCount: { .count(1) },
            inspectWindow: { _ in inspectCalls += 1; return .inspected(role: "AXWindow", hasSensitiveEvidence: false, safeTitle: "Docs") }
        ))
        XCTAssertEqual(inspectCalls, 1, "Identical focused and main window should only be inspected once")

        // (b) Non-private dialog/focused window over an Incognito main window must fail closed.
        XCTAssertFalse(BrowserMenuWindowGate.allowsMenuRead(
            applicationId: "com.google.Chrome",
            isBrowserCandidate: true,
            spec: browserSpec,
            policy: allowBrowser,
            same: ==,
            focusedWindow: { .window("dialog") },
            mainWindow: { .window("incognito-main") },
            windowCount: { .count(2) },
            inspectWindow: { win in
                win == "dialog"
                    ? .inspected(role: "AXWindow", hasSensitiveEvidence: false, safeTitle: "Print")
                    : .inspected(role: "AXWindow", hasSensitiveEvidence: false, safeTitle: "Secret (Incognito)")
            }
        ))

        // Non-AXWindow role (e.g. AXSheet) or mainWindow lookup failure must fail closed.
        XCTAssertFalse(BrowserMenuWindowGate.allowsMenuRead(
            applicationId: "com.google.Chrome",
            isBrowserCandidate: true,
            spec: browserSpec,
            policy: allowBrowser,
            same: ==,
            focusedWindow: { .window("sheet") },
            mainWindow: { .window("main") },
            windowCount: { .count(1) },
            inspectWindow: { win in
                win == "sheet"
                    ? .inspected(role: "AXSheet", hasSensitiveEvidence: false, safeTitle: "Save")
                    : .inspected(role: "AXWindow", hasSensitiveEvidence: false, safeTitle: "Docs")
            }
        ))
        XCTAssertFalse(BrowserMenuWindowGate.allowsMenuRead(
            applicationId: "com.google.Chrome",
            isBrowserCandidate: true,
            spec: browserSpec,
            policy: allowBrowser,
            same: ==,
            focusedWindow: { .window("w1") },
            mainWindow: { .failure },
            windowCount: { .count(1) },
            inspectWindow: { _ in .inspected(role: "AXWindow", hasSensitiveEvidence: false, safeTitle: "Docs") }
        ))
        XCTAssertFalse(BrowserMenuWindowGate.allowsMenuRead(
            applicationId: "com.google.Chrome",
            isBrowserCandidate: true,
            spec: browserSpec,
            policy: allowBrowser,
            same: ==,
            focusedWindow: { .window("w1") },
            mainWindow: { .window("w1") },
            windowCount: { .count(1) },
            inspectWindow: { _ in .inspected(role: "AXWindow", hasSensitiveEvidence: true, safeTitle: "Docs") }
        ))
        XCTAssertFalse(BrowserMenuWindowGate.allowsMenuRead(
            applicationId: "com.google.Chrome",
            isBrowserCandidate: true,
            spec: browserSpec,
            policy: allowBrowser,
            same: ==,
            focusedWindow: { .window("w1") },
            mainWindow: { .window("w1") },
            windowCount: { .count(1) },
            inspectWindow: { _ in .inspected(role: "AXWindow", hasSensitiveEvidence: false, safeTitle: nil) }
        ))

        // (c) Absent focused & main windows require positive AXWindows count == 0 proof.
        XCTAssertTrue(BrowserMenuWindowGate.allowsMenuRead(
            applicationId: "com.google.Chrome",
            isBrowserCandidate: true,
            spec: browserSpec,
            policy: allowBrowser,
            same: ==,
            focusedWindow: { .absent },
            mainWindow: { .absent },
            windowCount: { .count(0) },
            inspectWindow: { (_: String) in .failure }
        ))
        XCTAssertFalse(BrowserMenuWindowGate.allowsMenuRead(
            applicationId: "com.google.Chrome",
            isBrowserCandidate: true,
            spec: browserSpec,
            policy: allowBrowser,
            same: ==,
            focusedWindow: { .absent },
            mainWindow: { .absent },
            windowCount: { .count(1) },
            inspectWindow: { (_: String) in .failure }
        ))
        XCTAssertFalse(BrowserMenuWindowGate.allowsMenuRead(
            applicationId: "com.google.Chrome",
            isBrowserCandidate: true,
            spec: browserSpec,
            policy: allowBrowser,
            same: ==,
            focusedWindow: { .absent },
            mainWindow: { .absent },
            windowCount: { .failure },
            inspectWindow: { (_: String) in .failure }
        ))
    }
}

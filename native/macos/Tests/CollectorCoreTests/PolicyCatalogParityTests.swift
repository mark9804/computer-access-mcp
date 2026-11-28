import XCTest
@testable import CollectorCore

final class PolicyCatalogParityTests: XCTestCase {
    func testPolicyGatesAndBuiltInAdaptersMatchGeneratedCatalog() {
        XCTAssertEqual(ApplicationPolicy.mandatoryDeniedFamilies, GeneratedPolicyCatalog.mandatoryExcludedFamilies)
        XCTAssertEqual(ApplicationPolicy.systemUIFamilies, GeneratedPolicyCatalog.systemUIFamilies)
        XCTAssertEqual(BrowserGate.privateWindowIndicators, GeneratedPolicyCatalog.privateWindowIndicators)
        XCTAssertEqual(BrowserGate.privateWindowIndicators.count, 28)
        XCTAssertTrue(BrowserGate.isPrivateWindowTitle("New Incognito Tab - Google Chrome"))
        XCTAssertTrue(BrowserGate.isPrivateWindowTitle("Firefox — 私密瀏覽"))
        XCTAssertTrue(BrowserGate.isPrivateWindowTitle("Chrome — シークレット"))
        XCTAssertTrue(BrowserGate.isPrivateWindowTitle("Chrome — 시크릿"))

        XCTAssertEqual(BuiltInAdapters.all.map(\.spec.id), GeneratedPolicyCatalog.builtInAdapters.map(\.id))
        for (adapter, entry) in zip(BuiltInAdapters.all, GeneratedPolicyCatalog.builtInAdapters) {
            XCTAssertEqual(adapter.spec.id, entry.id)
            XCTAssertEqual(adapter.spec.displayName, entry.displayName)
            XCTAssertEqual(adapter.spec.matchBundleIds, Set(entry.bundleIds), "bundleIds drift for \(entry.id)")
        }
    }

    func testAppPolicyFamilyMatchingPrivateChromeLabelsAndPolicyBounds() {
        XCTAssertTrue(ApplicationPolicy.matchesFamily("com.google.Chrome.beta", family: "com.google.Chrome"))
        XCTAssertTrue(ApplicationPolicy.matchesFamily("COM.GOOGLE.CHROME", family: "com.google.chrome"))
        XCTAssertFalse(ApplicationPolicy.matchesFamily("com.google.ChromeEvil", family: "com.google.Chrome"))
        XCTAssertFalse(ApplicationPolicy.matchesFamily("", family: "com.google.Chrome"))
        XCTAssertFalse(ApplicationPolicy.matchesFamily("com.google.Chrome", family: ""))

        for privateLabel in [
            "Incognito", "InPrivate", "Private Browsing", "Private", "Private (2)",
            "无痕", "私密瀏覽", "シークレット", "시크릿", "Privé (1)",
        ] {
            XCTAssertTrue(BrowserGate.isPrivateChromeLabel(privateLabel), privateLabel)
        }
        for safeLabel in ["", "   ", "Privacy settings", "Private repository", "New Tab", "Downloads"] {
            XCTAssertFalse(BrowserGate.isPrivateChromeLabel(safeLabel), safeLabel)
        }

        let registry = AppAdapterRegistry.shared
        for browserVariant in [
            "com.google.Chrome.beta",
            "com.microsoft.edgemac.Dev",
            "com.brave.Browser.nightly",
            "com.kagi.kagimacos",
            "org.torproject.torbrowser",
            "net.waterfox",
            "org.mozilla.librewolf",
        ] {
            XCTAssertEqual(registry.adapter(for: browserVariant).spec.id, "browser-family", browserVariant)
        }
        XCTAssertEqual(registry.adapter(for: "com.google.ChromeEvil").spec.id, "generic")

        XCTAssertEqual(SafeAXDisplayText.label(title: "\u{200B}\u{FEFF}Hello\u{00AD}", description: nil, maxUnits: 64), "Hello")
        XCTAssertNil(SafeAXDisplayText.label(title: "\u{200B}\u{200C}\u{200D}\u{FEFF}\u{00AD}", description: nil, maxUnits: 64))
        // Interior ZWJ/ZWNJ must be preserved for compound emoji and Persian/Indic scripts.
        let familyEmoji = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}"
        let persianZWNJ = "می\u{200C}خواهم"
        XCTAssertEqual(SafeAXDisplayText.label(title: "\u{200D}\(familyEmoji)\u{200C}", description: nil, maxUnits: 64), familyEmoji)
        XCTAssertEqual(SafeAXDisplayText.label(title: persianZWNJ, description: nil, maxUnits: 64), persianZWNJ)

        XCTAssertTrue(BrowserGate.shouldBlockPrivateWindows(
            applicationId: "com.custom.browser",
            spec: GenericAdapter().spec,
            isBrowserCandidate: true
        ))
        XCTAssertFalse(BrowserGate.shouldBlockPrivateWindows(
            applicationId: "com.custom.editor",
            spec: GenericAdapter().spec,
            isBrowserCandidate: false
        ))

        let disabledDenylist = CapturePolicy(enabled: false, allowedApplicationIds: [], applicationScope: "denylist")
        XCTAssertEqual(
            ApplicationPolicy.evaluate("com.example.app", policy: disabledDenylist),
            .denied(reason: "policy-boundary", code: .applicationNotAllowed)
        )
        let denylistNoBrowser = CapturePolicy(enabled: true, allowedApplicationIds: [], applicationScope: "denylist", excludedApplicationIds: ["com.blocked.app"], allowBrowserContent: false)
        let denylistWithBrowser = CapturePolicy(enabled: true, allowedApplicationIds: [], applicationScope: "denylist", allowBrowserContent: true)
        let allowlistPolicy = CapturePolicy(enabled: true, allowedApplicationIds: ["com.allowed.app"], applicationScope: "allowlist")
        XCTAssertEqual(ApplicationPolicy.evaluate("com.1password.1password", policy: denylistWithBrowser), .denied(reason: "application-excluded", code: .applicationNotAllowed))
        XCTAssertEqual(ApplicationPolicy.evaluate("com.apple.ControlCenter", policy: allowlistPolicy), .denied(reason: "application-excluded", code: .applicationNotAllowed))
        XCTAssertEqual(ApplicationPolicy.evaluate("com.blocked.app.helper", policy: denylistNoBrowser), .denied(reason: "application-excluded", code: .applicationNotAllowed))
        XCTAssertEqual(ApplicationPolicy.evaluate("com.other.app", policy: allowlistPolicy), .denied(reason: "policy-boundary", code: .applicationNotAllowed))
        XCTAssertEqual(ApplicationPolicy.evaluate("com.google.Chrome", policy: denylistNoBrowser), .denied(reason: "policy-boundary", code: .browserExcluded))
        XCTAssertEqual(ApplicationPolicy.evaluate("com.custom.browser", policy: denylistNoBrowser, isBrowserCandidate: true), .denied(reason: "policy-boundary", code: .browserExcluded))
        XCTAssertEqual(ApplicationPolicy.evaluate("com.custom.browser", policy: denylistWithBrowser, isBrowserCandidate: true), .allowed)
        XCTAssertEqual(ApplicationPolicy.evaluate("com.allowed.app", policy: allowlistPolicy), .allowed)

        XCTAssertTrue(CapturePolicy().hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(maxTextCodeUnits: 0).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(maxTextCodeUnits: 8193).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(maxPending: 0).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(maxPending: 65).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(debounceMs: -1).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(debounceMs: 2_001, maxWaitMs: 3_000).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(debounceMs: 100, maxWaitMs: 50).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(maxWaitMs: 5_001).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(readTimeoutMs: 0).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(readTimeoutMs: 5_001).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(allowedApplicationIds: Array(repeating: "test.allowed", count: 65)).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(allowedApplicationIds: [""]).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(allowedApplicationIds: [String(repeating: "a", count: 257)]).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(excludedApplicationIds: Array(repeating: "test.excluded", count: 65)).hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(excludedApplicationIds: [""]).hasValidTextSettings)
    }

    func testBrowserChromeGateHandlesNormalDeepTreesPrivateBadgesAndFailClosedBoundaries() {
        func node(
            _ role: String?,
            subrole: TextSecurityGate.SubroleRead = .noValue,
            protectedContent: TextSecurityGate.ProtectedContentRead = .noValue,
            sensitive: Bool = false,
            title: String? = nil,
            description: String? = nil,
            identifier: String? = nil
        ) -> BrowserChromeNode {
            BrowserChromeNode(
                role: role,
                subrole: subrole,
                protectedContent: protectedContent,
                hasSensitiveEvidence: sensitive,
                safeTitle: title,
                safeDescription: description,
                safeIdentifier: identifier
            )
        }

        // 1. Normal deep browser tree: skips AXTabGroup, AXWebArea, BookmarkBarView, cross-PID, and empty depth-limit leaf.
        let normalNodes: [String: BrowserChromeNode] = [
            "root": node("AXWindow", title: "GitHub"),
            "tabs": node("AXTabGroup", title: "Incognito Docs Tab"),
            "web": node("AXWebArea", title: "Incognito Mode Guide"),
            "bookmarks": node("AXGroup", title: "Incognito Bookmark", identifier: "BookmarkBarView"),
            "toolbar": node("AXToolbar"),
            "back": node("AXButton", title: "Back"),
            "profile": node("AXButton", description: "Work Profile"),
            "g1": node("AXGroup"), "g2": node("AXGroup"), "g3": node("AXGroup"),
            "foreign": node("AXButton", title: "Incognito"),
        ]
        let normalChildren: [String: [String]] = [
            "root": ["tabs", "web", "bookmarks", "toolbar", "g1", "foreign"],
            "tabs": ["bad-tab"],
            "bookmarks": ["bad-bookmark"],
            "toolbar": ["back", "profile"],
            "g1": ["g2"], "g2": ["g3"], "g3": [],
        ]
        var visitedToolbarOrder: [String] = []
        let normalVerdict = BrowserChromeGate.inspect(
            window: "root",
            deadlineMs: 1_000,
            maxDepth: 3,
            nowMs: { 100 },
            matchesProcess: { $0 == "foreign" ? false : true },
            readNode: { id in
                if id == "back" || id == "profile" { visitedToolbarOrder.append(id) }
                return normalNodes[id]
            },
            readChildren: { id, _ in
                guard let kids = normalChildren[id] else { return .none }
                return .children(kids, truncated: false)
            }
        )
        XCTAssertEqual(normalVerdict, .verifiedNormal)
        XCTAssertEqual(visitedToolbarOrder, ["profile", "back"], "AXToolbar must be scanned tail-first")

        // 2. Private toolbar badge detected via title, description, or sensitive evidence.
        for badge in [
            node("AXButton", title: "Incognito"),
            node("AXButton", description: "无痕 (2)"),
            node("AXButton", sensitive: true, title: "Profile"),
        ] {
            let verdict = BrowserChromeGate.inspect(
                window: "root",
                deadlineMs: 1_000,
                nowMs: { 100 },
                matchesProcess: { _ in true },
                readNode: { $0 == "toolbar" ? node("AXToolbar") : badge },
                readChildren: { id, _ in
                    id == "root" ? .children(["toolbar"], truncated: false) :
                    id == "toolbar" ? .children(["badge"], truncated: false) : .none
                }
            )
            XCTAssertEqual(verdict, .privateDetected)
        }

        // 3. Fail-closed boundaries: metadata mayTraverse failure, truncated children, non-empty depth overflow,
        //    pid failure, node error, children error, maxNodes exhaustion, maxCalls exhaustion, deadline expiry.
        let metadataFailure = BrowserChromeGate.inspect(
            window: "root",
            deadlineMs: 1_000,
            nowMs: { 100 },
            matchesProcess: { _ in true },
            readNode: { _ in node("AXButton", subrole: .failure, title: nil) },
            readChildren: { id, _ in id == "root" ? .children(["btn"], truncated: false) : .none }
        )
        XCTAssertEqual(metadataFailure, .inconclusive)

        let truncatedChildren = BrowserChromeGate.inspect(
            window: "root",
            deadlineMs: 1_000,
            nowMs: { 100 },
            matchesProcess: { _ in true },
            readNode: { _ in node("AXToolbar") },
            readChildren: { id, _ in id == "root" ? .children([], truncated: true) : .none }
        )
        XCTAssertEqual(truncatedChildren, .inconclusive)

        let nonEmptyAtMaxDepth = BrowserChromeGate.inspect(
            window: "root",
            deadlineMs: 1_000,
            maxDepth: 1,
            nowMs: { 100 },
            matchesProcess: { _ in true },
            readNode: { _ in node("AXGroup") },
            readChildren: { id, _ in
                id == "root" ? .children(["g1"], truncated: false) :
                id == "g1" ? .children(["deep"], truncated: false) : .none
            }
        )
        XCTAssertEqual(nonEmptyAtMaxDepth, .inconclusive)

        let maxNodesHit = BrowserChromeGate.inspect(
            window: "root",
            deadlineMs: 1_000,
            maxNodes: 1,
            nowMs: { 100 },
            matchesProcess: { _ in true },
            readNode: { _ in node("AXButton", title: "Normal") },
            readChildren: { id, _ in id == "root" ? .children(["b1", "b2"], truncated: false) : .none }
        )
        XCTAssertEqual(maxNodesHit, .inconclusive)

        let pidError = BrowserChromeGate.inspect(
            window: "root",
            deadlineMs: 1_000,
            nowMs: { 100 },
            matchesProcess: { _ in nil },
            readNode: { _ in node("AXButton") },
            readChildren: { id, _ in id == "root" ? .children(["b1"], truncated: false) : .none }
        )
        XCTAssertEqual(pidError, .inconclusive)

        let expiredDeadline = BrowserChromeGate.inspect(
            window: "root",
            deadlineMs: 100,
            nowMs: { 100 },
            matchesProcess: { _ in true },
            readNode: { _ in node("AXButton") },
            readChildren: { _, _ in .none }
        )
        XCTAssertEqual(expiredDeadline, .inconclusive)
    }
}

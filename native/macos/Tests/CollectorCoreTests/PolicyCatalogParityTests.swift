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
    }
}

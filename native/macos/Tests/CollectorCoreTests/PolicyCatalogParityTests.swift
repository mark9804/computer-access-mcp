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
}

import XCTest
@testable import CollectorCore

final class SurfaceReadDiagnosticsTests: XCTestCase {
    func testRequiredRejectionDoesNotBorrowAHigherLevelBudgetOrMislabelFallback() {
        for hint in [nil, .anchorUnavailable, .providerUnavailable, .notStartedBudget, .callBudget, .timeBudget] as [SurfaceReadFailure?] {
            var diagnostics = SurfaceReadDiagnostics()
            diagnostics.note(.callBudget)
            diagnostics.noteRequiredBoundaryFailure(evidence: hint)
            XCTAssertEqual(diagnostics.failure, .boundaryUnverified)
            XCTAssertEqual(diagnostics.failure?.gapReason, "read-error")
        }
    }

    func testRequiredPrecedenceIsStickyRegardlessOfReportingOrder() {
        let ordered: [SurfaceReadFailure] = [.providerUnavailable, .notStartedBudget, .callBudget, .timeBudget,
            .anchorUnavailable, .boundaryUnverified, .boundaryIncomplete, .boundaryAXFailed, .boundaryMismatch, .securityExcluded]
        XCTAssertEqual(Set(ordered), Set(SurfaceReadFailure.allCases))
        for (index, stronger) in ordered.enumerated() {
            for weaker in ordered.prefix(index) {
                for order in [[stronger, weaker], [weaker, stronger]] {
                    var diagnostics = SurfaceReadDiagnostics()
                    for failure in order { diagnostics.note(failure) }
                    XCTAssertEqual(diagnostics.failure, stronger)
                }
            }
        }
    }
}

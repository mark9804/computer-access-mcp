import XCTest
import ApplicationServices
import CollectorCore
@testable import computer_history_collector

/// Fixed observation values exercise the production classifier; no AX IPC,
/// desktop, permissions, or existing History is involved.
final class AXBoundaryDiagnosticTests: XCTestCase {
    func testMissingComparisonOrOptionalAbsenceDoesNotAssertErrorOrChange() {
        var check = AXBoundaryDiagnostic()
        check.noteComparison(Optional<Int32>.none, expected: 42)
        check.noteComparison(Int32(42), expected: 42)
        check.noteAXStatus(.success)
        check.noteAXStatus(.noValue)
        check.noteAXStatus(.attributeUnsupported)
        check.noteAttribute(AXMetadataBatch.AttributeRead<String>.attributeUnsupported)
        check.noteAttribute(AXMetadataBatch.AttributeRead<Bool>.noValue)
        XCTAssertNil(check.failure)
        XCTAssertFalse(check.deadlineExceeded)
        XCTAssertEqual(check.failureIfRejected(false), .boundaryUnverified)
        XCTAssertNil(check.failureIfRejected(true))
    }

    func testPositiveMismatchBeatsAPIErrorAndUnfinishedRequiredCheckButNotSecurity() {
        var check = AXBoundaryDiagnostic()
        check.note(.boundaryIncomplete, deadlineExceeded: true)
        XCTAssertEqual(check.failureIfRejected(false), .boundaryIncomplete)
        check.noteAXStatus(.cannotComplete)
        XCTAssertEqual(check.failureIfRejected(false), .boundaryAXFailed)
        check.noteComparison(Int32(43), expected: 42)
        check.noteAXStatus(.failure)
        XCTAssertEqual(check.failureIfRejected(false), .boundaryMismatch)
        XCTAssertTrue(check.deadlineExceeded, "An actual cutoff may be observed even when stronger evidence wins the surface label")
        check.note(.securityExcluded)
        XCTAssertEqual(check.failureIfRejected(false), .securityExcluded)
    }

    func testMalformedMetadataIsAProviderFailureAndNotTimingOrMismatch() {
        for attribute in [AXMetadataBatch.AttributeRead<String>.null, .malformed, .apiFailure(.cannotComplete)] {
            var check = AXBoundaryDiagnostic()
            check.noteAttribute(attribute)
            check.note(.callBudget)
            XCTAssertEqual(check.failureIfRejected(false), .boundaryAXFailed)
            XCTAssertFalse(check.deadlineExceeded)
            XCTAssertNil(check.failureIfRejected(true), "A successful guard cannot export a cause")
        }
        XCTAssertEqual(AXBoundaryDiagnostic().failureIfRejected(false), .boundaryUnverified,
            "A different verification starts with no prior AX or deadline evidence")
    }
}

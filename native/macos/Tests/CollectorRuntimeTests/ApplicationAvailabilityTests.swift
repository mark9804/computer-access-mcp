import XCTest
import Foundation
import CollectorCore
@testable import CollectorRuntime

/// Existing metadata only: no AppKit singleton, AX, TCC, History, or process probe.
final class ApplicationAvailabilityTests: XCTestCase {
    func testMissingApplicationAndBundleRemainDistinctWithoutAdditionalMetadataReads() {
        var bundleReads = 0
        let missing = ApplicationAvailability.application(Optional<Int>.none, bundleIdentifier: { _ in
            bundleReads += 1; return "test.allowed"
        })
        guard case .failure(.applicationMissing) = missing else { return XCTFail("Expected missing application") }
        XCTAssertEqual(bundleReads, 0)

        let noBundle = ApplicationAvailability.application(42, bundleIdentifier: { value in
            XCTAssertEqual(value, 42); bundleReads += 1; return nil
        })
        guard case .failure(.bundleMissing) = noBundle else { return XCTFail("Expected missing bundle") }
        XCTAssertEqual(bundleReads, 1)

        // The pre-policy guard never validated length or birth: do not move
        // those identity checks ahead of the existing application policy gate.
        let emptyBundle = ApplicationAvailability.application(42, bundleIdentifier: { _ in "" })
        guard case .success(let observed) = emptyBundle else { return XCTFail("Expected pre-policy metadata") }
        XCTAssertEqual(observed.application, 42); XCTAssertEqual(observed.applicationId, "")
    }

    func testIdentityRejectionsPreserveOriginalLazyOrderAndDoNotReadFallbackMetadata() {
        let launch = Date(timeIntervalSince1970: 1_700_000_000.125)
        let cases: [(String?, Date?, Int32, ApplicationAvailability.Rejection, [String])] = [
            (nil, nil, 0, .bundleMissing, ["bundle"]),
            ("", nil, 0, .launchDateMissing, ["bundle", "launch"]),
            ("", launch, 1, .processIdentifierInvalid, ["bundle", "launch", "pid"]),
            ("", launch, 42, .bundleEmpty, ["bundle", "launch", "pid"]),
            (String(repeating: "\u{1F9ED}", count: 129), launch, 42, .bundleOverLimit, ["bundle", "launch", "pid"]),
        ]
        for (bundle, birth, pid, expected, expectedReads) in cases {
            var reads: [String] = []
            let result = ApplicationAvailability.identity(bundleIdentifier: { reads.append("bundle"); return bundle },
                launchDate: { reads.append("launch"); return birth }, processIdentifier: { reads.append("pid"); return pid })
            guard case .failure(let actual) = result else { return XCTFail("Rejected metadata must not gain identity") }
            XCTAssertEqual(actual, expected); XCTAssertEqual(reads, expectedReads)
        }
    }

    func testApplicationUnavailableForcesLocalIdentityRebaselineWithoutProbingDesktop() {
        // A new Session has no provider, observer, input tap or AX handles. This
        // calls the actual read-failure path, not Session.read's OS-facing gates.
        let session = AXWorkerSession()
        XCTAssertFalse(session.invalidatedFocus)
        session.invalidateReadFailure(nil)
        session.invalidateReadFailure(.fieldSecurityUnknown)
        XCTAssertFalse(session.invalidatedFocus, "Unrelated failure semantics are unchanged")
        session.invalidateReadFailure(.applicationUnavailable)
        XCTAssertTrue(session.invalidatedFocus, "Same handles must not reuse pre-unavailable input generations")
        session.invalidateReadFailure(.applicationUnavailable)
        XCTAssertTrue(session.invalidatedFocus, "Repeated failure stays invalid until a successful rebaseline")
    }

    func testValidIdentityRetainsExactBirthFormatAndOriginalSuccessfulPIDReads() throws {
        var reads: [String] = []
        let result = ApplicationAvailability.identity(bundleIdentifier: { reads.append("bundle"); return "test.allowed" },
            launchDate: { reads.append("launch"); return Date(timeIntervalSince1970: 1_700_000_000.125) },
            processIdentifier: { reads.append("pid"); return 42 })
        let identity = try result.get()
        XCTAssertEqual(identity.applicationId, "test.allowed"); XCTAssertEqual(identity.processId, 42)
        XCTAssertEqual(identity.processStartTime, "unix-ms:1700000000125.000")
        XCTAssertEqual(reads, ["bundle", "launch", "pid", "pid"])

        // The original 256-UTF16 boundary stays inclusive, including non-BMP data.
        let maximumBundle = String(repeating: "\u{1F9ED}", count: 128)
        let maximum = try ApplicationAvailability.identity(bundleIdentifier: { maximumBundle },
            launchDate: { Date(timeIntervalSince1970: 1) }, processIdentifier: { 42 }).get()
        XCTAssertEqual(maximum.applicationId, maximumBundle)
    }

    func testPrivateStateFallbackFailsClosedWhenProcessIsMissingOrMismatched() {
        let missingPid = ApplicationIdentity(
            applicationId: "com.custom.unknownbrowser",
            processId: Int32.max,
            processStartTime: "unix-ms:1700000000000.000"
        )
        XCTAssertEqual(AppIdentityGate.privateState(for: missingPid), "user-authorized")

        let mismatchedBirth = ApplicationIdentity(
            applicationId: "com.custom.editor",
            processId: getpid(),
            processStartTime: "unix-ms:1.000"
        )
        XCTAssertEqual(AppIdentityGate.privateState(for: mismatchedBirth), "user-authorized")
    }
}

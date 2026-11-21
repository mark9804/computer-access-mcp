import XCTest
import Foundation
@testable import CollectorCore

final class DesktopEvidenceTests: XCTestCase {
    func row(_ uid: UInt32 = 501, _ audit: UInt32 = 10) -> [String: Any] {
        ["kCGSSessionUserIDKey": NSNumber(value: uid), "kCGSSessionAuditIDKey": NSNumber(value: audit), "kCGSSessionOnConsoleKey": true, "kCGSessionLoginDoneKey": true]
    }
    func testPollOrNotificationBoundaryStaysStickyUntilUserAction() {
        let ready = DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: nil, consoleLocked: false, registrySessionMatched: true)
        for blocked in [DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: true), DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: nil, consoleLocked: false, registrySessionMatched: true, lockTransition: true)] {
            var latch = DesktopBoundaryLatch()
            XCTAssertEqual(latch.observe(ready), .unlocked)
            XCTAssertNotEqual(latch.observe(blocked), .unlocked)
            XCTAssertNotEqual(latch.observe(ready), .unlocked)
            latch.resetForUserAction(); XCTAssertEqual(latch.observe(ready), .unlocked)
            latch.block(); XCTAssertNotEqual(latch.observe(ready), .unlocked)
        }
    }
    func testBoolAndNumberTypesNeverCoerceStringIntegerOrBoolean() {
        XCTAssertNil(DesktopSessionEvidence.boolean(NSNumber(value: 0)))
        XCTAssertNil(DesktopSessionEvidence.boolean("false"))
        XCTAssertEqual(DesktopSessionEvidence.boolean(false), false)
        XCTAssertNil(DesktopSessionEvidence.number(true))
        XCTAssertNil(DesktopSessionEvidence.number("501"))
        XCTAssertFalse(DesktopSessionEvidence(["CGSSessionScreenIsLocked": 0]).valid)
    }
    func testCompatibilityRequiresMatchedSingleConsoleAndPositiveRootFalse() {
        let session = DesktopSessionEvidence(row())
        let registry = RegistryDesktopEvidence(rootLock: false, rows: [row()], session: session)
        XCTAssertTrue(registry.valid); XCTAssertTrue(registry.sessionMatched)
        let assessment = DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: nil, consoleLocked: registry.consoleLocked, registrySessionMatched: registry.sessionMatched)
        XCTAssertEqual(assessment.desktopStatus, .unlocked)
        XCTAssertEqual(assessment.reason, "ready-console-compat")
        XCTAssertEqual(assessment.lockSource, "io-console-compat")
        XCTAssertEqual(DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: nil, consoleLocked: false).desktopStatus, .unknown)
    }
    func testDuplicateIdentityMultipleConsoleWrongAuditAndMalformedRowsAreDenied() {
        let session = DesktopSessionEvidence(row())
        for rows: [[String: Any]] in [[row(), row()], [row(), row(502, 20)], [row(501, 11)], [["kCGSSessionOnConsoleKey": "true"]]] {
            let registry = RegistryDesktopEvidence(rootLock: false, rows: rows, session: session)
            XCTAssertFalse(registry.valid)
            XCTAssertFalse(registry.sessionMatched)
        }
    }
    func testLockTimeOrSecureInputPresenceNeverPassesAsZeroOrMalformed() {
        for key in ["CGSSessionScreenLockedTime", "kCGSSessionSecureInputPID"] {
            for value: Any in [0, "invalid", false] {
                var fields = row(); fields[key] = value
                XCTAssertTrue(DesktopSessionEvidence(fields).transition)
            }
        }
    }
    func testSecureMarkerRemainsBlockedButDoesNotClaimAnActiveAPIOrScreenLock() {
        for value: Any in [42, 0, false, "invalid"] {
            var fields = row(); fields["kCGSSessionSecureInputPID"] = value
            let evidence = DesktopSessionEvidence(fields)
            XCTAssertTrue(evidence.secureInputMarker); XCTAssertTrue(evidence.transition); XCTAssertFalse(evidence.lockTimeMarker)
            let assessment = DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: false,
                lockTransition: evidence.lockTimeMarker, secureInputMarker: evidence.secureInputMarker)
            XCTAssertEqual(assessment.desktopStatus, .unknown); XCTAssertEqual(assessment.reason, "secure-input-indicated")
            var latch = DesktopBoundaryLatch(); XCTAssertEqual(latch.observe(assessment), .unknown)
            let ready = DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: false)
            XCTAssertEqual(latch.observe(ready), .unlocked, "Secure Input alone is temporary; a lock boundary remains sticky")
        }
        XCTAssertEqual(DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: true,
            secureInputMarker: true).reason, "screen-locked")
        let mixed = DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: false,
            lockTransition: true, secureInputMarker: true)
        XCTAssertEqual(mixed.reason, "desktop-lock-transition")
        var latch = DesktopBoundaryLatch(); XCTAssertEqual(latch.observe(mixed), .unknown)
        XCTAssertEqual(latch.observe(DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: false)), .unknown)
        var fields = row(); fields["kCGSSessionSecureInputPID"] = 42
        let readyEvidence = DesktopSessionEvidence(row()), secureEvidence = DesktopSessionEvidence(fields)
        XCTAssertNotEqual(readyEvidence, secureEvidence)
        XCTAssertTrue(readyEvidence.sameDesktop(as: secureEvidence))
        fields["CGSSessionScreenLockedTime"] = 0
        XCTAssertFalse(readyEvidence.sameDesktop(as: DesktopSessionEvidence(fields)))
        fields = row(501, 11); fields["kCGSSessionSecureInputPID"] = 42
        XCTAssertFalse(readyEvidence.sameDesktop(as: DesktopSessionEvidence(fields)))
    }
    func testPositiveLockAlwaysWinsAndCompatibilityNeverOverridesBoundaryOrUnknown() {
        for lock in [1, 2, 3] {
            let a = DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: lock == 1 ? true : nil, consoleLocked: lock == 2, registryScreenLocked: lock == 3 ? true : nil, registrySessionMatched: true)
            XCTAssertEqual(a.desktopStatus, .locked)
        }
        for flags in [(false, true, true, false), (true, false, true, false), (true, true, false, false), (true, true, true, true)] {
            let a = DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: nil, consoleLocked: false, registrySessionMatched: true, sessionMatchesProcess: flags.0, sessionStable: flags.1, signalsValid: flags.2, lockTransition: flags.3)
            XCTAssertEqual(a.desktopStatus, .unknown)
        }
    }
}

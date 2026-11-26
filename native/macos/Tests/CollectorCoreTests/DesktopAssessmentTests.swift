import XCTest
@testable import CollectorCore

final class DesktopAssessmentTests: XCTestCase {
    func testMissingLockDoesNotBecomeUnlockedOrAnAccessibilityFailure() {
        let assessment = DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: nil)
        XCTAssertEqual(assessment.desktopStatus, .unknown)
        XCTAssertEqual(assessment.reason, "lock-state-unavailable")
    }
    func testOnlyCompletePositiveDesktopEvidenceAllowsReading() {
        for available in [false, true] {
            for console in [nil, false, true] as [Bool?] {
                for login in [nil, false, true] as [Bool?] {
                    for lock in [nil, false, true] as [Bool?] {
                        let value = DesktopAssessment(sessionAvailable: available, onConsole: console, loginDone: login, screenLocked: lock)
                        XCTAssertEqual(value.desktopStatus == .unlocked, available && console == true && login == true && lock == false)
                    }
                }
            }
        }
    }
    func testExplicitLockAndSessionFailuresRemainSeparate() {
        XCTAssertEqual(DesktopAssessment(sessionAvailable: true, onConsole: true, loginDone: true, screenLocked: true).desktopStatus, .locked)
        XCTAssertEqual(DesktopAssessment(sessionAvailable: false, onConsole: nil, loginDone: nil, screenLocked: nil).reason, "session-unavailable")
        XCTAssertEqual(DesktopAssessment(sessionAvailable: true, onConsole: false, loginDone: true, screenLocked: false).reason, "console-unavailable")
    }
    func testPermissionActionIsStrictAndCannotRunCollectorOrRequestScreenRecording() {
        XCTAssertEqual(PermissionAction.parse(["--permissions", "check"]), .check)
        XCTAssertEqual(PermissionAction.parse(["--permissions", "request-accessibility"]), .requestAccessibility)
        XCTAssertEqual(PermissionAction.parse(["--permissions", "open-accessibility-settings"]), .openAccessibilitySettings)
        XCTAssertEqual(PermissionAction.parse(["--permissions", "request-input-monitoring"]), .requestInputMonitoring)
        XCTAssertEqual(PermissionAction.parse(["--permissions", "open-input-monitoring-settings"]), .openInputMonitoringSettings)
        for args in [[], ["--permissions"], ["--permissions", "start"], ["--permissions", "screen-recording"], ["--permissions", "check", "extra"], ["--serve", "request-accessibility"]] {
            XCTAssertNil(PermissionAction.parse(args))
        }
    }
}

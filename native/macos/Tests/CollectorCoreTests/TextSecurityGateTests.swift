import XCTest
@testable import CollectorCore

final class TextSecurityGateTests: XCTestCase {
    func testOrdinaryAppKitUnsupportedOptionalSubroleWithBoundedCapabilitiesIsSafe() {
        for role in ["AXTextField", "AXTextArea", "AXStaticText"] {
            XCTAssertEqual(TextSecurityGate.classify(role: role, subrole: nil, subroleUnsupported: true, attributeListKnown: true, subroleAdvertised: false, boundedRangeAdvertised: true, characterCountKnown: true), .safe)
        }
    }
    func testSecureSubroleWinsEvenWhenOtherCapabilitiesLookOrdinary() {
        XCTAssertEqual(TextSecurityGate.classify(role: "AXTextField", subrole: "AXSecureTextField", subroleUnsupported: true, attributeListKnown: true, boundedRangeAdvertised: true, characterCountKnown: true), .sensitive)
        XCTAssertEqual(TextSecurityGate.classify(role: "AXSecureTextField", subrole: nil), .sensitive)
        XCTAssertEqual(TextSecurityGate.classify(role: "AXTextField", subrole: "AXPasswordField"), .sensitive)
    }
    func testMissingErrorMalformedOrUnknownCapabilitiesDoNotFallbackToValueReads() {
        XCTAssertEqual(TextSecurityGate.classify(role: "AXTextField", subrole: nil), .unknown)
        for flags in [(false, true, false, true, true), (true, false, false, true, true), (true, true, true, true, true), (true, true, false, false, true), (true, true, false, true, false)] {
            XCTAssertEqual(TextSecurityGate.classify(role: "AXTextField", subrole: nil, subroleUnsupported: flags.0, attributeListKnown: flags.1, subroleAdvertised: flags.2, boundedRangeAdvertised: flags.3, characterCountKnown: flags.4), .unknown)
        }
        XCTAssertEqual(TextSecurityGate.classify(role: "AXButton", subrole: nil, subroleUnsupported: true, attributeListKnown: true, boundedRangeAdvertised: true, characterCountKnown: true), .unknown)
        XCTAssertEqual(TextSecurityGate.classify(role: "AXTextField", subrole: "AXUnknown"), .unknown)
    }
}

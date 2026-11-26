import XCTest
@testable import CollectorCore

/// Pure metadata only: no AX, input events, application history or provider reads.
final class InputSecurityClassificationTests: XCTestCase {
    func testOrdinaryNonEditableRolesAreDiagnosedWithoutGrantingInput() {
        let policy = CapturePolicy(fieldSecurity: "denylist")
        for role in ["AXButton", "AXGroup", "AXWebArea", "AXStaticText"] {
            XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: role, subrole: .noValue, protectedContent: .value(false), policy: policy), .roleNotEditable)
            XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: role, subrole: .attributeUnsupported, protectedContent: .attributeUnsupported, policy: policy), .roleNotEditable)
        }
        // Non-editability is a rejection category, not a claim that the policy
        // or field is safe. Even an invalid policy cannot turn it into input.
        XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: "AXStaticText", subrole: .noValue, protectedContent: .noValue, policy: CapturePolicy(fieldSecurity: "invalid")), .roleNotEditable)
    }

    func testSensitiveEvidenceWinsOverNonEditableMissingAndMalformedFacts() {
        let policy = CapturePolicy(fieldSecurity: "denylist")
        XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: "AXSecureTextField", subrole: .failure, protectedContent: .malformed, policy: policy), .sensitive)
        XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: "AXButton", subrole: .value("AXPasswordField"), protectedContent: .failure, policy: policy), .sensitive)
        XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: nil, subrole: .value("AXProtectedText"), protectedContent: .malformed, policy: policy), .sensitive)
        XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: "AXStaticText", subrole: .malformed, protectedContent: .value(true), policy: policy), .sensitive)
        XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: nil, subrole: .failure, protectedContent: .value(true), policy: CapturePolicy(fieldSecurity: "invalid")), .sensitive)
    }

    func testMissingRolesAndAttributeFailuresStayUnknownBeforeRoleDiagnosis() {
        let policy = CapturePolicy(fieldSecurity: "denylist")
        for role: String? in [nil, ""] {
            XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: role, subrole: .noValue, protectedContent: .noValue, policy: policy), .unknown)
        }
        for role in ["AXTextField", "AXStaticText", "AXButton"] {
            for subrole: TextSecurityGate.SubroleRead in [.failure, .malformed] {
                XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: role, subrole: subrole, protectedContent: .value(false), policy: policy), .unknown)
            }
            for protected: TextSecurityGate.ProtectedContentRead in [.failure, .malformed] {
                XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: role, subrole: .noValue, protectedContent: protected, policy: policy), .unknown)
            }
        }
    }

    func testStrictFallbackIsLazyAndCannotAuthorizeNonEditableOrInvalidPolicy() {
        var fallbackCalls = 0
        let safeFallback: () -> SecureStatus = { fallbackCalls += 1; return .safe }
        XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: "AXTextField", subrole: .attributeUnsupported, protectedContent: .noValue, policy: CapturePolicy(), strictFallback: safeFallback), .allowed(.textField))
        XCTAssertEqual(fallbackCalls, 1)
        XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: "AXTextArea", subrole: .noValue, protectedContent: .noValue, policy: CapturePolicy(fieldSecurity: "denylist"), strictFallback: safeFallback), .allowed(.textArea))
        XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: "AXStaticText", subrole: .noValue, protectedContent: .noValue, policy: CapturePolicy(), strictFallback: safeFallback), .roleNotEditable)
        XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: "AXTextArea", subrole: .failure, protectedContent: .noValue, policy: CapturePolicy(), strictFallback: safeFallback), .unknown)
        XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: "AXTextArea", subrole: .noValue, protectedContent: .noValue, policy: CapturePolicy(fieldSecurity: "invalid"), strictFallback: safeFallback), .unknown)
        XCTAssertEqual(fallbackCalls, 1)
        XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: "AXTextArea", subrole: .attributeUnsupported, protectedContent: .noValue, policy: CapturePolicy(), strictFallback: { .sensitive }), .sensitive)
        XCTAssertEqual(TextSecurityGate.classifyInputMetadata(role: "AXTextArea", subrole: .attributeUnsupported, protectedContent: .noValue, policy: CapturePolicy(), strictFallback: { .unknown }), .unknown)
    }

    func testAllowedInputSetMatchesExistingSecurityAndRoleGates() {
        // Compare the actual old pair of gates, not classifyMetadata alone:
        // StaticText can be readable by AX without authorizing input Unicode.
        let samples: [(String?, TextSecurityGate.SubroleRead, TextSecurityGate.ProtectedContentRead)] = [
            ("AXTextField", .value("AXStandardTextField"), .value(false)),
            ("AXTextArea", .value("AXTextArea"), .noValue),
            ("AXTextArea", .noValue, .value(false)),
            ("AXTextField", .attributeUnsupported, .attributeUnsupported),
            ("AXTextField", .value("AXUnknown"), .noValue),
            ("AXStaticText", .value("AXStaticText"), .value(false)),
            ("AXButton", .noValue, .value(false)),
            ("AXTextArea", .malformed, .noValue),
            ("AXTextArea", .noValue, .failure),
            ("AXTextArea", .noValue, .value(true)),
            ("AXSecureTextField", .failure, .failure),
            (nil, .noValue, .noValue),
        ]
        for policy in [CapturePolicy(), CapturePolicy(fieldSecurity: "denylist"), CapturePolicy(fieldSecurity: "invalid")] {
            for (role, subrole, protected) in samples {
                let legacySecurity = TextSecurityGate.classifyMetadata(role: role, subrole: subrole, protectedContent: protected, policy: policy)
                let legacyRole = role.flatMap(InputTextFieldRole.init(rawValue:))
                let actual = TextSecurityGate.classifyInputMetadata(role: role, subrole: subrole, protectedContent: protected, policy: policy)
                if let legacyRole, policy.allows(legacySecurity) {
                    XCTAssertEqual(actual, .allowed(legacyRole))
                } else if case .allowed = actual {
                    XCTFail("Input eligibility widened the existing field-security and role gates")
                }
            }
        }
    }
}

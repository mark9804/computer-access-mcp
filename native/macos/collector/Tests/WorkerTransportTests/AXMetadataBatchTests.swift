import XCTest
import Foundation
import ApplicationServices
import CollectorCore
@testable import computer_access_collector

/// Exercises the production request/decoder with synthetic CF values only.
/// Creating an own-PID AX handle performs no AX IPC; every read injects copy,
/// so these tests never inspect the desktop, request TCC or read any AX value.
final class AXMetadataBatchTests: XCTestCase {
    private func handle() -> AXUIElement { AXUIElementCreateApplication(ProcessInfo.processInfo.processIdentifier) }
    private func array(_ values: [AnyObject]) -> CFArray { values as CFArray }
    private func error(_ status: AXError) -> AXValue {
        var status = status
        return AXValueCreate(.axError, &status)!
    }
    private func point(_ x: CGFloat, _ y: CGFloat) -> AXValue {
        var value = CGPoint(x: x, y: y)
        return AXValueCreate(.cgPoint, &value)!
    }
    private func size(_ width: CGFloat, _ height: CGFloat) -> AXValue {
        var value = CGSize(width: width, height: height)
        return AXValueCreate(.cgSize, &value)!
    }
    private func read(_ values: CFArray?, status: AXError = .success) -> AXMetadataBatch.Snapshot {
        AXMetadataBatch.read(element: handle(), permit: { true }, copy: { _, _, _, output in
            output.pointee = values
            return status
        })
    }

    private func fullArray(
        role: AnyObject,
        subrole: AnyObject,
        protected: AnyObject,
        enabled: AnyObject? = nil,
        title: AnyObject? = nil,
        description: AnyObject? = nil,
        url: AnyObject? = nil,
        position: AnyObject? = nil,
        size: AnyObject? = nil,
        identifier: AnyObject? = nil
    ) -> CFArray {
        let missing = error(.noValue)
        return array([
            role,
            subrole,
            protected,
            enabled ?? missing,
            title ?? missing,
            description ?? missing,
            url ?? missing,
            position ?? missing,
            size ?? missing,
            identifier ?? missing,
        ])
    }

    func testOnePermittedRequestUsesOnlyTheFixedTenMetadataAttributesWithoutValueAndOptionsZero() {
        let element = handle()
        var permits = 0, requests = 0
        let snapshot = AXMetadataBatch.read(element: element, permit: { permits += 1; return true }, copy: { receiver, attributes, options, output in
            requests += 1
            XCTAssertTrue(CFEqual(receiver, element))
            let names = attributes as? [String]
            XCTAssertEqual(names, [
                "AXRole",
                "AXSubrole",
                "AXContainsProtectedContent",
                "AXEnabled",
                "AXTitle",
                "AXDescription",
                "AXURL",
                "AXPosition",
                "AXSize",
                "AXIdentifier",
            ])
            XCTAssertFalse(names?.contains("AXValue") ?? true, "AXValue must never be fetched in metadata batch")
            XCTAssertEqual(options.rawValue, 0)
            output.pointee = self.fullArray(
                role: "AXLink" as NSString,
                subrole: self.error(.noValue),
                protected: kCFBooleanFalse!,
                enabled: kCFBooleanTrue!,
                title: "Docs" as NSString,
                description: "Reference link" as NSString,
                url: NSURL(string: "https://example.com/docs")!,
                position: self.point(120, 240),
                size: self.size(320, 44),
                identifier: "chat_message_list" as NSString
            )
            return .success
        })
        XCTAssertEqual(permits, 1)
        XCTAssertEqual(requests, AXMetadataBatch.requestCost)
        XCTAssertEqual(AXMetadataBatch.requestCost, 1)
        XCTAssertEqual(AXMetadataBatch.attributeCount, 10)
        XCTAssertEqual(snapshot.status, .success)
        XCTAssertEqual(snapshot.roleStatus, .value("AXLink"))
        XCTAssertEqual(snapshot.subroleRead, .noValue)
        XCTAssertEqual(snapshot.protectedRead, .value(false))
        XCTAssertEqual(snapshot.isEnabled, true)
        XCTAssertEqual(snapshot.safeTitle, "Docs")
        XCTAssertEqual(snapshot.safeDescription, "Reference link")
        XCTAssertEqual(snapshot.safeURL, "https://example.com/docs")
        XCTAssertEqual(snapshot.safeRect, SurfaceAbsoluteRect(x: 120, y: 240, width: 320, height: 44))
        XCTAssertEqual(snapshot.safeIdentifier, "chat_message_list")
        XCTAssertFalse(snapshot.hasSensitiveEvidence)

        // String URLs, empty identifiers, and missing geometry decode cleanly.
        let stringURL = read(fullArray(
            role: "AXWebArea" as NSString,
            subrole: error(.noValue),
            protected: error(.attributeUnsupported),
            enabled: kCFBooleanTrue!,
            title: "Home" as NSString,
            description: error(.noValue),
            url: "https://example.org" as NSString,
            identifier: "" as NSString
        ))
        XCTAssertEqual(stringURL.safeTitle, "Home")
        XCTAssertEqual(stringURL.safeURL, "https://example.org")
        XCTAssertNil(stringURL.safeRect)
        XCTAssertNil(stringURL.safeIdentifier)
    }

    func testBatchSuccessPreservesPerAttributeAbsenceErrorsNullAndMalformed() {
        let absent = read(fullArray(role: "AXTextArea" as NSString, subrole: error(.noValue), protected: error(.attributeUnsupported)))
        XCTAssertEqual(absent.status, .success)
        XCTAssertEqual(absent.role, "AXTextArea")
        XCTAssertEqual(absent.subroleStatus, .noValue)
        XCTAssertEqual(absent.protectedStatus, .attributeUnsupported)
        XCTAssertEqual(absent.subroleStatus.axError?.rawValue, -25212)
        XCTAssertEqual(absent.protectedStatus.axError?.rawValue, -25205)
        XCTAssertEqual(absent.subroleRead, .noValue)
        XCTAssertEqual(absent.protectedRead, .attributeUnsupported)
        XCTAssertNil(absent.isEnabled)
        XCTAssertNil(absent.safeRect)

        // CFNull does not mean noValue/unsupported; numeric 1 is not CFBoolean.
        let failed = read(fullArray(
            role: kCFNull!,
            subrole: error(.cannotComplete),
            protected: NSNumber(value: 1),
            title: "Never exposed" as NSString,
            position: point(10, 20),
            size: size(100, 30),
            identifier: "never_exposed_id" as NSString
        ))
        XCTAssertEqual(failed.status, .success)
        XCTAssertEqual(failed.roleStatus, .null)
        XCTAssertNil(failed.role)
        XCTAssertEqual(failed.subroleStatus, .apiFailure(.cannotComplete))
        XCTAssertEqual(failed.subroleStatus.axError?.rawValue, -25204)
        XCTAssertEqual(failed.protectedStatus, .malformed)
        XCTAssertEqual(failed.subroleRead, .failure)
        XCTAssertEqual(failed.protectedRead, .malformed)
        XCTAssertNil(failed.safeTitle, "Failed/malformed security metadata must suppress display attributes")
        XCTAssertNil(failed.safeRect, "Failed/malformed security metadata must suppress safeRect")
        XCTAssertNil(failed.safeIdentifier, "Failed/malformed security metadata must suppress safeIdentifier")
        XCTAssertFalse(TextSecurityGate.mayTraverse(subrole: failed.subroleRead, protectedContent: failed.protectedRead))

        // Invalid geometry values (negative size, NaN, mismatched AXValue type) return nil safeRect.
        let negativeSize = read(fullArray(
            role: "AXStaticText" as NSString,
            subrole: error(.noValue),
            protected: kCFBooleanFalse!,
            position: point(10, 20),
            size: size(-5, 30)
        ))
        XCTAssertNil(negativeSize.safeRect)
        let nanPoint = read(fullArray(
            role: "AXStaticText" as NSString,
            subrole: error(.noValue),
            protected: kCFBooleanFalse!,
            position: point(.nan, 20),
            size: size(50, 30)
        ))
        XCTAssertNil(nanPoint.safeRect)
        var cfRange = CFRange(location: 0, length: 5)
        let wrongAXValue = AXValueCreate(.cfRange, &cfRange)!
        let wrongGeometryType = read(fullArray(
            role: "AXStaticText" as NSString,
            subrole: error(.noValue),
            protected: kCFBooleanFalse!,
            position: wrongAXValue,
            size: size(50, 30)
        ))
        XCTAssertNil(wrongGeometryType.safeRect)
        // A non-error AXValue placed in a string slot must remain malformed.
        let pointInRoleSlot = read(fullArray(
            role: point(1, 2),
            subrole: error(.noValue),
            protected: kCFBooleanFalse!,
            position: point(10, 20),
            size: size(50, 30)
        ))
        XCTAssertEqual(pointInRoleSlot.roleStatus, .malformed)
        XCTAssertNil(pointInRoleSlot.safeRect)

        let nullProtected = read(fullArray(role: "AXTextArea" as NSString, subrole: "" as NSString, protected: kCFNull!))
        XCTAssertEqual(nullProtected.protectedStatus, .null)
        XCTAssertEqual(nullProtected.protectedRead, .malformed)
        // An AXError.success wrapper still contains no typed metadata value.
        let wrappedSuccess = read(fullArray(role: error(.success), subrole: "" as NSString, protected: kCFBooleanFalse!))
        XCTAssertEqual(wrappedSuccess.roleStatus, .malformed)
    }

    func testPositiveSensitiveEvidenceIsNotErasedByAnotherBadAttributeAndStripsDisplayMetadata() {
        let protected = read(fullArray(
            role: NSNumber(value: 7),
            subrole: error(.cannotComplete),
            protected: kCFBooleanTrue!,
            enabled: kCFBooleanTrue!,
            title: "Secret Title" as NSString,
            description: "Secret Desc" as NSString,
            url: NSURL(string: "https://secret.example/token")!,
            position: point(10, 20),
            size: size(200, 40),
            identifier: "secret_protected_id" as NSString
        ))
        XCTAssertEqual(protected.roleStatus, .malformed)
        XCTAssertEqual(protected.protectedStatus, .value(true))
        XCTAssertTrue(protected.hasSensitiveEvidence)
        XCTAssertNil(protected.safeTitle)
        XCTAssertNil(protected.safeDescription)
        XCTAssertNil(protected.safeURL)
        XCTAssertNil(protected.safeRect)
        XCTAssertNil(protected.safeIdentifier)
        XCTAssertEqual(TextSecurityGate.classifyMetadata(role: protected.role, subrole: protected.subroleRead,
            protectedContent: protected.protectedRead, policy: CapturePolicy(fieldSecurity: "denylist")), .sensitive)

        let secureRole = read(fullArray(
            role: "AXSecureTextField" as NSString,
            subrole: error(.noValue),
            protected: kCFBooleanFalse!,
            title: "Password" as NSString,
            description: "Enter password" as NSString,
            url: "https://vault.example" as NSString,
            position: point(10, 20),
            size: size(200, 40),
            identifier: "password_input_id" as NSString
        ))
        XCTAssertTrue(secureRole.hasSensitiveEvidence)
        XCTAssertNil(secureRole.safeTitle)
        XCTAssertNil(secureRole.safeDescription)
        XCTAssertNil(secureRole.safeURL)
        XCTAssertNil(secureRole.safeRect)
        XCTAssertNil(secureRole.safeIdentifier)

        let secureSubrole = read(fullArray(
            role: "AXTextField" as NSString,
            subrole: "AXSecureTextField" as NSString,
            protected: kCFBooleanFalse!,
            title: "PIN" as NSString,
            description: "Secret PIN" as NSString,
            url: NSURL(string: "https://bank.example")!,
            position: point(10, 20),
            size: size(200, 40),
            identifier: "pin_input_id" as NSString
        ))
        XCTAssertTrue(secureSubrole.hasSensitiveEvidence)
        XCTAssertNil(secureSubrole.safeTitle)
        XCTAssertNil(secureSubrole.safeDescription)
        XCTAssertNil(secureSubrole.safeURL)
        XCTAssertNil(secureSubrole.safeRect)
        XCTAssertNil(secureSubrole.safeIdentifier)
    }

    func testNilOrWrongLengthSuccessfulArraysRejectTheWholeShapeWithoutRetry() {
        // Fixed positional interpretation is valid only for exactly ten slots.
        let replies: [CFArray?] = [nil, array([]),
            array(["AXTextArea" as NSString, "" as NSString, kCFBooleanFalse!]),
            array(["AXTextArea" as NSString, "" as NSString, kCFBooleanFalse!, kCFBooleanTrue!, "T" as NSString, "D" as NSString, "https://example.com" as NSString, kCFNull!, kCFNull!]),
            array(["AXSecureTextField" as NSString, "" as NSString, kCFBooleanTrue!, kCFNull!, kCFNull!, kCFNull!, kCFNull!, kCFNull!, kCFNull!, kCFNull!, kCFNull!])]
        for reply in replies {
            var requests = 0
            let snapshot = AXMetadataBatch.read(element: handle(), permit: { true }, copy: { _, _, _, output in
                requests += 1; output.pointee = reply; return .success
            })
            XCTAssertEqual(requests, 1)
            XCTAssertEqual(snapshot.status, .malformed)
            XCTAssertEqual(snapshot.roleStatus, .malformed)
            XCTAssertEqual(snapshot.subroleStatus, .malformed)
            XCTAssertEqual(snapshot.protectedStatus, .malformed)
            XCTAssertNil(snapshot.safeTitle)
            XCTAssertNil(snapshot.safeDescription)
            XCTAssertNil(snapshot.safeURL)
            XCTAssertNil(snapshot.safeRect)
            XCTAssertNil(snapshot.safeIdentifier)
            XCTAssertFalse(snapshot.hasSensitiveEvidence)
        }
    }

    func testWholeRequestErrorsNeverBecomeOptionalAbsenceOrTriggerFallback() {
        for status in [AXError.notImplemented, .attributeUnsupported, .apiDisabled] {
            var requests = 0
            let snapshot = AXMetadataBatch.read(element: handle(), permit: { true }, copy: { _, _, _, output in
                requests += 1
                output.pointee = self.fullArray(role: "AXTextArea" as NSString, subrole: "" as NSString, protected: kCFBooleanFalse!)
                return status
            })
            XCTAssertEqual(requests, 1)
            XCTAssertEqual(snapshot.status, .apiFailure(status))
            XCTAssertEqual(snapshot.status.axError, status)
            XCTAssertEqual(snapshot.roleStatus, .notRead)
            XCTAssertEqual(snapshot.subroleStatus, .notRead)
            XCTAssertEqual(snapshot.protectedStatus, .notRead)
            XCTAssertEqual(snapshot.subroleRead, .failure)
            XCTAssertEqual(snapshot.protectedRead, .failure)
            XCTAssertNil(snapshot.safeTitle)
        }
    }

    func testDiagnosticsKeepTypedShapeAndRealErrorsButNeverMetadataValues() {
        let absent = read(fullArray(
            role: "SYNTHETIC_PRIVATE_ROLE" as NSString,
            subrole: error(.noValue),
            protected: error(.attributeUnsupported),
            title: "SYNTHETIC_PRIVATE_TITLE" as NSString,
            description: "SYNTHETIC_PRIVATE_DESC" as NSString,
            url: "https://synthetic.private/path" as NSString,
            identifier: "SYNTHETIC_PRIVATE_ID" as NSString
        ))
        XCTAssertEqual(absent.debugNumbers, ["batchStatus": 1, "roleStatus": 1, "subroleStatus": 2, "protectedStatus": 3,
            "subroleAXError": -25212, "protectedAXError": -25205])
        let failed = read(fullArray(role: kCFNull!, subrole: error(.cannotComplete), protected: NSNumber(value: 1)))
        XCTAssertEqual(failed.debugNumbers, ["batchStatus": 1, "roleStatus": 4, "subroleStatus": 7, "protectedStatus": 5, "subroleAXError": -25204])
        let request = read(nil, status: .cannotComplete)
        XCTAssertEqual(request.debugNumbers, ["batchStatus": 7, "roleStatus": 6, "subroleStatus": 6, "protectedStatus": 6, "batchAXError": -25204])
        XCTAssertFalse(String(describing: absent.debugNumbers).contains("SYNTHETIC_PRIVATE"))
    }

    func testPermitDenialPerformsNoCopy() {
        var permits = 0, requests = 0
        let snapshot = AXMetadataBatch.read(element: handle(), permit: { permits += 1; return false }, copy: { _, _, _, _ in
            requests += 1; XCTFail("copy must not run after the gate refused"); return .success
        })
        XCTAssertEqual(permits, 1)
        XCTAssertEqual(requests, 0)
        XCTAssertEqual(snapshot.status, .notPermitted)
        XCTAssertEqual(snapshot.roleStatus, .notRead)
        XCTAssertEqual(snapshot.subroleRead, .failure)
        XCTAssertEqual(snapshot.protectedRead, .failure)
    }
}

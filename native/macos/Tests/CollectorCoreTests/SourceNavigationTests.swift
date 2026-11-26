import XCTest
@testable import CollectorCore

final class SourceNavigationTests: XCTestCase {
    private let json = "{\"version\":1,\"applicationId\":\"test.allowed\",\"processId\":123,\"processStartTime\":\"unix-ms:1700000000000.123\",\"osSessionId\":\"audit-42\",\"desktopId\":\"console-audit-42\"}"
    private var request: SourceNavigationRequest { try! .parse(Data(json.utf8)) }
    private var application: SourceNavigationApplicationEvidence {
        SourceNavigationApplicationEvidence(identity: request.application, permittedNonBrowser: true)
    }
    private func session(uid: UInt32 = 501, effectiveUID: UInt32 = 501, audit: UInt32? = 42,
                         consoleUID: UInt32? = 501, consoleAudit: UInt32? = 42,
                         desktop: DesktopStatus = .unlocked) -> SourceNavigationSessionEvidence {
        SourceNavigationSessionEvidence(userId: uid, effectiveUserId: effectiveUID, auditSessionId: audit,
            consoleUserId: consoleUID, consoleAuditSessionId: consoleAudit, desktop: desktop)
    }
    private func fake() -> NavigationFakeProvider {
        NavigationFakeProvider(session: session(), application: application)
    }
    private func assertInvalid(_ value: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try SourceNavigationRequest.parse(Data(value.utf8)), file: file, line: line) { error in
            XCTAssertEqual(error as? SourceNavigationReason, .invalidRequest, file: file, line: line)
        }
    }

    func testExactArgumentsDoNotFallThroughToNavigation() {
        XCTAssertTrue(SourceNavigationRequest.acceptsArguments(["--navigate-source"]))
        for args in [[], ["navigate-source"], ["--navigate-source", "extra"], ["--navigate-source", "--serve"],
                     ["--serve", "--navigate-source"], ["--permissions", "check"], ["--navigate-source", "--navigate-source"]] {
            XCTAssertFalse(SourceNavigationRequest.acceptsArguments(args), "\(args)")
        }
    }

    func testCanonicalRequestAndOwnerLockSessionFormat() throws {
        let request = try SourceNavigationRequest.parse(Data((" \n" + json + "\r\n\t").utf8))
        XCTAssertEqual(request.applicationId, "test.allowed")
        XCTAssertEqual(request.processId, 123)
        XCTAssertEqual(request.processStartTime, "unix-ms:1700000000000.123")
        let id: UInt32 = 42
        let ownerLockSession = "audit-\(id)" // Ownership.swift production format.
        XCTAssertEqual(request.osSessionId, ownerLockSession)
        XCTAssertEqual(request.desktopId, "console-\(ownerLockSession)")
        XCTAssertEqual(request.auditSessionId, id)
        let escapedKey = json.replacingOccurrences(of: "\"version\"", with: "\"\\u0076ersion\"")
        XCTAssertEqual(try SourceNavigationRequest.parse(Data(escapedKey.utf8)), request)
    }

    func testRejectsUnknownMissingDuplicateAndNestedFields() {
        for value in ["", "{}", "[]", "null", "1", "true", json + json, json + "junk", json + "\0",
            "\u{FEFF}" + json, json.replacingOccurrences(of: "\"version\":1,", with: ""),
            json.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1"),
            json.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"\\u0076ersion\":1"),
            json.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"windowId\":\"historic\""),
            json.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"url\":\"https://example.test\""),
            json.replacingOccurrences(of: "\"test.allowed\"", with: "{\"bundle\":\"test.allowed\"}"),
            json.replacingOccurrences(of: "\"test.allowed\"", with: "[\"test.allowed\"]"),
            json.replacingOccurrences(of: "\"test.allowed\"", with: "null"),
            json.replacingOccurrences(of: "\"test.allowed\"", with: "true"),
            json.replacingOccurrences(of: "\"test.allowed\"", with: "\"test.\\uD800\""),
            json.replacingOccurrences(of: "\"test.allowed\"", with: "\"test.\\uDC00\""),
            json.replacingOccurrences(of: "\"test.allowed\"", with: "\"test.\\uD800\\u0041\""),
            json.replacingOccurrences(of: "\"test.allowed\"", with: "\"test.\\x41\""),
            json.replacingOccurrences(of: "\"test.allowed\"", with: "\"test.\nallowed\""),
            json.replacingOccurrences(of: "}", with: ",}")] {
            assertInvalid(value)
        }
        var invalidUTF8 = Data(json.utf8); invalidUTF8.append(0xFF)
        XCTAssertThrowsError(try SourceNavigationRequest.parse(invalidUTF8))
    }

    func testStrictNumbersBundleBirthAndSessionIdentity() {
        for version in ["true", "false", "null", "\"1\"", "1.5", "01", "-1", "0", "2", "+1"] {
            assertInvalid(json.replacingOccurrences(of: "\"version\":1", with: "\"version\":" + version))
        }
        for pid in ["true", "null", "\"123\"", "123.5", "0123", "0", "1", "-1", "2147483648", "99999999999"] {
            assertInvalid(json.replacingOccurrences(of: "\"processId\":123", with: "\"processId\":" + pid))
        }
        for bundle in ["", "test allowed", "test/allowed", "https://example.test", "com.测试", String(repeating: "x", count: 257)] {
            assertInvalid(json.replacingOccurrences(of: "test.allowed", with: bundle))
        }
        for birth in ["unix-ms:nan", "unix-ms:inf", "unix-ms:0.000", "unix-ms:-1.000", "unix-ms:01.123", "unix-ms:1",
                      "unix-ms:1.12", "unix-ms:1.1234", "unix-ms:1e3.123", "unix-ms:9007199254740992.000", "1700000000000.123"] {
            assertInvalid(json.replacingOccurrences(of: "unix-ms:1700000000000.123", with: birth))
        }
        for audit in ["fixture-42", "audit-042", "audit-+42", "audit--1", "audit-4294967295", "audit-4294967296", "audit-\\(id)"] {
            assertInvalid(json.replacingOccurrences(of: "audit-42", with: audit))
        }
        assertInvalid(json.replacingOccurrences(of: "console-audit-42", with: "console-audit-43"))
        assertInvalid(json.replacingOccurrences(of: "console-audit-42", with: "fixture-desktop"))
    }

    func testInputBudgetCountsBytesIncludingWhitespace() throws {
        let atLimit = Data((json + String(repeating: " ", count: 2_048 - json.utf8.count)).utf8)
        XCTAssertEqual(atLimit.count, SourceNavigationRequest.maximumInputBytes)
        XCTAssertEqual(try SourceNavigationRequest.parse(atLimit), request)
        var tooLong = atLimit; tooLong.append(32)
        XCTAssertThrowsError(try SourceNavigationRequest.parse(tooLong)) { error in
            XCTAssertEqual(error as? SourceNavigationReason, .inputTooLarge)
        }
    }

    func testSessionGateRequiresRealEffectiveAuditAndConsoleIdentity() {
        let cases: [(SourceNavigationSessionEvidence, SourceNavigationReason)] = [
            (session(audit: nil), .sessionUnavailable), (session(audit: UInt32.max), .sessionUnavailable),
            (session(consoleUID: nil), .sessionUnavailable), (session(consoleAudit: nil), .sessionUnavailable),
            (session(effectiveUID: 0), .sessionMismatch), (session(consoleUID: 502), .sessionMismatch),
            (session(consoleAudit: 43), .sessionMismatch), (session(audit: 43, consoleAudit: 43), .sessionMismatch),
            (session(desktop: .locked), .desktopUnavailable), (session(desktop: .unknown), .desktopUnavailable),
        ]
        for (evidence, reason) in cases {
            let provider = fake(); provider.sessions = [evidence]
            XCTAssertEqual(SourceNavigation.navigate(request, provider: provider), SourceNavigationReceipt(reason: reason))
            XCTAssertEqual(provider.runningCalls, 0)
            XCTAssertEqual(provider.activationCalls, 0)
            XCTAssertEqual(provider.frontmostCalls, 0)
        }
    }

    func testInitialProcessGateRequiresRunningBundlePidBirthAndNonBrowser() {
        var wrongPID = request.application; wrongPID.processId = 124
        var wrongBundle = request.application; wrongBundle.applicationId = "test.other"
        var reusedPID = request.application; reusedPID.processStartTime = "unix-ms:1700000000001.123"
        for identity in [wrongPID, wrongBundle, reusedPID] {
            let provider = fake(); provider.applications = [.init(identity: identity, permittedNonBrowser: true)]
            XCTAssertEqual(SourceNavigation.navigate(request, provider: provider).reason, .applicationMismatch)
            XCTAssertEqual(provider.activationCalls, 0)
        }
        let absent = fake(); absent.applications = [nil]
        XCTAssertEqual(SourceNavigation.navigate(request, provider: absent).reason, .applicationUnavailable)
        XCTAssertEqual(absent.activationCalls, 0)
        let blocked = fake(); blocked.applications = [.init(identity: request.application, permittedNonBrowser: false)]
        XCTAssertEqual(SourceNavigation.navigate(request, provider: blocked).reason, .applicationBlocked)
        XCTAssertEqual(blocked.activationCalls, 0)
    }

    func testFreshPreDispatchGateRefusesChangedSessionAndPidReuse() {
        let provider = fake(); provider.sessions = [session(), session(desktop: .locked)]
        XCTAssertEqual(SourceNavigation.navigate(request, provider: provider).reason, .desktopUnavailable)
        XCTAssertEqual(provider.activationCalls, 0)
        var newBirth = request.application; newBirth.processStartTime = "unix-ms:1700000000001.123"
        let reused = fake(); reused.applications = [application, .init(identity: newBirth, permittedNonBrowser: true)]
        XCTAssertEqual(SourceNavigation.navigate(request, provider: reused).reason, .applicationMismatch)
        XCTAssertEqual(reused.activationCalls, 0)
        for reason in [SourceNavigationReason.parentUnavailable, .deadlineExceeded] {
            let stopped = fake()
            let receipt = SourceNavigation.navigate(request, provider: stopped, markDispatched: { reason })
            XCTAssertEqual(receipt.outcome, .refused)
            XCTAssertEqual(receipt.reason, reason)
            XCTAssertEqual(stopped.activationCalls, 0)
        }
    }

    func testActivationConfirmedOnlyByFreshSameFrontmostAndBirth() {
        let provider = fake(); var dispatchCount = 0
        let receipt = SourceNavigation.navigate(request, provider: provider, markDispatched: { dispatchCount += 1; return nil })
        XCTAssertEqual(receipt.outcome, .activated)
        XCTAssertEqual(receipt.reason, .activated)
        XCTAssertEqual(provider.activationCalls, 1)
        XCTAssertEqual(dispatchCount, 1)
        XCTAssertEqual(provider.runningCalls, 4) // initial, dispatch, post, after-frontmost birth.
        XCTAssertEqual(provider.sessionCalls, 4)
        XCTAssertEqual(provider.frontmostCalls, 1)
        XCTAssertFalse(receipt.captured)
        XCTAssertFalse(receipt.launched)
    }

    func testDispatchNotConfirmationAndNeverRetries() {
        let rejected = fake(); rejected.accepted = false
        let rejection = SourceNavigation.navigate(request, provider: rejected)
        XCTAssertEqual(rejection.reason, .activationRejected)
        XCTAssertEqual(rejection.outcome, .uncertain)
        XCTAssertEqual(rejected.activationCalls, 1)
        XCTAssertEqual(rejected.frontmostCalls, 0)
        for front in [nil, SourceNavigationApplicationEvidence(identity: .init(applicationId: "test.other", processId: 222,
                                                                             processStartTime: request.processStartTime), permittedNonBrowser: true)] {
            let provider = fake(); provider.frontmost = front
            let receipt = SourceNavigation.navigate(request, provider: provider)
            XCTAssertEqual(receipt.outcome, .uncertain)
            XCTAssertEqual(receipt.reason, .activationUnconfirmed)
            XCTAssertEqual(provider.activationCalls, 1)
            XCTAssertEqual(provider.frontmostCalls, 1)
        }
    }

    func testPostDispatchSessionProcessAndAfterFrontmostBirthRaceAreUncertain() {
        let locked = fake(); locked.sessions = [session(), session(), session(desktop: .locked)]
        XCTAssertEqual(SourceNavigation.navigate(request, provider: locked).reason, .postconditionChanged)
        XCTAssertEqual(locked.activationCalls, 1)
        let ended = fake(); ended.applications = [application, application, nil]
        XCTAssertEqual(SourceNavigation.navigate(request, provider: ended).reason, .postconditionChanged)
        XCTAssertEqual(ended.activationCalls, 1)
        var newBirth = request.application; newBirth.processStartTime = "unix-ms:1700000000001.123"
        let reused = fake(); reused.applications = [application, application, application, .init(identity: newBirth, permittedNonBrowser: true)]
        let receipt = SourceNavigation.navigate(request, provider: reused)
        XCTAssertEqual(receipt.outcome, .uncertain)
        XCTAssertEqual(receipt.reason, .postconditionChanged)
        XCTAssertEqual(reused.frontmostCalls, 1)
        XCTAssertEqual(reused.activationCalls, 1)
        let frontmostReused = fake(); frontmostReused.frontmost = .init(identity: newBirth, permittedNonBrowser: true)
        XCTAssertEqual(SourceNavigation.navigate(request, provider: frontmostReused).reason, .activationUnconfirmed)
    }

    func testAllReceiptsAreFixedFiniteBoundedAndContentFree() throws {
        let reasons = Set(["activated", "invalid-request", "input-too-large", "input-timeout", "input-unavailable", "parent-unavailable",
            "deadline-exceeded", "session-unavailable", "session-mismatch", "desktop-unavailable", "application-unavailable",
            "application-mismatch", "application-blocked", "activation-rejected", "activation-unconfirmed", "postcondition-changed", "internal-error"])
        XCTAssertEqual(Set(SourceNavigationReason.allCases.map(\.rawValue)), reasons)
        for reason in SourceNavigationReason.allCases {
            for dispatched in [false, true] {
                let receipt = SourceNavigationReceipt(reason: reason, afterDispatch: dispatched)
                let line = receipt.encodedLine()
                XCTAssertLessThanOrEqual(line.count, SourceNavigationReceipt.maximumOutputBytes)
                XCTAssertEqual(line.last, 10)
                let object = try XCTUnwrap(JSONSerialization.jsonObject(with: line) as? [String: Any])
                XCTAssertEqual(Set(object.keys), Set(["version", "outcome", "reason", "captured", "launched"]))
                XCTAssertEqual(object["version"] as? Int, 1)
                XCTAssertEqual(object["captured"] as? Bool, false)
                XCTAssertEqual(object["launched"] as? Bool, false)
                XCTAssertEqual(object["reason"] as? String, reason.rawValue)
                let uncertain = [.activationRejected, .activationUnconfirmed, .postconditionChanged].contains(reason) ||
                    dispatched && [.parentUnavailable, .deadlineExceeded].contains(reason)
                XCTAssertEqual(receipt.outcome, reason == .activated ? .activated : uncertain ? .uncertain : .refused)
                XCTAssertFalse(String(decoding: line, as: UTF8.self).contains(request.applicationId))
                XCTAssertFalse(String(decoding: line, as: UTF8.self).contains(request.processStartTime))
            }
        }
        XCTAssertEqual(SourceNavigationReceipt(reason: .activated).exitCode, 0)
        XCTAssertEqual(SourceNavigationReceipt(reason: .applicationUnavailable).exitCode, 0)
        XCTAssertEqual(SourceNavigationReceipt(reason: .activationUnconfirmed).exitCode, 0)
        XCTAssertEqual(SourceNavigationReceipt(reason: .invalidRequest).exitCode, 64)
        XCTAssertEqual(SourceNavigationReceipt(reason: .inputTooLarge).exitCode, 64)
        XCTAssertEqual(SourceNavigationReceipt(reason: .internalError).exitCode, 70)
        XCTAssertEqual(SourceNavigationReceipt(reason: .inputUnavailable).exitCode, 74)
        XCTAssertEqual(SourceNavigationReceipt(reason: .inputTimeout).exitCode, 75)
        XCTAssertEqual(SourceNavigationReceipt(reason: .parentUnavailable, afterDispatch: true).exitCode, 75)
        XCTAssertEqual(SourceNavigationReceipt(reason: .deadlineExceeded, afterDispatch: true).exitCode, 75)
    }
}

private final class NavigationFakeProvider: SourceNavigationProvider {
    var sessions: [SourceNavigationSessionEvidence]
    var applications: [SourceNavigationApplicationEvidence?]
    var frontmost: SourceNavigationApplicationEvidence?
    var accepted = true
    var sessionCalls = 0
    var runningCalls = 0
    var activationCalls = 0
    var frontmostCalls = 0
    init(session: SourceNavigationSessionEvidence, application: SourceNavigationApplicationEvidence) {
        sessions = [session]; applications = [application]; frontmost = application
    }
    func sessionEvidence() -> SourceNavigationSessionEvidence {
        sessionCalls += 1
        return sessions.count > 1 ? sessions.removeFirst() : sessions[0]
    }
    func runningApplication(processId: Int32) -> SourceNavigationApplicationEvidence? {
        runningCalls += 1
        return applications.count > 1 ? applications.removeFirst() : applications[0]
    }
    func activate(_ request: SourceNavigationRequest, markDispatched: () -> SourceNavigationReason?) -> SourceNavigationDispatch {
        if let reason = SourceNavigationGate.session(request, sessionEvidence()) { return .notDispatched(reason) }
        if let reason = SourceNavigationGate.application(request, runningApplication(processId: request.processId)) { return .notDispatched(reason) }
        if let reason = markDispatched() { return .notDispatched(reason) }
        activationCalls += 1
        return .submitted(accepted: accepted)
    }
    func frontmostApplication() -> SourceNavigationApplicationEvidence? {
        frontmostCalls += 1
        return frontmost
    }
}

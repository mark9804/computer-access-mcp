import XCTest
import CollectorCore
@testable import CollectorRuntime

/// Production ReadGate + native closed classification, with only synthetic
/// metadata/identities/clocks. No CGEvent, AX handle, TCC query or tap is created.
final class InputContextDebugTests: XCTestCase {
    private let nanos: UInt64 = 1_000_000_000
    private func context(pid: Int32 = 42, surface: String = "fixture-field") -> InputTextContext {
        InputTextContext(target: InputTextTarget(application: ApplicationIdentity(applicationId: "test.allowed", processId: pid, processStartTime: "fixture-birth"),
            deviceId: "fixture-device", osSessionId: "fixture-session", desktopId: "fixture-desktop", windowId: "fixture-window", windowGeneration: 1),
            surfaceId: surface, captureEpoch: 1, foregroundGeneration: 1, focusGeneration: 1, policyRevision: 1, privateState: .normal)
    }
    private func metadata(timestamp: UInt64 = 1_000_000_000) -> InputTextEventMetadata {
        InputTextEventMetadata(targetProcessId: 42, timestampNanoseconds: timestamp, callbackTimeMs: 1_000)
    }
    private var policy: CapturePolicy { CapturePolicy(applicationScope: "denylist", inputText: true) }
    private func approval(_ context: InputTextContext? = nil, role: InputTextFieldRole = .textArea) -> InputTextApprovedContext {
        InputTextApprovedContext(context: context ?? self.context(), metadataMonotonicNanoseconds: nanos, role: role)
    }
    private func assertGap(_ decision: InputTextCaptureDecision, _ expected: InputTextGapReason, file: StaticString = #filePath, line: UInt = #line) {
        guard case .gap(let actual) = decision else { return XCTFail("Expected rejected production decision", file: file, line: line) }
        XCTAssertEqual(actual, expected, file: file, line: line)
    }
    private func assertClassification(_ rejection: InputTextReadRejection?, stage: InputDebugTrace.Stage, reason: InputDebugTrace.Reason,
                                      file: StaticString = #filePath, line: UInt = #line) {
        guard let rejection, let actual = InputDebugTrace.classification(rejection) else { return XCTFail("Missing closed production classification", file: file, line: line) }
        XCTAssertEqual(actual.0, stage, file: file, line: line)
        XCTAssertEqual(actual.1, reason, file: file, line: line)
    }

    func testReceiveClassifiesFutureExpiredAndBoundaryEventsBeforeAnySafetyOrUnicodeRead() {
        let cases: [(UInt64, UInt64, InputDebugTrace.Reason)] = [
            (nanos + 1, 0, .eventInFuture),
            (nanos - 200_000_001, 0, .eventAgeExceeded),
            (nanos, nanos, .eventBeforeBoundary),
        ]
        for (timestamp, boundary, reason) in cases {
            var calls: [String] = [], rejections: [InputTextReadRejection] = []
            let decision = InputTextReadGate.capture(metadata: metadata(timestamp: timestamp), modifiers: [], policy: policy,
                afterNanoseconds: boundary, nowNanoseconds: { calls.append("clock"); return self.nanos },
                safetyProvider: { _ in calls.append("safety"); return self.approval() },
                readUnicode: { calls.append("unicode"); return .text("synthetic") }, onRejection: { rejections.append($0) })
            assertGap(decision, .stale)
            XCTAssertEqual(calls, ["clock"])
            XCTAssertEqual(rejections.count, 1)
            assertClassification(rejections.first, stage: .receive, reason: reason)
        }
    }

    func testPreReadSafetyRejectionDoesNotReadUnicodeOrRunPostReadSafety() {
        var calls: [String] = [], rejection: InputTextReadRejection?
        let decision = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy,
            afterNanoseconds: 0, nowNanoseconds: { calls.append("clock"); return self.nanos },
            safetyProvider: { _ in calls.append("safety"); return nil },
            readUnicode: { calls.append("unicode"); return .text("never-read") }, onRejection: { rejection = $0 })
        assertGap(decision, .stale)
        XCTAssertEqual(calls, ["clock", "safety"])
        assertClassification(rejection, stage: .preReadSafety, reason: .safetyUnavailable)
    }

    func testPreReadApprovalMismatchRetainsOriginalShortCircuitOrder() {
        var calls: [String] = [], rejection: InputTextReadRejection?
        let decision = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy,
            afterNanoseconds: 0, nowNanoseconds: { calls.append("clock"); return self.nanos },
            safetyProvider: { _ in calls.append("safety"); return self.approval(self.context(pid: 43)) },
            readUnicode: { calls.append("unicode"); return .text("never-read") }, onRejection: { rejection = $0 })
        assertGap(decision, .targetMismatch)
        XCTAssertEqual(calls, ["clock", "safety", "clock"])
        assertClassification(rejection, stage: .preReadSafety, reason: .targetPidMismatch)
    }

    func testPostReadSafetyRejectionStillRunsAfterExactlyOneUnicodeRead() {
        var calls: [String] = [], safetyCalls = 0, rejection: InputTextReadRejection?
        let decision = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy,
            afterNanoseconds: 0, nowNanoseconds: { calls.append("clock"); return self.nanos },
            safetyProvider: { _ in
                calls.append("safety"); safetyCalls += 1
                return safetyCalls == 1 ? self.approval() : nil
            }, readUnicode: { calls.append("unicode"); return .text("synthetic") }, onRejection: { rejection = $0 })
        assertGap(decision, .stale)
        XCTAssertEqual(calls, ["clock", "safety", "clock", "clock", "unicode", "clock", "safety"])
        assertClassification(rejection, stage: .postReadSafety, reason: .safetyUnavailable)
    }

    func testPostReadContextAndRoleChangesAreNotReportedAsPermissionFailures() {
        for changeRole in [false, true] {
            var safetyCalls = 0, clocks = 0, reads = 0, rejection: InputTextReadRejection?
            let decision = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy,
                afterNanoseconds: 0, nowNanoseconds: { clocks += 1; return self.nanos },
                safetyProvider: { _ in
                    safetyCalls += 1
                    if safetyCalls == 1 { return self.approval() }
                    return changeRole ? self.approval(role: .textField) : self.approval(self.context(surface: "fixture-other-field"))
                }, readUnicode: { reads += 1; return .text("synthetic") }, onRejection: { rejection = $0 })
            assertGap(decision, changeRole ? .stale : .targetMismatch)
            XCTAssertEqual(safetyCalls, 2); XCTAssertEqual(reads, 1); XCTAssertEqual(clocks, 5)
            assertClassification(rejection, stage: .postReadSafety, reason: changeRole ? .roleChanged : .contextChanged)
        }
    }

    func testAlternateWindowProofIsFreshBeforeAndAfterUnicodeAndCannotAdoptChangedWindow() {
        var currentWindow = 7, proofs = 0, reads = 0
        let decision = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy,
            afterNanoseconds: 0, nowNanoseconds: { self.nanos }, safetyProvider: { _ in
                let route = WindowOwnership.match(expectedWindow: 7, allowTopLevel: true, direct: { .absent },
                    topLevel: { proofs += 1; return .value(currentWindow) }, same: { $0 == $1 },
                    verifyTopLevelWindow: { _ in true }, shouldContinue: { true })
                return route == nil ? nil : self.approval()
            }, readUnicode: { reads += 1; currentWindow = 8; return .text("synthetic") })
        XCTAssertEqual(proofs, 2); XCTAssertEqual(reads, 1)
        assertGap(decision, .stale)
    }

    func testUnicodeFailureIsClassifiedOnlyAfterOriginalPostReadChecks() {
        var calls: [String] = [], rejection: InputTextReadRejection?
        let decision = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy,
            afterNanoseconds: 0, nowNanoseconds: { calls.append("clock"); return self.nanos },
            safetyProvider: { _ in calls.append("safety"); return self.approval() },
            readUnicode: { calls.append("unicode"); return .unavailable }, onRejection: { rejection = $0 })
        assertGap(decision, .readError)
        XCTAssertEqual(calls, ["clock", "safety", "clock", "clock", "unicode", "clock", "safety", "clock", "clock"])
        assertClassification(rejection, stage: .unicodeRead, reason: .unicodeUnavailable)
    }

    func testExactly200msStillAcceptedButOneNanosecondPastClassifiesFinalEventAge() {
        for late in [false, true] {
            var clockCalls = 0, reads = 0, safetyCalls = 0, rejection: InputTextReadRejection?
            let decision = InputTextReadGate.capture(metadata: metadata(), modifiers: [], policy: policy,
                afterNanoseconds: 0, nowNanoseconds: {
                    clockCalls += 1
                    return clockCalls == 6 ? self.nanos + 200_000_000 + (late ? 1 : 0) : self.nanos
                }, safetyProvider: { _ in safetyCalls += 1; return self.approval() },
                readUnicode: { reads += 1; return .text("synthetic") }, onRejection: { rejection = $0 })
            XCTAssertEqual(clockCalls, 6); XCTAssertEqual(reads, 1); XCTAssertEqual(safetyCalls, 2)
            if late {
                assertGap(decision, .verificationTimeout)
                assertClassification(rejection, stage: .postReadSafety, reason: .eventAgeExceeded)
            } else {
                guard case .sample = decision else { return XCTFail("Original inclusive 200ms bound must remain") }
                XCTAssertNil(rejection)
            }
        }
    }

    func testShortcutStillChecksBothSafetyPhasesWithoutUnicodeOrRejection() {
        var clocks = 0, safetyCalls = 0, reads = 0, rejections = 0
        let decision = InputTextReadGate.capture(metadata: metadata(), modifiers: [.command], policy: policy,
            afterNanoseconds: 0, nowNanoseconds: { clocks += 1; return self.nanos },
            safetyProvider: { _ in safetyCalls += 1; return self.approval() },
            readUnicode: { reads += 1; return .text("never-read") }, onRejection: { _ in rejections += 1 })
        guard case .sample(let sample) = decision else { return XCTFail("Expected bounded shortcut evidence") }
        XCTAssertEqual(sample.eventKind, .shortcut); XCTAssertTrue(sample.text.isEmpty)
        XCTAssertEqual(clocks, 6); XCTAssertEqual(safetyCalls, 2); XCTAssertEqual(reads, 0); XCTAssertEqual(rejections, 0)
    }
}

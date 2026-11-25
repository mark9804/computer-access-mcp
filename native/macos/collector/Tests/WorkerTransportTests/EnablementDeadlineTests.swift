import XCTest
import Foundation
import ApplicationServices
import CollectorCore
@testable import computer_history_collector

/// All remote AX functions and the monotonic clock are injected. Only an own-PID
/// application handle is constructed; these tests do not query AX, TCC or input.
final class EnablementDeadlineTests: XCTestCase {
    private final class Fixture {
        var now: Int64 = 100
        var durations: [Int64] = []
        var calls: [String] = []
        var timeouts: [Float] = []
        var receivers: [AXUIElement] = []
        var timeoutError: AXError = .success
        var timeoutCost: Int64 = 0
        var namesError: AXError = .success
        var value = false
        var advertised = ["AXManualAccessibility"]
        func step(_ operation: String, _ receiver: AXUIElement) {
            calls.append(operation); receivers.append(receiver)
            if !durations.isEmpty { now += durations.removeFirst() }
        }
        func provider(hardDeadline: Int64 = 1500) -> NativeAXEnablementProvider {
            var api = NativeAXEnablementProvider.API()
            api.setTimeout = { receiver, seconds in
                self.receivers.append(receiver); self.timeouts.append(seconds); self.now += self.timeoutCost
                return self.timeoutError
            }
            api.names = { receiver, output in
                self.step("names", receiver); output.pointee = self.advertised as CFArray
                return self.namesError
            }
            api.current = { receiver, _, output in
                self.step("current", receiver); output.pointee = self.value ? kCFBooleanTrue : kCFBooleanFalse
                return .success
            }
            api.settable = { receiver, _, output in
                self.step("settable", receiver); output.pointee = DarwinBoolean(true)
                return .success
            }
            api.enable = { receiver, _, value in
                XCTAssertEqual(CFGetTypeID(value), CFBooleanGetTypeID())
                XCTAssertTrue(CFBooleanGetValue((value as! CFBoolean)))
                self.step("enable", receiver); self.value = true
                return .success
            }
            return NativeAXEnablementProvider(pid: ProcessInfo.processInfo.processIdentifier,
                timeoutMs: 1500, hardDeadlineMs: hardDeadline, nowMs: { self.now }, api: api)
        }
    }
    private let policy = CapturePolicy(axCompatibility: true)
    private func acquire(_ provider: NativeAXEnablementProvider, lease: AXEnablementLease = AXEnablementLease()) -> AXEnablementResult {
        lease.acquire(applicationId: "test.allowed", policy: policy, provider: provider)
    }
    private func assertTimeouts(_ actual: [Float], _ milliseconds: [Float], file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(actual.count, milliseconds.count, file: file, line: line)
        for (actual, expected) in zip(actual, milliseconds) {
            XCTAssertGreaterThan(actual, 0, file: file, line: line)
            XCTAssertEqual(actual, expected / 1000, accuracy: 0.000_001, file: file, line: line)
        }
    }

    func testFiveOperationsShareOnePreparationCapAndExactReceiver() {
        let f = Fixture(); f.durations = [10, 20, 15, 5, 10]
        let provider = f.provider(), lease = AXEnablementLease()
        XCTAssertTrue(f.timeouts.isEmpty, "Initialization must not install an unrelated whole-read timeout")
        XCTAssertEqual(acquire(provider, lease: lease), .init(status: .enabled, attribute: .manual, changed: true))
        XCTAssertEqual(f.calls, ["names", "current", "settable", "enable", "current"])
        assertTimeouts(f.timeouts, [100, 90, 70, 55, 50])
        XCTAssertTrue(f.receivers.allSatisfy { CFEqual($0, provider.application) })
        let calls = f.calls
        _ = acquire(provider, lease: lease); lease.release()
        XCTAssertEqual(f.calls, calls, "No write retry or automatic restoration")
    }

    func testRecoveryCompatibilityIsReadOnlyEvenWhenOriginalIsFalse() {
        let f = Fixture(), lease = AXEnablementLease()
        let result = lease.acquire(applicationId: "test.allowed", policy: policy, provider: f.provider(), allowWrite: false)
        XCTAssertEqual(result, .init(status: .denied, attribute: .manual))
        XCTAssertEqual(f.calls, ["names", "current"])
        XCTAssertFalse(f.value)
    }

    func testCapExhaustedByNamesIsUnknownAndNeverWritesOrTriesEnhanced() {
        let f = Fixture(); f.durations = [100]
        let result = acquire(f.provider())
        XCTAssertEqual(result.status, .originalUnknown)
        XCTAssertEqual(f.calls, ["names"])
        assertTimeouts(f.timeouts, [100])
    }

    func testHardDeadlineShortensTheEntirePreparationCap() {
        let f = Fixture(); f.durations = [5, 5, 5, 5, 5]
        XCTAssertEqual(acquire(f.provider(hardDeadline: 135)).status, .enabled)
        assertTimeouts(f.timeouts, [35, 30, 25, 20, 15])
        XCTAssertEqual(f.now, 125)
    }

    func testExpiredDeadlineAndTimeoutConfigurationFailureNeverCallAXOrClaimUnsupported() {
        let expired = Fixture()
        XCTAssertEqual(acquire(expired.provider(hardDeadline: 100)).status, .originalUnknown)
        XCTAssertTrue(expired.calls.isEmpty); XCTAssertTrue(expired.timeouts.isEmpty)
        let failed = Fixture(); failed.timeoutError = .cannotComplete
        XCTAssertEqual(acquire(failed.provider()).status, .originalUnknown)
        XCTAssertTrue(failed.calls.isEmpty)
        assertTimeouts(failed.timeouts, [100])
        let slow = Fixture(); slow.timeoutCost = 100
        XCTAssertEqual(acquire(slow.provider()).status, .originalUnknown)
        XCTAssertTrue(slow.calls.isEmpty, "The clock is rechecked after timeout setup")
    }

    func testExpiryDuringOriginalOrSettableReadNeverStartsTheWrite() {
        let original = Fixture(); original.durations = [10, 90]
        XCTAssertEqual(acquire(original.provider()).status, .originalUnknown)
        XCTAssertEqual(original.calls, ["names", "current"])
        let settable = Fixture(); settable.durations = [10, 10, 80]
        XCTAssertEqual(acquire(settable.provider()).status, .notSettable)
        XCTAssertEqual(settable.calls, ["names", "current", "settable"])
    }

    func testLateSuccessfulWriteOrReadbackIsNotVerifiedAndNeverRetried() {
        for durations: [Int64] in [[1, 1, 1, 97], [1, 1, 1, 1, 96]] {
            let f = Fixture(); f.durations = durations
            let provider = f.provider(), lease = AXEnablementLease()
            let result = acquire(provider, lease: lease)
            XCTAssertEqual(result, .init(status: .writeFailed, attribute: .manual, changed: true))
            XCTAssertEqual(f.calls.filter { $0 == "enable" }.count, 1)
            XCTAssertEqual(f.calls.count, durations.count)
            let calls = f.calls; _ = acquire(provider, lease: lease)
            XCTAssertEqual(f.calls, calls)
        }
    }

    func testOnlySuccessfulCapabilityAbsenceIsUnsupportedAndReadFailureIsNotRetried() {
        let absent = Fixture(); absent.advertised = []
        XCTAssertEqual(acquire(absent.provider()).status, .unsupported)
        XCTAssertEqual(absent.calls, ["names"])
        let failed = Fixture(); failed.namesError = .cannotComplete
        XCTAssertEqual(acquire(failed.provider()).status, .originalUnknown)
        XCTAssertEqual(failed.calls, ["names"])
    }
}

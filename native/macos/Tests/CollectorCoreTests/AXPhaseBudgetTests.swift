import Foundation
import XCTest
@testable import CollectorCore

final class AXPhaseBudgetTests: XCTestCase {
    func testOptionalBudgetReservesFinalValidationWithoutExtendingHardDeadline() {
        XCTAssertEqual(AXPhaseBudget.optionalDeadline(nowMs: 100, hardDeadlineMs: 1_500), 1_150)
        XCTAssertEqual(AXPhaseBudget.optionalDeadline(nowMs: 1_000, hardDeadlineMs: 1_500), 1_250)
        XCTAssertEqual(AXPhaseBudget.optionalDeadline(nowMs: 1_100, hardDeadlineMs: 1_500), 1_300)
        XCTAssertNil(AXPhaseBudget.optionalDeadline(nowMs: 1_102, hardDeadlineMs: 1_500))
        XCTAssertNil(AXPhaseBudget.optionalDeadline(nowMs: 1_500, hardDeadlineMs: 1_500))
        XCTAssertNil(AXPhaseBudget.optionalDeadline(nowMs: 1_501, hardDeadlineMs: 1_500))
        XCTAssertNil(AXPhaseBudget.optionalDeadline(nowMs: -1, hardDeadlineMs: Int64.max))
        XCTAssertEqual(AXPhaseBudget.optionalDeadline(nowMs: 0, hardDeadlineMs: Int64.max), Int64.max - 350)
    }

    func testMessagingTimeoutClampsEachPhaseAndRestoresHardBudget() throws {
        let hard: Int64 = 1_500
        let soft = try XCTUnwrap(AXPhaseBudget.optionalDeadline(nowMs: 100, hardDeadlineMs: hard))
        XCTAssertEqual(AXPhaseBudget.messagingTimeout(configuredSeconds: 1.5, nowMs: 1_100, deadlineMs: soft), 0.05)
        XCTAssertNil(AXPhaseBudget.messagingTimeout(configuredSeconds: 1.5, nowMs: soft, deadlineMs: soft))
        XCTAssertEqual(AXPhaseBudget.messagingTimeout(configuredSeconds: 1.5, nowMs: soft, deadlineMs: hard), 0.35)
        XCTAssertNil(AXPhaseBudget.messagingTimeout(configuredSeconds: 1.5, nowMs: hard, deadlineMs: hard))
        XCTAssertNil(AXPhaseBudget.messagingTimeout(configuredSeconds: 1.5, nowMs: hard + 1, deadlineMs: hard))
    }

    func testMessagingTimeoutIsFinitePositiveAndNeverUsesZeroDefault() {
        XCTAssertEqual(AXPhaseBudget.messagingTimeout(configuredSeconds: 1.5, nowMs: 100, deadlineMs: Int64.max), 1.5)
        XCTAssertEqual(AXPhaseBudget.messagingTimeout(configuredSeconds: 0.1, nowMs: 100, deadlineMs: 1_000), 0.1)
        XCTAssertEqual(AXPhaseBudget.messagingTimeout(configuredSeconds: 1.5, nowMs: 999, deadlineMs: 1_000), 0.001)
        for invalid: Float in [0, -1, 0.0001, .infinity, .nan] {
            XCTAssertNil(AXPhaseBudget.messagingTimeout(configuredSeconds: invalid, nowMs: 100, deadlineMs: 1_000))
        }
    }

    func testObserverRebindSharesFixedDeadlineAndNeverStartsLateOrAfterTimeoutSetupFailure() throws {
        let deadline = try XCTUnwrap(AXPhaseBudget.observerDeadline(nowMs: 100, hardDeadlineMs: 1500, phaseDeadlineMs: 1150))
        XCTAssertEqual(deadline, 200)
        XCTAssertEqual(AXPhaseBudget.observerDeadline(nowMs: 100, hardDeadlineMs: 1500, phaseDeadlineMs: 150), 150)
        XCTAssertNil(AXPhaseBudget.observerDeadline(nowMs: 1102, hardDeadlineMs: 1500, phaseDeadlineMs: 1500))
        var now: Int64 = 100, calls = 0, timeouts: [Float] = []
        func attempt() -> Bool {
            AXPhaseBudget.observerCall(
                nowMs: { now },
                deadlineMs: deadline,
                setTimeout: { timeouts.append($0); return true },
                perform: { calls += 1; now += 60; return true }
            )
        }
        XCTAssertTrue(attempt())
        XCTAssertTrue(attempt())
        XCTAssertFalse(attempt())
        XCTAssertEqual(calls, 2)
        XCTAssertEqual(timeouts.count, 2)
        XCTAssertEqual(timeouts[0], 0.1)
        XCTAssertEqual(timeouts[1], 0.04)
        now = 199
        XCTAssertFalse(AXPhaseBudget.observerCall(
            nowMs: { now },
            deadlineMs: deadline,
            setTimeout: { _ in now = deadline; return true },
            perform: { calls += 1; return true }
        ))
        now = 100
        XCTAssertFalse(AXPhaseBudget.observerCall(
            nowMs: { now },
            deadlineMs: deadline,
            setTimeout: { _ in false },
            perform: { calls += 1; return true }
        ))
        XCTAssertEqual(calls, 2)
    }
}

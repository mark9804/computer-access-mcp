import Foundation
import XCTest
import AccessContract
@testable import CollectorCore

final class InputGapDiagnosticTests: XCTestCase {
    private func run(inputText: Bool, gaps: [String]) throws -> [JSONValue] {
        let h = Harness(fixture: false)
        let policy = CapturePolicy(inputText: inputText)
        h.engine.receive(.object(["protocolVersion": j(1), "type": .string("configure"), "requestId": .string("config"), "ownerId": .string("owner"), "instanceId": .string("instance"), "policyRevision": j(1), "policy": try JSONValue.parse(JSONEncoder().encode(policy))]))
        h.control("start", lease: 30_000); h.clock.advance(51); h.engine.tick()
        var result = h.goodResult(try XCTUnwrap(h.env.launched.last))
        result.inputGaps = gaps
        h.engine.complete(result)
        let validator = try ContractValidator()
        for frame in h.frames { XCTAssertNoThrow(try validator.encodeFrame(frame)) }
        return h.frames
    }
    func testActualEngineLabelsEveryInputGapWithoutSuppressingFocusedText() throws {
        let cases: [(InputTextGapReason, String, String)] = [
            (.stale, "stale", "input-context-unverified"),
            (.targetMismatch, "stale", "input-target-mismatch"),
            (.roleNotEditable, "stale", "input-role-not-editable"),
            (.verificationTimeout, "stale", "input-verification-timeout"),
            (.fieldSecurityUnknown, "stale", "input-field-security-unknown"),
            (.budget, "budget", "input-text-budget"),
            (.backpressure, "backpressure", "input-text-backpressure"),
            (.readError, "read-error", "input-text-read-unavailable"),
            (.policyBoundary, "policy-boundary", "input-policy-boundary")
        ]
        for (reason, coarse, code) in cases {
            let frames = try run(inputText: true, gaps: [reason.rawValue])
            let gaps = frames.filter { $0["payload"]?["kind"] == .string("gap") }
            XCTAssertEqual(gaps.count, 1)
            XCTAssertEqual(gaps.first?["payload"]?["reason"], .string(coarse))
            XCTAssertEqual(gaps.first?["payload"]?["diagnostic"], .object(["code": .string(code)]))
            XCTAssertEqual(gaps.first?["payload"]?["providerApplicationId"], .string("test.allowed"))
            XCTAssertTrue(frames.contains { $0["payload"]?["kind"] == .string("text.snapshot") })
        }
    }
    func testUnknownInputReasonsNeverReachWireAndDisabledChannelCannotClaimGaps() throws {
        let frames = try run(inputText: true, gaps: ["PRIVATE_INPUT", "stale", "not-a-gap"])
        let gaps = frames.filter { $0["payload"]?["kind"] == .string("gap") }
        XCTAssertEqual(gaps.count, 1)
        for frame in frames { XCTAssertFalse(String(decoding: try frame.canonicalData(), as: UTF8.self).contains("PRIVATE_INPUT")) }
        let disabled = try run(inputText: false, gaps: ["stale", InputTextGapReason.targetMismatch.rawValue,
            InputTextGapReason.roleNotEditable.rawValue, InputTextGapReason.fieldSecurityUnknown.rawValue])
        XCTAssertFalse(disabled.contains { $0["payload"]?["kind"] == .string("gap") })
    }
    func testInputGapCountRemainsBounded() throws {
        let frames = try run(inputText: true, gaps: Array(repeating: "stale", count: 20))
        XCTAssertEqual(frames.filter { $0["payload"]?["kind"] == .string("gap") }.count, 4)
    }
}

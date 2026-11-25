import Foundation
import XCTest
@testable import HistoryContract

final class InputActivityTests: XCTestCase {
    private var validator: ContractValidator!

    override func setUpWithError() throws { validator = try ContractValidator() }

    func testAdditivePolicyLeavesLegacyAbsentAndSupportsExplicitOptIn() throws {
        let legacy = configure()
        XCTAssertEqual(ContractLimits.protocolVersion, 1)
        XCTAssertEqual(try validator.validateMessage(legacy), legacy)
        XCTAssertNil(try validator.decodeFrame(validator.encodeFrame(legacy))["policy"]?["inputActivity"])
        for enabled in [false, true] {
            let message = replacing(legacy, path: ["policy", "inputActivity"], with: .bool(enabled))
            XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(message)), message)
        }
        for value: JSONValue in [.null, .number(1), .string("true")] {
            assertInvalid(replacing(legacy, path: ["policy", "inputActivity"], with: value))
        }
    }

    func testApplicationActivityRoundtripsWithoutWindowsOrRawInput() throws {
        for source in ["fixture", "cg.listen-only"] {
            let message = inputActivity(source: source)
            XCTAssertEqual(try validator.validateMessage(message), message)
            XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(message)), message)
            XCTAssertNil(message["target"]?["identity"]?["windowId"])
            XCTAssertEqual(message["target"]?["identity"]?.objectValue?.count, 6)
        }
        var cap = inputActivity()
        cap = replacing(cap, path: ["payload", "counts", "pointerReleases"], with: .number(256))
        cap = replacing(cap, path: ["payload", "coverage", "truncated"], with: .bool(true))
        XCTAssertEqual(try validator.validateMessage(cap), cap)
    }

    func testGateRequiredForBothSourcesWithoutFixtureBypass() {
        for source in ["fixture", "cg.listen-only"] {
            let message = inputActivity(source: source)
            for path in [["payload", "gate"], ["payload", "gate", "policyRevision"], ["payload", "gate", "secureInput"], ["payload", "gate", "targetAttribution"], ["payload", "gate", "detail"]] {
                assertInvalid(replacing(message, path: path, with: nil))
            }
            assertInvalid(replacing(message, path: ["payload", "gate", "policyRevision"], with: .number(2)))
            assertInvalid(replacing(message, path: ["payload", "gate", "secureInput"], with: .string("unknown")))
            assertInvalid(replacing(message, path: ["payload", "gate", "targetAttribution"], with: .string("foreground-pid")))
            assertInvalid(replacing(message, path: ["payload", "gate", "detail"], with: .string("raw-events")))
        }
    }

    func testTimeCountCoverageAndActorSemanticsFailClosed() {
        let message = inputActivity()
        for (path, value): ([String], JSONValue) in [
            (["payload", "intervalStartMs"], .number(1001)),
            (["payload", "intervalEndMs"], .number(2001)),
            (["eventTimeMs"], .number(1000)),
            (["payload", "counts", "pointerReleases"], .number(0)),
            (["payload", "counts", "pointerReleases"], .number(257)),
            (["payload", "counts", "pointerReleases"], .number(1.5)),
            (["payload", "counts", "pointerReleases"], .bool(true)),
            (["payload", "counts", "scrollSamples"], .number(256)),
            (["payload", "coverage", "status"], .string("complete")),
            (["payload", "coverage", "status"], .string("unknown")),
            (["payload", "coverage", "missingReasons"], .array([])),
            (["actor"], .string("user-estimated")),
            (["actor"], .string("agent")),
            (["relatedActionIds"], .array([.string("synthetic-action")])),
        ] {
            assertInvalid(replacing(message, path: path, with: value))
        }
    }

    func testApplicationIdentityCannotBeUsedForExistingPayloads() {
        let message = inputActivity()
        for payload in [
            snapshot(),
            JSONValue.object(["kind": .string("text.changed"), "baseSnapshotId": .string("before"), "after": snapshot()]),
            JSONValue.object(["kind": .string("gap"), "reason": .string("stale"), "count": .number(1)]),
            JSONValue.object(["kind": .string("context.changed"), "reason": .string("application")]),
        ] {
            assertInvalid(replacing(message, path: ["payload"], with: payload))
        }
        assertInvalid(replacing(message, path: ["target"], with: observation()["target"]))
        assertInvalid(replacing(message, path: ["target"], with: .object(["kind": .string("unresolved"), "reason": .string("not-observed")])))
    }

    func testRequiredFieldsAndClosedObjectsRejectSensitiveDetails() {
        let message = inputActivity()
        for path in [["target"], ["target", "identity"], ["payload"], ["payload", "counts"], ["payload", "gate"], ["payload", "coverage"]] {
            assertInvalid(replacing(message, path: path + ["unknown"], with: .string("synthetic-only")))
        }
        for path in [["target", "identity", "processStartTime"], ["payload", "intervalStartMs"], ["payload", "counts", "dragSamples"], ["payload", "coverage", "missingReasons"]] {
            assertInvalid(replacing(message, path: path, with: nil))
        }
        for field in ["keycodes", "chars", "modifiers", "coords", "URLs", "windows"] {
            assertInvalid(replacing(message, path: ["payload", field], with: .string("synthetic-only")))
        }
        assertInvalid(replacing(message, path: ["target", "identity", "windowId"], with: .string("synthetic-window")))
        assertInvalid(replacing(message, path: ["target", "identity", "windowGeneration"], with: .number(1)))
    }

    private func inputActivity(source: String = "fixture") -> JSONValue {
        let identity = replacing(replacing(targetIdentity(), path: ["windowId"], with: nil), path: ["windowGeneration"], with: nil)
        let payload = JSONValue.object([
            "kind": .string("input.activity"), "source": .string(source), "scope": .string("application"),
            "intervalStartMs": .number(1000), "intervalEndMs": .number(2000),
            "counts": .object(["pointerReleases": .number(1), "dragSamples": .number(0), "scrollSamples": .number(0), "shortcutPresses": .number(0)]),
            "gate": .object(["policyRevision": .number(1), "secureInput": .string("inactive"), "targetAttribution": .string("event-target-pid"), "detail": .string("coarse-counts")]),
            "coverage": coverage(status: "partial", reasons: ["input-events-partial", "application-only", "effect-unverified"]),
        ])
        let message = replacing(observation(payload: payload), path: ["target"], with: .object(["kind": .string("application"), "identity": identity]))
        return replacing(message, path: ["eventTimeMs"], with: .number(2000))
    }

    private func assertInvalid(_ value: JSONValue, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try validator.validateMessage(value), file: file, line: line) { error in
            XCTAssertEqual(error as? ProtocolError, .invalidMessage, file: file, line: line)
        }
    }
}

import Foundation
import XCTest
@testable import AccessContract

final class MenuActionTests: XCTestCase {
    private var validator: ContractValidator!

    override func setUpWithError() throws { validator = try ContractValidator() }

    func testAdditivePolicyLeavesLegacyAbsentAndSupportsExplicitOptIn() throws {
        let legacy = configure()
        XCTAssertEqual(try validator.validateMessage(legacy), legacy)
        XCTAssertNil(try validator.decodeFrame(validator.encodeFrame(legacy))["policy"]?["menuActions"])
        for enabled in [false, true] {
            let message = replacing(legacy, path: ["policy", "menuActions"], with: .bool(enabled))
            XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(message)), message)
        }
        for value: JSONValue in [.null, .number(1), .string("true")] {
            assertInvalid(replacing(legacy, path: ["policy", "menuActions"], with: value))
        }
        let capability = JSONValue.object([
            "name": .string("menu.action"), "direction": .string("observe"),
            "scope": .string("app-local"), "support": .string("supported"), "reason": .string("synthetic-only"),
        ])
        let withCapability = replacing(hello(), path: ["capabilities"], with: .array([capability]))
        XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(withCapability)), withCapability)
    }

    func testValidMenuActionsRoundtripAndRespectUTF16Budget() throws {
        for source in ["fixture", "ax.menu"] {
            let message = menuAction(source: source, path: ["File", "Save"])
            XCTAssertEqual(try validator.validateMessage(message), message)
            XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(message)), message)
        }
        let truncated = menuAction(source: "ax.menu", path: ["File", "Export", "PDF..."], truncated: true)
        XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(truncated)), truncated)

        let depth8 = menuAction(source: "ax.menu", path: ["L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8"])
        XCTAssertEqual(try validator.validateMessage(depth8), depth8)

        // Supplementary scalar U+1D11E occupies 2 UTF-16 code units; 4 * 64 = 512 UTF-16 code units.
        let segment = String(repeating: "\u{1D11E}", count: 64)
        let exactBudget = menuAction(source: "ax.menu", path: [segment, segment, segment, segment])
        XCTAssertEqual(try validator.validateMessage(exactBudget), exactBudget)
    }

    func testPathConstraintsRejectShortDeepBlankControlAndOverBudget() {
        let base = menuAction()
        let pair = "\u{1D11E}"
        let invalidPaths: [[String]] = [
            [],
            ["File"],
            ["L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9"],
            ["File", ""],
            ["File", "   "],
            ["File", "\u{00A0}\u{3000}\u{FEFF}"],
            ["File", "Save\nAs"],
            ["File", "Save\rAs"],
            ["File", "Save\tAs"],
            ["File", "Save\u{0000}As"],
            ["File", "Save\u{007F}As"],
            ["File", "Save\u{0085}As"],
            ["File", "Save\u{009F}As"],
            ["File", String(repeating: pair, count: 65)],
            [String(repeating: pair, count: 64), String(repeating: pair, count: 64), String(repeating: pair, count: 64), String(repeating: pair, count: 64), "a"],
        ]
        for path in invalidPaths {
            assertInvalid(replacing(base, path: ["payload", "path"], with: .array(path.map(JSONValue.string))))
        }
    }

    func testTargetRelationTimeCoverageGateAndLiteralsFailClosed() {
        let base = menuAction()
        assertInvalid(replacing(base, path: ["target"], with: observation()["target"]))
        assertInvalid(replacing(base, path: ["target"], with: .object(["kind": .string("unresolved"), "reason": .string("focus-unavailable")])))
        assertInvalid(replacing(base, path: ["target", "identity", "windowId"], with: .string("window")))
        assertInvalid(replacing(base, path: ["relation"], with: .object(["basis": .string("temporal-same-surface"), "evidenceIds": .array([.string("earlier:1")]), "effect": .string("unverified")])))
        assertInvalid(replacing(base, path: ["actor"], with: .string("user-estimated")))
        assertInvalid(replacing(base, path: ["relatedActionIds"], with: .array([.string("action-1")])))
        assertInvalid(replacing(base, path: ["eventTimeMs"], with: .number(2501)))

        assertInvalid(replacing(base, path: ["payload", "coverage"], with: coverage(status: "complete", truncated: false, reasons: [])))
        assertInvalid(replacing(base, path: ["payload", "coverage", "status"], with: .string("unknown")))
        assertInvalid(replacing(base, path: ["payload", "coverage", "missingReasons"], with: .array([.string("effect-unverified")])))
        assertInvalid(replacing(base, path: ["payload", "coverage", "missingReasons"], with: .array([.string("menu-bar-only")])))
        assertInvalid(replacing(base, path: ["payload", "coverage", "truncated"], with: .bool(true)))
        assertInvalid(replacing(base, path: ["payload", "coverage", "missingReasons"], with: .array([.string("menu-bar-only"), .string("effect-unverified"), .string("menu-title-truncated")])))

        assertInvalid(replacing(base, path: ["payload", "gate"], with: nil))
        assertInvalid(replacing(base, path: ["payload", "gate", "secure"], with: .string("sensitive")))
        assertInvalid(replacing(base, path: ["payload", "gate", "secure"], with: .string("unknown")))
        assertInvalid(replacing(base, path: ["payload", "gate", "privateState"], with: .string("private")))
        assertInvalid(replacing(base, path: ["payload", "gate", "privateState"], with: .string("unknown")))
        assertInvalid(replacing(base, path: ["payload", "gate", "policyRevision"], with: .number(2)))

        assertInvalid(replacing(base, path: ["payload", "source"], with: .string("cg.listen-only")))
        assertInvalid(replacing(base, path: ["payload", "scope"], with: .string("application")))
        assertInvalid(replacing(base, path: ["payload", "secureInput"], with: .string("active")))
        assertInvalid(replacing(base, path: ["payload", "effect"], with: .string("confirmed")))
        assertInvalid(replacing(base, path: ["payload", "coords"], with: .object(["x": .number(1), "y": .number(2)])))
    }

    private func menuAction(source: String = "fixture", path: [String] = ["File", "Save"], truncated: Bool = false) -> JSONValue {
        let identity = replacing(replacing(targetIdentity(), path: ["windowId"], with: nil), path: ["windowGeneration"], with: nil)
        var reasons = ["menu-bar-only", "effect-unverified"]
        if truncated { reasons.append("menu-title-truncated") }
        let payload = JSONValue.object([
            "kind": .string("menu.action"),
            "source": .string(source),
            "scope": .string("menu-bar"),
            "path": .array(path.map(JSONValue.string)),
            "observedAtMs": .number(2500),
            "gate": .object(["secure": .string("safe"), "privateState": .string("normal"), "policyRevision": .number(1)]),
            "secureInput": .string("inactive"),
            "coverage": coverage(status: "partial", truncated: truncated, reasons: reasons),
            "effect": .string("unverified"),
        ])
        let message = replacing(observation(payload: payload), path: ["target"], with: .object(["kind": .string("application"), "identity": identity]))
        return replacing(message, path: ["eventTimeMs"], with: .number(2500))
    }

    private func assertInvalid(_ value: JSONValue, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try validator.validateMessage(value), file: file, line: line) { error in
            XCTAssertEqual(error as? ProtocolError, .invalidMessage, file: file, line: line)
        }
    }
}

import Foundation
import XCTest
@testable import AccessContract

final class TextRangeTests: XCTestCase {
    private var validator: ContractValidator!

    override func setUpWithError() throws { validator = try ContractValidator() }

    func testAdditivePolicyDefaultsDoNotMigrateLegacyMessages() throws {
        let legacy = configure()
        XCTAssertEqual(ContractLimits.protocolVersion, 1)
        XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(legacy)), legacy)
        XCTAssertNil(legacy["policy"]?["textRange"])
        XCTAssertNil(legacy["policy"]?["sampleIntervalMs"])
        for basis in ["prefix", "visible"] {
            for interval in [1000, 1001, 30000] as [Double] {
                let value = replacing(replacing(legacy, path: ["policy", "textRange"], with: .string(basis)), path: ["policy", "sampleIntervalMs"], with: .number(interval))
                XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(value)), value)
            }
        }
    }

    func testPolicyTypesBoundsClosedFieldsAndDebounceRemainStrict() {
        for value: JSONValue in [.null, .bool(true), .number(1), .string("all"), .object([:]), .array([])] {
            assertInvalid(replacing(configure(), path: ["policy", "textRange"], with: value))
        }
        for value: JSONValue in [.null, .bool(false), .string("1000"), .number(999), .number(1000.5), .number(30001), .number(.infinity), .number(.nan)] {
            assertInvalid(replacing(configure(), path: ["policy", "sampleIntervalMs"], with: value))
        }
        assertInvalid(replacing(configure(), path: ["policy", "enabled"], with: .number(1)))
        assertInvalid(replacing(configure(), path: ["policy", "inputActivity"], with: .number(1)))
        assertInvalid(replacing(configure(), path: ["policy", "maxWaitMs"], with: .number(1)))
        assertInvalid(replacing(configure(), path: ["policy", "visible"], with: .bool(true)))
    }

    func testVisibleRangeCapabilityIsAdditive() throws {
        let capability = JSONValue.object(["name": .string("text.visible-range"), "direction": .string("observe"), "scope": .string("app-local"), "support": .string("supported"), "reason": .string("synthetic-only")])
        let value = replacing(hello(), path: ["capabilities"], with: .array([capability]))
        XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(value)), value)
    }

    func testOmittedBasisPreservesLegacyNonzeroAccessibleRange() throws {
        var value = replacing(visible(), path: ["payload", "rangeBasis"], with: nil)
        value = replacing(value, path: ["payload", "coverage"], with: coverage())
        value = replacing(value, path: ["payload", "selection"], with: textRange(start: 30, length: 1))
        XCTAssertEqual(try validator.validateMessage(value), value)
        assertInvalid(replacing(value, path: ["payload", "rangeBasis"], with: .string("prefix")))
        let prefix = replacing(observation(), path: ["payload", "rangeBasis"], with: .string("prefix"))
        XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(prefix)), prefix)
    }

    func testVisibleFixtureAndNativeRangeRoundtripUTF16() throws {
        for text in ["可见🙂", "🙂", "👩🏽‍💻", "e\u{301}", "中\n文", "\u{0}"] {
            let value = visible(text: text)
            XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(value)), value)
        }
        let native = nativeVisible()
        XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(native)), native)
        let all = visible(text: "🙂", start: 0, total: 2)
        XCTAssertEqual(try validator.validateMessage(all), all)
        XCTAssertEqual(all["payload"]?["coverage"]?["status"], .string("partial"))
    }

    func testVisibleSourceScopeReadAndGateAreRequired() {
        for source in ["ax.value", "uia.value", "uia.text"] {
            assertInvalid(replacing(nativeVisible(), path: ["payload", "source"], with: .string(source)))
        }
        assertInvalid(replacing(nativeVisible(), path: ["payload", "gate"], with: nil))
        assertInvalid(replacing(nativeVisible(), path: ["payload", "gate", "policyRevision"], with: .number(2)))
        assertInvalid(replacing(nativeVisible(), path: ["payload", "gate", "secure"], with: .string("unknown")))
        assertInvalid(replacing(visible(), path: ["payload", "scope"], with: .string("field")))
        for state in ["unavailable", "redacted"] {
            var value = replacing(visible(), path: ["payload", "valueState"], with: .string(state))
            for field in ["text", "range", "totalLength"] { value = replacing(value, path: ["payload", field], with: nil) }
            assertInvalid(value)
        }
    }

    func testVisibleCoverageMustRemainPartialWithSpecificReason() throws {
        assertInvalid(replacing(visible(), path: ["payload", "coverage"], with: coverage()))
        assertInvalid(replacing(visible(), path: ["payload", "coverage", "status"], with: .string("unknown")))
        assertInvalid(replacing(visible(), path: ["payload", "coverage", "missingReasons"], with: .array([])))
        assertInvalid(replacing(visible(), path: ["payload", "coverage", "missingReasons"], with: .array([.string("text-budget")])))
        let value = replacing(visible(), path: ["payload", "coverage"], with: coverage(status: "partial", truncated: true, reasons: ["visible-range-only", "text-budget"]))
        XCTAssertEqual(try validator.validateMessage(value), value)
    }

    func testOnlyZeroTotalCanProduceEmptyVisibleRead() throws {
        let empty = visible(text: "", start: 0, total: 0)
        XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(empty)), empty)
        XCTAssertNoThrow(try validator.validateMessage(replacing(empty, path: ["payload", "selection"], with: textRange())))
        assertInvalid(visible(text: "", start: 0, total: 1))
        assertInvalid(visible(text: "", start: 40, total: 40))
        assertInvalid(visible(text: "", start: 1, total: 0))
    }

    func testVisibleRequiredFieldsNumericBoundsAndSums() throws {
        for field in ["text", "range", "totalLength"] { assertInvalid(replacing(visible(), path: ["payload", field], with: nil)) }
        for field in ["start", "length", "unit"] { assertInvalid(replacing(visible(), path: ["payload", "range", field], with: nil)) }
        for value: JSONValue in [.number(-1), .number(10.5), .bool(true), .number(ContractLimits.maxSafeInteger + 1)] {
            assertInvalid(replacing(visible(), path: ["payload", "range", "start"], with: value))
        }
        assertInvalid(replacing(visible(), path: ["payload", "totalLength"], with: .bool(true)))
        assertInvalid(replacing(visible(), path: ["payload", "totalLength"], with: .number(13)))
        assertInvalid(replacing(visible(), path: ["payload", "range", "length"], with: .number(3)))
        assertInvalid(replacing(visible(), path: ["payload", "range", "unit"], with: .string("codepoint")))
        let largest = visible(start: ContractLimits.maxSafeInteger - 4, total: ContractLimits.maxSafeInteger)
        XCTAssertNoThrow(try validator.validateMessage(largest))
        assertInvalid(replacing(largest, path: ["payload", "range", "start"], with: .number(ContractLimits.maxSafeInteger - 3)))
        for start in [0, 100, ContractLimits.maxSafeInteger - 8192] {
            for length in [1, 2, 17, 8192] {
                let value = visible(text: String(repeating: "x", count: length), start: start, total: start + Double(length))
                XCTAssertNoThrow(try validator.validateMessage(value))
                assertInvalid(replacing(value, path: ["payload", "totalLength"], with: .number(start + Double(length) - 1)))
            }
        }
    }

    func testVisibleSelectionMustFitAbsoluteCapturedUTF16Range() throws {
        for selection in [textRange(start: 10), textRange(start: 10, length: 4), textRange(start: 12, length: 2), textRange(start: 14)] {
            XCTAssertNoThrow(try validator.validateMessage(replacing(visible(), path: ["payload", "selection"], with: selection)))
        }
        for selection in [textRange(start: 0), textRange(start: 9, length: 1), textRange(start: 14, length: 1), textRange(start: 15), textRange(start: 11, length: 4), textRange(start: ContractLimits.maxSafeInteger, length: 1)] {
            assertInvalid(replacing(visible(), path: ["payload", "selection"], with: selection))
        }
        let maximum = replacing(visible(text: String(repeating: "🙂", count: 4096), start: 100, total: 8292), path: ["payload", "selection"], with: textRange(start: 100, length: 8192))
        XCTAssertNoThrow(try validator.validateMessage(maximum))
        assertInvalid(replacing(maximum, path: ["payload", "selection", "length"], with: .number(8193)))
        var legacy = replacing(visible(), path: ["payload", "rangeBasis"], with: nil)
        legacy = replacing(legacy, path: ["payload", "totalLength"], with: .number(10000))
        assertInvalid(replacing(legacy, path: ["payload", "selection"], with: textRange(length: 8193)))
    }

    func testVisibleMalformedSurrogatesAndClosedFields() throws {
        let value = visible(text: "TOKEN")
        let json = String(decoding: try value.canonicalData(), as: UTF8.self)
        for surrogate in [#"\ud800"#, #"\udc00"#] {
            XCTAssertThrowsError(try validator.decodeFrame(Data(json.replacingOccurrences(of: "TOKEN", with: surrogate).utf8))) { error in
                XCTAssertEqual(error as? ProtocolError, .invalidMessage)
            }
        }
        for path in [["payload"], ["payload", "range"], ["payload", "coverage"]] {
            assertInvalid(replacing(visible(), path: path + ["unknown"], with: .string("synthetic-only")))
        }
        assertInvalid(visible(text: String(repeating: "🙂", count: 4097), total: 10000))
    }

    func testVisibleTextChangedUsesIdenticalValidation() throws {
        let after = visible()["payload"]!
        let value = observation(payload: .object(["kind": .string("text.changed"), "baseSnapshotId": .string("before"), "after": after]))
        XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(value)), value)
        assertInvalid(replacing(value, path: ["payload", "after", "totalLength"], with: .number(13)))
    }

    private func visible(text: String = "可见🙂", start: Double = 10, total: Double = 40) -> JSONValue {
        var payload = snapshot(text: text)
        payload = replacing(payload, path: ["rangeBasis"], with: .string("visible"))
        payload = replacing(payload, path: ["scope"], with: .string("accessible-range"))
        payload = replacing(payload, path: ["range"], with: textRange(start: start, length: Double(text.utf16.count)))
        payload = replacing(payload, path: ["totalLength"], with: .number(total))
        payload = replacing(payload, path: ["coverage"], with: coverage(status: "partial", reasons: ["visible-range-only"]))
        return observation(payload: payload)
    }

    private func nativeVisible() -> JSONValue {
        let value = replacing(visible(), path: ["payload", "source"], with: .string("ax.range"))
        return replacing(value, path: ["payload", "gate"], with: .object(["secure": .string("safe"), "privateState": .string("normal"), "policyRevision": .number(1)]))
    }

    private func assertInvalid(_ value: JSONValue, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try validator.validateMessage(value), file: file, line: line) { error in
            XCTAssertEqual(error as? ProtocolError, .invalidMessage, file: file, line: line)
        }
    }
}

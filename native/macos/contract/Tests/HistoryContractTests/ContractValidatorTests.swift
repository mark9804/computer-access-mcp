import Foundation
import XCTest
@testable import HistoryContract

final class ContractValidatorTests: XCTestCase {
    private var validator: ContractValidator!

    override func setUpWithError() throws { validator = try ContractValidator() }

    func testAllTopLevelBranchesAndActions() throws {
        let fixtures: [JSONValue] = [
            hello(), configure(), configured(),
            control(), state(), observation(),
            observation(payload: .object(["kind": .string("gap"), "reason": .string("timeout"), "count": .number(1)])),
            observation(payload: .object(["kind": .string("context.changed"), "reason": .string("focus")])),
            observation(payload: .object(["kind": .string("text.changed"), "baseSnapshotId": .string("before"), "after": snapshot()])),
            action(.object(["kind": .string("text.set"), "text": .string("合成🙂")])),
            action(.object(["kind": .string("pointer.click"), "point": .object(["x": .number(-2.5), "y": .number(3.25), "space": .string("window-point"), "transformId": .string("mapping")]), "button": .string("left"), "count": .number(2)])),
            action(.object(["kind": .string("key.chord"), "keys": .array([.string("Meta"), .string("A")])])),
            action(.object(["kind": .string("view.zoom"), "subject": .string("page"), "scale": .number(1.25)])),
            receipt(), protocolFailure(),
        ]
        for fixture in fixtures {
            XCTAssertEqual(try validator.validateMessage(fixture), fixture)
            XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(fixture)), fixture)
        }
    }

    func testClosedObjectsAndRequiredFieldsAtEveryLayer() throws {
        for path in [[], ["stamp"], ["target"], ["target", "identity"], ["payload"], ["payload", "coverage"], ["payload", "range"]] {
            assertInvalid(replacing(observation(), path: path + ["unknown"], with: .string("synthetic-private-body")))
        }
        for path in [["protocolVersion"], ["seq"], ["stamp", "captureEpoch"], ["target", "identity", "processId"], ["payload", "captureEndMs"]] {
            assertInvalid(replacing(observation(), path: path, with: nil))
        }
        assertInvalid(replacing(hello(), path: ["capabilities"], with: .object([:])))
        assertInvalid(replacing(observation(), path: ["target"], with: .null))
    }

    func testBooleanIsNotANumberOrIntegerOrNumericConstant() throws {
        assertInvalid(replacing(observation(), path: ["seq"], with: .bool(true)))
        assertInvalid(replacing(observation(), path: ["payload", "coverage", "truncated"], with: .number(0)))
        assertInvalid(replacing(hello(), path: ["maxFrameBytes"], with: .bool(true)))
        assertInvalid(replacing(protocolFailure(), path: ["retryable"], with: .number(0)))
        assertInvalid(replacing(configure(), path: ["policy", "enabled"], with: .number(1)))
        assertInvalid(replacing(action(.object(["kind": .string("view.zoom"), "subject": .string("page"), "scale": .bool(true)])), path: ["runtimeGeneration"], with: .number(1)))
        XCTAssertEqual(try JSONValue.parse(Data("[true,1,false,0]".utf8)), .array([.bool(true), .number(1), .bool(false), .number(0)]))
        XCTAssertEqual(try JSONDecoder().decode(JSONValue.self, from: Data("[true,1]".utf8)), .array([.bool(true), .number(1)]))
    }

    func testSafeIntegerBoundsAndFiniteNumbers() throws {
        XCTAssertNoThrow(try validator.validateMessage(replacing(observation(), path: ["seq"], with: .number(ContractLimits.maxSafeInteger))))
        for number in [ContractLimits.maxSafeInteger + 1, 0, -1, 1.5, .infinity, -.infinity, .nan] {
            assertInvalid(replacing(observation(), path: ["seq"], with: .number(number)))
        }
        for number in [0, 2_147_483_648] as [Double] {
            assertInvalid(replacing(observation(), path: ["target", "identity", "processId"], with: .number(number)))
        }
        let overflow = String(decoding: try hello().canonicalData(), as: UTF8.self).replacingOccurrences(of: "65536", with: "1e400")
        assertError(.invalidMessage) { try self.validator.decodeFrame(Data(overflow.utf8)) }
        let scientific = String(decoding: try hello().canonicalData(), as: UTF8.self).replacingOccurrences(of: "65536", with: "6.5536e4")
        XCTAssertEqual(try validator.decodeFrame(Data(scientific.utf8)), hello())
    }

    func testVersionErrorsHavePrecedenceAndNoBody() throws {
        for version: JSONValue in [.number(2), .number(0), .string("1"), .bool(true), .null, .array([]), .object([:])] {
            assertError(.unsupportedVersion) {
                try self.validator.validateMessage(.object(["protocolVersion": version, "body": .string("never-echo-this-synthetic-body")]))
            }
        }
        for value: JSONValue in [.null, .array([]), .string("synthetic"), .number(1), .bool(true), .object([:])] { assertInvalid(value) }
        for error: ProtocolError in [.invalidMessage, .unsupportedVersion, .frameTooLarge] {
            XCTAssertEqual(error.localizedDescription, error.code)
            XCTAssertEqual(String(describing: error), error.code)
            XCTAssertEqual(ValidationResult.invalid(error).jsonValue, .object(["valid": .bool(false), "code": .string(error.code)]))
        }
    }

    func testUnicodeAndUTF16RangeLengthWithoutNormalization() throws {
        for text in ["", "中文测试", "🙂", "👩🏽‍💻", "e\u{301}", "é", "行一\n行二\t\u{0}", "ＡＢＣ"] {
            let value = observation(payload: snapshot(text: text))
            XCTAssertEqual(try validator.decodeFrame(validator.encodeFrame(value)), value)
        }
        let emoji = snapshot(text: "🙂")
        assertInvalid(observation(payload: replacing(emoji, path: ["range", "length"], with: .number(1))))
        let combining = snapshot(text: "e\u{301}")
        assertInvalid(observation(payload: replacing(combining, path: ["range", "length"], with: .number(1))))
        XCTAssertNotEqual(JSONValue.string("é"), .string("e\u{301}"))
        let changed = JSONValue.object([
            "kind": .string("text.changed"), "baseSnapshotId": .string("é"),
            "after": replacing(snapshot(), path: ["snapshotId"], with: .string("e\u{301}")),
        ])
        XCTAssertNoThrow(try validator.validateMessage(observation(payload: changed)))
    }

    func testUTF16TextAndIdentifierBudgets() throws {
        XCTAssertNoThrow(try validator.validateMessage(observation(payload: snapshot(text: String(repeating: "🙂", count: 4096)))))
        XCTAssertNoThrow(try validator.validateMessage(observation(payload: snapshot(text: String(repeating: "中", count: 8192)))))
        assertInvalid(observation(payload: snapshot(text: String(repeating: "🙂", count: 4097))))
        XCTAssertNoThrow(try validator.validateMessage(replacing(hello(), path: ["instanceId"], with: .string(String(repeating: "🙂", count: 64)))))
        assertInvalid(replacing(hello(), path: ["instanceId"], with: .string(String(repeating: "🙂", count: 65))))
    }

    func testStrictJSONAndUTF8AndSurrogates() throws {
        let invalid = ["", " ", "{", "null null", "{\"a\":1,}", "[1,]", "+1", "01", "-.5", "1.", "1e", "NaN", "Infinity", "\"raw\nnewline\"", "\"\\x20\"", "\"\\uD800\"", "\"\\uDC00\"", "\"\\uD800x\"", "\"\\uD800\\u0041\"", "\"\\uZZZZ\""]
        for input in invalid { assertError(.invalidMessage) { try JSONValue.parse(Data(input.utf8)) } }
        for data in [Data([0xff]), Data([0xc0, 0xaf]), Data([0x22, 0xed, 0xa0, 0x80, 0x22])] {
            assertError(.invalidMessage) { try JSONValue.parse(data) }
        }
        XCTAssertEqual(try JSONValue.parse(Data("\"\\uD83D\\uDE42\"".utf8)), .string("🙂"))
        XCTAssertEqual(try JSONValue.parse(Data("{\"x\":1,\"x\":2}".utf8)), .object(["x": .number(2)]))
        var bom = Data([0xef, 0xbb, 0xbf])
        bom.append(try hello().canonicalData())
        assertError(.invalidMessage) { try self.validator.decodeFrame(bom) }
    }

    func testReadNeedsTextAndRangeButEmptyReadIsValid() throws {
        XCTAssertNoThrow(try validator.validateMessage(observation(payload: snapshot(text: ""))))
        for key in ["text", "range"] {
            assertInvalid(observation(payload: replacing(snapshot(), path: [key], with: nil)))
        }
        assertInvalid(observation(payload: replacing(snapshot(), path: ["text"], with: .null)))
        assertInvalid(observation(payload: replacing(snapshot(), path: ["range", "length"], with: .number(0))))
    }

    func testUnavailableAndRedactedHaveNoContentRangeOrSelection() throws {
        for state in ["unavailable", "redacted"] {
            var unavailable = replacing(snapshot(), path: ["valueState"], with: .string(state))
            unavailable = replacing(unavailable, path: ["text"], with: nil)
            unavailable = replacing(unavailable, path: ["range"], with: nil)
            unavailable = replacing(unavailable, path: ["coverage"], with: coverage(status: "partial", reasons: ["filtered"]))
            XCTAssertNoThrow(try validator.validateMessage(observation(payload: unavailable)))
            for (key, value) in [("text", JSONValue.string("")), ("range", textRange()), ("selection", textRange())] {
                assertInvalid(observation(payload: replacing(unavailable, path: [key], with: value)))
            }
            assertInvalid(observation(payload: replacing(unavailable, path: ["coverage"], with: coverage())))
        }
    }

    func testCoverageAndCaptureTimes() throws {
        for invalidCoverage in [coverage(truncated: true), coverage(reasons: ["missing"]), coverage(status: "partial"), coverage(status: "unknown")] {
            assertInvalid(observation(payload: replacing(snapshot(), path: ["coverage"], with: invalidCoverage)))
        }
        for status in ["partial", "unknown"] {
            XCTAssertNoThrow(try validator.validateMessage(observation(payload: replacing(snapshot(), path: ["coverage"], with: coverage(status: status, reasons: ["synthetic-gap"])))) )
        }
        assertInvalid(observation(payload: replacing(snapshot(), path: ["captureEndMs"], with: .number(9))))
        XCTAssertNoThrow(try validator.validateMessage(observation(payload: replacing(snapshot(), path: ["captureEndMs"], with: .number(10)))))
    }

    func testFieldScopeRangeAndSelectionBounds() throws {
        for path in [["totalLength"], ["range", "start"]] {
            assertInvalid(observation(payload: replacing(snapshot(), path: path, with: path.count == 1 ? nil : .number(1))))
        }
        assertInvalid(observation(payload: replacing(snapshot(), path: ["totalLength"], with: .number(0))))
        assertInvalid(observation(payload: replacing(snapshot(), path: ["totalLength"], with: .number(99))))
        var ranged = replacing(snapshot(), path: ["scope"], with: .string("accessible-range"))
        ranged = replacing(ranged, path: ["range", "start"], with: .number(20))
        ranged = replacing(ranged, path: ["totalLength"], with: .number(30))
        XCTAssertNoThrow(try validator.validateMessage(observation(payload: ranged)))
        assertInvalid(observation(payload: replacing(ranged, path: ["totalLength"], with: .number(21))))
        XCTAssertNoThrow(try validator.validateMessage(observation(payload: replacing(ranged, path: ["totalLength"], with: nil))))
        XCTAssertNoThrow(try validator.validateMessage(observation(payload: replacing(ranged, path: ["selection"], with: textRange(start: 29, length: 1)))))
        assertInvalid(observation(payload: replacing(ranged, path: ["selection"], with: textRange(start: 30, length: 1))))
    }

    func testResolvedTargetChangedBaseAndAgentAttribution() throws {
        let unresolved = JSONValue.object(["kind": .string("unresolved"), "reason": .string("not-observed")])
        assertInvalid(replacing(observation(), path: ["target"], with: unresolved))
        let changed = JSONValue.object(["kind": .string("text.changed"), "baseSnapshotId": .string("snapshot"), "after": snapshot()])
        assertInvalid(observation(payload: changed))
        let gap = observation(payload: .object(["kind": .string("gap"), "reason": .string("stale"), "count": .number(1)]))
        XCTAssertNoThrow(try validator.validateMessage(replacing(gap, path: ["target"], with: unresolved)))
        let agent = replacing(gap, path: ["actor"], with: .string("agent"))
        assertInvalid(agent)
        XCTAssertNoThrow(try validator.validateMessage(replacing(agent, path: ["relatedActionIds"], with: .array([.string("action")]))))
    }

    func testReceiptDispatchEffectMatrixAndTimes() throws {
        for dispatch in ["not-dispatched", "dispatched", "partial", "unknown"] {
            for effect in ["confirmed", "unverifiable", "uncertain", "refused"] {
                let candidate = receipt(dispatch: dispatch, effect: effect)
                let valid = !(effect == "confirmed" && ["not-dispatched", "unknown"].contains(dispatch))
                    && !(effect == "refused" && dispatch != "not-dispatched")
                    && !(dispatch == "unknown" && effect != "uncertain")
                if valid { XCTAssertNoThrow(try validator.validateMessage(candidate)) }
                else { assertInvalid(candidate) }
            }
        }
        assertInvalid(replacing(receipt(), path: ["evidenceIds"], with: .array([])))
        assertInvalid(replacing(receipt(), path: ["endedMs"], with: .number(9)))
        XCTAssertNoThrow(try validator.validateMessage(replacing(receipt(), path: ["endedMs"], with: .number(10))))
    }

    func testPolicyAndCollectionBudgets() throws {
        assertInvalid(replacing(configure(), path: ["policy", "maxWaitMs"], with: .number(19)))
        XCTAssertNoThrow(try validator.validateMessage(replacing(configure(), path: ["policy", "maxWaitMs"], with: .number(20))))
        assertInvalid(replacing(configure(), path: ["policy", "allowedApplicationIds"], with: .array(Array(repeating: .string("synthetic.app"), count: 65))))
        assertInvalid(replacing(observation(), path: ["relatedActionIds"], with: .array(Array(repeating: .string("action"), count: 17))))
        assertInvalid(action(.object(["kind": .string("key.chord"), "keys": .array([])])))
    }

    func testSchemaDepthOneOfAndMissingReferences() throws {
        let emptyRoot = JSONValue.object(["$defs": .object([:]), "type": .string("boolean")])
        let schema = try SchemaValidator(root: emptyRoot)
        XCTAssertNoThrow(try schema.validateNode(.bool(true), node: emptyRoot, depth: 32))
        assertError(.invalidMessage) { try schema.validateNode(.bool(true), node: emptyRoot, depth: 33) }
        let ambiguous = JSONValue.object(["$defs": .object([:]), "oneOf": .array([.object(["const": .bool(true)]), .object(["type": .string("boolean")])])])
        assertError(.invalidMessage) { try SchemaValidator(root: ambiguous).validate(.bool(true)) }
        let absent = JSONValue.object(["$defs": .object([:]), "$ref": .string("#/$defs/Absent")])
        assertError(.invalidMessage) { try SchemaValidator(root: absent).validate(.bool(true)) }
        let deep = String(repeating: "[", count: 33) + "0" + String(repeating: "]", count: 33)
        assertError(.invalidMessage) { try JSONValue.parse(Data(deep.utf8)) }
    }

    func testFrameBytesAndCanonicalOriginal() throws {
        let value = hello()
        let encoded = try validator.encodeFrame(value)
        XCTAssertEqual(encoded.last, 10)
        XCTAssertFalse(encoded.suffix(2) == Data([92, 110]))
        var exact = try value.canonicalData()
        exact.append(Data(repeating: 32, count: ContractLimits.maxFrameBytes - exact.count))
        XCTAssertEqual(try validator.decodeFrame(exact), value)
        exact.append(32)
        assertError(.frameTooLarge) { try self.validator.decodeFrame(exact) }
        let result = try JSONValue.parse(ValidationResult.valid(value).encodedLine())
        XCTAssertEqual(result, .object(["valid": .bool(true), "message": value]))
        let largeCapabilities = Array(repeating: JSONValue.object(["name": .string("text.snapshot"), "direction": .string("observe"), "scope": .string("app-local"), "support": .string("supported"), "reason": .string(String(repeating: "\u{0}", count: 256))]), count: 64)
        let large = replacing(hello(), path: ["capabilities"], with: .array(largeCapabilities))
        XCTAssertNoThrow(try validator.validateMessage(large))
        assertError(.frameTooLarge) { try self.validator.encodeFrame(large) }
    }

    private func assertInvalid(_ value: JSONValue, file: StaticString = #filePath, line: UInt = #line) {
        assertError(.invalidMessage, file: file, line: line) { try self.validator.validateMessage(value) }
    }

    private func assertError<T>(_ expected: ProtocolError, file: StaticString = #filePath, line: UInt = #line, _ body: () throws -> T) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            XCTAssertEqual(error as? ProtocolError, expected, file: file, line: line)
        }
    }
}

func replacing(_ value: JSONValue, path: [String], with replacement: JSONValue?) -> JSONValue {
    guard let key = path.first, var object = value.objectValue else { return replacement ?? value }
    if path.count == 1 { object[key] = replacement }
    else if let child = object[key] { object[key] = replacing(child, path: Array(path.dropFirst()), with: replacement) }
    return .object(object)
}

func hello() -> JSONValue {
    .object(["protocolVersion": .number(1), "type": .string("hello"), "instanceId": .string("fixture"), "capabilities": .array([]), "maxFrameBytes": .number(65536)])
}

func configure() -> JSONValue {
    .object(["protocolVersion": .number(1), "type": .string("configure"), "requestId": .string("request"), "ownerId": .string("owner"), "instanceId": .string("fixture"), "policyRevision": .number(1), "policy": .object(["enabled": .bool(false), "allowedApplicationIds": .array([]), "maxTextCodeUnits": .number(8192), "maxPending": .number(8), "debounceMs": .number(20), "maxWaitMs": .number(100), "readTimeoutMs": .number(1000)])])
}

func configured() -> JSONValue {
    .object(["protocolVersion": .number(1), "type": .string("configured"), "requestId": .string("request"), "ownerId": .string("owner"), "instanceId": .string("fixture"), "policyRevision": .number(1)])
}

func control() -> JSONValue {
    replacing(replacing(replacing(configured(), path: ["type"], with: .string("control")), path: ["command"], with: .string("stop")), path: ["leaseDurationMs"], with: .number(1000))
}

func state() -> JSONValue {
    .object(["protocolVersion": .number(1), "type": .string("state"), "requestId": .string("request"), "instanceId": .string("fixture"), "state": .string("stopped"), "stamp": stamp(), "reason": .string("")])
}

func stamp() -> JSONValue {
    .object(["captureEpoch": .number(1), "foregroundGeneration": .number(2), "focusGeneration": .number(3), "policyRevision": .number(1)])
}

func targetIdentity() -> JSONValue {
    .object(["deviceId": .string("synthetic-device"), "osSessionId": .string("synthetic-os-session"), "desktopId": .string("synthetic-desktop"), "processId": .number(123), "processStartTime": .string("synthetic-birth"), "applicationId": .string("fixture.app"), "windowId": .string("window"), "windowGeneration": .number(1)])
}

func coverage(status: String = "complete", truncated: Bool = false, reasons: [String] = []) -> JSONValue {
    .object(["status": .string(status), "truncated": .bool(truncated), "missingReasons": .array(reasons.map(JSONValue.string))])
}

func textRange(start: Double = 0, length: Double = 0) -> JSONValue {
    .object(["unit": .string("utf16"), "start": .number(start), "length": .number(length)])
}

func snapshot(text: String = "中文🙂") -> JSONValue {
    .object(["kind": .string("text.snapshot"), "snapshotId": .string("snapshot"), "editSessionId": .string("edit"), "nodeId": .string("node"), "source": .string("fixture"), "scope": .string("field"), "valueState": .string("read"), "text": .string(text), "range": textRange(length: Double(text.utf16.count)), "totalLength": .number(Double(text.utf16.count)), "composition": .string("unknown"), "captureStartMs": .number(10), "captureEndMs": .number(11), "coverage": coverage()])
}

func observation(payload: JSONValue = snapshot()) -> JSONValue {
    .object(["protocolVersion": .number(1), "type": .string("observation"), "eventId": .string("event"), "instanceId": .string("fixture"), "seq": .number(1), "eventTimeMs": .number(10), "monotonicMs": .number(20), "target": .object(["kind": .string("resolved"), "identity": targetIdentity()]), "stamp": stamp(), "actor": .string("unknown"), "relatedActionIds": .array([]), "payload": payload])
}

func action(_ value: JSONValue) -> JSONValue {
    .object(["protocolVersion": .number(1), "type": .string("action.request"), "requestId": .string("request"), "actionId": .string("action"), "target": targetIdentity(), "stamp": stamp(), "snapshotId": .string("snapshot"), "backendId": .string("fixture"), "runtimeGeneration": .number(1), "deadlineMs": .number(1000), "sessionId": .string("session"), "agentId": .string("agent"), "grantId": .string("grant"), "leaseId": .string("lease"), "mode": .string("background"), "expectedCondition": .string("fixture-only"), "action": value])
}

func receipt(dispatch: String = "dispatched", effect: String = "confirmed") -> JSONValue {
    .object(["protocolVersion": .number(1), "type": .string("action.receipt"), "requestId": .string("request"), "actionId": .string("action"), "dispatch": .string(dispatch), "effect": .string(effect), "startedMs": .number(10), "endedMs": .number(11), "route": .string("fixture"), "evidenceIds": .array([.string("evidence")]), "reason": .string("")])
}

func protocolFailure() -> JSONValue {
    .object(["protocolVersion": .number(1), "type": .string("error"), "requestId": .string("request"), "code": .string("stale"), "retryable": .bool(false)])
}

import XCTest
import HistoryContract
@testable import CollectorCore

/// Pure injected providers only: never accesses real AX, input, desktop or data.
final class FieldDenylistTests: XCTestCase {
    private let deny = CapturePolicy(fieldSecurity: "denylist")
    func testOptionalAbsenceAndSuccessfulUnrecognizedSubrolesNeedExplicitDenylist() {
        let values: [TextSecurityGate.SubroleRead] = [.noValue, .attributeUnsupported, .value(""), .value("AXUnknown")]
        for role in ["AXTextField", "AXTextArea", "AXStaticText"] {
            for value in values {
                XCTAssertEqual(TextSecurityGate.classifyMetadata(role: role, subrole: value, protectedContent: .noValue, policy: deny), .notDeclaredSensitive)
                XCTAssertEqual(TextSecurityGate.classifyMetadata(role: role, subrole: value, protectedContent: .attributeUnsupported, policy: CapturePolicy()), .unknown)
            }
        }
        for role: String? in [nil, "AXButton", "AXGroup", "AXWebArea"] {
            XCTAssertEqual(TextSecurityGate.classifyMetadata(role: role, subrole: .noValue, protectedContent: .value(false), policy: deny), .unknown)
        }
    }
    func testSensitiveDeclarationsWinAndMetadataFailuresNeverBecomeAbsence() {
        for policy in [CapturePolicy(), deny] {
            for subrole in ["AXSecureTextField", "axPASSWORDfield", "AXpRoTeCtEdText"] {
                XCTAssertEqual(TextSecurityGate.classifyMetadata(role: "AXTextArea", subrole: .value(subrole), protectedContent: .value(false), policy: policy), .sensitive)
            }
            XCTAssertEqual(TextSecurityGate.classifyMetadata(role: "AXSecureTextField", subrole: .failure, protectedContent: .failure, policy: policy), .sensitive)
            XCTAssertEqual(TextSecurityGate.classifyMetadata(role: "AXTextField", subrole: .value("AXStandardTextField"), protectedContent: .value(true), policy: policy), .sensitive)
            for failed: TextSecurityGate.SubroleRead in [.failure, .malformed] {
                XCTAssertEqual(TextSecurityGate.classifyMetadata(role: "AXTextArea", subrole: failed, protectedContent: .value(false), policy: policy), .unknown)
            }
            for failed: TextSecurityGate.ProtectedContentRead in [.failure, .malformed] {
                XCTAssertEqual(TextSecurityGate.classifyMetadata(role: "AXTextArea", subrole: .value("AXTextArea"), protectedContent: failed, policy: policy), .unknown)
            }
        }
    }
    func testStrictCompatibilityRemainsExplicitAndDenylistNeverClaimsSafe() {
        XCTAssertEqual(TextSecurityGate.classifyMetadata(role: "AXTextArea", subrole: .value("AXTextArea"), protectedContent: .noValue, policy: CapturePolicy()), .safe)
        XCTAssertEqual(TextSecurityGate.classifyMetadata(role: "AXTextArea", subrole: .value("AXTextArea"), protectedContent: .value(false), policy: deny), .notDeclaredSensitive)
        XCTAssertEqual(TextSecurityGate.classifyMetadata(role: "AXTextField", subrole: .attributeUnsupported, protectedContent: .attributeUnsupported, policy: CapturePolicy(), strictFallback: { .safe }), .safe)
        XCTAssertEqual(CapturePolicy().fieldSecurityMode, "strict")
        XCTAssertTrue(CapturePolicy(fieldSecurity: "strict").hasValidTextSettings)
        XCTAssertFalse(CapturePolicy(fieldSecurity: "allow-all").hasValidTextSettings)
        for status: SecureStatus in [.unknown, .sensitive] { XCTAssertFalse(deny.allows(status)) }
        XCTAssertTrue(deny.allows(.notDeclaredSensitive)); XCTAssertFalse(CapturePolicy().allows(.notDeclaredSensitive))
        XCTAssertFalse(CapturePolicy(fieldSecurity: "allow-all").allows(.safe))
    }
    func testProtectedAndFailedContainerMetadataPruneBeforeChildOrTextGetter() {
        for (subrole, protected) in [(TextSecurityGate.SubroleRead.value("AXProtectedGroup"), TextSecurityGate.ProtectedContentRead.noValue), (.noValue, .value(true)), (.failure, .value(false)), (.malformed, .noValue), (.noValue, .failure), (.noValue, .malformed)] {
            var childReads = 0; var textReads = 0
            if TextSecurityGate.mayTraverse(subrole: subrole, protectedContent: protected) { childReads += 1; textReads += 1 }
            XCTAssertEqual(childReads, 0); XCTAssertEqual(textReads, 0)
        }
        XCTAssertTrue(TextSecurityGate.mayTraverse(subrole: .noValue, protectedContent: .attributeUnsupported))
        XCTAssertTrue(TextSecurityGate.mayTraverse(subrole: .value("AXUnknown"), protectedContent: .value(false)))
    }
    func testDenylistReaderAllowsAbsenceButKeepsAppAndPostReadGates() {
        let clock = FakeClock(), provider = FakeProvider(); provider.secure = .notDeclaredSensitive
        XCTAssertEqual(BoundedTextReader().read(ticket: ticket(clock, policy: deny), provider: provider, clock: clock).text?.text, "test")
        XCTAssertEqual(BoundedTextReader().read(ticket: ticket(clock), provider: provider, clock: clock).diagnostic?.code, .fieldSecurityUnknown)
        for id in ["com.1password.1password", "com.apple.safari.extension"] {
            let excluded = FakeProvider(); excluded.app.applicationId = id; excluded.secure = .notDeclaredSensitive
            let policy = CapturePolicy(applicationScope: "denylist", allowBrowserContent: true, fieldSecurity: "denylist")
            XCTAssertNil(BoundedTextReader().read(ticket: ticket(clock, policy: policy), provider: excluded, clock: clock).text)
            XCTAssertEqual(excluded.resolveCalls, 0); XCTAssertEqual(excluded.textCalls, 0)
        }
        for failed: SecureStatus in [.unknown, .sensitive] {
            let changed = FakeProvider(); changed.secure = .notDeclaredSensitive; changed.onRange = { changed.secure = failed }
            let result = BoundedTextReader().read(ticket: ticket(clock, policy: deny), provider: changed, clock: clock)
            XCTAssertNil(result.text); XCTAssertEqual(result.diagnostic?.code, failed == .sensitive ? .secureField : .fieldSecurityUnknown)
        }
        let selected = FakeProvider(); selected.secure = .notDeclaredSensitive; selected.onSelection = { selected.secure = .unknown }
        XCTAssertEqual(BoundedTextReader().read(ticket: ticket(clock, policy: deny), provider: selected, clock: clock).diagnostic?.code, .fieldSecurityUnknown)
    }
    func testDenylistRangeMarkerAndValueFallbackRemainPreAndPostGated() {
        for route in ["range", "marker", "value"] {
            for failedAt in [0, 1, 2] {
                let clock = FakeClock(), provider = FieldFallbackProvider(route: route)
                provider.failAt = failedAt
                let result = BoundedTextReader().read(ticket: ticket(clock, policy: CapturePolicy(textMarkers: true, fieldSecurity: "denylist")), provider: provider, clock: clock)
                if failedAt == 0 { XCTAssertEqual(result.text?.text, "test") }
                else { XCTAssertNil(result.text); XCTAssertEqual(result.diagnostic?.code, .fieldSecurityUnknown) }
                if failedAt == 1 { XCTAssertEqual(provider.markerCalls, 0); XCTAssertEqual(provider.valueCalls, 0) }
            }
        }
    }
    private func inputContext(mode: String? = "strict", generation: Int64 = 1, privacy: InputTextPrivateState = .normal) -> InputTextContext {
        InputTextContext(target: .init(application: .init(applicationId: "test.allowed", processId: 42, processStartTime: "birth"), deviceId: "device", osSessionId: "session", desktopId: "desktop", windowId: "window", windowGeneration: generation), surfaceId: "surface", captureEpoch: 1, foregroundGeneration: 1, focusGeneration: 1, policyRevision: 1, privateState: privacy, fieldSecurity: mode)
    }
    func testInputFrozenPolicyMustMatchBeforeUnicodeAndStillBeFresh() {
        let nanos: UInt64 = 1_000_000_000, metadata = InputTextEventMetadata(targetProcessId: 42, timestampNanoseconds: 1_000_000_000, callbackTimeMs: 1_000)
        for (policyMode, contextMode, age) in [("denylist", "denylist", UInt64(0)), ("strict", "denylist", 0), ("denylist", "strict", 0), ("denylist", "unknown", 0), ("denylist", "denylist", 200_000_001)] {
            var reads = 0
            let result = InputTextReadGate.capture(metadata: metadata, modifiers: [], policy: CapturePolicy(inputText: true, fieldSecurity: policyMode), afterNanoseconds: 0, nowNanoseconds: { nanos }, safetyProvider: { _ in .init(context: self.inputContext(mode: contextMode), metadataMonotonicNanoseconds: nanos - age, role: .textArea) }, readUnicode: { reads += 1; return .text("synthetic") })
            if policyMode == contextMode && age == 0 {
                guard case .sample(let sample) = result else { return XCTFail("Denylist must accept fresh approved absence") }
                var buffer = InputTextAccumulator(); buffer.add(sample, source: .cgUnicode)
                XCTAssertEqual(buffer.takeSegment(approvedContext: sample.context)?.payload()["gate"]?["secure"], .string("not-declared-sensitive"))
                XCTAssertEqual(reads, 1)
            } else { guard case .gap = result else { return XCTFail("Mismatch or stale approval accepted") }; XCTAssertEqual(reads, 0) }
        }
    }
    func testInputFieldPolicyChangesDiscardPostReadAndBufferedData() throws {
        let nanos: UInt64 = 1_000_000_000; var approvals = 0
        let result = InputTextReadGate.capture(metadata: .init(targetProcessId: 42, timestampNanoseconds: nanos, callbackTimeMs: 1_000), modifiers: [], policy: CapturePolicy(inputText: true, fieldSecurity: "denylist"), afterNanoseconds: 0, nowNanoseconds: { nanos }, safetyProvider: { _ in
            approvals += 1; return .init(context: self.inputContext(mode: approvals == 1 ? "denylist" : "strict"), metadataMonotonicNanoseconds: nanos, role: .textArea)
        }, readUnicode: { .text("synthetic") })
        guard case .gap = result else { return XCTFail("Changed field policy accepted") }
        var buffer = InputTextAccumulator(); buffer.add(.init(context: inputContext(mode: "denylist"), eventKind: .text, text: "synthetic", modifiers: [], callbackTimeMs: 1_000), source: .cgUnicode)
        XCTAssertNil(buffer.takeDue(nowMs: 1_500, approvedContext: inputContext())); XCTAssertNil(buffer.pending)
        var old = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(inputContext())) as? [String: Any]); old.removeValue(forKey: "fieldSecurity")
        let decoded = try JSONDecoder().decode(InputTextContext.self, from: JSONSerialization.data(withJSONObject: old))
        XCTAssertTrue(decoded.isValid); XCTAssertEqual(decoded.fieldSecurityMode, "strict")
        XCTAssertFalse(inputContext(mode: "unknown").isValid)
    }
    func testActualEngineAllChannelsEmitConservativeGateAndValidateContract() throws {
        for mode: String? in [nil, "denylist"] {
            let h = Harness(fixture: false), policy = CapturePolicy(captureScope: "region", inputText: true, selectionCapture: true, fieldSecurity: mode)
            h.engine.hello()
            h.engine.receive(.object(["protocolVersion": j(1), "type": .string("configure"), "requestId": .string("config"), "ownerId": .string("owner"), "instanceId": .string("instance"), "policyRevision": j(1), "policy": try JSONValue.parse(JSONEncoder().encode(policy))]))
            h.control("start", lease: 30_000); h.clock.advance(51); h.engine.tick()
            var result = h.goodResult(try XCTUnwrap(h.env.launched.last))
            result.sessionIdentity = .init(sessionId: "worker", windowId: "window", nodeId: "node", surfaceId: "surface", windowGeneration: 1, focusGeneration: 1)
            result.surface = SurfaceBaseline().snapshot(surfaceId: "surface", scope: "region", nodes: [.init(id: "node", role: "text", text: "synthetic", observedAtMs: h.clock.unixMs)], complete: true, matchingKnown: true, truncated: false, missingReasons: [])
            result.selection = .init(text: "selection", source: "ax.range", rangeStart: 0, truncated: false, missingReasons: ["selection-only"])
            let context = InputTextContext(target: .init(application: try XCTUnwrap(result.application), deviceId: "device", osSessionId: "session", desktopId: "desktop", windowId: "window", windowGeneration: 1), surfaceId: "surface", captureEpoch: h.engine.captureEpoch, foregroundGeneration: h.engine.foregroundGeneration + 1, focusGeneration: h.engine.focusGeneration + 1, policyRevision: 1, privateState: .normal, fieldSecurity: mode)
            var buffer = InputTextAccumulator(); buffer.add(.init(context: context, eventKind: .text, text: "input", modifiers: [], callbackTimeMs: h.clock.unixMs), source: .cgUnicode)
            result.inputRecords = [try XCTUnwrap(buffer.takeSegment(approvedContext: context))]; h.engine.complete(result)
            for kind in ["text.snapshot", "surface.snapshot", "selection.snapshot", "input.text"] {
                let frame = try XCTUnwrap(h.frames.first { $0["payload"]?["kind"] == .string(kind) })
                XCTAssertEqual(frame["payload"]?["gate"]?["secure"], .string(mode == "denylist" ? "not-declared-sensitive" : "safe"))
            }
            XCTAssertTrue(h.frames.first?["capabilities"]?.arrayValue?.contains { $0["name"] == .string("field.denylist") } == true)
            let validator = try ContractValidator(); for frame in h.frames { XCTAssertNoThrow(try validator.encodeFrame(frame)) }
        }
    }
}

private final class FieldFallbackProvider: TextFieldProvider {
    let route: String
    var failAt = 0
    var secure: SecureStatus = .notDeclaredSensitive
    var markerCalls = 0, valueCalls = 0
    init(route: String) { self.route = route }
    func application() -> ApplicationIdentity? { .init(applicationId: "test.allowed", processId: 42, processStartTime: "birth") }
    func resolveFocusedField() -> Bool { true }
    func role() -> String? { "AXTextArea" }
    func secureStatus() -> SecureStatus { secure }
    func numberOfCharacters() -> Int? { 4 }
    func stringForRange(start: Int, length: Int) -> String? {
        if failAt == 1 || (failAt == 2 && route == "range") { secure = .unknown }
        return route == "range" ? "test" : nil
    }
    func markerStringForRange(start: Int, length: Int) -> String? {
        markerCalls += 1
        if failAt == 2 && route == "marker" { secure = .unknown }
        return route == "marker" ? "test" : nil
    }
    func boundedKnownLengthValue() -> String? { valueCalls += 1; if failAt == 2 { secure = .unknown }; return "test" }
    func selectedRange() -> TextSelection? { nil }
    func remainsSameFocusAndWindow() -> Bool { true }
}

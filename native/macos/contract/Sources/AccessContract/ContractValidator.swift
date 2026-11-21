import Foundation

public enum ContractLimits {
    public static let protocolVersion = 1
    public static let maxFrameBytes = 65_536
    public static let maxTextCodeUnits = 8_192
    public static let maxDepth = 32
    public static let maxCollectionItems = 256
    public static let maxSafeInteger: Double = 9_007_199_254_740_991
}

/// Errors deliberately contain only a protocol code, never input values or text.
public enum ProtocolError: String, Error, Equatable, Sendable, CustomStringConvertible, LocalizedError {
    case invalidMessage = "invalid-message"
    case unsupportedVersion = "unsupported-version"
    case frameTooLarge = "frame-too-large"

    public var code: String { rawValue }
    public var description: String { rawValue }
    public var errorDescription: String? { rawValue }
}

/// Wire-v1 validation only. This library has no native desktop or recorder dependencies.
public struct ContractValidator: Sendable {
    private let schema: SchemaValidator

    public init() throws {
        guard let url = Bundle.module.url(forResource: "wire.schema", withExtension: "json") else {
            throw ProtocolError.invalidMessage
        }
        do { schema = try SchemaValidator(root: JSONValue.parse(Data(contentsOf: url))) }
        catch { throw ProtocolError.invalidMessage }
    }

    /// Returns the original value unchanged, after structural and semantic validation.
    public func validateMessage(_ value: JSONValue) throws -> JSONValue {
        if let version = value["protocolVersion"], version != .number(1) {
            throw ProtocolError.unsupportedVersion
        }
        try schema.validate(value)
        try validateSemantics(value)
        return value
    }

    /// Decode a single bounded JSON frame; unlike the stream, no LF is required here.
    public func decodeFrame(_ bytes: Data) throws -> JSONValue {
        guard bytes.count <= ContractLimits.maxFrameBytes else { throw ProtocolError.frameTooLarge }
        return try validateMessage(JSONValue.parse(bytes))
    }

    /// Canonical JSON plus LF. The LF is included in the hard frame budget.
    public func encodeFrame(_ value: JSONValue) throws -> Data {
        let validated = try validateMessage(value)
        var bytes = try validated.canonicalData()
        bytes.append(0x0a)
        guard bytes.count <= ContractLimits.maxFrameBytes else { throw ProtocolError.frameTooLarge }
        return bytes
    }

    private func validateSemantics(_ message: JSONValue) throws {
        if message["type"] == .string("configure") {
            guard let policy = message["policy"] else { throw ProtocolError.invalidMessage }
            try validatePolicy(policy)
        }
        if message["type"] == .string("observation") {
            guard let payload = message["payload"], let kind = payload["kind"]?.stringValue else { throw ProtocolError.invalidMessage }
            if kind == "gap", let id = payload["providerApplicationId"]?.stringValue {
                guard id.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$", options: .regularExpression) == id.startIndex..<id.endIndex else { throw ProtocolError.invalidMessage }
            }
            let contentKinds = ["text.snapshot", "text.changed", "surface.snapshot", "selection.snapshot", "input.text"]
            if let relation = message["relation"] {
                guard contentKinds.contains(kind), let ids = relation["evidenceIds"]?.arrayValue,
                      Set(ids.compactMap { stringKey($0) }).count == ids.count,
                      !ids.contains(message["eventId"] ?? .null) else { throw ProtocolError.invalidMessage }
                // Host separately checks retained evidence, ordering and same-surface identity.
            }
            if ["surface.snapshot", "selection.snapshot", "input.text"].contains(kind) {
                guard message["target"]?["kind"] == .string("resolved"), message["actor"] == .string("unknown"),
                      message["relatedActionIds"]?.arrayValue?.isEmpty == true else { throw ProtocolError.invalidMessage }
                try validateGate(payload["gate"], revision: message["stamp"]?["policyRevision"])
                if kind == "surface.snapshot" { try validateSurface(payload) }
                else if kind == "selection.snapshot" { try validateSelection(payload) }
                else { try validateInputText(payload, message: message) }
            }
            // An application-only identity is never a resolved text/window target.
            if message["target"]?["kind"] == .string("application") && payload["kind"] != .string("input.activity") {
                throw ProtocolError.invalidMessage
            }
            if payload["kind"] == .string("input.activity") { try validateInputActivity(payload, message: message) }
            if payload["kind"] == .string("text.snapshot") || payload["kind"] == .string("text.changed") {
                guard message["target"]?["kind"] == .string("resolved") else { throw ProtocolError.invalidMessage }
                let changed = payload["kind"] == .string("text.changed")
                guard let snapshot = changed ? payload["after"] : payload else { throw ProtocolError.invalidMessage }
                try validateText(snapshot)
                if snapshot["source"] != .string("fixture") || snapshot["gate"] != nil {
                    try validateGate(snapshot["gate"], revision: message["stamp"]?["policyRevision"])
                }
                if changed && payload["baseSnapshotId"] == snapshot["snapshotId"] { throw ProtocolError.invalidMessage }
            }
            if message["actor"] == .string("agent") && message["relatedActionIds"]?.arrayValue?.isEmpty == true {
                throw ProtocolError.invalidMessage
            }
        }
        if message["type"] == .string("action.receipt") {
            guard let start = message["startedMs"]?.numberValue,
                  let end = message["endedMs"]?.numberValue, end >= start else { throw ProtocolError.invalidMessage }
            let dispatch = message["dispatch"]
            let effect = message["effect"]
            if effect == .string("confirmed") && (
                message["evidenceIds"]?.arrayValue?.isEmpty == true ||
                dispatch == .string("not-dispatched") || dispatch == .string("unknown")
            ) { throw ProtocolError.invalidMessage }
            if effect == .string("refused") && dispatch != .string("not-dispatched") { throw ProtocolError.invalidMessage }
            if dispatch == .string("unknown") && effect != .string("uncertain") { throw ProtocolError.invalidMessage }
        }
    }

    private func validatePolicy(_ policy: JSONValue) throws {
        guard let maxWait = policy["maxWaitMs"]?.numberValue,
              let debounce = policy["debounceMs"]?.numberValue, maxWait >= debounce,
              let allowed = policy["allowedApplicationIds"]?.arrayValue else { throw ProtocolError.invalidMessage }
        for values in [allowed, policy["excludedApplicationIds"]?.arrayValue ?? []] {
            let ids = values.compactMap(\.stringValue)
            guard ids.count == values.count, Set(ids.map { $0.lowercased() }).count == ids.count,
                  ids.allSatisfy({ id in
                      guard let match = id.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$", options: .regularExpression) else { return false }
                      return match == id.startIndex..<id.endIndex
                  }) else { throw ProtocolError.invalidMessage }
        }
        // Preserve legacy empty lists and deny-wins overlap; authorization remains Host-owned.
    }

    private func validateCoverage(_ coverage: JSONValue) throws {
        guard let reasons = coverage["missingReasons"]?.arrayValue else { throw ProtocolError.invalidMessage }
        if coverage["status"] == .string("complete") {
            if coverage["truncated"] == .bool(true) || !reasons.isEmpty { throw ProtocolError.invalidMessage }
        } else if reasons.isEmpty { throw ProtocolError.invalidMessage }
    }

    private func validateGate(_ gate: JSONValue?, revision: JSONValue?) throws {
        // user-authorized is a declaration, never a replacement for Host policy checks.
        guard let gate, (gate["secure"] == .string("safe") || gate["secure"] == .string("not-declared-sensitive")), gate["policyRevision"] == revision,
              gate["privateState"] == .string("normal") || gate["privateState"] == .string("user-authorized") else { throw ProtocolError.invalidMessage }
    }

    private func validateRange(_ range: JSONValue) throws {
        guard let start = range["start"]?.numberValue, let length = range["length"]?.numberValue,
              length <= ContractLimits.maxSafeInteger - start else { throw ProtocolError.invalidMessage }
    }

    // Swift String hashing normalizes Unicode; wire identifiers compare exact UTF-16 units like JS.
    private func stringKey(_ value: JSONValue?) -> [UInt16]? { value?.stringValue.map { Array($0.utf16) } }

    private func validateSurface(_ snapshot: JSONValue) throws {
        guard let start = snapshot["captureStartMs"]?.numberValue,
              let end = snapshot["captureEndMs"]?.numberValue, end >= start,
              let coverage = snapshot["coverage"], let nodes = snapshot["nodes"]?.arrayValue else { throw ProtocolError.invalidMessage }
        try validateCoverage(coverage)
        var byID: [[UInt16]: JSONValue] = [:]
        var textUnits = 0
        if let geometry = snapshot["geometry"] {
            guard let observed = geometry["observedAtMs"]?.numberValue, observed >= start, observed <= end else { throw ProtocolError.invalidMessage }
        }
        guard nodes.filter({ $0["focused"] == .bool(true) }).count <= 1 else { throw ProtocolError.invalidMessage }
        for node in nodes {
            guard (node["bounds"] == nil) == (node["boundsObservedAtMs"] == nil),
                  node["bounds"] == nil || snapshot["geometry"] != nil else { throw ProtocolError.invalidMessage }
            if let observed = node["boundsObservedAtMs"]?.numberValue {
                guard observed >= start, observed <= end else { throw ProtocolError.invalidMessage }
            }
            if let role = node["axRole"]?.stringValue {
                guard role.range(of: "^AX[A-Za-z0-9]{1,62}$", options: .regularExpression) == role.startIndex..<role.endIndex else { throw ProtocolError.invalidMessage }
            }
            guard let id = stringKey(node["id"]), byID[id] == nil,
                  let observed = node["observedAtMs"]?.numberValue, observed >= start, observed <= end else { throw ProtocolError.invalidMessage }
            textUnits += node["text"]?.stringValue?.utf16.count ?? 0
            guard textUnits <= ContractLimits.maxTextCodeUnits else { throw ProtocolError.invalidMessage }
            byID[id] = node
        }
        for node in nodes {
            guard let id = stringKey(node["id"]) else { throw ProtocolError.invalidMessage }
            var seen: Set<[UInt16]> = [id]
            var parent = stringKey(node["parentId"])
            while let parentID = parent {
                guard !seen.contains(parentID), let ancestor = byID[parentID] else { throw ProtocolError.invalidMessage }
                seen.insert(parentID)
                parent = stringKey(ancestor["parentId"])
            }
        }
        if snapshot["mode"] == .string("full") {
            if snapshot["changes"] != nil || snapshot["baseRevision"] != nil { throw ProtocolError.invalidMessage }
        } else {
            guard let base = snapshot["baseRevision"]?.numberValue, let revision = snapshot["revision"]?.numberValue, base < revision,
                  let changes = snapshot["changes"], let added = changes["added"]?.arrayValue,
                  let updated = changes["updated"]?.arrayValue, let removed = changes["removed"]?.arrayValue else { throw ProtocolError.invalidMessage }
            let ids = (added + updated + removed).compactMap { stringKey($0) }
            guard Set(ids).count == ids.count,
                  (added + updated).allSatisfy({ byID[stringKey($0) ?? []] != nil }),
                  removed.allSatisfy({ byID[stringKey($0) ?? []] == nil }),
                  coverage["status"] == .string("complete") || removed.isEmpty else { throw ProtocolError.invalidMessage }
        }
    }

    private func validateSelection(_ snapshot: JSONValue) throws {
        guard let start = snapshot["captureStartMs"]?.numberValue,
              let end = snapshot["captureEndMs"]?.numberValue, end >= start,
              let text = snapshot["text"]?.stringValue, let range = snapshot["range"],
              range["length"]?.numberValue == Double(text.utf16.count),
              snapshot["coverage"]?["status"] == .string("partial"),
              snapshot["coverage"]?["missingReasons"]?.arrayValue?.contains(.string("selection-only")) == true else { throw ProtocolError.invalidMessage }
        try validateRange(range)
    }

    private func validateInputText(_ payload: JSONValue, message: JSONValue) throws {
        guard let start = payload["intervalStartMs"]?.numberValue, let end = payload["intervalEndMs"]?.numberValue,
              end >= start, end - start <= 5000, message["eventTimeMs"]?.numberValue == end,
              let text = payload["text"]?.stringValue, let modifiers = payload["modifiers"]?.arrayValue,
              Set(modifiers.compactMap(\.stringValue)).count == modifiers.count,
              payload["coverage"]?["status"] == .string("partial"),
              let reasons = payload["coverage"]?["missingReasons"]?.arrayValue,
              reasons.contains(.string("input-events-partial")), reasons.contains(.string("effect-unverified")) else { throw ProtocolError.invalidMessage }
        let command = modifiers.contains(.string("command")) || modifiers.contains(.string("control"))
        if payload["eventKind"] == .string("text") {
            if text.isEmpty || command { throw ProtocolError.invalidMessage }
        } else if !text.isEmpty || (payload["eventKind"] == .string("shortcut") && !command) { throw ProtocolError.invalidMessage }
    }

    private func validateInputActivity(_ payload: JSONValue, message: JSONValue) throws {
        // Synthetic and listen-only sources share every gate, interval and attribution rule.
        guard message["target"]?["kind"] == .string("application"),
              message["actor"] == .string("unknown"),
              message["relatedActionIds"]?.arrayValue?.isEmpty == true,
              payload["gate"]?["policyRevision"] == message["stamp"]?["policyRevision"],
              let start = payload["intervalStartMs"]?.numberValue,
              let end = payload["intervalEndMs"]?.numberValue,
              start.truncatingRemainder(dividingBy: 1000) == 0, end == start + 1000,
              message["eventTimeMs"]?.numberValue == end,
              let counts = payload["counts"],
              let pointer = counts["pointerReleases"]?.numberValue,
              let drag = counts["dragSamples"]?.numberValue,
              let scroll = counts["scrollSamples"]?.numberValue,
              let shortcut = counts["shortcutPresses"]?.numberValue,
              payload["coverage"]?["status"] == .string("partial"),
              payload["coverage"]?["missingReasons"]?.arrayValue?.isEmpty == false else {
            throw ProtocolError.invalidMessage
        }
        let count = pointer + drag + scroll + shortcut
        guard count >= 1, count <= 256 else { throw ProtocolError.invalidMessage }
    }

    private func validateText(_ snapshot: JSONValue) throws {
        guard let captureStart = snapshot["captureStartMs"]?.numberValue,
              let captureEnd = snapshot["captureEndMs"]?.numberValue, captureEnd >= captureStart,
              let coverage = snapshot["coverage"],
              let missingReasons = coverage["missingReasons"]?.arrayValue else { throw ProtocolError.invalidMessage }
        let complete = coverage["status"] == .string("complete")
        if complete && (coverage["truncated"] == .bool(true) || !missingReasons.isEmpty) { throw ProtocolError.invalidMessage }
        if !complete && missingReasons.isEmpty { throw ProtocolError.invalidMessage }
        let range = snapshot["range"]
        let selection = snapshot["selection"]
        if let range { try validateRange(range) }
        if let selection { try validateRange(selection) }
        let totalLength = snapshot["totalLength"]?.numberValue
        if snapshot["valueState"] == .string("read") {
            guard let text = snapshot["text"]?.stringValue,
                  let start = range?["start"]?.numberValue,
                  let length = range?["length"]?.numberValue,
                  length == Double(text.utf16.count) else { throw ProtocolError.invalidMessage }
            if let totalLength, start + length > totalLength { throw ProtocolError.invalidMessage }
            if snapshot["scope"] == .string("field") && complete && (start != 0 || totalLength != length) {
                throw ProtocolError.invalidMessage
            }
        } else if snapshot["text"] != nil || range != nil || selection != nil || complete {
            throw ProtocolError.invalidMessage
        }
        if let selection, let totalLength {
            guard let start = selection["start"]?.numberValue,
                  let length = selection["length"]?.numberValue,
                  start + length <= totalLength else { throw ProtocolError.invalidMessage }
        }
        // Omitted basis preserves legacy wire-v1 accessible-range semantics.
        if snapshot["rangeBasis"] == .string("prefix"), let range, range["start"] != .number(0) {
            throw ProtocolError.invalidMessage
        }
        if snapshot["rangeBasis"] == .string("visible") {
            guard snapshot["source"] == .string("fixture") || snapshot["source"] == .string("ax.range") || snapshot["source"] == .string("ax.marker"),
                  snapshot["scope"] == .string("accessible-range"), snapshot["valueState"] == .string("read"),
                  let start = range?["start"]?.numberValue, let length = range?["length"]?.numberValue,
                  let totalLength, coverage["status"] == .string("partial"),
                  missingReasons.contains(.string("visible-range-only")),
                  start <= totalLength, length <= totalLength - start,
                  totalLength == 0 || length > 0 else { throw ProtocolError.invalidMessage }
            // Subtraction above prevents imprecise overflow near the safe-integer bound.
            let end = start + length
            guard end <= ContractLimits.maxSafeInteger, end.rounded(.towardZero) == end else { throw ProtocolError.invalidMessage }
            if let selection {
                guard let selectionStart = selection["start"]?.numberValue,
                      let selectionLength = selection["length"]?.numberValue,
                      selectionStart >= start, selectionStart <= end,
                      selectionLength <= end - selectionStart else { throw ProtocolError.invalidMessage }
            }
        }
    }
}

/// Deliberately limited to the generated schema's supported subset; not a general
/// JSON Schema implementation. References and union branches consume depth too,
/// matching validate.ts rather than measuring only nested input containers.
struct SchemaValidator: Sendable {
    let root: JSONValue
    let definitions: [String: JSONValue]

    init(root: JSONValue) throws {
        guard let definitions = root["$defs"]?.objectValue else { throw ProtocolError.invalidMessage }
        self.root = root
        self.definitions = definitions
    }

    func validate(_ value: JSONValue) throws { try validateNode(value, node: root, depth: 0) }

    func validateNode(_ value: JSONValue, node: JSONValue, depth: Int) throws {
        guard depth <= ContractLimits.maxDepth, let rule = node.objectValue else { throw ProtocolError.invalidMessage }
        if let reference = rule["$ref"]?.stringValue {
            guard reference.hasPrefix("#/$defs/"), let name = reference.split(separator: "/").last,
                  let target = definitions[String(name)] else { throw ProtocolError.invalidMessage }
            try validateNode(value, node: target, depth: depth + 1)
            return
        }
        if let branches = rule["oneOf"]?.arrayValue {
            var matches = 0
            for branch in branches {
                do { try validateNode(value, node: branch, depth: depth + 1); matches += 1 }
                catch is ProtocolError { continue }
            }
            guard matches == 1 else { throw ProtocolError.invalidMessage }
            return
        }
        if let expected = rule["const"], value != expected { throw ProtocolError.invalidMessage }
        if let values = rule["enum"]?.arrayValue, !values.contains(value) { throw ProtocolError.invalidMessage }
        switch rule["type"]?.stringValue {
        case "object":
            guard let record = value.objectValue else { throw ProtocolError.invalidMessage }
            let properties = rule["properties"]?.objectValue ?? [:]
            for key in rule["required"]?.arrayValue ?? [] {
                guard let name = key.stringValue, record[name] != nil else { throw ProtocolError.invalidMessage }
            }
            // Every generated object is closed; unknown keys always fail, as in TS.
            for (key, child) in record {
                guard let childRule = properties[key] else { throw ProtocolError.invalidMessage }
                try validateNode(child, node: childRule, depth: depth + 1)
            }
        case "array":
            guard let items = value.arrayValue,
                  Double(items.count) >= (rule["minItems"]?.numberValue ?? 0),
                  Double(items.count) <= (rule["maxItems"]?.numberValue ?? Double(ContractLimits.maxCollectionItems)),
                  let itemRule = rule["items"] else { throw ProtocolError.invalidMessage }
            for item in items { try validateNode(item, node: itemRule, depth: depth + 1) }
        case "string":
            guard let text = value.stringValue,
                  Double(text.unicodeScalars.count) >= (rule["minLength"]?.numberValue ?? 0),
                  Double(text.unicodeScalars.count) <= (rule["maxLength"]?.numberValue ?? Double(ContractLimits.maxTextCodeUnits)) else {
                throw ProtocolError.invalidMessage
            }
            // JSON Schema counts code points; wire v1 separately limits UTF-16 units.
            if let maxUTF16 = rule["x-maxUtf16CodeUnits"]?.numberValue, Double(text.utf16.count) > maxUTF16 {
                throw ProtocolError.invalidMessage
            }
            // Swift String cannot contain unpaired UTF-16 surrogates; parse() rejects them.
        case "integer", "number":
            guard let number = value.numberValue, number.isFinite else { throw ProtocolError.invalidMessage }
            if rule["type"] == .string("integer") && (
                number.rounded(.towardZero) != number || abs(number) > ContractLimits.maxSafeInteger
            ) { throw ProtocolError.invalidMessage }
            guard number >= (rule["minimum"]?.numberValue ?? -.infinity),
                  number <= (rule["maximum"]?.numberValue ?? .infinity) else { throw ProtocolError.invalidMessage }
        case "boolean":
            guard value.boolValue != nil else { throw ProtocolError.invalidMessage }
        case nil:
            guard rule["const"] != nil || rule["enum"] != nil else { throw ProtocolError.invalidMessage }
        default: throw ProtocolError.invalidMessage
        }
    }
}

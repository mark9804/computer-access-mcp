import Foundation

/// JSON primitives stay distinct: in particular `true` is never the number 1.
/// Numbers use IEEE-754 Double, like the TypeScript side of wire v1.
public indirect enum JSONValue: Codable, Equatable, Sendable {
    case object([String: JSONValue])
    case array([JSONValue])
    case string(String)
    case number(Double)
    case bool(Bool)
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode([JSONValue].self) { self = .array(value) }
        else { self = .object(try container.decode([String: JSONValue].self)) }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }

    public static func == (lhs: JSONValue, rhs: JSONValue) -> Bool {
        switch (lhs, rhs) {
        case (.object(let left), .object(let right)): return left == right
        case (.array(let left), .array(let right)): return left == right
        // Swift's normal String equality normalizes Unicode; JS compares code units.
        case (.string(let left), .string(let right)): return left.utf16.elementsEqual(right.utf16)
        case (.number(let left), .number(let right)): return left == right
        case (.bool(let left), .bool(let right)): return left == right
        case (.null, .null): return true
        default: return false
        }
    }

    public subscript(key: String) -> JSONValue? {
        guard case .object(let value) = self else { return nil }
        return value[key]
    }

    public var objectValue: [String: JSONValue]? {
        guard case .object(let value) = self else { return nil }
        return value
    }
    public var arrayValue: [JSONValue]? {
        guard case .array(let value) = self else { return nil }
        return value
    }
    public var stringValue: String? {
        guard case .string(let value) = self else { return nil }
        return value
    }
    public var numberValue: Double? {
        guard case .number(let value) = self else { return nil }
        return value
    }
    public var boolValue: Bool? {
        guard case .bool(let value) = self else { return nil }
        return value
    }

    /// Strict UTF-8/JSON decoding, with bounded structural recursion and no repairs.
    /// Parsing numbers ourselves preserves JS rounding and overflow semantics instead
    /// of allowing NSNumber Boolean bridging or Foundation Decimal differences.
    public static func parse(_ data: Data) throws -> JSONValue {
        guard String(data: data, encoding: .utf8) != nil else { throw ProtocolError.invalidMessage }
        var parser = JSONParser(bytes: Array(data))
        return try parser.parse()
    }

    /// Deterministic key order, without adding, dropping, or normalizing message values.
    public func canonicalData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        do { return try encoder.encode(self) }
        catch { throw ProtocolError.invalidMessage }
    }
}

private struct JSONParser {
    let bytes: [UInt8]
    var offset = 0

    mutating func parse() throws -> JSONValue {
        // BOM is not JSON whitespace; wire decoding never silently strips it.
        let value = try parseValue(depth: 0)
        skipWhitespace()
        guard offset == bytes.count else { throw ProtocolError.invalidMessage }
        return value
    }

    mutating func parseValue(depth: Int) throws -> JSONValue {
        guard depth <= ContractLimits.maxDepth else { throw ProtocolError.invalidMessage }
        skipWhitespace()
        guard offset < bytes.count else { throw ProtocolError.invalidMessage }
        switch bytes[offset] {
        case 0x7b:
            offset += 1
            var result: [String: JSONValue] = [:]
            skipWhitespace()
            if consume(0x7d) { return .object(result) }
            while true {
                skipWhitespace()
                let key = try parseString()
                skipWhitespace()
                guard consume(0x3a) else { throw ProtocolError.invalidMessage }
                result[key] = try parseValue(depth: depth + 1)
                skipWhitespace()
                if consume(0x7d) { return .object(result) }
                guard consume(0x2c) else { throw ProtocolError.invalidMessage }
            }
        case 0x5b:
            offset += 1
            var result: [JSONValue] = []
            skipWhitespace()
            if consume(0x5d) { return .array(result) }
            while true {
                result.append(try parseValue(depth: depth + 1))
                skipWhitespace()
                if consume(0x5d) { return .array(result) }
                guard consume(0x2c) else { throw ProtocolError.invalidMessage }
            }
        case 0x22: return .string(try parseString())
        case 0x74: try consumeLiteral(Array("true".utf8)); return .bool(true)
        case 0x66: try consumeLiteral(Array("false".utf8)); return .bool(false)
        case 0x6e: try consumeLiteral(Array("null".utf8)); return .null
        case 0x2d, 0x30...0x39: return .number(try parseNumber())
        default: throw ProtocolError.invalidMessage
        }
    }

    mutating func parseString() throws -> String {
        guard consume(0x22) else { throw ProtocolError.invalidMessage }
        var result: [UInt8] = []
        while offset < bytes.count {
            let byte = bytes[offset]
            offset += 1
            if byte == 0x22 {
                guard let text = String(bytes: result, encoding: .utf8) else { throw ProtocolError.invalidMessage }
                return text
            }
            guard byte >= 0x20 else { throw ProtocolError.invalidMessage }
            if byte != 0x5c { result.append(byte); continue }
            guard offset < bytes.count else { throw ProtocolError.invalidMessage }
            let escaped = bytes[offset]
            offset += 1
            switch escaped {
            case 0x22, 0x5c, 0x2f: result.append(escaped)
            case 0x62: result.append(0x08)
            case 0x66: result.append(0x0c)
            case 0x6e: result.append(0x0a)
            case 0x72: result.append(0x0d)
            case 0x74: result.append(0x09)
            case 0x75:
                let first = try parseHexUnit()
                let scalar: UInt32
                if (0xd800...0xdbff).contains(first) {
                    guard consume(0x5c), consume(0x75) else { throw ProtocolError.invalidMessage }
                    let second = try parseHexUnit()
                    guard (0xdc00...0xdfff).contains(second) else { throw ProtocolError.invalidMessage }
                    scalar = 0x10000 + (first - 0xd800) * 0x400 + second - 0xdc00
                } else {
                    guard !(0xdc00...0xdfff).contains(first) else { throw ProtocolError.invalidMessage }
                    scalar = first
                }
                guard let unicode = Unicode.Scalar(scalar) else { throw ProtocolError.invalidMessage }
                result.append(contentsOf: String(unicode).utf8)
            default: throw ProtocolError.invalidMessage
            }
        }
        throw ProtocolError.invalidMessage
    }

    mutating func parseHexUnit() throws -> UInt32 {
        var value: UInt32 = 0
        for _ in 0..<4 {
            guard offset < bytes.count else { throw ProtocolError.invalidMessage }
            let byte = bytes[offset]
            offset += 1
            let digit: UInt32
            switch byte {
            case 0x30...0x39: digit = UInt32(byte - 0x30)
            case 0x41...0x46: digit = UInt32(byte - 0x41 + 10)
            case 0x61...0x66: digit = UInt32(byte - 0x61 + 10)
            default: throw ProtocolError.invalidMessage
            }
            value = value * 16 + digit
        }
        return value
    }

    mutating func parseNumber() throws -> Double {
        let start = offset
        _ = consume(0x2d)
        if !consume(0x30) {
            guard offset < bytes.count, (0x31...0x39).contains(bytes[offset]) else { throw ProtocolError.invalidMessage }
            while offset < bytes.count, (0x30...0x39).contains(bytes[offset]) { offset += 1 }
        }
        if consume(0x2e) { try consumeDigits() }
        if consume(0x65) || consume(0x45) {
            if !consume(0x2b) { _ = consume(0x2d) }
            try consumeDigits()
        }
        guard let value = Double(String(decoding: bytes[start..<offset], as: UTF8.self)), value.isFinite else {
            throw ProtocolError.invalidMessage
        }
        return value
    }

    mutating func consumeDigits() throws {
        let start = offset
        while offset < bytes.count, (0x30...0x39).contains(bytes[offset]) { offset += 1 }
        guard offset > start else { throw ProtocolError.invalidMessage }
    }

    mutating func consumeLiteral(_ literal: [UInt8]) throws {
        guard bytes[offset...].starts(with: literal) else { throw ProtocolError.invalidMessage }
        offset += literal.count
    }

    mutating func consume(_ byte: UInt8) -> Bool {
        guard offset < bytes.count, bytes[offset] == byte else { return false }
        offset += 1
        return true
    }

    mutating func skipWhitespace() {
        while offset < bytes.count, [0x20, 0x09, 0x0a, 0x0d].contains(bytes[offset]) { offset += 1 }
    }
}

import Foundation

public enum ValidationResult: Equatable, Sendable {
    case valid(JSONValue)
    case invalid(ProtocolError)

    /// Invalid responses contain only a code, never a copy or description of input.
    public var jsonValue: JSONValue {
        switch self {
        case .valid(let message): return .object(["valid": .bool(true), "message": message])
        case .invalid(let error): return .object(["valid": .bool(false), "code": .string(error.code)])
        }
    }

    public func encodedLine() throws -> Data {
        var data = try jsonValue.canonicalData()
        data.append(0x0a)
        return data
    }
}

/// Bounded, recovering NDJSON validation for the standalone checker, not a recorder.
/// One response per input line; errors do not prevent validating subsequent lines.
/// The 65,536-byte budget includes LF (and CR when present), like FrameDecoder in TS.
/// A nonempty unterminated line at EOF is invalid, even if it contains valid JSON.
public struct JSONLValidator: Sendable {
    private let validator: ContractValidator
    private var pending = Data()
    private var discardingOversizeLine = false

    public init(validator: ContractValidator) { self.validator = validator }

    /// Exposed to make the hard memory bound independently testable.
    public var bufferedByteCount: Int { pending.count }

    public mutating func push(_ chunk: Data, emit: (ValidationResult) throws -> Void) rethrows {
        for byte in chunk {
            if byte == 0x0a {
                let result: ValidationResult
                if discardingOversizeLine || pending.count + 1 > ContractLimits.maxFrameBytes {
                    result = .invalid(.frameTooLarge)
                } else {
                    do { result = .valid(try validator.decodeFrame(pending)) }
                    catch let error as ProtocolError { result = .invalid(error) }
                    catch { result = .invalid(.invalidMessage) }
                }
                pending.removeAll(keepingCapacity: true)
                discardingOversizeLine = false
                try emit(result)
            } else if !discardingOversizeLine {
                if pending.count == ContractLimits.maxFrameBytes {
                    pending.removeAll(keepingCapacity: true)
                    discardingOversizeLine = true
                } else {
                    pending.append(byte)
                }
            }
        }
    }

    public mutating func finish(emit: (ValidationResult) throws -> Void) rethrows {
        let result: ValidationResult?
        if discardingOversizeLine { result = .invalid(.frameTooLarge) }
        else if !pending.isEmpty { result = .invalid(.invalidMessage) }
        else { result = nil }
        pending.removeAll(keepingCapacity: false)
        discardingOversizeLine = false
        if let result { try emit(result) }
    }
}

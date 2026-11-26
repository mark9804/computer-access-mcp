import Foundation
import HistoryContract

// This executable only validates stdin. It cannot read or operate any desktop.
let arguments = Array(CommandLine.arguments.dropFirst())
guard arguments.isEmpty || arguments == ["--validate-jsonl"] else {
    FileHandle.standardError.write(Data("usage: contract-check [--validate-jsonl]\n".utf8))
    exit(64)
}

func emit(_ result: ValidationResult) throws {
    try FileHandle.standardOutput.write(contentsOf: result.encodedLine())
}

do {
    var stream = JSONLValidator(validator: try ContractValidator())
    while let chunk = try FileHandle.standardInput.read(upToCount: 8_192), !chunk.isEmpty {
        try stream.push(chunk, emit: emit)
    }
    try stream.finish(emit: emit)
} catch {
    // Never print Foundation errors: they can include file paths or input fragments.
    FileHandle.standardError.write(Data("contract-check: I/O or contract initialization failure\n".utf8))
    exit(74)
}

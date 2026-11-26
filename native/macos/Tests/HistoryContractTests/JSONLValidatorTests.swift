import Foundation
import XCTest
@testable import HistoryContract

final class JSONLValidatorTests: XCTestCase {
    func testChunkingCRLFAndOneResponsePerLine() throws {
        let validator = try ContractValidator()
        var stream = JSONLValidator(validator: validator)
        let expected = observation(payload: snapshot(text: "中文🙂e\u{301}"))
        var bytes = try expected.canonicalData()
        bytes.append(contentsOf: [13, 10])
        bytes.append(Data("not-json\n\n".utf8))
        bytes.append(try validator.encodeFrame(hello()))
        var results: [ValidationResult] = []
        // Split through every UTF-8 sequence, JSON escape, and CRLF boundary.
        for byte in bytes { stream.push(Data([byte])) { results.append($0) } }
        stream.finish { results.append($0) }
        XCTAssertEqual(results, [.valid(expected), .invalid(.invalidMessage), .invalid(.invalidMessage), .valid(hello())])
        XCTAssertEqual(stream.bufferedByteCount, 0)
    }

    func testEOFIsSafeAndRejectsUnterminatedFrames() throws {
        let validator = try ContractValidator()
        var stream = JSONLValidator(validator: validator)
        var results: [ValidationResult] = []
        stream.finish { results.append($0) }
        XCTAssertTrue(results.isEmpty)
        stream.push(try hello().canonicalData()) { results.append($0) }
        XCTAssertTrue(results.isEmpty)
        stream.finish { results.append($0) }
        XCTAssertEqual(results, [.invalid(.invalidMessage)])
        stream.finish { results.append($0) }
        XCTAssertEqual(results.count, 1)
        stream.push(try validator.encodeFrame(hello())) { results.append($0) }
        stream.finish { results.append($0) }
        XCTAssertEqual(results.last, .valid(hello()))
    }

    func testLFCountsTowardExactFrameBudget() throws {
        let validator = try ContractValidator()
        let payload = try hello().canonicalData()
        var exact = payload
        exact.append(Data(repeating: 32, count: ContractLimits.maxFrameBytes - payload.count - 1))
        exact.append(10)
        XCTAssertEqual(exact.count, ContractLimits.maxFrameBytes)
        var tooLong = payload
        tooLong.append(Data(repeating: 32, count: ContractLimits.maxFrameBytes - payload.count))
        tooLong.append(10)
        var stream = JSONLValidator(validator: validator)
        var results: [ValidationResult] = []
        stream.push(exact) { results.append($0) }
        stream.push(tooLong) { results.append($0) }
        stream.push(try validator.encodeFrame(hello())) { results.append($0) }
        stream.finish { results.append($0) }
        XCTAssertEqual(results, [.valid(hello()), .invalid(.frameTooLarge), .valid(hello())])
    }

    func testOversizeLineHasBoundedMemoryAndRecoversWithoutEcho() throws {
        let validator = try ContractValidator()
        var stream = JSONLValidator(validator: validator)
        var results: [ValidationResult] = []
        for _ in 0..<100 {
            stream.push(Data(repeating: 120, count: 8192)) { results.append($0) }
            XCTAssertLessThanOrEqual(stream.bufferedByteCount, ContractLimits.maxFrameBytes)
        }
        XCTAssertTrue(results.isEmpty)
        stream.push(Data("discarded-private-body\n".utf8)) { results.append($0) }
        stream.push(try validator.encodeFrame(hello())) { results.append($0) }
        stream.finish { results.append($0) }
        XCTAssertEqual(results, [.invalid(.frameTooLarge), .valid(hello())])
        XCTAssertEqual(String(decoding: try results[0].encodedLine(), as: UTF8.self), "{\"code\":\"frame-too-large\",\"valid\":false}\n")
        stream.push(Data(repeating: 120, count: ContractLimits.maxFrameBytes + 1)) { results.append($0) }
        stream.finish { results.append($0) }
        XCTAssertEqual(results.last, .invalid(.frameTooLarge))
    }

    func testInvalidUTF8ThenValidLine() throws {
        let validator = try ContractValidator()
        var stream = JSONLValidator(validator: validator)
        var results: [ValidationResult] = []
        stream.push(Data([0xff, 10])) { results.append($0) }
        stream.push(try validator.encodeFrame(hello())) { results.append($0) }
        XCTAssertEqual(results, [.invalid(.invalidMessage), .valid(hello())])
    }

    func testCLIValidAndInvalidLinesExitZeroAndProtocolOnly() throws {
        let validator = try ContractValidator()
        var input = try validator.encodeFrame(observation())
        input.append(Data("{\"protocolVersion\":2,\"body\":\"never-echo-synthetic-body\"}\nnot-json\n".utf8))
        let result = try runCLI(arguments: ["--validate-jsonl"], input: input)
        XCTAssertEqual(result.exit, 0)
        XCTAssertTrue(result.stderr.isEmpty)
        let lines = result.stdout.split(separator: 10)
        XCTAssertEqual(lines.count, 3)
        XCTAssertEqual(try JSONValue.parse(Data(lines[0])), ValidationResult.valid(observation()).jsonValue)
        XCTAssertEqual(try JSONValue.parse(Data(lines[1])), ValidationResult.invalid(.unsupportedVersion).jsonValue)
        XCTAssertEqual(try JSONValue.parse(Data(lines[2])), ValidationResult.invalid(.invalidMessage).jsonValue)
        XCTAssertFalse(String(decoding: result.stdout, as: UTF8.self).contains("never-echo"))
    }

    func testCLIDefaultEOFAndBadArguments() throws {
        let empty = try runCLI(arguments: [], input: Data())
        XCTAssertEqual(empty.exit, 0)
        XCTAssertTrue(empty.stdout.isEmpty)
        XCTAssertTrue(empty.stderr.isEmpty)
        let partial = try runCLI(arguments: [], input: hello().canonicalData())
        XCTAssertEqual(partial.exit, 0)
        XCTAssertEqual(try JSONValue.parse(partial.stdout), ValidationResult.invalid(.invalidMessage).jsonValue)
        for arguments in [["run"], ["--validate-jsonl", "extra"], ["--help"]] {
            let invalid = try runCLI(arguments: arguments, input: Data())
            XCTAssertEqual(invalid.exit, 64)
            XCTAssertTrue(invalid.stdout.isEmpty)
            XCTAssertEqual(String(decoding: invalid.stderr, as: UTF8.self), "usage: contract-check [--validate-jsonl]\n")
        }
    }

    private func runCLI(arguments: [String], input: Data) throws -> (exit: Int32, stdout: Data, stderr: Data) {
        // swift test builds the checker product in the same configuration directory.
        var directory = Bundle(for: JSONLValidatorTests.self).bundleURL
        var executable: URL?
        for _ in 0..<6 {
            let candidate = directory.appendingPathComponent("contract-check")
            if FileManager.default.isExecutableFile(atPath: candidate.path) { executable = candidate; break }
            directory.deleteLastPathComponent()
        }
        let process = Process()
        process.executableURL = try XCTUnwrap(executable, "contract-check must be built alongside the tests")
        process.arguments = arguments
        let stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        try stdin.fileHandleForWriting.write(contentsOf: input)
        try stdin.fileHandleForWriting.close()
        let output = try stdout.fileHandleForReading.readToEnd() ?? Data()
        let diagnostics = try stderr.fileHandleForReading.readToEnd() ?? Data()
        process.waitUntilExit()
        return (process.terminationStatus, output, diagnostics)
    }
}

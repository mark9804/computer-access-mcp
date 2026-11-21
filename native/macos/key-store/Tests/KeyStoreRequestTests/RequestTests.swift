import Foundation
import XCTest
@testable import KeyStoreRequest

final class RequestTests: XCTestCase {
    private let valid = Data("{\"version\":1,\"command\":\"get\",\"service\":\"synthetic.service\",\"account\":\"synthetic.account\"}\n".utf8)

    private func pipe(_ data: Data) throws -> FileHandle {
        let pipe = Pipe()
        try pipe.fileHandleForWriting.write(contentsOf: data)
        try pipe.fileHandleForWriting.close()
        return pipe.fileHandleForReading
    }

    func testFoundationEOFIsNilNotAnEmptyChunk() throws {
        let input = try pipe(valid)
        defer { try? input.close() }
        XCTAssertEqual(try input.read(upToCount: 2049), valid)
        XCTAssertNil(try input.read(upToCount: 2049))
    }

    func testCompleteGetCreateAndDeleteFollowedByEOFAreAccepted() throws {
        for command in ["get", "create", "delete"] {
            let bytes = Data(String(decoding: valid, as: UTF8.self).replacingOccurrences(of: "get", with: command).utf8)
            let input = try pipe(bytes)
            defer { try? input.close() }
            let request = try KeyStoreRequest.read(arguments: ["helper", "--command", command], from: input)
            XCTAssertEqual(request.command, command)
            XCTAssertEqual(request.service, "synthetic.service")
        }
    }

    func testUnknownArgumentsRejectBeforeReading() throws {
        let input = try pipe(valid)
        defer { try? input.close() }
        XCTAssertThrowsError(try KeyStoreRequest.read(arguments: ["helper"], from: input))
        XCTAssertEqual(try input.read(upToCount: 2049), valid)
    }

    func testMismatchMalformedExtraKeyAndOversizedReject() throws {
        let cases = [
            Data(),
            Data("not-json".utf8),
            Data("{\"version\":1}".utf8),
            Data(repeating: 32, count: 2049),
            Data("{\"version\":1,\"command\":\"get\",\"service\":\"s\",\"account\":\"a\",\"extra\":true}".utf8),
        ]
        for data in cases {
            let input = try pipe(data)
            defer { try? input.close() }
            XCTAssertThrowsError(try KeyStoreRequest.read(arguments: ["helper", "--command", "get"], from: input))
        }
        let mismatch = try pipe(valid)
        defer { try? mismatch.close() }
        XCTAssertThrowsError(try KeyStoreRequest.read(arguments: ["helper", "--command", "create"], from: mismatch))
    }

    func testIOErrorDoesNotBecomeEOFSuccess() throws {
        let input = try pipe(valid)
        try input.close()
        XCTAssertThrowsError(try KeyStoreRequest.read(arguments: ["helper", "--command", "get"], from: input))
    }
}

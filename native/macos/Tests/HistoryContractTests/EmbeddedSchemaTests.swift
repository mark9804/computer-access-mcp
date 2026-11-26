import XCTest
import Foundation
@testable import HistoryContract

final class EmbeddedSchemaTests: XCTestCase {
    func testEmbeddedSchemaInitializesRepeatedlyWithoutExternalBundle() throws {
        let first = try ContractValidator()
        let second = try ContractValidator()
        let hello = Data(#"{"protocolVersion":1,"type":"hello","instanceId":"standalone-test","capabilities":[],"maxFrameBytes":65536}"#.utf8)
        let firstDecoded = try first.decodeFrame(hello)
        let secondDecoded = try second.decodeFrame(hello)
        XCTAssertEqual(firstDecoded, secondDecoded)
        XCTAssertEqual(firstDecoded["instanceId"], .string("standalone-test"))
    }

    func testJSONParserRejectsOverflowNonFiniteNumbers() {
        let overflow = Data(#"{"protocolVersion":1,"value":1e500}"#.utf8)
        XCTAssertThrowsError(try JSONValue.parse(overflow)) { error in
            XCTAssertEqual(error as? ProtocolError, .invalidMessage)
        }
    }
}

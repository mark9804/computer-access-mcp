import XCTest
import Foundation
@testable import CollectorCore

final class ReadTicketDebugTests: XCTestCase {
    func testOldReadTicketOmissionDecodesAndDebugIdDoesNotEnterPublicFrames() throws {
        let h = Harness(); h.start()
        var ticket = try XCTUnwrap(h.engine.outstanding)
        let firstId = ticket.debugRequestId
        XCTAssertEqual(firstId, CollectorDebugTrace.enabled ? 1 : nil)
        let oldData = try JSONSerialization.data(withJSONObject: try JSONSerialization.jsonObject(with: JSONEncoder().encode(ticket)))
        var old = try XCTUnwrap(JSONSerialization.jsonObject(with: oldData) as? [String: Any])
        old.removeValue(forKey: "debugRequestId")
        XCTAssertNil(try JSONDecoder().decode(ReadTicket.self, from: JSONSerialization.data(withJSONObject: old)).debugRequestId)
        ticket.debugRequestId = 9_007_199_254_740_991
        XCTAssertEqual(try JSONDecoder().decode(ReadTicket.self, from: JSONEncoder().encode(ticket)).debugRequestId, ticket.debugRequestId)
        h.engine.complete(h.goodResult(ticket))
        h.clock.advance(200); h.engine.tick()
        let second = try XCTUnwrap(h.engine.outstanding)
        XCTAssertEqual(second.debugRequestId, CollectorDebugTrace.enabled ? 2 : nil)
        h.control("pause"); h.control("resume"); h.clock.advance(51); h.engine.tick()
        XCTAssertEqual(h.engine.outstanding?.debugRequestId, CollectorDebugTrace.enabled ? 3 : nil, "Never reuse on pause/resume")
        for frame in h.frames {
            let text = try XCTUnwrap(String(data: frame.canonicalData(), encoding: .utf8))
            XCTAssertFalse(text.contains("debugRequestId")); XCTAssertFalse(text.contains(ticket.token))
        }
    }
}

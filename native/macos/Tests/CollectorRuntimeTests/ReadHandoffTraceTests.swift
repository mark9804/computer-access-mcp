import XCTest
import Foundation
import Darwin
@testable import CollectorCore
@testable import CollectorRuntime

final class ReadHandoffTraceTests: XCTestCase {
    private func response() -> PendingReadResponseTrace {
        PendingReadResponseTrace(requestId: 7, readId: 3, deadlineMs: 1500, readMs: 1000,
            postReadPollMs: 20, encodeMs: 2, frameBytes: 10, readyMs: 1100)
    }
    func testPreparedResponseOnlyBecomesWrittenAfterEveryByteAndKeepsAttemptStalls() throws {
        var trace = SessionOutputTrace()
        trace.replace(response()); XCTAssertTrue(trace.completed(at: 1100).isEmpty)
        trace.polledBeforeWrite(elapsedMs: 7)
        trace.attemptedWrite(at: 1110, written: -1) // EAGAIN/EINTR, not a successful first write.
        trace.attemptedWrite(at: 1113, written: 4)
        XCTAssertTrue(trace.completed(at: 1113).isEmpty)
        trace.attemptedWrite(at: 1120, written: 0)
        trace.attemptedWrite(at: 1130, written: 6)
        let records = trace.completed(at: 1131)
        XCTAssertEqual(records.map(\.code), ["session-response-ready", "session-response-written"])
        XCTAssertEqual(records[0].numbers["readyMs"], 1100)
        XCTAssertEqual(records[0].numbers["readMs"], 1000)
        let written = records[1].numbers
        XCTAssertEqual(written["firstWriteMs"], 1110, "First attempt, not first success")
        XCTAssertEqual(written["writeCalls"], 4); XCTAssertEqual(written["writeStalls"], 2)
        XCTAssertEqual(written["preWritePollMs"], 7); XCTAssertEqual(written["elapsedMs"], 31)
        XCTAssertEqual(written["readRemainingMs"], 369); XCTAssertEqual(written["frameBytes"], 10)
        XCTAssertNil(trace.pending); XCTAssertTrue(trace.completed(at: 1132).isEmpty)
    }
    func testReplacingPendingResponseWithNoticeClearsAllReadTraceEvenAfterAttempt() {
        var trace = SessionOutputTrace()
        trace.replace(response()); trace.polledBeforeWrite(elapsedMs: 9)
        trace.attemptedWrite(at: 1110, written: -1)
        trace.replace() // The production ACK/dirty/secure/fatal replacement calls this.
        trace.attemptedWrite(at: 1111, written: 10)
        XCTAssertNil(trace.pending); XCTAssertTrue(trace.completed(at: 1112).isEmpty)
        trace.replace(response()); XCTAssertEqual(trace.pending?.writeCalls, 0)
        XCTAssertNil(trace.pending?.firstWriteMs)
    }
    func testAnonymousNonblockingPipePartialWriteAndWouldBlockAreCountedWithoutEarlyCompletion() throws {
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&fds), 0); defer { close(fds[0]); close(fds[1]) }
        XCTAssertGreaterThanOrEqual(fcntl(fds[0], F_SETFL, O_NONBLOCK), 0)
        XCTAssertGreaterThanOrEqual(fcntl(fds[1], F_SETFL, O_NONBLOCK), 0)
        let filler = [UInt8](repeating: 120, count: 4096)
        var filled = 0
        while filled < 1_048_576 {
            let count = filler.withUnsafeBytes { Darwin.write(fds[1], $0.baseAddress, $0.count) }
            let error = errno
            if count > 0 { filled += count; continue }
            XCTAssertTrue(error == EAGAIN || error == EWOULDBLOCK); break
        }
        XCTAssertGreaterThan(filled, 0)
        var trace = SessionOutputTrace(); trace.replace(response())
        let blocked = filler.withUnsafeBytes { Darwin.write(fds[1], $0.baseAddress, 10) }
        let blockedError = errno
        XCTAssertEqual(blocked, -1); XCTAssertTrue(blockedError == EAGAIN || blockedError == EWOULDBLOCK)
        trace.attemptedWrite(at: 1110, written: blocked)
        XCTAssertTrue(trace.completed(at: 1111).isEmpty)
        var drained = [UInt8](repeating: 0, count: 8192)
        while Darwin.read(fds[0], &drained, drained.count) > 0 {}
        let first = filler.withUnsafeBytes { Darwin.write(fds[1], $0.baseAddress, 4) }
        trace.attemptedWrite(at: 1120, written: first); XCTAssertEqual(first, 4)
        XCTAssertTrue(trace.completed(at: 1120).isEmpty)
        let last = filler.withUnsafeBytes { Darwin.write(fds[1], $0.baseAddress, 6) }
        trace.attemptedWrite(at: 1130, written: last); XCTAssertEqual(last, 6)
        let records = trace.completed(at: 1131)
        XCTAssertEqual(records.last?.numbers["writeCalls"], 3)
        XCTAssertEqual(records.last?.numbers["writeStalls"], 1)
    }
    func testSnapshotsUseObservedLFAndCallbackTimesAndEveryFullJSONRecordFits512Bytes() throws {
        var worker = WorkerReadTrace(requestId: 7, deadlineMs: 1500, startedMs: 100, lastPollMs: 200)
        worker.polled(at: 450)
        let received = worker.received(childPid: 123, frameBytes: 19, frameReadyMs: 460, decodeMs: 3, dispatchStartedMs: 470)
        let dispatched = worker.dispatched(childPid: 123, dispatchStartedMs: 470, at: 510)
        XCTAssertEqual(received.numbers["frameReadyMs"], 460)
        XCTAssertEqual(received.numbers["dispatchStartedMs"], 470); XCTAssertEqual(received.numbers["pollGapMs"], 250)
        XCTAssertEqual(dispatched.numbers["elapsedMs"], 40, "Callback duration, not entire read")
        var output = SessionOutputTrace(); output.replace(response()); output.attemptedWrite(at: 1110, written: 10)
        var records = output.completed(at: 1120)
        records += [worker.requestWritten(childPid: 123, at: 120), received, dispatched,
            worker.cancelled(childPid: 123, at: 520, pendingBytes: 9, bufferBytes: 7),
            ReadHandoffRecord(code: "collector-loop-summary", numbers: ["elapsedMs": 1, "controlMs": 1, "tickMs": 1, "pollMs": 1, "flushMs": 1]),
            ReadHandoffRecord(code: "collector-poll-summary", numbers: ["elapsedMs": 1, "workerMs": 1, "activityMs": 1, "desktopMs": 1])]
        for record in records {
            let file = record.code.hasPrefix("session-") ? "SessionTransport.swift" : record.code == "collector-loop-summary" ? "main.swift" : record.code == "collector-poll-summary" ? "Environment.swift" : "Worker.swift"
            // Actual Foundation JSON encoding of the logger's complete envelope,
            // every numeric value at worst signed safe-int width, plus terminal LF.
            let value: [String: Any] = ["version": 1, "code": record.code, "pid": Int32.max,
                "timeMs": Int64(9_007_199_254_740_991), "monotonicMs": Int64(9_007_199_254_740_991),
                "file": file, "line": 9999, "numbers": record.numbers.mapValues { _ in Int64(-9_007_199_254_740_991) }, "flags": [String: Bool]()]
            let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
            XCTAssertLessThanOrEqual(data.count + 1, 512, record.code)
            let text = try XCTUnwrap(String(data: data, encoding: .utf8))
            XCTAssertFalse(text.contains("token")); XCTAssertFalse(text.contains("body"))
            XCTAssertFalse(text.contains("strings")); XCTAssertFalse(text.contains("argv"))
        }
    }
}

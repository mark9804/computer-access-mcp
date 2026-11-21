import Foundation
import CollectorCore

/// Content-free snapshots only. Emission is deliberately outside the original
/// stdout-drain / completion critical paths; record time is not observation time.
struct ReadHandoffRecord {
    let code: String
    let numbers: [String: Int64]
    func emit(file: StaticString = #fileID, line: UInt = #line) { CollectorDebugTrace.record(code, numbers: numbers, file: file, line: line) }
}

func handoffRequestId(_ ticket: ReadTicket) -> Int64? {
    guard let value = ticket.debugRequestId, (1...9_007_199_254_740_991).contains(value) else { return nil }
    return value
}

struct PendingReadResponseTrace {
    let requestId: Int64
    let readId: Int64
    let deadlineMs: Int64
    let readMs: Int64
    let postReadPollMs: Int64
    let encodeMs: Int64
    let frameBytes: Int64 // Includes the terminal LF, not just JSON.
    let readyMs: Int64 // Absolute monotonic snapshot after encoding + LF.
    var preWritePollMs: Int64 = 0
    var firstWriteMs: Int64? // Absolute first actual write ATTEMPT, even EAGAIN/EINTR.
    var writeCalls: Int64 = 0
    var writeStalls: Int64 = 0 // Retriable attempts with no positive progress.
    var writtenBytes: Int64 = 0
}

/// Optional (debug-only) state, never a transport queue or delivery decision.
/// Replacing an unsent read result with ACK/dirty/fatal/secure notices clears it.
struct SessionOutputTrace {
    private(set) var pending: PendingReadResponseTrace?
    mutating func replace(_ response: PendingReadResponseTrace? = nil) { pending = response }
    mutating func polledBeforeWrite(elapsedMs: Int64) {
        guard pending != nil, pending?.firstWriteMs == nil else { return }
        pending?.preWritePollMs += elapsedMs
    }
    mutating func attemptedWrite(at nowMs: Int64, written: Int) {
        guard pending != nil else { return }
        if pending?.firstWriteMs == nil { pending?.firstWriteMs = nowMs }
        pending?.writeCalls += 1
        if written > 0 { pending?.writtenBytes += Int64(written) }
        else { pending?.writeStalls += 1 }
    }
    mutating func completed(at nowMs: Int64) -> [ReadHandoffRecord] {
        guard let value = pending, value.writtenBytes == value.frameBytes, let firstWriteMs = value.firstWriteMs else { return [] }
        pending = nil
        return [
            ReadHandoffRecord(code: "session-response-ready", numbers: ["requestId": value.requestId, "readId": value.readId,
                "readRemainingMs": value.deadlineMs - value.readyMs, "readMs": value.readMs,
                "postReadPollMs": value.postReadPollMs, "encodeMs": value.encodeMs,
                "frameBytes": value.frameBytes, "readyMs": value.readyMs]),
            ReadHandoffRecord(code: "session-response-written", numbers: ["requestId": value.requestId, "readId": value.readId,
                "readRemainingMs": value.deadlineMs - nowMs, "elapsedMs": nowMs - value.readyMs,
                "preWritePollMs": value.preWritePollMs, "firstWriteMs": firstWriteMs,
                "writeCalls": value.writeCalls, "writeStalls": value.writeStalls, "frameBytes": value.frameBytes]),
        ]
    }
}

struct WorkerReadTrace {
    let requestId: Int64
    let deadlineMs: Int64
    let startedMs: Int64
    var lastPollMs: Int64
    var pollGapMs: Int64 = 0
    mutating func polled(at nowMs: Int64) { pollGapMs = max(0, nowMs - lastPollMs); lastPollMs = nowMs }
    func requestWritten(childPid: Int32, at nowMs: Int64) -> ReadHandoffRecord {
        ReadHandoffRecord(code: "worker-request-written", numbers: ["childPid": Int64(childPid), "requestId": requestId,
            "readRemainingMs": deadlineMs - nowMs, "elapsedMs": nowMs - startedMs, "requestWrittenMs": nowMs])
    }
    /// frameReadyMs is when the parent's existing splitter FIRST OBSERVES the LF,
    /// NOT kernel arrival / first byte. Dirty/ACK frames never use this record.
    func received(childPid: Int32, frameBytes: Int, frameReadyMs: Int64, decodeMs: Int64, dispatchStartedMs: Int64) -> ReadHandoffRecord {
        ReadHandoffRecord(code: "worker-response-received", numbers: ["childPid": Int64(childPid), "requestId": requestId,
            "readRemainingMs": deadlineMs - dispatchStartedMs, "frameBytes": Int64(frameBytes), "frameReadyMs": frameReadyMs,
            "decodeMs": decodeMs, "pollGapMs": pollGapMs, "dispatchStartedMs": dispatchStartedMs])
    }
    func dispatched(childPid: Int32, dispatchStartedMs: Int64, at nowMs: Int64) -> ReadHandoffRecord {
        ReadHandoffRecord(code: "worker-response-dispatched", numbers: ["childPid": Int64(childPid), "requestId": requestId,
            "readRemainingMs": deadlineMs - nowMs, "elapsedMs": nowMs - dispatchStartedMs])
    }
    func cancelled(childPid: Int32, at nowMs: Int64, pendingBytes: Int, bufferBytes: Int) -> ReadHandoffRecord {
        ReadHandoffRecord(code: "worker-read-cancelled", numbers: ["childPid": Int64(childPid), "requestId": requestId,
            "readRemainingMs": deadlineMs - nowMs, "pendingBytes": Int64(pendingBytes), "bufferBytes": Int64(bufferBytes),
            "pollGapMs": max(0, nowMs - lastPollMs)])
    }
}

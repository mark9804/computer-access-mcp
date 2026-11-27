import Foundation
import Darwin
import CollectorCore
import HistoryContract

// Private exit status, not the generic protocol/fault exit and not a receipt.
let sessionReadDeadlineExit: Int32 = 76

struct MenuActionPipeFrame: Codable {
    let menuAction: MenuActionRecord
}

/// Priority order for unsolicited worker frames: committed `menuAction` flushes
/// before `menuTracking` so Hide/Quit/app-switch clicks are never delayed behind
/// `{"menuTracking":false}`, followed by `submitDirty` and debounced `dirty`.
func nextSessionUnsolicitedFrame(
    takeMenuAction: () -> MenuActionRecord?,
    takeMenuTracking: () -> Bool?,
    takeSubmitDirty: () -> Bool,
    takeDirty: () -> Bool,
    nowMs: Int64,
    nextDirtyMs: inout Int64,
    debounceMs: Int
) -> Data? {
    if let record = takeMenuAction(),
       var encoded = try? JSONEncoder().encode(MenuActionPipeFrame(menuAction: record)),
       encoded.count < 65_500 {
        encoded.append(10)
        return encoded
    }
    if let tracking = takeMenuTracking() {
        return Data("{\"menuTracking\":\(tracking ? "true" : "false")}\n".utf8)
    }
    if takeSubmitDirty() {
        return Data("{\"submitDirty\":true}\n".utf8)
    }
    if nowMs >= nextDirtyMs, takeDirty() {
        nextDirtyMs = nowMs + Int64(max(50, debounceMs))
        return Data("{\"dirty\":true}\n".utf8)
    }
    return nil
}

/// Locked watchdog state is independent of the AX run loop. Input callbacks get
/// the same finite hard ceiling as explicit reads, even when provider IPC hangs.
enum SessionReadOperation: Int64 {
    case authority = 1, enablement, focusedReader, fieldGate, observerRemove, observerCreate, observerAdd
    case selection, surface, finalField, finalDesktop, inputBegin, inputDrain, windowAnchor, completed
}
final class WorkerDeadline {
    private let lock = NSLock()
    private var deadline: Int64
    private var stage: Int64 = 0
    private var inRequestDeadline = false
    private var readId: Int64 = 0
    private var operation: SessionReadOperation?
    private var operationStart: Int64 = 0
    private var index: Int64 = -1
    init(_ deadline: Int64) { self.deadline = deadline }
    func beginIdle(_ value: Int64, phase: Int64 = 0) {
        lock.lock(); defer { lock.unlock() }
        deadline = value; inRequestDeadline = false; stage = phase
        readId = 0; operation = nil; operationStart = 0; index = -1
    }
    func beginRequest(_ value: Int64) {
        lock.lock(); defer { lock.unlock() }
        deadline = value; inRequestDeadline = true; stage = 1
        readId = 0; operation = nil; operationStart = 0; index = -1
    }
    func phase(_ value: Int64) {
        lock.lock(); defer { lock.unlock() }
        stage = value; readId = 0; operation = nil; operationStart = 0; index = -1
    }
    func progress(readId: Int64, operation: SessionReadOperation, index: Int64, nowMs: Int64) {
        lock.lock(); defer { lock.unlock() }
        self.readId = readId; self.operation = operation; self.index = index; operationStart = nowMs
    }
    func watchdogSnapshot(_ now: Int64) -> (expired: Bool, phase: Int64, remaining: Int64, readId: Int64, operation: Int64, elapsedMs: Int64, index: Int64, inRequestDeadline: Bool) {
        lock.lock(); defer { lock.unlock() }
        return (now >= deadline, stage, deadline - now, readId, operation?.rawValue ?? 0, operation == nil ? 0 : max(0, now - operationStart), index, inRequestDeadline)
    }
    func snapshot(_ now: Int64) -> (expired: Bool, phase: Int64, remaining: Int64, readId: Int64, operation: Int64, elapsedMs: Int64, index: Int64) {
        let s = watchdogSnapshot(now)
        return (s.expired, s.phase, s.remaining, s.readId, s.operation, s.elapsedMs, s.index)
    }
}

func runSessionWorker(_ options: CLIOptions) -> Int32 {
    guard !options.fixture else { return 64 }
    WorkerProgress.attachFromEnvironment()
    defer { WorkerProgress.detach() }
    let parent = getppid(), clock = SystemCollectorClock()
    let watchdogDeadline = WorkerDeadline(clock.monotonicMs + 5_500)
    let watchdog = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
    watchdog.schedule(deadline: .now(), repeating: .milliseconds(20))
    watchdog.setEventHandler {
        if getppid() != parent { CollectorDebugTrace.record("session-parent-lost", stack: true); _exit(70) }
        let state = watchdogDeadline.watchdogSnapshot(clock.monotonicMs)
        if state.expired {
            // The background watchdog's own stack is not the blocked AX stack.
            // These fields describe the last entered main-thread operation.
            CollectorDebugTrace.record("session-watchdog", numbers: ["phase": state.phase, "readRemainingMs": state.remaining,
                "readId": state.readId, "operation": state.operation, "elapsedMs": state.elapsedMs, "nodeIndex": state.index], stack: true)
            _exit(state.inRequestDeadline ? sessionReadDeadlineExit : 70)
        }
    }
    watchdog.resume()
    defer { watchdog.cancel() }
    let stdinFlags = fcntl(STDIN_FILENO, F_GETFL)
    if stdinFlags >= 0 { _ = fcntl(STDIN_FILENO, F_SETFL, stdinFlags | O_NONBLOCK) }
    let stdoutFlags = fcntl(STDOUT_FILENO, F_GETFL)
    if stdoutFlags >= 0 { _ = fcntl(STDOUT_FILENO, F_SETFL, stdoutFlags | O_NONBLOCK) }
    var bytes = Data(), output = Data()
    var outputTrace = SessionOutputTrace()
    var deferredResponseTrace: [ReadHandoffRecord] = [] // At most one ready/written pair.
    var initial = true
    var policy: CapturePolicy?
    var epoch: Int64?
    var revision: Int64?
    var idleUntil = clock.monotonicMs + 5_000
    let session = AXWorkerSession()
    if CollectorDebugTrace.enabled {
        session.debugProgress = { readId, operation, index in
            watchdogDeadline.progress(readId: readId, operation: operation, index: index, nowMs: clock.monotonicMs)
        }
    }
    var nextDirty = Int64(0)
    var retireAfterOutput = false
    var retirementStarted: Int64?
    var fatalSent = false
    var secureSent = false
    let launchToken = ProcessInfo.processInfo.environment["DSH_COLLECTOR_WORKER_TOKEN"] ?? ""
    while getppid() == parent, clock.monotonicMs < idleUntil {
        watchdogDeadline.beginIdle(clock.monotonicMs + 5_500)
        var chunk = [UInt8](repeating: 0, count: 4096)
        let count = Darwin.read(STDIN_FILENO, &chunk, chunk.count)
        let readError = errno
        if count == 0 { return 0 }
        if count < 0 && readError != EAGAIN && readError != EWOULDBLOCK && readError != EINTR { CollectorDebugTrace.record("session-pipe-read", numbers: ["errno": Int64(readError)], stack: true); return 74 }
        if count > 0 {
            guard bytes.count + count <= 65_536 else { return 64 }
            bytes.append(contentsOf: chunk.prefix(count))
        }
        if !deferredResponseTrace.isEmpty {
            // The original outer watchdog reset already ran. Only emit after an
            // existing no-data read, never before a newly received request/ACK.
            // Busy ingress drops the optional pair instead of adding a queue.
            if count < 0, readError == EAGAIN || readError == EWOULDBLOCK, bytes.isEmpty {
                for record in deferredResponseTrace { record.emit() }
            }
            deferredResponseTrace.removeAll(keepingCapacity: true)
        }
        if output.isEmpty, !retireAfterOutput, let newline = bytes.firstIndex(of: 10) {
            let frame = Data(bytes[..<newline]); bytes.removeSubrange(...newline)
            if let command = try? JSONValue.parse(frame), let retireToken = command["retire"]?.stringValue {
                guard command["sessionToken"] == .string(launchToken), retireToken.count == 36 else { return 64 }
                WorkerProgress.finishRequest()
                WorkerProgress.stage(operation: 22)
                retirementStarted = clock.monotonicMs
                // Extend idle deadline so partial retire ACK writes near the 60s
                // idle edge are never truncated before flushing to the parent.
                idleUntil = max(idleUntil, clock.monotonicMs + 5_000)
                CollectorDebugTrace.record("session-retire-received")
                let healthy = session.retireHealthy()
                CollectorDebugTrace.record("session-retire", numbers: ["elapsedMs": clock.monotonicMs - retirementStarted!], flags: ["healthy": healthy], stack: !healthy)
                let ack = JSONValue.object(["retired": .string(retireToken), "sessionToken": .string(launchToken), "inputHealthy": .bool(healthy)])
                guard var encoded = try? ack.canonicalData() else { return 70 }
                encoded.append(10); output = encoded; outputTrace.replace(); retireAfterOutput = true
            } else {
            guard let json = try? JSONValue.parse(frame),
                  let request = try? JSONDecoder().decode(ReadTicket.self, from: json.canonicalData()),
                  !initial || request.token == ProcessInfo.processInfo.environment["DSH_COLLECTOR_WORKER_TOKEN"],
                  request.policy.enabled, request.policy.hasValidTextSettings, request.policy.usesSessionWorker,
                  (1...8192).contains(request.policy.maxTextCodeUnits),
                  request.deadlineMonotonicMs > clock.monotonicMs, request.deadlineMonotonicMs - clock.monotonicMs <= 5_000,
                  policy == nil || policy == request.policy, epoch == nil || epoch == request.captureEpoch,
                  revision == nil || revision == request.policyRevision else { CollectorDebugTrace.record("session-request-invalid", stack: true); return 64 }
            initial = false; policy = request.policy; epoch = request.captureEpoch; revision = request.policyRevision
            watchdogDeadline.beginRequest(request.deadlineMonotonicMs)
            let debugRequestId = CollectorDebugTrace.enabled ? handoffRequestId(request) : nil
            WorkerProgress.beginRequest(requestId: debugRequestId, deadlineMs: request.deadlineMonotonicMs)
            let readStarted = clock.monotonicMs
            var result = session.read(request)
            let readEnded = debugRequestId == nil ? nil : clock.monotonicMs
            watchdogDeadline.phase(2)
            WorkerProgress.stage(operation: 17)
            session.poll()
            let postReadPollEnded = debugRequestId == nil ? nil : clock.monotonicMs
            if session.secureInputDetected {
                result = ReadResult(token: request.token, reason: "secure-input-active", captureStartMs: clock.unixMs, captureEndMs: clock.unixMs)
            }
            if clock.monotonicMs - readStarted > 500 || request.deadlineMonotonicMs - clock.monotonicMs < 100 {
                var numbers = ["elapsedMs": clock.monotonicMs - readStarted, "readRemainingMs": request.deadlineMonotonicMs - clock.monotonicMs]
                if let debugRequestId { numbers["requestId"] = debugRequestId }
                CollectorDebugTrace.record("session-read-end", numbers: numbers)
            }
            guard clock.monotonicMs < request.deadlineMonotonicMs else {
                CollectorDebugTrace.record("session-read-deadline", stack: true)
                return session.inputFailure == nil ? sessionReadDeadlineExit : 70
            }
            guard getppid() == parent else { CollectorDebugTrace.record("session-parent-lost", stack: true); return 70 }
            watchdogDeadline.phase(2)
            let encodeStarted = debugRequestId == nil ? nil : clock.monotonicMs
            WorkerProgress.stage(operation: 18)
            guard var encoded = try? JSONEncoder().encode(result), encoded.count < 65_500 else { CollectorDebugTrace.record("session-response-encode", stack: true); return 70 }
            encoded.append(10); output = encoded
            if let debugRequestId, let readEnded, let postReadPollEnded, let encodeStarted {
                let readyMs = clock.monotonicMs
                outputTrace.replace(PendingReadResponseTrace(requestId: debugRequestId, readId: session.debugReadId,
                    deadlineMs: request.deadlineMonotonicMs, readMs: readEnded - readStarted,
                    postReadPollMs: postReadPollEnded - readEnded, encodeMs: readyMs - encodeStarted,
                    frameBytes: Int64(encoded.count), readyMs: readyMs))
            } else { outputTrace.replace() }
            idleUntil = clock.monotonicMs + 60_000
            }
        }
        watchdogDeadline.phase(3)
        if !retireAfterOutput {
            WorkerProgress.stage(operation: 19)
            let pollStarted = clock.monotonicMs
            session.poll()
            let elapsed = clock.monotonicMs - pollStarted
            outputTrace.polledBeforeWrite(elapsedMs: elapsed)
            if elapsed > 100 { CollectorDebugTrace.record("session-idle-poll-slow", numbers: ["elapsedMs": elapsed]) }
        }
        if let failure = session.inputFailure, !fatalSent, !retireAfterOutput {
            // Fatal input listener boundaries must never inherit a short request
            // deadline (or exit 76) and must survive the 60s idle edge during write.
            watchdogDeadline.beginIdle(clock.monotonicMs + 5_500)
            idleUntil = max(idleUntil, clock.monotonicMs + 5_000)
            CollectorDebugTrace.record("session-input-disabled", stack: true)
            let message = JSONValue.object(["inputDisabled": .string(failure)])
            guard var encoded = try? message.canonicalData() else { return 70 }
            encoded.append(10); output = encoded; outputTrace.replace(); fatalSent = true; retireAfterOutput = true
            WorkerProgress.finishRequest()
        }
        if session.secureInputDetected, !secureSent, !retireAfterOutput, session.inputFailure == nil {
            // No output bytes have been sent yet: replace any queued content with
            // a closed boundary notice. Partial frames drain below without pumping
            // callbacks, so a known boundary is never inserted into JSON mid-frame.
            watchdogDeadline.beginIdle(clock.monotonicMs + 5_500)
            WorkerProgress.finishRequest()
            output = Data("{\"secureInput\":true}\n".utf8); outputTrace.replace(); secureSent = true
        }
        if !retireAfterOutput, !session.secureInputDetected, !initial, output.isEmpty {
            if let frame = nextSessionUnsolicitedFrame(
                takeMenuAction: { session.takeNextMenuAction() },
                takeMenuTracking: { session.takeMenuTracking() },
                takeSubmitDirty: { session.takeSubmitDirty() },
                takeDirty: { session.takeDirty() },
                nowMs: clock.monotonicMs,
                nextDirtyMs: &nextDirty,
                debounceMs: policy?.debounceMs ?? 50
            ) {
                output = frame; outputTrace.replace()
            }
        }
        watchdogDeadline.phase(4)
        if !output.isEmpty {
            WorkerProgress.stage(operation: 20)
            let attemptedAt = outputTrace.pending == nil ? nil : clock.monotonicMs
            let (written, writeError): (Int, Int32) = output.withUnsafeBytes {
                let n = Darwin.write(STDOUT_FILENO, $0.baseAddress, $0.count)
                return (n, errno)
            }
            if let attemptedAt { outputTrace.attemptedWrite(at: attemptedAt, written: written) }
            if written > 0 { output.removeFirst(written) }
            else if written < 0 && writeError != EINTR && writeError != EAGAIN && writeError != EWOULDBLOCK { CollectorDebugTrace.record("session-pipe-write", numbers: ["errno": Int64(writeError)], stack: true); return 74 }
            if output.isEmpty {
                watchdogDeadline.beginIdle(clock.monotonicMs + 5_500)
                if outputTrace.pending != nil {
                    // Snapshot only; emit after the original next-outer watchdog reset.
                    deferredResponseTrace = outputTrace.completed(at: clock.monotonicMs)
                    WorkerProgress.finishRequest()
                }
            }
        }
        if retireAfterOutput {
            if output.isEmpty {
                if let retirementStarted {
                    CollectorDebugTrace.record("session-retire-written", numbers: ["elapsedMs": clock.monotonicMs - retirementStarted, "pendingBytes": 0])
                    // The listener is stopped and local observer source detached.
                    // Do not release retained AX handles or run process teardown
                    // before the parent can ACK+reap this exact child.
                    withExtendedLifetime(session) { _exit(0) }
                }
                return 0 // Unsolicited fatal frame retains its existing failure path.
            }
            // A partial ACK must never pump input/observer callbacks after sealing.
            // Wait only for pipe writability, not AX sources or input timers.
            // This wait is bounded; the original parent retirement deadline wins.
            var writable = pollfd(fd: STDOUT_FILENO, events: Int16(POLLOUT), revents: 0)
            _ = Darwin.poll(&writable, 1, 10)
            continue
        }
        if !output.isEmpty {
            // Once a nonblocking write starts a frame, finish it without running
            // input/AX callbacks or accepting another request. The watchdog/parent
            // still bound this wait; do not truncate or splice NDJSON frames.
            var writable = pollfd(fd: STDOUT_FILENO, events: Int16(POLLOUT), revents: 0)
            while !output.isEmpty, getppid() == parent {
                _ = Darwin.poll(&writable, 1, 10)
                let attemptedAt = outputTrace.pending == nil ? nil : clock.monotonicMs
                let (written, writeError): (Int, Int32) = output.withUnsafeBytes {
                    let n = Darwin.write(STDOUT_FILENO, $0.baseAddress, $0.count)
                    return (n, errno)
                }
                if let attemptedAt { outputTrace.attemptedWrite(at: attemptedAt, written: written) }
                if written > 0 { output.removeFirst(written) }
                else if written < 0 && writeError != EINTR && writeError != EAGAIN && writeError != EWOULDBLOCK { return 74 }
            }
            if output.isEmpty {
                watchdogDeadline.beginIdle(clock.monotonicMs + 5_500)
                if outputTrace.pending != nil {
                    deferredResponseTrace = outputTrace.completed(at: clock.monotonicMs)
                    WorkerProgress.finishRequest()
                }
            }
            continue
        }
        if !retireAfterOutput, !session.secureInputDetected, !initial, session.hasPendingMenuFrame {
            // Drain any remaining queued menu frame immediately without a 10ms runloop sleep.
            continue
        }
        // Own run loop is the only home of AXObserver and opt-in input callbacks.
        WorkerProgress.stage(operation: 21)
        watchdogDeadline.beginIdle(clock.monotonicMs + 5_500, phase: 5)
        let runLoopStarted = clock.monotonicMs
        _ = CFRunLoopRunInMode(.defaultMode, 0.01, true)
        let elapsed = clock.monotonicMs - runLoopStarted
        if elapsed > 100 { CollectorDebugTrace.record("session-runloop-slow", numbers: ["elapsedMs": elapsed]) }
    }
    return 0
}

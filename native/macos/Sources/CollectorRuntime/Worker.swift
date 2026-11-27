import Foundation
import Darwin
import CollectorCore
import HistoryContract
import AppKit
import ApplicationServices
import Carbon
import CCollectorSupport

final class WorkerManager {
    private var pid: pid_t = 0
    private var input: Int32 = -1
    private var output: Int32 = -1
    private var pending = Data()
    private var bytes = Data()
    private var ticket: ReadTicket?
    private var completingTicket: ReadTicket?
    private var readTrace: WorkerReadTrace?
    private var progressPage: WorkerProgressPage?
    private var session = false
    private var sessionPolicy: CapturePolicy?
    private var sessionEpoch: Int64?
    private var idleUntil: Int64 = 0
    private var launchToken: String?
    private var retirement: WorkerRetirement?
    private var timedOutWorker: TimedOutWorker?
    private var timeoutCleanup: ReadTimeoutCleanup = .ineligible
    var readyForRead: Bool { retirement == nil && timedOutWorker == nil && timeoutCleanup != .unconfirmed }
    var readDeadlineReached: (ReadTicket) -> Void = { _ in }
    var dirty: () -> Void = {}
    var submitDirty: () -> Void = {}
    var menuAction: (MenuActionRecord) -> Void = { _ in }
    var menuTracking: (Bool) -> Void = { _ in }
    var inputDisabled: (String) -> Void = { _ in }
    var secureInput: () -> Void = {}
    private let executable: String
    private let fixture: Bool
    private let scenario: String
    private let retirementNow: () -> Int64
    var completed: (ReadResult) -> Void = { _ in }
    init(executable: String, fixture: Bool, scenario: String,
         retirementNow: @escaping () -> Int64 = { SystemCollectorClock().monotonicMs }) {
        self.executable = executable; self.fixture = fixture; self.scenario = scenario
        self.retirementNow = retirementNow
    }
    private func failure(_ ticket: ReadTicket, _ reason: String = "read-error", diagnostic: ReadDiagnostic.Code? = nil) {
        let now = SystemCollectorClock().unixMs
        completed(ReadResult(token: ticket.token, reason: reason, diagnostic: diagnostic.map { ReadDiagnostic(code: $0) }, captureStartMs: now, captureEndMs: now))
    }
    private func beginReadTrace(_ ticket: ReadTicket) {
        guard CollectorDebugTrace.enabled, let requestId = handoffRequestId(ticket) else { readTrace = nil; return }
        let now = SystemCollectorClock().monotonicMs
        readTrace = WorkerReadTrace(requestId: requestId, deadlineMs: ticket.deadlineMonotonicMs, startedMs: now, lastPollMs: now)
    }
    func launch(_ ticket: ReadTicket) {
        guard readyForRead else { failure(ticket, "stale", diagnostic: .workerRetirementPending); return }
        if session, pid > 0, self.ticket == nil, sessionPolicy == ticket.policy, sessionEpoch == ticket.captureEpoch,
           var encoded = try? JSONEncoder().encode(ticket), encoded.count < 65_535 {
            encoded.append(10); self.ticket = ticket; pending = encoded; idleUntil = 0; beginReadTrace(ticket); poll(); return
        }
        cancel()
        guard readyForRead else { failure(ticket, "stale", diagnostic: .workerRetirementPending); return }
        timeoutCleanup = .ineligible
        session = ticket.policy.usesSessionWorker && !fixture
        sessionPolicy = ticket.policy; sessionEpoch = ticket.captureEpoch
        var childInput: [Int32] = [-1, -1]
        var childOutput: [Int32] = [-1, -1]
        guard pipe(&childInput) == 0 else { failure(ticket); return }
        guard pipe(&childOutput) == 0 else { close(childInput[0]); close(childInput[1]); failure(ticket); return }
        guard var encoded = try? JSONEncoder().encode(ticket), encoded.count < 65_535 else {
            for fd in childInput + childOutput { close(fd) }; failure(ticket); return
        }
        encoded.append(10)
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_adddup2(&actions, childInput[0], STDIN_FILENO)
        posix_spawn_file_actions_adddup2(&actions, childOutput[1], STDOUT_FILENO)
        if CollectorDebugTrace.enabled { posix_spawn_file_actions_adddup2(&actions, STDERR_FILENO, STDERR_FILENO) }
        else { posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) }
        for fd in childInput + childOutput { posix_spawn_file_actions_addclose(&actions, fd) }
        // A fixed child-only diagnostic FD is opt-in, never an inherited secret.
        // If either pipe uses the destination, disable diagnostics rather than
        // change the old pipe actions or accidentally close a duplicated end.
        var childProgress: WorkerProgressPage?
        if session, CollectorDebugTrace.enabled || ticket.policy.inputText == true,
           !(childInput + childOutput).contains(WorkerProgressPage.inheritedFD) {
            childProgress = WorkerProgressPage()
            if let page = childProgress,
               posix_spawn_file_actions_adddup2(&actions, page.descriptor, WorkerProgressPage.inheritedFD) != 0 {
                childProgress = nil
            }
        }
        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT))
        var argv = [executable, "--ax-worker", "--parent-pid", String(getpid()), "--worker-token", ticket.token]
        if fixture { argv += ["--synthetic", "yes", "--fixture-scenario", scenario] }
        if session { argv += ["--session-worker", "yes"] }
        // No inherited environment secrets. Launch identity is a one-shot token;
        // OS process parent and anonymous pipes establish this local relationship.
        let env = ["DSH_COLLECTOR_WORKER_TOKEN=\(ticket.token)", "PATH=/usr/bin:/bin"] +
            (CollectorDebugTrace.enabled ? ["DSH_COMPUTER_HISTORY_DEBUG=1"] : []) +
            (childProgress == nil ? [] : ["DSH_COMPUTER_HISTORY_PROGRESS_FD=\(WorkerProgressPage.inheritedFD)"])
        var cargs = argv.map { strdup($0) } + [nil]
        var cenv = env.map { strdup($0) } + [nil]
        defer { for value in cargs + cenv { if let value { free(value) } } }
        var child: pid_t = 0
        let result = posix_spawn(&child, executable, &actions, &attributes, &cargs, &cenv)
        close(childInput[0]); close(childOutput[1]); childProgress?.closeDescriptor()
        guard result == 0 else { close(childInput[1]); close(childOutput[0]); failure(ticket); return }
        CollectorDebugTrace.record("worker-launch", numbers: ["childPid": Int64(child), "readRemainingMs": ticket.deadlineMonotonicMs - SystemCollectorClock().monotonicMs], flags: ["session": session])
        pid = child; input = childInput[1]; output = childOutput[0]; launchToken = ticket.token
        progressPage = childProgress
        self.ticket = ticket; pending = encoded; bytes = Data(); beginReadTrace(ticket)
        let inputFlags = fcntl(input, F_GETFL)
        if inputFlags >= 0 { _ = fcntl(input, F_SETFL, inputFlags | O_NONBLOCK) }
        let outputFlags = fcntl(output, F_GETFL)
        if outputFlags >= 0 { _ = fcntl(output, F_SETFL, outputFlags | O_NONBLOCK) }
        poll()
    }
    func retire() {
        guard retirement == nil else { return } // Repeated A→B→C never replaces the handshake.
        guard pid > 0, session, sessionPolicy?.inputText == true, let launchToken else { cancel(); return }
        let now = retirementNow()
        let state = WorkerRetirement(pid: pid, sessionToken: launchToken, retireToken: UUID().uuidString,
            nowMs: now, readDeadlineMs: ticket?.deadlineMonotonicMs)
        let readRemainingMs = (ticket?.deadlineMonotonicMs ?? now) - now, inFlight = ticket != nil
        retirement = state; ticket = nil; readTrace = nil; idleUntil = 0
        let command = JSONValue.object(["retire": .string(state.retireToken), "sessionToken": .string(launchToken)])
        guard var encoded = try? command.canonicalData() else { faultInput(stage: "worker-retire-encode"); return }
        encoded.append(10); pending.append(encoded)
        CollectorDebugTrace.record("worker-retire-begin", numbers: ["childPid": Int64(pid),
            "remainingMs": state.deadlineMs - now, "readRemainingMs": readRemainingMs], flags: ["inFlight": inFlight])
    }
    private func faultInput(_ reason: String? = nil, stage: String = "worker-fault",
                            osError: Int32? = nil, file: StaticString = #fileID, line: UInt = #line) {
        let reason = reason ?? retirement?.failureReason.rawValue ?? "input-monitoring-unavailable"
        var numbers: [String: Int64] = ["childPid": Int64(pid), "pendingBytes": Int64(pending.count), "bufferBytes": Int64(bytes.count)]
        if let osError { numbers["errno"] = Int64(osError) }
        if let retirement { numbers["remainingMs"] = (retirement.reapDeadlineMs ?? retirement.deadlineMs) - retirementNow() }
        if let ticket { numbers["readRemainingMs"] = ticket.deadlineMonotonicMs - SystemCollectorClock().monotonicMs }
        CollectorDebugTrace.record(stage, numbers: numbers,
            flags: ["session": session, "inFlight": ticket != nil, "retiring": retirement != nil,
                    "acknowledged": retirement?.acknowledged == true], stack: true, file: file, line: line)
        cancel(); inputDisabled(reason)
    }
    private func pollRetiredExit(_ retirement: WorkerRetirement, ackAcceptedAt: Int64? = nil) {
        let child = pid
        guard child > 0, child == retirement.pid, let deadline = retirement.reapDeadlineMs else {
            faultInput(stage: "worker-retire-wait"); return
        }
        func reportAck() {
            if let ackAcceptedAt {
                CollectorDebugTrace.record("worker-retire-ack", numbers: ["childPid": Int64(child),
                    "remainingMs": retirement.deadlineMs - ackAcceptedAt], flags: ["healthy": true])
            }
        }
        guard retirementNow() < deadline else {
            reportAck(); faultInput(stage: "worker-retire-timeout"); return
        }
        var status: Int32 = 0
        let reaped = waitpid(child, &status, WNOHANG), waitError = errno
        let now = retirementNow() // Observe the actual wait before diagnostics can delay this sample.
        reportAck()
        if reaped == child {
            let cleanInTime = retirement.mayReplace(reapedPID: reaped, waitStatus: status, nowMs: now)
            pid = 0 // Already reaped. Never let cancellation signal this PID.
            CollectorDebugTrace.record("worker-reaped", numbers: ["childPid": Int64(child), "waitStatus": Int64(status),
                "remainingMs": deadline - now], flags: ["acknowledged": true, "forced": false])
            guard cleanInTime else { faultInput(stage: "worker-retire-exit"); return }
            sealWorker()
        } else if reaped != 0 && !(reaped < 0 && waitError == EINTR) {
            faultInput(stage: "worker-retire-wait", osError: reaped < 0 ? waitError : nil)
        } else if now >= deadline {
            faultInput(stage: "worker-retire-timeout")
        }
        // An interrupted wait proves nothing; defer to the next poll only
        // within the same reap cutoff. Do not signal a child based on EINTR.
    }
    func poll() {
        if timedOutWorker != nil { _ = timedOutReadCleanup(); return }
        guard pid > 0 else { return }
        if let retirement {
            // After ACK this is a terminal wait, not another pipe/read opportunity.
            if retirement.acknowledged { pollRetiredExit(retirement); return }
            if retirementNow() >= retirement.deadlineMs { faultInput(stage: "worker-retire-timeout"); return }
        }
        let now = SystemCollectorClock().monotonicMs
        if ticket == nil, idleUntil > 0, now >= idleUntil {
            if sessionPolicy?.inputText == true { faultInput(stage: "worker-idle-timeout") } else { cancel() }; return
        }
        let activeTicket = ticket
        if readTrace != nil { readTrace?.polled(at: now) }
        var requestWritten: ReadHandoffRecord?
        // Delay new stderr work until the original read/decode/completion path is
        // finished. The numeric write snapshot retains its actual observation.
        defer { requestWritten?.emit() }
        func fail(_ stage: String, osError: Int32? = nil, line: UInt = #line) {
            if sessionPolicy?.inputText == true || retirement != nil { faultInput(stage: stage, osError: osError, line: line) }
            else { CollectorDebugTrace.record(stage, numbers: ["childPid": Int64(pid)], stack: true, line: line)
                cancel(); if let activeTicket { failure(activeTicket) } }
        }
        if input >= 0, !pending.isEmpty {
            let (count, writeError): (Int, Int32) = pending.withUnsafeBytes {
                let n = Darwin.write(input, $0.baseAddress, $0.count)
                return (n, errno)
            }
            if count > 0 {
                pending.removeFirst(count)
                if pending.isEmpty, ticket != nil {
                    requestWritten = readTrace?.requestWritten(childPid: pid, at: SystemCollectorClock().monotonicMs)
                }
                if pending.isEmpty, let retirement {
                    CollectorDebugTrace.record("worker-retire-sent", numbers: ["childPid": Int64(pid), "remainingMs": retirement.deadlineMs - retirementNow()])
                }
            }
            else if count < 0 && writeError != EAGAIN && writeError != EWOULDBLOCK && writeError != EINTR { fail("worker-pipe-write", osError: writeError); return }
            if pending.isEmpty && !session { close(input); input = -1 }
        }
        var chunk = [UInt8](repeating: 0, count: 4096)
        var eof = false
        for _ in 0..<16 {
            let count = Darwin.read(output, &chunk, chunk.count)
            let readError = errno
            if count > 0 {
                guard bytes.count + count <= 65_536 else { fail("worker-frame-budget"); return }
                bytes.append(contentsOf: chunk.prefix(count))
            } else if count == 0 { eof = true; break }
            else if readError == EINTR { continue }
            else if readError == EAGAIN || readError == EWOULDBLOCK { break }
            else { fail("worker-pipe-read", osError: readError); return }
        }
        var frames: [(data: Data, readyMs: Int64?)] = []
        while let newline = bytes.firstIndex(of: 10) {
            // First splitter observation, before any boundary scan or decode.
            // No first-byte claim: dirty + partial replies can share one batch.
            let readyMs = readTrace == nil ? nil : SystemCollectorClock().monotonicMs
            frames.append((Data(bytes[..<newline]), readyMs)); bytes.removeSubrange(...newline)
        }
        // An already-observed boundary outranks every content reply read in the
        // same pipe batch, even when the reply appeared first in the byte stream.
        if session, let failure = frames.compactMap({ try? JSONValue.parse($0.data)["inputDisabled"]?.stringValue }).first {
            faultInput(failure, stage: "worker-input-disabled"); return
        }
        let sawSecureInput = session && frames.contains(where: { $0.data == Data("{\"secureInput\":true}".utf8) })
        if sawSecureInput {
            secureInput()
            if !session { return } // A non-input or owner boundary cancelled it.
        }
        for (index, observed) in frames.enumerated() {
            let frame = observed.data
            if frame == Data("{\"secureInput\":true}".utf8), session { continue }
            if session, frame == Data("{\"dirty\":true}".utf8) { if retirement == nil && !sawSecureInput { dirty() }; continue }
            if session, frame == Data("{\"submitDirty\":true}".utf8) { if retirement == nil && !sawSecureInput { submitDirty() }; continue }
            if session, frame == Data("{\"menuTracking\":true}".utf8) { if retirement == nil && !sawSecureInput { menuTracking(true) }; continue }
            if session, frame == Data("{\"menuTracking\":false}".utf8) { if retirement == nil && !sawSecureInput { menuTracking(false) }; continue }
            if session, let message = try? JSONValue.parse(frame),
               let object = message.objectValue, object.count == 1, object["menuAction"] != nil {
                guard let decoded = try? JSONDecoder().decode(MenuActionPipeFrame.self, from: frame) else {
                    if retirement != nil { faultInput(stage: "worker-retire-frame"); return }
                    fail("worker-response-invalid"); return
                }
                if retirement == nil && !sawSecureInput { menuAction(decoded.menuAction) }
                continue
            }
            if session, let message = try? JSONValue.parse(frame), let reason = message["inputDisabled"]?.stringValue {
                faultInput(reason, stage: "worker-input-disabled"); return
            }
            if session, var state = retirement {
                let observedAt = retirementNow()
                guard observedAt < state.deadlineMs else { faultInput(stage: "worker-retire-timeout"); return }
                if let message = try? JSONValue.parse(frame), message["retired"] != nil {
                    // A terminal ACK must have the exact control shape and be
                    // last in this batch, with neither queued command bytes nor
                    // trailing old frames. Never open a grace for contamination.
                    guard let object = message.objectValue, object.count == 3,
                          let retireToken = object["retired"]?.stringValue,
                          let sessionToken = object["sessionToken"]?.stringValue,
                          pending.isEmpty, index == frames.count - 1, bytes.isEmpty else {
                        faultInput(stage: "worker-retire-frame"); return
                    }
                    let acceptedAt = retirementNow() // Parsing or scheduling cannot make a late ACK timely.
                    guard state.acknowledge(pid: pid, sessionToken: sessionToken, retireToken: retireToken,
                        healthy: object["inputHealthy"] == .bool(true), nowMs: acceptedAt) else {
                        faultInput(stage: "worker-retire-ack"); return
                    }
                    retirement = state
                    pollRetiredExit(state, ackAcceptedAt: acceptedAt)
                    return
                }
                guard (try? JSONDecoder().decode(ReadResult.self, from: frame)) != nil else {
                    faultInput(stage: "worker-retire-frame"); return
                }
                continue // Validate only the old reply shape; never retain or deliver it.
            }
            let decodeStarted = readTrace == nil ? nil : SystemCollectorClock().monotonicMs
            guard let ticket, (try? JSONValue.parse(frame)) != nil,
                  let response = try? JSONDecoder().decode(ReadResult.self, from: frame), response.token == ticket.token else { fail("worker-response-invalid"); return }
            let decodedAt = readTrace == nil ? nil : SystemCollectorClock().monotonicMs
            let responseTrace = readTrace
            let responseChild = pid // The callback/retirement below can clear both.
            if session {
                self.ticket = nil; readTrace = nil; idleUntil = SystemCollectorClock().monotonicMs + 60_000
                if response.reason == "session-app-changed" || response.reason == "application-excluded" {
                    if sessionPolicy?.inputText == true { retire() } else { cancel() }
                }
            } else { readTrace = nil; cancel() }
            let dispatchStarted = responseTrace == nil ? nil : SystemCollectorClock().monotonicMs
            completingTicket = ticket
            defer { completingTicket = nil }
            completed(response)
            if let responseTrace, let frameReadyMs = observed.readyMs, let decodeStarted, let decodedAt, let dispatchStarted {
                let dispatchedAt = SystemCollectorClock().monotonicMs
                // New JSON/stderr work happens only AFTER the original callback.
                responseTrace.received(childPid: responseChild, frameBytes: frame.count + 1, frameReadyMs: frameReadyMs,
                    decodeMs: decodedAt - decodeStarted, dispatchStartedMs: dispatchStarted).emit()
                responseTrace.dispatched(childPid: responseChild, dispatchStartedMs: dispatchStarted, at: dispatchedAt).emit()
            }
            if pid == 0 { return }
        }
        if eof {
            if session, let ticket, ticket.policy.inputText == true,
               SystemCollectorClock().monotonicMs >= ticket.deadlineMonotonicMs {
                readDeadlineReached(ticket)
                if pid == 0 { return } // Exact expired ticket was sealed in the callback.
            }
            fail("worker-eof")
        }
    }
    private struct TimedOutWorker {
        let pid: pid_t
        let startedMs: Int64
        let deadlineMs: Int64
        let requestId: Int64?
        let diagnostic: WorkerReadTrace?
        let progress: WorkerProgressPage?
        var signalAttempted = false
        var forced = false
    }
    private enum TimeoutExit { case pending, interrupted, exited(Int32), unknown(Int32) }
    private func probeExit(_ child: pid_t) -> TimeoutExit {
        var status: Int32 = 0
        for _ in 0..<4 {
            let waited = waitpid(child, &status, WNOHANG)
            if waited == child { return .exited(status) }
            if waited == 0 { return .pending }
            let error = errno
            if error != EINTR { return .unknown(error) }
        }
        return .interrupted
    }
    private func traceCleanup(_ outcome: String, _ child: TimedOutWorker, status: Int32? = nil, error: Int32? = nil) {
        guard CollectorDebugTrace.enabled else { return }
        var numbers = ["childPid": Int64(child.pid), "elapsedMs": min(Int64(Int32.max), max(0, SystemCollectorClock().monotonicMs - child.startedMs))]
        if let requestId = child.requestId { numbers["requestId"] = requestId }
        if let status { numbers["waitStatus"] = Int64(status) }
        if let error { numbers["errno"] = Int64(error) }
        CollectorDebugTrace.record("worker-read-timeout-cleanup", numbers: numbers, strings: ["outcome": outcome])
    }
    private static let terminalInputFailureReasons: Set<String> = [
        "input-monitoring-required",
        "input-monitoring-disabled",
        "input-monitoring-unavailable",
        "input-session-boundary-requires-resume",
    ]

    /// Drains any already-queued non-blocking bytes from the worker pipe before
    /// timeout sealing so a concurrent `inputDisabled` or `secureInput` frame
    /// is never masked by a read deadline when `engine.tick()` precedes `poll()`.
    private func scanPendingBoundaryFramesBeforeAbort() -> Bool {
        if output >= 0 {
            var chunk = [UInt8](repeating: 0, count: 4096)
            for _ in 0..<16 {
                let count = Darwin.read(output, &chunk, chunk.count)
                let readError = errno
                if count > 0 {
                    guard bytes.count + count <= 65_536 else {
                        faultInput(stage: "worker-frame-budget")
                        return true
                    }
                    bytes.append(contentsOf: chunk.prefix(count))
                } else if count == 0 || readError == EAGAIN || readError == EWOULDBLOCK {
                    break
                } else if readError == EINTR {
                    continue
                } else {
                    break
                }
            }
        }
        var frames: [Data] = []
        var searchStart = bytes.startIndex
        while let newline = bytes[searchStart...].firstIndex(of: 10) {
            frames.append(Data(bytes[searchStart..<newline]))
            searchStart = bytes.index(after: newline)
        }
        for frame in frames {
            if let message = try? JSONValue.parse(frame),
               let reason = message["inputDisabled"]?.stringValue {
                faultInput(reason, stage: "worker-input-disabled")
                return true
            }
            if let decoded = try? JSONDecoder().decode(ReadResult.self, from: frame),
               let reason = decoded.reason,
               Self.terminalInputFailureReasons.contains(reason) {
                faultInput(reason, stage: "worker-input-disabled")
                return true
            }
        }
        if frames.contains(where: { $0 == Data("{\"secureInput\":true}".utf8) }) {
            cancel()
            secureInput()
            return true
        }
        return false
    }

    func abortTimedOutRead(_ ticket: ReadTicket) -> ReadTimeoutCleanup {
        let now = SystemCollectorClock().monotonicMs
        let isActiveTicket = self.ticket == ticket
        let isLateCompletion = self.completingTicket == ticket
        guard now >= ticket.deadlineMonotonicMs, (isActiveTicket || isLateCompletion), retirement == nil,
              pid > 0, timedOutWorker == nil, session, ticket.policy.inputText == true else { return .ineligible }
        if scanPendingBoundaryFramesBeforeAbort() {
            return .ineligible
        }
        let child = pid, progress = progressPage, diagnostic = readTrace
        let cancelled = diagnostic?.cancelled(childPid: child, at: now, pendingBytes: pending.count, bufferBytes: bytes.count)
        // Probe and SIGKILL live child BEFORE sealing/closing pipes so a still-running
        // session worker cannot observe stdin EOF (exit 0) or stdout EPIPE (exit 74)
        // and race ahead of SIGKILL into an unrecoverable non-deadline exit status.
        let observed = probeExit(child)
        var owned = TimedOutWorker(pid: child, startedMs: now, deadlineMs: ticket.deadlineMonotonicMs,
            requestId: ticket.debugRequestId, diagnostic: diagnostic, progress: progress)
        if case .pending = observed {
            owned.signalAttempted = true
            if kill(child, SIGKILL) == 0 { owned.forced = true }
            else { let error = errno; if error != ESRCH { traceCleanup("unconfirmed", owned, error: error) } }
        }
        sealWorker()
        timedOutWorker = owned
        defer { cancelled?.emit() }
        let result = finishTimedOutWorker(owned, observed)
        if result == .awaitingExit { traceCleanup("awaiting", owned) }
        return result
    }
    private func finishTimedOutWorker(_ child: TimedOutWorker, _ result: TimeoutExit) -> ReadTimeoutCleanup {
        switch result {
        case .pending:
            // Only waitpid returning 0 proves the PID is still our child. An
            // interrupted wait does not. The control loop never blocks here.
            if !child.signalAttempted {
                var signalled = child
                signalled.signalAttempted = true
                if kill(child.pid, SIGKILL) == 0 { signalled.forced = true }
                else { let error = errno; if error != ESRCH { traceCleanup("unconfirmed", child, error: error) } }
                timedOutWorker = signalled
            }
            timeoutCleanup = .awaitingExit; return .awaitingExit
        case .interrupted:
            timeoutCleanup = .awaitingExit; return .awaitingExit
        case .unknown(let error):
            timedOutWorker = nil; timeoutCleanup = .unconfirmed
            traceCleanup("unconfirmed", child, error: error); return .unconfirmed
        case .exited(let status):
            timedOutWorker = nil
            // waitpid's exact PID is authoritative; a vanilla exit/other
            // signal is never rewritten as a known deadline/watchdog exit.
            let inInitialFocus = child.progress?.endedInsideInitialFocus(deadlineMs: child.deadlineMs) == true
            CollectorDebugTrace.record("worker-reaped", numbers: ["childPid": Int64(child.pid), "waitStatus": Int64(status)], flags: ["forced": child.forced, "inInitialFocus": inInitialFocus])
            if let diagnostic = child.diagnostic {
                child.progress?.snapshot(requestId: diagnostic.requestId, deadlineMs: diagnostic.deadlineMs,
                    childPid: child.pid, nowMs: SystemCollectorClock().monotonicMs)?.emit()
            }
            // 70 was also used for unrelated errors. SessionTransport's
            // private deadline-only code is distinct from those exits.
            let knownDeadlineExit = (status == SIGKILL && child.forced) || status == sessionReadDeadlineExit << 8
            if SystemCollectorClock().monotonicMs - child.startedMs >= 1_000 {
                // Owner must explicitly resume; we did eventually see the exact exit.
                traceCleanup("unconfirmed", child, status: status); timeoutCleanup = .ineligible
            } else if !knownDeadlineExit {
                traceCleanup("unexpected-exit", child, status: status); timeoutCleanup = .ineligible
            } else {
                traceCleanup("reaped", child, status: status); timeoutCleanup = .reaped
            }
            return timeoutCleanup
        }
    }
    func timedOutReadCleanup() -> ReadTimeoutCleanup {
        guard let child = timedOutWorker else { return timeoutCleanup }
        return finishTimedOutWorker(child, probeExit(child.pid))
    }
    private func sealWorker() {
        progressPage = nil
        pid = 0; ticket = nil; readTrace = nil
        session = false; sessionPolicy = nil; sessionEpoch = nil; idleUntil = 0; launchToken = nil; retirement = nil
        if input >= 0 { close(input); input = -1 }
        if output >= 0 { close(output); output = -1 }
        pending.removeAll(keepingCapacity: false); bytes.removeAll(keepingCapacity: false)
    }
    private func reapChildSynchronously(_ child: pid_t, progress: WorkerProgressPage?, snapshotTrace: WorkerReadTrace?) {
        // Kill first even if the provider is blocked inside synchronous AX IPC.
        // waitpid then reaps this exact child; do not merely discard its reply.
        var status: Int32 = 0
        var alreadyExited: pid_t
        repeat { alreadyExited = waitpid(child, &status, WNOHANG) } while alreadyExited < 0 && errno == EINTR
        let forced = alreadyExited == 0
        var reaped = alreadyExited
        if forced {
            kill(child, SIGKILL)
            repeat { reaped = waitpid(child, &status, 0) } while reaped < 0 && errno == EINTR
        }
        if reaped == child {
            CollectorDebugTrace.record("worker-reaped", numbers: ["childPid": Int64(child), "waitStatus": Int64(status)], flags: ["forced": forced])
            // Never read or encode the progress page before the original
            // kill/exact-reap. Stale/invalid pages are diagnostic absence.
            if let snapshotTrace {
                progress?.snapshot(requestId: snapshotTrace.requestId, deadlineMs: snapshotTrace.deadlineMs,
                    childPid: child, nowMs: SystemCollectorClock().monotonicMs)?.emit()
            }
        } else {
            timeoutCleanup = .unconfirmed // Do not replace a worker whose exit could not be proved.
            CollectorDebugTrace.record("worker-retire-wait", numbers: ["childPid": Int64(child), "errno": Int64(errno)], stack: true)
        }
    }
    func cancel() {
        let cancelled: ReadHandoffRecord?
        if ticket != nil, let readTrace {
            cancelled = readTrace.cancelled(childPid: pid, at: SystemCollectorClock().monotonicMs,
                pendingBytes: pending.count, bufferBytes: bytes.count)
        } else { cancelled = nil }
        defer { cancelled?.emit() } // Seal/close/kill/exact-reap precede new trace IO.
        let child = pid, progress = progressPage, snapshotTrace = readTrace
        let pendingTimedOut = timedOutWorker
        timedOutWorker = nil
        sealWorker()
        if let pendingTimedOut {
            reapChildSynchronously(pendingTimedOut.pid, progress: pendingTimedOut.progress, snapshotTrace: pendingTimedOut.diagnostic)
        }
        if child > 0 {
            reapChildSynchronously(child, progress: progress, snapshotTrace: snapshotTrace)
        }
    }
    deinit { cancel() }
}

func runWorker(_ options: CLIOptions) -> Int32 {
    if options.sessionWorker { return runSessionWorker(options) }
    let parent = getppid()
    let clock = SystemCollectorClock()
    let started = clock.monotonicMs
    // Even a hard-killed serve process must not leave an AX child alive. This
    // watchdog is not the AX thread and performs no GUI/session reads.
    let watchdog = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
    watchdog.schedule(deadline: .now(), repeating: .milliseconds(20))
    watchdog.setEventHandler {
        if getppid() != parent || clock.monotonicMs - started > 5_500 { _exit(70) }
    }
    watchdog.resume()
    defer { watchdog.cancel() }
    var buffer = Data()
    var chunk = [UInt8](repeating: 0, count: 4096)
    while !buffer.contains(10) {
        let n = Darwin.read(STDIN_FILENO, &chunk, chunk.count)
        guard n > 0, buffer.count + n <= 65_536 else { return 64 }
        buffer.append(contentsOf: chunk.prefix(n))
    }
    guard buffer.last == 10, !buffer.dropLast().contains(10),
          let parsed = try? JSONValue.parse(Data(buffer.dropLast())),
          let request = try? JSONDecoder().decode(ReadTicket.self, from: parsed.canonicalData()),
          request.token == ProcessInfo.processInfo.environment["DSH_COLLECTOR_WORKER_TOKEN"],
          request.policy.enabled, request.policy.hasValidTextSettings,
          request.policy.maxTextCodeUnits >= 1, request.policy.maxTextCodeUnits <= 8192,
          request.deadlineMonotonicMs > clock.monotonicMs, request.deadlineMonotonicMs - clock.monotonicMs <= 5_000 else { return 64 }
    if options.fixture && options.scenario == "workerhang" { while true { pause() } }
    func failure(_ reason: String, _ code: ReadDiagnostic.Code) -> ReadResult {
        ReadResult(token: request.token, reason: reason, diagnostic: ReadDiagnostic(code: code),
                   captureStartMs: clock.unixMs, captureEndMs: clock.unixMs)
    }
    let result: ReadResult
    if options.fixture {
        result = BoundedTextReader().read(ticket: request, provider: SyntheticFieldProvider(options.scenario), clock: clock)
    } else {
        let assessment = desktopAssessment()
        if assessment.isSecureInputOnly || IsSecureEventInputEnabled() {
            result = failure("secure-input-active", .secureField)
        } else if assessment.desktopStatus != .unlocked {
            result = failure("desktop-unavailable", .desktopUnavailable)
        } else if !AXIsProcessTrusted() {
            result = failure("permission-denied", .accessibilityDenied)
        } else if let running = NSWorkspace.shared.frontmostApplication, let applicationId = running.bundleIdentifier {
            if case let .denied(reason, code) = ApplicationPolicy.evaluate(applicationId, policy: request.policy) {
                result = failure(reason, code)
            } else if !AppIdentityGate.permittedApplication(running, policy: request.policy) {
                result = failure("policy-boundary", .browserExcluded)
            } else if let app = AppIdentityGate.identity(running) {
                let adapter = AppAdapterRegistry.shared.adapter(for: app.applicationId)
                let provider = AXFieldProvider(
                    expected: app,
                    timeoutMs: request.policy.readTimeoutMs,
                    policy: request.policy,
                    adapter: adapter,
                    privateState: AppIdentityGate.privateState(for: running)
                )
                var secureInputTriggered = false
                provider.secureInput = { secureInputTriggered = true }
                provider.deadlineMonotonicMs = request.deadlineMonotonicMs
                var read = BoundedTextReader().read(ticket: request, provider: provider, clock: clock, staticTextProbe: adapter.spec.staticTextProbe)
                if secureInputTriggered || IsSecureEventInputEnabled() {
                    result = failure("secure-input-active", .secureField)
                } else if provider.privateWindowBlocked {
                    result = failure("policy-boundary", .browserExcluded)
                } else {
                    if read.application != nil { read.privateState = provider.privateState }
                    result = read
                }
            } else { result = failure("policy-boundary", .applicationUnavailable) }
        } else {
            result = failure("policy-boundary", .applicationUnavailable)
        }
    }
    let carriesMaterial = result.application != nil || result.text != nil || result.surface != nil || result.selection != nil
    guard getppid() == parent, clock.monotonicMs < request.deadlineMonotonicMs,
          options.fixture || !carriesMaterial || (desktopStatus() == .unlocked && !IsSecureEventInputEnabled() && AXIsProcessTrusted()),
          var encoded = try? JSONEncoder().encode(result), encoded.count < 65_535 else { return 70 }
    encoded.append(10)
    // Worker output may block only until parent shutdown/deadline watchdog.
    var offset = 0
    while offset < encoded.count {
        let (count, writeError): (Int, Int32) = encoded.withUnsafeBytes {
            let n = Darwin.write(STDOUT_FILENO, $0.baseAddress!.advanced(by: offset), $0.count - offset)
            return (n, errno)
        }
        if count > 0 { offset += count }
        else if count < 0 && writeError == EINTR { continue }
        else { return 74 }
    }
    return 0
}

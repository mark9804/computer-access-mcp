import Foundation
import Darwin
import ApplicationServices
import CollectorCore
import CCollectorSupport

/// One anonymous, unlinked mapping per owned session worker. No capture decision
/// may depend on this page; failed diagnostics are simply absent.
final class WorkerProgressPage {
    static let inheritedFD: Int32 = 198
    private(set) var descriptor: Int32
    let mapping: OpaquePointer
    init?() {
        var fd: Int32 = -1
        guard let page = collector_progress_create(&fd) else { return nil }
        mapping = page; descriptor = fd
    }
    fileprivate init?(attaching fd: Int32) {
        guard let page = collector_progress_attach(fd) else { return nil }
        mapping = page; descriptor = -1
    }
    func closeDescriptor() {
        if descriptor >= 0 { close(descriptor); descriptor = -1 }
    }
    deinit { closeDescriptor(); collector_progress_unmap(mapping) }
    @discardableResult
    fileprivate func write(_ state: collector_progress_snapshot) -> Bool {
        var state = state
        return collector_progress_write(mapping, &state) == 1
    }
    func endedInsideInitialFocus(deadlineMs: Int64) -> Bool {
        collector_focus_fence_matches(mapping, deadlineMs) == 1
    }
    /// The production caller invokes this only AFTER kill/exact-reap. The page is
    /// untrusted diagnostics: reject stale requests and malformed numeric fields.
    func snapshot(requestId: Int64, deadlineMs: Int64, childPid: Int32, nowMs: Int64) -> ReadHandoffRecord? {
        var value = collector_progress_snapshot()
        guard collector_progress_read(mapping, &value) == 1,
              requestId > 0, requestId <= 9_007_199_254_740_991,
              value.request_id == requestId, value.deadline_ms == deadlineMs,
              (0...9_007_199_254_740_991).contains(value.read_id),
              (0...22).contains(value.operation), (0...23).contains(value.api),
              (0...26).contains(value.attribute), (1...2).contains(value.phase),
              (-25214...0).contains(value.status), (-1...Int64(Int32.max)).contains(value.index),
              value.started_ms >= 0, value.updated_ms >= value.started_ms,
              nowMs >= value.updated_ms, deadlineMs > 0, childPid > 0 else { return nil }
        func elapsed(_ start: Int64) -> Int64 { min(Int64(Int32.max), nowMs - start) }
        let remaining = max(-Int64(Int32.max), min(Int64(Int32.max), deadlineMs - nowMs))
        return ReadHandoffRecord(code: "worker-operation-snapshot", numbers: [
            "requestId": requestId, "readId": value.read_id, "childPid": Int64(childPid),
            "operation": value.operation, "api": value.api, "attribute": value.attribute, "phase": value.phase,
            "operationElapsedMs": elapsed(value.started_ms), "progressAgeMs": elapsed(value.updated_ms),
            "readRemainingMs": remaining, "axError": value.status, "nodeIndex": value.index,
        ])
    }
}

/// Single producer: the worker's existing run loop only, never its watchdog.
/// Each call writes fixed numeric atomics, without a lock, allocation, IO or AX.
/// A nested call restores the outer *entered* context and original start time.
/// Depth beyond eight is diagnostic no-op, not a change to business execution.
enum WorkerProgress {
    private static var page: WorkerProgressPage?
    private static var state = collector_progress_snapshot()
    private static var stageGeneration: UInt64 = 0
    private static var depth = 0
    private static func now() -> Int64 { Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000) }
    static func attachFromEnvironment() {
        guard ProcessInfo.processInfo.environment["DSH_COMPUTER_HISTORY_PROGRESS_FD"] == String(WorkerProgressPage.inheritedFD) else { return }
        // This FD is inherited solely by the session worker's explicit spawn dup.
        // Close it even if attachment validation fails; no later exec inherits it.
        let fd = WorkerProgressPage.inheritedFD
        defer { close(fd) }
        guard page == nil, let attached = WorkerProgressPage(attaching: fd) else { return }
        page = attached
        CollectorDebugTrace.record("session-progress-ready", numbers: ["phase": 1])
    }
    static func initialFocus<T>(deadlineMs: Int64, _ read: () -> T) -> T {
        guard let page else { return read() }
        let saved = errno
        collector_focus_fence_set(page.mapping, deadlineMs)
        errno = saved
        defer {
            let resultErrno = errno
            collector_focus_fence_set(page.mapping, 0)
            errno = resultErrno
        }
        return read()
    }
    static func detach() {
        page = nil; state = collector_progress_snapshot(); depth = 0; stageGeneration &+= 1
    }
    static func beginRequest(requestId: Int64?, deadlineMs: Int64) {
        guard let page else { return }
        let savedErrno = errno; defer { errno = savedErrno }
        collector_focus_fence_set(page.mapping, 0)
        guard CollectorDebugTrace.enabled || requestId != nil else { return }
        stageGeneration &+= 1
        state = collector_progress_snapshot()
        state.request_id = requestId ?? 0; state.deadline_ms = deadlineMs
        state.operation = 16; state.phase = 1; state.status = -1; state.index = -1
        state.started_ms = now(); state.updated_ms = state.started_ms
        publish()
    }
    static func finishRequest() {
        guard let page else { return }
        let savedErrno = errno; defer { errno = savedErrno }
        collector_focus_fence_set(page.mapping, 0)
        guard CollectorDebugTrace.enabled || state.request_id > 0 else { return }
        stageGeneration &+= 1
        // Publish request 0 so idle callbacks never appear to belong to a reply
        // which has already left the pipe. Previous slots are stale by requestId.
        state = collector_progress_snapshot()
        state.index = -1; state.phase = 1; state.status = -1
        state.started_ms = now(); state.updated_ms = state.started_ms
        publish()
    }
    static func stage(readId: Int64? = nil, operation: Int64, index: Int64 = -1) {
        guard page != nil, CollectorDebugTrace.enabled || state.request_id > 0 else { return }
        let savedErrno = errno; defer { errno = savedErrno }
        stageGeneration &+= 1
        if let readId { state.read_id = readId }
        state.operation = operation; state.index = index
        state.api = 0; state.attribute = 0; state.phase = 1; state.status = -1
        state.started_ms = now(); state.updated_ms = state.started_ms
        publish()
    }
    static func withCall(api: Int64, attribute: Int64 = 0, _ body: () -> AXError) -> AXError {
        invoke(api: api, attribute: attribute, body, status: { Int64($0.rawValue) })
    }
    static func withValue<T>(api: Int64, attribute: Int64 = 0, _ body: () -> T) -> T {
        // phase2/status0 means only "returned" for non-AX APIs, not success.
        invoke(api: api, attribute: attribute, body, status: { _ in 0 })
    }
    private static func invoke<T>(api: Int64, attribute: Int64, _ body: () -> T, status: (T) -> Int64) -> T {
        guard page != nil, CollectorDebugTrace.enabled || state.request_id > 0, depth < 8 else { return body() }
        let entryErrno = errno
        let outer = state, generation = stageGeneration, nested = depth > 0
        depth += 1
        state.api = api; state.attribute = attribute; state.phase = 1; state.status = -1
        state.started_ms = now(); state.updated_ms = state.started_ms
        let entered = state
        publish()
        errno = entryErrno
        let result = body()
        let resultErrno = errno
        defer { errno = resultErrno }
        depth -= 1
        guard generation == stageGeneration else { return result }
        state = entered; state.phase = 2; state.status = status(result); state.updated_ms = now()
        publish()
        if nested {
            state = outer; state.updated_ms = now()
            publish()
        }
        return result
    }
    private static func publish() { _ = page?.write(state) }

    // Internal test access uses exactly the same producer, without environment,
    // desktop queries or attaching a production worker.
    static func useForTesting(_ testPage: WorkerProgressPage?) {
        detach(); page = testPage
    }
}

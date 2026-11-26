import Foundation
import Darwin
import ApplicationServices
import Synchronization
import CollectorCore
import CCollectorSupport

/// One anonymous, unlinked mapping per owned session worker. No capture decision
/// may depend on this page; failed diagnostics are simply absent.
final class WorkerProgressPage: @unchecked Sendable {
    static let inheritedFD: Int32 = 198
    private let descriptorStorage: Atomic<Int32>
    var descriptor: Int32 { descriptorStorage.load(ordering: .acquiring) }
    let mapping: OpaquePointer
    init?() {
        var fd: Int32 = -1
        guard let page = collector_progress_create(&fd) else { return nil }
        mapping = page
        descriptorStorage = Atomic(fd)
    }
    fileprivate init?(attaching fd: Int32) {
        guard let page = collector_progress_attach(fd) else { return nil }
        mapping = page
        descriptorStorage = Atomic(-1)
    }
    func closeDescriptor() {
        let fd = descriptorStorage.exchange(-1, ordering: .acquiringAndReleasing)
        if fd >= 0 { close(fd) }
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
/// Each call writes fixed numeric atomics, without a blocking IO or AX call under lock.
/// A nested call restores the outer *entered* context and original start time.
/// Depth beyond eight is diagnostic no-op, not a change to business execution.
enum WorkerProgress {
    private struct Storage: Sendable {
        var page: WorkerProgressPage?
        var state = collector_progress_snapshot()
        var stageGeneration: UInt64 = 0
        var depth = 0
    }

    private static let storage = Mutex(Storage())
    private static func now() -> Int64 { Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000) }

    static func attachFromEnvironment() {
        guard ProcessInfo.processInfo.environment["DSH_COMPUTER_HISTORY_PROGRESS_FD"] == String(WorkerProgressPage.inheritedFD) else { return }
        // This FD is inherited solely by the session worker's explicit spawn dup.
        // Close it even if attachment validation fails; no later exec inherits it.
        let fd = WorkerProgressPage.inheritedFD
        defer { close(fd) }
        let attached = storage.withLock { box -> Bool in
            guard box.page == nil, let page = WorkerProgressPage(attaching: fd) else { return false }
            box.page = page
            return true
        }
        if attached {
            CollectorDebugTrace.record("session-progress-ready", numbers: ["phase": 1])
        }
    }

    static func initialFocus<T>(deadlineMs: Int64, _ read: () -> T) -> T {
        let saved = errno
        let page = storage.withLock { $0.page }
        guard let page else {
            errno = saved
            return read()
        }
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
        storage.withLock { box in
            box.page = nil
            box.state = collector_progress_snapshot()
            box.depth = 0
            box.stageGeneration &+= 1
        }
    }

    static func beginRequest(requestId: Int64?, deadlineMs: Int64) {
        let savedErrno = errno; defer { errno = savedErrno }
        storage.withLock { box in
            guard let page = box.page else { return }
            collector_focus_fence_set(page.mapping, 0)
            guard CollectorDebugTrace.enabled || requestId != nil else { return }
            box.stageGeneration &+= 1
            box.state = collector_progress_snapshot()
            box.state.request_id = requestId ?? 0
            box.state.deadline_ms = deadlineMs
            box.state.operation = 16
            box.state.phase = 1
            box.state.status = -1
            box.state.index = -1
            box.state.started_ms = now()
            box.state.updated_ms = box.state.started_ms
            _ = page.write(box.state)
        }
    }

    static func finishRequest() {
        let savedErrno = errno; defer { errno = savedErrno }
        storage.withLock { box in
            guard let page = box.page else { return }
            collector_focus_fence_set(page.mapping, 0)
            guard CollectorDebugTrace.enabled || box.state.request_id > 0 else { return }
            box.stageGeneration &+= 1
            // Publish request 0 so idle callbacks never appear to belong to a reply
            // which has already left the pipe. Previous slots are stale by requestId.
            box.state = collector_progress_snapshot()
            box.state.index = -1
            box.state.phase = 1
            box.state.status = -1
            box.state.started_ms = now()
            box.state.updated_ms = box.state.started_ms
            _ = page.write(box.state)
        }
    }

    static func stage(readId: Int64? = nil, operation: Int64, index: Int64 = -1) {
        let savedErrno = errno; defer { errno = savedErrno }
        storage.withLock { box in
            guard let page = box.page, CollectorDebugTrace.enabled || box.state.request_id > 0 else { return }
            box.stageGeneration &+= 1
            if let readId { box.state.read_id = readId }
            box.state.operation = operation
            box.state.index = index
            box.state.api = 0
            box.state.attribute = 0
            box.state.phase = 1
            box.state.status = -1
            box.state.started_ms = now()
            box.state.updated_ms = box.state.started_ms
            _ = page.write(box.state)
        }
    }

    static func withCall(api: Int64, attribute: Int64 = 0, _ body: () -> AXError) -> AXError {
        invoke(api: api, attribute: attribute, body, status: { Int64($0.rawValue) })
    }

    static func withValue<T>(api: Int64, attribute: Int64 = 0, _ body: () -> T) -> T {
        // phase2/status0 means only "returned" for non-AX APIs, not success.
        invoke(api: api, attribute: attribute, body, status: { _ in 0 })
    }

    private static func invoke<T>(api: Int64, attribute: Int64, _ body: () -> T, status: (T) -> Int64) -> T {
        let entryErrno = errno
        let frame: (outer: collector_progress_snapshot, entered: collector_progress_snapshot, generation: UInt64, nested: Bool)? =
            storage.withLock { box in
                guard let page = box.page,
                      CollectorDebugTrace.enabled || box.state.request_id > 0,
                      box.depth < 8 else { return nil }
                let outer = box.state
                let generation = box.stageGeneration
                let nested = box.depth > 0
                box.depth += 1
                box.state.api = api
                box.state.attribute = attribute
                box.state.phase = 1
                box.state.status = -1
                box.state.started_ms = now()
                box.state.updated_ms = box.state.started_ms
                let entered = box.state
                _ = page.write(entered)
                return (outer, entered, generation, nested)
            }
        guard let frame else {
            errno = entryErrno
            return body()
        }
        errno = entryErrno
        let result = body()
        let resultErrno = errno
        defer { errno = resultErrno }
        let code = status(result)
        storage.withLock { box in
            box.depth = max(0, box.depth - 1)
            guard let page = box.page, frame.generation == box.stageGeneration else { return }
            box.state = frame.entered
            box.state.phase = 2
            box.state.status = code
            box.state.updated_ms = now()
            _ = page.write(box.state)
            if frame.nested {
                box.state = frame.outer
                box.state.updated_ms = now()
                _ = page.write(box.state)
            }
        }
        return result
    }

    // Internal test access uses exactly the same producer, without environment,
    // desktop queries or attaching a production worker.
    static func useForTesting(_ testPage: WorkerProgressPage?) {
        storage.withLock { box in
            box.page = testPage
            box.state = collector_progress_snapshot()
            box.depth = 0
            box.stageGeneration &+= 1
        }
    }
}

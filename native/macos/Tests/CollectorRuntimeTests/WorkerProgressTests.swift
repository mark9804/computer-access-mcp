import XCTest
import Foundation
import Darwin
import ApplicationServices
import CCollectorSupport
@testable import CollectorRuntime

final class WorkerProgressTests: XCTestCase {
    private func sample(request: Int64 = 7, api: Int64 = 3) -> collector_progress_snapshot {
        collector_progress_snapshot(
            request_id: request,
            read_id: 5,
            operation: 9,
            api: api,
            attribute: 7,
            phase: 1,
            started_ms: 100,
            updated_ms: 101,
            deadline_ms: 1500,
            status: -1,
            index: 4
        )
    }

    private func write(_ state: collector_progress_snapshot, to page: WorkerProgressPage) {
        var state = state
        XCTAssertEqual(collector_progress_write(page.mapping, &state), 1)
    }

    func testAnonymousPageIsPrivateSizedCloseOnExecAndAttachesOnDarwin() throws {
        let page = try XCTUnwrap(WorkerProgressPage())
        var info = stat()
        XCTAssertEqual(fstat(page.descriptor, &info), 0)
        XCTAssertEqual(info.st_uid, geteuid())
        XCTAssertEqual(info.st_mode & 0o777, 0o600)
        XCTAssertLessThanOrEqual(info.st_nlink, 1)
        XCTAssertEqual(info.st_size, off_t(getpagesize()))
        XCTAssertNotEqual(fcntl(page.descriptor, F_GETFD) & FD_CLOEXEC, 0)

        let attached = try XCTUnwrap(collector_progress_attach(page.descriptor))
        defer { collector_progress_unmap(attached) }
        write(sample(), to: page)
        var state = collector_progress_snapshot()
        XCTAssertEqual(collector_progress_read(attached, &state), 1)
        XCTAssertEqual(state.request_id, 7)
        XCTAssertEqual(state.api, 3)

        collector_focus_fence_set(attached, 1500)
        XCTAssertTrue(page.endedInsideInitialFocus(deadlineMs: 1500))
        XCTAssertFalse(page.endedInsideInitialFocus(deadlineMs: 1501))
        collector_focus_fence_set(attached, 0)
        XCTAssertFalse(page.endedInsideInitialFocus(deadlineMs: 1500))
        XCTAssertNil(collector_progress_attach(-1))
    }

    func testMalformedStaleOrUninitializedPagesAreDiagnosticAbsence() throws {
        let page = try XCTUnwrap(WorkerProgressPage())
        XCTAssertNil(page.snapshot(requestId: 7, deadlineMs: 1500, childPid: 1, nowMs: 1600))
        write(sample(), to: page)
        XCTAssertNil(page.snapshot(requestId: 8, deadlineMs: 1500, childPid: 1, nowMs: 1600))
        XCTAssertNil(page.snapshot(requestId: 7, deadlineMs: 1600, childPid: 1, nowMs: 1600))
        var invalid = sample()
        invalid.attribute = 27
        write(invalid, to: page)
        XCTAssertNil(page.snapshot(requestId: 7, deadlineMs: 1500, childPid: 1, nowMs: 1600))
    }

    func testNestedCallsPreserveOuterEnteredContextReturnValueErrnoAndRequestAssociation() throws {
        let page = try XCTUnwrap(WorkerProgressPage())
        WorkerProgress.useForTesting(page)
        defer { WorkerProgress.detach() }
        WorkerProgress.beginRequest(requestId: 7, deadlineMs: 1500)
        WorkerProgress.stage(readId: 5, operation: 11, index: 2)
        var outerStart: Int64 = 0
        errno = EDOM
        let result = WorkerProgress.withValue(api: 15) { () -> Int in
            XCTAssertEqual(errno, EDOM)
            var entered = collector_progress_snapshot()
            XCTAssertEqual(collector_progress_read(page.mapping, &entered), 1)
            outerStart = entered.started_ms
            let inner = WorkerProgress.withCall(api: 23, attribute: 23) { () -> AXError in
                errno = EAGAIN
                return .cannotComplete
            }
            XCTAssertEqual(inner, .cannotComplete)
            XCTAssertEqual(errno, EAGAIN)
            var resumed = collector_progress_snapshot()
            XCTAssertEqual(collector_progress_read(page.mapping, &resumed), 1)
            XCTAssertEqual(resumed.api, 15)
            XCTAssertEqual(resumed.phase, 1)
            XCTAssertEqual(resumed.started_ms, outerStart)
            XCTAssertEqual(resumed.status, -1)
            errno = EINTR
            return 42
        }
        XCTAssertEqual(result, 42)
        XCTAssertEqual(errno, EINTR)
        var returned = collector_progress_snapshot()
        XCTAssertEqual(collector_progress_read(page.mapping, &returned), 1)
        XCTAssertEqual(returned.api, 15)
        XCTAssertEqual(returned.phase, 2)
        XCTAssertEqual(returned.status, 0)
        let _: Bool = WorkerProgress.withValue(api: 18) {
            WorkerProgress.finishRequest()
            return false
        }
        var idle = collector_progress_snapshot()
        XCTAssertEqual(collector_progress_read(page.mapping, &idle), 1)
        XCTAssertEqual(idle.request_id, 0)
        WorkerProgress.useForTesting(nil)
        let value = WorkerProgress.withCall(api: 3) { errno = ERANGE; return AXError.noValue }
        XCTAssertEqual(value, .noValue)
        XCTAssertEqual(errno, ERANGE)
    }

    func testFullSnapshotTraceFitsDarwinMinimumAtomicPipeWrite() throws {
        let numbers: [String: Int64] = [
            "requestId": 9_007_199_254_740_991, "readId": 9_007_199_254_740_991,
            "childPid": Int64(Int32.max), "operation": 22, "api": 23, "attribute": 26, "phase": 2,
            "operationElapsedMs": Int64(Int32.max), "progressAgeMs": Int64(Int32.max),
            "readRemainingMs": -Int64(Int32.max), "axError": -25214, "nodeIndex": Int64(Int32.max),
        ]
        let value: [String: Any] = [
            "version": 1, "code": "worker-operation-snapshot", "pid": Int32.max,
            "timeMs": Int64(9_007_199_254_740_991), "monotonicMs": Int64(9_007_199_254_740_991),
            "file": "Worker.swift", "line": 9999, "numbers": numbers, "flags": [String: Bool](),
        ]
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        XCTAssertLessThanOrEqual(data.count + 1, 512)
    }
}

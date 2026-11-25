import XCTest
import Foundation
import Darwin
@testable import CollectorCore
@testable import computer_history_collector

/// Real anonymous pipes + owned synthetic child processes. These scripts never
/// import AppKit/AX, inspect the desktop, request TCC or install any event tap.
final class WorkerTransportTests: XCTestCase {
    private var directories: [URL] = []
    override func tearDown() {
        for directory in directories {
            XCTAssertTrue(directory.lastPathComponent.hasPrefix("dsh-worker-fixture-"))
            try? FileManager.default.removeItem(at: directory)
        }
        directories = []; super.tearDown()
    }
    func testWatchdogProgressReportsActiveReadWithoutMovingItsDeadlineAndClearsOnOuterPhaseChange() {
        let watchdog = WorkerDeadline(1500)
        watchdog.phase(1)
        watchdog.progress(readId: 140, operation: .observerRemove, index: 2, nowMs: 200)
        let active = watchdog.snapshot(1499)
        XCTAssertFalse(active.expired); XCTAssertEqual(active.remaining, 1)
        XCTAssertEqual(active.phase, 1); XCTAssertEqual(active.readId, 140)
        XCTAssertEqual(active.operation, SessionReadOperation.observerRemove.rawValue)
        XCTAssertEqual(active.elapsedMs, 1299); XCTAssertEqual(active.index, 2)
        XCTAssertTrue(watchdog.snapshot(1500).expired)
        watchdog.phase(2)
        let encoded = watchdog.snapshot(1501)
        XCTAssertTrue(encoded.expired); XCTAssertEqual(encoded.remaining, -1)
        XCTAssertEqual(encoded.readId, 0); XCTAssertEqual(encoded.operation, 0); XCTAssertEqual(encoded.index, -1)
        XCTAssertEqual(encoded.elapsedMs, 0)
    }

    private func manager(_ scenario: String,
                         retirementNow: @escaping () -> Int64 = { SystemCollectorClock().monotonicMs }) throws -> WorkerManager {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("dsh-worker-fixture-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        directories.append(directory)
        let script = directory.appendingPathComponent("worker.sh")
        let source = #"""
#!/bin/sh
IFS= read -r request || exit 0
SCENARIO="SCENARIO_PLACEHOLDER"
BARRIER="DIRECTORY_PLACEHOLDER"
if [ "$SCENARIO" = "slow-read" ]; then sleep 0.95; fi
if [ "$SCENARIO" = "secure-batch" ]; then
  printf '{"token":"%s","reason":"read-error","captureStartMs":1,"captureEndMs":1}\n{"secureInput":true}\n' "$DSH_COLLECTOR_WORKER_TOKEN"
elif [ "$SCENARIO" = "submit-dirty" ]; then
  printf '{"token":"%s","reason":"read-error","captureStartMs":1,"captureEndMs":1}\n{"submitDirty":true}\n' "$DSH_COLLECTOR_WORKER_TOKEN"
elif [ "$SCENARIO" = "menu-frames" ]; then
  printf '{"token":"%s","reason":"read-error","captureStartMs":1,"captureEndMs":1}\n{"menuTracking":true}\n{"menuAction":{"application":{"applicationId":"test.allowed","processId":42,"processStartTime":"birth-1"},"path":["File","Save"],"truncated":false,"observedAtMs":1000,"privateState":"normal","captureEpoch":1,"foregroundGeneration":0,"focusGeneration":0,"policyRevision":1,"fieldSecurity":"strict"}}\n{"menuTracking":false}\n' "$DSH_COLLECTOR_WORKER_TOKEN"
elif [ "$SCENARIO" = "menu-secure-batch" ]; then
  printf '{"menuTracking":true}\n{"menuAction":{"application":{"applicationId":"test.allowed","processId":42,"processStartTime":"birth-1"},"path":["File","Save"],"truncated":false,"observedAtMs":1000,"privateState":"normal","captureEpoch":1,"foregroundGeneration":0,"focusGeneration":0,"policyRevision":1,"fieldSecurity":"strict"}}\n{"secureInput":true}\n'
else
  printf '{"token":"%s","reason":"read-error","captureStartMs":1,"captureEndMs":1}\n' "$DSH_COLLECTOR_WORKER_TOKEN"
fi
if [ "$SCENARIO" = "idle-eof" ]; then exit 0; fi
if [ "$SCENARIO" = "fatal" ]; then
  printf '{"inputDisabled":"input-monitoring-disabled"}\n'
  exit 0
fi
while IFS= read -r line; do
  case "$line" in
    *'"retire"'*)
      token=${line#*\"retire\":\"}
      token=${token%%\"*}
      case "$SCENARIO" in
        unhealthy) healthy=false ;;
        eof) exit 0 ;;
        hang) IFS= read -r ignored; exit 0 ;;
        fatal-retirement)
          printf '{"inputDisabled":"input-monitoring-required"}\n'
          exit 0 ;;
        queued-ack|hold-after-ack|nonzero-after-ack)
          while [ ! -f "$BARRIER/release-ack" ]; do sleep 0.005; done
          healthy=true ;;
        *) healthy=true ;;
      esac
      if [ "$SCENARIO" = "menu-frames" ]; then
        printf '{"menuTracking":true}\n{"menuAction":{"application":{"applicationId":"test.allowed","processId":42,"processStartTime":"birth-1"},"path":["File","Late"],"truncated":false,"observedAtMs":1001,"privateState":"normal","captureEpoch":1,"foregroundGeneration":0,"focusGeneration":0,"policyRevision":1,"fieldSecurity":"strict"}}\n{"retired":"%s","sessionToken":"%s","inputHealthy":true}\n' "$token" "$DSH_COLLECTOR_WORKER_TOKEN"
        exit 0
      fi
      if [ "$SCENARIO" = "malformed-before-ack" ]; then
        printf '{"token":"%s"}\n{"retired":"%s","sessionToken":"%s","inputHealthy":true}\n' "$DSH_COLLECTOR_WORKER_TOKEN" "$token" "$DSH_COLLECTOR_WORKER_TOKEN"
        exit 0
      fi
      if [ "$SCENARIO" = "trailing-after-ack" ]; then
        printf '{"retired":"%s","sessionToken":"%s","inputHealthy":true}\n{' "$token" "$DSH_COLLECTOR_WORKER_TOKEN"
        exit 0
      fi
      if [ "$SCENARIO" = "partial" ]; then
        printf '{"retired":"%s",' "$token"
        sleep 0.03
        printf '"sessionToken":"%s","inputHealthy":true}\n' "$DSH_COLLECTOR_WORKER_TOKEN"
      else
        printf '{"retired":"%s","sessionToken":"%s","inputHealthy":%s}\n' "$token" "$DSH_COLLECTOR_WORKER_TOKEN" "$healthy"
      fi
      case "$SCENARIO" in
        queued-ack)
          : > "$BARRIER/ack-written" ;;
        hold-after-ack|nonzero-after-ack)
          : > "$BARRIER/ack-written"
          while [ ! -f "$BARRIER/release-exit" ]; do sleep 0.005; done
          if [ "$SCENARIO" = "nonzero-after-ack" ]; then exit 6; fi ;;
      esac
      exit 0
      ;;
  esac
done
"""#.replacingOccurrences(of: "SCENARIO_PLACEHOLDER", with: scenario)
            .replacingOccurrences(of: "DIRECTORY_PLACEHOLDER", with: directory.path)
        try source.write(to: script, atomically: true, encoding: .utf8)
        XCTAssertEqual(chmod(script.path, 0o700), 0)
        return WorkerManager(executable: script.path, fixture: false, scenario: "allowed", retirementNow: retirementNow)
    }
    private func request() -> ReadTicket {
        let now = SystemCollectorClock().monotonicMs
        return ReadTicket(token: UUID().uuidString, policyRevision: 1, captureEpoch: 1,
            policy: CapturePolicy(inputText: true), hint: nil, deadlineMonotonicMs: now + 5000,
            deviceId: "fixture-device", osSessionId: "fixture-session", desktopId: "fixture-desktop")
    }
    private func until(_ manager: WorkerManager, timeout: TimeInterval = 2, _ condition: () -> Bool) {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            manager.poll()
            if condition() { return }
            Thread.sleep(forTimeInterval: 0.005)
        } while Date() < deadline
        XCTFail("bounded synthetic worker condition timed out")
    }
    func testSecureNoticeSealsSameBatchBeforeReplyAndRequiresHealthyAckAndExactReap() throws {
        let worker = try manager("secure-batch"); defer { worker.cancel() }
        var notices = 0, completions = 0, faults = 0
        worker.secureInput = { notices += 1; worker.retire() }
        worker.completed = { _ in completions += 1 }
        worker.inputDisabled = { _ in faults += 1 }
        worker.launch(request()); until(worker) { notices == 1 }
        until(worker) { worker.readyForRead }
        XCTAssertEqual(completions, 0, "Notice outranks an earlier complete reply in the same batch")
        XCTAssertEqual(faults, 0)
    }
    func testSessionSecureBoundaryIsOneWayAndRetiresAnUnattemptedListenerWithoutOSCalls() {
        let session = AXWorkerSession()
        session.suppressSecureInput(); session.suppressSecureInput()
        XCTAssertTrue(session.secureInputDetected)
        let ticket = request()
        let result = session.read(ticket)
        XCTAssertEqual(result.reason, "secure-input-active"); XCTAssertNil(result.text); XCTAssertNil(result.surface)
        XCTAssertTrue(session.retireHealthy(), "No tap was attempted and no failure is concealed")
    }
    func testHealthyRetirementActualPipesAndExactReapPermitNextSession() throws {
        let worker = try manager("healthy"); defer { worker.cancel() }
        var complete = 0, faults = 0
        worker.completed = { _ in complete += 1 }; worker.inputDisabled = { _ in faults += 1 }
        worker.launch(request()); until(worker) { complete == 1 }
        worker.retire(); XCTAssertFalse(worker.readyForRead)
        until(worker) { worker.readyForRead }
        XCTAssertEqual(faults, 0)
        worker.launch(request()); until(worker) { complete == 2 }
        XCTAssertEqual(faults, 0)
    }
    func testSwitchDuringHealthyInFlightReadWaitsForOriginalDeadlineAndExactRetirement() throws {
        let worker = try manager("slow-read"); defer { worker.cancel() }
        var completions = 0, faults = 0
        worker.completed = { _ in completions += 1 }; worker.inputDisabled = { _ in faults += 1 }
        worker.launch(request())
        worker.retire() // The synthetic read has not returned; old 750ms always failed.
        XCTAssertFalse(worker.readyForRead)
        until(worker, timeout: 3) { worker.readyForRead }
        XCTAssertEqual(faults, 0)
        XCTAssertEqual(completions, 0, "Old in-flight content stays sealed while ACK+exact reap complete")
    }
    func testMissingMalformedUnhealthyAndContaminatedAcksSignalControlFault() throws {
        for scenario in ["unhealthy", "eof", "hang", "malformed-before-ack", "trailing-after-ack"] {
            let worker = try manager(scenario); defer { worker.cancel() }
            var complete = false, faults: [String] = []
            worker.completed = { _ in complete = true }; worker.inputDisabled = { faults.append($0) }
            worker.launch(request()); until(worker) { complete }
            worker.retire(); until(worker) { !faults.isEmpty }
            XCTAssertEqual(faults, ["worker-retirement-ack-failed"], scenario)
        }
    }
    func testExplicitListenerErrorWhileAwaitingRetirementDoesNotBecomeAckFault() throws {
        let worker = try manager("fatal-retirement"); defer { worker.cancel() }
        var complete = false, reasons: [String] = []
        worker.completed = { _ in complete = true }
        worker.inputDisabled = { reasons.append($0) }
        worker.launch(request()); until(worker) { complete }
        worker.retire(); until(worker) { !reasons.isEmpty }
        XCTAssertEqual(reasons, ["input-monitoring-required"])
    }
    func testIdleEOFWithoutOutstandingTicketIsNotSilentlyRestartable() throws {
        let worker = try manager("idle-eof"); defer { worker.cancel() }
        var reasons: [String] = []
        worker.inputDisabled = { reasons.append($0) }
        worker.launch(request()); until(worker) { reasons.count == 1 }
        worker.poll(); XCTAssertEqual(reasons, ["input-monitoring-unavailable"])
    }
    func testUnsolicitedFatalFrameReachesParentWithoutContentRequest() throws {
        let worker = try manager("fatal"); defer { worker.cancel() }
        var reasons: [String] = []
        worker.inputDisabled = { reasons.append($0) }
        worker.launch(request()); until(worker) { !reasons.isEmpty }
        XCTAssertEqual(reasons, ["input-monitoring-disabled"])
    }
    func testSplitAckAndRepeatedAppRetireRequestsPreserveOriginalHandshake() throws {
        let worker = try manager("partial"); defer { worker.cancel() }
        var complete = false, faults = 0
        worker.completed = { _ in complete = true }; worker.inputDisabled = { _ in faults += 1 }
        worker.launch(request()); until(worker) { complete }
        worker.retire(); worker.retire(); worker.retire()
        until(worker) { worker.readyForRead }
        XCTAssertEqual(faults, 0)
    }
    func testStopDuringRetirementKillsOwnedChildAndIgnoresLateAck() throws {
        let worker = try manager("partial")
        var complete = false, faults = 0
        worker.completed = { _ in complete = true }; worker.inputDisabled = { _ in faults += 1 }
        worker.launch(request()); until(worker) { complete }
        worker.retire(); worker.cancel(); worker.poll()
        XCTAssertTrue(worker.readyForRead); XCTAssertEqual(faults, 0)
    }
    func testTerminalObserverDetachDoesNotRunRemoteUnregisterOrReleaseHandles() {
        final class Handle {
            let released: () -> Void
            init(_ released: @escaping () -> Void) { self.released = released }
            deinit { released() }
        }
        var order: [String] = [], released = false
        var retainedHandle: Handle? = Handle { released = true }
        ObserverTeardown.perform(forProcessExit: true, unregister: {
            XCTFail("Terminal retirement must not wait for remote provider unregister IPC")
        }, detach: { order.append("detach") }, release: { retainedHandle = nil })
        XCTAssertEqual(order, ["detach"]); XCTAssertNotNil(retainedHandle); XCTAssertFalse(released)
        ObserverTeardown.perform(forProcessExit: false, unregister: { order.append("unregister") },
            detach: { order.append("detach") }, release: { retainedHandle = nil; order.append("release") })
        XCTAssertEqual(order, ["detach", "unregister", "detach", "release"]); XCTAssertTrue(released)
    }
    private func queueHealthyAcknowledgement(_ worker: WorkerManager) throws -> URL {
        let directory = try XCTUnwrap(directories.last)
        worker.retire()
        worker.poll() // Send retire, but child cannot ACK until released below.
        try Data().write(to: directory.appendingPathComponent("release-ack"))
        let marker = directory.appendingPathComponent("ack-written")
        let timeout = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
        // Actual pipe write completes before this marker, without any parent poll.
        while !FileManager.default.fileExists(atPath: marker.path), DispatchTime.now().uptimeNanoseconds < timeout {
            Thread.sleep(forTimeInterval: 0.005)
        }
        let queued = FileManager.default.fileExists(atPath: marker.path)
        XCTAssertTrue(queued, "Synthetic Worker did not queue its ACK")
        guard queued else { throw CocoaError(.fileReadNoSuchFile) }
        return directory
    }
    func testHealthyAckQueuedBeforeDeadlineIsStillRejectedWhenParentOnlyPollsAfterIt() throws {
        var now: Int64 = 1000, complete = false, faults: [String] = []
        let worker = try manager("queued-ack", retirementNow: { now }); defer { worker.cancel() }
        worker.completed = { _ in complete = true }; worker.inputDisabled = { faults.append($0) }
        worker.launch(request()); until(worker) { complete }
        _ = try queueHealthyAcknowledgement(worker)
        now += 750 // Precisely at the original ACK cutoff is already late.
        worker.poll()
        XCTAssertEqual(faults, ["worker-retirement-ack-failed"])
        worker.poll(); XCTAssertEqual(faults.count, 1, "A queued ACK must not revive a timed-out session")
    }
    func testTimelyAckAndCleanReapAfterOriginalCutoffContinueThroughActualPipes() throws {
        var now: Int64 = 1000, completions = 0, faults: [String] = []
        let worker = try manager("hold-after-ack", retirementNow: { now }); defer { worker.cancel() }
        worker.completed = { _ in completions += 1 }; worker.inputDisabled = { faults.append($0) }
        worker.launch(request()); until(worker) { completions == 1 }
        let directory = try queueHealthyAcknowledgement(worker)
        now = 1743; worker.poll() // d−7ms; child must stay alive behind the exit barrier (WNOHANG == 0).
        XCTAssertFalse(worker.readyForRead); XCTAssertTrue(faults.isEmpty)
        now = 1794; worker.poll() // d+44ms; still pending in the bounded reap-only window.
        XCTAssertFalse(worker.readyForRead); XCTAssertTrue(faults.isEmpty)
        try Data().write(to: directory.appendingPathComponent("release-exit"))
        until(worker) { worker.readyForRead }
        XCTAssertTrue(faults.isEmpty); XCTAssertEqual(completions, 1, "The old Worker must not deliver again")
        worker.launch(request()); until(worker) { completions == 2 }
        XCTAssertTrue(faults.isEmpty)
    }
    func testTimelyAckDoesNotAllowLateOrNonzeroExitThroughActualPipes() throws {
        for scenario in ["hold-after-ack", "nonzero-after-ack"] {
            var now: Int64 = 1000, completions = 0, faults: [String] = []
            let worker = try manager(scenario, retirementNow: { now }); defer { worker.cancel() }
            worker.completed = { _ in completions += 1 }; worker.inputDisabled = { faults.append($0) }
            worker.launch(request()); until(worker) { completions == 1 }
            let directory = try queueHealthyAcknowledgement(worker)
            now = 1743; worker.poll()
            XCTAssertFalse(worker.readyForRead); XCTAssertTrue(faults.isEmpty)
            if scenario == "nonzero-after-ack" {
                now = 1794
                try Data().write(to: directory.appendingPathComponent("release-exit"))
                until(worker) { !faults.isEmpty }
            } else {
                now = 1842; worker.poll()
                XCTAssertFalse(worker.readyForRead); XCTAssertTrue(faults.isEmpty)
                now = 1843; worker.poll() // Exact expiry; this child still cannot exit through the barrier.
            }
            XCTAssertEqual(faults, ["worker-retirement-exit-unconfirmed"], scenario)
            worker.poll(); XCTAssertEqual(faults.count, 1)
            XCTAssertEqual(completions, 1)
        }
    }
    func testOwnerCancellationStillClearsAnAckedRetirementImmediately() throws {
        var now: Int64 = 1000, complete = false, faults: [String] = []
        let worker = try manager("hold-after-ack", retirementNow: { now }); defer { worker.cancel() }
        worker.completed = { _ in complete = true }; worker.inputDisabled = { faults.append($0) }
        worker.launch(request()); until(worker) { complete }
        let directory = try queueHealthyAcknowledgement(worker)
        now = 1743; worker.poll()
        XCTAssertFalse(worker.readyForRead); XCTAssertTrue(faults.isEmpty)
        worker.cancel() // No release-exit marker; explicit boundary owns cleanup.
        XCTAssertTrue(worker.readyForRead); XCTAssertTrue(faults.isEmpty)
        try Data().write(to: directory.appendingPathComponent("release-exit"))
        now = 1794; worker.poll(); XCTAssertTrue(faults.isEmpty)
    }
    func testSubmitDirtyFrameSignalsParentWithoutBreakingRetirement() throws {
        let worker = try manager("submit-dirty"); defer { worker.cancel() }
        var completions = 0, submitDirtyCount = 0, faults = 0
        worker.completed = { _ in completions += 1 }
        worker.submitDirty = { submitDirtyCount += 1 }
        worker.inputDisabled = { _ in faults += 1 }
        worker.launch(request())
        until(worker) { completions == 1 && submitDirtyCount == 1 }
        XCTAssertEqual(faults, 0)
        worker.retire()
        until(worker) { worker.readyForRead }
        XCTAssertEqual(faults, 0)
    }
    func testMenuTrackingAndMenuActionFramesDeliverOverPipeAndDropDuringRetirement() throws {
        let worker = try manager("menu-frames"); defer { worker.cancel() }
        var completions = 0, faults = 0
        var trackingEvents: [Bool] = []
        var actions: [MenuActionRecord] = []
        worker.completed = { _ in completions += 1 }
        worker.menuTracking = { trackingEvents.append($0) }
        worker.menuAction = { actions.append($0) }
        worker.inputDisabled = { _ in faults += 1 }
        worker.launch(request())
        until(worker) { completions == 1 && trackingEvents == [true, false] && actions.count == 1 }
        XCTAssertEqual(actions.first?.path, ["File", "Save"])
        XCTAssertEqual(faults, 0)
        // Late in-flight menu frames preceding the retirement ACK are dropped cleanly without faulting retirement.
        worker.retire()
        until(worker) { worker.readyForRead }
        XCTAssertEqual(faults, 0)
        XCTAssertEqual(actions.count, 1)
        XCTAssertEqual(trackingEvents, [true, false])
    }
    func testMenuActionFrameInSameBatchAsSecureInputIsDropped() throws {
        let worker = try manager("menu-secure-batch"); defer { worker.cancel() }
        var notices = 0, faults = 0
        var trackingEvents: [Bool] = []
        var actions: [MenuActionRecord] = []
        worker.secureInput = { notices += 1; worker.retire() }
        worker.menuTracking = { trackingEvents.append($0) }
        worker.menuAction = { actions.append($0) }
        worker.inputDisabled = { _ in faults += 1 }
        worker.launch(request())
        until(worker) { notices == 1 }
        until(worker) { worker.readyForRead }
        XCTAssertEqual(faults, 0)
        XCTAssertTrue(trackingEvents.isEmpty, "menuTracking in same batch as secureInput must be dropped")
        XCTAssertTrue(actions.isEmpty, "menuAction in same batch as secureInput must be dropped")
    }
    func testSessionUnsolicitedFrameFlushesMenuActionBeforeMenuTracking() throws {
        var queuedAction: MenuActionRecord? = MenuActionRecord(
            application: ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "birth-1"),
            path: ["App", "Quit"],
            truncated: false,
            observedAtMs: 2_000,
            privateState: "normal",
            captureEpoch: 1,
            foregroundGeneration: 0,
            focusGeneration: 0,
            policyRevision: 1,
            fieldSecurity: "strict"
        )
        var queuedTracking: Bool? = false
        var submitDirty = true
        var dirty = true
        var nextDirty: Int64 = 0

        func drainNext() -> Data? {
            nextSessionUnsolicitedFrame(
                takeMenuAction: { let r = queuedAction; queuedAction = nil; return r },
                takeMenuTracking: { let t = queuedTracking; queuedTracking = nil; return t },
                takeSubmitDirty: { let s = submitDirty; submitDirty = false; return s },
                takeDirty: { let d = dirty; dirty = false; return d },
                nowMs: 100,
                nextDirtyMs: &nextDirty,
                debounceMs: 50
            )
        }

        // Committed menuAction must flush BEFORE menuTracking: false so Hide/Quit/app-switch cannot drop it.
        let first = try XCTUnwrap(drainNext())
        XCTAssertEqual(first.last, 10)
        let decoded = try JSONDecoder().decode(MenuActionPipeFrame.self, from: Data(first.dropLast()))
        XCTAssertEqual(decoded.menuAction.path, ["App", "Quit"])

        let second = try XCTUnwrap(drainNext())
        XCTAssertEqual(second, Data("{\"menuTracking\":false}\n".utf8))

        let third = try XCTUnwrap(drainNext())
        XCTAssertEqual(third, Data("{\"submitDirty\":true}\n".utf8))

        let fourth = try XCTUnwrap(drainNext())
        XCTAssertEqual(fourth, Data("{\"dirty\":true}\n".utf8))
        XCTAssertEqual(nextDirty, 150)

        // When opening a menu with no committed action queued, menuTracking: true flushes immediately.
        queuedTracking = true
        let openFrame = try XCTUnwrap(drainNext())
        XCTAssertEqual(openFrame, Data("{\"menuTracking\":true}\n".utf8))
    }
}

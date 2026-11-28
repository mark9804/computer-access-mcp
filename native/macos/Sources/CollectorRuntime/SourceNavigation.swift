import Foundation
import AppKit
import ApplicationServices
import Darwin
import CCollectorSupport
import CollectorCore

/// This provider never constructs AXFieldProvider, NativeEnvironment, a worker,
/// CollectorEngine or OwnerLock. It has no historic window/node or text path.
private struct NativeSourceNavigationProvider: SourceNavigationProvider {
    func sessionEvidence() -> SourceNavigationSessionEvidence {
        let uid = getuid(), effectiveUID = geteuid()
        var auditBefore: UInt32 = 0, auditAfter: UInt32 = 0
        let auditBeforeValid = collector_audit_session(&auditBefore) == 0
        let before = DesktopSessionEvidence(CGSessionCopyCurrentDictionary() as? [String: Any])
        let assessment = desktopAssessment()
        let after = DesktopSessionEvidence(CGSessionCopyCurrentDictionary() as? [String: Any])
        let auditAfterValid = collector_audit_session(&auditAfter) == 0
        let stable = before == after && before.valid && after.valid && uid == getuid() && effectiveUID == geteuid()
        let audit = auditBeforeValid && auditAfterValid && auditBefore == auditAfter ? auditBefore : nil
        // Positive outer lock/transition evidence also wins; a briefly unlocked
        // inner assessment cannot erase the surrounding session samples.
        let safeOuterSession = stable && before.onConsole == true && before.loginDone == true &&
            before.screenLocked != true && !before.transition
        return SourceNavigationSessionEvidence(userId: uid, effectiveUserId: effectiveUID, auditSessionId: audit,
            consoleUserId: stable ? after.uid : nil, consoleAuditSessionId: stable ? after.audit : nil,
            desktop: safeOuterSession ? assessment.desktopStatus : .unknown)
    }

    private func evidence(_ app: NSRunningApplication?) -> SourceNavigationApplicationEvidence? {
        guard let app, !app.isTerminated, app.processIdentifier > 1,
              let bundle = app.bundleIdentifier, !bundle.isEmpty, bundle.utf8.count <= 256,
              let launch = app.launchDate, launch.timeIntervalSince1970.isFinite, launch.timeIntervalSince1970 > 0 else { return nil }
        // Exact same birth representation as the capture identity; a PID alone,
        // executable path, name or bundle identifier cannot recover an old target.
        let identity = ApplicationIdentity(applicationId: bundle, processId: app.processIdentifier,
            processStartTime: String(format: "unix-ms:%.3f", launch.timeIntervalSince1970 * 1_000))
        // This static helper reads bundle metadata only, not AX/TCC or content.
        return SourceNavigationApplicationEvidence(identity: identity, permittedNonBrowser: AppIdentityGate.permittedNonBrowser(app))
    }

    func runningApplication(processId: Int32) -> SourceNavigationApplicationEvidence? {
        evidence(NSRunningApplication(processIdentifier: processId))
    }

    func activate(_ request: SourceNavigationRequest, markDispatched: () -> SourceNavigationReason?) -> SourceNavigationDispatch {
        // Do not reuse an object from the initial gate. Resolve this PID afresh
        // and validate bundle + birth again immediately before the single action.
        if let reason = SourceNavigationGate.session(request, sessionEvidence()) { return .notDispatched(reason) }
        let app = NSRunningApplication(processIdentifier: request.processId)
        if let reason = SourceNavigationGate.application(request, evidence(app)) { return .notDispatched(reason) }
        guard let app, !app.isTerminated else { return .notDispatched(.applicationUnavailable) }
        if let reason = markDispatched() { return .notDispatched(reason) }
        // No URL/open/launch, no AX actions, no all-windows option, no retry.
        return .submitted(accepted: app.activate())
    }

    func frontmostApplication() -> SourceNavigationApplicationEvidence? {
        evidence(NSWorkspace.shared.frontmostApplication)
    }
}

/// A separate queue enforces parent loss and a total deadline even if AppKit is
/// blocked. Dispatch is marked before entering activate, so an unknown effect is
/// never misreported as a safely refused action. No automatic retries exist.
private final class SourceNavigationWatchdog {
    private let lock = NSLock()
    private let parent: pid_t
    private let started = DispatchTime.now().uptimeNanoseconds
    private var dispatched = false
    private var finished = false
    private var timer: DispatchSourceTimer?
    static let inputNanoseconds: UInt64 = 1_000_000_000
    static let totalNanoseconds: UInt64 = 4_000_000_000

    init(parent: pid_t) { self.parent = parent }
    private var elapsed: UInt64 { DispatchTime.now().uptimeNanoseconds - started }
    private func boundaryReason() -> SourceNavigationReason? {
        if parent <= 1 || getppid() != parent { return .parentUnavailable }
        if elapsed >= Self.totalNanoseconds { return .deadlineExceeded }
        return nil
    }
    func start() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "source-navigation-watchdog", qos: .userInitiated))
        timer.schedule(deadline: .now(), repeating: .milliseconds(20), leeway: .milliseconds(2))
        timer.setEventHandler { [weak self] in
            guard let self, let reason = self.boundaryReason() else { return }
            self.finish(reason: reason)
        }
        self.timer = timer
        timer.resume()
    }
    func inputBoundary() -> SourceNavigationReason? {
        if let reason = boundaryReason() { return reason }
        return elapsed >= Self.inputNanoseconds ? .inputTimeout : nil
    }
    func markDispatched() -> SourceNavigationReason? {
        lock.lock(); defer { lock.unlock() }
        if let reason = boundaryReason() { return reason }
        guard !finished else { return .deadlineExceeded }
        dispatched = true
        return nil
    }
    func finish(reason: SourceNavigationReason) -> Never {
        lock.lock()
        finishLocked(SourceNavigationReceipt(reason: reason, afterDispatch: dispatched))
    }
    func finish(_ receipt: SourceNavigationReceipt) -> Never {
        lock.lock()
        if let reason = boundaryReason() {
            finishLocked(SourceNavigationReceipt(reason: reason, afterDispatch: dispatched))
        }
        finishLocked(receipt)
    }
    private func finishLocked(_ receipt: SourceNavigationReceipt) -> Never {
        // The winning writer exits while holding the lock: a watchdog/main race
        // cannot concatenate two responses or dispatch after a timeout receipt.
        finished = true
        let success = writeSourceNavigationReceipt(receipt)
        Darwin._exit(success ? receipt.exitCode : 74)
    }
}

private func readSourceNavigationInput(_ watchdog: SourceNavigationWatchdog) -> Result<Data, SourceNavigationReason> {
    guard isatty(STDIN_FILENO) == 0 else { return .failure(.inputUnavailable) }
    let flags = fcntl(STDIN_FILENO, F_GETFL)
    guard flags >= 0, fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == 0 else { return .failure(.inputUnavailable) }
    var data = Data()
    var chunk = [UInt8](repeating: 0, count: 256)
    while true {
        if let reason = watchdog.inputBoundary() { return .failure(reason) }
        let count = Darwin.read(STDIN_FILENO, &chunk, chunk.count)
        if count > 0 {
            guard data.count + count <= SourceNavigationRequest.maximumInputBytes else { return .failure(.inputTooLarge) }
            data.append(contentsOf: chunk.prefix(count))
        } else if count == 0 { return .success(data) }
        else if errno == EINTR { continue }
        else if errno == EAGAIN || errno == EWOULDBLOCK {
            var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
            if poll(&descriptor, 1, 20) < 0 && errno != EINTR { return .failure(.inputUnavailable) }
            if descriptor.revents & Int16(POLLNVAL) != 0 { return .failure(.inputUnavailable) }
        } else { return .failure(.inputUnavailable) }
    }
}

private func writeSourceNavigationReceipt(_ receipt: SourceNavigationReceipt) -> Bool {
    let bytes = receipt.encodedLine()
    guard bytes.count <= SourceNavigationReceipt.maximumOutputBytes, isatty(STDOUT_FILENO) == 0 else { return false }
    let flags = fcntl(STDOUT_FILENO, F_GETFL)
    guard flags >= 0, fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK) == 0 else { return false }
    let deadline = DispatchTime.now().uptimeNanoseconds + 250_000_000
    var offset = 0
    while offset < bytes.count && DispatchTime.now().uptimeNanoseconds < deadline {
        let count = bytes.withUnsafeBytes { Darwin.write(STDOUT_FILENO, $0.baseAddress!.advanced(by: offset), $0.count - offset) }
        if count > 0 { offset += count }
        else if count < 0 && errno == EINTR { continue }
        else if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
            var descriptor = pollfd(fd: STDOUT_FILENO, events: Int16(POLLOUT), revents: 0)
            if poll(&descriptor, 1, 10) < 0 && errno != EINTR { return false }
            if descriptor.revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 { return false }
        } else { return false }
    }
    return offset == bytes.count
}

/// Only the exact first mode branch reaches here. Stdin must close after a single
/// <=2048-byte JSON request. Invalid input is rejected before touching AppKit.
func runSourceNavigation() -> Int32 {
    signal(SIGPIPE, SIG_IGN)
    let watchdog = SourceNavigationWatchdog(parent: getppid())
    watchdog.start()
    let data: Data
    switch readSourceNavigationInput(watchdog) {
    case .success(let value): data = value
    case .failure(let reason): watchdog.finish(reason: reason)
    }
    let request: SourceNavigationRequest
    do { request = try SourceNavigationRequest.parse(data) }
    catch let reason as SourceNavigationReason { watchdog.finish(reason: reason) }
    catch { watchdog.finish(reason: .internalError) }
    let receipt = SourceNavigation.navigate(request, provider: NativeSourceNavigationProvider(), markDispatched: watchdog.markDispatched)
    watchdog.finish(receipt)
}

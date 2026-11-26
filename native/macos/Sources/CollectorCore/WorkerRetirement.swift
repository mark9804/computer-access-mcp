import Foundation

/// Control-plane worker retirement handshake state.
public struct WorkerRetirement {
    public let pid: Int32
    public let sessionToken: String
    public let retireToken: String

    public enum Failure: String {
        case ackFailed = "worker-retirement-ack-failed"
        case exitUnconfirmed = "worker-retirement-exit-unconfirmed"
    }

    public let deadlineMs: Int64
    public private(set) var reapDeadlineMs: Int64?
    public var acknowledged: Bool { reapDeadlineMs != nil }
    public var failureReason: Failure { acknowledged ? .exitUnconfirmed : .ackFailed }
    public private(set) var failed = false

    public init(pid: Int32, sessionToken: String, retireToken: String, nowMs: Int64, readDeadlineMs: Int64? = nil) {
        let remainingRead = min(5_000, max(0, (readDeadlineMs ?? nowMs) - nowMs))
        self.pid = pid
        self.sessionToken = sessionToken
        self.retireToken = retireToken
        self.deadlineMs = nowMs + remainingRead + 750
    }

    public mutating func acknowledge(pid: Int32, sessionToken: String, retireToken: String, healthy: Bool, nowMs: Int64) -> Bool {
        guard !failed, !acknowledged, nowMs < deadlineMs, self.pid == pid,
              self.sessionToken == sessionToken, self.retireToken == retireToken, healthy else {
            failed = true
            return false
        }
        reapDeadlineMs = max(deadlineMs, nowMs + 100)
        return true
    }

    public mutating func fault() { failed = true }

    public func mayReplace(reapedPID: Int32, waitStatus: Int32, nowMs: Int64) -> Bool {
        guard let reapDeadlineMs else { return false }
        return !failed && pid > 0 && reapedPID == pid && waitStatus == 0 && nowMs < reapDeadlineMs
    }
}

/// Detaches local run-loop observer source during process exit without blocking on remote unregister IPC.
public enum ObserverTeardown {
    public static func perform(
        forProcessExit: Bool,
        unregister: () -> Void,
        detach: () -> Void,
        release: () -> Void
    ) {
        if !forProcessExit { unregister() }
        detach()
        if !forProcessExit { release() }
    }
}

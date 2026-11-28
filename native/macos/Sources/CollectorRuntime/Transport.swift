import Foundation
import Darwin
import HistoryContract

/// Nonblocking stdout, bounded in frames/bytes/time. Never use FileHandle.write
/// on the control loop: a Host that stops reading cannot pin worker shutdown.
final class BoundedOutput {
    private struct Item { var data: Data; var offset: Int; var observation: Bool }
    private var items: [Item] = []
    private let validator: ContractValidator
    private var blockedSince: UInt64?
    var maxPending = 8
    private(set) var failed = false
    var empty: Bool { items.isEmpty }
    init(validator: ContractValidator) {
        self.validator = validator
        let flags = fcntl(STDOUT_FILENO, F_GETFL)
        if flags >= 0 { _ = fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK) }
        signal(SIGPIPE, SIG_IGN)
    }
    func enqueue(_ message: JSONValue) {
        guard !failed else { return }
        guard let data = try? validator.encodeFrame(message) else { failed = true; return }
        let observation = message["type"] == .string("observation")
        let observations = items.filter(\.observation).count
        guard items.count < maxPending + 8, (!observation || observations < maxPending),
              items.reduce(0, { $0 + $1.data.count - $1.offset }) + data.count <= 524_288 else { failed = true; return }
        items.append(Item(data: data, offset: 0, observation: observation))
        flush()
    }
    func discardObservations() {
        // A partially written NDJSON line cannot be retracted without corrupting
        // framing; Host independently rejects its old stamp after revocation.
        items.removeAll { $0.observation && $0.offset == 0 }
    }
    func flush() {
        guard !failed else { return }
        for _ in 0..<8 {
            guard let first = items.first else { blockedSince = nil; return }
            let (written, writeError): (Int, Int32) = first.data.withUnsafeBytes { bytes in
                guard let base = bytes.baseAddress, first.offset < bytes.count else { return (0, 0) }
                let n = Darwin.write(STDOUT_FILENO, base.advanced(by: first.offset), bytes.count - first.offset)
                return (n, errno)
            }
            if written > 0 {
                blockedSince = nil; items[0].offset += written
                if items[0].offset == items[0].data.count { items.removeFirst() }
            } else if written < 0 && writeError == EINTR { continue }
            else if written < 0 && (writeError == EAGAIN || writeError == EWOULDBLOCK) {
                let now = DispatchTime.now().uptimeNanoseconds
                if let since = blockedSince, now - since >= 250_000_000 { failed = true }
                else if blockedSince == nil { blockedSince = now }
                return
            } else { failed = true; return }
        }
    }
}

final class InputFrames {
    private var validator: JSONLValidator
    init(_ contract: ContractValidator) {
        validator = JSONLValidator(validator: contract)
        let flags = fcntl(STDIN_FILENO, F_GETFL)
        if flags >= 0 { _ = fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) }
    }
    /// At most 32 KiB per tick prevents a hostile writer starving lease checks.
    func drain(_ emit: (ValidationResult) -> Void) -> Bool {
        var bytes = [UInt8](repeating: 0, count: 4096)
        for _ in 0..<8 {
            let count = Darwin.read(STDIN_FILENO, &bytes, bytes.count)
            let readError = errno
            if count > 0 { validator.push(Data(bytes.prefix(count)), emit: emit) }
            else if count == 0 { validator.finish(emit: emit); return false }
            else if readError == EINTR { continue }
            else if readError == EAGAIN || readError == EWOULDBLOCK { return true }
            else { return false }
        }
        return true
    }
}

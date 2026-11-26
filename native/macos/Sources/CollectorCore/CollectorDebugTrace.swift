import Foundation
import Darwin
import MachO
import Synchronization

/// Development diagnostics only: fixed call sites, counters, closed reason codes
/// and explicitly authorized application metadata. Never content, window titles,
/// input characters, argv or raw errors; Host independently projects each field.
/// Opt-in comes from the owning Host, not content or a public capture policy.
public enum CollectorDebugTrace {
    private struct RateLimitState: Sendable {
        var lastCode: String?
        var lastTime: UInt64 = 0
    }

    public static let enabled = ProcessInfo.processInfo.environment["DSH_COMPUTER_HISTORY_DEBUG"] == "1"
        || ProcessInfo.processInfo.environment["COMPUTER_HISTORY_DEBUG"] == "1"

    private static let rateLimit = Mutex(RateLimitState())

    public static func record(_ code: String, numbers: [String: Int64] = [:], flags: [String: Bool] = [:],
                              strings: [String: String] = [:], stack: Bool = false, file: StaticString = #fileID, line: UInt = #line) {
        guard enabled else { return }
        // Do not exhaust a lifetime allowance during a long debug run. Repeated
        // nonfatal samples are rate limited; faults always get one atomic attempt.
        // Distinct phases/reasons/branches of one read must not suppress each
        // other. The bounded key contains no app name, title or content.
        let key = [code, strings["stage"] ?? "", strings["reason"] ?? "", strings["status"] ?? "",
                    strings["phase"] ?? "", strings["outcome"] ?? "",
                   numbers["requestId"].map(String.init) ?? "", numbers["readId"].map(String.init) ?? "",
                   numbers["nodeIndex"].map(String.init) ?? ""].joined(separator: ":")
        let permitted = rateLimit.withLockIfAvailable { state -> Bool in
            let now = DispatchTime.now().uptimeNanoseconds
            if !stack, state.lastCode == key, now >= state.lastTime, now - state.lastTime < 1_000_000_000 { return false }
            state.lastCode = key
            state.lastTime = now
            return true
        }
        guard permitted == true else { return }
        var value: [String: Any] = ["version": 1, "code": code, "pid": getpid(),
            "timeMs": Int64(Date().timeIntervalSince1970 * 1000),
            "monotonicMs": Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000),
            "file": String(describing: file).split(separator: "/").last.map(String.init) ?? "unknown",
            "line": line, "numbers": numbers, "flags": flags]
        if !strings.isEmpty {
            var bounded: [String: String] = [:]
            for (key, raw) in strings {
                if key == "applicationId" {
                    // Never truncate an identifier into a different-looking ID.
                    if raw.utf16.count <= 256 && !raw.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) { bounded[key] = raw }
                } else { bounded[key] = String(raw.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.prefix(128)) }
            }
            value["strings"] = bounded
        }
        if stack {
            value["stack"] = Thread.callStackReturnAddresses.prefix(12).map { "0x" + String($0.uint64Value, radix: 16) }
            if let header = _dyld_get_image_header(0) { value["imageBase"] = "0x" + String(UInt(bitPattern: header), radix: 16) }
        }
        // Darwin PIPE_BUF may be only 512. Parent and worker share this pipe;
        // shorten optional stack addresses until the ENTIRE line is atomic.
        let pipeLimit = fpathconf(STDERR_FILENO, _PC_PIPE_BUF)
        let limit = pipeLimit > 0 ? min(Int(pipeLimit), 4000) : 512
        var addresses = value["stack"] as? [String] ?? []
        var encoded = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        while let data = encoded, data.count + 1 > limit, !addresses.isEmpty {
            addresses.removeLast(); value["stack"] = addresses
            encoded = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        }
        // Application names are optional metadata. Truncate by Unicode scalar
        // until the complete record fits the same atomic write, never split it.
        var fields = value["strings"] as? [String: String] ?? [:]
        while let data = encoded, data.count + 1 > limit, let name = fields["applicationName"], !name.isEmpty {
            let scalars = name.unicodeScalars
            fields["applicationName"] = String(String.UnicodeScalarView(scalars.dropLast()))
            value["strings"] = fields
            encoded = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        }
        guard var data = encoded, data.count + 1 <= limit else { return }
        data.append(10)
        let old = fcntl(STDERR_FILENO, F_GETFL)
        guard old >= 0 else { return }
        if (old & O_NONBLOCK) == 0, fcntl(STDERR_FILENO, F_SETFL, old | O_NONBLOCK) != 0 { return }
        _ = data.withUnsafeBytes { Darwin.write(STDERR_FILENO, $0.baseAddress, $0.count) }
    }
}

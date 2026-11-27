import Foundation
import Darwin
import CCollectorSupport

struct OwnerLock: ~Copyable {
    private var directory: Int32
    private var file: Int32
    let sessionId: String
    enum Failure: Error { case session, path, busy }

    init(fixture: Bool, fixtureLockId: String?) throws {
        let session: String
        if fixture { session = "fixture-" + (fixtureLockId ?? UUID().uuidString) }
        else {
            var id: UInt32 = 0
            guard collector_audit_session(&id) == 0 else { throw Failure.session }
            session = "audit-\(id)"
        }
        // Open one component at a time without following symlinks. /private/tmp
        // is the canonical macOS temporary parent, not the /tmp symlink.
        let root = open("/private/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard root >= 0 else { throw Failure.path }
        defer { close(root) }
        let name = "dsh-computer-history-\(getuid())"
        if mkdirat(root, name, mode_t(0o700)) != 0 && errno != EEXIST { throw Failure.path }
        let dir = openat(root, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard dir >= 0 else { throw Failure.path }
        var statDir = stat()
        guard fstat(dir, &statDir) == 0, statDir.st_uid == getuid(), statDir.st_mode & 0o777 == 0o700 else { close(dir); throw Failure.path }
        let fd = openat(dir, "collector-\(session).lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, mode_t(0o600))
        guard fd >= 0 else { close(dir); throw Failure.path }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o777 == 0o600, info.st_nlink == 1 else { close(fd); close(dir); throw Failure.path }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { close(fd); close(dir); throw Failure.busy }
        self.directory = dir; self.file = fd; self.sessionId = session
    }

    mutating func release() {
        if file >= 0 {
            flock(file, LOCK_UN)
            close(file)
            file = -1
        }
        if directory >= 0 {
            close(directory)
            directory = -1
        }
    }

    deinit {
        if file >= 0 {
            flock(file, LOCK_UN)
            close(file)
        }
        if directory >= 0 {
            close(directory)
        }
    }
}

struct CLIOptions {
    let fixture: Bool
    let worker: Bool
    var sessionWorker: Bool = false
    let owner: String
    let instance: String
    let device: String
    let scenario: String
    let fixtureLock: String?
    static func parse(_ args: [String]) -> CLIOptions? {
        guard let mode = args.first, ["--serve", "--fixture", "--ax-worker"].contains(mode) else { return nil }
        let worker = mode == "--ax-worker"
        var values: [String: String] = [:]
        var index = 1
        while index < args.count {
            let key = args[index]
            guard ["--owner-id", "--instance-id", "--device-id", "--fixture-scenario", "--fixture-lock-id", "--parent-pid", "--worker-token", "--synthetic", "--session-worker"].contains(key),
                  index + 1 < args.count, values[key] == nil else { return nil }
            values[key] = args[index + 1]; index += 2
        }
        if worker {
            guard let parent = values["--parent-pid"].flatMap(Int32.init), parent == getppid(), parent > 1,
                  let token = values["--worker-token"], token.count == 36,
                  isatty(STDIN_FILENO) == 0, isatty(STDOUT_FILENO) == 0,
                  ProcessInfo.processInfo.environment["DSH_COLLECTOR_WORKER_TOKEN"] == token else { return nil }
            return CLIOptions(fixture: values["--synthetic"] == "yes", worker: true, sessionWorker: values["--session-worker"] == "yes", owner: "", instance: "", device: "", scenario: values["--fixture-scenario"] ?? "allowed", fixtureLock: nil)
        }
        guard let owner = values["--owner-id"], let instance = values["--instance-id"], let device = values["--device-id"],
              validId(owner), validId(instance), validId(device),
              values["--parent-pid"] == nil, values["--worker-token"] == nil, values["--synthetic"] == nil, values["--session-worker"] == nil else { return nil }
        let fixture = mode == "--fixture"
        let scenario = values["--fixture-scenario"] ?? "allowed"
        guard ["allowed", "activity", "locked", "unknown", "workerhang", "empty", "partial", "value", "focus-loss", "sensitive", "browser", "readerror"].contains(scenario),
              fixture || (values["--fixture-scenario"] == nil && values["--fixture-lock-id"] == nil) else { return nil }
        if let lock = values["--fixture-lock-id"], lock.isEmpty || lock.count > 64 || !lock.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }) { return nil }
        return CLIOptions(fixture: fixture, worker: false, owner: owner, instance: instance, device: device, scenario: scenario, fixtureLock: values["--fixture-lock-id"])
    }
    static func validId(_ id: String) -> Bool { !id.isEmpty && id.utf16.count <= 96 && !id.unicodeScalars.contains(where: { $0.value < 32 }) }
}

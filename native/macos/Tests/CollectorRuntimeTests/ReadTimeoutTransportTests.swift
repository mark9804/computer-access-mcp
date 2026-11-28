import XCTest
import Foundation
import Darwin
@testable import CollectorCore
@testable import CollectorRuntime

/// Run real spawn, inherited FD, pipe and waitpid with an inert C child. The
/// child models only a focus call boundary: no AX, TCC, desktop or input tap.
final class ReadTimeoutTransportTests: XCTestCase {
    func testOwnedChildIsRecoveredOnForcedKillDeadlineExitAndLateCompletionButRejectsUnrelatedExit() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).resolvingSymlinksInPath()
            .appendingPathComponent("dsh-timeout-fixture-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { if root.lastPathComponent.hasPrefix("dsh-timeout-fixture-"), root == root.resolvingSymlinksInPath() { try? FileManager.default.removeItem(at: root) } }
        let source = root.appendingPathComponent("fixture.c"), exe = root.appendingPathComponent("fixture")
        try #"""
        #include "CCollectorSupport.h"
        #include <stdio.h>
        #include <poll.h>
        #include <unistd.h>
        #include <fcntl.h>
        #include <stdlib.h>
        #include <string.h>
        #include <time.h>
        int main(int argc, char **argv) {
            char bytes[65536];
            if (!fgets(bytes, sizeof(bytes), stdin)) return 6;
            char *mark = strstr(bytes, "\"deadlineMonotonicMs\":");
            if (!mark || !getenv("DSH_COMPUTER_HISTORY_PROGRESS_FD")) return 7;
            long long end = strtoll(strchr(mark, ':') + 1, 0, 10);
            collector_progress_page *page = collector_progress_attach(198);
            if (end <= 0 || !page) return 8;
            // Rely on a numeric synthetic policyRevision, not any GUI or app name.
            char *rev = strstr(bytes, "\"policyRevision\":");
            long revision = rev ? strtol(strchr(rev, ':') + 1, 0, 10) : 0;
            if (revision < 1 || revision > 11) return 13;
            const char *kind = revision == 1 ? "match" : revision == 2 ? "outside-focus" :
                revision == 3 ? "pending" : revision == 4 ? "watchdog" :
                revision == 5 ? "unrelated" : revision == 6 ? "late-reply" :
                revision == 7 ? "pending-input-disabled" : revision == 8 ? "pending-secure-input" :
                revision == 9 ? "late-app-changed" : revision == 10 ? "pending-input-result" :
                "late-reply-eof-reader";
            alarm(4);
            collector_focus_fence_set(page, end - (strcmp(kind, "outside-focus") == 0));
            if (revision >= 6) {
                // Wait for parent barrier so launch()'s synchronous poll() cannot race ahead of deadline.
                char goPath[64];
                snprintf(goPath, sizeof(goPath), "go-%ld", revision);
                while (access(goPath, F_OK) != 0) {
                    struct timespec step = {0, 1000000};
                    nanosleep(&step, 0);
                }
            }
            if (!strcmp(kind, "pending") && write(STDOUT_FILENO, "{", 1) != 1) return 14;
            if (!strcmp(kind, "late-reply") || !strcmp(kind, "late-app-changed") ||
                !strcmp(kind, "pending-input-result") || !strcmp(kind, "late-reply-eof-reader")) {
                const char *tok = getenv("DSH_COLLECTOR_WORKER_TOKEN");
                const char *reason = !strcmp(kind, "late-app-changed") ? "session-app-changed" :
                    !strcmp(kind, "pending-input-result") ? "input-monitoring-required" : "read-error";
                char reply[512];
                int len = snprintf(reply, sizeof(reply),
                    "{\"token\":\"%s\",\"reason\":\"%s\",\"captureStartMs\":1,\"captureEndMs\":1}\n",
                    tok ? tok : "", reason);
                if (len <= 0 || write(STDOUT_FILENO, reply, (size_t)len) != len) return 15;
            }
            if (!strcmp(kind, "pending-input-disabled")) {
                const char *msg = "{\"inputDisabled\":\"input-monitoring-disabled\"}\n";
                if (write(STDOUT_FILENO, msg, strlen(msg)) != (ssize_t)strlen(msg)) return 16;
            }
            if (!strcmp(kind, "pending-secure-input")) {
                const char *msg = "{\"secureInput\":true}\n";
                if (write(STDOUT_FILENO, msg, strlen(msg)) != (ssize_t)strlen(msg)) return 17;
            }
            if (close(open("ready", O_TRUNC|O_WRONLY|O_CREAT, 0600))) return 9;
            if (!strcmp(kind, "watchdog") || !strcmp(kind, "unrelated")) {
                for (;;) {
                    struct timespec at;
                    clock_gettime(CLOCK_UPTIME_RAW, &at);
                    if (at.tv_sec * 1000LL + at.tv_nsec / 1000000 >= end) break;
                    struct timespec step = {0, 1000000}; nanosleep(&step, 0);
                }
                _exit(!strcmp(kind, "watchdog") ? 76 : 70);
            }
            if (!strcmp(kind, "late-reply-eof-reader")) {
                // Mirror runSessionWorker: actively read stdin and return 0 on EOF.
                // Parent must SIGKILL before closing stdin or this child would exit 0.
                while (fgets(bytes, sizeof(bytes), stdin) != NULL) {}
                return 0;
            }
            for (;;) pause();
        }
        """#.write(to: source, atomically: true, encoding: .utf8)
        let support = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Sources/CCollectorSupport")
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/clang")
        compiler.arguments = ["-I", support.appendingPathComponent("include").path, source.path, support.appendingPathComponent("progress.c").path, "-o", exe.path]
        try compiler.run(); compiler.waitUntilExit(); XCTAssertEqual(compiler.terminationStatus, 0)
        // WorkerManager inherits the test process's working directory, not a data root.
        // Give only the inert child a private cwd for its synthetic readiness marker.
        for revision in 1...11 {
            let marker = root.appendingPathComponent("ready-\(revision)")
            let goFile = root.appendingPathComponent("go-\(revision)")
            let wrapper = root.appendingPathComponent("launch-\(revision)")
            try "#!/bin/sh\ncd '\(root.path)' || exit 12\nexec '\(exe.path)' \"$@\"\n".write(to: wrapper, atomically: true, encoding: .utf8)
            XCTAssertEqual(chmod(wrapper.path, 0o700), 0)
            let manager = WorkerManager(executable: wrapper.path, fixture: false, scenario: "unused")
            defer { manager.cancel() }
            let clock = SystemCollectorClock(), started = clock.monotonicMs
            let ticket = ReadTicket(token: UUID().uuidString, policyRevision: Int64(revision), captureEpoch: 1,
                policy: CapturePolicy(inputText: true), hint: nil, deadlineMonotonicMs: started + 650,
                deviceId: "test-device", osSessionId: "test-session", desktopId: "test-desktop")
            var completions = 0, faults: [String] = [], secureNotices = 0
            var lateAbortResult: ReadTimeoutCleanup?
            let isLateCompletionCase = [6, 9, 11].contains(revision)
            manager.completed = { _ in
                completions += 1
                if isLateCompletionCase {
                    lateAbortResult = manager.abortTimedOutRead(ticket)
                }
            }
            manager.inputDisabled = { faults.append($0) }
            manager.secureInput = { secureNotices += 1 }
            manager.launch(ticket)
            XCTAssertEqual(completions, 0, "launch() must not prematurely dispatch frame for revision \(revision)")
            XCTAssertTrue(faults.isEmpty, "launch() must not prematurely fault for revision \(revision)")
            XCTAssertEqual(secureNotices, 0, "launch() must not prematurely notice secureInput for revision \(revision)")
            if revision >= 6 {
                try Data().write(to: goFile)
            }
            let ready = root.appendingPathComponent("ready")
            while clock.monotonicMs < ticket.deadlineMonotonicMs - 80 && !FileManager.default.fileExists(atPath: ready.path) {
                Thread.sleep(forTimeInterval: 0.005)
            }
            XCTAssertTrue(FileManager.default.fileExists(atPath: ready.path), "synthetic child never reached the expected fence for revision \(revision)")
            try FileManager.default.moveItem(at: ready, to: marker)
            while clock.monotonicMs < ticket.deadlineMonotonicMs + (revision >= 4 ? 20 : 0) {
                Thread.sleep(forTimeInterval: 0.004)
            }
            var result: ReadTimeoutCleanup
            if isLateCompletionCase {
                manager.poll()
                result = try XCTUnwrap(lateAbortResult, "late completion must synchronously trigger abortTimedOutRead for revision \(revision)")
            } else {
                result = manager.abortTimedOutRead(ticket)
            }
            while result == .awaitingExit && clock.monotonicMs < ticket.deadlineMonotonicMs + 850 {
                Thread.sleep(forTimeInterval: 0.004); result = manager.timedOutReadCleanup()
            }
            let expected: ReadTimeoutCleanup = [5, 7, 8, 9, 10].contains(revision) ? .ineligible : .reaped
            XCTAssertEqual(result, expected, "revision \(revision)")
            if revision == 9 {
                XCTAssertFalse(manager.readyForRead, "retirement handshake must stay intact until explicitly cancelled or ACKed")
            } else {
                XCTAssertTrue(manager.readyForRead, "revision \(revision)")
            }
            XCTAssertEqual(completions, isLateCompletionCase ? 1 : 0, "revision \(revision)")
            let expectedFaults: [String] = revision == 7 ? ["input-monitoring-disabled"] :
                revision == 10 ? ["input-monitoring-required"] : []
            XCTAssertEqual(faults, expectedFaults, "revision \(revision)")
            XCTAssertEqual(secureNotices, revision == 8 ? 1 : 0, "revision \(revision)")
        }
    }
}

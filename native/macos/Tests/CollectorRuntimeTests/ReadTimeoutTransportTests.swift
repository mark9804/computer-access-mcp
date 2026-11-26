import XCTest
import Foundation
import Darwin
@testable import CollectorCore
@testable import CollectorRuntime

/// Run real spawn, inherited FD, pipe and waitpid with an inert C child. The
/// child models only a focus call boundary: no AX, TCC, desktop or input tap.
final class ReadTimeoutTransportTests: XCTestCase {
    func testOwnedChildIsRecoveredOnlyInsideTheExactInitialFocusFence() throws {
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
            if (revision < 1 || revision > 5) return 13;
            const char *kind = revision == 1 ? "match" : revision == 2 ? "stale" :
                revision == 3 ? "pending" : revision == 4 ? "watchdog" : "unrelated";
            collector_focus_fence_set(page, end - (strcmp(kind, "stale") == 0));
            if (!strcmp(kind, "pending") && write(STDOUT_FILENO, "{", 1) != 1) return 14;
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
            // One inert process, bounded even if the test fails before reaping.
            alarm(4);
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
        for revision in 1...5 {
            let marker = root.appendingPathComponent("ready-\(revision)")
            let wrapper = root.appendingPathComponent("launch-\(revision)")
            try "#!/bin/sh\ncd '\(root.path)' || exit 12\nexec '\(exe.path)' \"$@\"\n".write(to: wrapper, atomically: true, encoding: .utf8)
            XCTAssertEqual(chmod(wrapper.path, 0o700), 0)
            let manager = WorkerManager(executable: wrapper.path, fixture: false, scenario: "unused")
            defer { manager.cancel() }
            let clock = SystemCollectorClock(), started = clock.monotonicMs
            let ticket = ReadTicket(token: UUID().uuidString, policyRevision: Int64(revision), captureEpoch: 1,
                policy: CapturePolicy(inputText: true), hint: nil, deadlineMonotonicMs: started + 650,
                deviceId: "test-device", osSessionId: "test-session", desktopId: "test-desktop")
            var completions = 0, faults = 0
            manager.completed = { _ in completions += 1 }; manager.inputDisabled = { _ in faults += 1 }
            manager.launch(ticket)
            let ready = root.appendingPathComponent("ready")
            while clock.monotonicMs < ticket.deadlineMonotonicMs - 80 && !FileManager.default.fileExists(atPath: ready.path) {
                Thread.sleep(forTimeInterval: 0.005)
            }
            XCTAssertTrue(FileManager.default.fileExists(atPath: ready.path), "synthetic child never reached the expected fence")
            try FileManager.default.moveItem(at: ready, to: marker)
            while clock.monotonicMs < ticket.deadlineMonotonicMs + (revision >= 4 ? 20 : 0) {
                Thread.sleep(forTimeInterval: 0.004)
            }
            var result = manager.abortTimedOutRead(ticket)
            while result == .awaitingExit && clock.monotonicMs < ticket.deadlineMonotonicMs + 850 {
                Thread.sleep(forTimeInterval: 0.004); result = manager.timedOutReadCleanup()
            }
            XCTAssertEqual(result, revision == 1 || revision == 4 ? .reaped : .ineligible, "revision \(revision)")
            XCTAssertTrue(manager.readyForRead); XCTAssertEqual(completions, 0); XCTAssertEqual(faults, 0)
        }
    }
}

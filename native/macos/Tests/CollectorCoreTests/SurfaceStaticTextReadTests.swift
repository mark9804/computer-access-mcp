import XCTest
@testable import CollectorCore

final class SurfaceStaticTextReadTests: XCTestCase {
    func testInitialAuthorityFailureIsInterruptedBeforeGeometryOrBody() {
        var calls = 0
        let result = SurfaceStaticTextRead.read(
            budget: 64,
            stopAfterNonempty: true,
            sampleGeometry: { calls += 1 },
            canStartAttempt: { calls += 1; return true },
            shouldContinue: { false },
            precheck: { calls += 1; return true },
            readRange: { _, _ in calls += 1; return "never read" },
            charge: { _ in calls += 1; return true },
            postcheck: { calls += 1; return true }
        )
        XCTAssertEqual(result.failure, .interrupted)
        XCTAssertNil(result.text)
        XCTAssertEqual(result.attempts, 0)
        XCTAssertEqual(calls, 0)
    }

    func testGeometryPrecedesCompleteAttemptAndEveryReturnedBodyEndsAtPostcheck() {
        var events: [String] = []
        var requests: [Int] = []
        let result = SurfaceStaticTextRead.read(
            budget: 64,
            stopAfterNonempty: true,
            sampleGeometry: { events.append("geometry") },
            canStartAttempt: { true },
            shouldContinue: { true },
            precheck: { events.append("pre"); return true },
            readRange: { _, count in
                events.append("range")
                requests.append(count)
                return count <= 1 ? "x" : ""
            },
            charge: { events.append("charge:\($0)"); return true },
            postcheck: { events.append("length+post"); return true }
        )
        XCTAssertEqual(result.text, "x")
        XCTAssertEqual(requests, [64, 32, 16, 8, 4, 2, 1])
        XCTAssertEqual(events, ["geometry"] + requests.flatMap { ["pre", "range", "charge:\($0 == 1 ? 1 : 0)", "length+post"] })
        XCTAssertEqual(result.consumedUnits, 1)
    }

    func testSingleShotReadFetchesFullMessageWithoutEightCharCutoff() {
        let message = "This is a 25+ character chat message from QQ"
        var requests: [Int] = []
        let result = SurfaceStaticTextRead.read(
            budget: 256,
            stopAfterNonempty: false,
            sampleGeometry: {},
            canStartAttempt: { true },
            shouldContinue: { true },
            precheck: { true },
            readRange: { start, count in
                requests.append(count)
                return boundedUTF16Slice(message, start: start, length: min(count, message.utf16.count))
            },
            charge: { _ in true },
            postcheck: { true }
        )
        XCTAssertEqual(requests, [256])
        XCTAssertEqual(result.attempts, 1)
        XCTAssertEqual(result.text, message)
        XCTAssertEqual(result.consumedUnits, message.utf16.count)
        XCTAssertNil(result.failure)
    }

    func testLastPermittedAttemptKeepsVerifiedResultAndDoesNotStartAnother() {
        var remaining = 1, reads = 0, posts = 0
        let result = SurfaceStaticTextRead.read(
            budget: 64,
            stopAfterNonempty: false,
            sampleGeometry: {},
            canStartAttempt: { remaining > 0 },
            shouldContinue: { true },
            precheck: { true },
            readRange: { _, _ in remaining -= 1; reads += 1; return "" },
            charge: { _ in true },
            postcheck: { posts += 1; return true }
        )
        XCTAssertNil(result.failure)
        XCTAssertEqual(result.text, "")
        XCTAssertEqual(result.attempts, 1)
        XCTAssertEqual(reads, 1)
        XCTAssertEqual(posts, 1)
    }

    func testRejectedAndOversizedResultsAreChargedBeforePostAndNeverRetained() {
        for cause in ["pre", "post-sensitive", "post-identity", "post-length", "deadline", "charge", "oversized"] {
            var live = true, events: [String] = [], charged = 0
            let result = SurfaceStaticTextRead.read(
                budget: 64,
                stopAfterNonempty: true,
                sampleGeometry: {},
                canStartAttempt: { true },
                shouldContinue: { live },
                precheck: { cause != "pre" },
                readRange: { _, _ in
                    events.append("range")
                    if cause == "deadline" { live = false }
                    return cause == "oversized" ? String(repeating: "x", count: 65) : "body"
                },
                charge: { count in charged += count; events.append("charge"); return cause != "charge" },
                postcheck: { events.append("post"); return !cause.hasPrefix("post-") }
            )
            XCTAssertNotNil(result.failure, cause)
            XCTAssertNil(result.text, cause)
            if cause == "pre" {
                XCTAssertEqual(charged, 0)
                XCTAssertTrue(events.isEmpty)
            } else {
                XCTAssertEqual(events, ["range", "charge", "post"])
                XCTAssertEqual(charged, cause == "oversized" ? 65 : 4)
            }
        }
    }
}

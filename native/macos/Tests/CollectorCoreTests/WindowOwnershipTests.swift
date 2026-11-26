import XCTest
@testable import CollectorCore

final class WindowOwnershipTests: XCTestCase {
    func testDirectEvidenceAndFailuresCannotStartAnotherRoute() {
        var alternates = 0, inspections = 0
        func resolve(_ direct: WindowReference<Int>, allow: Bool = true) -> WindowOwnership.Route? {
            WindowOwnership.match(expectedWindow: 7, allowTopLevel: allow, direct: { direct },
                topLevel: { alternates += 1; return .value(7) }, same: { $0 == $1 },
                verifyTopLevelWindow: { _ in inspections += 1; return true }, shouldContinue: { true })
        }
        XCTAssertEqual(resolve(.value(7)), .direct)
        XCTAssertNil(resolve(.value(8)))
        XCTAssertNil(resolve(.rejected))
        XCTAssertNil(resolve(.absent, allow: false))
        XCTAssertEqual(alternates, 0)
        XCTAssertEqual(inspections, 0)
        XCTAssertEqual(resolve(.absent), .topLevel)
        XCTAssertEqual(alternates, 1)
        XCTAssertEqual(inspections, 1)
    }

    func testAlternateRequiresExactWindowFreshSecurityAndLiveDeadlineEveryTime() {
        var topWindow = 7, safe = true, now = 0, expiredDuringRead = false, inspections = 0
        func resolve() -> WindowOwnership.Route? {
            WindowOwnership.match(expectedWindow: 7, allowTopLevel: true, direct: { .absent },
                topLevel: { if expiredDuringRead { now = 10 }; return .value(topWindow) }, same: { $0 == $1 },
                verifyTopLevelWindow: { _ in inspections += 1; return safe }, shouldContinue: { now < 10 })
        }
        XCTAssertEqual(resolve(), .topLevel)
        topWindow = 8
        XCTAssertNil(resolve())
        XCTAssertEqual(inspections, 1)
        topWindow = 7; safe = false
        XCTAssertNil(resolve())
        XCTAssertEqual(inspections, 2)
        safe = true; expiredDuringRead = true
        XCTAssertNil(resolve())
        XCTAssertEqual(inspections, 2)
    }

    func testParentChainProvesOwnershipOnlyWhenDirectAndTopLevelAreAbsent() {
        // 8-hop Qt-style hierarchy: node 10 -> 11 -> ... -> 17 -> window 7.
        let parents: [Int: Int] = [10: 11, 11: 12, 12: 13, 13: 14, 14: 15, 15: 16, 16: 17, 17: 7]
        var chainRuns = 0
        var verifiedHops: [Int] = []
        var windowChecks = 0

        func resolve(
            direct: WindowReference<Int>,
            topLevel: WindowReference<Int>,
            allow: Bool = true,
            windowValid: Bool = true
        ) -> WindowOwnership.Route? {
            WindowOwnership.match(
                expectedWindow: 7,
                allowTopLevel: allow,
                direct: { direct },
                topLevel: { topLevel },
                same: { $0 == $1 },
                verifyTopLevelWindow: { _ in windowChecks += 1; return windowValid },
                shouldContinue: { true },
                parentChain: {
                    chainRuns += 1
                    return WindowOwnership.walkParentChain(
                        from: 10,
                        expectedWindow: 7,
                        parent: { parents[$0] },
                        same: { $0 == $1 },
                        verifyHop: { verifiedHops.append($0); return true },
                        shouldContinue: { true }
                    )
                }
            )
        }

        // Direct or top-level positive/rejected results must never invoke parentChain.
        XCTAssertEqual(resolve(direct: .value(7), topLevel: .absent), .direct)
        XCTAssertNil(resolve(direct: .value(8), topLevel: .absent))
        XCTAssertNil(resolve(direct: .rejected, topLevel: .absent))
        XCTAssertNil(resolve(direct: .absent, topLevel: .absent, allow: false))
        XCTAssertEqual(resolve(direct: .absent, topLevel: .value(7)), .topLevel)
        XCTAssertNil(resolve(direct: .absent, topLevel: .value(8)))
        XCTAssertNil(resolve(direct: .absent, topLevel: .rejected))
        XCTAssertEqual(chainRuns, 0)

        // Both direct and topLevel absent with allowTopLevel=true walks parentChain and verifies window.
        XCTAssertEqual(resolve(direct: .absent, topLevel: .absent), .parentChain)
        XCTAssertEqual(chainRuns, 1)
        XCTAssertEqual(verifiedHops, [11, 12, 13, 14, 15, 16, 17, 7])
        XCTAssertEqual(windowChecks, 2)

        // Unverified window still rejects even when parentChain reaches expectedWindow.
        XCTAssertNil(resolve(direct: .absent, topLevel: .absent, windowValid: false))
        XCTAssertEqual(chainRuns, 2)
    }

    func testParentChainRejectsCyclesCrossPIDHopsHopCapExceededAndDeadline() {
        func matchViaParentChain(
            from start: Int,
            expectedWindow: Int,
            parents: [Int: Int],
            verifyHop: @escaping (Int) -> Bool = { _ in true }
        ) -> WindowOwnership.Route? {
            func walk() -> WindowReference<Int> {
                WindowOwnership.walkParentChain(
                    from: start,
                    expectedWindow: expectedWindow,
                    parent: { parents[$0] },
                    same: { $0 == $1 },
                    verifyHop: verifyHop,
                    shouldContinue: { true }
                )
            }
            return WindowOwnership.match(
                expectedWindow: expectedWindow,
                allowTopLevel: true,
                direct: { .absent },
                topLevel: { .absent },
                same: { $0 == $1 },
                verifyTopLevelWindow: { _ in true },
                shouldContinue: { true },
                parentChain: walk
            )
        }

        // 1. Self-loop and multi-node cycles are rejected immediately.
        let selfLoop: [Int: Int] = [1: 1]
        var selfSteps = 0
        let selfRef = WindowOwnership.walkParentChain(
            from: 1,
            expectedWindow: 99,
            parent: { selfSteps += 1; return selfLoop[$0] },
            same: { $0 == $1 },
            verifyHop: { _ in true },
            shouldContinue: { true }
        )
        if case .rejected = selfRef {} else { XCTFail("Expected self-loop cycle to be rejected") }
        XCTAssertEqual(selfSteps, 1)

        let cycle: [Int: Int] = [1: 2, 2: 3, 3: 2]
        var cycleSteps = 0
        let cycleRef = WindowOwnership.walkParentChain(
            from: 1,
            expectedWindow: 99,
            parent: { cycleSteps += 1; return cycle[$0] },
            same: { $0 == $1 },
            verifyHop: { _ in true },
            shouldContinue: { true }
        )
        if case .rejected = cycleRef {} else { XCTFail("Expected multi-hop cycle to be rejected") }
        XCTAssertEqual(cycleSteps, 3)

        // 2. Cross-PID hop aborts immediately without traversing above the foreign ancestor.
        let chain: [Int: Int] = [1: 2, 2: 3, 3: 4, 4: 99]
        let pids: [Int: Int32] = [1: 500, 2: 500, 3: 999, 4: 500, 99: 500]
        var visited: [Int] = []
        let crossPidRoute = matchViaParentChain(
            from: 1,
            expectedWindow: 99,
            parents: chain,
            verifyHop: { hop in visited.append(hop); return pids[hop] == 500 }
        )
        XCTAssertNil(crossPidRoute)
        XCTAssertEqual(visited, [2, 3], "Walk must stop at the first cross-PID hop")

        // 3. Exact 16-hop chain succeeds; 17-hop chain exceeds maxParentChainHops and fails.
        var exact16: [Int: Int] = [:]
        for hop in 0..<16 { exact16[hop] = hop + 1 }
        let ok16 = matchViaParentChain(from: 0, expectedWindow: 16, parents: exact16)
        XCTAssertEqual(ok16, .parentChain)

        var chain17 = exact16
        chain17[16] = 17
        let tooDeep = matchViaParentChain(from: 0, expectedWindow: 17, parents: chain17)
        XCTAssertNil(tooDeep)

        // 4. Deadline cancellation mid-walk stops immediately.
        var ticks = 0
        let cancelled = WindowOwnership.walkParentChain(
            from: 0,
            expectedWindow: 16,
            parent: { exact16[$0] },
            same: { $0 == $1 },
            verifyHop: { _ in true },
            shouldContinue: { ticks += 1; return ticks <= 4 }
        )
        if case .rejected = cancelled {} else { XCTFail("Expected cancellation to return .rejected") }
    }
}

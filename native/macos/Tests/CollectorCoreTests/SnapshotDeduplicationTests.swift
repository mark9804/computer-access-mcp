import Foundation
import XCTest
import HistoryContract
@testable import CollectorCore

/// Synthetic worker replies run through the production Engine and wire validator.
/// No AX, existing History, permission request, or private desktop content is read.
final class SnapshotDeduplicationTests: XCTestCase {
    private func start(inputText: Bool = false) throws -> Harness {
        let h = Harness(fixture: false); h.env.inputAvailable = true
        let policy = CapturePolicy(inputActivity: true, axCompatibility: true, captureScope: "window", inputText: inputText, selectionCapture: true)
        h.engine.receive(.object(["protocolVersion": j(1), "type": .string("configure"), "requestId": .string("config"),
            "ownerId": .string("owner"), "instanceId": .string("instance"), "policyRevision": j(1),
            "policy": try JSONValue.parse(JSONEncoder().encode(policy))]))
        h.control("start", lease: 30000); h.clock.advance(51); h.engine.tick()
        return h
    }
    private func next(_ h: Harness) {
        h.clock.advance(1001); h.engine.tick()
        XCTAssertNotNil(h.engine.outstanding)
    }
    private func reply(_ h: Harness, baseline: SurfaceBaseline, text: String = "A\u{1F9EA}", selectionText: String = "A") throws -> ReadResult {
        var result = h.goodResult(try XCTUnwrap(h.engine.outstanding))
        result.text = TextRead(text: text, source: "ax.range", totalLength: text.utf16.count,
            selection: TextSelection(start: 0, length: min(1, text.utf16.count)), complete: true, missingReasons: [])
        result.sessionIdentity = .init(sessionId: "worker", windowId: "window", nodeId: "field", surfaceId: "surface", windowGeneration: 1, focusGeneration: 1)
        result.selection = .init(text: selectionText, source: "ax.range", rangeStart: 0, truncated: false, missingReasons: ["selection-only"])
        let now = h.clock.unixMs
        let geometry = SurfaceGeometry(windowSize: .init(width: 800, height: 600), observedAtMs: now)
        result.surface = baseline.snapshot(surfaceId: "surface", scope: "window", nodes: [
            .init(id: "field", role: "editable", text: text, observedAtMs: now,
                bounds: .init(x: 10, y: 20, width: 200, height: 30), boundsObservedAtMs: now, axRole: "AXTextArea", focused: true),
        ], complete: true, matchingKnown: true, truncated: false, missingReasons: [], geometry: geometry)
        return result
    }
    private func frames(_ h: Harness, _ kind: String) -> [JSONValue] {
        h.frames.filter { $0["payload"]?["kind"] == .string(kind) }
    }
    private func validate(_ h: Harness) throws {
        let validator = try ContractValidator()
        var previous: Double = 0
        for frame in h.frames {
            XCTAssertNoThrow(try validator.encodeFrame(frame))
            if frame["type"] == .string("observation") {
                let seq = try XCTUnwrap(frame["seq"]?.numberValue)
                XCTAssertGreaterThan(seq, previous); previous = seq
            }
        }
    }
    func testUnchangedPollsEmitNoSnapshotOrNewClockButKeepScheduleAndHeartbeat() throws {
        let h = try start(), baseline = SurfaceBaseline()
        h.engine.complete(try reply(h, baseline: baseline))
        let first = h.frames, firstEnd = frames(h, "surface.snapshot")[0]["payload"]?["captureEndMs"]
        next(h); h.engine.complete(try reply(h, baseline: baseline))
        XCTAssertEqual(h.frames, first)
        XCTAssertEqual(frames(h, "surface.snapshot")[0]["payload"]?["captureEndMs"], firstEnd)
        next(h); h.engine.complete(try reply(h, baseline: baseline))
        XCTAssertEqual(h.env.launched.count, 3); XCTAssertEqual(h.engine.state, "running")
        for kind in ["text.snapshot", "surface.snapshot", "selection.snapshot"] { XCTAssertEqual(frames(h, kind).count, 1) }
        h.control("heartbeat", lease: 30000)
        XCTAssertEqual(h.frames.last?["state"], .string("running"))
        try validate(h)
    }
    func testInitialBlankVariantsSkipTextChannelsButKeepEmptyFocusedLayout() throws {
        let h = try start(), baseline = SurfaceBaseline()
        for (index, blank) in ["", " \t\r\n", "\u{3000}\u{00a0}\n"].enumerated() {
            if index > 0 { next(h) }
            h.engine.complete(try reply(h, baseline: baseline, text: blank, selectionText: blank))
        }
        XCTAssertTrue(frames(h, "text.snapshot").isEmpty)
        XCTAssertTrue(frames(h, "selection.snapshot").isEmpty)
        XCTAssertEqual(frames(h, "surface.snapshot").count, 3)
        let anchor = try XCTUnwrap(frames(h, "surface.snapshot").first?["payload"]?["nodes"]?.arrayValue?.first)
        XCTAssertEqual(anchor["text"], .string("")); XCTAssertEqual(anchor["focused"], .bool(true))
        XCTAssertEqual(anchor["bounds"]?["x"], j(10))
        next(h)
        var moved = try reply(h, baseline: baseline, text: "\u{3000}\u{00a0}\n", selectionText: "")
        moved.surface?.nodes[0].bounds?.x = 11; moved.surface?.nodes[0].focused = false
        h.engine.complete(moved)
        XCTAssertEqual(frames(h, "surface.snapshot").count, 4)
        XCTAssertTrue(frames(h, "text.snapshot").isEmpty)
        XCTAssertTrue(frames(h, "selection.snapshot").isEmpty)
        try validate(h)
    }
    func testNonblankRawTextAndIndependentSingleClearSurviveBlankVariants() throws {
        let h = try start(), baseline = SurfaceBaseline(), raw = " \n汉字\u{1F9EA}\t "
        h.engine.complete(try reply(h, baseline: baseline, text: raw, selectionText: raw))
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: "", selectionText: raw))
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: " \n", selectionText: "\u{3000}"))
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: "\u{3000}", selectionText: ""))
        XCTAssertEqual(frames(h, "text.snapshot").map { $0["payload"]?["text"] }, [.string(raw), .string("")])
        XCTAssertEqual(frames(h, "selection.snapshot").map { $0["payload"]?["text"] }, [.string(raw), .string("\u{3000}")])
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: raw, selectionText: raw))
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: " \t", selectionText: "\n"))
        XCTAssertEqual(frames(h, "text.snapshot").last?["payload"]?["text"], .string(" \t"))
        XCTAssertEqual(frames(h, "selection.snapshot").last?["payload"]?["text"], .string("\n"))
        XCTAssertEqual(frames(h, "text.snapshot").count, 4)
        XCTAssertEqual(frames(h, "selection.snapshot").count, 4)
        try validate(h)
    }
    func testBlankWithoutContinuousChannelAndTargetEvidenceCannotBecomeClear() throws {
        let h = try start(), baseline = SurfaceBaseline()
        h.engine.complete(try reply(h, baseline: baseline))
        next(h)
        var absent = try reply(h, baseline: baseline); absent.text = nil; absent.selection = nil
        h.engine.complete(absent)
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: "", selectionText: ""))
        XCTAssertEqual(frames(h, "text.snapshot").count, 1)
        XCTAssertEqual(frames(h, "selection.snapshot").count, 1)
        next(h); h.engine.complete(try reply(h, baseline: baseline))
        next(h)
        var replacement = try reply(h, baseline: baseline, text: "", selectionText: "")
        replacement.sessionIdentity?.sessionId = "replacement-worker"
        h.engine.complete(replacement)
        XCTAssertEqual(frames(h, "text.snapshot").count, 2)
        XCTAssertEqual(frames(h, "selection.snapshot").count, 2)
        h.control("pause", lease: 30000); h.control("resume", lease: 30000)
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: "", selectionText: ""))
        XCTAssertEqual(frames(h, "text.snapshot").count, 2)
        XCTAssertEqual(frames(h, "selection.snapshot").count, 2)
        try validate(h)
    }
    func testPartialOrUnknownBlankRangesRemainEvidenceNotFieldOrSelectionClears() throws {
        let h = try start(), baseline = SurfaceBaseline()
        h.engine.complete(try reply(h, baseline: baseline))
        for total in [nil, 9] as [Int?] {
            next(h)
            var partial = try reply(h, baseline: baseline, text: "", selectionText: "")
            partial.text = TextRead(text: "", source: "ax.range", totalLength: total, complete: false,
                missingReasons: [total == nil ? "length-unknown" : "range-short-read"])
            partial.selection?.truncated = true; partial.selection?.missingReasons.append("range-short-read")
            h.engine.complete(partial)
        }
        XCTAssertEqual(frames(h, "text.snapshot").count, 3)
        XCTAssertEqual(frames(h, "selection.snapshot").count, 2) // Same uncertain selection deduplicates normally.
        XCTAssertEqual(frames(h, "text.snapshot").last?["payload"]?["coverage"]?["status"], .string("partial"))
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: "", selectionText: ""))
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: "\u{3000}", selectionText: " \n"))
        XCTAssertEqual(frames(h, "text.snapshot").count, 4)
        XCTAssertEqual(frames(h, "selection.snapshot").count, 3)
        XCTAssertEqual(frames(h, "text.snapshot").last?["payload"]?["scope"], .string("field"))
        XCTAssertEqual(frames(h, "selection.snapshot").last?["payload"]?["text"], .string(""))
        try validate(h)
    }
    func testTextAndSelectionChangesAreIndependentAndReturningTextIsNotGloballyDeduplicated() throws {
        let h = try start(), baseline = SurfaceBaseline()
        h.engine.complete(try reply(h, baseline: baseline))
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: "B\u{1F9EA}"))
        next(h); h.engine.complete(try reply(h, baseline: baseline))
        XCTAssertEqual(frames(h, "text.snapshot").count, 3); XCTAssertEqual(frames(h, "surface.snapshot").count, 3)
        XCTAssertEqual(frames(h, "selection.snapshot").count, 1)
        next(h)
        var changed = try reply(h, baseline: baseline)
        changed.text?.selection = .init(start: 1, length: 2)
        changed.selection = .init(text: "\u{1F9EA}", source: "ax.range", rangeStart: 1, truncated: false, missingReasons: ["selection-only"])
        h.engine.complete(changed)
        XCTAssertEqual(frames(h, "text.snapshot").count, 4); XCTAssertEqual(frames(h, "selection.snapshot").count, 2)
        XCTAssertEqual(frames(h, "surface.snapshot").count, 3)
        try validate(h)
    }
    func testIdenticalUTF16IsRequiredInsteadOfSwiftCanonicalStringEquality() throws {
        let h = try start(), baseline = SurfaceBaseline()
        h.engine.complete(try reply(h, baseline: baseline, text: "é"))
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: "e\u{301}"))
        XCTAssertEqual(frames(h, "text.snapshot").count, 2)
        XCTAssertEqual(frames(h, "surface.snapshot").count, 2)
        try validate(h)
    }
    func testCoverageGeometrySourceAndStructureChangesCannotDisappearAsDuplicates() throws {
        let h = try start(), baseline = SurfaceBaseline()
        h.engine.complete(try reply(h, baseline: baseline))
        next(h)
        var partial = try reply(h, baseline: baseline)
        partial.surface?.complete = false; partial.surface?.mode = "full"; partial.surface?.baseRevision = nil
        partial.surface?.truncated = true; partial.surface?.missingReasons = ["node-budget"]
        partial.text?.source = "ax.value"
        h.engine.complete(partial)
        XCTAssertEqual(frames(h, "text.snapshot").count, 2); XCTAssertEqual(frames(h, "surface.snapshot").count, 2)
        next(h); h.engine.complete(try reply(h, baseline: baseline))
        next(h)
        var moved = try reply(h, baseline: baseline)
        moved.surface?.nodes[0].bounds?.x = 11
        h.engine.complete(moved)
        next(h)
        var role = try reply(h, baseline: baseline)
        role.surface?.nodes[0].role = "text"; role.surface?.nodes[0].axRole = "AXStaticText"
        h.engine.complete(role)
        XCTAssertEqual(frames(h, "surface.snapshot").count, 5)
        XCTAssertEqual(frames(h, "selection.snapshot").count, 1)
        try validate(h)
    }
    func testChannelAbsenceAndRejectedReadForceFreshEvidenceWithoutWakingOtherChannels() throws {
        let h = try start(), baseline = SurfaceBaseline()
        h.engine.complete(try reply(h, baseline: baseline))
        next(h)
        var absent = try reply(h, baseline: baseline); absent.selection = nil; absent.surface = nil
        h.engine.complete(absent)
        next(h); h.engine.complete(try reply(h, baseline: baseline))
        XCTAssertEqual(frames(h, "text.snapshot").count, 1)
        XCTAssertEqual(frames(h, "surface.snapshot").count, 2); XCTAssertEqual(frames(h, "selection.snapshot").count, 2)
        XCTAssertEqual(frames(h, "surface.snapshot").last?["payload"]?["mode"], .string("full"))
        next(h)
        let ticket = try XCTUnwrap(h.engine.outstanding)
        h.engine.complete(ReadResult(token: ticket.token, reason: "read-error", captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs))
        next(h); h.engine.complete(try reply(h, baseline: baseline))
        XCTAssertEqual(frames(h, "text.snapshot").count, 2)
        XCTAssertEqual(frames(h, "surface.snapshot").count, 3); XCTAssertEqual(frames(h, "selection.snapshot").count, 3)
        try validate(h)
    }
    func testSkippedSurfaceRevisionCannotBecomeDanglingDiffBase() throws {
        let h = try start(), baseline = SurfaceBaseline()
        h.engine.complete(try reply(h, baseline: baseline)) // r1 emitted
        next(h); h.engine.complete(try reply(h, baseline: baseline)) // r2 skipped
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: "B\u{1F9EA}")) // r3 changed
        let rebased = try XCTUnwrap(frames(h, "surface.snapshot").last?["payload"])
        XCTAssertEqual(rebased["revision"], j(3)); XCTAssertEqual(rebased["mode"], .string("full"))
        XCTAssertNil(rebased["baseRevision"]); XCTAssertNil(rebased["changes"])
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: "C\u{1F9EA}")) // r4 base r3 exists
        let diff = try XCTUnwrap(frames(h, "surface.snapshot").last?["payload"])
        XCTAssertEqual(diff["mode"], .string("diff")); XCTAssertEqual(diff["baseRevision"], j(3))
        XCTAssertEqual(diff["changes"]?["updated"], .array([.string("field")]))
        XCTAssertEqual(diff["nodes"]?.arrayValue?.first?["observedAtMs"], j(h.clock.unixMs))
        try validate(h)
    }
    func testApplicationAndUserPauseBoundariesNeverReuseIdenticalPriorEvidence() throws {
        let h = try start(), baseline = SurfaceBaseline()
        h.engine.complete(try reply(h, baseline: baseline))
        h.engine.excludedApplicationEvent()
        next(h); h.engine.complete(try reply(h, baseline: baseline))
        h.control("pause", lease: 30000)
        h.engine.workerDirty(); h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "paused")
        h.control("resume", lease: 30000)
        next(h); h.engine.complete(try reply(h, baseline: baseline))
        for kind in ["text.snapshot", "surface.snapshot", "selection.snapshot"] { XCTAssertEqual(frames(h, kind).count, 3) }
        try validate(h)
    }
    func testCachedDuplicateStillChecksDesktopBeforeSuppressingAndResumeRebaselines() throws {
        let h = try start(), baseline = SurfaceBaseline()
        h.engine.complete(try reply(h, baseline: baseline))
        next(h)
        let duplicate = try reply(h, baseline: baseline)
        h.env.desktop = .locked // No poll/notification has reached the Engine yet.
        h.engine.complete(duplicate)
        XCTAssertEqual(h.engine.state, "paused")
        for kind in ["text.snapshot", "surface.snapshot", "selection.snapshot"] { XCTAssertEqual(frames(h, kind).count, 1) }
        h.env.desktop = .unlocked
        h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "paused")
        h.control("resume", lease: 30000)
        next(h); h.engine.complete(try reply(h, baseline: baseline))
        for kind in ["text.snapshot", "surface.snapshot", "selection.snapshot"] { XCTAssertEqual(frames(h, kind).count, 2) }
        try validate(h)
    }
    func testExpiredDuplicateCannotHideDeadlineAndNextAllowedSampleIsFresh() throws {
        let h = try start(), baseline = SurfaceBaseline()
        h.engine.complete(try reply(h, baseline: baseline))
        next(h)
        let duplicate = try reply(h, baseline: baseline), ticket = try XCTUnwrap(h.engine.outstanding)
        h.clock.advance(ticket.deadlineMonotonicMs - h.clock.monotonicMs)
        h.engine.complete(duplicate)
        XCTAssertEqual(frames(h, "text.snapshot").count, 1)
        XCTAssertEqual(frames(h, "gap").last?["payload"]?["diagnostic"]?["code"], .string("read-deadline"))
        next(h); h.engine.complete(try reply(h, baseline: baseline))
        for kind in ["text.snapshot", "surface.snapshot", "selection.snapshot"] { XCTAssertEqual(frames(h, kind).count, 2) }
        try validate(h)
    }
    func testUnverifiedReplacementIdentityNeverDeduplicatesByContentAlone() throws {
        let h = try start(), baseline = SurfaceBaseline()
        var first = try reply(h, baseline: baseline); first.sessionIdentity = nil; first.surface = nil; first.selection = nil
        h.engine.complete(first)
        next(h)
        var replacement = try reply(h, baseline: baseline); replacement.sessionIdentity = nil; replacement.surface = nil; replacement.selection = nil
        h.engine.complete(replacement)
        XCTAssertEqual(frames(h, "text.snapshot").count, 2)
        XCTAssertNotEqual(frames(h, "text.snapshot").first?["payload"]?["nodeId"], frames(h, "text.snapshot").last?["payload"]?["nodeId"])
        try validate(h)
    }
    func testDuplicateSnapshotsNeverSuppressDistinctInputEventsActivityOrGaps() throws {
        let h = try start(inputText: true), baseline = SurfaceBaseline()
        h.engine.complete(try reply(h, baseline: baseline))
        for blank in ["", " \n"] {
            next(h)
            var result = try reply(h, baseline: baseline, text: blank, selectionText: blank)
            let app = try XCTUnwrap(result.application), identity = try XCTUnwrap(result.sessionIdentity)
            let context = InputTextContext(target: .init(application: app, deviceId: "device", osSessionId: "session", desktopId: "desktop", windowId: identity.windowId, windowGeneration: identity.windowGeneration), surfaceId: identity.surfaceId, captureEpoch: h.engine.captureEpoch, foregroundGeneration: h.engine.foregroundGeneration, focusGeneration: h.engine.focusGeneration, policyRevision: h.engine.policyRevision, privateState: .normal)
            var input = InputTextAccumulator()
            input.add(InputTextSample(context: context, eventKind: .text, text: "same input", modifiers: [], callbackTimeMs: h.clock.unixMs), source: .cgUnicode)
            result.inputRecords = [try XCTUnwrap(input.takeSegment(approvedContext: context))]
            result.inputGaps = ["stale"]
            h.engine.complete(result)
            h.engine.inputActivity(.init(application: app, category: .pointerRelease, callbackTimeMs: h.clock.unixMs))
        }
        next(h); h.engine.complete(try reply(h, baseline: baseline, text: " \n", selectionText: " \n"))
        XCTAssertEqual(frames(h, "input.text").count, 2); XCTAssertEqual(frames(h, "input.activity").count, 2)
        XCTAssertEqual(frames(h, "gap").count, 2)
        XCTAssertEqual(frames(h, "text.snapshot").count, 2); XCTAssertEqual(frames(h, "selection.snapshot").count, 2)
        XCTAssertEqual(frames(h, "surface.snapshot").count, 3)
        try validate(h)
    }
    func testMalformedIgnoredFieldsAreStillRejectedInsteadOfDeduplicatedOrRepaired() throws {
        let h = try start(), baseline = SurfaceBaseline(), validator = try ContractValidator()
        h.engine.complete(try reply(h, baseline: baseline))
        next(h)
        var badClock = try reply(h, baseline: baseline)
        badClock.surface?.nodes[0].boundsObservedAtMs = h.clock.unixMs - 1
        badClock.surface?.geometry?.observedAtMs = h.clock.unixMs - 1
        h.engine.complete(badClock)
        let invalidClock = try XCTUnwrap(frames(h, "surface.snapshot").last)
        XCTAssertThrowsError(try validator.encodeFrame(invalidClock))
        next(h); h.engine.complete(try reply(h, baseline: baseline))
        XCTAssertEqual(frames(h, "surface.snapshot").count, 3)
        next(h)
        var badDiff = try reply(h, baseline: baseline)
        badDiff.surface?.mode = "diff"; badDiff.surface?.baseRevision = nil
        h.engine.complete(badDiff)
        let invalidDiff = try XCTUnwrap(frames(h, "surface.snapshot").last)
        XCTAssertEqual(invalidDiff["payload"]?["mode"], .string("diff"))
        XCTAssertThrowsError(try validator.encodeFrame(invalidDiff))
        let blank = try start(), blankBaseline = SurfaceBaseline()
        var badBlank = try reply(blank, baseline: blankBaseline, text: "", selectionText: "")
        badBlank.captureStartMs = -1; badBlank.captureEndMs = -1; badBlank.surface = nil
        blank.engine.complete(badBlank)
        for kind in ["text.snapshot", "selection.snapshot"] {
            let frame = try XCTUnwrap(frames(blank, kind).first)
            XCTAssertThrowsError(try validator.encodeFrame(frame)) // Invalid initial blanks are never hidden.
        }
    }
}

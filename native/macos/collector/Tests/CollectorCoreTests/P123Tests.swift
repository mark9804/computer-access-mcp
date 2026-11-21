import XCTest
import AccessContract
@testable import CollectorCore

private final class EnablementFake: AXEnablementProvider {
    var supported: Set<AXEnablementResult.Attribute> = [.manual]
    var value: Bool? = false
    var writable: Bool? = true
    var writeSuccess = true
    var readBack = true
    var calls: [String] = []
    func supports(_ attribute: AXEnablementResult.Attribute) -> Bool { calls.append("supports-\(attribute.rawValue)"); return supported.contains(attribute) }
    func current(_ attribute: AXEnablementResult.Attribute) -> Bool? { calls.append("current-\(attribute.rawValue)"); return value }
    func settable(_ attribute: AXEnablementResult.Attribute) -> Bool? { calls.append("settable-\(attribute.rawValue)"); return writable }
    func enable(_ attribute: AXEnablementResult.Attribute) -> Bool { calls.append("write-\(attribute.rawValue)"); if writeSuccess && readBack { value = true }; return writeSuccess }
}
private final class MarkerFake: TextFieldProvider {
    let base = FakeProvider()
    var markerCalls = 0
    var markerText: String? = "marker"
    var rangeEffect: (() -> Void)?
    var stable = true
    func application() -> ApplicationIdentity? { base.application() }
    func resolveFocusedField() -> Bool { base.resolveFocusedField() }
    func role() -> String? { base.role() }
    func secureStatus() -> SecureStatus { base.secureStatus() }
    func numberOfCharacters() -> Int? { 6 }
    func stringForRange(start: Int, length: Int) -> String? { rangeEffect?(); return nil }
    func markerStringForRange(start: Int, length: Int) -> String? { markerCalls += 1; return markerText }
    func boundedKnownLengthValue() -> String? { nil }
    func selectedRange() -> TextSelection? { nil }
    func remainsSameFocusAndWindow() -> Bool { stable }
}
final class P123Tests: XCTestCase {
    private func configure(_ h: Harness, policy: CapturePolicy) {
        h.engine.receive(.object(["protocolVersion": j(1), "type": .string("configure"), "requestId": .string("config"), "ownerId": .string("owner"), "instanceId": .string("instance"), "policyRevision": j(1), "policy": try! JSONValue.parse(JSONEncoder().encode(policy))]))
        h.control("start", lease: 30000); h.clock.advance(51); h.engine.tick()
    }
    private func identity(_ session: String = "session-worker", _ serial: Int64 = 1) -> WorkerSurfaceIdentity {
        .init(sessionId: session, windowId: "window-\(serial)", nodeId: "node-\(serial)", surfaceId: "surface-\(serial)", windowGeneration: serial, focusGeneration: serial)
    }
    func testLegacyPolicyDecodingDefaultsDoNotEnableSession() throws {
        let policy = try CapturePolicy(JSONValue.parse(Data("{\"enabled\":true,\"allowedApplicationIds\":[\"test.allowed\"],\"maxTextCodeUnits\":128,\"maxPending\":8,\"debounceMs\":10,\"maxWaitMs\":50,\"readTimeoutMs\":200}".utf8)))
        XCTAssertTrue(policy.hasValidTextSettings); XCTAssertFalse(policy.usesSessionWorker)
        XCTAssertNil(policy.applicationScope); XCTAssertNil(policy.inputText)
    }
    func testMandatoryFamiliesCaseAndDotBoundaryCannotBeOverridden() {
        let policy = CapturePolicy(allowedApplicationIds: [], applicationScope: "denylist", allowBrowserContent: true)
        for id in ["COM.1PASSWORD", "com.1password.1password.autofill-extension", "com.1password.safari.extension", "com.agilebits.onepassword7", "com.agilebits.onepassword.extension", "com.apple.SAFARI.extension"] {
            XCTAssertFalse(ApplicationPolicy.allows(id, policy: policy))
        }
        XCTAssertTrue(ApplicationPolicy.allows("com.apple.safarish", policy: policy))
    }
    func testCustomExcludesHaveCaseInsensitiveFamilyBoundary() {
        let policy = CapturePolicy(allowedApplicationIds: [], applicationScope: "denylist", excludedApplicationIds: ["Com.Excluded"])
        XCTAssertFalse(ApplicationPolicy.allows("com.excluded.child", policy: policy)); XCTAssertTrue(ApplicationPolicy.allows("com.excludedExtra", policy: policy))
    }
    func testBrowserExceptionRequiresBothExplicitFieldsAndStillDeniesSafari() {
        var policy = CapturePolicy(allowedApplicationIds: ["com.google.Chrome"], allowBrowserContent: true)
        XCTAssertFalse(BrowserGate.allows("com.google.Chrome", policy: policy))
        policy.applicationScope = "denylist"; XCTAssertTrue(BrowserGate.allows("com.google.Chrome", policy: policy))
        XCTAssertFalse(BrowserGate.allows("com.apple.Safari", policy: policy))
        policy.allowBrowserContent = nil; XCTAssertFalse(BrowserGate.allows("com.google.Chrome", policy: policy))
    }
    func testUnknownNativeSettingsFailClosed() {
        for policy in [CapturePolicy(applicationScope: "all"), CapturePolicy(captureScope: "desktop"), CapturePolicy(maxTreeNodes: 97), CapturePolicy(maxTreeNodes: 0)] { XCTAssertFalse(policy.hasValidTextSettings) }
    }
    func testEnablementDisabledAndDeniedNeverTouchProvider() {
        let fake = EnablementFake(), lease = AXEnablementLease()
        XCTAssertEqual(lease.acquire(applicationId: "test.allowed", policy: CapturePolicy(), provider: fake).status, .disabled)
        XCTAssertTrue(fake.calls.isEmpty)
        lease.release()
        XCTAssertEqual(lease.acquire(applicationId: "com.1password.1password", policy: CapturePolicy(applicationScope: "denylist", axCompatibility: true), provider: fake).status, .denied)
        XCTAssertTrue(fake.calls.isEmpty)
    }
    func testEnablementUnknownOriginalRefusesWithoutTryingEnhanced() {
        let fake = EnablementFake(); fake.value = nil; fake.supported = [.manual, .enhanced]
        XCTAssertEqual(AXEnablementLease().acquire(applicationId: "test.allowed", policy: CapturePolicy(axCompatibility: true), provider: fake).status, .originalUnknown)
        XCTAssertEqual(fake.calls, ["supports-manual", "current-manual"])
    }
    func testEnablementFalseToTrueVerifiedAndReleaseNeverForcesFalse() {
        let fake = EnablementFake(), lease = AXEnablementLease()
        let result = lease.acquire(applicationId: "test.allowed", policy: CapturePolicy(axCompatibility: true), provider: fake)
        XCTAssertEqual(result.status, .enabled); XCTAssertTrue(result.changed)
        let calls = fake.calls; lease.release(); XCTAssertEqual(fake.calls, calls); XCTAssertEqual(fake.value, true)
    }
    func testEnablementOldTrueAndUnknownSettableNeverWrite() {
        let trueFake = EnablementFake(); trueFake.value = true
        XCTAssertEqual(AXEnablementLease().acquire(applicationId: "test.allowed", policy: CapturePolicy(axCompatibility: true), provider: trueFake).status, .alreadyEnabled)
        XCTAssertFalse(trueFake.calls.contains("settable-manual"))
        let unknown = EnablementFake(); unknown.writable = nil
        XCTAssertEqual(AXEnablementLease().acquire(applicationId: "test.allowed", policy: CapturePolicy(axCompatibility: true), provider: unknown).status, .notSettable)
        XCTAssertFalse(unknown.calls.contains("write-manual"))
    }
    func testEnhancedOnlyFallbackWhenManualCapabilityAbsent() {
        let fake = EnablementFake(); fake.supported = [.enhanced]
        let result = AXEnablementLease().acquire(applicationId: "test.allowed", policy: CapturePolicy(axCompatibility: true), provider: fake)
        XCTAssertEqual(result.attribute, .enhanced); XCTAssertEqual(result.status, .enabled)
        XCTAssertFalse(fake.calls.contains("write-manual"))
    }
    func testEnablementWriteUnknownReadbackNotSuccessAndNotRetried() {
        let fake = EnablementFake(); fake.readBack = false
        let lease = AXEnablementLease(), policy = CapturePolicy(axCompatibility: true)
        XCTAssertEqual(lease.acquire(applicationId: "test.allowed", policy: policy, provider: fake).status, .writeFailed)
        _ = lease.acquire(applicationId: "test.allowed", policy: policy, provider: fake)
        XCTAssertEqual(fake.calls.filter { $0 == "write-manual" }.count, 1)
    }
    func testMarkerExplicitOptInAndSafeMetadataBeforeRead() {
        let clock = FakeClock(), fake = MarkerFake()
        XCTAssertNil(BoundedTextReader().read(ticket: ticket(clock), provider: fake, clock: clock).text); XCTAssertEqual(fake.markerCalls, 0)
        let result = BoundedTextReader().read(ticket: ticket(clock, policy: CapturePolicy(textMarkers: true)), provider: fake, clock: clock)
        XCTAssertEqual(result.text?.source, "ax.marker"); XCTAssertEqual(result.text?.text, "marker")
        fake.base.secure = .unknown
        _ = BoundedTextReader().read(ticket: ticket(clock, policy: CapturePolicy(textMarkers: true)), provider: fake, clock: clock)
        XCTAssertEqual(fake.markerCalls, 1)
    }
    func testRangeFailureCannotReadMarkerAcrossNewSecurityOrFocusBoundary() {
        for sensitive in [true, false] {
            let clock = FakeClock(), fake = MarkerFake()
            fake.rangeEffect = { if sensitive { fake.base.secure = .sensitive } else { fake.stable = false } }
            let result = BoundedTextReader().read(ticket: ticket(clock, policy: CapturePolicy(textMarkers: true)), provider: fake, clock: clock)
            XCTAssertNil(result.text); XCTAssertEqual(fake.markerCalls, 0)
        }
    }
    func testMarkerOversizeRejectedWithoutPersistingOpaqueAnything() {
        let clock = FakeClock(), fake = MarkerFake(); fake.markerText = "oversized"
        let result = BoundedTextReader().read(ticket: ticket(clock, policy: CapturePolicy(textMarkers: true)), provider: fake, clock: clock)
        XCTAssertNil(result.text); XCTAssertEqual(result.diagnostic?.code, .textResultInvalid)
    }
    func testEmptySubroleRequiresAllIndependentMetadataEvidence() {
        XCTAssertEqual(TextSecurityGate.classifyEmptySubrole(role: "AXTextArea", editable: true, boundedRangeAdvertised: true, characterCountKnown: true), .safe)
        for role in ["AXGroup", "AXMenuItem", "AXStaticText", "AXSecureTextField", nil] { XCTAssertEqual(TextSecurityGate.classifyEmptySubrole(role: role, editable: true, boundedRangeAdvertised: true, characterCountKnown: true), .unknown) }
        XCTAssertEqual(TextSecurityGate.classifyEmptySubrole(role: "AXTextField", editable: nil, boundedRangeAdvertised: true, characterCountKnown: true), .unknown)
        XCTAssertEqual(TextSecurityGate.classifyEmptySubrole(role: "AXTextField", editable: true, boundedRangeAdvertised: false, characterCountKnown: true), .unknown)
        XCTAssertEqual(TextSecurityGate.classifyEmptySubrole(role: "AXTextField", editable: true, boundedRangeAdvertised: true, characterCountKnown: false), .unknown)
    }
    func testCompleteDiffAlwaysContainsCurrentNodesNotPatchOrOldTimestamp() {
        let baseline = SurfaceBaseline()
        _ = baseline.snapshot(surfaceId: "s", scope: "region", nodes: [.init(id: "a", role: "text", text: "old", observedAtMs: 1)], complete: true, matchingKnown: true, truncated: false, missingReasons: [])
        let current = baseline.snapshot(surfaceId: "s", scope: "region", nodes: [.init(id: "a", role: "text", text: "new", observedAtMs: 2)], complete: true, matchingKnown: true, truncated: false, missingReasons: [])
        XCTAssertEqual(current.mode, "diff"); XCTAssertEqual(current.updated, ["a"]); XCTAssertEqual(current.nodes.first?.text, "new"); XCTAssertEqual(current.nodes.first?.observedAtMs, 2)
    }
    func testPartialOrUncertainMatchingResetsAndNeverInfersRemoval() {
        for matching in [true, false] {
            let baseline = SurfaceBaseline()
            _ = baseline.snapshot(surfaceId: "s", scope: "window", nodes: [.init(id: "old", role: "text", text: "expired", observedAtMs: 1)], complete: true, matchingKnown: true, truncated: false, missingReasons: [])
            let partial = baseline.snapshot(surfaceId: "s", scope: "window", nodes: [], complete: false, matchingKnown: matching, truncated: true, missingReasons: ["tree-budget"])
            XCTAssertEqual(partial.mode, "full"); XCTAssertTrue(partial.removed.isEmpty); XCTAssertTrue(partial.nodes.isEmpty)
            let next = baseline.snapshot(surfaceId: "s", scope: "window", nodes: [], complete: true, matchingKnown: true, truncated: false, missingReasons: [])
            XCTAssertEqual(next.mode, "full")
        }
    }
    func testNewSurfaceAlwaysRebaselines() {
        let baseline = SurfaceBaseline()
        _ = baseline.snapshot(surfaceId: "old", scope: "region", nodes: [], complete: true, matchingKnown: true, truncated: false, missingReasons: [])
        let current = baseline.snapshot(surfaceId: "new", scope: "region", nodes: [], complete: true, matchingKnown: true, truncated: false, missingReasons: [])
        XCTAssertEqual(current.revision, 1); XCTAssertEqual(current.mode, "full"); XCTAssertNil(current.baseRevision)
    }
    func testReadBudgetBoundsCallsDeadlinesAndAggregateUTF16() {
        var budget = ReadBudget(deadlineMs: 500, finalValidationReserveMs: 100, maxCalls: 4, validationReserveCalls: 2, maxTextUnits: 3)
        XCTAssertTrue(budget.consumeCalls(1, nowMs: 100))
        XCTAssertTrue(budget.consumeCalls(1, nowMs: 100))
        XCTAssertFalse(budget.consumeCalls(1, nowMs: 100))
        budget.beginFinalValidation()
        XCTAssertTrue(budget.consumeCalls(1, nowMs: 450))
        XCTAssertFalse(budget.consumeCalls(1, nowMs: 500))
        XCTAssertTrue(budget.consumeText(2))
        XCTAssertFalse(budget.consumeText(2))
        XCTAssertTrue(budget.textViolated)
        XCTAssertEqual(budget.remainingTextUnits, 0)
    }
    func testEngineSessionStableIdentityAndNewWorkerRebaseline() {
        let h = Harness(); configure(h, policy: CapturePolicy(axCompatibility: true))
        var first = h.goodResult(h.env.launched.last!); first.sessionIdentity = identity(); h.engine.complete(first)
        let stamp = h.engine.stamp, target = h.textFrames.last?["target"]
        h.clock.advance(151); h.engine.tick()
        var second = h.goodResult(h.env.launched.last!); second.sessionIdentity = identity(); h.engine.complete(second)
        XCTAssertEqual(h.engine.stamp, stamp); XCTAssertEqual(h.textFrames.last?["target"], target)
        h.clock.advance(151); h.engine.tick()
        var third = h.goodResult(h.env.launched.last!); third.sessionIdentity = identity("new-worker"); h.engine.complete(third)
        XCTAssertNotEqual(h.engine.stamp, stamp)
    }
    func testExcludedApplicationEventAndReadEmitNothingAttributed() {
        let h = Harness(); configure(h, policy: CapturePolicy(allowedApplicationIds: [], applicationScope: "denylist", allowBrowserContent: true))
        let before = h.frames.count
        h.engine.applicationEvent(SourceHint(application: .init(applicationId: "com.1password.1password", processId: 42, processStartTime: "birth"), eventTimeMs: h.clock.unixMs))
        XCTAssertEqual(h.frames.count, before)
        h.clock.advance(51); h.engine.tick(); let current = h.env.launched.last!
        h.engine.complete(ReadResult(token: current.token, reason: "application-excluded", captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs))
        XCTAssertEqual(h.frames.count, before)
    }
    func testUnattributedActivationClearsOldInputContextWithoutPausingDesktop() throws {
        let h = Harness(); h.env.inputAvailable = true
        configure(h, policy: CapturePolicy(inputActivity: true, captureScope: "window", inputText: true))
        let old = try XCTUnwrap(h.engine.outstanding), epoch = h.engine.captureEpoch
        let inputBegins = h.env.inputBegins, inputEnds = h.env.inputEnds, cancels = h.env.cancelCalls
        h.engine.excludedApplicationEvent()
        XCTAssertEqual(h.engine.state, "running"); XCTAssertEqual(h.engine.desktop, .unlocked)
        XCTAssertGreaterThan(h.engine.captureEpoch, epoch); XCTAssertGreaterThan(h.env.cancelCalls, cancels)
        XCTAssertEqual(h.env.inputBegins, inputBegins); XCTAssertEqual(h.env.inputEnds, inputEnds)
        XCTAssertNil(h.engine.outstanding)
        h.engine.complete(h.goodResult(old)); XCTAssertTrue(h.textFrames.isEmpty)
        h.clock.advance(51); h.engine.tick()
        let current = try XCTUnwrap(h.engine.outstanding)
        XCTAssertNil(current.hint); XCTAssertEqual(current.captureEpoch, h.engine.captureEpoch)
        h.engine.complete(h.goodResult(current)); XCTAssertEqual(h.textFrames.count, 1)
    }
    func testIndependentSurfaceSelectionInputAndStatusValidateWire() throws {
        let h = Harness(fixture: false); configure(h, policy: CapturePolicy(captureScope: "region", inputText: true, selectionCapture: true))
        let current = h.env.launched.last!, app = ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "birth")
        var result = ReadResult(token: current.token, application: app, captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs)
        result.sessionIdentity = identity()
        result.enablement = .init(status: .enabled, attribute: .manual, changed: true); result.observerStatus = "best-effort"
        result.surface = SurfaceBaseline().snapshot(surfaceId: "surface-1", scope: "region", nodes: [.init(id: "node-1", role: "text", text: "tree", observedAtMs: h.clock.unixMs)], complete: true, matchingKnown: true, truncated: false, missingReasons: [])
        result.selection = .init(text: "selection", source: "ax.range", rangeStart: 0, truncated: false, missingReasons: ["selection-only"])
        let context = InputTextContext(target: .init(application: app, deviceId: "device", osSessionId: "session", desktopId: "desktop", windowId: "window-1", windowGeneration: 1), surfaceId: "surface-1", captureEpoch: h.engine.captureEpoch, foregroundGeneration: h.engine.foregroundGeneration + 1, focusGeneration: h.engine.focusGeneration + 1, policyRevision: 1, privateState: .normal)
        var input = InputTextAccumulator()
        input.add(InputTextSample(context: context, eventKind: .text, text: "input", modifiers: [], callbackTimeMs: h.clock.unixMs), source: .cgUnicode)
        result.inputRecords = [try XCTUnwrap(input.takeSegment(approvedContext: context))]
        h.engine.complete(result); h.control("heartbeat", lease: 30000)
        for kind in ["surface.snapshot", "selection.snapshot", "input.text"] { XCTAssertTrue(h.frames.contains { $0["payload"]?["kind"] == .string(kind) }) }
        let inputIndex = try XCTUnwrap(h.frames.firstIndex { $0["payload"]?["kind"] == .string("input.text") })
        let surfaceIndex = try XCTUnwrap(h.frames.firstIndex { $0["payload"]?["kind"] == .string("surface.snapshot") })
        XCTAssertLessThan(inputIndex, surfaceIndex)
        XCTAssertEqual(h.frames.last?["captureDiagnostics"]?["axEnablement"], .string("enabled"))
        let validator = try ContractValidator(); for frame in h.frames { _ = try validator.encodeFrame(frame) }
    }
    func testHealthyRetirementRequiresExactAckThenExactCleanReap() {
        var retirement = WorkerRetirement(pid: 42, sessionToken: "session", retireToken: "retire", nowMs: 0)
        XCTAssertEqual(retirement.failureReason, .ackFailed)
        XCTAssertFalse(retirement.mayReplace(reapedPID: 42, waitStatus: 0, nowMs: 1))
        XCTAssertTrue(retirement.acknowledge(pid: 42, sessionToken: "session", retireToken: "retire", healthy: true, nowMs: 1))
        XCTAssertEqual(retirement.failureReason, .exitUnconfirmed)
        XCTAssertEqual(retirement.reapDeadlineMs, 750, "An early ACK need not extend the original budget")
        XCTAssertFalse(retirement.mayReplace(reapedPID: 43, waitStatus: 0, nowMs: 2))
        XCTAssertFalse(retirement.mayReplace(reapedPID: 42, waitStatus: 9, nowMs: 2), "SIGKILL is not clean exit")
        XCTAssertFalse(retirement.mayReplace(reapedPID: 42, waitStatus: 1 << 8, nowMs: 2), "Nonzero exit is not clean")
        XCTAssertTrue(retirement.mayReplace(reapedPID: 42, waitStatus: 0, nowMs: 2))
        XCTAssertFalse(retirement.mayReplace(reapedPID: 42, waitStatus: 0, nowMs: 750))
    }
    func testTimelyLastMomentAckOnlyExtendsExactExitObservationOnce() {
        var retirement = WorkerRetirement(pid: 42, sessionToken: "s", retireToken: "r", nowMs: 0)
        XCTAssertEqual(retirement.deadlineMs, 750)
        XCTAssertTrue(retirement.acknowledge(pid: 42, sessionToken: "s", retireToken: "r", healthy: true, nowMs: 743))
        XCTAssertEqual(retirement.reapDeadlineMs, 843)
        XCTAssertFalse(retirement.mayReplace(reapedPID: 0, waitStatus: 0, nowMs: 743), "No owned child was reaped yet")
        XCTAssertTrue(retirement.mayReplace(reapedPID: 42, waitStatus: 0, nowMs: 794))
        XCTAssertTrue(retirement.mayReplace(reapedPID: 42, waitStatus: 0, nowMs: 842))
        XCTAssertFalse(retirement.mayReplace(reapedPID: 42, waitStatus: 0, nowMs: 843))
        XCTAssertFalse(retirement.mayReplace(reapedPID: 42, waitStatus: 0, nowMs: 844))
        var duplicate = retirement
        XCTAssertFalse(duplicate.acknowledge(pid: 42, sessionToken: "s", retireToken: "r", healthy: true, nowMs: 794))
        XCTAssertEqual(duplicate.reapDeadlineMs, 843, "Duplicate ACK cannot renew the terminal window")
        XCTAssertFalse(duplicate.mayReplace(reapedPID: 42, waitStatus: 0, nowMs: 795))
        retirement.fault()
        XCTAssertFalse(retirement.mayReplace(reapedPID: 42, waitStatus: 0, nowMs: 794), "An already-failed retirement cannot reopen")
    }
    func testRetirementWaitsOnlyForBoundedOriginalReadThenAckAndReap() {
        let idle = WorkerRetirement(pid: 42, sessionToken: "s", retireToken: "r", nowMs: 100)
        XCTAssertEqual(idle.deadlineMs, 850)
        let expired = WorkerRetirement(pid: 42, sessionToken: "s", retireToken: "r", nowMs: 100, readDeadlineMs: 50)
        XCTAssertEqual(expired.deadlineMs, 850)
        var reading = WorkerRetirement(pid: 42, sessionToken: "s", retireToken: "r", nowMs: 100, readDeadlineMs: 1600)
        XCTAssertEqual(reading.deadlineMs, 2350)
        XCTAssertFalse(reading.mayReplace(reapedPID: 42, waitStatus: 0, nowMs: 1200))
        XCTAssertTrue(reading.acknowledge(pid: 42, sessionToken: "s", retireToken: "r", healthy: true, nowMs: 1700))
        XCTAssertTrue(reading.mayReplace(reapedPID: 42, waitStatus: 0, nowMs: 2349))
        XCTAssertFalse(reading.mayReplace(reapedPID: 42, waitStatus: 0, nowMs: 2350))
        XCTAssertEqual(WorkerRetirement(pid: 42, sessionToken: "s", retireToken: "r", nowMs: 100, readDeadlineMs: 999999).deadlineMs, 5850)
    }
    func testRetirementFaultAndWrongStaleUnhealthyAcksCannotRecover() {
        for which in 0..<6 {
            var retirement = WorkerRetirement(pid: 42, sessionToken: "session", retireToken: "retire", nowMs: 0)
            if which == 0 { retirement.fault() }
            let now: Int64 = which == 4 ? 750 : 1
            XCTAssertFalse(retirement.acknowledge(pid: which == 1 ? 43 : 42, sessionToken: which == 2 ? "wrong" : "session",
                retireToken: which == 5 ? "wrong" : "retire", healthy: which != 3, nowMs: now))
            XCTAssertFalse(retirement.acknowledge(pid: 42, sessionToken: "session", retireToken: "retire", healthy: true, nowMs: now + 1))
            XCTAssertNil(retirement.reapDeadlineMs)
            XCTAssertFalse(retirement.mayReplace(reapedPID: 42, waitStatus: 0, nowMs: now + 2))
        }
    }
    func testInputSessionFailureLatchesWithoutOutstandingReadAndAcrossAppEvents() {
        let h = Harness(); configure(h, policy: CapturePolicy(inputText: true))
        var result = h.goodResult(h.env.launched.last!); result.sessionIdentity = identity(); h.engine.complete(result)
        XCTAssertNil(h.engine.outstanding)
        h.engine.inputSessionUnavailable("input-monitoring-disabled")
        let launched = h.env.launched.count
        h.engine.applicationEvent(.init(application: .init(applicationId: "test.allowed", processId: 55, processStartTime: "other"), eventTimeMs: h.clock.unixMs))
        h.engine.desktopChanged(.unlocked, accessibility: true); h.engine.workerDirty(); h.clock.advance(1000); h.engine.tick()
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.env.launched.count, launched)
        h.control("start", lease: 30000); XCTAssertEqual(h.engine.state, "paused")
        h.control("resume", lease: 30000); XCTAssertEqual(h.engine.state, "running")
    }
    func testRetirementFaultsRemainStickyAndCannotRestartOnApplicationOrDesktopEvents() {
        for reason in [WorkerRetirement.Failure.ackFailed.rawValue, WorkerRetirement.Failure.exitUnconfirmed.rawValue] {
            let h = Harness(); configure(h, policy: CapturePolicy(inputText: true))
            let ticket = h.env.launched.last!, launches = h.env.launched.count
            h.engine.secureInputDetected()
            h.engine.inputSessionUnavailable(reason)
            XCTAssertEqual(h.frames.last?["requestId"], .string("input"))
            XCTAssertEqual(h.frames.last?["reason"], .string(reason))
            h.engine.complete(h.goodResult(ticket))
            h.env.workerReady = true; h.env.secureInputBlocked = false
            h.engine.applicationEvent(.init(application: .init(applicationId: "test.allowed", processId: 55,
                processStartTime: "other"), eventTimeMs: h.clock.unixMs))
            h.engine.desktopChanged(.unlocked, accessibility: true); h.engine.workerDirty()
            h.clock.advance(1000); h.engine.tick(); h.control("heartbeat"); h.control("start")
            XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.frames.last?["reason"], .string(reason))
            XCTAssertEqual(h.env.launched.count, launches); XCTAssertTrue(h.textFrames.isEmpty)
            h.control("resume", lease: 30000); XCTAssertEqual(h.engine.state, "running")
        }
    }
    func testFirstPauseCauseSurvivesSecondaryDesktopBoundaryHeartbeatAndRejectedStart() {
        let h = Harness(); configure(h, policy: CapturePolicy(inputText: true))
        let oldTicket = h.env.launched.last!
        h.engine.inputSessionUnavailable("input-monitoring-disabled")
        XCTAssertEqual(h.frames.last?["reason"], .string("input-monitoring-disabled"))
        let epoch = h.engine.captureEpoch
        h.env.desktopReason = "secure-input-indicated"
        h.engine.desktopChanged(.unknown, accessibility: false)
        XCTAssertGreaterThan(h.engine.captureEpoch, epoch, "Secondary boundaries still fence old stamps")
        XCTAssertEqual(h.frames.last?["reason"], .string("input-monitoring-disabled"))
        h.control("heartbeat"); XCTAssertEqual(h.frames.last?["reason"], .string("input-monitoring-disabled"))
        h.control("start"); XCTAssertEqual(h.frames.last?["reason"], .string("input-monitoring-disabled"))
        h.engine.complete(h.goodResult(oldTicket)); XCTAssertTrue(h.textFrames.isEmpty)
        h.control("pause"); XCTAssertEqual(h.frames.last?["reason"], .string("user-paused"))
        h.engine.desktopChanged(.locked, accessibility: false)
        h.control("heartbeat"); XCTAssertEqual(h.frames.last?["reason"], .string("user-paused"))
        h.env.desktop = .unknown; h.env.desktopReason = "desktop-lock-transition"
        h.control("resume"); XCTAssertEqual(h.frames.last?["reason"], .string("desktop-lock-transition"))
        h.env.desktop = .unlocked; h.control("resume"); XCTAssertEqual(h.engine.state, "running")
        h.engine.inputSessionUnavailable("input-monitoring-required")
        XCTAssertEqual(h.frames.last?["reason"], .string("input-monitoring-required"))
    }
    func testSecureReadBoundaryDropsOldMaterialAndWaitsForHealthyRetirementThenContinues() {
        let h = Harness(); configure(h, policy: CapturePolicy(inputText: true))
        let ticket = h.env.launched.last!, count = h.env.launched.count, epoch = h.engine.captureEpoch
        h.env.workerReady = false // Synthetic ACK/reap has not completed yet.
        h.engine.complete(ReadResult(token: ticket.token, reason: "secure-input-active", captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs))
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.frames.last?["reason"], .string("secure-input-suppressed"))
        XCTAssertEqual(h.env.retireCalls, 1); XCTAssertGreaterThan(h.engine.captureEpoch, epoch)
        h.control("heartbeat", lease: 30000); XCTAssertEqual(h.frames.last?["reason"], .string("secure-input-suppressed"))
        h.engine.complete(h.goodResult(ticket)); XCTAssertTrue(h.textFrames.isEmpty)
        h.engine.desktopChanged(.unlocked, accessibility: true); h.engine.workerDirty(); h.clock.advance(250); h.engine.tick()
        XCTAssertEqual(h.env.launched.count, count); XCTAssertEqual(h.engine.state, "paused")
        h.env.workerReady = true; h.env.secureInputBlocked = true
        h.engine.desktopChanged(.unlocked, accessibility: true); XCTAssertEqual(h.engine.state, "paused")
        h.env.secureInputBlocked = false; h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "running"); XCTAssertEqual(h.frames.last?["reason"], .string("secure-input-cleared"))
        h.clock.advance(51); h.engine.tick(); XCTAssertEqual(h.env.launched.count, count + 1)
        XCTAssertGreaterThan(h.env.launched.last!.captureEpoch, ticket.captureEpoch)
    }
    func testSecureSuppressionCannotRecoverAcrossFaultOwnerPauseStopOrRealDesktopBoundary() {
        let h = Harness(); configure(h, policy: CapturePolicy(inputText: true))
        h.engine.secureInputDetected(); h.engine.inputSessionUnavailable("input-monitoring-disabled")
        h.env.workerReady = true; h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.frames.last?["reason"], .string("input-monitoring-disabled"))
        h.control("resume", lease: 30000); h.engine.secureInputDetected(); h.control("pause")
        h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.frames.last?["reason"], .string("user-paused"))
        h.control("resume", lease: 30000); h.engine.secureInputDetected()
        h.env.secureInputBlocked = false; h.env.desktopReason = "screen-locked"; h.engine.desktopChanged(.locked, accessibility: false)
        h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.frames.last?["reason"], .string("screen-locked"))
        h.control("resume", lease: 30000); h.engine.secureInputDetected(); h.control("stop")
        h.engine.desktopChanged(.unlocked, accessibility: true); h.engine.secureInputDetected()
        XCTAssertEqual(h.engine.state, "stopped")
    }
    func testInputPermissionRevokedDuringSuppressionCannotReopenWithoutOwnerResume() {
        let h = Harness(); configure(h, policy: CapturePolicy(inputText: true))
        h.engine.secureInputDetected(); h.env.inputPermission = false
        h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.frames.last?["reason"], .string("input-monitoring-required"))
        h.env.inputPermission = true; h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "paused")
    }
    func testStartDuringSecureInputDefersListenersAndClearCanContinueWithoutResume() {
        let h = Harness(); h.env.secureInputBlocked = true; h.env.inputAvailable = true
        h.configure(inputActivity: true); h.control("start", lease: 30000)
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.env.inputBegins, 0)
        XCTAssertEqual(h.frames.last?["requestId"], .string("start")); XCTAssertEqual(h.frames.last?["reason"], .string("secure-input-suppressed"))
        h.env.secureInputBlocked = false; h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "running"); XCTAssertEqual(h.env.inputBegins, 1)
        h.engine.secureInputDetected(); h.env.secureInputBlocked = false; h.engine.desktopChanged(.unlocked, accessibility: false)
        h.engine.desktopChanged(.unlocked, accessibility: true)
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.frames.last?["reason"], .string("permission-denied"))
    }
    func testInputTextOnlyAXRevocationCannotAutoResumeOrRecreateListener() {
        let h = Harness(); configure(h, policy: CapturePolicy(inputText: true))
        h.engine.desktopChanged(.unlocked, accessibility: false)
        h.engine.desktopChanged(.unlocked, accessibility: true)
        let count = h.env.launched.count; h.clock.advance(1000); h.engine.tick()
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.env.launched.count, count)
    }
    func testInputWorkerTimeoutWithoutEligibleCleanupPausesInsteadOfAutomaticRestart() {
        let h = Harness(); configure(h, policy: CapturePolicy(inputText: true))
        h.clock.advance(201); h.engine.tick(); XCTAssertEqual(h.engine.state, "paused")
        XCTAssertEqual(h.frames.last?["reason"], .string("read-timeout-unrecoverable"))
        let count = h.env.launched.count; h.clock.advance(1000); h.engine.tick(); XCTAssertEqual(h.env.launched.count, count)
    }
    func testInputWorkerFailurePausesAndDirtyCannotRestart() {
        let h = Harness(); configure(h, policy: CapturePolicy(inputText: true))
        h.engine.complete(ReadResult(token: h.env.launched.last!.token, reason: "input-monitoring-required", captureStartMs: h.clock.unixMs, captureEndMs: h.clock.unixMs))
        let count = h.env.launched.count; h.engine.workerDirty(); h.clock.advance(1000); h.engine.tick()
        XCTAssertEqual(h.engine.state, "paused"); XCTAssertEqual(h.env.launched.count, count)
    }
}

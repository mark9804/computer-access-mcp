import XCTest
import CollectorCore

/// Entirely synthetic callbacks: no AppKit, AX handles, process, History, key
/// provider, GUI fixture, or permission APIs are created by these tests.
final class WindowFocusAnchorTests: XCTestCase {
    private final class Fake {
        let expected = ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "synthetic-birth")
        var policy = CapturePolicy(captureScope: "window")
        var applications: [ApplicationIdentity?] = []
        var focuses: [FocusElementRead<Int>] = [.noValue, .noValue]
        var windows: [Int?] = [101, 101]
        var windowAllowed = true
        var live = true
        var expireAfterCall: Int?
        var calls: [String] = []
        var inspected: [Int] = []

        init() { applications = [expected, expected] }
        private func record(_ name: String) {
            calls.append(name)
            if calls.count == expireAfterCall { live = false }
        }
        func application() -> ApplicationIdentity? {
            record("application")
            return applications.isEmpty ? nil : applications.removeFirst()
        }
        func focus() -> FocusElementRead<Int> {
            record("focus")
            return focuses.isEmpty ? .failure : focuses.removeFirst()
        }
        func window() -> Int? {
            record("window")
            return windows.isEmpty ? nil : windows.removeFirst()
        }
        func inspect(_ window: Int) -> Bool {
            record("inspect")
            inspected.append(window)
            return windowAllowed
        }
        func sameWindow(_ lhs: Int, _ rhs: Int) -> Bool {
            record("same-window")
            return lhs == rhs
        }
    }
    private let resolveCalls = ["application", "focus", "window", "inspect", "focus", "window", "same-window", "application"]
    private let validateCalls = ["application", "focus", "window", "same-window", "inspect", "focus", "window", "same-window", "application"]
    private func resolve(_ fake: Fake) -> Int? {
        WindowFocusAnchor.resolve(policy: fake.policy, expectedApplication: fake.expected,
            application: { fake.application() }, focus: { fake.focus() }, window: { fake.window() },
            inspectWindow: { fake.inspect($0) }, sameWindow: { fake.sameWindow($0, $1) },
            shouldContinue: { fake.live })
    }
    private func validate(_ fake: Fake, frozen: Int = 101) -> Bool {
        WindowFocusAnchor.validate(window: frozen, policy: fake.policy, expectedApplication: fake.expected,
            application: { fake.application() }, focus: { fake.focus() }, window: { fake.window() },
            inspectWindow: { fake.inspect($0) }, sameWindow: { fake.sameWindow($0, $1) },
            shouldContinue: { fake.live })
    }

    func testExplicitAbsenceAtBothEndsReturnsWindowWithoutInventingFocus() {
        let absent: [FocusElementRead<Int>] = [.noValue, .attributeUnsupported]
        for before in absent {
            for after in absent {
                let fake = Fake(); fake.focuses = [before, after]
                XCTAssertEqual(resolve(fake), 101)
                XCTAssertEqual(fake.calls, resolveCalls)
                XCTAssertEqual(fake.inspected, [101])
            }
        }
    }
    func testInitialElementFailureOrMalformedNeverReadsWindow() {
        let reads: [FocusElementRead<Int>] = [.element(101), .failure, .malformed]
        for read in reads {
            let fake = Fake(); fake.focuses = [read]
            XCTAssertNil(resolve(fake))
            XCTAssertEqual(fake.calls, ["application", "focus"])
            XCTAssertTrue(fake.inspected.isEmpty)
        }
    }
    func testFinalFocusAppearedFailureOrMalformedRefusesAlreadyInspectedWindow() {
        let reads: [FocusElementRead<Int>] = [.element(101), .failure, .malformed]
        for read in reads {
            let fake = Fake(); fake.focuses = [.noValue, read]
            XCTAssertNil(resolve(fake))
            XCTAssertEqual(fake.calls, Array(resolveCalls.prefix(5)))
            XCTAssertEqual(fake.inspected, [101])
        }
    }
    func testNonWindowOrInvalidPoliciesPerformNoAdapterCallbacks() {
        for scope in [nil, "focused", "region", "unsupported"] as [String?] {
            let fake = Fake(); fake.policy.captureScope = scope
            XCTAssertNil(resolve(fake)); XCTAssertTrue(fake.calls.isEmpty)
            XCTAssertFalse(validate(fake)); XCTAssertTrue(fake.calls.isEmpty)
        }
        let disabled = Fake(); disabled.policy.enabled = false
        let invalidRange = Fake(); invalidRange.policy.textRange = "whole-value"
        let invalidField = Fake(); invalidField.policy.fieldSecurity = "allow"
        let invalidNodes = Fake(); invalidNodes.policy.maxTreeNodes = 97
        for fake in [disabled, invalidRange, invalidField, invalidNodes] {
            XCTAssertNil(resolve(fake)); XCTAssertFalse(validate(fake)); XCTAssertTrue(fake.calls.isEmpty)
        }
    }
    func testExcludedExpectedApplicationPerformsNoAdapterCallbacks() {
        for broad in [false, true] {
            let fake = Fake()
            fake.policy.applicationScope = broad ? "denylist" : "allowlist"
            fake.policy.excludedApplicationIds = ["test.allowed"]
            XCTAssertNil(resolve(fake)); XCTAssertFalse(validate(fake)); XCTAssertTrue(fake.calls.isEmpty)
        }
        let fake = Fake(); fake.policy.allowedApplicationIds = ["test.other"]
        XCTAssertNil(resolve(fake)); XCTAssertTrue(fake.calls.isEmpty)
    }
    func testFirstApplicationMustMatchEveryIdentityField() {
        let fake = Fake()
        var changedID = fake.expected; changedID.applicationId = "test.other"
        var changedPID = fake.expected; changedPID.processId = 43
        var changedBirth = fake.expected; changedBirth.processStartTime = "reused-pid-birth"
        let identities: [ApplicationIdentity?] = [nil, changedID, changedPID, changedBirth]
        for identity in identities {
            let sample = Fake(); sample.applications = [identity]
            XCTAssertNil(resolve(sample)); XCTAssertEqual(sample.calls, ["application"])
            XCTAssertTrue(sample.inspected.isEmpty)
        }
    }
    func testFinalApplicationMustMatchEveryIdentityField() {
        let fake = Fake()
        var changedID = fake.expected; changedID.applicationId = "test.other"
        var changedPID = fake.expected; changedPID.processId = 43
        var changedBirth = fake.expected; changedBirth.processStartTime = "reused-pid-birth"
        let identities: [ApplicationIdentity?] = [nil, changedID, changedPID, changedBirth]
        for identity in identities {
            let sample = Fake(); sample.applications = [sample.expected, identity]
            XCTAssertNil(resolve(sample)); XCTAssertEqual(sample.calls, resolveCalls)
        }
    }
    func testMissingInitialWindowNeverInspectsAnything() {
        let fake = Fake(); fake.windows = [nil]
        XCTAssertNil(resolve(fake)); XCTAssertEqual(fake.calls, Array(resolveCalls.prefix(3)))
        XCTAssertTrue(fake.inspected.isEmpty)
    }
    func testWindowMetadataFailureNeverRechecksOrSamplesOtherWindow() {
        let fake = Fake(); fake.windowAllowed = false
        XCTAssertNil(resolve(fake)); XCTAssertEqual(fake.calls, Array(resolveCalls.prefix(4)))
        XCTAssertEqual(fake.inspected, [101])
    }
    func testMissingOrDifferentFinalWindowRefusesAnchor() {
        for final in [nil, 102] as [Int?] {
            let fake = Fake(); fake.windows = [101, final]
            XCTAssertNil(resolve(fake))
            XCTAssertEqual(fake.calls, Array(resolveCalls.prefix(final == nil ? 6 : 7)))
            XCTAssertEqual(fake.inspected, [101])
        }
    }
    func testExpiredBeforeStartPerformsNoAdapterCallbacks() {
        let fake = Fake(); fake.live = false
        XCTAssertNil(resolve(fake)); XCTAssertFalse(validate(fake)); XCTAssertTrue(fake.calls.isEmpty)
    }
    func testExpiryAfterEveryResolutionCallbackStopsBeforeNextCallback() {
        for count in 1...resolveCalls.count {
            let fake = Fake(); fake.expireAfterCall = count
            XCTAssertNil(resolve(fake), "callback \(count)")
            XCTAssertEqual(fake.calls, Array(resolveCalls.prefix(count)))
        }
    }
    func testValidationOfSameWindowFreshlyRepeatsAllChecks() {
        let fake = Fake()
        XCTAssertTrue(validate(fake)); XCTAssertEqual(fake.calls, validateCalls)
        XCTAssertEqual(fake.inspected, [101])
    }
    func testValidationRejectsDifferentInitialWindowBeforeInspectingIt() {
        let fake = Fake(); fake.windows = [102, 102]
        XCTAssertFalse(validate(fake)); XCTAssertEqual(fake.calls, Array(validateCalls.prefix(4)))
        XCTAssertTrue(fake.inspected.isEmpty)
    }
    func testValidationRejectsMissingOrDifferentFinalWindow() {
        for final in [nil, 102] as [Int?] {
            let fake = Fake(); fake.windows = [101, final]
            XCTAssertFalse(validate(fake))
            XCTAssertEqual(fake.calls, Array(validateCalls.prefix(final == nil ? 7 : 8)))
            XCTAssertEqual(fake.inspected, [101])
        }
    }
    func testValidationDoesNotReuseSuccessfulOldAbsence() {
        let fake = Fake(); fake.focuses = [.noValue, .element(201)]
        XCTAssertFalse(validate(fake)); XCTAssertEqual(fake.calls, Array(validateCalls.prefix(6)))
    }
    func testExpiryAfterEveryValidationCallbackStopsBeforeNextCallback() {
        for count in 1...validateCalls.count {
            let fake = Fake(); fake.expireAfterCall = count
            XCTAssertFalse(validate(fake), "callback \(count)")
            XCTAssertEqual(fake.calls, Array(validateCalls.prefix(count)))
        }
    }
    func testMandatoryDeniedFamiliesNeverReachAdapterEvenWithBrowserAuthorization() {
        for id in ["com.1password.1password", "com.apple.Safari", "com.agilebits.onepassword-osx.helper"] {
            var calls = 0
            let policy = CapturePolicy(applicationScope: "denylist", allowBrowserContent: true, captureScope: "window")
            let app = ApplicationIdentity(applicationId: id, processId: 42, processStartTime: "synthetic-birth")
            let result: Int? = WindowFocusAnchor.resolve(policy: policy, expectedApplication: app,
                application: { calls += 1; return app }, focus: { calls += 1; return .noValue },
                window: { calls += 1; return 101 }, inspectWindow: { _ in calls += 1; return true },
                sameWindow: { $0 == $1 }, shouldContinue: { calls += 1; return true })
            XCTAssertNil(result); XCTAssertEqual(calls, 0)
        }
    }
    func testKnownBrowserRequiresExplicitBroadBrowserAuthorization() {
        let app = ApplicationIdentity(applicationId: "com.google.Chrome", processId: 42, processStartTime: "synthetic-birth")
        for broad in [false, true] {
            for allowBrowser in [false, true] {
                var calls = 0
                let policy = CapturePolicy(allowedApplicationIds: [app.applicationId], applicationScope: broad ? "denylist" : "allowlist", allowBrowserContent: allowBrowser, captureScope: "window")
                let result: Int? = WindowFocusAnchor.resolve(policy: policy, expectedApplication: app,
                    application: { calls += 1; return app }, focus: { calls += 1; return .attributeUnsupported },
                    window: { calls += 1; return 101 }, inspectWindow: { _ in calls += 1; return true },
                    sameWindow: { $0 == $1 }, shouldContinue: { true })
                XCTAssertEqual(result != nil, broad && allowBrowser)
                XCTAssertEqual(calls > 0, broad && allowBrowser)
            }
        }
    }
    func testOpaqueNonEquatableHandlesUseAdapterIdentityNotSwiftEquality() {
        final class Handle { let id: Int; init(_ id: Int) { self.id = id } }
        let first = Handle(101), fresh = Handle(101)
        var windows = [first, fresh], comparisons = 0
        let app = ApplicationIdentity(applicationId: "test.allowed", processId: 42, processStartTime: "synthetic-birth")
        let result = WindowFocusAnchor.resolve(policy: CapturePolicy(captureScope: "window"), expectedApplication: app,
            application: { app }, focus: { FocusElementRead<Handle>.noValue }, window: { windows.removeFirst() },
            inspectWindow: { $0 === first }, sameWindow: { lhs, rhs in comparisons += 1; return lhs.id == rhs.id },
            shouldContinue: { true })
        XCTAssertTrue(result === first); XCTAssertEqual(comparisons, 1)
    }
}

import Foundation
import AppKit
import ApplicationServices
import Carbon
import CollectorCore

/// All AX handles, optional markers, subscriptions and input buffers live in this
/// one killable worker, never on Collector's control loop or in persistent data.
final class AXWorkerSession {
    private let clock = SystemCollectorClock()
    private let id = UUID().uuidString
    private var boundApplication: ApplicationIdentity?
    private var provider: AXFieldProvider?
    private var previousField: AXUIElement?
    private var previousWindow: AXUIElement?
    private var identity: WorkerSurfaceIdentity?
    private var serial: Int64 = 0
    private var nodeMap = AXSurfaceNodeMap<AXUIElement>(equal: { CFEqual($0, $1) })
    private let baseline = SurfaceBaseline()
    private let enablement = AXEnablementLease()
    private var observer: AXObserver?
    private var registrations: [(AXUIElement, CFString)] = []
    private var observedField: AXUIElement?
    private var observedWindow: AXUIElement?
    private var input: InputTextCapture?
    private var inputAttempted = false
    private var currentTicket: ReadTicket?
    private var activeReadDeadline: Int64?
    private var currentInputContext: InputTextContext?
    private(set) var dirty = false
    private(set) var submitDirty = false
    private var observerState = "unavailable"
    private(set) var invalidatedFocus = false
    private var focusInvalidationSerial: UInt64 = 0
    var inputFailure: String?
    private(set) var secureInputDetected = false
    func suppressSecureInput() {
        guard !secureInputDetected else { input?.invalidate(); return }
        secureInputDetected = true
        currentInputContext = nil; input?.suppressSecureInput()
        inputGaps.removeAll(); baseline.reset(); nodeMap.reset(); dirty = true; submitDirty = false
    }
    private func desktopReadable() -> Bool {
        let assessment = WorkerProgress.withValue(api: 15) { desktopAssessment() }
        if assessment.isSecureInputOnly { suppressSecureInput() }
        return assessment.desktopStatus == .unlocked && !secureInputDetected
    }
    private var inputGaps: [String] = []
    private var retiringForProcessExit = false
    private(set) var debugReadId: Int64 = 0
    var debugProgress: ((Int64, SessionReadOperation, Int64) -> Void)?
    private func mark(_ operation: SessionReadOperation, index: Int64 = -1) {
        WorkerProgress.stage(readId: debugReadId, operation: operation.rawValue, index: index)
        debugProgress?(debugReadId, operation, index)
    }
    private var inputContextEstablishedNanoseconds: UInt64?

    private func traceInput(_ stage: InputDebugTrace.Stage, _ reason: InputDebugTrace.Reason,
                            targetPid: Int32? = nil, role: InputTextFieldRole? = nil, line: UInt = #line) {
        let now = DispatchTime.now().uptimeNanoseconds
        let age = inputContextEstablishedNanoseconds.flatMap { now >= $0 ? Int64((now - $0) / 1_000_000) : nil }
        InputDebugTrace.record(.context, stage: stage, reason: reason, readId: debugReadId,
            targetPid: targetPid ?? boundApplication?.processId, contextAgeMs: currentInputContext == nil ? nil : age,
            contextPresent: currentInputContext != nil, ticketPresent: currentTicket != nil,
            fieldPresent: previousField != nil, windowPresent: previousWindow != nil, role: role, file: #fileID, line: line)
    }

    func takeDirty() -> Bool { let value = dirty; dirty = false; return value }
    func takeSubmitDirty() -> Bool { let value = submitDirty; submitDirty = false; return value }
    func poll() { input?.poll() }
    func invalidateReadFailure(_ code: ReadDiagnostic.Code?) {
        input?.invalidate(); currentInputContext = nil
        if code == .applicationUnavailable {
            // Collector discards its Worker identity on this exact negative
            // reply. Even the same AX handles must establish a new identity so
            // the recovered input context advances with Collector's generations.
            invalidatedFocus = true; baseline.reset(); nodeMap.reset()
        }
    }
    func retireHealthy() -> Bool {
        // Seal content before checking listener health. Retirement never flushes
        // or reauthorizes a previous field, and no more run-loop callbacks follow.
        retiringForProcessExit = true
        submitDirty = false
        currentTicket = nil; currentInputContext = nil; input?.invalidate()
        let started = clock.monotonicMs
        let healthy = input?.retireHealthy() ?? (inputFailure == nil && !inputAttempted)
        CollectorDebugTrace.record("session-retire-input-ended", numbers: ["elapsedMs": clock.monotonicMs - started], flags: ["healthy": inputFailure == nil && healthy])
        input = nil; baseline.reset(); nodeMap.reset(); inputGaps.removeAll()
        let detachStarted = clock.monotonicMs
        removeObserver(forProcessExit: true)
        CollectorDebugTrace.record("session-retire-observer-detached", numbers: ["elapsedMs": clock.monotonicMs - detachStarted])
        return inputFailure == nil && healthy
    }
    private func invalidate(focus: Bool) {
        dirty = true
        if focus {
            submitDirty = false
            focusInvalidationSerial &+= 1
            input?.invalidate(); invalidatedFocus = true; currentInputContext = nil; baseline.reset(); nodeMap.reset()
        }
    }
    private func nodeID(_ element: AXUIElement) -> String {
        // This is only called just after a real focus/window boundary reset.
        // Surface batches use a disposable map copy and can reject saturation.
        nodeMap.identifier(for: element) ?? UUID().uuidString
    }

    private func prepareSurface(_ capture: AXSurfaceCapture, focus: AXUIElement?) -> (nodes: [SurfaceNodeRead], map: AXSurfaceNodeMap<AXUIElement>, reset: Bool)? {
        var proposed = nodeMap
        let pin = focus.flatMap { field in identity.map { (field, $0.nodeId) } }
        let reset = proposed.prepareCommit(adapterId: capture.adapterId, selecting: capture.selectedHandles, pin: pin)
        guard let nodes = capture.materializeNodes(nodeID: { proposed.identifier(for: $0) }) else { return nil }
        return (nodes, proposed, reset)
    }

    private func commitSurface(_ capture: AXSurfaceCapture, prepared: (nodes: [SurfaceNodeRead], map: AXSurfaceNodeMap<AXUIElement>, reset: Bool),
                               surfaceId: String, scope: String) -> SurfaceReadResult {
        if prepared.reset { baseline.reset() }
        nodeMap = prepared.map
        return baseline.snapshot(surfaceId: surfaceId, scope: scope, nodes: prepared.nodes, complete: capture.complete,
            matchingKnown: true, truncated: capture.truncated, missingReasons: capture.reasons, geometry: capture.geometry)
    }
    private func installObserver(_ provider: AXFieldProvider) {
        guard let application = provider.app, let window = provider.window else { return }
        let field = provider.field
        let sameField = (observedField == nil && field == nil) || observedField.flatMap { old in field.map { CFEqual(old, $0) } } == true
        if let observedWindow, CFEqual(observedWindow, window), sameField, observer != nil, !registrations.isEmpty { return }
        guard let ticket = currentTicket,
              let observerDeadline = AXPhaseBudget.observerDeadline(nowMs: clock.monotonicMs,
                  hardDeadlineMs: ticket.deadlineMonotonicMs, phaseDeadlineMs: provider.deadlineMonotonicMs) else {
            // Close the local source even when no optional IPC budget remains.
            removeObserver(deadline: clock.monotonicMs); observerState = "unavailable"; return
        }
        removeObserver(deadline: observerDeadline)
        guard clock.monotonicMs < observerDeadline else { observerState = "unavailable"; return }
        mark(.observerCreate)
        var created: AXObserver?
        let status = WorkerProgress.withCall(api: 12) { AXObserverCreate(provider.expected.processId, { _, _, name, context in
            guard let context else { return }
            let session = Unmanaged<AXWorkerSession>.fromOpaque(context).takeUnretainedValue()
            // Callback carries no value/title/text. Only dirty and boundary bits.
            let notification = name as String
            session.invalidate(focus: notification == kAXFocusedUIElementChangedNotification || notification == kAXFocusedWindowChangedNotification)
        }, &created) }
        guard status == .success, let created, clock.monotonicMs < observerDeadline else { observerState = "unavailable"; return }
        observer = created; observedField = field; observedWindow = window
        let context = Unmanaged.passUnretained(self).toOpaque()
        var notifications: [(AXUIElement, CFString)] = [(application, kAXFocusedUIElementChangedNotification as CFString), (application, kAXFocusedWindowChangedNotification as CFString)]
        if let field {
            notifications += [(field, kAXValueChangedNotification as CFString), (field, kAXSelectedTextChangedNotification as CFString)]
        }
        for (index, registration) in notifications.enumerated() {
            let (element, name) = registration
            mark(.observerAdd, index: Int64(index))
            let accepted = AXPhaseBudget.observerCall(nowMs: { self.clock.monotonicMs }, deadlineMs: observerDeadline,
                setTimeout: { NativeOperation.setTimeout(element, $0) == .success },
                perform: { WorkerProgress.withCall(api: 13, { AXObserverAddNotification(created, element, name, context) }) == .success })
            if accepted { registrations.append(registration) }
        }
        observerState = registrations.isEmpty ? "unavailable" : "best-effort"
        CFRunLoopAddSource(CFRunLoopGetMain(), AXObserverGetRunLoopSource(created), .commonModes)
    }
    private func removeObserver(forProcessExit: Bool = false, deadline: Int64? = nil) {
        ObserverTeardown.perform(forProcessExit: forProcessExit, unregister: {
            if let observer {
                let cutoff = deadline ?? clock.monotonicMs // No unbudgeted remote cleanup on deinit.
                for (index, registration) in registrations.enumerated() {
                    let (element, name) = registration
                    mark(.observerRemove, index: Int64(index))
                    _ = AXPhaseBudget.observerCall(nowMs: { self.clock.monotonicMs }, deadlineMs: cutoff,
                        setTimeout: { NativeOperation.setTimeout(element, $0) == .success },
                        perform: { WorkerProgress.withCall(api: 14, { AXObserverRemoveNotification(observer, element, name) }) == .success })
                }
            }
        }, detach: {
            if let observer { CFRunLoopRemoveSource(CFRunLoopGetMain(), AXObserverGetRunLoopSource(observer), .commonModes) }
        }, release: {
            registrations.removeAll(); observer = nil; observedField = nil; observedWindow = nil
        })
        // Terminal retirement deliberately retains observer/registration handles.
        // SessionTransport holds this session until the ACK drains, then _exit
        // releases process-owned resources without provider IPC or ARC teardown.
    }
    private func safety(_ request: InputTextSafetyRequest) -> Result<InputTextApprovedContext, InputTextGapReason> {
        // Reject as before. The typed receipt only describes the first failed
        // guard, does not perform new queries, and cannot permit any input.
        func reject(_ stage: InputDebugTrace.Stage, _ reason: InputDebugTrace.Reason,
                    _ gap: InputTextGapReason = .stale, targetPid: Int32? = nil, role: InputTextFieldRole? = nil,
                    line: UInt = #line) -> Result<InputTextApprovedContext, InputTextGapReason> {
            traceInput(stage, reason, targetPid: targetPid, role: role, line: line)
            return .failure(gap)
        }
        guard let ticket = currentTicket else { return reject(.safetyEntry, .ticketMissing) }
        guard let expected = boundApplication else { return reject(.safetyEntry, .applicationMissing) }
        guard let identity else { return reject(.safetyEntry, .identityMissing) }
        guard let context = currentInputContext else { return reject(.safetyEntry, .contextMissing) }
        guard ticket.policy.inputText == true else { return reject(.safetyEntry, .policyDisabled) }
        guard context.isValid else { return reject(.safetyEntry, .contextInvalid) }
        guard context.fieldSecurityMode == ticket.policy.fieldSecurityMode else { return reject(.safetyEntry, .fieldSecurityPolicyChanged) }
        guard ApplicationPolicy.allows(expected.applicationId, policy: ticket.policy) else { return reject(.safetyEntry, .applicationExcluded) }
        // Idle events retain the existing 180ms gate. A flush inside an explicit
        // read may not start a new safety window beyond that read's hard cutoff.
        if let activeReadDeadline, clock.monotonicMs >= activeReadDeadline { return reject(.safetyEntry, .deadlineExceeded, .verificationTimeout) }
        guard desktopReadable() else { return reject(.safetyEntry, .desktopUnavailable) }
        guard WorkerProgress.withValue(api: 16, { AXIsProcessTrusted() }) else { return reject(.safetyEntry, .accessibilityUnavailable) }
        guard !WorkerProgress.withValue(api: 17, { IsSecureEventInputEnabled() }) else { suppressSecureInput(); return reject(.safetyEntry, .secureInputActive) }
        guard let oldField = previousField else { return reject(.safetyEntry, .fieldMissing) }
        guard let oldWindow = previousWindow else { return reject(.safetyEntry, .windowMissing) }
        switch request {
        case .event(let metadata):
            guard metadata.targetProcessId == expected.processId else {
                return reject(.safetyRequest, .targetPidMismatch, metadata.targetProcessId > 1 ? .targetMismatch : .stale, targetPid: metadata.targetProcessId)
            }
        case .flush(let old):
            guard old == context else { return reject(.safetyRequest, .contextChanged, .contextMismatch(old, context)) }
        }
        // A new provider means every event gets fresh identity/role/security AX
        // evidence, not a cached permission. Hard worker watchdog bounds blocking.
        let check = AXFieldProvider(expected: expected, timeoutMs: min(100, ticket.policy.readTimeoutMs), policy: ticket.policy)
        check.debugReadId = debugReadId
        check.secureInput = { [weak self] in self?.suppressSecureInput() }
        check.deadlineMonotonicMs = min(clock.monotonicMs + 180, activeReadDeadline ?? Int64.max)
        guard check.resolveFocusedField() else {
            if check.lastFocusResolveStatus == .mismatch { return reject(.safetyResolve, .focusUnresolved, .targetMismatch) }
            if check.lastFocusResolveDeadlineExceeded { return reject(.safetyResolve, .deadlineExceeded, .verificationTimeout) }
            return reject(.safetyResolve, .focusUnresolved)
        }
        guard let field = check.field else { return reject(.safetyResolve, .fieldMissing) }
        guard let window = check.window else { return reject(.safetyResolve, .windowMissing) }
        guard CFEqual(field, oldField) else { return reject(.safetyResolve, .fieldChanged, .targetMismatch) }
        guard CFEqual(window, oldWindow) else { return reject(.safetyResolve, .windowChanged, .targetMismatch) }
        let role: InputTextFieldRole
        switch check.inputEligibility() {
        case .sensitive: return reject(.safetySecurity, .fieldSensitive)
        case .unknown: return reject(.safetySecurity, .fieldSecurityUnknown, .fieldSecurityUnknown)
        case .roleNotEditable: return reject(.safetyRole, .roleUnsupported, .roleNotEditable)
        case .allowed(let approvedRole): role = approvedRole
        }
        var boundaryFailure: SurfaceReadFailure?
        guard check.remainsSameFocusAndWindow(onBoundaryFailure: { boundaryFailure = $0 }) else {
            switch boundaryFailure {
            case .boundaryMismatch: return reject(.safetyFinal, .focusWindowUnverified, .targetMismatch, role: role)
            case .boundaryIncomplete: return reject(.safetyFinal, .deadlineExceeded, .verificationTimeout, role: role)
            default: return reject(.safetyFinal, .focusWindowUnverified, role: role)
            }
        }
        guard !WorkerProgress.withValue(api: 17, { IsSecureEventInputEnabled() }) else { suppressSecureInput(); return reject(.safetyFinal, .secureInputActive) }
        guard desktopReadable() else { return reject(.safetyFinal, .desktopUnavailable) }
        guard context.surfaceId == identity.surfaceId else { return reject(.safetyFinal, .surfaceChanged, .targetMismatch, role: role) }
        guard clock.monotonicMs < check.deadlineMonotonicMs else { return reject(.safetyFinal, .deadlineExceeded, .verificationTimeout, role: role) }
        return .success(InputTextApprovedContext(context: context, metadataMonotonicNanoseconds: DispatchTime.now().uptimeNanoseconds, role: role))
    }
    /// A missing AX focus has no field/selection/input context. A separately
    /// verified window may still yield a current surface; never an empty text read.
    private func readUnfocusedWindow(_ ticket: ReadTicket, provider: AXFieldProvider, application app: ApplicationIdentity,
                                     started: Int64, enablement: AXEnablementResult) -> ReadResult {
        input?.invalidate(); currentInputContext = nil; inputGaps.removeAll()
        let anchorEpoch = focusInvalidationSerial
        var surfaceAttempted = false
        var accepted = false
        defer {
            provider.deadlineMonotonicMs = ticket.deadlineMonotonicMs
            provider.finishWindowSampling()
            if !accepted { baseline.reset(); nodeMap.reset(); invalidatedFocus = true }
        }
        func failure(_ reason: String, _ code: ReadDiagnostic.Code) -> ReadResult {
            var result = ReadResult(token: ticket.token, reason: reason, diagnostic: .init(code: code), captureStartMs: started, captureEndMs: max(started, clock.unixMs))
            result.enablement = enablement
            if surfaceAttempted {
                if code == .secureField { provider.noteSurfaceFailure(.securityExcluded) }
                else if code == .focusChanged || code == .fieldSecurityUnknown { provider.noteSurfaceFailure(.boundaryUnverified) }
                else if code == .readDeadline { provider.noteSurfaceFailure(.timeBudget) }
            }
            result.surfaceFailure = provider.surfaceFailure
            if code != .secureField, result.surfaceFailure != .securityExcluded,
               !reason.hasPrefix("secure-input-") { result.diagnosticApplication = app }
            return result
        }
        guard ticket.policy.captureScope == "window", ticket.policy.enabled, ticket.policy.hasValidTextSettings,
              clock.monotonicMs < ticket.deadlineMonotonicMs,
              let optionalDeadline = AXPhaseBudget.optionalDeadline(nowMs: clock.monotonicMs, hardDeadlineMs: ticket.deadlineMonotonicMs) else {
            provider.noteSurfaceFailure(.notStartedBudget); return failure("stale", .readDeadline)
        }
        provider.deadlineMonotonicMs = optionalDeadline
        mark(.windowAnchor)
        guard provider.resolveUnfocusedWindow(), let window = provider.window, provider.field == nil else {
            if provider.privateWindowBlocked || provider.surfaceFailure == .securityExcluded {
                provider.noteSurfaceFailure(.securityExcluded)
                return failure("policy-boundary", provider.privateWindowBlocked ? .browserExcluded : .secureField)
            }
            return failure("focus-unavailable", .focusedFieldUnavailable)
        }
        let changed = invalidatedFocus || identity == nil || previousField != nil ||
            previousWindow.map { !CFEqual($0, window) } != false
        if changed {
            serial += 1; baseline.reset(); nodeMap.reset()
            // nodeId is an unused opaque DTO slot in this mode, NOT a fake focus.
            identity = WorkerSurfaceIdentity(sessionId: id, windowId: UUID().uuidString, nodeId: UUID().uuidString,
                surfaceId: UUID().uuidString, windowGeneration: serial, focusGeneration: serial)
        }
        installObserver(provider)
        surfaceAttempted = true
        mark(.surface)
        guard let identity,
              let tree = provider.readSurface(scope: "window", maxNodes: ticket.policy.maxTreeNodes ?? 64,
                  maxText: min(8192, ticket.policy.maxTextCodeUnits)) else {
            return failure("read-error", .textReadUnavailable)
        }
        guard !tree.nodes.isEmpty else { provider.noteSurfaceFailure(.providerUnavailable); return failure("read-error", .textReadUnavailable) }
        // The shared surface AX counter remains active through these hard-phase
        // checks; no reset/refund and no authorization from cached window metadata.
        provider.deadlineMonotonicMs = ticket.deadlineMonotonicMs
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else {
            // A delivered candidate cannot be retained without this final proof.
            provider.noteSurfaceFailure(.boundaryIncomplete); return failure("stale", .readDeadline)
        }
        mark(.finalField)
        guard provider.remainsSameFocusAndWindow(onBoundaryFailure: { provider.noteSurfaceFailure($0) }) else {
            provider.noteSurfaceFailure(.boundaryUnverified); return failure("stale", .focusChanged)
        }
        // A notification invalidates the old anchor, but need not mean AX
        // returned a different object. Preserve the unclassified boundary code.
        guard focusInvalidationSerial == anchorEpoch else {
            provider.noteSurfaceFailure(.boundaryUnverified); return failure("stale", .focusChanged)
        }
        mark(.finalDesktop)
        guard desktopReadable() else { return failure(secureInputDetected ? "secure-input-active" : "desktop-unavailable", .desktopUnavailable) }
        guard !WorkerProgress.withValue(api: 17, { IsSecureEventInputEnabled() }) else { suppressSecureInput(); return failure("secure-input-active", .secureField) }
        guard WorkerProgress.withValue(api: 16, { AXIsProcessTrusted() }) else { return failure("permission-denied", .accessibilityDenied) }
        guard inputFailure == nil else { return failure(inputFailure!, .inputTextReadUnavailable) }
        guard focusInvalidationSerial == anchorEpoch else { return failure("stale", .focusChanged) }
        guard !secureInputDetected else { return failure("secure-input-active", .secureField) }
        guard provider.actualTextReadUnits <= 8192 else { return failure("read-error", .textResultInvalid) }
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline) }
        var result = ReadResult(token: ticket.token, application: app, diagnostic: .init(code: .focusedFieldUnavailable),
            captureStartMs: started, captureEndMs: max(started, clock.unixMs))
        result.diagnosticApplication = app
        result.focusAbsent = true; result.enablement = enablement; result.sessionIdentity = identity
        result.privateState = provider.privateState
        guard let prepared = prepareSurface(tree, focus: nil) else { return failure("read-error", .textResultInvalid) }
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline) }
        result.surface = commitSurface(tree, prepared: prepared, surfaceId: identity.surfaceId, scope: "window")
        result.captureEndMs = max(started, clock.unixMs)
        previousField = nil; previousWindow = window; invalidatedFocus = false
        result.observerStatus = observerState
        accepted = true
        return result
    }
    func read(_ ticket: ReadTicket) -> ReadResult {
        debugReadId += 1
        input?.debugReadId = debugReadId
        let started = clock.unixMs
        activeReadDeadline = ticket.deadlineMonotonicMs
        mark(.authority)
        defer { activeReadDeadline = nil; mark(.completed) }
        // Failure metadata belongs only to this ticket, never a previous provider.
        self.provider = nil
        var surfaceAttempted = false
        let fastOnly = ticket.focusedFastOnly == true
        var diagnosticApplication: ApplicationIdentity?
        func failure(_ reason: String, _ code: ReadDiagnostic.Code? = nil) -> ReadResult {
            invalidateReadFailure(code)
            var result = ReadResult(token: ticket.token, reason: reason, diagnostic: code.map { ReadDiagnostic(code: $0) }, captureStartMs: started, captureEndMs: max(started, clock.unixMs))
            if !fastOnly, ticket.policy.captureScope == "region" || ticket.policy.captureScope == "window" {
                if surfaceAttempted {
                    if code == .secureField { self.provider?.noteSurfaceFailure(.securityExcluded) }
                    else if code == .focusChanged || code == .fieldSecurityUnknown { self.provider?.noteSurfaceFailure(.boundaryUnverified) }
                    else if code == .readDeadline { self.provider?.noteSurfaceFailure(.timeBudget) }
                }
                result.surfaceFailure = self.provider?.surfaceFailure
            }
            if code != .secureField, result.surfaceFailure != .securityExcluded,
               !reason.hasPrefix("secure-input-") { result.diagnosticApplication = diagnosticApplication }
            return result
        }
        currentTicket = ticket
        guard !secureInputDetected else { return failure("secure-input-active") }
        guard desktopReadable() else { return failure(secureInputDetected ? "secure-input-active" : "desktop-unavailable", .desktopUnavailable) }
        guard !WorkerProgress.withValue(api: 17, { IsSecureEventInputEnabled() }) else { suppressSecureInput(); return failure("secure-input-active", .secureField) }
        guard WorkerProgress.withValue(api: 16, { AXIsProcessTrusted() }) else { return failure("permission-denied", .accessibilityDenied) }
        let application: (application: NSRunningApplication, applicationId: String)
        switch ApplicationAvailability.application(WorkerProgress.withValue(api: 18, { NSWorkspace.shared.frontmostApplication }),
            bundleIdentifier: { $0.bundleIdentifier }) {
        case .success(let observed): application = observed
        case .failure(let rejection):
            ApplicationAvailability.record(rejection, phase: .sessionApplication, readId: debugReadId)
            return failure("policy-boundary", .applicationUnavailable)
        }
        let running = application.application, applicationId = application.applicationId
        guard ApplicationPolicy.allows(applicationId, policy: ticket.policy) else {
            let silentExclude = ticket.policy.applicationScope == "denylist" ||
                ApplicationPolicy.isMandatoryDenied(applicationId) ||
                ApplicationPolicy.isSystemUI(applicationId)
            return failure(silentExclude ? "application-excluded" : "policy-boundary", .applicationNotAllowed)
        }
        let app: ApplicationIdentity
        switch WorkerProgress.withValue(api: 19, { AXFieldProvider.identityObservation(running) }) {
        case .success(let observed): app = observed
        case .failure(let rejection):
            ApplicationAvailability.record(rejection, phase: .sessionIdentity, readId: debugReadId)
            return failure("policy-boundary", .applicationUnavailable)
        }
        guard AXFieldProvider.permittedApplication(running, policy: ticket.policy) else { return failure("policy-boundary", .browserExcluded) }
        guard boundApplication == nil || boundApplication == app else { return failure("session-app-changed", .focusChanged) }
        boundApplication = app
        if let hint = ticket.hint, hint.application != app { return failure("stale", .focusChanged) }
        diagnosticApplication = app
        CollectorDebugTrace.record("session-read-context", numbers: ["readId": debugReadId, "targetPid": Int64(app.processId)],
            strings: ["applicationId": app.applicationId, "applicationName": running.localizedName ?? "unknown"])
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline) }
        let adapter = AppAdapterRegistry.shared.adapter(for: app.applicationId)
        mark(.enablement)
        let enabled = enablement.acquire(
            applicationId: app.applicationId,
            policy: ticket.policy,
            activation: adapter.spec.activation,
            provider: NativeAXEnablementProvider(pid: app.processId, timeoutMs: ticket.policy.readTimeoutMs, hardDeadlineMs: ticket.deadlineMonotonicMs),
            allowWrite: ticket.readOnlyAXEnablement != true
        )
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline) }
        let provider = AXFieldProvider(expected: app, timeoutMs: ticket.policy.readTimeoutMs, policy: ticket.policy, adapter: adapter)
        provider.debugReadId = debugReadId
        if ticket.policy.inputText == true {
            if let inputFailure { return failure(inputFailure) }
            guard CGPreflightListenEventAccess() else {
                inputFailure = "input-monitoring-required"; return failure("input-monitoring-required")
            }
            if inputAttempted, input?.isHealthy != true {
                inputFailure = "input-monitoring-disabled"; return failure("input-monitoring-disabled")
            }
            if IsSecureEventInputEnabled() { suppressSecureInput(); return failure("secure-input-active", .secureField) }
            provider.recoverableFocusDeadline = ticket.deadlineMonotonicMs
        }
        provider.secureInput = { [weak self] in self?.suppressSecureInput() }
        provider.deadlineMonotonicMs = ticket.deadlineMonotonicMs
        self.provider = provider
        mark(.focusedReader)
        var result = BoundedTextReader().read(
            ticket: ticket,
            provider: provider,
            clock: clock,
            staticTextProbe: adapter.spec.staticTextProbe
        )
        guard !secureInputDetected else { return failure("secure-input-active", .secureField) }
        if result.diagnostic?.code != .secureField { result.diagnosticApplication = diagnosticApplication }
        result.enablement = enabled
        if provider.privateWindowBlocked {
            provider.noteSurfaceFailure(.securityExcluded)
            var blocked = failure("policy-boundary", .browserExcluded)
            blocked.surfaceFailure = .securityExcluded
            blocked.diagnosticApplication = nil
            return blocked
        }
        if !fastOnly, provider.field == nil, ticket.policy.captureScope == "window",
           adapter.spec.windowAnchor.allowsUnfocusedWindow,
           result.diagnostic?.code == .focusedFieldUnavailable,
           provider.canFallbackToUnfocusedWindow {
            return readUnfocusedWindow(ticket, provider: provider, application: app, started: started, enablement: enabled)
        }
        guard let field = provider.field, let window = provider.window else {
            // Failed resolution closes the old input context and forces the next
            // successful read to rebaseline, even if AX returns the same handles.
            input?.invalidate(); currentInputContext = nil; invalidatedFocus = true
            baseline.reset(); nodeMap.reset()
            if !fastOnly, ticket.policy.captureScope == "region" || ticket.policy.captureScope == "window" { result.surfaceFailure = provider.surfaceFailure ?? .anchorUnavailable }
            return result
        }
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline) }
        mark(.fieldGate)
        let focusRole = provider.role()
        let textFocus = ["AXTextField", "AXTextArea", "AXStaticText"].contains(focusRole)
        let focusSecurity = provider.secureStatus()
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline) }
        guard focusSecurity != .sensitive, !textFocus || ticket.policy.allows(focusSecurity) else {
            return failure("stale", focusSecurity == .sensitive ? .secureField : .fieldSecurityUnknown)
        }
        // Each optional channel is independent of prefix-text availability. A
        // menu focus is not text, but an explicitly requested window tree can
        // still be traversed with per-leaf safety checks; no input is permitted.
        result.application = app
        let changed = invalidatedFocus || identity == nil || previousField.map { !CFEqual($0, field) } != false || previousWindow.map { !CFEqual($0, window) } != false
        if changed {
            serial += 1; baseline.reset(); nodeMap.reset(); input?.invalidate()
            identity = WorkerSurfaceIdentity(sessionId: id, windowId: UUID().uuidString, nodeId: nodeID(field), surfaceId: UUID().uuidString, windowGeneration: serial, focusGeneration: serial)
        }
        invalidatedFocus = false; previousField = field; previousWindow = window
        result.sessionIdentity = identity
        result.privateState = provider.privateState
        installObserver(provider)
        result.observerStatus = observerState
        var remaining = max(0, 8192 - provider.actualTextReadUnits - (ticket.policy.inputText == true ? 2048 : 0))
        let surfaceRequested = !fastOnly && (ticket.policy.captureScope == "region" || ticket.policy.captureScope == "window")
        var pendingSurface: AXSurfaceCapture?
        // A soft timeout drops optional channels, not already-read focused text.
        // Fast submit reads skip selection and surface traversal to finish in 2-3 AX IPCs.
        if !fastOnly {
            if let optionalDeadline = AXPhaseBudget.optionalDeadline(nowMs: clock.monotonicMs, hardDeadlineMs: ticket.deadlineMonotonicMs) {
                provider.deadlineMonotonicMs = optionalDeadline
                defer { provider.deadlineMonotonicMs = ticket.deadlineMonotonicMs }
                mark(.selection)
                if ticket.policy.selectionCapture == true, let selected = provider.readSelection(maxUnits: min(remaining, ticket.policy.maxTextCodeUnits)) {
                    result.selection = selected
                }
                remaining = max(0, 8192 - provider.actualTextReadUnits - (ticket.policy.inputText == true ? 2048 : 0))
                if surfaceRequested, let scope = ticket.policy.captureScope {
                    if clock.monotonicMs < optionalDeadline {
                        surfaceAttempted = true
                        mark(.surface)
                        if let tree = provider.readSurface(scope: scope, maxNodes: ticket.policy.maxTreeNodes ?? 64, maxText: min(remaining, ticket.policy.maxTextCodeUnits)) {
                            pendingSurface = tree
                            remaining -= provider.surfaceReadUnits
                        } else { result.surfaceFailure = provider.surfaceFailure ?? .providerUnavailable }
                    } else { provider.noteSurfaceFailure(.notStartedBudget); result.surfaceFailure = .notStartedBudget }
                }
            } else if surfaceRequested { provider.noteSurfaceFailure(.notStartedBudget); result.surfaceFailure = .notStartedBudget }
        }
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else {
            if pendingSurface != nil { provider.noteSurfaceFailure(.boundaryIncomplete) }
            return failure("stale", .readDeadline)
        }
        if surfaceRequested && pendingSurface == nil {
            result.surfaceFailure = provider.surfaceFailure ?? .notStartedBudget
        }
        mark(.finalField)
        let sameFocus = surfaceAttempted
            ? provider.remainsSameFocusAndWindow(onBoundaryFailure: { provider.noteSurfaceFailure($0) })
            : provider.remainsSameFocusAndWindow()
        var finalRoleFailure: SurfaceReadFailure?
        let finalRole = surfaceAttempted
            ? provider.finalSurfaceRole(onBoundaryFailure: { finalRoleFailure = $0 })
            : provider.role()
        if surfaceAttempted && finalRole == "AXSecureTextField" { provider.noteSurfaceFailure(.securityExcluded) }
        if surfaceAttempted && finalRole != focusRole {
            // A missing role isn't a positive contradiction. Only use its typed
            // cause when this comparison actually rejected the candidate.
            if let finalRole, let focusRole, !finalRole.isEmpty, !focusRole.isEmpty {
                provider.noteSurfaceFailure(.boundaryMismatch)
            } else {
                provider.noteSurfaceFailure(finalRoleFailure ?? .boundaryUnverified)
            }
        }
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline) }
        guard sameFocus, finalRole == focusRole else { return failure("stale", .focusChanged) }
        let finalSecurity = surfaceAttempted && textFocus
            ? provider.finalSurfaceSecurity(onBoundaryFailure: { provider.noteSurfaceFailure($0) })
            : provider.secureStatus()
        if surfaceAttempted {
            if finalSecurity == .sensitive { provider.noteSurfaceFailure(.securityExcluded) }
            else if textFocus && !ticket.policy.allows(finalSecurity) { provider.noteSurfaceFailure(.boundaryUnverified) }
        }
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline) }
        guard finalSecurity != .sensitive, !textFocus || ticket.policy.allows(finalSecurity) else {
            return failure("stale", finalSecurity == .sensitive ? .secureField : .fieldSecurityUnknown)
        }
        mark(.finalDesktop)
        guard desktopReadable() else { return failure(secureInputDetected ? "secure-input-active" : "desktop-unavailable", .desktopUnavailable) }
        guard !WorkerProgress.withValue(api: 17, { IsSecureEventInputEnabled() }) else { suppressSecureInput(); return failure("secure-input-active", .secureField) }
        guard WorkerProgress.withValue(api: 16, { AXIsProcessTrusted() }) else { return failure("permission-denied", .accessibilityDenied) }
        guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline) }
        let frozen = identity!
        currentInputContext = InputTextContext(target: InputTextTarget(application: app, deviceId: ticket.deviceId, osSessionId: ticket.osSessionId, desktopId: ticket.desktopId, windowId: frozen.windowId, windowGeneration: frozen.windowGeneration), surfaceId: frozen.surfaceId, captureEpoch: ticket.captureEpoch,
            foregroundGeneration: (ticket.foregroundGeneration ?? 0) + (changed ? 1 : 0), focusGeneration: (ticket.focusGeneration ?? 0) + (changed ? 1 : 0), policyRevision: ticket.policyRevision,
            privateState: provider.privateState == "user-authorized" ? .userAuthorized : .normal, fieldSecurity: ticket.policy.fieldSecurityMode)
        inputContextEstablishedNanoseconds = DispatchTime.now().uptimeNanoseconds
        if ticket.policy.inputText == true { traceInput(.contextEstablish, .accepted, role: focusRole.flatMap { InputTextFieldRole(rawValue: $0) }) }
        if ticket.policy.inputText == true, !inputAttempted {
            mark(.inputBegin)
            let capture = InputTextCapture(policy: ticket.policy, safetyProvider: { [weak self] in self?.safety($0) ?? .failure(.stale) })
            capture.debugReadId = debugReadId
            capture.gap = { [weak self] reason in
                guard let self else { return }; self.dirty = true
                if self.inputGaps.count < 4 { self.inputGaps.append(reason.rawValue) }
            }
            capture.disabled = { [weak self] reason in self?.inputFailure = reason; self?.dirty = true }
            capture.secureInput = { [weak self] in self?.suppressSecureInput() }
            capture.submitTrigger = { [weak self] in
                guard let self, !self.secureInputDetected else { return }
                self.submitDirty = true
            }
            if capture.begin() { input = capture; inputAttempted = true }
            else if capture.reason == "secure-input-active" { suppressSecureInput() }
            else { inputAttempted = true; inputFailure = capture.reason }
        }
        if let inputFailure { return failure(inputFailure) }
        mark(.inputDrain)
        let pending = input?.drainPending() ?? []
        guard !secureInputDetected else { return failure("secure-input-active", .secureField) }
        guard provider.actualTextReadUnits <= 8192 else { return failure("read-error", .textResultInvalid) }
        remaining = max(0, 8192 - provider.actualTextReadUnits)
        result.inputRecords = pending.filter { record in
            guard record.text.utf16.count <= remaining else { if inputGaps.count < 4 { inputGaps.append("budget") }; return false }
            remaining -= record.text.utf16.count; return true
        }
        if let pendingSurface {
            guard let prepared = prepareSurface(pendingSurface, focus: field) else { return failure("read-error", .textResultInvalid) }
            // Stable-ID allocation is local and bounded, but it may still cross
            // the ticket cutoff. Never advance a baseline for a late candidate.
            guard clock.monotonicMs < ticket.deadlineMonotonicMs else { return failure("stale", .readDeadline) }
            result.surface = commitSurface(pendingSurface, prepared: prepared, surfaceId: identity!.surfaceId,
                scope: ticket.policy.captureScope!)
        }
        result.inputGaps = inputGaps; inputGaps.removeAll()
        result.captureEndMs = max(started, clock.unixMs)
        return result
    }
    deinit { input?.end(); removeObserver(forProcessExit: retiringForProcessExit); enablement.release() }
}

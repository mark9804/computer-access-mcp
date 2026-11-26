import Foundation
import Darwin
import MachO
import HistoryContract
import CollectorCore

public enum CollectorCLI {
    private static func resolveExecutablePath() -> String {
        var size: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &size)
        if size > 0 {
            var buffer = [CChar](repeating: 0, count: Int(size))
            if _NSGetExecutablePath(&buffer, &size) == 0 {
                let path = buffer.withUnsafeBufferPointer { ptr -> String in
                    guard let base = ptr.baseAddress else { return "" }
                    return String(cString: base)
                }
                if !path.isEmpty {
                    return URL(fileURLWithPath: path).standardizedFileURL.path
                }
            }
        }
        return URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.path
    }

    public static func run() -> Int32 {
        signal(SIGPIPE, SIG_IGN)
        let arguments = Array(CommandLine.arguments.dropFirst())
        if SourceNavigationRequest.acceptsArguments(arguments) { return runSourceNavigation() }
        if let action = PermissionAction.parse(arguments) { return runPermissionAction(action) }
        guard let options = CLIOptions.parse(arguments) else { return 64 }
        if options.worker { return runWorker(options) }
        guard let validator = try? ContractValidator() else { return 70 }
        let output = BoundedOutput(validator: validator)
        let clock = SystemCollectorClock()
        let binary = resolveExecutablePath()
        let worker = WorkerManager(executable: binary, fixture: options.fixture, scenario: options.scenario)
        let environment = NativeEnvironment(fixture: options.fixture, scenario: options.scenario, worker: worker)

    output.enqueue(CollectorEngine.helloMessage(instanceId: options.instance, fixture: options.fixture))

    let ownerLock: OwnerLock
    do { ownerLock = try OwnerLock(fixture: options.fixture, fixtureLockId: options.fixtureLock) }
    catch { return 73 }
    defer { ownerLock.release() }

    let engine = CollectorEngine(
        ownerId: options.owner,
        instanceId: options.instance,
        deviceId: options.device,
        osSessionId: ownerLock.sessionId,
        desktopId: options.fixture ? "fixture-desktop" : "console-\(ownerLock.sessionId)",
        fixture: options.fixture,
        environment: environment,
        clock: clock,
        validator: validator
    )
    engine.emit = { output.enqueue($0) }
    engine.discardQueuedObservations = { output.discardObservations() }
    environment.desktopEvent = { engine.desktopChanged($0, accessibility: $1) }
    environment.secureInputEvent = { engine.secureInputDetected() }
    environment.applicationEvent = { engine.applicationEvent($0) }
    environment.excludedApplicationEvent = { engine.excludedApplicationEvent() }
    environment.inputActivityEvent = { engine.inputActivity($0) }
    environment.inputActivityInvalidated = { engine.clearInputActivity() }
    environment.inputActivityDisabled = { engine.inputActivityUnavailable($0) }
    worker.completed = { engine.complete($0) }
    worker.dirty = { engine.workerDirty() }
    worker.submitDirty = { engine.workerSubmitDirty() }
    worker.menuAction = { engine.menuAction($0) }
    worker.menuTracking = { engine.workerMenuTracking($0) }
    worker.readDeadlineReached = { engine.workerReadDeadlineReached($0) }
    worker.inputDisabled = { engine.inputSessionUnavailable($0) }
    worker.secureInput = { engine.secureInputDetected() }

    let input = InputFrames(validator)
    let parent = getppid()
    guard parent > 1 else { engine.stop("parent-death"); return 70 }

    var signalSources: [DispatchSourceSignal] = []
    for number in [SIGTERM, SIGINT, SIGHUP] {
        signal(number, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
        source.setEventHandler { engine.stop("signal") }
        source.resume()
        signalSources.append(source)
    }
    defer {
        for source in signalSources { source.cancel() }
        environment.cancelRead()
        environment.endMonitoring()
    }

    let timer = DispatchSource.makeTimerSource(queue: .main)
    var exitAt: Int64?
    timer.schedule(deadline: .now(), repeating: .milliseconds(10), leeway: .milliseconds(2))
    timer.setEventHandler {
        if !engine.shouldExit {
            if getppid() != parent { engine.stop("parent-death") }
            let alive = input.drain { result in
                switch result {
                case .valid(let message):
                    if message["type"] == .string("configure"),
                       let max = message["policy"]?["maxPending"]?.numberValue {
                        output.maxPending = Int(max)
                    }
                    engine.receive(message)
                case .invalid(let error):
                    engine.failure(error.code)
                }
            }
            if !alive { engine.stop("owner-eof") }
            engine.tick(parentAlive: getppid() == parent)
            if !engine.shouldExit { environment.poll() }
        }
        output.flush()
        if output.failed { engine.stop("stdout-backpressure") }
        if engine.shouldExit {
            if exitAt == nil { exitAt = clock.monotonicMs + 250 }
            if output.empty || output.failed || clock.monotonicMs >= exitAt! {
                CFRunLoopStop(CFRunLoopGetMain())
            }
        }
    }
    timer.resume()
    CFRunLoopRun()
    timer.cancel()
    return output.failed ? 74 : 0
    }
}

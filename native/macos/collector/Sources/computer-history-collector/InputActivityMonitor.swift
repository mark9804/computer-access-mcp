import Foundation
import AppKit
import CoreGraphics
import Carbon
import CollectorCore

/// Opt-in passive listener. Constructing this object performs no OS inspection.
/// CGEvent objects never escape the synchronous callback and are never serialized.
final class InputActivityMonitor {
    private let policy: CapturePolicy
    private let desktopUnlocked: () -> Bool
    private let clock = SystemCollectorClock()
    private var tap: CFMachPort?
    private var source: CFRunLoopSource?
    private var active = false
    private var acceptAfterNanoseconds: UInt64 = 0
    private(set) var reason = "input-monitoring-unavailable"
    var sample: (InputActivitySample) -> Void = { _ in }
    var invalidated: () -> Void = {}
    var disabled: (String) -> Void = { _ in }
    var secureInput: () -> Void = {}
    var isHealthy: Bool {
        guard active, let tap else { return false }
        return CFMachPortIsValid(tap) && CGEvent.tapIsEnabled(tap: tap)
    }
    private func secureInputActive() -> Bool {
        guard IsSecureEventInputEnabled() else { return false }
        invalidateEpoch(); invalidated(); secureInput(); return true
    }

    init(policy: CapturePolicy, desktopUnlocked: @escaping () -> Bool) {
        self.policy = policy; self.desktopUnlocked = desktopUnlocked
    }
    func begin() -> Bool {
        end()
        guard policy.enabled, policy.inputActivity == true else { return false }
        guard CGPreflightListenEventAccess() else { CollectorDebugTrace.record("input-activity-permission", stack: true); reason = "input-monitoring-required"; return false }
        guard !IsSecureEventInputEnabled() else { reason = "secure-input-active"; return false }
        guard desktopUnlocked() else { return false }
        let types: [CGEventType] = [.leftMouseUp, .rightMouseUp, .otherMouseUp,
            .leftMouseDragged, .rightMouseDragged, .otherMouseDragged, .scrollWheel, .keyDown]
        let mask = types.reduce(CGEventMask(0)) { $0 | (CGEventMask(1) << $1.rawValue) }
        guard let created = CGEvent.tapCreate(tap: .cgAnnotatedSessionEventTap, place: .tailAppendEventTap,
            options: .listenOnly, eventsOfInterest: mask, callback: { _, type, event, context in
                if let context {
                    Unmanaged<InputActivityMonitor>.fromOpaque(context).takeUnretainedValue().receive(type, event)
                }
                // A listen-only tap never changes, consumes, posts or redirects an event.
                return Unmanaged.passUnretained(event)
            }, userInfo: Unmanaged.passUnretained(self).toOpaque()) else { CollectorDebugTrace.record("input-activity-tap-create", stack: true); return false }
        guard let runLoopSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, created, 0) else {
            CollectorDebugTrace.record("input-activity-source-create", stack: true)
            CFMachPortInvalidate(created); return false
        }
        tap = created; source = runLoopSource; active = true
        invalidateEpoch()
        CFRunLoopAddSource(CFRunLoopGetMain(), runLoopSource, .commonModes)
        guard CGEvent.tapIsEnabled(tap: created) else { end(); return false }
        return true
    }
    func end() {
        active = false
        if let tap { CGEvent.tapEnable(tap: tap, enable: false) }
        if let source { CFRunLoopRemoveSource(CFRunLoopGetMain(), source, .commonModes); CFRunLoopSourceInvalidate(source) }
        if let tap { CFMachPortInvalidate(tap) }
        source = nil; tap = nil
    }
    /// Native-only fence: a recent queued event cannot be relabeled into a newer epoch.
    /// This never calls invalidated(), so the engine's clear callback cannot recurse.
    func invalidateEpoch() { acceptAfterNanoseconds = DispatchTime.now().uptimeNanoseconds }
    private func fail(_ reason: String) {
        CollectorDebugTrace.record("input-activity-failed", flags: ["required": reason == "input-monitoring-required", "disabled": reason == "input-monitoring-disabled"], stack: true)
        self.reason = reason
        end(); invalidated(); disabled(reason)
    }
    /// Called by the control tick even if no input reaches the callback.
    func poll() {
        guard active, let tap else { return }
        if !CGEvent.tapIsEnabled(tap: tap) { fail("input-monitoring-disabled"); return }
        if !CGPreflightListenEventAccess() { fail("input-monitoring-required"); return }
        _ = secureInputActive()
    }
    private func foreground() -> ApplicationIdentity? {
        guard let app = NSWorkspace.shared.frontmostApplication,
              let identity = AXFieldProvider.identity(app),
              ApplicationPolicy.allows(identity.applicationId, policy: policy),
              AXFieldProvider.permittedApplication(app, policy: policy) else { return nil }
        return identity
    }
    /// Not a field-safety assertion: only global Secure Input + desktop + exact app metadata.
    func validate(application: ApplicationIdentity) -> Bool {
        guard active, let tap, CGEvent.tapIsEnabled(tap: tap) else { return false }
        guard CGPreflightListenEventAccess() else { fail("input-monitoring-required"); return false }
        guard !secureInputActive(), desktopUnlocked(),
              foreground() == application, !secureInputActive(), active else { invalidated(); return false }
        return true
    }
    private func receive(_ type: CGEventType, _ event: CGEvent) {
        if type == .tapDisabledByTimeout || type == .tapDisabledByUserInput {
            fail("input-monitoring-disabled"); return
        }
        guard active else { return }
        // Timestamp is inspected only to reject delayed/future callbacks. It is not retained.
        let nowNanos = DispatchTime.now().uptimeNanoseconds
        let timestamp = event.timestamp
        guard InputActivityFreshness.accepts(timestampNanoseconds: timestamp, nowNanoseconds: nowNanos, afterNanoseconds: acceptAfterNanoseconds) else { invalidated(); return }
        guard !secureInputActive(), desktopUnlocked(), active else { invalidated(); return }
        let targetPid = event.getIntegerValueField(.eventTargetUnixProcessID)
        guard targetPid > 1, targetPid <= Int64(Int32.max), let identity = foreground(),
              Int64(identity.processId) == targetPid else { invalidated(); return }
        let category: InputActivityCategory
        switch type {
        case .leftMouseUp, .rightMouseUp, .otherMouseUp: category = .pointerRelease
        case .leftMouseDragged, .rightMouseDragged, .otherMouseDragged: category = .dragSample
        case .scrollWheel: category = .scrollSample
        case .keyDown:
            // No keycode, Unicode, keyboard layout, location, deltas or event descriptions.
            let flags = event.flags
            guard flags.contains(.maskCommand) || flags.contains(.maskControl),
                  event.getIntegerValueField(.keyboardEventAutorepeat) == 0 else { return }
            category = .shortcutPress
        default: return
        }
        guard validate(application: identity) else { return }
        // Desktop and bundle metadata checks are synchronous, but not bounded OS calls.
        // Recheck age after them so a stalled callback never turns an old event into new activity.
        guard InputActivityFreshness.accepts(timestampNanoseconds: timestamp, nowNanoseconds: DispatchTime.now().uptimeNanoseconds, afterNanoseconds: acceptAfterNanoseconds) else { invalidated(); return }
        sample(InputActivitySample(application: identity, category: category, callbackTimeMs: clock.unixMs))
    }
}

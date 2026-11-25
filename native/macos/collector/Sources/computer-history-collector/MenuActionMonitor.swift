import Foundation
import CoreGraphics
import Carbon
import CollectorCore

/// Isolated worker-only passive CGEventTap used solely to distinguish commit
/// (left mouse release or Return/KP Enter) vs cancel (Escape) while an AXMenu
/// under the foreground app's top menu bar is open. Never reads coordinates,
/// Unicode strings, or arbitrary keycodes, and degrades silently if Input
/// Monitoring permission is absent.
final class MenuActionMonitor {
    private static let returnKeyCode: Int64 = 36
    private static let kpEnterKeyCode: Int64 = 76
    private static let escapeKeyCode: Int64 = 53

    private let isMenuOpen: () -> Bool
    private let onCommit: () -> Void
    private let onCancel: () -> Void
    private let onSecureInput: () -> Void

    private var tap: CFMachPort?
    private var source: CFRunLoopSource?
    private var runLoop: CFRunLoop?
    private var active = false
    private var secureInputBlocked = false
    private var acceptAfterNanoseconds: UInt64 = 0

    var isActive: Bool {
        guard active, !secureInputBlocked, let tap else { return false }
        return CFMachPortIsValid(tap) && CGEvent.tapIsEnabled(tap: tap)
    }

    init(
        isMenuOpen: @escaping () -> Bool,
        onCommit: @escaping () -> Void,
        onCancel: @escaping () -> Void,
        onSecureInput: @escaping () -> Void
    ) {
        self.isMenuOpen = isMenuOpen
        self.onCommit = onCommit
        self.onCancel = onCancel
        self.onSecureInput = onSecureInput
    }

    deinit { end() }

    @discardableResult
    func begin() -> Bool {
        guard !secureInputBlocked else { return false }
        if isActive { return true }
        end()
        // Degrade gracefully without prompting or pausing capture when Input Monitoring is absent.
        guard CGPreflightListenEventAccess() else { return false }
        guard !IsSecureEventInputEnabled() else {
            suppressSecureInput()
            return false
        }
        let mask = (CGEventMask(1) << CGEventType.leftMouseUp.rawValue) |
            (CGEventMask(1) << CGEventType.keyDown.rawValue)
        guard let created = CGEvent.tapCreate(
            tap: .cgAnnotatedSessionEventTap,
            place: .tailAppendEventTap,
            options: .listenOnly,
            eventsOfInterest: mask,
            callback: { _, type, event, context in
                if let context {
                    Unmanaged<MenuActionMonitor>.fromOpaque(context).takeUnretainedValue().receive(type, event)
                }
                // Listen-only: never mutate, consume, inject, or retain the CGEvent.
                return Unmanaged.passUnretained(event)
            },
            userInfo: Unmanaged.passUnretained(self).toOpaque()
        ) else {
            return false
        }
        guard let createdSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, created, 0) else {
            CFMachPortInvalidate(created)
            return false
        }
        let current = CFRunLoopGetCurrent()
        tap = created
        source = createdSource
        runLoop = current
        active = true
        invalidate()
        CFRunLoopAddSource(current, createdSource, .commonModes)
        guard CGEvent.tapIsEnabled(tap: created) else {
            end()
            return false
        }
        return true
    }

    func end() {
        active = false
        if let tap { CGEvent.tapEnable(tap: tap, enable: false) }
        if let source, let runLoop {
            CFRunLoopRemoveSource(runLoop, source, .commonModes)
            CFRunLoopSourceInvalidate(source)
        }
        if let tap { CFMachPortInvalidate(tap) }
        tap = nil
        source = nil
        runLoop = nil
    }

    func invalidate() {
        acceptAfterNanoseconds = DispatchTime.now().uptimeNanoseconds
    }

    func suppressSecureInput() {
        end()
        if !secureInputBlocked {
            secureInputBlocked = true
            onSecureInput()
        }
    }

    func poll() {
        guard active else { return }
        if IsSecureEventInputEnabled() {
            suppressSecureInput()
            return
        }
        guard let tap, CFMachPortIsValid(tap), CGEvent.tapIsEnabled(tap: tap),
              CGPreflightListenEventAccess() else {
            // Stay dormant without faulting the collector.
            end()
            return
        }
    }

    private func receive(_ type: CGEventType, _ event: CGEvent) {
        guard active, !secureInputBlocked else { return }
        if type == .tapDisabledByUserInput {
            end()
            return
        }
        if type == .tapDisabledByTimeout {
            if let tap, CFMachPortIsValid(tap), CGPreflightListenEventAccess(), !IsSecureEventInputEnabled() {
                CGEvent.tapEnable(tap: tap, enable: true)
                if !CGEvent.tapIsEnabled(tap: tap) { end() }
            } else {
                end()
            }
            return
        }
        // Fast path: do not inspect event fields when no top-menu-bar menu is open.
        guard isMenuOpen() else { return }
        if IsSecureEventInputEnabled() {
            suppressSecureInput()
            return
        }
        let nowNanos = DispatchTime.now().uptimeNanoseconds
        let timestamp = event.timestamp
        guard InputActivityFreshness.accepts(
            timestampNanoseconds: timestamp,
            nowNanoseconds: nowNanos,
            afterNanoseconds: acceptAfterNanoseconds
        ) else {
            return
        }
        switch type {
        case .leftMouseUp:
            onCommit()
        case .keyDown:
            switch event.getIntegerValueField(.keyboardEventKeycode) {
            case Self.returnKeyCode, Self.kpEnterKeyCode:
                onCommit()
            case Self.escapeKeyCode:
                onCancel()
            default:
                break
            }
        default:
            break
        }
    }
}

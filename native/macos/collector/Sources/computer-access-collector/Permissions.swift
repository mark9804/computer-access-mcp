import Foundation
import AppKit
import ApplicationServices
import CollectorCore

private struct InputMonitoringPermission: Encodable {
    let state: String
    let promptRequested: Bool
    let settingsOpened: Bool
}
private struct PermissionResponse: Encodable {
    let version = 1
    let action: PermissionAction
    let accessibility: String
    let desktop: DesktopAssessment
    let screenRecording = "not-required"
    let promptRequested: Bool
    let settingsOpened: Bool
    let captured = false
    let inputMonitoring: InputMonitoringPermission
}

/// Only reached by the dedicated owner-initiated Host endpoint. No monitor,
/// owner lock, worker, AX value, screenshot or Keychain operation is created.
func runPermissionAction(_ action: PermissionAction) -> Int32 {
    let prompt = action == .requestAccessibility
    let trusted: Bool
    if prompt {
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        // A request is asynchronous. A false return is NOT a failed request or
        // proof that the user denied; UI must offer an explicit check afterwards.
        trusted = AXIsProcessTrustedWithOptions(options)
    } else {
        trusted = AXIsProcessTrusted()
    }
    var opened = false
    if action == .openAccessibilitySettings {
        opened = NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")!)
    }
    let inputPrompt = action == .requestInputMonitoring
    // Independent Input Monitoring grant. No event tap is created by onboarding.
    if inputPrompt { _ = CGRequestListenEventAccess() }
    var inputSettingsOpened = false
    if action == .openInputMonitoringSettings {
        inputSettingsOpened = NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent")!)
    }
    let input = InputMonitoringPermission(state: CGPreflightListenEventAccess() ? "granted" : "not-granted",
        promptRequested: inputPrompt, settingsOpened: inputSettingsOpened)
    let response = PermissionResponse(action: action, accessibility: trusted ? "granted" : "not-granted",
        desktop: desktopAssessment(), promptRequested: prompt, settingsOpened: opened, inputMonitoring: input)
    guard var data = try? JSONEncoder().encode(response), data.count < 4096 else { return 70 }
    data.append(10)
    FileHandle.standardOutput.write(data)
    return 0
}

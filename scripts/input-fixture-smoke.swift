import AppKit
import ApplicationServices
import CoreGraphics
import Foundation

// Explicit test-only mutation of our exact synthetic fixture. Never user apps,
// content reads, clipboard, permission prompts, global key posting or files.
guard CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--authorized-synthetic-input",
      ["selection", "input"].contains(CommandLine.arguments[2]) else { exit(64) }
let mode = CommandLine.arguments[2]
let expected = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("native-bin/Computer History Fixture.app").standardizedFileURL
let executable = expected.appendingPathComponent("Contents/MacOS/computer-history-fixture")
func exactFixture(_ candidate: NSRunningApplication) -> Bool {
    candidate.bundleIdentifier == "com.dsh.computer-history.fixture" && candidate.bundleURL?.standardizedFileURL == expected && expected.resolvingSymlinksInPath() == expected
        && candidate.executableURL?.standardizedFileURL == executable && executable.resolvingSymlinksInPath() == executable && !candidate.isTerminated
}
let apps = NSRunningApplication.runningApplications(withBundleIdentifier: "com.dsh.computer-history.fixture")
guard AXIsProcessTrusted(), apps.count == 1, let app = apps.first, let birth = app.launchDate,
      exactFixture(app),
      NSWorkspace.shared.frontmostApplication?.processIdentifier == app.processIdentifier else { exit(65) }
func current() -> Bool {
    let live = NSRunningApplication.runningApplications(withBundleIdentifier: "com.dsh.computer-history.fixture")
    return live.count == 1 && live[0].processIdentifier == app.processIdentifier && live[0].launchDate == birth && exactFixture(live[0])
      && NSWorkspace.shared.frontmostApplication?.processIdentifier == app.processIdentifier
}
let root = AXUIElementCreateApplication(app.processIdentifier)
AXUIElementSetMessagingTimeout(root, 0.2)
func attribute(_ element: AXUIElement, _ name: String) -> CFTypeRef? {
    guard [kAXFocusedUIElementAttribute, kAXRoleAttribute, kAXSubroleAttribute, kAXWindowAttribute, kAXFocusedWindowAttribute].contains(name), current() else { return nil }
    var pid: pid_t = 0
    guard AXUIElementGetPid(element, &pid) == .success, pid == app.processIdentifier else { return nil }
    var value: CFTypeRef?
    return AXUIElementCopyAttributeValue(element, name as CFString, &value) == .success ? value : nil
}
guard let raw = attribute(root, kAXFocusedUIElementAttribute), CFGetTypeID(raw) == AXUIElementGetTypeID() else { exit(66) }
let field = raw as! AXUIElement
AXUIElementSetMessagingTimeout(field, 0.2)
guard attribute(field, kAXRoleAttribute) as? String == "AXTextField",
      let appWindow = attribute(root, kAXFocusedWindowAttribute), let fieldWindow = attribute(field, kAXWindowAttribute), CFEqual(appWindow, fieldWindow) else { exit(67) }
var subrole: CFTypeRef?
let subroleStatus = AXUIElementCopyAttributeValue(field, kAXSubroleAttribute as CFString, &subrole)
guard subroleStatus == .attributeUnsupported || (subroleStatus == .success && subrole as? String == "AXStandardTextField") else { exit(68) }
if mode == "selection" {
    // This test's preparation command has already set the fixed synthetic text.
    var range = CFRange(location: 0, length: 2)
    guard current(), let latest = attribute(root, kAXFocusedUIElementAttribute), CFEqual(latest, field),
          let latestWindow = attribute(root, kAXFocusedWindowAttribute), CFEqual(latestWindow, appWindow),
          let value = AXValueCreate(.cfRange, &range), AXUIElementSetAttributeValue(field, kAXSelectedTextRangeAttribute as CFString, value) == .success else { exit(69) }
} else {
    guard CGPreflightPostEventAccess() else { exit(77) }
    // One explicitly synthetic Unicode event, not a physical-typing or IME test.
    // Avoid a long multi-event injection while the user can change focus.
    let text = Array("P4-SYNTHETIC".utf16)
    guard current() else { exit(71) }
    guard let sameFocus = attribute(root, kAXFocusedUIElementAttribute), CFEqual(field, sameFocus) else { exit(72) }
    guard let down = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: true),
          let up = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: false) else { exit(73) }
    down.flags = []; up.flags = []
    down.setIntegerValueField(.eventTargetUnixProcessID, value: Int64(app.processIdentifier))
    up.setIntegerValueField(.eventTargetUnixProcessID, value: Int64(app.processIdentifier))
    text.withUnsafeBufferPointer { units in
        down.keyboardSetUnicodeString(stringLength: units.count, unicodeString: units.baseAddress!)
        up.keyboardSetUnicodeString(stringLength: units.count, unicodeString: units.baseAddress!)
    }
    guard current() else { exit(74) }
    guard let latest = attribute(root, kAXFocusedUIElementAttribute), CFEqual(latest, field) else { exit(75) }
    guard let latestWindow = attribute(root, kAXFocusedWindowAttribute), CFEqual(latestWindow, appWindow) else { exit(76) }
    down.postToPid(app.processIdentifier); up.postToPid(app.processIdentifier)
}
print("synthetic-\(mode)-dispatched")

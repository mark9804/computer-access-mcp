import AppKit
import ApplicationServices
import Foundation

// Explicit, user-authorized synthetic GUI setup only. No permission prompt, AX
// text read, external app traversal, input events, clipboard, watcher or log file.
// visible/async press a fixture-owned preparation button once; the fixture alone
// selects/scrolls its own document or schedules its synthetic update.
func refuse(_ code: String, _ status: Int32) -> Never {
    print(code)
    exit(status)
}
let modes = ["plain", "empty", "secure", "visible", "async", "unmarked", "protected", "slow-tree"]
let withMetadata = CommandLine.arguments.count == 3 && CommandLine.arguments[2] == "--metadata"
guard (CommandLine.arguments.count == 2 || withMetadata), modes.contains(CommandLine.arguments[1]) else {
    refuse("fixture-prepare-invalid-mode", 64)
}
guard AXIsProcessTrusted() else { refuse("fixture-prepare-ax-required", 77) }
let mode = CommandLine.arguments[1]
let bundleID = "com.dsh.computer-access.fixture"
let expectedBundle = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    .appendingPathComponent("native-bin/Computer Access Fixture.app").standardizedFileURL
let expectedExecutable = expectedBundle.appendingPathComponent("Contents/MacOS/computer-access-fixture")
func exactFixture(_ app: NSRunningApplication) -> Bool {
    guard !app.isTerminated, app.processIdentifier > 1, app.bundleIdentifier == bundleID,
          let bundle = app.bundleURL?.standardizedFileURL,
          let executable = app.executableURL?.standardizedFileURL else { return false }
    return bundle == expectedBundle && bundle.resolvingSymlinksInPath() == expectedBundle
        && executable == expectedExecutable && executable.resolvingSymlinksInPath() == expectedExecutable
}
let apps = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
guard apps.count == 1, let app = apps.first, exactFixture(app), let launchDate = app.launchDate else {
    refuse("fixture-prepare-identity-mismatch", 65)
}
func stillExactFixture() -> Bool {
    let current = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
    return current.count == 1 && current[0].processIdentifier == app.processIdentifier
        && current[0].launchDate == launchDate && exactFixture(current[0])
}
func owned(_ element: AXUIElement) -> Bool {
    var pid: pid_t = 0
    return AXUIElementGetPid(element, &pid) == .success && pid == app.processIdentifier
}
// Only structural metadata is readable. In particular, AXValue, selected text,
// names, titles and descriptions are never read by this preparation helper.
func metadata(_ element: AXUIElement, _ name: String) -> CFTypeRef? {
    let allowed = [kAXWindowsAttribute, kAXChildrenAttribute, kAXIdentifierAttribute,
                   kAXRoleAttribute, kAXSubroleAttribute, kAXFocusedUIElementAttribute, kAXFocusedWindowAttribute] as [String]
    guard allowed.contains(name), owned(element) else { return nil }
    var result: CFTypeRef?
    guard AXUIElementCopyAttributeValue(element, name as CFString, &result) == .success else { return nil }
    return result
}
let root = AXUIElementCreateApplication(app.processIdentifier)
AXUIElementSetMessagingTimeout(root, 0.25)
let fieldID: String
switch mode {
case "secure": fieldID = "fixture.secure"
case "empty": fieldID = "fixture.empty-editor"
case "visible", "unmarked", "protected", "slow-tree": fieldID = "fixture.readonly-text"
default: fieldID = "fixture.editor"
}
let buttonID = mode == "visible" ? "fixture.prepare-visible" : mode == "async" ? "fixture.prepare-async" : mode == "unmarked" ? "fixture.prepare-unmarked" : mode == "protected" ? "fixture.prepare-protected" : mode == "slow-tree" ? "fixture.prepare-slow-tree" : nil
let fieldRole = ["visible", "unmarked", "protected", "slow-tree"].contains(mode) ? "AXTextArea" : "AXTextField"
var queue = (metadata(root, kAXWindowsAttribute as String) as? [AXUIElement]) ?? []
// Some AppKit states report an empty AXWindows list while still exposing the
// exact focused window. Stay within this verified fixture PID; no global fallback.
if queue.isEmpty, let focused = metadata(root, kAXFocusedWindowAttribute as String), CFGetTypeID(focused) == AXUIElementGetTypeID() {
    queue = [focused as! AXUIElement]
}
var inspected = 0
var field: AXUIElement?
var button: AXUIElement?
let searchDeadline = ProcessInfo.processInfo.systemUptime + 3
while !queue.isEmpty && inspected < 128 && ProcessInfo.processInfo.systemUptime < searchDeadline {
    let element = queue.removeFirst()
    inspected += 1
    guard owned(element) else { refuse("fixture-prepare-element-identity", 65) }
    AXUIElementSetMessagingTimeout(element, 0.25)
    let identifier = metadata(element, kAXIdentifierAttribute as String) as? String
    if identifier == fieldID {
        guard field == nil, metadata(element, kAXRoleAttribute as String) as? String == fieldRole else {
            refuse("fixture-prepare-field-mismatch", 66)
        }
        field = element
    }
    if let buttonID, identifier == buttonID {
        guard button == nil, metadata(element, kAXRoleAttribute as String) as? String == "AXButton" else {
            refuse("fixture-prepare-button-mismatch", 66)
        }
        button = element
    }
    queue.append(contentsOf: ((metadata(element, kAXChildrenAttribute as String) as? [AXUIElement]) ?? []).prefix(32))
}
guard queue.isEmpty, let field else { refuse("fixture-prepare-field-unavailable", 66) }
guard stillExactFixture() else { refuse("fixture-prepare-identity-changed", 65) }
if buttonID != nil {
    guard let button else { refuse("fixture-prepare-button-unavailable", 66) }
    guard app.activate(options: [.activateIgnoringOtherApps]) else { refuse("fixture-prepare-activation-failed", 69) }
    guard stillExactFixture() && owned(button) && owned(field) else { refuse("fixture-prepare-identity-changed", 65) }
    // Never retry an AXPress: a failed/unknown response may already have acted.
    guard AXUIElementPerformAction(button, kAXPressAction as CFString) == .success else {
        refuse("fixture-prepare-press-failed", 68)
    }
} else {
    let subrole = metadata(field, kAXSubroleAttribute as String) as? String
    if mode == "secure" {
        guard subrole == "AXSecureTextField" else { refuse("fixture-prepare-secure-role-mismatch", 67) }
    } else {
        guard subrole != "AXSecureTextField" else { refuse("fixture-prepare-secure-role-mismatch", 67) }
        let synthetic = mode == "plain" ? "你好，合成测试 𠮷 smoke-1" : ""
        guard AXUIElementSetAttributeValue(field, kAXValueAttribute as CFString, synthetic as CFString) == .success else {
            refuse("fixture-prepare-value-failed", 68)
        }
    }
    guard app.activate(options: [.activateIgnoringOtherApps]) else { refuse("fixture-prepare-activation-failed", 69) }
    guard stillExactFixture() && owned(field) else { refuse("fixture-prepare-identity-changed", 65) }
    guard AXUIElementSetAttributeValue(field, kAXFocusedAttribute as CFString, kCFBooleanTrue) == .success else {
        refuse("fixture-prepare-focus-failed", 69)
    }
}
// Read-only structural confirmation, not a second setup action or text read.
let focusDeadline = ProcessInfo.processInfo.systemUptime + 1
repeat {
    guard stillExactFixture() else { refuse("fixture-prepare-identity-changed", 65) }
    if app.isActive,
       let raw = metadata(root, kAXFocusedUIElementAttribute as String),
       CFGetTypeID(raw) == AXUIElementGetTypeID() {
        let focused = raw as! AXUIElement
        if metadata(focused, kAXIdentifierAttribute as String) as? String == fieldID,
           metadata(focused, kAXRoleAttribute as String) as? String == fieldRole {
            if withMetadata {
                // Synthetic identity metadata only. Match the production native
                // process-start encoding; never print AX/provider content or paths.
                let metadata: [String: Any] = [
                    "marker": "fixture-prepared-\(mode)",
                    "processId": Int(app.processIdentifier),
                    "processStartTime": String(format: "unix-ms:%.3f", launchDate.timeIntervalSince1970 * 1000),
                ]
                guard let data = try? JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys]),
                      let json = String(data: data, encoding: .utf8) else {
                    refuse("fixture-prepare-metadata-failed", 70)
                }
                print(json)
            } else {
                print("fixture-prepared-\(mode)")
            }
            exit(0)
        }
    }
    RunLoop.current.run(until: Date().addingTimeInterval(0.02))
} while ProcessInfo.processInfo.systemUptime < focusDeadline
refuse("fixture-prepare-focus-unconfirmed", 69)

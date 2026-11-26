import AppKit
import Foundation
import VisibleTreeFixtureModel

// This branch exits before NSApplication.shared or any AppKit object creation.
// It requires no GUI/AX authorization and deliberately contains structure only.
if CommandLine.arguments.contains("--describe-visible-tree") {
    print(VisibleTreeFixture.structureDescription)
    exit(0)
}

// This fixture only owns synthetic controls. It does not observe other apps,
// create AX clients/event taps, read the clipboard, log entered text or write files.
// Running opens a GUI, so it requires a separate explicitly authorized manual test.
guard CommandLine.arguments.contains("--synthetic-fixture") else {
    FileHandle.standardError.write(Data("Refusing to launch: pass --synthetic-fixture for an explicitly authorized GUI test.\n".utf8))
    exit(64)
}

// Synthetic declaration variants; no secrets and no observation of other apps.
final class FieldSecurityFixtureTextView: NSTextView {
    var fieldSecurityVariant = "normal"
    override func accessibilitySubrole() -> NSAccessibility.Subrole? {
        fieldSecurityVariant == "normal" ? super.accessibilitySubrole() : NSAccessibility.Subrole(rawValue: "AXUnknown")
    }
    override func isAccessibilityProtectedContent() -> Bool { fieldSecurityVariant == "protected" }
}

final class SlowFixtureScrollView: NSScrollView {
    var delayChildren = false
    override func accessibilityChildren() -> [Any]? {
        if delayChildren { delayChildren = false; Thread.sleep(forTimeInterval: 1.2) }
        return super.accessibilityChildren()
    }
}

@MainActor
final class FixtureDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow!
    private var editor: NSTextField!
    private var second: NSTextField!
    private var status: NSTextField!
    private var readOnlyText: FieldSecurityFixtureTextView!
    private var readOnlyScroll: SlowFixtureScrollView!
    private var pendingAsync: DispatchWorkItem?
    private var changes = 0

    // Fixed public test data, never derived from another application or user input.
    private static let visiblePrefix = "FIXTURE-VISIBLE-PREFIX-314159"
    private static let visibleTail = "FIXTURE-VISIBLE-TAIL-271828"
    private static let asyncBefore = "异步合成测试 FIXTURE-ASYNC-BEFORE-161803"
    private static let asyncAfter = "异步合成测试 FIXTURE-ASYNC-AFTER-161803"
    private static var visibleDocument: String {
        (["0000 | \(visiblePrefix)"]
            + (1...240).map { String(format: "%04d | Synthetic read-only content line %04d.", $0, $0) }
            + ["0241 | \(visibleTail)"]).joined(separator: "\n")
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect: NSRect(x: 100, y: 100, width: 680, height: 600), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.minSize = NSSize(width: 680, height: 600)
        window.title = "Computer History — SYNTHETIC FIXTURE ONLY"
        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        root.translatesAutoresizingMaskIntoConstraints = false
        let content = window.contentView!
        content.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor), root.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            root.topAnchor.constraint(equalTo: content.topAnchor), root.bottomAnchor.constraint(lessThanOrEqualTo: content.bottomAnchor),
        ])
        root.addArrangedSubview(NSTextField(labelWithString: "Synthetic data only. Never paste real credentials or personal history."))
        editor = NSTextField(string: "你好 — synthetic editor")
        editor.setAccessibilityIdentifier("fixture.editor")
        editor.placeholderString = "CJK / paste / replace / undo test"
        editor.widthAnchor.constraint(equalToConstant: 620).isActive = true
        root.addArrangedSubview(editor)
        second = NSTextField(string: "")
        second.setAccessibilityIdentifier("fixture.empty-editor")
        second.placeholderString = "Empty editable field must remain observable"
        second.widthAnchor.constraint(equalToConstant: 620).isActive = true
        root.addArrangedSubview(second)
        let secure = NSSecureTextField(string: "SYNTHETIC-NOT-A-SECRET")
        secure.setAccessibilityIdentifier("fixture.secure")
        secure.widthAnchor.constraint(equalToConstant: 620).isActive = true
        root.addArrangedSubview(secure)
        let buttons = NSStackView()
        buttons.spacing = 8
        for (title, action) in [("Long tail 甲", #selector(longA)), ("Long tail 乙", #selector(longB)), ("Clear", #selector(clearText)), ("Async change", #selector(asyncChange)), ("New window", #selector(newWindow))] {
            buttons.addArrangedSubview(NSButton(title: title, target: self, action: action))
        }
        root.addArrangedSubview(buttons)
        root.addArrangedSubview(NSTextField(labelWithString: "Read-only, selectable synthetic document (visible-range test):"))
        readOnlyScroll = SlowFixtureScrollView(frame: NSRect(x: 0, y: 0, width: 620, height: 180))
        readOnlyScroll.hasVerticalScroller = true
        readOnlyScroll.hasHorizontalScroller = false
        readOnlyScroll.borderType = .bezelBorder
        readOnlyScroll.widthAnchor.constraint(equalToConstant: 620).isActive = true
        readOnlyScroll.heightAnchor.constraint(equalToConstant: 180).isActive = true
        readOnlyText = FieldSecurityFixtureTextView(frame: NSRect(origin: .zero, size: readOnlyScroll.contentSize))
        readOnlyText.isEditable = false
        readOnlyText.isSelectable = true
        readOnlyText.isRichText = false
        readOnlyText.isVerticallyResizable = true
        readOnlyText.isHorizontallyResizable = false
        readOnlyText.minSize = NSSize(width: 0, height: readOnlyScroll.contentSize.height)
        readOnlyText.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        readOnlyText.autoresizingMask = [.width]
        readOnlyText.textContainer?.widthTracksTextView = true
        readOnlyText.textContainer?.containerSize = NSSize(width: readOnlyScroll.contentSize.width, height: CGFloat.greatestFiniteMagnitude)
        readOnlyText.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        readOnlyText.textContainerInset = NSSize(width: 8, height: 8)
        readOnlyText.setAccessibilityIdentifier("fixture.readonly-text")
        readOnlyText.string = Self.visibleDocument
        readOnlyScroll.documentView = readOnlyText
        root.addArrangedSubview(readOnlyScroll)
        let preparations = NSStackView()
        preparations.spacing = 8
        let visibleButton = NSButton(title: "Prepare visible tail", target: self, action: #selector(prepareVisible))
        visibleButton.setAccessibilityIdentifier("fixture.prepare-visible")
        let asyncButton = NSButton(title: "Prepare async (2 seconds)", target: self, action: #selector(prepareAsync))
        asyncButton.setAccessibilityIdentifier("fixture.prepare-async")
        preparations.addArrangedSubview(visibleButton)
        preparations.addArrangedSubview(asyncButton)
        root.addArrangedSubview(preparations)
        let fieldPreparations = NSStackView()
        fieldPreparations.spacing = 8
        for (title, identifier, selector) in [("Unmarked field", "fixture.prepare-unmarked", #selector(prepareUnmarked)), ("Protected field", "fixture.prepare-protected", #selector(prepareProtected)), ("Slow tree", "fixture.prepare-slow-tree", #selector(prepareSlowTree))] {
            let button = NSButton(title: title, target: self, action: selector)
            button.setAccessibilityIdentifier(identifier)
            fieldPreparations.addArrangedSubview(button)
        }
        root.addArrangedSubview(fieldPreparations)
        status = NSTextField(labelWithString: "Synthetic mutation count: 0")
        status.setAccessibilityIdentifier("fixture.mutation-count")
        root.addArrangedSubview(status)
        root.addArrangedSubview(NSTextField(labelWithString: "No collectors or system permission requests are installed by this fixture."))
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
    private func changed() { changes += 1; status.stringValue = "Synthetic mutation count: \(changes)" }
    private func cancelAsync() { pendingAsync?.cancel(); pendingAsync = nil }
    @objc private func longA() { cancelAsync(); editor.stringValue = String(repeating: "中", count: 160) + "甲"; changed() }
    @objc private func longB() { cancelAsync(); editor.stringValue = String(repeating: "中", count: 160) + "乙"; changed() }
    @objc private func clearText() { cancelAsync(); editor.stringValue = ""; changed() }
    @objc private func asyncChange() { prepareAsync() }
    @objc private func prepareVisible() {
        cancelAsync(); readOnlyScroll.delayChildren = false
        readOnlyText.fieldSecurityVariant = "normal"
        readOnlyText.string = Self.visibleDocument
        window.makeKeyAndOrderFront(nil)
        window.contentView?.layoutSubtreeIfNeeded()
        if let container = readOnlyText.textContainer { readOnlyText.layoutManager?.ensureLayout(for: container) }
        // The fixture changes only its own selection/viewport. No collector or
        // external-app scroll action is used to manufacture visible evidence.
        let tail = (readOnlyText.string as NSString).range(of: Self.visibleTail)
        window.makeFirstResponder(readOnlyText)
        readOnlyText.setSelectedRange(tail)
        readOnlyText.scrollRangeToVisible(tail)
        readOnlyScroll.reflectScrolledClipView(readOnlyScroll.contentView)
        changed()
    }
    private func prepareFieldVariant(_ variant: String) {
        cancelAsync(); readOnlyScroll.delayChildren = false
        readOnlyText.fieldSecurityVariant = variant
        readOnlyText.string = "FIELD-POLICY-SYNTHETIC 合成字段"
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(readOnlyText)
        readOnlyText.setSelectedRange(NSRange(location: 0, length: 5))
        changed()
    }
    @objc private func prepareUnmarked() { prepareFieldVariant("unmarked") }
    @objc private func prepareProtected() { prepareFieldVariant("protected") }
    @objc private func prepareSlowTree() { prepareFieldVariant("unmarked"); readOnlyScroll.delayChildren = true }
    @objc private func prepareAsync() {
        cancelAsync()
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(editor)
        editor.stringValue = Self.asyncBefore
        editor.currentEditor()?.string = Self.asyncBefore
        changed()
        let update = DispatchWorkItem { [weak self] in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.editor.stringValue = Self.asyncAfter
                self.editor.currentEditor()?.string = Self.asyncAfter
                self.changed()
                self.pendingAsync = nil
            }
        }
        pendingAsync = update
        DispatchQueue.main.asyncAfter(deadline: .now() + 2, execute: update)
    }
    @objc private func newWindow() {
        let new = NSWindow(contentRect: NSRect(x: 160, y: 160, width: 400, height: 160), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        new.isReleasedWhenClosed = false
        new.title = "Synthetic second window"
        let field = NSTextField(string: "Second target — synthetic only")
        field.setAccessibilityIdentifier("fixture.second-window-editor")
        field.frame = NSRect(x: 20, y: 60, width: 360, height: 24)
        new.contentView?.addSubview(field)
        new.makeKeyAndOrderFront(nil)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
let app = NSApplication.shared
let delegate: NSObject & NSApplicationDelegate = CommandLine.arguments.contains("--visible-tree-fixture")
    ? VisibleTreeFixtureDelegate() : FixtureDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()

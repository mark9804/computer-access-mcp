import AppKit
import VisibleTreeFixtureModel

// Public AppKit accessibility provider only. This file never creates AX clients,
// event taps, scroll actions, permission prompts or references to other apps.
final class VisibleTreeFixtureWindow: NSWindow {
    override func isAccessibilityProtectedContent() -> Bool { false }
}

final class VisibleTreeFixtureRootView: NSView {
    override func isAccessibilityElement() -> Bool { true }
    override func accessibilityRole() -> NSAccessibility.Role? { .group }
    override func accessibilitySubrole() -> NSAccessibility.Subrole? { NSAccessibility.Subrole(rawValue: "AXUnknown") }
    override func isAccessibilityProtectedContent() -> Bool { false }
    override func accessibilityWindow() -> Any? { window }
    override func accessibilityTopLevelUIElement() -> Any? { window }
    override func accessibilityChildren() -> [Any]? { subviews }
    override func accessibilityVisibleChildren() -> [Any]? { subviews }
}

final class VisibleTreeFixtureInput: NSTextField {
    // This subclass supplies its own AX facts, so make the synthetic focus
    // anchor's element/role explicit as well, rather than relying on AppKit.
    override func isAccessibilityElement() -> Bool { true }
    override func accessibilityRole() -> NSAccessibility.Role? { .textField }
    override func accessibilitySubrole() -> NSAccessibility.Subrole? { NSAccessibility.Subrole(rawValue: "AXUnknown") }
    override func isAccessibilityProtectedContent() -> Bool { false }
    override func accessibilityWindow() -> Any? { window }
    override func accessibilityTopLevelUIElement() -> Any? { window }
}

// These stable row/text objects are retained by their owning view. AXChildren
// and AXVisibleChildren return references to these same objects, not copies.
class VisibleTreeFixtureElement: NSAccessibilityElement {
    weak var owner: VisibleTreeFixtureListView?
    let rowIndex: Int

    init(owner: VisibleTreeFixtureListView, rowIndex: Int, role: NSAccessibility.Role, parent: Any) {
        self.owner = owner
        self.rowIndex = rowIndex
        super.init()
        setAccessibilityElement(true)
        setAccessibilityRole(role)
        setAccessibilitySubrole(NSAccessibility.Subrole(rawValue: "AXUnknown"))
        setAccessibilityParent(parent)
        setAccessibilityIdentifier("fixture.visible-tree.\(role.rawValue).\(rowIndex)")
    }

    override func accessibilityWindow() -> Any? { owner?.window }
    override func accessibilityTopLevelUIElement() -> Any? { owner?.window }
    override func isAccessibilityProtectedContent() -> Bool { false }
    override func isAccessibilityFocused() -> Bool { false }
    override func accessibilityFrame() -> NSRect {
        guard let owner, owner.window != nil else { return .zero }
        return NSAccessibility.screenRect(fromView: owner, rect: owner.rowFrame(rowIndex))
    }
}

final class VisibleTreeFixtureText: VisibleTreeFixtureElement {
    private var text: NSString { VisibleTreeFixture.text(forRow: rowIndex) as NSString }
    override func accessibilityValue() -> Any? { text }
    override func accessibilityNumberOfCharacters() -> Int { text.length }
    override func accessibilityVisibleCharacterRange() -> NSRange {
        NSRange(location: 0, length: VisibleTreeFixture.visibleRows.contains(rowIndex) ? text.length : 0)
    }
    override func accessibilityString(for range: NSRange) -> String? {
        let value = text
        guard range.location >= 0, range.length >= 0, range.location <= value.length,
              range.length <= value.length - range.location else { return nil }
        return value.substring(with: range)
    }
    override func accessibilityChildren() -> [Any]? { [] }
    override func accessibilityVisibleChildren() -> [Any]? { [] }
}

final class VisibleTreeFixtureRow: VisibleTreeFixtureElement {
    private lazy var textElement: VisibleTreeFixtureText? = {
        guard let owner else { return nil }
        return VisibleTreeFixtureText(owner: owner, rowIndex: rowIndex, role: .staticText, parent: self)
    }()
    override func accessibilityChildren() -> [Any]? { textElement.map { [$0] } ?? [] }
    override func accessibilityVisibleChildren() -> [Any]? {
        VisibleTreeFixture.visibleRows.contains(rowIndex) ? accessibilityChildren() : []
    }
}

final class VisibleTreeFixtureListView: NSView {
    private lazy var rows: [VisibleTreeFixtureRow] = (0..<VisibleTreeFixture.rowCount).map {
        VisibleTreeFixtureRow(owner: self, rowIndex: $0, role: .row, parent: self)
    }

    override var isFlipped: Bool { true }
    override func isAccessibilityElement() -> Bool { true }
    override func accessibilityRole() -> NSAccessibility.Role? { .list }
    override func accessibilitySubrole() -> NSAccessibility.Subrole? { NSAccessibility.Subrole(rawValue: "AXUnknown") }
    override func isAccessibilityProtectedContent() -> Bool { false }
    override func accessibilityWindow() -> Any? { window }
    override func accessibilityTopLevelUIElement() -> Any? { window }
    override func accessibilityChildren() -> [Any]? { rows }
    override func accessibilityVisibleChildren() -> [Any]? { Array(rows[VisibleTreeFixture.visibleRows]) }

    func rowFrame(_ index: Int) -> NSRect {
        NSRect(x: 0, y: CGFloat((index - VisibleTreeFixture.visibleRows.lowerBound) * VisibleTreeFixture.rowHeight),
               width: bounds.width, height: CGFloat(VisibleTreeFixture.rowHeight))
    }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.textBackgroundColor.setFill()
        dirtyRect.fill()
        let attributes: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedSystemFont(ofSize: 12, weight: .regular),
            .foregroundColor: NSColor.labelColor,
        ]
        for index in VisibleTreeFixture.visibleRows {
            let frame = rowFrame(index)
            if index.isMultiple(of: 2) {
                NSColor.quaternaryLabelColor.withAlphaComponent(0.08).setFill()
                frame.fill()
            }
            (VisibleTreeFixture.text(forRow: index) as NSString).draw(
                at: NSPoint(x: 8, y: frame.minY + 2), withAttributes: attributes
            )
        }
    }
}

final class VisibleTreeFixtureDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow!

    func applicationDidFinishLaunching(_ notification: Notification) {
        window = VisibleTreeFixtureWindow(
            contentRect: NSRect(x: 100, y: 100, width: 680, height: 572),
            styleMask: [.titled, .closable], backing: .buffered, defer: false
        )
        window.title = "SYNTHETIC ONLY — visible rows 480...503 of 1000"
        let root = VisibleTreeFixtureRootView(frame: NSRect(x: 0, y: 0, width: 680, height: 572))
        root.setAccessibilityIdentifier("fixture.visible-tree.root")
        window.contentView = root
        let input = VisibleTreeFixtureInput(string: "SYNTHETIC FOCUS INPUT — no private content")
        input.frame = NSRect(x: 20, y: 528, width: 640, height: 24)
        input.setAccessibilityIdentifier("fixture.visible-tree.input")
        root.addSubview(input)
        let list = VisibleTreeFixtureListView(frame: NSRect(
            x: 20, y: 20, width: 640,
            height: CGFloat(VisibleTreeFixture.visibleRows.count * VisibleTreeFixture.rowHeight)
        ))
        list.setAccessibilityIdentifier("fixture.visible-tree.list")
        root.addSubview(list)
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(input)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

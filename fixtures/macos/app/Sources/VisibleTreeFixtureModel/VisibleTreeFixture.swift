import Foundation

// Foundation-only constants shared by the GUI, --describe-visible-tree and tests.
// No NSApplication, AX client, permissions, environment inspection or user data.
public enum VisibleTreeFixture {
    public static let rowCount = 1_000
    public static let visibleRows = 480..<504
    public static let rowHeight = 20

    public static func text(forRow index: Int) -> String {
        precondition((0..<rowCount).contains(index))
        return String(format: "SYNTHETIC ROW %04d — visible-tree fixture.", index)
    }

    public static let structureDescription = """
    Synthetic visible-tree fixture (structure only; no GUI or AX client)
    launch opt-in: --synthetic-fixture --visible-tree-fixture
    window: one synthetic NSWindow, explicit non-protected declaration
      root: AXGroup, explicit window/top-level ownership
        input: AXTextField, initial focus, fixed synthetic text, non-protected
        list: AXList, explicit window/top-level ownership, non-protected
          AXChildren: 1000 stable sibling AXRow elements, indexes 0...999
          AXVisibleChildren: the same row objects at indexes 480...503 (24 rows)
          each row: one AXStaticText child with fixed synthetic row text
          row/text: explicit parent/window/top-level ownership, non-protected
    viewport: 24 rows x 20 points; no scrolling or actions to reveal other rows
    sampling distinction: head/tail child pages do not contain the visible middle
    coverage: visible children are a provider subset, not the complete child tree
    validation: description/model tests and compilation are not remote AX acceptance
    """
}

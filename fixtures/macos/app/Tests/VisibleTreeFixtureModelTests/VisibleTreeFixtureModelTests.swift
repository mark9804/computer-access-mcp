import Foundation
import VisibleTreeFixtureModel
import XCTest

final class VisibleTreeFixtureModelTests: XCTestCase {
    func testVisibleRowsAreSmallMiddleSubsetNotHeadOrTailPages() {
        let allRows = Array(0..<VisibleTreeFixture.rowCount)
        let visibleRows = Array(allRows[VisibleTreeFixture.visibleRows])
        XCTAssertEqual(allRows.count, 1_000)
        XCTAssertEqual(visibleRows, Array(480...503))
        XCTAssertEqual(visibleRows.count * VisibleTreeFixture.rowHeight, 480)
        let headAndTailPages = Array(allRows.prefix(4)) + Array(allRows.suffix(4))
        XCTAssertTrue(Set(visibleRows).isDisjoint(with: headAndTailPages))
        XCTAssertEqual(VisibleTreeFixture.text(forRow: visibleRows[0]), "SYNTHETIC ROW 0480 — visible-tree fixture.")
        XCTAssertEqual(VisibleTreeFixture.text(forRow: visibleRows[23]), "SYNTHETIC ROW 0503 — visible-tree fixture.")
    }

    func testStructureDescriptionDistinguishesVisibleSubsetFromCompleteTree() {
        let description = VisibleTreeFixture.structureDescription
        XCTAssertTrue(description.contains("--synthetic-fixture --visible-tree-fixture"))
        XCTAssertTrue(description.contains("AXChildren: 1000 stable sibling AXRow"))
        XCTAssertTrue(description.contains("AXVisibleChildren: the same row objects at indexes 480...503 (24 rows)"))
        XCTAssertTrue(description.contains("not the complete child tree"))
        XCTAssertTrue(description.contains("not remote AX acceptance"))
        XCTAssertFalse(description.contains("SYNTHETIC ROW 0480"), "A structure manifest must not dump row content")
    }
}

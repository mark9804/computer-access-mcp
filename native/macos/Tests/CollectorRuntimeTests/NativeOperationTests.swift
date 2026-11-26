import XCTest
import Foundation
import ApplicationServices
@testable import CollectorRuntime

final class NativeOperationTests: XCTestCase {
    func testFixedAttributeCodesDoNotExportUnknownNamesOrValues() {
        let names: [(String, Int64)] = [("AXManualAccessibility", 1), ("AXEnhancedUserInterface", 2),
            ("AXFocusedUIElement", 3), ("AXWindow", 5), ("AXTopLevelUIElement", 6), ("AXRole", 7),
            ("AXChildren", 10), ("AXStringForRange", 13), ("AXValue", 14), ("AXTextMarkerForIndex", 21),
            ("AXMainWindow", 24), ("AXMenuBar", 25), ("AXSelectedChildren", 26)]
        for (name, code) in names { XCTAssertEqual(NativeOperation.attribute(name as CFString), code) }
        XCTAssertEqual(NativeOperation.attribute("synthetic-secret-not-an-attribute" as CFString), 0)
    }
    func testAXAndValueDiagnosticsPreserveOriginalSingleCallResults() {
        var calls = 0
        for result: AXError in [.success, .cannotComplete, .attributeUnsupported] {
            XCTAssertEqual(WorkerProgress.withCall(api: 3, attribute: 1, { calls += 1; return result }), result)
        }
        XCTAssertEqual(calls, 3)
        let value = WorkerProgress.withValue(api: 15, { calls += 1; return false })
        XCTAssertFalse(value); XCTAssertEqual(calls, 4)
    }
}

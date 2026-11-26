import Foundation
import ApplicationServices

/// Fixed numeric diagnostics around the existing calls. No new queries, text,
/// handles or attribute names leave this process; unknown names map to zero.
/// These wrappers return the original status/value without granting authority.
enum NativeOperation {
    static func attribute(_ name: CFString) -> Int64 {
        switch name as String {
        case "AXManualAccessibility": return 1
        case "AXEnhancedUserInterface": return 2
        case "AXFocusedUIElement": return 3
        case "AXFocusedWindow": return 4
        case "AXMainWindow": return 24
        case "AXMenuBar": return 25
        case "AXSelectedChildren": return 26
        case "AXWindow": return 5
        case "AXTopLevelUIElement": return 6
        case "AXRole": return 7
        case "AXSubrole": return 8
        case "AXContainsProtectedContent": return 9
        case "AXChildren": return 10
        case "AXParent": return 11
        case "AXNumberOfCharacters": return 12
        case "AXStringForRange": return 13
        case "AXValue": return 14
        case "AXPosition": return 15
        case "AXSize": return 16
        case "AXEditable": return 17
        case "AXSelectedTextRange": return 18
        case "AXVisibleChildren", "AXVisibleCharacterRange": return 19
        case "AXTextMarkerForIndex", "AXStringForTextMarkerRange": return 21
        default: return 0
        }
    }
    static func setTimeout(_ element: AXUIElement, _ seconds: Float) -> AXError {
        WorkerProgress.withCall(api: 1) { AXUIElementSetMessagingTimeout(element, seconds) }
    }
    static func copyNames(_ element: AXUIElement, _ value: UnsafeMutablePointer<CFArray?>) -> AXError {
        WorkerProgress.withCall(api: 2) { AXUIElementCopyAttributeNames(element, value) }
    }
    static func copyValue(_ element: AXUIElement, _ name: CFString, _ value: UnsafeMutablePointer<CFTypeRef?>) -> AXError {
        WorkerProgress.withCall(api: 3, attribute: attribute(name)) { AXUIElementCopyAttributeValue(element, name, value) }
    }
    static func getPid(_ element: AXUIElement, _ value: UnsafeMutablePointer<pid_t>) -> AXError {
        WorkerProgress.withCall(api: 7) { AXUIElementGetPid(element, value) }
    }
    static func getCount(_ element: AXUIElement, _ name: CFString, _ value: UnsafeMutablePointer<CFIndex>) -> AXError {
        WorkerProgress.withCall(api: 8, attribute: attribute(name)) { AXUIElementGetAttributeValueCount(element, name, value) }
    }
    static func copyValues(_ element: AXUIElement, _ name: CFString, _ offset: CFIndex, _ count: CFIndex,
                           _ value: UnsafeMutablePointer<CFArray?>) -> AXError {
        WorkerProgress.withCall(api: 9, attribute: attribute(name)) { AXUIElementCopyAttributeValues(element, name, offset, count, value) }
    }
    static func parameterizedNames(_ element: AXUIElement, _ value: UnsafeMutablePointer<CFArray?>) -> AXError {
        WorkerProgress.withCall(api: 10) { AXUIElementCopyParameterizedAttributeNames(element, value) }
    }
    static func parameterizedValue(_ element: AXUIElement, _ name: CFString, _ parameter: CFTypeRef,
                                   _ value: UnsafeMutablePointer<CFTypeRef?>) -> AXError {
        WorkerProgress.withCall(api: 11, attribute: attribute(name)) { AXUIElementCopyParameterizedAttributeValue(element, name, parameter, value) }
    }
}

import Foundation
import ApplicationServices
import Darwin

/// Optional Accessibility SPI: all opaque markers remain worker-local CF values.
/// No raw marker bytes, full-document start/end range, attributed text, fallback
/// to AXValue, or marker serialization is ever used here.
final class TextMarkerBridge {
    private typealias TypeID = @convention(c) () -> CFTypeID
    private typealias CreateRange = @convention(c) (CFAllocator?, CFTypeRef, CFTypeRef) -> Unmanaged<CFTypeRef>?
    static let shared = TextMarkerBridge()
    private let markerType: TypeID?
    private let rangeType: TypeID?
    private let createRange: CreateRange?
    init() {
        let handle = dlopen("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices", RTLD_LAZY | RTLD_LOCAL)
        func symbol<T>(_ name: String, _ type: T.Type) -> T? {
            guard let handle, let address = dlsym(handle, name) else { return nil }
            return unsafeBitCast(address, to: type)
        }
        markerType = symbol("AXTextMarkerGetTypeID", TypeID.self)
        rangeType = symbol("AXTextMarkerRangeGetTypeID", TypeID.self)
        createRange = symbol("AXTextMarkerRangeCreate", CreateRange.self)
        // Framework remains loaded for the function pointers' entire process life.
    }
    var available: Bool { markerType != nil && rangeType != nil && createRange != nil }
    func string(field: AXUIElement, start: Int, length: Int, permit: () -> Bool, permitText: () -> Bool, received: (Int) -> Bool) -> String? {
        guard available, start >= 0, length >= 0, length <= 8192,
              start <= 9_007_199_254_740_991 - length, permit() else { return nil }
        var names: CFArray?
        guard NativeOperation.parameterizedNames(field, &names) == .success,
              let names = names as? [String], names.contains("AXTextMarkerForIndex"), names.contains("AXStringForTextMarkerRange") else { return nil }
        func marker(_ index: Int) -> CFTypeRef? {
            guard permit() else { return nil }
            var value: CFTypeRef?
            guard NativeOperation.parameterizedValue(field, "AXTextMarkerForIndex" as CFString, NSNumber(value: index), &value) == .success,
                  let value, CFGetTypeID(value) == markerType!() else { return nil }
            return value
        }
        // The maximum span is established by bounded UTF-16 indices BEFORE the
        // provider is asked for text. Providers lacking this route are unsupported.
        guard let first = marker(start), let last = marker(start + length),
              let range = createRange!(kCFAllocatorDefault, first, last)?.takeRetainedValue(),
              CFGetTypeID(range) == rangeType!(), permitText() else { return nil }
        var value: CFTypeRef?
        guard NativeOperation.parameterizedValue(field, "AXStringForTextMarkerRange" as CFString, range, &value) == .success,
              let text = value as? String, received(text.utf16.count), text.utf16.count <= length else { return nil }
        return text
    }
}

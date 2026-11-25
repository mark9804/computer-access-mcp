import Foundation
import HistoryContract

/// Window-relative AX points, not pixels, desktop coordinates or visibility proof.
public struct SurfaceBounds: Codable, Equatable, Sendable {
    public var x: Double
    public var y: Double
    public var width: Double
    public var height: Double
    public init(x: Double, y: Double, width: Double, height: Double) {
        self.x = x; self.y = y; self.width = width; self.height = height
    }
    public var isValid: Bool {
        x.isFinite && y.isFinite && abs(x) <= 1_000_000 && abs(y) <= 1_000_000 &&
            SurfaceWindowSize(width: width, height: height).isValid
    }
    public var json: JSONValue {
        .object(["x": .number(x), "y": .number(y), "width": .number(width), "height": .number(height)])
    }
}
public struct SurfaceWindowSize: Codable, Equatable, Sendable {
    public var width: Double
    public var height: Double
    public init(width: Double, height: Double) { self.width = width; self.height = height }
    public var isValid: Bool {
        width.isFinite && height.isFinite && width >= 0 && height >= 0 && width <= 1_000_000 && height <= 1_000_000
    }
    public var json: JSONValue { .object(["width": .number(width), "height": .number(height)]) }
}
public struct SurfaceGeometry: Codable, Equatable, Sendable {
    public var coordinateSpace: String = "window-top-left-point"
    public var windowSize: SurfaceWindowSize
    public var observedAtMs: Int64
    public init(windowSize: SurfaceWindowSize, observedAtMs: Int64) {
        self.windowSize = windowSize; self.observedAtMs = observedAtMs
    }
    public var isValid: Bool { coordinateSpace == "window-top-left-point" && windowSize.isValid && observedAtMs >= 0 }
    public var json: JSONValue {
        .object(["coordinateSpace": .string(coordinateSpace), "windowSize": windowSize.json, "observedAtMs": .number(Double(observedAtMs))])
    }
}

/// Ephemeral AX rectangle. Deliberately NOT Codable: the absolute desktop origin
/// never crosses the worker boundary. AX position and size share top-left points.
public struct SurfaceAbsoluteRect: Equatable {
    public let x: Double
    public let y: Double
    public let width: Double
    public let height: Double
    public init?(x: Double, y: Double, width: Double, height: Double) {
        guard SurfaceBounds(x: x, y: y, width: width, height: height).isValid else { return nil }
        self.x = x; self.y = y; self.width = width; self.height = height
    }
    public func relative(to window: SurfaceAbsoluteRect) -> SurfaceBounds? {
        let bounds = SurfaceBounds(x: x - window.x, y: y - window.y, width: width, height: height)
        return bounds.isValid ? bounds : nil
    }
    /// Any observed move or resize invalidates the shared origin, without
    /// discarding independently validated text. No tolerance, clipping or Y flip.
    public func geometry(ifUnchanged final: SurfaceAbsoluteRect?, observedAtMs: Int64) -> SurfaceGeometry? {
        guard final == self, observedAtMs >= 0 else { return nil }
        return SurfaceGeometry(windowSize: .init(width: width, height: height), observedAtMs: observedAtMs)
    }
}

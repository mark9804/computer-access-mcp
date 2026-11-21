import Foundation
import AccessContract

public struct WorkerSurfaceIdentity: Codable, Equatable {
    public var sessionId: String
    public var windowId: String
    public var nodeId: String
    public var surfaceId: String
    public var windowGeneration: Int64
    public var focusGeneration: Int64

    public init(sessionId: String, windowId: String, nodeId: String, surfaceId: String, windowGeneration: Int64, focusGeneration: Int64) {
        self.sessionId = sessionId
        self.windowId = windowId
        self.nodeId = nodeId
        self.surfaceId = surfaceId
        self.windowGeneration = windowGeneration
        self.focusGeneration = focusGeneration
    }
}

public struct SurfaceNodeRead: Codable, Equatable {
    public var id: String
    public var parentId: String?
    public var role: String
    public var text: String?
    public var observedAtMs: Int64
    public var bounds: SurfaceBounds?
    public var boundsObservedAtMs: Int64?
    public var axRole: String?
    public var focused: Bool?

    public init(
        id: String,
        parentId: String? = nil,
        role: String,
        text: String? = nil,
        observedAtMs: Int64,
        bounds: SurfaceBounds? = nil,
        boundsObservedAtMs: Int64? = nil,
        axRole: String? = nil,
        focused: Bool? = nil
    ) {
        self.id = id
        self.parentId = parentId
        self.role = role
        self.text = text
        self.observedAtMs = observedAtMs
        self.bounds = bounds
        self.boundsObservedAtMs = boundsObservedAtMs
        self.axRole = axRole
        self.focused = focused
    }

    public var json: JSONValue {
        var value: [String: JSONValue] = ["id": .string(id), "role": .string(role), "observedAtMs": j(observedAtMs)]
        if let parentId { value["parentId"] = .string(parentId) }
        if let text { value["text"] = .string(text) }
        if let bounds { value["bounds"] = bounds.json }
        if let boundsObservedAtMs { value["boundsObservedAtMs"] = j(boundsObservedAtMs) }
        if let axRole { value["axRole"] = .string(axRole) }
        if let focused { value["focused"] = .bool(focused) }
        return .object(value)
    }
}

public struct SurfaceReadResult: Codable {
    public var surfaceId: String
    public var revision: Int64
    public var scope: String
    public var mode: String
    public var nodes: [SurfaceNodeRead]
    public var baseRevision: Int64?
    public var added: [String]
    public var updated: [String]
    public var removed: [String]
    public var truncated: Bool
    public var missingReasons: [String]
    public var complete: Bool
    public var geometry: SurfaceGeometry? = nil
}

public struct SelectionReadResult: Codable {
    public var text: String
    public var source: String
    public var rangeStart: Int
    public var truncated: Bool
    public var missingReasons: [String]

    public init(text: String, source: String, rangeStart: Int, truncated: Bool, missingReasons: [String]) {
        self.text = text
        self.source = source
        self.rangeStart = rangeStart
        self.truncated = truncated
        self.missingReasons = missingReasons
    }
}

/// Computes full vs diff surface snapshots against the immediately preceding complete baseline.
public final class SurfaceBaseline {
    private var prior: [String: SurfaceNodeRead]?
    private var surfaceId: String?
    private var revision: Int64 = 0
    private var priorGeometry: SurfaceGeometry?

    public init() {}

    public func reset() {
        prior = nil
        surfaceId = nil
        revision = 0
        priorGeometry = nil
    }

    public func snapshot(
        surfaceId: String,
        scope: String,
        nodes: [SurfaceNodeRead],
        complete: Bool,
        matchingKnown: Bool,
        truncated: Bool,
        missingReasons: [String],
        geometry: SurfaceGeometry? = nil
    ) -> SurfaceReadResult {
        if self.surfaceId != surfaceId {
            reset()
            self.surfaceId = surfaceId
        }
        let base = revision
        revision += 1
        let current = Dictionary(nodes.map { ($0.id, $0) }, uniquingKeysWith: { _, new in new })
        let complete = complete && !truncated && missingReasons.isEmpty
        let mayDiff = complete && matchingKnown && prior != nil
        let windowChanged = priorGeometry?.windowSize != geometry?.windowSize || priorGeometry?.coordinateSpace != geometry?.coordinateSpace
        var added: [String] = []
        var updated: [String] = []
        var removed: [String] = []
        if mayDiff, let prior {
            added = nodes.filter { prior[$0.id] == nil }.map(\.id)
            updated = nodes.filter { node in
                guard let old = prior[node.id] else { return false }
                return windowChanged || old.text != node.text || old.role != node.role || old.parentId != node.parentId ||
                    old.bounds != node.bounds || old.axRole != node.axRole || old.focused != node.focused
            }.map(\.id)
            removed = prior.keys.filter { current[$0] == nil }.sorted()
        }
        prior = complete && matchingKnown ? current : nil
        priorGeometry = prior == nil ? nil : geometry
        return SurfaceReadResult(
            surfaceId: surfaceId,
            revision: revision,
            scope: scope,
            mode: mayDiff ? "diff" : "full",
            nodes: nodes,
            baseRevision: mayDiff ? base : nil,
            added: added,
            updated: updated,
            removed: removed,
            truncated: truncated,
            missingReasons: missingReasons,
            complete: complete,
            geometry: geometry
        )
    }
}

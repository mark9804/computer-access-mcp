import Foundation
import ApplicationServices
import CollectorCore

typealias AXSurfaceCapture = AXSurfaceCaptureValue<AXUIElement>

struct AXSurfaceCaptureValue<Handle> {
    let nodes: [SurfaceNodeRead]
    let truncated: Bool
    let reasons: [String]
    let complete: Bool
    let geometry: SurfaceGeometry?
    let adapterId: String
    private let references: [(String, Handle)]

    init(
        nodes: [SurfaceNodeRead],
        truncated: Bool,
        reasons: [String],
        complete: Bool,
        geometry: SurfaceGeometry?,
        adapterId: String,
        references: [(String, Handle)]
    ) {
        self.nodes = nodes
        self.truncated = truncated
        self.reasons = reasons
        self.complete = complete
        self.geometry = geometry
        self.adapterId = adapterId
        self.references = references
    }

    var selectedHandles: [Handle] { references.map(\.1) }

    func materializeNodes(nodeID: (Handle) -> String?) -> [SurfaceNodeRead]? {
        guard nodes.count <= 96, references.count == nodes.count, Set(nodes.map(\.id)).count == nodes.count else { return nil }
        var seen = Set<String>()
        for (id, _) in references where !seen.insert(id).inserted { return nil }
        guard nodes.allSatisfy({ seen.contains($0.id) && ($0.parentId.map { seen.contains($0) } ?? true) }) else { return nil }
        var ids: [String: String] = [:]
        for (id, handle) in references {
            guard let stable = nodeID(handle) else { return nil }
            ids[id] = stable
        }
        guard Set(ids.values).count == ids.count else { return nil }
        var result: [SurfaceNodeRead] = []
        for var node in nodes {
            guard let id = ids[node.id] else { return nil }
            node.id = id
            if let parent = node.parentId {
                guard let parentID = ids[parent] else { return nil }
                node.parentId = parentID
            }
            result.append(node)
        }
        return result
    }
}

/// Bounded map translating AXUIElement handles to stable UUIDs within one session epoch.
struct AXSurfaceNodeMap<Handle> {
    private var entries: [(Handle, String)] = []
    private(set) var adapterId: String?
    private let equal: (Handle, Handle) -> Bool
    private let makeID: () -> String
    private let capacity = 192

    init(equal: @escaping (Handle, Handle) -> Bool, makeID: @escaping () -> String = { UUID().uuidString }) {
        self.equal = equal
        self.makeID = makeID
    }

    mutating func reset() {
        entries.removeAll()
        adapterId = nil
    }

    mutating func identifier(for handle: Handle) -> String? {
        if let known = entries.first(where: { equal($0.0, handle) }) { return known.1 }
        guard entries.count < capacity else { return nil }
        let value = makeID()
        entries.append((handle, value))
        return value
    }

    @discardableResult
    mutating func prepareCommit(adapterId: String, selecting handles: [Handle], pin: (Handle, String)?) -> Bool {
        var unseen: [Handle] = []
        for handle in handles where !entries.contains(where: { equal($0.0, handle) }) && !unseen.contains(where: { equal($0, handle) }) {
            unseen.append(handle)
        }
        let resetNeeded = self.adapterId != adapterId || entries.count + unseen.count > capacity
        if resetNeeded {
            entries.removeAll()
            if let pin { entries.append(pin) }
        }
        self.adapterId = adapterId
        return resetNeeded
    }
}

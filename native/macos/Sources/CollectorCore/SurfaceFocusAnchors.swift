public enum SurfaceFocusPathReason: String, Equatable {
    case budget
    case cycle
    case unavailable
}

public struct SurfaceFocusAnchor<Handle: Hashable> {
    public let handle: Handle
    public let metadata: WeightedSurfaceMetadata

    fileprivate init(handle: Handle, metadata: WeightedSurfaceMetadata) {
        self.handle = handle
        self.metadata = metadata
    }
}

/// Verified ancestor chain from root to focused element for traversal prioritization.
public struct SurfaceFocusAnchorPlan<Handle: Hashable> {
    public let nodes: [SurfaceFocusAnchor<Handle>]
    public let root: Handle
    public let focus: Handle
    public let work: Int
    public let probes: Int

    fileprivate init(nodes: [SurfaceFocusAnchor<Handle>], root: Handle, focus: Handle, work: Int, probes: Int) {
        self.nodes = nodes
        self.root = root
        self.focus = focus
        self.work = work
        self.probes = probes
    }
}

public struct SurfaceFocusAnchorResult<Handle: Hashable> {
    public let plan: SurfaceFocusAnchorPlan<Handle>?
    public let work: Int
    public let probes: Int
    public let reason: SurfaceFocusPathReason?

    fileprivate init(plan: SurfaceFocusAnchorPlan<Handle>?, work: Int, probes: Int, reason: SurfaceFocusPathReason?) {
        self.plan = plan
        self.work = work
        self.probes = probes
        self.reason = reason
    }
}

public enum SurfaceFocusAnchors {
    public static let maximumHops = 48
    public static let maximumWork = 160
    public static let maximumProbes = 48

    public static func collect<Handle: Hashable>(
        root: Handle,
        focus: Handle,
        maxHops: Int = maximumHops,
        maxWork: Int = maximumWork,
        maxProbes: Int = maximumProbes,
        inspect: (Handle) -> WeightedSurfaceInspection,
        parent: (Handle) -> Handle?,
        shouldContinue: () -> Bool = { true }
    ) -> SurfaceFocusAnchorResult<Handle> {
        let hopCap = min(maximumHops, max(0, maxHops))
        let workCap = min(maximumWork, max(0, maxWork))
        let probeCap = min(maximumProbes, max(0, maxProbes))
        var work = 0
        var probes = 0
        var reversed: [SurfaceFocusAnchor<Handle>] = []
        var seen = Set<Handle>()
        var current = focus

        func failed(_ reason: SurfaceFocusPathReason) -> SurfaceFocusAnchorResult<Handle> {
            .init(plan: nil, work: work, probes: probes, reason: reason)
        }

        while reversed.count < hopCap {
            guard work < workCap, probes < probeCap, shouldContinue() else {
                return failed(.budget)
            }
            guard seen.insert(current).inserted else { return failed(.cycle) }
            work += 1
            probes += 1
            let inspection = inspect(current)
            guard shouldContinue() else { return failed(.budget) }
            guard case let .allowed(metadata) = inspection,
                  (0...1_000_000).contains(metadata.childCount),
                  let policy = WeightedSurfaceTraversal.rolePolicy(for: metadata.role),
                  reversed.isEmpty || !policy.readsText else {
                return failed(.unavailable)
            }
            let remainingCost = policy.inspectionCost(childCount: metadata.childCount) - 1
            guard remainingCost <= workCap - work else { return failed(.budget) }
            work += remainingCost
            reversed.append(.init(handle: current, metadata: metadata))
            if current == root {
                let plan = SurfaceFocusAnchorPlan(
                    nodes: Array(reversed.reversed()),
                    root: root,
                    focus: focus,
                    work: work,
                    probes: probes
                )
                return .init(plan: plan, work: work, probes: probes, reason: nil)
            }
            guard reversed.count < hopCap, work < workCap, shouldContinue() else {
                return failed(.budget)
            }
            work += 1
            let next = parent(current)
            guard shouldContinue() else { return failed(.budget) }
            guard let next else { return failed(.unavailable) }
            current = next
        }
        return failed(.budget)
    }
}

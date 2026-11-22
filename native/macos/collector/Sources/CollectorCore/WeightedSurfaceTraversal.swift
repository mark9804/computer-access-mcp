///Exploration reason codes for bounded surface tree traversal.
public enum WeightedSurfaceTraversalReason: String, CaseIterable, Equatable {
    case workBudget = "weighted-work-budget"
    case probeBudget = "tree-probe-budget"
    case pendingBudget = "tree-pending-budget"
    case outputBudget = "tree-output-budget"
    case depthBudget = "tree-depth-budget"
    case timeBudget = "tree-time-budget"
    case providerRefused = "tree-provider-refused"
    case invalidChildCount = "tree-child-count-invalid"
    case inconsistentChildren = "tree-children-inconsistent"
    case repeatedNode = "tree-cycle-or-shared-node"
    case unsupportedRole = "tree-role-unsupported"
    case securityPruned = "tree-security-pruned"
    case anchorParentUnconfirmed = "tree-anchor-parent-unconfirmed"
}

public enum WeightedSurfaceRolePolicy: Equatable {
    case text
    case wrapper
    case semantic
    case composite

    public var readsText: Bool { self == .text }

    public func inspectionCost(childCount: Int) -> Int {
        switch self {
        case .text: return 2
        case .wrapper: return childCount <= 1 ? 1 : 3
        case .semantic: return childCount <= 1 ? 2 : 3
        case .composite: return 4
        }
    }
}

/// Returns true when `text` contains at least one non-whitespace scalar and every
/// non-whitespace scalar falls in a Unicode Private Use Area (e.g. Codicon icon glyphs).
public func isPrivateUseOnlyText(_ text: String) -> Bool {
    var hasNonWhitespace = false
    for scalar in text.unicodeScalars {
        if scalar.properties.isWhitespace { continue }
        hasNonWhitespace = true
        let value = scalar.value
        let isPrivateUse = (0xE000...0xF8FF).contains(value)
            || (0xF0000...0xFFFFD).contains(value)
            || (0x100000...0x10FFFD).contains(value)
        if !isPrivateUse { return false }
    }
    return hasNonWhitespace
}

public struct WeightedSurfaceMetadata: Equatable {
    public let role: String
    public let subrole: String?
    public let childCount: Int
    public let isFocused: Bool
    public let observedAtMs: Int64
    public let isEnabled: Bool?
    public let displayText: String?
    public let bounds: SurfaceBounds?

    public init(
        role: String,
        childCount: Int,
        isFocused: Bool = false,
        observedAtMs: Int64 = 0,
        isEnabled: Bool? = nil,
        displayText: String? = nil,
        bounds: SurfaceBounds? = nil,
        subrole: String? = nil
    ) {
        self.role = role
        self.subrole = subrole
        self.childCount = childCount
        self.isFocused = isFocused
        self.observedAtMs = observedAtMs
        self.isEnabled = isEnabled
        self.displayText = displayText
        self.bounds = bounds
    }
}

public enum WeightedSurfaceInspection {
    case allowed(WeightedSurfaceMetadata)
    case pruned(WeightedSurfaceTraversalReason)
}

public enum WeightedSurfaceChildrenRead<Handle: Hashable> {
    case values([Handle])
    case unavailable(WeightedSurfaceTraversalReason)
}

public struct WeightedSurfaceTraversalLimits: Equatable {
    public let maxOutputNodes: Int
    public let maxWork: Int
    public let maxProbes: Int
    public let maxPending: Int
    public let maxDepth: Int
    public let pageSize: Int
    public let maxPriorityBurst: Int

    public init(
        maxOutputNodes: Int = 48,
        maxWork: Int? = nil,
        maxProbes: Int? = nil,
        maxPending: Int = 192,
        maxDepth: Int = 64,
        pageSize: Int = 4,
        maxPriorityBurst: Int = 4
    ) {
        let output = min(96, max(0, maxOutputNodes))
        self.maxOutputNodes = output
        self.maxWork = min(384, max(0, maxWork ?? output * 8))
        self.maxProbes = min(384, max(0, maxProbes ?? output * 6))
        self.maxPending = min(192, max(0, maxPending))
        self.maxDepth = min(64, max(0, maxDepth))
        self.pageSize = min(64, max(1, pageSize))
        self.maxPriorityBurst = min(4, max(1, maxPriorityBurst))
    }
}

public struct WeightedSurfaceSample<Handle: Hashable> {
    public let handle: Handle
    public let parent: Handle?
    public let metadata: WeightedSurfaceMetadata
    public let textRead: SurfaceNodeRead?
}

public struct WeightedSurfaceTraversalCounters: Equatable {
    public fileprivate(set) var work = 0
    public fileprivate(set) var probes = 0
    public fileprivate(set) var textReads = 0
    public fileprivate(set) var childPages = 0
    public fileprivate(set) var peakPending = 0
    public fileprivate(set) var sampledNodes = 0
    public fileprivate(set) var maxDepth = 0
    public fileprivate(set) var maxFanout = 0
    public fileprivate(set) var inspectedChildren = 0

    public init() {}
}

public struct WeightedSurfaceTraversalResult<Handle: Hashable> {
    public let nodes: [WeightedSurfaceSample<Handle>]
    public let reasons: [WeightedSurfaceTraversalReason]
    public let complete: Bool
    public let counters: WeightedSurfaceTraversalCounters
}

public enum SurfaceTextCoverage {
    public static func priority(depth: Int, context: Bool, compositeAncestors: Int, fallback: Int) -> Int {
        guard context else { return fallback }
        return 8_000 + min(64, max(0, depth)) * 30 + fallback / 10 - min(64, max(0, compositeAncestors)) * 500
    }

    public static func outputRank(_ value: String?, focused: Bool, header: Bool = false) -> Int {
        if focused { return 0 }
        if value?.unicodeScalars.contains(where: { !$0.properties.isWhitespace }) == true {
            return header ? 1 : 2
        }
        return value == nil ? 4 : 3
    }
}

/// Alternates child pages from tail and head without requesting the full children array.
public struct SurfaceChildFrontier {
    private var lower = 0
    private var upper: Int
    private var tail: Bool

    public init(count: Int, headFirst: Bool = false) {
        upper = min(1_000_000, max(0, count))
        tail = !headFirst
    }

    public var remaining: Int { upper - lower }

    public mutating func next(maxCount: Int) -> (offset: Int, count: Int, reverse: Bool)? {
        let count = min(remaining, min(64, max(0, maxCount)))
        guard count > 0 else { return nil }
        let reverse = tail
        let offset: Int
        if tail {
            upper -= count
            offset = upper
        } else {
            offset = lower
            lower += count
        }
        tail.toggle()
        return (offset, count, reverse)
    }
}

private enum WeightedSurfaceWork<Handle: Hashable> {
    case inspect(Handle, parent: Handle?, depth: Int, headerCandidate: Bool = false)
    case text(Int)
    case children(Int, offset: Int)
}

private struct WeightedSurfaceJob<Handle: Hashable> {
    let work: WeightedSurfaceWork<Handle>
    let priority: Int
}

private struct PaneHeaderBand {
    let parentIndex: Int
    let minY: Double
    let maxY: Double
    let maxDepth: Int
    let maxProbes: Int = 12
    let maxTextHits: Int = 2
    var probesUsed = 0
    var textHits = 0

    func contains(_ bounds: SurfaceBounds?) -> Bool {
        guard let bounds, bounds.width > 0, bounds.height > 0 else { return false }
        return bounds.y >= minY && (bounds.y + bounds.height) <= maxY
    }

    var active: Bool {
        probesUsed < maxProbes && textHits < maxTextHits
    }
}

private struct WeightedSurfaceObservation<Handle: Hashable> {
    let handle: Handle
    var parent: Handle?
    let metadata: WeightedSurfaceMetadata
    let depth: Int
    let focusContext: Int
    let compositeAncestors: Int
    let inHeaderBand: Bool
    var textRead: SurfaceNodeRead?
}

public enum WeightedSurfaceTraversal {
    public static func rolePolicy(for role: String) -> WeightedSurfaceRolePolicy? {
        switch role {
        case "AXTextField", "AXTextArea", "AXStaticText":
            return .text
        case "AXWindow", "AXGroup", "AXScrollArea", "AXSplitGroup", "AXSheet", "AXLayoutArea":
            return .wrapper
        case "AXWebArea", "AXDocument", "AXList", "AXTable", "AXColumn", "AXRow", "AXCell", "AXOutline", "AXHeading":
            return .semantic
        case "AXButton", "AXToolbar", "AXPopUpButton", "AXComboBox", "AXCheckBox", "AXLink", "AXTabGroup", "AXTabButton", "AXRadioGroup", "AXRadioButton":
            return .composite
        default:
            return nil
        }
    }

    public static func run<Handle: Hashable>(
        root: Handle,
        limits: WeightedSurfaceTraversalLimits = .init(),
        preferredRoles: Set<String> = [],
        ignoredRoles: Set<String> = [],
        ignoredSubroles: Set<String> = [],
        collapseEmptyContainers: Bool = false,
        preparationWork: Int = 0,
        preparationProbes: Int = 0,
        focusAnchors: SurfaceFocusAnchorPlan<Handle>? = nil,
        inspect: (Handle) -> WeightedSurfaceInspection,
        children: (Handle, Int, Int) -> WeightedSurfaceChildrenRead<Handle>,
        text: (Handle) -> SurfaceNodeRead?,
        shouldContinue: () -> Bool = { true },
        shouldContinueAfterWork: (() -> Bool)? = nil
    ) -> WeightedSurfaceTraversalResult<Handle> {
        func acceptsCompletedWork() -> Bool {
            if let shouldContinueAfterWork { return shouldContinueAfterWork() }
            return shouldContinue()
        }

        var reasons: [WeightedSurfaceTraversalReason] = []
        var counters = WeightedSurfaceTraversalCounters()
        var queue: [WeightedSurfaceJob<Handle>] = []
        var discovered: Set<Handle> = []
        var observations: [WeightedSurfaceObservation<Handle>] = []
        var priorityBurst = 0
        var observationsByHandle: [Handle: Int] = [:]
        var seeded = Set<Handle>()
        var confirmedSeedParents = Set<Handle>()
        var compositeDepth: [Handle: Int] = [:]
        var contexts: [Handle: Int] = [:]
        var frontiers: [Int: SurfaceChildFrontier] = [:]
        var headerBand: PaneHeaderBand?

        let anchors = focusAnchors.flatMap { plan in
            plan.root == root && plan.nodes.first?.handle == root && plan.nodes.last?.handle == plan.focus &&
                plan.nodes.count <= limits.maxDepth + 1 && plan.nodes.count <= limits.maxPending &&
                plan.work <= limits.maxWork && plan.probes <= limits.maxProbes &&
                plan.work == preparationWork && plan.probes == preparationProbes ? plan : nil
        }
        let contentFirst = anchors != nil
        counters.work = min(limits.maxWork, max(0, preparationWork))
        counters.probes = min(limits.maxProbes, max(0, preparationProbes))

        func note(_ reason: WeightedSurfaceTraversalReason) {
            if !reasons.contains(reason) { reasons.append(reason) }
        }
        func spend(_ cost: Int) -> Bool {
            guard cost >= 0, cost <= limits.maxWork - counters.work else {
                note(.workBudget)
                return false
            }
            counters.work += cost
            return true
        }
        func enqueue(_ work: WeightedSurfaceWork<Handle>, priority: Int) -> Bool {
            guard queue.count < limits.maxPending else {
                note(.pendingBudget)
                return false
            }
            queue.append(WeightedSurfaceJob(work: work, priority: priority))
            counters.peakPending = max(counters.peakPending, queue.count)
            return true
        }
        func roleBoost(_ role: String) -> Int {
            preferredRoles.contains(role) ? 40 : 0
        }
        func pagePriority(_ metadata: WeightedSurfaceMetadata) -> Int {
            let base: Int
            if metadata.isFocused { base = 70 }
            else if metadata.childCount == 1 { base = 60 }
            else { base = 30 }
            return base + roleBoost(metadata.role)
        }
        func contextPriority(_ context: Int, fallback: Int) -> Int {
            context > 0 ? 80 + min(20, fallback / 3) : fallback
        }
        func childPagePriority(_ observation: WeightedSurfaceObservation<Handle>, continuation: Bool = false) -> Int {
            let fallback = (continuation ? 20 : pagePriority(observation.metadata)) + roleBoost(observation.metadata.role)
            if contentFirst {
                return SurfaceTextCoverage.priority(
                    depth: observation.depth,
                    context: observation.focusContext > 0,
                    compositeAncestors: observation.compositeAncestors + (rolePolicy(for: observation.metadata.role) == .composite ? 1 : 0),
                    fallback: fallback
                )
            }
            return contextPriority(observation.focusContext, fallback: fallback)
        }

        if preparationWork < 0 || preparationProbes < 0 {
            note(.providerRefused)
            return WeightedSurfaceTraversalResult(nodes: [], reasons: reasons, complete: false, counters: counters)
        }
        if preparationWork > limits.maxWork { note(.workBudget) }
        if preparationProbes > limits.maxProbes { note(.probeBudget) }

        if limits.maxOutputNodes == 0 {
            note(.outputBudget)
        } else if let anchors {
            for (depth, anchor) in anchors.nodes.enumerated() {
                let index = observations.count
                observations.append(.init(
                    handle: anchor.handle,
                    parent: nil,
                    metadata: anchor.metadata,
                    depth: depth,
                    focusContext: anchors.nodes.count,
                    compositeAncestors: 0,
                    inHeaderBand: false
                ))
                observationsByHandle[anchor.handle] = index
                seeded.insert(anchor.handle)
                discovered.insert(anchor.handle)
                counters.maxDepth = max(counters.maxDepth, depth)
                counters.maxFanout = max(counters.maxFanout, anchor.metadata.childCount)
                counters.inspectedChildren += anchor.metadata.childCount
            }
            // Detect the closest enclosing pane header band above the main content container
            // (e.g. QQ chat-header / Feishu chatContainer__headerWrapper) from cached geometry.
            for childIndex in stride(from: observations.count - 1, through: 1, by: -1) {
                let parentIndex = childIndex - 1
                let parent = observations[parentIndex]
                let child = observations[childIndex]
                guard parent.metadata.childCount >= 2,
                      let parentBounds = parent.metadata.bounds,
                      let childBounds = child.metadata.bounds,
                      childBounds.height >= 200 else { continue }
                let headerHeight = childBounds.y - parentBounds.y
                if headerHeight >= 24 && headerHeight <= 120 {
                    headerBand = PaneHeaderBand(
                        parentIndex: parentIndex,
                        minY: parentBounds.y - 4,
                        maxY: childBounds.y + 8,
                        maxDepth: parent.depth + 6
                    )
                    break
                }
            }
            counters.sampledNodes = observations.count
            for index in observations.indices.reversed() {
                let observation = observations[index]
                if rolePolicy(for: observation.metadata.role)?.readsText == true {
                    _ = enqueue(.text(index), priority: observation.metadata.isFocused ? 13_000 : 12_000)
                    if observation.metadata.childCount > 0 { note(.inconsistentChildren) }
                } else if observation.metadata.childCount > 0 {
                    if observation.depth == limits.maxDepth { note(.depthBudget) }
                    else {
                        let priority = headerBand?.parentIndex == index ? 11_600 : childPagePriority(observation)
                        _ = enqueue(.children(index, offset: 0), priority: priority)
                    }
                }
            }
        } else if enqueue(.inspect(root, parent: nil, depth: 0), priority: 30) {
            discovered.insert(root)
        }

        func effectivePriority(_ job: WeightedSurfaceJob<Handle>) -> Int {
            if case let .inspect(_, _, depth, headerCandidate) = job.work,
               headerCandidate, headerBand?.active != true {
                return 8_000 + min(64, max(0, depth)) * 30
            }
            return job.priority
        }

        while !queue.isEmpty {
            guard shouldContinue() else { note(.timeBudget); break }
            var selected = 0
            if priorityBurst < limits.maxPriorityBurst {
                var selectedPriority = effectivePriority(queue[0])
                for index in queue.indices.dropFirst() {
                    let candidatePriority = effectivePriority(queue[index])
                    if candidatePriority > selectedPriority {
                        selected = index
                        selectedPriority = candidatePriority
                    }
                }
            }
            priorityBurst = selected == 0 ? 0 : priorityBurst + 1
            let job = queue.remove(at: selected)
            switch job.work {
            case let .inspect(handle, parent, depth, headerCandidate):
                guard depth <= limits.maxDepth else { note(.depthBudget); continue }
                guard counters.probes < limits.maxProbes else { note(.probeBudget); continue }
                guard spend(1) else { continue }
                counters.probes += 1
                let inspection = inspect(handle)
                guard acceptsCompletedWork() else { note(.timeBudget); continue }
                let metadata: WeightedSurfaceMetadata
                switch inspection {
                case let .pruned(reason): note(reason); continue
                case let .allowed(value): metadata = value
                }
                let insideHeader: Bool
                if headerCandidate,
                   let band = headerBand,
                   band.active,
                   depth <= band.maxDepth,
                   metadata.role != "AXToolbar",
                   band.contains(metadata.bounds) {
                    headerBand?.probesUsed += 1
                    insideHeader = true
                } else {
                    insideHeader = false
                }
                if depth > 0, !metadata.isFocused,
                   ignoredRoles.contains(metadata.role)
                    || (metadata.subrole.map { ignoredSubroles.contains($0) } ?? false) {
                    note(.unsupportedRole)
                    continue
                }
                guard let policy = rolePolicy(for: metadata.role) else { note(.unsupportedRole); continue }
                guard (0...1_000_000).contains(metadata.childCount) else { note(.invalidChildCount); continue }
                if depth > 0, !metadata.isFocused, metadata.isEnabled == false, metadata.childCount == 0,
                   !policy.readsText, metadata.displayText?.isEmpty != false {
                    continue
                }
                guard spend(policy.inspectionCost(childCount: metadata.childCount) - 1) else { continue }
                if insideHeader,
                   let displayText = metadata.displayText,
                   !isPrivateUseOnlyText(displayText),
                   displayText.unicodeScalars.contains(where: { !$0.properties.isWhitespace }) {
                    headerBand?.textHits += 1
                }
                let index = observations.count
                observations.append(WeightedSurfaceObservation(
                    handle: handle,
                    parent: parent,
                    metadata: metadata,
                    depth: depth,
                    focusContext: contexts[handle] ?? 0,
                    compositeAncestors: compositeDepth[handle] ?? 0,
                    inHeaderBand: insideHeader
                ))
                observationsByHandle[handle] = index
                counters.sampledNodes = observations.count
                counters.maxDepth = max(counters.maxDepth, depth)
                counters.maxFanout = max(counters.maxFanout, metadata.childCount)
                counters.inspectedChildren += metadata.childCount
                if policy.readsText {
                    let boost = roleBoost(metadata.role)
                    let textPriority: Int
                    if insideHeader {
                        textPriority = 12_500
                    } else {
                        textPriority = (contentFirst ? (metadata.isFocused ? 13_000 : 12_000) : (metadata.isFocused ? 130 : 120)) + boost
                    }
                    _ = enqueue(.text(index), priority: textPriority)
                    if metadata.childCount > 0 { note(.inconsistentChildren) }
                }
                if !policy.readsText && metadata.childCount > 0 {
                    if depth == limits.maxDepth { note(.depthBudget) }
                    else {
                        let childrenPriority: Int
                        if insideHeader, let band = headerBand, band.active, depth < band.maxDepth {
                            childrenPriority = 11_000 + min(48, depth) * 10 + 5
                        } else {
                            childrenPriority = childPagePriority(observations[index])
                        }
                        _ = enqueue(.children(index, offset: 0), priority: childrenPriority)
                    }
                }

            case let .text(index):
                guard spend(2) else { continue }
                counters.textReads += 1
                let value = text(observations[index].handle)
                guard acceptsCompletedWork() else { note(.timeBudget); continue }
                guard let value, value.text != nil else { note(.providerRefused); continue }
                observations[index].textRead = value
                if observations[index].inHeaderBand,
                   let readText = value.text,
                   !isPrivateUseOnlyText(readText),
                   readText.unicodeScalars.contains(where: { !$0.properties.isWhitespace }) {
                    headerBand?.textHits += 1
                }

            case let .children(index, offset):
                guard counters.probes < limits.maxProbes else { note(.probeBudget); continue }
                let observation = observations[index]
                let remaining = observation.metadata.childCount - offset
                guard remaining > 0 else { note(.inconsistentChildren); continue }
                let capacity = limits.maxPending - queue.count
                guard capacity > 0 else { note(.pendingBudget); continue }
                let slots = capacity > 1 && remaining > 1 ? capacity - 1 : capacity
                let count = min(limits.pageSize, min(remaining, slots))
                var requestOffset = offset
                var requestCount = count
                var reversePage = false
                let headFirstFrontier = observation.inHeaderBand || headerBand?.parentIndex == index
                if contentFirst {
                    var frontier = frontiers[index] ?? SurfaceChildFrontier(count: observation.metadata.childCount, headFirst: headFirstFrontier)
                    guard let page = frontier.next(maxCount: count) else { note(.inconsistentChildren); continue }
                    frontiers[index] = frontier
                    requestOffset = page.offset
                    requestCount = page.count
                    reversePage = page.reverse
                }
                guard spend(1) else { continue }
                counters.childPages += 1
                let page = children(observation.handle, requestOffset, requestCount)
                guard acceptsCompletedWork() else { note(.timeBudget); continue }
                let handles: [Handle]
                switch page {
                case let .unavailable(reason): note(reason); continue
                case let .values(values): handles = values
                }
                guard handles.count <= requestCount else { note(.inconsistentChildren); continue }
                if handles.count != requestCount { note(.inconsistentChildren) }
                let orderedHandles = reversePage ? Array(handles.reversed()) : handles
                let emitHeaderCandidate: Bool
                if let band = headerBand, band.active {
                    emitHeaderCandidate = (band.parentIndex == index && offset == 0)
                        || (observation.inHeaderBand && observation.depth < band.maxDepth)
                } else {
                    emitHeaderCandidate = false
                }
                for (childPos, handle) in orderedHandles.enumerated() {
                    if discovered.contains(handle) {
                        if seeded.contains(handle), let seededIndex = observationsByHandle[handle],
                           let anchors, seededIndex > 0, anchors.nodes[seededIndex - 1].handle == observation.handle,
                           !confirmedSeedParents.contains(handle) {
                            observations[seededIndex].parent = observation.handle
                            confirmedSeedParents.insert(handle)
                        } else {
                            note(.repeatedNode)
                        }
                        continue
                    }
                    let context = observation.focusContext
                    let compositeAncestors = observation.compositeAncestors + (rolePolicy(for: observation.metadata.role) == .composite ? 1 : 0)
                    let priority: Int
                    if emitHeaderCandidate {
                        priority = 11_000 + min(48, observation.depth + 1) * 10 - min(9, childPos)
                    } else if contentFirst {
                        priority = SurfaceTextCoverage.priority(depth: observation.depth + 1, context: context > 0, compositeAncestors: compositeAncestors, fallback: pagePriority(observation.metadata))
                    } else {
                        priority = contextPriority(context, fallback: pagePriority(observation.metadata))
                    }
                    if enqueue(.inspect(handle, parent: observation.handle, depth: observation.depth + 1, headerCandidate: emitHeaderCandidate), priority: priority) {
                        discovered.insert(handle)
                        contexts[handle] = context
                        compositeDepth[handle] = compositeAncestors
                    }
                }
                let nextOffset = offset + handles.count
                let hasRemaining = contentFirst ? (frontiers[index]?.remaining ?? 0) > 0 : nextOffset < observation.metadata.childCount
                if handles.count == requestCount, hasRemaining {
                    _ = enqueue(.children(index, offset: nextOffset), priority: childPagePriority(observation, continuation: true))
                }
            }
        }

        if let anchors, anchors.nodes.dropFirst().contains(where: { !confirmedSeedParents.contains($0.handle) }) {
            note(.anchorParentUnconfirmed)
        }

        func isExcludedLeaf(_ observation: WeightedSurfaceObservation<Handle>) -> Bool {
            guard observation.depth > 0, !observation.metadata.isFocused else { return false }
            if observation.metadata.role == "AXStaticText",
               let readText = observation.textRead?.text,
               isPrivateUseOnlyText(readText) {
                return true
            }
            return observation.metadata.isEnabled == false &&
                observation.metadata.childCount == 0 &&
                (observation.textRead?.text?.isEmpty != false) &&
                (observation.metadata.displayText?.isEmpty != false)
        }

        func isCollapsibleEmptyWrapper(_ observation: WeightedSurfaceObservation<Handle>) -> Bool {
            guard collapseEmptyContainers, observation.depth > 0, !observation.metadata.isFocused else { return false }
            guard rolePolicy(for: observation.metadata.role) == .wrapper else { return false }
            return observation.textRead == nil && observation.metadata.displayText == nil
        }

        let eligibleIndices = observations.indices.filter { !isExcludedLeaf(observations[$0]) }
        let outputEligibleIndices = collapseEmptyContainers
            ? eligibleIndices.filter { !isCollapsibleEmptyWrapper(observations[$0]) }
            : eligibleIndices
        var retained: Set<Handle> = []
        let byHandle = Dictionary(uniqueKeysWithValues: observations.enumerated().map { ($0.element.handle, $0.offset) })
        let textIndices = outputEligibleIndices.filter {
            observations[$0].textRead != nil || observations[$0].metadata.displayText != nil
        }.sorted {
            let leftText = observations[$0].textRead?.text ?? observations[$0].metadata.displayText
            let rightText = observations[$1].textRead?.text ?? observations[$1].metadata.displayText
            let left = SurfaceTextCoverage.outputRank(leftText, focused: observations[$0].metadata.isFocused, header: observations[$0].inHeaderBand)
            let right = SurfaceTextCoverage.outputRank(rightText, focused: observations[$1].metadata.isFocused, header: observations[$1].inHeaderBand)
            return left == right ? $0 < $1 : left < right
        }
        for index in textIndices where retained.count < limits.maxOutputNodes {
            retained.insert(observations[index].handle)
        }
        var ancestors = textIndices.filter { retained.contains(observations[$0].handle) }.compactMap { observations[$0].parent }
        var examinedAncestors: Set<Handle> = []
        while !ancestors.isEmpty, retained.count < limits.maxOutputNodes {
            var next: [Handle] = []
            for handle in ancestors where retained.count < limits.maxOutputNodes {
                guard examinedAncestors.insert(handle).inserted, let index = byHandle[handle] else { continue }
                if !isCollapsibleEmptyWrapper(observations[index]) {
                    retained.insert(handle)
                }
                if let parent = observations[index].parent { next.append(parent) }
            }
            ancestors = next
        }
        for index in outputEligibleIndices where retained.count < limits.maxOutputNodes {
            retained.insert(observations[index].handle)
        }
        if retained.count < outputEligibleIndices.count { note(.outputBudget) }
        let nodes = observations.filter { retained.contains($0.handle) }.map { observation in
            var parentHandle = observation.parent
            if collapseEmptyContainers {
                while let candidate = parentHandle,
                      !retained.contains(candidate),
                      let candidateIndex = byHandle[candidate],
                      isCollapsibleEmptyWrapper(observations[candidateIndex]) {
                    parentHandle = observations[candidateIndex].parent
                }
            }
            let parent = parentHandle.flatMap { retained.contains($0) ? $0 : nil }
            if parentHandle != nil, parent == nil { note(.outputBudget) }
            return WeightedSurfaceSample(
                handle: observation.handle,
                parent: parent,
                metadata: observation.metadata,
                textRead: observation.textRead
            )
        }
        return WeightedSurfaceTraversalResult(nodes: nodes, reasons: reasons, complete: reasons.isEmpty && queue.isEmpty, counters: counters)
    }
}

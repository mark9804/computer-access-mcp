import Foundation

/// Custom application adapter for macOS Figma Desktop (Electron four-zone canvas layout).
public struct FigmaAdapter: AppAdapter {
    public let spec = AppAdapterSpec(
        id: "figma",
        displayName: "Figma",
        matchBundleIds: ["com.figma.Desktop"],
        activation: .enhancedUI,
        windowAnchor: .allowUnfocusedWindow,
        staticTextProbe: .boundedRangeProbe(maxUnits: 256),
        preferredRoles: [
            "AXWebArea",
            "AXHeading",
            "AXStaticText",
            "AXTextField",
            "AXTextArea",
            "AXComboBox",
            "AXCheckBox",
            "AXRadioButton",
            "AXButton",
            "AXRow",
        ],
        ignoredRoles: ["AXMenuBar", "AXMenu", "AXMenuItem", "AXToolbar", "AXScrollBar", "AXSlider"],
        pageSize: 16,
        maxNodeTextUnits: 256,
        blockPrivateWindows: false
    )

    private static let maxShellDepth = 12
    private static let maxShellVisits = 64
    private static let maxLandmarkDepth = 8
    private static let maxLandmarkVisits = 64
    private static let maxZoneDepth = 12
    private static let maxTabDepth = 10
    private static let maxTabVisits = 64
    private static let maxCanvasVisits = 80
    private static let maxSidebarVisits = 120

    private static let ignoredChromeRoles: Set<String> = [
        "AXToolbar", "AXMenuBar", "AXMenu", "AXMenuItem", "AXScrollBar", "AXSlider", "AXImage",
    ]
    private static let shellSkippedRoles: Set<String> = [
        "AXButton", "AXToolbar", "AXMenuBar", "AXMenu", "AXMenuItem",
        "AXScrollBar", "AXSlider", "AXStaticText", "AXTextField", "AXTextArea", "AXImage",
    ]
    private static let landmarkLocatorSkippedRoles: Set<String> = [
        "AXButton", "AXToolbar", "AXMenuBar", "AXMenu", "AXMenuItem",
        "AXScrollBar", "AXSlider", "AXStaticText", "AXTextField", "AXTextArea",
        "AXComboBox", "AXCheckBox", "AXRadioButton", "AXTabButton", "AXTabGroup",
        "AXTable", "AXColumn", "AXOutline", "AXList", "AXImage", "AXHeading", "AXLink",
    ]
    private static let tabChromeNoise: Set<String> = [
        "Close tab",
        "New file",
        "Open tabs and recently closed items",
    ]
    private static let rightSidebarChromeNoise: Set<String> = [
        "Apply variable",
        "Apply variable mode",
        "Apply variable/property",
        "Toggle visibility",
        "Prototype view",
        "Add fill",
        "Add stroke",
        "Add effect",
        "Add layout guide",
        "Add export settings",
        "Align left",
        "Align horizontal centers",
        "Align right",
        "Align top",
        "Align vertical centers",
        "Align bottom",
        "Distribute horizontal spacing",
        "Distribute vertical spacing",
        "Ignore auto layout",
        "Edit object",
        "Create link",
        "Create instance swap property",
        "Component configuration",
        "Edit template style",
        "Remix template colors",
        "Adjust tone",
        "Resize handle",
        "Select matching layers",
        "More actions",
        "Present",
        "Share",
        "Help",
        "Multiplayer tools",
    ]
    private static let leftSidebarChromeNoise: Set<String> = [
        "Minimize UI",
        "Collapse layers",
        "Find",
        "Add new page",
        "Navigation Bar",
        "Resize handle",
    ]
    private static let leftSidebarItemRoles: Set<String> = [
        "AXRow", "AXCell", "AXStaticText", "AXHeading",
        "AXButton", "AXRadioButton", "AXTabButton", "AXTextField", "AXTextArea",
    ]

    public init() {}

    public func extractSurface(context: SafeAXContext) -> CustomSurfaceResult? {
        guard let rootInfo = context.inspect(context.root) else { return nil }
        if context.isAborted { return nil }

        // Step 1: Shallow BFS through Electron outer shell to locate Tab Bar and Main Document AXWebAreas.
        var webAreas: [AXNodeInfo] = []
        var shellQueue: [(handle: AXNodeHandle, depth: Int)] = [(context.root, 0)]
        var shellVisited: Set<AXNodeHandle> = [context.root]
        var shellCursor = 0
        var shellVisits = 1

        while shellCursor < shellQueue.count,
              shellVisits < Self.maxShellVisits,
              context.canContinue,
              !context.isAborted {
            let entry = shellQueue[shellCursor]
            shellCursor += 1
            let info: AXNodeInfo
            if entry.handle == context.root {
                info = rootInfo
            } else {
                shellVisits += 1
                guard let fresh = context.inspect(entry.handle) else { continue }
                info = fresh
            }
            if info.role == "AXWebArea" {
                webAreas.append(info)
                if webAreas.count >= 2 {
                    let hasTabCandidate = webAreas.contains { area in
                        if let rect = context.bounds(of: area.handle)?.bounds, rect.height > 0 {
                            return rect.height <= 60
                        }
                        return area.label == "Figma"
                    }
                    let hasMainCandidate = webAreas.contains { area in
                        if let rect = context.bounds(of: area.handle)?.bounds, rect.height > 0 {
                            return rect.height > 100
                        }
                        return area.label != "Figma"
                    }
                    if hasTabCandidate && hasMainCandidate { break }
                }
                continue
            }
            if entry.handle != context.root, Self.shellSkippedRoles.contains(info.role) { continue }
            guard entry.depth < Self.maxShellDepth, info.childCount > 0 else { continue }
            guard let children = context.children(of: entry.handle, offset: 0, limit: min(info.childCount, 32)) else { continue }
            for child in children where shellVisited.insert(child).inserted {
                shellQueue.append((child, entry.depth + 1))
            }
        }
        if context.isAborted { return nil }

        var tabBarWebArea: AXNodeInfo?
        var mainWebArea: AXNodeInfo?
        var largestMainArea: Double = -1
        for area in webAreas {
            if let rect = context.bounds(of: area.handle)?.bounds, rect.width > 0, rect.height > 0 {
                if rect.height <= 60 {
                    if tabBarWebArea == nil { tabBarWebArea = area }
                } else if rect.height > 100 {
                    let areaSize = rect.width * rect.height
                    if areaSize > largestMainArea {
                        largestMainArea = areaSize
                        mainWebArea = area
                    }
                } else if mainWebArea == nil {
                    mainWebArea = area
                }
            } else if area.label == "Figma" {
                if tabBarWebArea == nil { tabBarWebArea = area }
            } else if mainWebArea == nil {
                mainWebArea = area
            }
        }
        if mainWebArea == nil, webAreas.count == 1, let only = webAreas.first {
            mainWebArea = only
            tabBarWebArea = nil
        }
        guard let mainWebArea else { return nil }

        // Step 2: Bounded locator BFS inside Main AXWebArea to find canvas and sidebar landmarks.
        var landmarkMain: AXNodeInfo?
        var rightSidebar: AXNodeInfo?
        var leftSidebar: AXNodeInfo?

        var lmQueue: [(handle: AXNodeHandle, depth: Int)] = [(mainWebArea.handle, 0)]
        var lmVisited: Set<AXNodeHandle> = [mainWebArea.handle]
        var lmCursor = 0
        var lmVisits = 1

        while lmCursor < lmQueue.count,
              lmVisits < Self.maxLandmarkVisits,
              context.canContinue,
              !context.isAborted,
              !(landmarkMain != nil && rightSidebar != nil && leftSidebar != nil) {
            let entry = lmQueue[lmCursor]
            lmCursor += 1
            let info: AXNodeInfo
            if entry.handle == mainWebArea.handle {
                info = mainWebArea
            } else {
                lmVisits += 1
                guard let fresh = context.inspect(entry.handle) else { continue }
                info = fresh
            }
            if entry.handle != mainWebArea.handle {
                if info.subrole == "AXLandmarkMain" {
                    landmarkMain = info
                    continue
                }
                if info.subrole == "AXLandmarkRegion" {
                    let lowered = info.label?.lowercased()
                    if lowered == "right sidebar" {
                        rightSidebar = info
                        continue
                    }
                    if lowered == "left sidebar" {
                        leftSidebar = info
                        continue
                    }
                }
                if Self.landmarkLocatorSkippedRoles.contains(info.role) { continue }
            }
            guard entry.depth < Self.maxLandmarkDepth, info.childCount > 0 else { continue }
            guard let children = context.children(of: entry.handle, offset: 0, limit: min(info.childCount, 32)) else { continue }
            for child in children where lmVisited.insert(child).inserted {
                lmQueue.append((child, entry.depth + 1))
            }
        }
        if context.isAborted { return nil }

        // Fall back to standard weighted traversal on Home / File Browser screens without canvas.
        guard let landmarkMain else { return nil }

        // Step 3: Emit prioritized zones within maxNodes.
        let maxNodes = min(96, max(1, context.maxOutputNodes))
        var seen: Set<AXNodeHandle> = []
        var focusAssigned = false
        var truncated = false
        var nodes: [CustomSurfaceNode] = []

        func makeNode(_ info: AXNodeInfo, parent: AXNodeHandle?, role: String, text: String?) -> CustomSurfaceNode {
            let bounds = context.bounds(of: info.handle)
            let isFocused = !focusAssigned && (context.focus.map { $0 == info.handle } ?? info.isFocused)
            if isFocused { focusAssigned = true }
            return CustomSurfaceNode(
                handle: info.handle,
                parent: parent,
                role: role,
                axRole: info.role,
                text: text,
                isFocused: isFocused,
                observedAtMs: info.observedAtMs,
                bounds: bounds?.bounds,
                boundsObservedAtMs: bounds?.observedAtMs
            )
        }

        func hasZeroSize(_ handle: AXNodeHandle) -> Bool {
            guard let rect = context.bounds(of: handle)?.bounds else { return false }
            return rect.width <= 0 || rect.height <= 0
        }

        // Zone 1: Root container + Main AXWebArea (title + Figma URL) + Open File Tabs.
        seen.insert(context.root)
        let rootText = mainWebArea.handle == context.root ? context.displayText(of: mainWebArea.handle) : nil
        nodes.append(makeNode(rootInfo, parent: nil, role: "container", text: rootText))

        if mainWebArea.handle != context.root,
           nodes.count < maxNodes,
           seen.insert(mainWebArea.handle).inserted {
            nodes.append(makeNode(mainWebArea, parent: context.root, role: "container", text: context.displayText(of: mainWebArea.handle)))
        }

        if let tabBarWebArea,
           tabBarWebArea.handle != context.root,
           tabBarWebArea.handle != mainWebArea.handle,
           nodes.count + 2 <= maxNodes,
           context.canContinue,
           !context.isAborted {
            let maxTabItems = min(10, max(1, maxNodes - nodes.count - 1))
            var collectedTabs: [(AXNodeInfo, String)] = []
            var tabQueue: [(handle: AXNodeHandle, depth: Int)] = [(tabBarWebArea.handle, 0)]
            var tabVisited: Set<AXNodeHandle> = [tabBarWebArea.handle]
            var tabCursor = 0
            var tabVisits = 1

            while tabCursor < tabQueue.count,
                  tabVisits < Self.maxTabVisits,
                  collectedTabs.count < maxTabItems,
                  context.canContinue,
                  !context.isAborted {
                let entry = tabQueue[tabCursor]
                tabCursor += 1
                let info: AXNodeInfo
                if entry.handle == tabBarWebArea.handle {
                    info = tabBarWebArea
                } else {
                    tabVisits += 1
                    guard let fresh = context.inspect(entry.handle),
                          !Self.ignoredChromeRoles.contains(fresh.role),
                          !hasZeroSize(fresh.handle) else { continue }
                    info = fresh
                }
                if info.role == "AXRadioButton" || info.role == "AXTabButton" {
                    var tabLabel = context.displayText(of: info.handle)
                    if tabLabel == nil, info.childCount > 0,
                       let tabChildren = context.children(of: info.handle, offset: 0, limit: min(info.childCount, 4)) {
                        for child in tabChildren where context.canContinue && !context.isAborted {
                            if let childInfo = context.inspect(child), childInfo.role == "AXStaticText",
                               let raw = context.text(of: child) {
                                let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                                if !trimmed.isEmpty, !isPrivateUseOnlyText(trimmed) {
                                    tabLabel = trimmed
                                    break
                                }
                            }
                        }
                    }
                    if let tabLabel, !tabLabel.isEmpty, !isPrivateUseOnlyText(tabLabel),
                       !Self.tabChromeNoise.contains(tabLabel) {
                        collectedTabs.append((info, tabLabel))
                    }
                    continue
                }
                guard entry.depth < Self.maxTabDepth, info.childCount > 0,
                      info.role != "AXButton", info.role != "AXStaticText",
                      info.role != "AXTextField", info.role != "AXTextArea" else { continue }
                guard let children = context.children(of: entry.handle, offset: 0, limit: min(info.childCount, 24)) else { continue }
                for child in children where tabVisited.insert(child).inserted {
                    tabQueue.append((child, entry.depth + 1))
                }
            }

            if !collectedTabs.isEmpty, nodes.count < maxNodes, seen.insert(tabBarWebArea.handle).inserted {
                nodes.append(makeNode(tabBarWebArea, parent: context.root, role: "container", text: context.displayText(of: tabBarWebArea.handle)))
                for (tabInfo, tabText) in collectedTabs where nodes.count < maxNodes {
                    if seen.insert(tabInfo.handle).inserted {
                        nodes.append(makeNode(tabInfo, parent: tabBarWebArea.handle, role: "container", text: tabText))
                    }
                }
            }
        }
        if context.isAborted { return nil }

        // Reserve proportional output slots so Right Inspector and Left Sidebar are never starved by deep selections.
        let remainingAfterHeader = max(0, maxNodes - nodes.count)
        let hasRight = rightSidebar != nil
        let hasLeft = leftSidebar != nil
        let reservePool = max(0, remainingAfterHeader - 1)
        let desiredRight = hasRight ? min(24, max(18, remainingAfterHeader * 45 / 100)) : 0
        let desiredLeft = hasLeft ? min(18, max(8, remainingAfterHeader * 25 / 100)) : 0
        let rightReserve: Int
        let leftReserve: Int
        if desiredRight + desiredLeft <= reservePool {
            rightReserve = desiredRight
            leftReserve = desiredLeft
        } else if reservePool == 0 {
            rightReserve = 0
            leftReserve = 0
        } else {
            rightReserve = hasRight ? max(1, reservePool * 2 / 3) : 0
            leftReserve = hasLeft ? max(0, reservePool - rightReserve) : 0
        }
        let canvasLimit = max(0, remainingAfterHeader - rightReserve - leftReserve)

        // Zone 2: Selected Canvas Hierarchy (AXLandmarkMain).
        if canvasLimit > 0, nodes.count < maxNodes, seen.insert(landmarkMain.handle).inserted {
            nodes.append(makeNode(landmarkMain, parent: mainWebArea.handle, role: "container", text: context.displayText(of: landmarkMain.handle)))
            var canvasEmitted = 1
            var canvasVisits = 0
            var canvasVisited: Set<AXNodeHandle> = [landmarkMain.handle]

            func walkCanvas(_ parentInfo: AXNodeInfo, emittedParent: AXNodeHandle, depth: Int) {
                guard canvasEmitted < canvasLimit,
                      nodes.count < maxNodes,
                      canvasVisits < Self.maxCanvasVisits,
                      depth < Self.maxZoneDepth,
                      parentInfo.childCount > 0,
                      context.canContinue,
                      !context.isAborted else {
                    if parentInfo.childCount > 0 && canvasEmitted >= canvasLimit { truncated = true }
                    return
                }
                let pageLimit = min(parentInfo.childCount, 24)
                if parentInfo.childCount > pageLimit { truncated = true }
                guard let children = context.children(of: parentInfo.handle, offset: 0, limit: pageLimit) else { return }
                for child in children {
                    guard canvasEmitted < canvasLimit, nodes.count < maxNodes else {
                        truncated = true
                        return
                    }
                    guard canvasVisits < Self.maxCanvasVisits, context.canContinue, !context.isAborted else { return }
                    guard canvasVisited.insert(child).inserted else { continue }
                    canvasVisits += 1
                    guard let info = context.inspect(child), !Self.ignoredChromeRoles.contains(info.role) else { continue }
                    let isFocusNode = (context.focus == info.handle) || info.isFocused
                    if info.subrole == "AXApplicationGroup" {
                        let label = context.displayText(of: info.handle)
                        var nextParent = emittedParent
                        if (label != nil || isFocusNode), seen.insert(info.handle).inserted {
                            nodes.append(makeNode(info, parent: emittedParent, role: "container", text: label))
                            canvasEmitted += 1
                            nextParent = info.handle
                        }
                        if info.childCount > 0 {
                            walkCanvas(info, emittedParent: nextParent, depth: depth + 1)
                        }
                    } else if info.role == "AXStaticText" {
                        guard let raw = context.text(of: info.handle) else { continue }
                        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !trimmed.isEmpty, !isPrivateUseOnlyText(trimmed), trimmed != "Dimensions" else { continue }
                        if seen.insert(info.handle).inserted {
                            nodes.append(makeNode(info, parent: emittedParent, role: "text", text: trimmed))
                            canvasEmitted += 1
                        }
                    } else if info.role == "AXTextField" || info.role == "AXTextArea" {
                        guard let raw = context.text(of: info.handle) else { continue }
                        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard isFocusNode || (!trimmed.isEmpty && !isPrivateUseOnlyText(trimmed)) else { continue }
                        if seen.insert(info.handle).inserted {
                            nodes.append(makeNode(info, parent: emittedParent, role: "editable", text: raw))
                            canvasEmitted += 1
                        }
                    } else if info.role == "AXHeading" {
                        if let label = context.displayText(of: info.handle),
                           !isPrivateUseOnlyText(label),
                           label != "Dimensions",
                           seen.insert(info.handle).inserted {
                            nodes.append(makeNode(info, parent: emittedParent, role: "text", text: label))
                            canvasEmitted += 1
                        } else if info.childCount > 0 {
                            walkCanvas(info, emittedParent: emittedParent, depth: depth + 1)
                        }
                    } else if info.childCount > 0 {
                        walkCanvas(info, emittedParent: emittedParent, depth: depth + 1)
                    }
                }
            }

            walkCanvas(landmarkMain, emittedParent: landmarkMain.handle, depth: 0)
        }
        if context.isAborted { return nil }

        // Zone 3: Right Design/Prototype Inspector.
        if let rightSidebar,
           nodes.count < maxNodes,
           context.canContinue {
            let remainingForRight = max(0, maxNodes - nodes.count - leftReserve)
            let rightLimit = hasLeft ? min(max(rightReserve, 28), remainingForRight) : max(0, maxNodes - nodes.count)
            if rightLimit > 0, seen.insert(rightSidebar.handle).inserted {
                nodes.append(makeNode(rightSidebar, parent: mainWebArea.handle, role: "container", text: context.displayText(of: rightSidebar.handle)))
                var rightEmitted = 1
                var rightVisits = 0
                var rightVisited: Set<AXNodeHandle> = [rightSidebar.handle]

                func walkRightSidebar(_ parentInfo: AXNodeInfo, emittedParent: AXNodeHandle, parentText: String?, depth: Int) {
                    guard rightEmitted < rightLimit,
                          nodes.count < maxNodes,
                          rightVisits < Self.maxSidebarVisits,
                          depth < Self.maxZoneDepth,
                          parentInfo.childCount > 0,
                          context.canContinue,
                          !context.isAborted else {
                        if parentInfo.childCount > 0 && rightEmitted >= rightLimit { truncated = true }
                        return
                    }
                    let pageLimit = min(parentInfo.childCount, 24)
                    if parentInfo.childCount > pageLimit { truncated = true }
                    guard let children = context.children(of: parentInfo.handle, offset: 0, limit: pageLimit) else { return }
                    for child in children {
                        guard rightEmitted < rightLimit, nodes.count < maxNodes else {
                            truncated = true
                            return
                        }
                        guard rightVisits < Self.maxSidebarVisits, context.canContinue, !context.isAborted else { return }
                        guard rightVisited.insert(child).inserted else { continue }
                        rightVisits += 1
                        guard let info = context.inspect(child),
                              !Self.ignoredChromeRoles.contains(info.role),
                              !hasZeroSize(info.handle) else { continue }
                        if let rawLabel = info.label, Self.rightSidebarChromeNoise.contains(rawLabel) {
                            continue
                        }
                        let isFocusNode = (context.focus == info.handle) || info.isFocused
                        switch info.role {
                        case "AXRadioButton", "AXTabButton", "AXButton", "AXCheckBox":
                            if let label = context.displayText(of: info.handle),
                               !isPrivateUseOnlyText(label),
                               !Self.rightSidebarChromeNoise.contains(label) {
                                if seen.insert(info.handle).inserted {
                                    nodes.append(makeNode(info, parent: emittedParent, role: "container", text: label))
                                    rightEmitted += 1
                                }
                            } else if info.childCount > 0 {
                                walkRightSidebar(info, emittedParent: emittedParent, parentText: parentText, depth: depth + 1)
                            }
                        case "AXHeading":
                            if let label = context.displayText(of: info.handle),
                               !isPrivateUseOnlyText(label),
                               !Self.rightSidebarChromeNoise.contains(label) {
                                if seen.insert(info.handle).inserted {
                                    nodes.append(makeNode(info, parent: emittedParent, role: "text", text: label))
                                    rightEmitted += 1
                                }
                            } else if info.childCount > 0 {
                                walkRightSidebar(info, emittedParent: emittedParent, parentText: parentText, depth: depth + 1)
                            }
                        case "AXComboBox", "AXPopUpButton":
                            var nextParent = emittedParent
                            var nextParentText = parentText
                            if let label = context.displayText(of: info.handle),
                               !isPrivateUseOnlyText(label),
                               !Self.rightSidebarChromeNoise.contains(label),
                               seen.insert(info.handle).inserted {
                                nodes.append(makeNode(info, parent: emittedParent, role: "container", text: label))
                                rightEmitted += 1
                                nextParent = info.handle
                                nextParentText = label
                            }
                            if info.childCount > 0 {
                                walkRightSidebar(info, emittedParent: nextParent, parentText: nextParentText, depth: depth + 1)
                            }
                        case "AXTextField", "AXTextArea":
                            guard let raw = context.text(of: info.handle) else { continue }
                            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                            guard isFocusNode || (!trimmed.isEmpty && !isPrivateUseOnlyText(trimmed)) else { continue }
                            if seen.insert(info.handle).inserted {
                                nodes.append(makeNode(info, parent: emittedParent, role: "editable", text: raw))
                                rightEmitted += 1
                            }
                        case "AXStaticText":
                            guard let raw = context.text(of: info.handle) else { continue }
                            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                            guard !trimmed.isEmpty,
                                  !isPrivateUseOnlyText(trimmed),
                                  !Self.rightSidebarChromeNoise.contains(trimmed),
                                  trimmed != parentText else { continue }
                            if seen.insert(info.handle).inserted {
                                nodes.append(makeNode(info, parent: emittedParent, role: "text", text: trimmed))
                                rightEmitted += 1
                            }
                        default:
                            if info.childCount > 0 {
                                walkRightSidebar(info, emittedParent: emittedParent, parentText: parentText, depth: depth + 1)
                            }
                        }
                    }
                }

                walkRightSidebar(rightSidebar, emittedParent: rightSidebar.handle, parentText: nil, depth: 0)
            }
        }
        if context.isAborted { return nil }

        // Zone 4: Left Sidebar (visible file header + in-viewport Pages and Layers items).
        if let leftSidebar,
           nodes.count < maxNodes,
           context.canContinue,
           seen.insert(leftSidebar.handle).inserted {
            let leftSidebarBounds = context.bounds(of: leftSidebar.handle)?.bounds
            nodes.append(makeNode(leftSidebar, parent: mainWebArea.handle, role: "container", text: context.displayText(of: leftSidebar.handle)))
            var leftVisits = 0
            var leftVisited: Set<AXNodeHandle> = [leftSidebar.handle]

            func isVisibleInLeftSidebar(_ handle: AXNodeHandle, isContainer: Bool) -> Bool {
                guard let rect = context.bounds(of: handle)?.bounds else { return true }
                guard rect.width > 0, rect.height > 1 else { return false }
                if let sidebarRect = leftSidebarBounds, rect.y >= sidebarRect.y + sidebarRect.height {
                    return false
                }
                return isContainer ? (rect.y + rect.height > 0) : (rect.y >= 0)
            }

            func walkLeftSidebar(_ parentInfo: AXNodeInfo, depth: Int) {
                guard nodes.count < maxNodes,
                      leftVisits < Self.maxSidebarVisits,
                      depth < Self.maxZoneDepth,
                      parentInfo.childCount > 0,
                      context.canContinue,
                      !context.isAborted else {
                    if parentInfo.childCount > 0 && nodes.count >= maxNodes { truncated = true }
                    return
                }
                let pageCap = ["AXColumn", "AXTable", "AXOutline", "AXList"].contains(parentInfo.role) ? 64 : 24
                let pageLimit = min(parentInfo.childCount, pageCap)
                if parentInfo.childCount > pageLimit { truncated = true }
                guard let children = context.children(of: parentInfo.handle, offset: 0, limit: pageLimit) else { return }
                for child in children {
                    guard nodes.count < maxNodes else {
                        truncated = true
                        return
                    }
                    guard leftVisits < Self.maxSidebarVisits, context.canContinue, !context.isAborted else { return }
                    guard leftVisited.insert(child).inserted else { continue }
                    leftVisits += 1
                    guard let info = context.inspect(child), !Self.ignoredChromeRoles.contains(info.role) else { continue }
                    if let rawLabel = info.label, Self.leftSidebarChromeNoise.contains(rawLabel) { continue }
                    let isItem = Self.leftSidebarItemRoles.contains(info.role)
                    guard isVisibleInLeftSidebar(info.handle, isContainer: !isItem) else { continue }
                    let isFocusNode = (context.focus == info.handle) || info.isFocused
                    switch info.role {
                    case "AXRow", "AXCell", "AXRadioButton", "AXTabButton", "AXButton":
                        if let label = context.displayText(of: info.handle),
                           !isPrivateUseOnlyText(label),
                           !Self.leftSidebarChromeNoise.contains(label) {
                            if seen.insert(info.handle).inserted {
                                nodes.append(makeNode(info, parent: leftSidebar.handle, role: "container", text: label))
                            }
                        } else if info.childCount > 0 {
                            walkLeftSidebar(info, depth: depth + 1)
                        }
                    case "AXHeading":
                        if let label = context.displayText(of: info.handle),
                           !isPrivateUseOnlyText(label),
                           !Self.leftSidebarChromeNoise.contains(label) {
                            if seen.insert(info.handle).inserted {
                                nodes.append(makeNode(info, parent: leftSidebar.handle, role: "text", text: label))
                            }
                        } else if info.childCount > 0 {
                            walkLeftSidebar(info, depth: depth + 1)
                        }
                    case "AXTextField", "AXTextArea":
                        guard let raw = context.text(of: info.handle) else { continue }
                        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard isFocusNode || (!trimmed.isEmpty && !isPrivateUseOnlyText(trimmed)) else { continue }
                        if seen.insert(info.handle).inserted {
                            nodes.append(makeNode(info, parent: leftSidebar.handle, role: "editable", text: raw))
                        }
                    case "AXStaticText":
                        guard let raw = context.text(of: info.handle) else { continue }
                        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !trimmed.isEmpty,
                              !isPrivateUseOnlyText(trimmed),
                              !Self.leftSidebarChromeNoise.contains(trimmed) else { continue }
                        if seen.insert(info.handle).inserted {
                            nodes.append(makeNode(info, parent: leftSidebar.handle, role: "text", text: trimmed))
                        }
                    default:
                        if info.childCount > 0 {
                            walkLeftSidebar(info, depth: depth + 1)
                        }
                    }
                }
            }

            walkLeftSidebar(leftSidebar, depth: 0)
        }
        if context.isAborted { return nil }

        return CustomSurfaceResult(nodes: nodes, complete: false, missingReasons: truncated ? ["tree-output-budget"] : [])
    }
}

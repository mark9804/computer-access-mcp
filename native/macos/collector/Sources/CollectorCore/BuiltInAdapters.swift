/// Built-in declarative application adapters shipped with `computer-access-collector`.
public struct GenericAdapter: AppAdapter {
    public let spec = AppAdapterSpec(
        id: "generic",
        displayName: "Generic Desktop Adapter",
        matchBundleIds: [],
        activation: .none,
        windowAnchor: .focusedOnly,
        staticTextProbe: .standard,
        preferredRoles: ["AXTextArea", "AXTextField", "AXStaticText", "AXWebArea"],
        ignoredRoles: ["AXMenuBar", "AXMenu", "AXScrollBar"],
        pageSize: 8,
        maxNodeTextUnits: 128
    )

    public init() {}
}

public struct VSCodeFamilyAdapter: AppAdapter {
    public let spec = AppAdapterSpec(
        id: "vscode-family",
        displayName: "VSCode & Electron Editors",
        matchBundleIds: [
            "com.google.antigravity",
            "com.google.antigravity-ide",
            "com.microsoft.VSCode",
            "com.microsoft.VSCodeInsiders",
            "com.todesktop.230313mzl4w4u92",
            "com.exafunction.windsurf",
        ],
        activation: .manualAccessibility,
        windowAnchor: .allowUnfocusedWindow,
        staticTextProbe: .standard,
        preferredRoles: ["AXTextArea", "AXWebArea", "AXDocument", "AXScrollArea", "AXTextField", "AXStaticText"],
        ignoredRoles: ["AXMenuBar", "AXMenu", "AXMenuItem", "AXToolbar", "AXScrollBar"],
        pageSize: 16,
        maxNodeTextUnits: 256
    )

    public init() {}
}

public struct BrowserFamilyAdapter: AppAdapter {
    public let spec = AppAdapterSpec(
        id: "browser-family",
        displayName: "Web Browsers (Chromium & Firefox)",
        matchBundleIds: [
            "com.google.Chrome",
            "com.google.Chrome.canary",
            "org.chromium.Chromium",
            "com.brave.Browser",
            "com.microsoft.edgemac",
            "company.thebrowser.Browser",
            "company.thebrowser.browser",
            "company.thebrowser.dia",
            "com.vivaldi.Vivaldi",
            "com.operasoftware.Opera",
            "org.mozilla.firefox",
            "org.mozilla.nightly",
            "app.zen-browser.zen",
            "app.floorp.Floorp",
            "ai.perplexity.comet",
            "com.openai.atlas",
            "net.imput.helium",
        ],
        activation: .manualAccessibility,
        windowAnchor: .allowUnfocusedWindow,
        staticTextProbe: .standard,
        preferredRoles: ["AXWebArea", "AXDocument", "AXHeading", "AXStaticText", "AXTextArea", "AXTextField", "AXLink", "AXScrollArea"],
        ignoredRoles: ["AXMenuBar", "AXMenu", "AXMenuItem", "AXScrollBar"],
        pageSize: 16,
        maxNodeTextUnits: 256,
        blockPrivateWindows: true
    )

    public init() {}
}

public struct TerminalFamilyAdapter: AppAdapter {
    public let spec = AppAdapterSpec(
        id: "terminal-family",
        displayName: "Terminals & CLI",
        matchBundleIds: [
            "com.apple.Terminal",
            "com.googlecode.iterm2",
            "com.mitchellh.ghostty",
            "dev.warp.Warp-Stable",
            "net.kovidgoyal.kitty",
            "com.github.wez.wezterm",
            "com.raphaelamorim.rio",
            "dev.commandline.waveterm",
        ],
        activation: .none,
        windowAnchor: .allowTopLevelFallback,
        staticTextProbe: .standard,
        preferredRoles: ["AXTextArea", "AXScrollArea", "AXStaticText", "AXTextField"],
        ignoredRoles: ["AXMenuBar", "AXMenu", "AXScrollBar"],
        pageSize: 16,
        maxNodeTextUnits: 1024
    )

    public init() {}
}

public struct QQAdapter: AppAdapter {
    public let spec = AppAdapterSpec(
        id: "qq",
        displayName: "Tencent QQ",
        matchBundleIds: ["com.tencent.qq"],
        activation: .none,
        windowAnchor: .allowUnfocusedWindow,
        staticTextProbe: .boundedRangeProbe(maxUnits: 256),
        preferredRoles: ["AXWebArea", "AXList", "AXTable", "AXRow", "AXScrollArea", "AXStaticText", "AXTextArea", "AXTextField"],
        ignoredRoles: ["AXMenuBar", "AXMenu", "AXScrollBar"],
        pageSize: 16,
        maxNodeTextUnits: 256
    )

    public init() {}
}

public struct FeishuAdapter: AppAdapter {
    public let spec = AppAdapterSpec(
        id: "feishu",
        displayName: "Feishu / Lark",
        matchBundleIds: ["com.electron.lark", "com.bytedance.feishu"],
        activation: .manualAccessibility,
        windowAnchor: .allowUnfocusedWindow,
        staticTextProbe: .boundedRangeProbe(maxUnits: 256),
        preferredRoles: ["AXWebArea", "AXList", "AXScrollArea", "AXStaticText", "AXTextArea", "AXTextField"],
        ignoredRoles: ["AXMenuBar", "AXMenu", "AXScrollBar"],
        pageSize: 16,
        maxNodeTextUnits: 256
    )

    public init() {}
}

public struct WeChatAdapter: AppAdapter {
    public let spec = AppAdapterSpec(
        id: "wechat",
        displayName: "WeChat",
        matchBundleIds: ["com.tencent.xinWeChat"],
        activation: .none,
        windowAnchor: .allowUnfocusedWindow,
        staticTextProbe: .boundedRangeProbe(maxUnits: 256),
        preferredRoles: ["AXList", "AXTable", "AXRow", "AXScrollArea", "AXStaticText", "AXTextArea", "AXTextField"],
        ignoredRoles: ["AXMenuBar", "AXMenu", "AXScrollBar"],
        pageSize: 16,
        maxNodeTextUnits: 256
    )

    private static let tailMessageLimit = 32
    private static let maxLocatorDepth = 12
    private static let maxLocatorVisits = 80
    private static let skippedContainerRoles: Set<String> = [
        "AXButton", "AXToolbar", "AXMenuBar", "AXMenu", "AXMenuItem",
        "AXScrollBar", "AXImage", "AXTable", "AXOutline",
    ]

    public init() {}

    public func extractSurface(context: SafeAXContext) -> CustomSurfaceResult? {
        guard let rootInfo = context.inspect(context.root) else { return nil }

        var chatNameInfo: AXNodeInfo?
        var fallbackTitleInfo: AXNodeInfo?
        var messageListInfo: AXNodeInfo?
        var inputInfo: AXNodeInfo?

        // Check focused handle first when it directly identifies the chat input field.
        if let focus = context.focus, let focusInfo = context.inspect(focus) {
            if focusInfo.identifier == "chat_input_field" {
                inputInfo = focusInfo
            }
        }
        if context.isAborted { return nil }

        // Shallow BFS locating right chat pane elements while skipping left nav and session_list.
        var queue: [(handle: AXNodeHandle, depth: Int)] = [(context.root, 0)]
        var visited: Set<AXNodeHandle> = [context.root]
        var cursor = 0
        var inspectedCount = 1

        while cursor < queue.count,
              inspectedCount < Self.maxLocatorVisits,
              context.canContinue,
              !(chatNameInfo != nil && messageListInfo != nil && inputInfo != nil) {
            let entry = queue[cursor]
            cursor += 1
            let info: AXNodeInfo
            if entry.handle == context.root {
                info = rootInfo
            } else {
                inspectedCount += 1
                guard let fresh = context.inspect(entry.handle) else { continue }
                info = fresh
            }
            if info.identifier == "session_list" || info.identifier == "virtual_cell" { continue }
            if entry.handle != context.root, Self.skippedContainerRoles.contains(info.role) { continue }

            switch info.identifier {
            case "current_chat_name_label":
                chatNameInfo = info
                continue
            case "big_title_line_h_view":
                if info.role == "AXStaticText" {
                    fallbackTitleInfo = info
                    // Qt header views may expose current_chat_name_label as a child of AXStaticText.
                    if chatNameInfo == nil, let nested = context.children(of: entry.handle, offset: 0, limit: 8) {
                        for child in nested where visited.insert(child).inserted {
                            queue.append((child, entry.depth + 1))
                        }
                    }
                    continue
                }
            case "chat_message_list":
                messageListInfo = info
                continue
            case "chat_input_field":
                inputInfo = info
                continue
            default:
                break
            }

            if chatNameInfo != nil && messageListInfo != nil && inputInfo != nil { break }
            guard entry.depth < Self.maxLocatorDepth,
                  info.childCount > 0,
                  info.role != "AXList",
                  info.role != "AXStaticText",
                  info.role != "AXTextArea",
                  info.role != "AXTextField" else { continue }

            guard let children = context.children(of: entry.handle, offset: 0, limit: min(info.childCount, 32)) else { continue }
            for child in children where visited.insert(child).inserted {
                queue.append((child, entry.depth + 1))
            }
        }

        if context.isAborted { return nil }

        // Accept focused AXTextArea as input fallback only when chat_message_list confirms chat UI.
        if inputInfo == nil, messageListInfo != nil,
           let focus = context.focus, let focusInfo = context.inspect(focus), focusInfo.role == "AXTextArea" {
            inputInfo = focusInfo
        }
        if context.isAborted { return nil }

        // Fall back to standard weighted traversal if neither chat list nor chat input is present.
        guard messageListInfo != nil || inputInfo != nil else { return nil }

        let maxNodes = min(96, max(1, context.maxOutputNodes))
        var seen: Set<AXNodeHandle> = [context.root]
        var focusAssigned = false
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

        var nodes: [CustomSurfaceNode] = [makeNode(rootInfo, parent: nil, role: "container", text: nil)]

        if let titleInfo = chatNameInfo ?? fallbackTitleInfo,
           nodes.count < maxNodes,
           seen.insert(titleInfo.handle).inserted,
           let titleText = context.text(of: titleInfo.handle),
           !titleText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            nodes.append(makeNode(titleInfo, parent: context.root, role: "text", text: titleText))
        }

        let reserveInputSlot = (inputInfo != nil && !seen.contains(inputInfo!.handle)) ? 1 : 0
        var truncatedTail = false

        if let listInfo = messageListInfo, nodes.count + reserveInputSlot < maxNodes {
            let listParentReady = listInfo.handle == context.root || seen.insert(listInfo.handle).inserted
            if listParentReady {
                if listInfo.handle != context.root {
                    nodes.append(makeNode(listInfo, parent: context.root, role: "container", text: nil))
                }
                let messageSlots = max(0, maxNodes - nodes.count - reserveInputSlot)
                let tailLimit = min(Self.tailMessageLimit, listInfo.childCount)
                if listInfo.childCount > tailLimit { truncatedTail = true }
                if tailLimit > 0, messageSlots > 0, context.canContinue {
                    let tailOffset = max(0, listInfo.childCount - tailLimit)
                    if let tailChildren = context.children(of: listInfo.handle, offset: tailOffset, limit: tailLimit) {
                        var collected: [CustomSurfaceNode] = []
                        func appendTextLeaf(_ info: AXNodeInfo) {
                            guard collected.count < messageSlots, seen.insert(info.handle).inserted,
                                  let body = context.text(of: info.handle),
                                  !body.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
                            collected.append(makeNode(info, parent: listInfo.handle, role: "text", text: body))
                        }
                        for child in tailChildren.reversed() {
                            guard collected.count < messageSlots, context.canContinue else {
                                truncatedTail = true
                                break
                            }
                            guard let childInfo = context.inspect(child),
                                  childInfo.identifier != "virtual_cell",
                                  !hasZeroSize(child) else { continue }
                            if childInfo.role == "AXStaticText" {
                                appendTextLeaf(childInfo)
                            } else if childInfo.childCount > 0, !Self.skippedContainerRoles.contains(childInfo.role) {
                                // Bounded unwrap for container-wrapped message cells (up to 8 children).
                                guard let nested = context.children(of: child, offset: 0, limit: min(childInfo.childCount, 8)) else { continue }
                                for sub in nested.reversed() {
                                    guard collected.count < messageSlots, context.canContinue else {
                                        truncatedTail = true
                                        break
                                    }
                                    guard let subInfo = context.inspect(sub),
                                          subInfo.identifier != "virtual_cell",
                                          subInfo.role == "AXStaticText",
                                          !hasZeroSize(sub) else { continue }
                                    appendTextLeaf(subInfo)
                                }
                            }
                        }
                        nodes.append(contentsOf: collected.reversed())
                    }
                }
            }
        }

        if let inputInfo, nodes.count < maxNodes, seen.insert(inputInfo.handle).inserted {
            let draft = context.text(of: inputInfo.handle)
            nodes.append(makeNode(inputInfo, parent: context.root, role: "editable", text: draft))
        }

        if context.isAborted { return nil }
        return CustomSurfaceResult(nodes: nodes, complete: false, missingReasons: truncatedTail ? ["tree-output-budget"] : [])
    }
}

public struct SlackAdapter: AppAdapter {
    public let spec = AppAdapterSpec(
        id: "slack",
        displayName: "Slack",
        matchBundleIds: ["com.tinyspeck.slackmacgap"],
        activation: .manualAccessibility,
        windowAnchor: .allowUnfocusedWindow,
        staticTextProbe: .boundedRangeProbe(maxUnits: 256),
        preferredRoles: ["AXWebArea", "AXList", "AXScrollArea", "AXStaticText", "AXTextArea", "AXTextField"],
        ignoredRoles: ["AXMenuBar", "AXMenu", "AXScrollBar"],
        pageSize: 16,
        maxNodeTextUnits: 256
    )

    public init() {}
}

public struct TyporaAdapter: AppAdapter {
    public let spec = AppAdapterSpec(
        id: "typora",
        displayName: "Typora",
        matchBundleIds: ["abnerworks.Typora"],
        activation: .enhancedUI,
        windowAnchor: .allowUnfocusedWindow,
        staticTextProbe: .standard,
        preferredRoles: ["AXWebArea", "AXDocument", "AXTextArea", "AXHeading", "AXStaticText", "AXTextField", "AXScrollArea"],
        ignoredRoles: ["AXMenuBar", "AXMenu", "AXMenuItem", "AXToolbar", "AXScrollBar"],
        pageSize: 16,
        maxNodeTextUnits: 512
    )

    public init() {}
}

public enum BuiltInAdapters {
    public static let specialized: [any AppAdapter] = [
        VSCodeFamilyAdapter(),
        BrowserFamilyAdapter(),
        TerminalFamilyAdapter(),
        QQAdapter(),
        FeishuAdapter(),
        WeChatAdapter(),
        SlackAdapter(),
        TyporaAdapter(),
    ]

    public static let all: [any AppAdapter] = [GenericAdapter()] + specialized
}

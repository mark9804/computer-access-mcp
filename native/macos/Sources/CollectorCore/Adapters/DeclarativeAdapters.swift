/// Built-in declarative application adapters shipped with `computer-history-collector`.
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
        staticTextProbe: .boundedRangeProbe(maxUnits: 256),
        preferredRoles: [
            "AXTextArea",
            "AXWebArea",
            "AXDocument",
            "AXTabGroup",
            "AXTabButton",
            "AXRadioButton",
            "AXHeading",
            "AXScrollArea",
            "AXTextField",
            "AXStaticText",
        ],
        ignoredRoles: ["AXMenuBar", "AXMenu", "AXMenuItem", "AXToolbar", "AXScrollBar"],
        ignoredSubroles: ["AXApplicationStatus"],
        pageSize: 16,
        maxNodeTextUnits: 256,
        collapseEmptyContainers: true
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

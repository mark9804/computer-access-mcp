//! Built-in declarative `AppAdapterSpec` definitions and `DeclarativeAdapter` instances.
//!
//! Each adapter here delegates surface extraction to `WeightedSurfaceTraversal` through the
//! kernel-enforced `SafeSurfaceContext` boundary.

use super::{
    ActivationMode, AppAdapterSpec, DeclarativeAdapter, StaticTextPolicy, WindowAnchorPolicy,
};

pub const GENERIC_ADAPTER_SPEC: AppAdapterSpec = AppAdapterSpec {
    id: "generic",
    display_name: "Generic Desktop Adapter",
    match_application_ids: &[],
    activation: ActivationMode::None,
    window_anchor: WindowAnchorPolicy::FocusedOnly,
    static_text_probe: StaticTextPolicy::Standard,
    preferred_roles: &["AXTextArea", "AXTextField", "AXStaticText", "AXWebArea"],
    ignored_roles: &["AXMenuBar", "AXMenu", "AXScrollBar"],
    ignored_subroles: &[],
    page_size: 8,
    max_node_text_units: 128,
    block_private_windows: false,
    collapse_empty_containers: false,
    expand_text_wrapper_ids: &[],
};

pub const VSCODE_FAMILY_SPEC: AppAdapterSpec = AppAdapterSpec {
    id: "vscode-family",
    display_name: "VSCode & Electron Editors",
    match_application_ids: &[
        "com.google.antigravity",
        "com.google.antigravity-ide",
        "com.microsoft.vscode",
        "com.microsoft.vscodeinsiders",
        "com.todesktop.230313mzl4w4u92",
        "com.exafunction.windsurf",
        "antigravity.exe",
        "antigravityide.exe",
        "code.exe",
        "code-insiders.exe",
        "cursor.exe",
        "windsurf.exe",
    ],
    activation: ActivationMode::ManualAccessibility,
    window_anchor: WindowAnchorPolicy::AllowUnfocusedWindow,
    static_text_probe: StaticTextPolicy::BoundedRangeProbe { max_units: 256 },
    preferred_roles: &[
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
    ignored_roles: &["AXMenuBar", "AXMenu", "AXMenuItem", "AXToolbar", "AXScrollBar"],
    ignored_subroles: &["AXApplicationStatus"],
    page_size: 16,
    max_node_text_units: 256,
    block_private_windows: false,
    collapse_empty_containers: true,
    expand_text_wrapper_ids: &[],
};

pub const BROWSER_FAMILY_SPEC: AppAdapterSpec = AppAdapterSpec {
    id: "browser-family",
    display_name: "Web Browsers (Chromium & Firefox)",
    match_application_ids: &[
        "com.google.chrome",
        "com.google.chrome.canary",
        "org.chromium.chromium",
        "com.brave.browser",
        "com.microsoft.edgemac",
        "company.thebrowser.browser",
        "company.thebrowser.dia",
        "com.vivaldi.vivaldi",
        "com.operasoftware.opera",
        "org.mozilla.firefox",
        "org.mozilla.nightly",
        "app.zen-browser.zen",
        "app.floorp.floorp",
        "ai.perplexity.comet",
        "com.openai.atlas",
        "net.imput.helium",
        "chrome.exe",
        "chromium.exe",
        "msedge.exe",
        "brave.exe",
        "vivaldi.exe",
        "opera.exe",
        "firefox.exe",
        "zen.exe",
        "floorp.exe",
        "arc.exe",
        "dia.exe",
        "comet.exe",
    ],
    activation: ActivationMode::ManualAccessibility,
    window_anchor: WindowAnchorPolicy::AllowUnfocusedWindow,
    static_text_probe: StaticTextPolicy::Standard,
    preferred_roles: &[
        "AXWebArea",
        "AXDocument",
        "AXHeading",
        "AXStaticText",
        "AXTextArea",
        "AXTextField",
        "AXLink",
        "AXScrollArea",
    ],
    ignored_roles: &["AXMenuBar", "AXMenu", "AXMenuItem", "AXScrollBar"],
    ignored_subroles: &[],
    page_size: 16,
    max_node_text_units: 256,
    block_private_windows: true,
    collapse_empty_containers: true,
    expand_text_wrapper_ids: &[],
};

pub const TERMINAL_FAMILY_SPEC: AppAdapterSpec = AppAdapterSpec {
    id: "terminal-family",
    display_name: "Terminals & CLI",
    match_application_ids: &[
        "com.apple.terminal",
        "com.googlecode.iterm2",
        "com.mitchellh.ghostty",
        "dev.warp.warp-stable",
        "net.kovidgoyal.kitty",
        "com.github.wez.wezterm",
        "com.raphaelamorim.rio",
        "dev.commandline.waveterm",
        "windowsterminal.exe",
        "microsoft.windowsterminal",
        "wt.exe",
        "wezterm-gui.exe",
        "alacritty.exe",
        "warp.exe",
        "waveterm.exe",
        "rio.exe",
        "conhost.exe",
        "mintty.exe",
    ],
    activation: ActivationMode::None,
    window_anchor: WindowAnchorPolicy::AllowTopLevelFallback,
    static_text_probe: StaticTextPolicy::Standard,
    preferred_roles: &["AXTextArea", "AXScrollArea", "AXStaticText", "AXTextField"],
    ignored_roles: &["AXMenuBar", "AXMenu", "AXScrollBar"],
    ignored_subroles: &[],
    page_size: 16,
    max_node_text_units: 1024,
    block_private_windows: false,
    collapse_empty_containers: false,
    expand_text_wrapper_ids: &[],
};

pub const QQ_ADAPTER_SPEC: AppAdapterSpec = AppAdapterSpec {
    id: "qq",
    display_name: "Tencent QQ",
    match_application_ids: &["com.tencent.qq", "qq.exe"],
    activation: ActivationMode::ManualAccessibility,
    window_anchor: WindowAnchorPolicy::AllowUnfocusedWindow,
    static_text_probe: StaticTextPolicy::BoundedRangeProbe { max_units: 256 },
    preferred_roles: &[
        "AXWebArea",
        "AXList",
        "AXTable",
        "AXRow",
        "AXScrollArea",
        "AXStaticText",
        "AXTextArea",
        "AXTextField",
    ],
    ignored_roles: &["AXMenuBar", "AXMenu", "AXScrollBar"],
    ignored_subroles: &[],
    page_size: 16,
    max_node_text_units: 256,
    block_private_windows: false,
    collapse_empty_containers: false,
    expand_text_wrapper_ids: &[],
};

pub const FEISHU_ADAPTER_SPEC: AppAdapterSpec = AppAdapterSpec {
    id: "feishu",
    display_name: "Feishu / Lark",
    match_application_ids: &[
        "com.electron.lark",
        "com.bytedance.feishu",
        "feishu.exe",
        "lark.exe",
    ],
    activation: ActivationMode::ManualAccessibility,
    window_anchor: WindowAnchorPolicy::AllowUnfocusedWindow,
    static_text_probe: StaticTextPolicy::BoundedRangeProbe { max_units: 256 },
    preferred_roles: &[
        "AXWebArea",
        "AXList",
        "AXScrollArea",
        "AXStaticText",
        "AXTextArea",
        "AXTextField",
    ],
    ignored_roles: &["AXMenuBar", "AXMenu", "AXScrollBar"],
    ignored_subroles: &[],
    page_size: 16,
    max_node_text_units: 256,
    block_private_windows: false,
    collapse_empty_containers: true,
    expand_text_wrapper_ids: &[],
};

pub const SLACK_ADAPTER_SPEC: AppAdapterSpec = AppAdapterSpec {
    id: "slack",
    display_name: "Slack",
    match_application_ids: &["com.tinyspeck.slackmacgap", "slack.exe", "91750d7e.slack"],
    activation: ActivationMode::ManualAccessibility,
    window_anchor: WindowAnchorPolicy::AllowUnfocusedWindow,
    static_text_probe: StaticTextPolicy::BoundedRangeProbe { max_units: 256 },
    preferred_roles: &[
        "AXWebArea",
        "AXList",
        "AXScrollArea",
        "AXStaticText",
        "AXTextArea",
        "AXTextField",
    ],
    ignored_roles: &["AXMenuBar", "AXMenu", "AXScrollBar"],
    ignored_subroles: &[],
    page_size: 16,
    max_node_text_units: 256,
    block_private_windows: false,
    collapse_empty_containers: true,
    expand_text_wrapper_ids: &[],
};

pub const TYPORA_ADAPTER_SPEC: AppAdapterSpec = AppAdapterSpec {
    id: "typora",
    display_name: "Typora",
    match_application_ids: &["abnerworks.typora", "typora.exe"],
    activation: ActivationMode::EnhancedUi,
    window_anchor: WindowAnchorPolicy::AllowUnfocusedWindow,
    static_text_probe: StaticTextPolicy::Standard,
    preferred_roles: &[
        "AXWebArea",
        "AXDocument",
        "AXTextArea",
        "AXHeading",
        "AXStaticText",
        "AXTextField",
        "AXScrollArea",
    ],
    ignored_roles: &["AXMenuBar", "AXMenu", "AXMenuItem", "AXToolbar", "AXScrollBar"],
    ignored_subroles: &[],
    page_size: 16,
    max_node_text_units: 512,
    block_private_windows: false,
    collapse_empty_containers: false,
    expand_text_wrapper_ids: &[],
};

pub static GENERIC_ADAPTER: DeclarativeAdapter = DeclarativeAdapter {
    spec: &GENERIC_ADAPTER_SPEC,
};
pub static VSCODE_FAMILY_ADAPTER: DeclarativeAdapter = DeclarativeAdapter {
    spec: &VSCODE_FAMILY_SPEC,
};
pub static BROWSER_FAMILY_ADAPTER: DeclarativeAdapter = DeclarativeAdapter {
    spec: &BROWSER_FAMILY_SPEC,
};
pub static TERMINAL_FAMILY_ADAPTER: DeclarativeAdapter = DeclarativeAdapter {
    spec: &TERMINAL_FAMILY_SPEC,
};
pub static QQ_ADAPTER: DeclarativeAdapter = DeclarativeAdapter {
    spec: &QQ_ADAPTER_SPEC,
};
pub static FEISHU_ADAPTER: DeclarativeAdapter = DeclarativeAdapter {
    spec: &FEISHU_ADAPTER_SPEC,
};
pub static SLACK_ADAPTER: DeclarativeAdapter = DeclarativeAdapter {
    spec: &SLACK_ADAPTER_SPEC,
};
pub static TYPORA_ADAPTER: DeclarativeAdapter = DeclarativeAdapter {
    spec: &TYPORA_ADAPTER_SPEC,
};

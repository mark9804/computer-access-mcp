use std::collections::{HashMap, HashSet};

use access_contract::utf16_len;

use crate::policy::{is_private_use_only_text, ApplicationPolicy, ResolvedAppIdentity};
use crate::protocol_model::bounded_utf16_slice;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationMode {
    None,
    ManualAccessibility,
    EnhancedUi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowAnchorPolicy {
    FocusedOnly,
    AllowTopLevelFallback,
    AllowUnfocusedWindow,
}

impl WindowAnchorPolicy {
    pub fn allows_top_level_fallback(self) -> bool {
        matches!(self, Self::AllowTopLevelFallback | Self::AllowUnfocusedWindow)
    }

    pub fn allows_unfocused_window(self) -> bool {
        self == Self::AllowUnfocusedWindow
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticTextPolicy {
    Standard,
    BoundedRangeProbe { max_units: usize },
}

/// Declarative per-application adapter specification covering surface traversal tuning and security defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAdapterSpec {
    pub id: &'static str,
    pub display_name: &'static str,
    pub match_application_ids: &'static [&'static str],
    pub activation: ActivationMode,
    pub window_anchor: WindowAnchorPolicy,
    pub static_text_probe: StaticTextPolicy,
    pub preferred_roles: &'static [&'static str],
    pub ignored_roles: &'static [&'static str],
    pub ignored_subroles: &'static [&'static str],
    pub page_size: usize,
    pub max_node_text_units: usize,
    pub block_private_windows: bool,
    pub collapse_empty_containers: bool,
}

impl AppAdapterSpec {
    pub fn ignores_role(&self, role: &str) -> bool {
        self.ignored_roles.contains(&role)
    }

    pub fn ignores_subrole(&self, subrole: &str) -> bool {
        self.ignored_subroles.contains(&subrole)
    }

    pub fn prefers_role(&self, role: &str) -> bool {
        self.preferred_roles.contains(&role)
    }
}

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
};

pub const QQ_ADAPTER_SPEC: AppAdapterSpec = AppAdapterSpec {
    id: "qq",
    display_name: "Tencent QQ",
    match_application_ids: &["com.tencent.qq", "qq.exe"],
    activation: ActivationMode::None,
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
};

pub const WECHAT_ADAPTER_SPEC: AppAdapterSpec = AppAdapterSpec {
    id: "wechat",
    display_name: "WeChat",
    match_application_ids: &["com.tencent.xinwechat", "wechat.exe", "weixin.exe"],
    activation: ActivationMode::None,
    window_anchor: WindowAnchorPolicy::AllowUnfocusedWindow,
    static_text_probe: StaticTextPolicy::BoundedRangeProbe { max_units: 256 },
    preferred_roles: &[
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
};

pub const FIGMA_ADAPTER_SPEC: AppAdapterSpec = AppAdapterSpec {
    id: "figma",
    display_name: "Figma",
    match_application_ids: &["com.figma.desktop", "figma.exe"],
    activation: ActivationMode::EnhancedUi,
    window_anchor: WindowAnchorPolicy::AllowUnfocusedWindow,
    static_text_probe: StaticTextPolicy::BoundedRangeProbe { max_units: 256 },
    preferred_roles: &[
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
    ignored_roles: &[
        "AXMenuBar",
        "AXMenu",
        "AXMenuItem",
        "AXToolbar",
        "AXScrollBar",
        "AXSlider",
    ],
    ignored_subroles: &[],
    page_size: 16,
    max_node_text_units: 256,
    block_private_windows: false,
    collapse_empty_containers: true,
};

pub const SPECIALIZED_ADAPTERS: &[&AppAdapterSpec] = &[
    &VSCODE_FAMILY_SPEC,
    &BROWSER_FAMILY_SPEC,
    &TERMINAL_FAMILY_SPEC,
    &QQ_ADAPTER_SPEC,
    &FEISHU_ADAPTER_SPEC,
    &WECHAT_ADAPTER_SPEC,
    &SLACK_ADAPTER_SPEC,
    &TYPORA_ADAPTER_SPEC,
    &FIGMA_ADAPTER_SPEC,
];

/// Case-insensitive adapter registry falling back to `GENERIC_ADAPTER_SPEC`.
pub struct AdapterRegistry {
    by_app_id: HashMap<String, &'static AppAdapterSpec>,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AdapterRegistry {
    pub fn new() -> Self {
        let mut by_app_id = HashMap::new();
        for &spec in SPECIALIZED_ADAPTERS {
            for &app_id in spec.match_application_ids {
                by_app_id
                    .entry(app_id.to_ascii_lowercase())
                    .or_insert(spec);
            }
        }
        Self { by_app_id }
    }

    pub fn adapter_for(&self, application_id: &str) -> &'static AppAdapterSpec {
        self.by_app_id
            .get(&application_id.to_ascii_lowercase())
            .copied()
            .unwrap_or(&GENERIC_ADAPTER_SPEC)
    }

    /// Dual-ID adapter lookup checking every identifier in `identity.candidate_ids()` in order
    /// before falling back to `GENERIC_ADAPTER_SPEC`, ensuring MSIX/AppX package names (e.g.
    /// `thebrowsercompany.arc` + `arc.exe`, `mozilla.firefox` + `firefox.exe`) always resolve to
    /// their specialized adapter (`browser-family` with `block_private_windows: true`).
    pub fn adapter_for_identity(&self, identity: &ResolvedAppIdentity) -> &'static AppAdapterSpec {
        for candidate in identity.candidate_ids() {
            if let Some(&spec) = self.by_app_id.get(&candidate.to_ascii_lowercase()) {
                return spec;
            }
        }
        if ApplicationPolicy::is_browser_identity(identity) {
            return &BROWSER_FAMILY_SPEC;
        }
        &GENERIC_ADAPTER_SPEC
    }

    pub fn is_terminal_app(&self, application_id: &str) -> bool {
        self.adapter_for(application_id).id == "terminal-family"
    }

    pub fn is_terminal_identity(&self, identity: &ResolvedAppIdentity) -> bool {
        self.adapter_for_identity(identity).id == "terminal-family"
    }

    pub fn all_ids() -> HashSet<&'static str> {
        let mut ids = HashSet::new();
        ids.insert(GENERIC_ADAPTER_SPEC.id);
        for &spec in SPECIALIZED_ADAPTERS {
            ids.insert(spec.id);
        }
        ids
    }
}

/// Bounded zero-extra-IPC display text composer for non-sensitive roles (excluding pure PUA icon glyphs).
pub struct SafeDisplayText;

impl SafeDisplayText {
    pub const ALLOWED_ROLES: &[&str] = &[
        "AXHeading",
        "AXLink",
        "AXButton",
        "AXTabButton",
        "AXRadioButton",
        "AXCell",
        "AXWebArea",
    ];

    fn clean(value: Option<&str>) -> Option<&str> {
        let trimmed = value?.trim();
        if trimmed.is_empty() || is_private_use_only_text(trimmed) {
            return None;
        }
        Some(trimmed)
    }

    pub fn compose(
        role: &str,
        title: Option<&str>,
        description: Option<&str>,
        url: Option<&str>,
        max_units: usize,
    ) -> Option<String> {
        if !Self::ALLOWED_ROLES.contains(&role) || max_units == 0 {
            return None;
        }
        let clean_title = Self::clean(title);
        let clean_desc = Self::clean(description);
        let clean_url = Self::clean(url);
        let raw: String = match role {
            "AXWebArea" => match (clean_title, clean_url) {
                (Some(t), Some(u)) => {
                    if t.contains(u) {
                        t.to_string()
                    } else {
                        format!("{t} ({u})")
                    }
                }
                (Some(t), None) => t.to_string(),
                (None, Some(u)) => u.to_string(),
                (None, None) => clean_desc?.to_string(),
            },
            "AXLink" => {
                let label = clean_title.or(clean_desc);
                match (label, clean_url) {
                    (Some(l), Some(u)) if l != u => format!("{l} ({u})"),
                    (Some(l), _) => l.to_string(),
                    (None, Some(u)) => u.to_string(),
                    (None, None) => return None,
                }
            }
            _ => clean_title.or(clean_desc).or(clean_url)?.to_string(),
        };
        if raw.is_empty() {
            return None;
        }
        let len = utf16_len(&raw).min(max_units);
        let bounded = bounded_utf16_slice(&raw, 0, len)?;
        (!bounded.is_empty()).then_some(bounded)
    }

    pub fn label(title: Option<&str>, description: Option<&str>, max_units: usize) -> Option<String> {
        if max_units == 0 {
            return None;
        }
        let raw = Self::clean(title).or_else(|| Self::clean(description))?;
        let len = utf16_len(raw).min(max_units);
        let bounded = bounded_utf16_slice(raw, 0, len)?;
        (!bounded.is_empty()).then_some(bounded)
    }
}

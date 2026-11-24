//! Two-tier Windows `AppAdapter` contract, declarative/custom registry, and display-text helpers.
//!
//! Submodules maintain strictly acyclic imports and Rust module-privacy boundaries:
//! - [`kernel`] owns `KernelSurfaceContext`, `SurfaceCaptureRunner`, and `validate_custom_result`,
//!   keeping all internal security and budget state strictly module-private inside `kernel.rs`.
//! - [`declarative`], [`wechat`], and [`figma`] depend only on the public contract types in this
//!   module and never import [`kernel`] or one another.

use std::collections::{HashMap, HashSet};

use access_contract::utf16_len;

use crate::policy::{is_private_use_only_text, ApplicationPolicy, ResolvedAppIdentity};
use crate::protocol_model::{bounded_utf16_slice, SurfaceBounds};

pub mod declarative;
pub mod figma;
pub mod kernel;
pub mod wechat;

pub use declarative::{
    BROWSER_FAMILY_ADAPTER, BROWSER_FAMILY_SPEC, FEISHU_ADAPTER, FEISHU_ADAPTER_SPEC,
    GENERIC_ADAPTER, GENERIC_ADAPTER_SPEC, QQ_ADAPTER, QQ_ADAPTER_SPEC, SLACK_ADAPTER,
    SLACK_ADAPTER_SPEC, TERMINAL_FAMILY_ADAPTER, TERMINAL_FAMILY_SPEC, TYPORA_ADAPTER,
    TYPORA_ADAPTER_SPEC, VSCODE_FAMILY_ADAPTER, VSCODE_FAMILY_SPEC,
};
pub use figma::{FigmaAdapter, FIGMA_ADAPTER, FIGMA_ADAPTER_SPEC};
pub use wechat::{WeChatAdapter, WECHAT_ADAPTER, WECHAT_ADAPTER_SPEC};

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
    pub expand_text_wrapper_ids: &'static [&'static str],
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

    /// Returns `true` when a readable-text-role wrapper with `identifier` should still have its
    /// children probed. Matches either an exact identifier (`"big_title_line_h_view"`) or the
    /// final `.`-delimited segment of a hierarchical AutomationId path
    /// (`"MainWindow.centralWidget.big_title_line_h_view"`).
    pub fn expands_text_wrapper_id(&self, identifier: Option<&str>) -> bool {
        if self.expand_text_wrapper_ids.is_empty() {
            return false;
        }
        let Some(id) = identifier else {
            return false;
        };
        let suffix = id.rsplit('.').next();
        self.expand_text_wrapper_ids
            .iter()
            .any(|&target| id == target || suffix == Some(target))
    }
}

/// Opaque handle indexing an interned element inside the active surface capture store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SurfaceHandle(pub usize);

/// Safe pre-gated node metadata exposed to custom `AppAdapter` extractors.
///
/// INVARIANT: Never constructed or cached for sensitive (`AXSecureTextField`, `IsPassword == true`,
/// or sensitive subrole) elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterNodeInfo {
    pub handle: SurfaceHandle,
    pub role: String,
    pub subrole: Option<String>,
    pub child_count: usize,
    pub is_focused: bool,
    pub observed_at_ms: i64,
    pub identifier: Option<String>,
    pub class_name: Option<String>,
    pub label: Option<String>,
    pub is_offscreen: bool,
}

/// One node emitted by a custom `AppAdapter` prior to kernel graph validation & materialization.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomSurfaceNode {
    pub handle: SurfaceHandle,
    pub parent: Option<SurfaceHandle>,
    pub role: &'static str,
    pub ax_role: Option<String>,
    pub text: Option<String>,
    pub is_focused: bool,
    pub observed_at_ms: i64,
    pub bounds: Option<SurfaceBounds>,
    pub bounds_observed_at_ms: Option<i64>,
}

/// Output returned by `AppAdapter::extract_surface`.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomSurfaceResult {
    pub nodes: Vec<CustomSurfaceNode>,
    pub complete: bool,
    pub missing_reasons: Vec<String>,
}

/// Kernel-enforced surface read context passed to custom `AppAdapter` extractors.
pub trait SafeSurfaceContext {
    fn spec(&self) -> &'static AppAdapterSpec;
    fn scope(&self) -> &str;
    fn max_output_nodes(&self) -> usize;
    fn window_size(&self) -> Option<(f64, f64)>;
    fn root(&self) -> SurfaceHandle;
    fn focus(&self) -> Option<SurfaceHandle>;
    fn is_aborted(&self) -> bool;
    fn can_continue(&self) -> bool;
    fn has_inspected(&self, handle: SurfaceHandle) -> bool;
    fn inspect(&mut self, handle: SurfaceHandle) -> Option<AdapterNodeInfo>;
    fn children(
        &mut self,
        handle: SurfaceHandle,
        offset: usize,
        limit: usize,
    ) -> Option<Vec<SurfaceHandle>>;
    fn last_children_truncated(&self) -> bool;
    fn tail_children(&mut self, handle: SurfaceHandle, limit: usize) -> Option<Vec<SurfaceHandle>>;
    fn text(&mut self, handle: SurfaceHandle, max_units: Option<usize>) -> Option<String>;
    fn display_text(&mut self, handle: SurfaceHandle) -> Option<String>;
    fn bounds(&mut self, handle: SurfaceHandle) -> Option<(SurfaceBounds, i64)>;
    fn note_missing_reason(&mut self, reason: &'static str);
}

/// Trait implemented by built-in declarative and custom application adapters.
pub trait AppAdapter: Sync {
    fn spec(&self) -> &'static AppAdapterSpec;

    fn has_custom_extractor(&self) -> bool {
        false
    }

    fn extract_surface(&self, _ctx: &mut dyn SafeSurfaceContext) -> Option<CustomSurfaceResult> {
        None
    }
}

/// Declarative-only adapter delegating surface extraction to `WeightedSurfaceTraversal`.
pub struct DeclarativeAdapter {
    pub spec: &'static AppAdapterSpec,
}

impl AppAdapter for DeclarativeAdapter {
    fn spec(&self) -> &'static AppAdapterSpec {
        self.spec
    }
}

/// Single source-of-truth list of all specialized built-in adapters, mirroring macOS
/// `BuiltInAdapters.specialized` (`GENERIC_ADAPTER` is the fallback).
pub const BUILT_IN_SPECIALIZED_ADAPTERS: &[&'static dyn AppAdapter] = &[
    &VSCODE_FAMILY_ADAPTER,
    &BROWSER_FAMILY_ADAPTER,
    &TERMINAL_FAMILY_ADAPTER,
    &QQ_ADAPTER,
    &FEISHU_ADAPTER,
    &WECHAT_ADAPTER,
    &SLACK_ADAPTER,
    &TYPORA_ADAPTER,
    &FIGMA_ADAPTER,
];

/// Case-insensitive adapter registry falling back to `GENERIC_ADAPTER`.
pub struct AdapterRegistry {
    by_app_id: HashMap<String, &'static dyn AppAdapter>,
    by_adapter_id: HashMap<&'static str, &'static dyn AppAdapter>,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AdapterRegistry {
    pub fn new() -> Self {
        let mut by_app_id: HashMap<String, &'static dyn AppAdapter> = HashMap::new();
        let mut by_adapter_id: HashMap<&'static str, &'static dyn AppAdapter> = HashMap::new();
        by_adapter_id.insert(GENERIC_ADAPTER.spec().id, &GENERIC_ADAPTER);
        for &adapter in BUILT_IN_SPECIALIZED_ADAPTERS {
            let spec = adapter.spec();
            by_adapter_id.entry(spec.id).or_insert(adapter);
            for &app_id in spec.match_application_ids {
                by_app_id
                    .entry(app_id.to_ascii_lowercase())
                    .or_insert(adapter);
            }
        }
        Self {
            by_app_id,
            by_adapter_id,
        }
    }

    pub fn adapter_impl_for(&self, application_id: &str) -> &'static dyn AppAdapter {
        self.by_app_id
            .get(&application_id.to_ascii_lowercase())
            .copied()
            .unwrap_or(&GENERIC_ADAPTER)
    }

    pub fn adapter_for(&self, application_id: &str) -> &'static AppAdapterSpec {
        self.adapter_impl_for(application_id).spec()
    }

    /// Dual-ID adapter lookup checking every identifier in `identity.candidate_ids()` in order
    /// before falling back to `GENERIC_ADAPTER`, ensuring MSIX/AppX package names (e.g.
    /// `thebrowsercompany.arc` + `arc.exe`, `mozilla.firefox` + `firefox.exe`) always resolve to
    /// their specialized adapter (`browser-family` with `block_private_windows: true`).
    pub fn adapter_impl_for_identity(
        &self,
        identity: &ResolvedAppIdentity,
    ) -> &'static dyn AppAdapter {
        for candidate in identity.candidate_ids() {
            if let Some(&adapter) = self.by_app_id.get(&candidate.to_ascii_lowercase()) {
                return adapter;
            }
        }
        if ApplicationPolicy::is_browser_identity(identity) {
            return &BROWSER_FAMILY_ADAPTER;
        }
        &GENERIC_ADAPTER
    }

    pub fn adapter_for_identity(&self, identity: &ResolvedAppIdentity) -> &'static AppAdapterSpec {
        self.adapter_impl_for_identity(identity).spec()
    }

    pub fn custom_adapter_for(&self, adapter_id: &str) -> Option<&'static dyn AppAdapter> {
        self.by_adapter_id
            .get(adapter_id)
            .copied()
            .filter(|adapter| adapter.has_custom_extractor())
    }

    pub fn has_custom_extractor(&self, adapter_id: &str) -> bool {
        self.custom_adapter_for(adapter_id).is_some()
    }

    pub fn is_terminal_app(&self, application_id: &str) -> bool {
        self.adapter_for(application_id).id == "terminal-family"
    }

    pub fn is_terminal_identity(&self, identity: &ResolvedAppIdentity) -> bool {
        self.adapter_for_identity(identity).id == "terminal-family"
    }

    pub fn all_ids() -> HashSet<&'static str> {
        let mut ids = HashSet::new();
        ids.insert(GENERIC_ADAPTER.spec().id);
        for &adapter in BUILT_IN_SPECIALIZED_ADAPTERS {
            ids.insert(adapter.spec().id);
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

    /// Trim leading/trailing whitespace and invisible zero-width/format characters
    /// (`U+200B`, `U+200C`, `U+200D`, `U+FEFF`, `U+00AD`), returning `None` for empty,
    /// invisible-only, or pure Private Use Area icon text.
    pub fn clean(value: Option<&str>) -> Option<&str> {
        let trimmed = value?.trim_matches(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{00AD}'
                )
        });
        if trimmed.is_empty()
            || crate::policy::is_effectively_empty_text(trimmed)
            || is_private_use_only_text(trimmed)
        {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_text_wrapper_id_matches_exact_and_dotted_suffix_semantics() {
        assert!(WECHAT_ADAPTER_SPEC.expands_text_wrapper_id(Some("big_title_line_h_view")));
        assert!(WECHAT_ADAPTER_SPEC.expands_text_wrapper_id(Some(
            "MainWindow.centralWidget.splitter.big_title_line_h_view"
        )));
        assert!(!WECHAT_ADAPTER_SPEC.expands_text_wrapper_id(Some(
            "MainWindow.big_title_line_h_view.current_chat_name_label"
        )));
        assert!(!WECHAT_ADAPTER_SPEC.expands_text_wrapper_id(Some("big_title_line_h_view_extra")));
        assert!(!WECHAT_ADAPTER_SPEC.expands_text_wrapper_id(Some("BIG_TITLE_LINE_H_VIEW")));
        assert!(!WECHAT_ADAPTER_SPEC.expands_text_wrapper_id(Some("")));
        assert!(!WECHAT_ADAPTER_SPEC.expands_text_wrapper_id(None));

        // Non-WeChat adapters do not declare text wrapper expansion IDs.
        for &adapter in BUILT_IN_SPECIALIZED_ADAPTERS {
            if adapter.spec().id != "wechat" {
                assert!(
                    !adapter
                        .spec()
                        .expands_text_wrapper_id(Some("big_title_line_h_view")),
                    "adapter {} must not expand WeChat wrapper ID",
                    adapter.spec().id
                );
            }
        }
        assert!(!GENERIC_ADAPTER_SPEC.expands_text_wrapper_id(Some("big_title_line_h_view")));
    }

    #[test]
    fn single_table_adapter_registry_is_consistent_across_all_lookups() {
        let registry = AdapterRegistry::new();
        assert_eq!(BUILT_IN_SPECIALIZED_ADAPTERS.len(), 9);
        assert_eq!(AdapterRegistry::all_ids().len(), 10);

        let mut seen_ids = HashSet::new();
        seen_ids.insert(GENERIC_ADAPTER.spec().id);
        for &adapter in BUILT_IN_SPECIALIZED_ADAPTERS {
            let spec = adapter.spec();
            assert!(seen_ids.insert(spec.id), "duplicate adapter id {}", spec.id);
            assert_eq!(
                registry.has_custom_extractor(spec.id),
                adapter.has_custom_extractor(),
                "custom extractor flag mismatch for {}",
                spec.id
            );
            assert_eq!(
                registry.custom_adapter_for(spec.id).map(|a| a.spec().id),
                adapter.has_custom_extractor().then_some(spec.id),
                "custom_adapter_for mismatch for {}",
                spec.id
            );
            for &app_id in spec.match_application_ids {
                assert_eq!(registry.adapter_for(app_id).id, spec.id);
                assert_eq!(registry.adapter_impl_for(app_id).spec().id, spec.id);
                let identity =
                    ResolvedAppIdentity::from_single(app_id.to_ascii_uppercase()).unwrap();
                assert_eq!(registry.adapter_for_identity(&identity).id, spec.id);
                assert_eq!(
                    registry.adapter_impl_for_identity(&identity).spec().id,
                    spec.id
                );
            }
        }

        // Only wechat and figma declare custom extractors.
        let custom_ids: HashSet<&str> = BUILT_IN_SPECIALIZED_ADAPTERS
            .iter()
            .filter(|a| a.has_custom_extractor())
            .map(|a| a.spec().id)
            .collect();
        assert_eq!(custom_ids, HashSet::from(["wechat", "figma"]));
        assert!(!registry.has_custom_extractor("generic"));
        assert!(registry.custom_adapter_for("generic").is_none());
        assert!(registry.custom_adapter_for("unknown").is_none());

        // Fallback for unmatched apps & unknown browser identities.
        let unknown = ResolvedAppIdentity::from_single("notepad.exe".to_string()).unwrap();
        assert_eq!(registry.adapter_impl_for("notepad.exe").spec().id, "generic");
        assert_eq!(registry.adapter_impl_for_identity(&unknown).spec().id, "generic");
        let msix_browser = ResolvedAppIdentity::from_parts(
            Some("thebrowsercompany.arc".to_string()),
            Some("arc.exe".to_string()),
        )
        .unwrap();
        assert_eq!(
            registry.adapter_impl_for_identity(&msix_browser).spec().id,
            "browser-family"
        );
    }
}

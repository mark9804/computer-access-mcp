//! Phase 4 comprehensive unit & integration tests mirroring macOS `AppAdapterTests.swift`,
//! `FigmaAdapterTests.swift`, and `AXSurfaceCaptureTests.swift`, plus Windows-specific UIA
//! adapter parity assertions (dotted Qt `AutomationId`s, Win32 DuiLib `AXRow` fallback,
//! Windows Electron titlebar chrome pruning, `y >= window_height` / `is_offscreen` clipping,
//! geometric sidebar fallback, and zero-size ZWSP ghost node filtering).

use std::collections::{HashMap, HashSet};

use access_contract::utf16_len;
use collector_core::adapters::{
    ActivationMode, AdapterRegistry, AppAdapterSpec, SafeDisplayText, StaticTextPolicy,
    WindowAnchorPolicy,
};
use collector_core::adapters_custom::{
    matches_wechat_id, validate_custom_result, AppAdapter, BackendAllowedNode, BackendCallBudget,
    BackendChildrenPage, BackendInspection, BackendTailChildrenRead, BackendTextRead,
    CustomSurfaceNode, CustomSurfaceResult, FigmaAdapter, KernelSurfaceContext, SafeSurfaceContext,
    SurfaceBackend, SurfaceCaptureOutcome, SurfaceCaptureRunner, SurfaceCapturedTree,
    SurfaceHandle, WeChatAdapter, BROWSER_FAMILY_ADAPTER, FEISHU_ADAPTER, FIGMA_ADAPTER,
    GENERIC_ADAPTER, QQ_ADAPTER, SLACK_ADAPTER, TYPORA_ADAPTER, VSCODE_FAMILY_ADAPTER,
    WECHAT_ADAPTER,
};
use collector_core::policy::{
    is_private_use_only_text, ApplicationPolicy, BrowserGate, ProtectedContentRead, ReadBudget,
    ResolvedAppIdentity, SubroleRead,
};
use collector_core::protocol_model::{
    bounded_utf16_slice, CapturePolicy, CollectorClock, SurfaceAbsoluteRect, SurfaceBaseline,
    SurfaceBounds, SurfaceNode, SurfaceReadFailure,
};
use collector_core::uia_traversal::{
    PendingSurfaceCapture, RuntimeIdKey, SurfaceNodeMap, WeightedSurfaceTraversalReason,
};

struct FakeClock {
    mono: i64,
    unix: i64,
}

impl FakeClock {
    fn new() -> Self {
        Self {
            mono: 1_000,
            unix: 1_700_000_000_000,
        }
    }
}

impl CollectorClock for FakeClock {
    fn unix_ms(&self) -> i64 {
        self.unix
    }

    fn monotonic_ms(&self) -> i64 {
        self.mono
    }
}

#[derive(Clone)]
struct MockNode {
    role: &'static str,
    category: &'static str,
    subrole: SubroleRead,
    protected_content: ProtectedContentRead,
    children: Vec<usize>,
    parent: Option<usize>,
    text: Option<String>,
    reported_length: Option<usize>,
    is_focused: bool,
    is_enabled: Option<bool>,
    display_text: Option<String>,
    window_title: Option<String>,
    bounds: Option<SurfaceAbsoluteRect>,
    identifier: Option<String>,
    class_name: Option<String>,
    label: Option<String>,
    is_offscreen: bool,
}

impl Default for MockNode {
    fn default() -> Self {
        Self {
            role: "AXGroup",
            category: "container",
            subrole: SubroleRead::NoValue,
            protected_content: ProtectedContentRead::Value(false),
            children: Vec::new(),
            parent: None,
            text: None,
            reported_length: None,
            is_focused: false,
            is_enabled: None,
            display_text: None,
            window_title: None,
            bounds: None,
            identifier: None,
            class_name: None,
            label: None,
            is_offscreen: false,
        }
    }
}

impl MockNode {
    fn new(role: &'static str) -> Self {
        let category = match role {
            "AXStaticText" => "text",
            "AXTextField" | "AXTextArea" => "editable",
            "AXSecureTextField" | "AXSlider" | "AXImage" | "AXScrollBar" => "other",
            _ => "container",
        };
        Self {
            role,
            category,
            ..Self::default()
        }
    }

    fn children(mut self, c: Vec<usize>) -> Self {
        self.children = c;
        self
    }

    fn parent(mut self, p: usize) -> Self {
        self.parent = Some(p);
        self
    }

    fn text(mut self, t: impl Into<String>) -> Self {
        self.text = Some(t.into());
        self
    }

    fn reported_length(mut self, len: usize) -> Self {
        self.reported_length = Some(len);
        self
    }

    fn focused(mut self) -> Self {
        self.is_focused = true;
        self
    }

    fn enabled(mut self, v: bool) -> Self {
        self.is_enabled = Some(v);
        self
    }

    fn display_text(mut self, dt: impl Into<String>) -> Self {
        self.display_text = Some(dt.into());
        self
    }

    fn window_title(mut self, wt: impl Into<String>) -> Self {
        self.window_title = Some(wt.into());
        self
    }

    fn bounds(mut self, x: f64, y: f64, w: f64, h: f64) -> Self {
        self.bounds = SurfaceAbsoluteRect::new(x, y, w, h);
        self
    }

    fn identifier(mut self, id: impl Into<String>) -> Self {
        self.identifier = Some(id.into());
        self
    }

    fn label(mut self, lbl: impl Into<String>) -> Self {
        self.label = Some(lbl.into());
        self
    }

    fn subrole(mut self, sr: &str) -> Self {
        self.subrole = SubroleRead::Value(sr.to_string());
        self
    }

    fn protected(mut self) -> Self {
        self.protected_content = ProtectedContentRead::Value(true);
        self
    }

    fn offscreen(mut self) -> Self {
        self.is_offscreen = true;
        self
    }
}

type InspectHook = Box<dyn FnMut(usize, bool) -> Option<BackendInspection>>;
type ChildHook = Box<dyn FnMut(&mut Option<SurfaceReadFailure>)>;
type TextHook = Box<dyn FnMut(usize) -> Option<BackendTextRead>>;

struct MockSurfaceBackend {
    nodes: HashMap<usize, MockNode>,
    desktop_failure: Option<SurfaceReadFailure>,
    final_boundary_failure: Option<SurfaceReadFailure>,
    window_rect: Option<SurfaceAbsoluteRect>,
    inspected_indices: Vec<usize>,
    child_requests: Vec<(usize, usize, usize)>,
    text_reads: Vec<usize>,
    bounds_calls: usize,
    charge_per_child_ipc: bool,
    cap_reported_child_count: Option<usize>,
    access_denied_children: HashSet<usize>,
    on_inspect: Option<InspectHook>,
    on_child_page: Option<ChildHook>,
    on_text_read: Option<TextHook>,
}

impl MockSurfaceBackend {
    fn new(nodes: HashMap<usize, MockNode>) -> Self {
        Self {
            nodes,
            desktop_failure: None,
            final_boundary_failure: None,
            window_rect: SurfaceAbsoluteRect::new(100.0, 200.0, 800.0, 600.0),
            inspected_indices: Vec::new(),
            child_requests: Vec::new(),
            text_reads: Vec::new(),
            bounds_calls: 0,
            charge_per_child_ipc: false,
            cap_reported_child_count: None,
            access_denied_children: HashSet::new(),
            on_inspect: None,
            on_child_page: None,
            on_text_read: None,
        }
    }

    fn with_window_rect(mut self, x: f64, y: f64, w: f64, h: f64) -> Self {
        self.window_rect = SurfaceAbsoluteRect::new(x, y, w, h);
        self
    }
}

impl SurfaceBackend for MockSurfaceBackend {
    fn verify_desktop_and_application(&mut self) -> Option<SurfaceReadFailure> {
        self.desktop_failure
    }

    fn inspect_backend_node(
        &mut self,
        index: usize,
        is_root: bool,
        _calls: &mut BackendCallBudget,
    ) -> BackendInspection {
        self.inspected_indices.push(index);
        if let Some(ref mut hook) = self.on_inspect {
            if let Some(custom) = hook(index, is_root) {
                return custom;
            }
        }
        let Some(node) = self.nodes.get(&index) else {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::ProviderRefused);
        };
        let child_count = self
            .cap_reported_child_count
            .map_or(node.children.len(), |cap| node.children.len().min(cap));
        BackendInspection::Allowed(Box::new(BackendAllowedNode {
            role: node.role.to_string(),
            category: node.category,
            subrole: node.subrole.clone(),
            protected_content: node.protected_content,
            child_count,
            is_focused: node.is_focused,
            observed_at_ms: 1_000 + index as i64,
            is_enabled: node.is_enabled,
            display_text: node.display_text.clone(),
            window_title: is_root.then(|| node.window_title.clone()).flatten(),
            absolute_rect: node.bounds,
            identifier: node.identifier.clone(),
            class_name: node.class_name.clone(),
            label: node.label.clone(),
            is_offscreen: node.is_offscreen,
            strict_security: None,
        }))
    }

    fn parent_backend_node(
        &mut self,
        index: usize,
        _calls: &mut BackendCallBudget,
    ) -> Option<usize> {
        self.nodes.get(&index)?.parent
    }

    fn children_backend_page(
        &mut self,
        index: usize,
        expected_role: &str,
        offset: usize,
        limit: usize,
        calls: &mut BackendCallBudget,
    ) -> BackendChildrenPage {
        self.child_requests.push((index, offset, limit));
        if let Some(ref mut hook) = self.on_child_page {
            hook(&mut self.desktop_failure);
        }
        if self.access_denied_children.contains(&index) {
            return BackendChildrenPage::AccessDenied;
        }
        let Some(node) = self.nodes.get(&index) else {
            return BackendChildrenPage::Unavailable(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        };
        if node.role != expected_role {
            return BackendChildrenPage::Unavailable(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        }
        if self.charge_per_child_ipc {
            let mut page = Vec::new();
            let mut budget_truncated = false;
            for &child in node.children.iter().skip(offset).take(limit) {
                if !calls.try_consume(1) {
                    budget_truncated = true;
                    break;
                }
                page.push(child);
            }
            let truncated =
                budget_truncated || offset.saturating_add(page.len()) < node.children.len();
            return BackendChildrenPage::Values {
                handles: page,
                truncated,
            };
        }
        let page: Vec<usize> = node
            .children
            .iter()
            .skip(offset)
            .take(limit)
            .copied()
            .collect();
        let truncated = offset.saturating_add(page.len()) < node.children.len();
        BackendChildrenPage::Values {
            handles: page,
            truncated,
        }
    }

    fn tail_children_backend(
        &mut self,
        index: usize,
        expected_role: &str,
        limit: usize,
        calls: &mut BackendCallBudget,
    ) -> BackendTailChildrenRead {
        if self.access_denied_children.contains(&index) {
            return BackendTailChildrenRead::AccessDenied;
        }
        let Some(node) = self.nodes.get(&index) else {
            return BackendTailChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        };
        if node.role != expected_role {
            return BackendTailChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        }
        let total = node.children.len();
        let actual_limit = limit.min(total);
        let offset = total.saturating_sub(actual_limit);
        self.child_requests.push((index, offset, actual_limit));
        if let Some(ref mut hook) = self.on_child_page {
            hook(&mut self.desktop_failure);
        }
        if self.charge_per_child_ipc {
            let mut tail = Vec::new();
            let mut budget_truncated = false;
            for &child in node.children.iter().rev().take(actual_limit) {
                if !calls.try_consume(1) {
                    budget_truncated = true;
                    break;
                }
                tail.push(child);
            }
            tail.reverse();
            return BackendTailChildrenRead::Values {
                handles: tail,
                truncated: budget_truncated || total > limit,
            };
        }
        BackendTailChildrenRead::Values {
            handles: node.children[offset..].to_vec(),
            truncated: total > limit,
        }
    }

    fn read_backend_node_text(
        &mut self,
        index: usize,
        expected_role: &str,
        max_units: usize,
        static_text_probe: StaticTextPolicy,
        _calls: &mut BackendCallBudget,
    ) -> BackendTextRead {
        self.text_reads.push(index);
        if let Some(ref mut hook) = self.on_text_read {
            if let Some(custom) = hook(index) {
                return custom;
            }
        }
        let Some(node) = self.nodes.get(&index) else {
            return BackendTextRead::Unavailable {
                reasons: vec!["node-text-unavailable".to_string()],
            };
        };
        let Some(ref raw) = node.text else {
            return BackendTextRead::Unavailable {
                reasons: vec!["node-text-unavailable".to_string()],
            };
        };
        let raw_units = utf16_len(raw);
        let declared = node.reported_length.unwrap_or(raw_units);
        if expected_role == "AXStaticText" && declared == 0 {
            return match static_text_probe {
                StaticTextPolicy::Standard => BackendTextRead::Text {
                    value: String::new(),
                    complete: true,
                    reasons: Vec::new(),
                },
                StaticTextPolicy::BoundedRangeProbe { max_units: probe_lim } => {
                    let cap = max_units.min(probe_lim);
                    let slice =
                        bounded_utf16_slice(raw, 0, raw_units.min(cap)).unwrap_or_default();
                    BackendTextRead::Text {
                        value: slice,
                        complete: false,
                        reasons: vec!["static-text-length-unverified".to_string()],
                    }
                }
            };
        }
        let slice = bounded_utf16_slice(raw, 0, raw_units.min(max_units)).unwrap_or_default();
        let complete = utf16_len(&slice) == raw_units;
        BackendTextRead::Text {
            value: slice,
            complete,
            reasons: if complete {
                Vec::new()
            } else {
                vec!["text-budget".to_string()]
            },
        }
    }

    fn read_backend_node_bounds(
        &mut self,
        index: usize,
        window_rect: SurfaceAbsoluteRect,
    ) -> Option<(SurfaceBounds, i64)> {
        self.bounds_calls += 1;
        let rect = self.nodes.get(&index)?.bounds?;
        let rel = rect.relative_to(window_rect)?;
        Some((rel, 1_050))
    }

    fn read_backend_window_rect(&mut self) -> Option<SurfaceAbsoluteRect> {
        self.window_rect
    }

    fn verify_final_surface_boundary(&mut self) -> Option<SurfaceReadFailure> {
        self.final_boundary_failure
    }
}

fn id(app_id: &str) -> ResolvedAppIdentity {
    ResolvedAppIdentity::from_single(app_id.to_string()).expect("valid app id")
}

fn allowlist_policy(apps: &[&str]) -> CapturePolicy {
    CapturePolicy {
        enabled: true,
        application_scope: Some("allowlist".to_string()),
        allowed_application_ids: apps.iter().map(|s| s.to_string()).collect(),
        capture_scope: Some("window".to_string()),
        field_security: Some("denylist".to_string()),
        ..CapturePolicy::default()
    }
}

fn denylist_policy() -> CapturePolicy {
    CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        capture_scope: Some("window".to_string()),
        field_security: Some("denylist".to_string()),
        ..CapturePolicy::default()
    }
}

fn assert_valid_forest(tree: &SurfaceCapturedTree) {
    let ids: HashSet<&str> = tree.nodes.iter().map(|n| n.id.as_str()).collect();
    assert_eq!(ids.len(), tree.nodes.len(), "duplicate node IDs");
    let by_id: HashMap<&str, &SurfaceNode> =
        tree.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    for node in &tree.nodes {
        let mut seen: HashSet<&str> = HashSet::new();
        seen.insert(node.id.as_str());
        let mut cur = node.parent_id.as_deref();
        while let Some(pid) = cur {
            assert!(ids.contains(pid), "missing parent {pid}");
            assert!(seen.insert(pid), "cycle detected in parent graph at {pid}");
            cur = by_id.get(pid).and_then(|p| p.parent_id.as_deref());
        }
    }
}

fn texts_of(tree: &SurfaceCapturedTree) -> Vec<&str> {
    tree.nodes.iter().filter_map(|n| n.text.as_deref()).collect()
}

// ============================================================================
// Test 1: Registry Matches Built-In Adapters & Falls Back to Generic
// ============================================================================
#[test]
fn registry_matches_all_built_in_adapters_and_falls_back_to_generic() {
    let registry = AdapterRegistry::new();
    let all_ids = AdapterRegistry::all_ids();
    assert_eq!(all_ids.len(), 10);
    for expected in [
        "generic",
        "vscode-family",
        "browser-family",
        "terminal-family",
        "qq",
        "feishu",
        "wechat",
        "slack",
        "typora",
        "figma",
    ] {
        assert!(all_ids.contains(expected), "missing adapter id {expected}");
    }

    for app_id in [
        "com.google.antigravity",
        "COM.GOOGLE.ANTIGRAVITY",
        "com.google.antigravity-ide",
        "com.microsoft.VSCode",
        "antigravity.exe",
        "CODE.EXE",
        "code-insiders.exe",
        "cursor.exe",
        "windsurf.exe",
    ] {
        let spec = registry.adapter_for(app_id);
        assert_eq!(spec.id, "vscode-family", "{app_id}");
        assert_eq!(spec.activation, ActivationMode::ManualAccessibility);
        assert_eq!(spec.window_anchor, WindowAnchorPolicy::AllowUnfocusedWindow);
        assert_eq!(
            spec.static_text_probe,
            StaticTextPolicy::BoundedRangeProbe { max_units: 256 }
        );
        assert_eq!(spec.ignored_subroles, &["AXApplicationStatus"]);
        assert_eq!(spec.page_size, 16);
        assert_eq!(spec.max_node_text_units, 256);
    }

    for app_id in [
        "com.google.Chrome",
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "brave.exe",
        "arc.exe",
    ] {
        let spec = registry.adapter_for(app_id);
        assert_eq!(spec.id, "browser-family", "{app_id}");
        assert!(spec.block_private_windows);
    }

    for app_id in ["com.apple.Terminal", "windowsterminal.exe", "wt.exe"] {
        let spec = registry.adapter_for(app_id);
        assert_eq!(spec.id, "terminal-family", "{app_id}");
        assert_eq!(spec.window_anchor, WindowAnchorPolicy::AllowTopLevelFallback);
        assert_eq!(spec.max_node_text_units, 1024);
    }

    for app_id in ["com.tencent.qq", "QQ.EXE"] {
        let spec = registry.adapter_for(app_id);
        assert_eq!(spec.id, "qq", "{app_id}");
        assert_eq!(spec.activation, ActivationMode::ManualAccessibility);
        assert_eq!(
            spec.static_text_probe,
            StaticTextPolicy::BoundedRangeProbe { max_units: 256 }
        );
    }

    for app_id in ["com.tencent.xinWeChat", "wechat.exe", "weixin.exe"] {
        let spec = registry.adapter_for(app_id);
        assert_eq!(spec.id, "wechat", "{app_id}");
        assert!(registry.has_custom_extractor(spec.id));
    }

    for app_id in ["com.figma.Desktop", "FIGMA.EXE"] {
        let spec = registry.adapter_for(app_id);
        assert_eq!(spec.id, "figma", "{app_id}");
        assert_eq!(spec.activation, ActivationMode::EnhancedUi);
        assert!(!spec.block_private_windows);
        assert!(registry.has_custom_extractor(spec.id));
    }

    for unknown in ["notepad.exe", "org.example.editor", "com.apple.Notes"] {
        let spec = registry.adapter_for(unknown);
        assert_eq!(spec.id, "generic", "{unknown}");
        assert_eq!(spec.activation, ActivationMode::None);
        assert_eq!(spec.window_anchor, WindowAnchorPolicy::FocusedOnly);
        assert!(!registry.has_custom_extractor(spec.id));
    }
}

// ============================================================================
// Test 2: Custom Extractor Hook Supports Large Pages & Rejects Invalid Graphs
// ============================================================================
#[test]
fn custom_extractor_hook_supports_large_pages_and_rejects_invalid_graphs() {
    static CUSTOM_SPEC: AppAdapterSpec = AppAdapterSpec {
        id: "custom-chat",
        display_name: "Custom Chat",
        match_application_ids: &["org.example.chat"],
        activation: ActivationMode::None,
        window_anchor: WindowAnchorPolicy::FocusedOnly,
        static_text_probe: StaticTextPolicy::Standard,
        preferred_roles: &[],
        ignored_roles: &[],
        ignored_subroles: &[],
        page_size: 32,
        max_node_text_units: 256,
        block_private_windows: false,
        collapse_empty_containers: false,
    };

    struct CustomChatAdapter;
    impl AppAdapter for CustomChatAdapter {
        fn spec(&self) -> &'static AppAdapterSpec {
            &CUSTOM_SPEC
        }
        fn extract_surface(&self, ctx: &mut dyn SafeSurfaceContext) -> Option<CustomSurfaceResult> {
            let root = ctx.root();
            let root_info = ctx.inspect(root)?;
            let children = ctx.children(root, 0, 24)?;
            let mut nodes = vec![CustomSurfaceNode {
                handle: root,
                parent: None,
                role: "container",
                ax_role: Some(root_info.role),
                text: None,
                is_focused: false,
                observed_at_ms: root_info.observed_at_ms,
                bounds: None,
                bounds_observed_at_ms: None,
            }];
            for child in children {
                let Some(info) = ctx.inspect(child) else {
                    continue;
                };
                let Some(body) = ctx.text(child, None) else {
                    continue;
                };
                let bounds = ctx.bounds(child);
                nodes.push(CustomSurfaceNode {
                    handle: child,
                    parent: Some(root),
                    role: "text",
                    ax_role: Some(info.role),
                    text: Some(body),
                    is_focused: false,
                    observed_at_ms: info.observed_at_ms,
                    bounds: bounds.map(|(b, _)| b),
                    bounds_observed_at_ms: bounds.map(|(_, ts)| ts),
                });
            }
            Some(CustomSurfaceResult {
                nodes,
                complete: true,
                missing_reasons: Vec::new(),
            })
        }
    }

    let clock = FakeClock::new();
    let mut graph = HashMap::new();
    graph.insert(0, MockNode::new("AXWindow").children((1..=20).collect()));
    for i in 1..=20 {
        graph.insert(i, MockNode::new("AXStaticText").parent(0).text(format!("Row {i}")));
    }

    let mut backend = MockSurfaceBackend::new(graph.clone());
    let app = id("org.example.chat");
    let policy = allowlist_policy(&["org.example.chat"]);
    let outcome = SurfaceCaptureRunner::run(
        &CustomChatAdapter,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    );
    let SurfaceCaptureOutcome::Success(captured) = outcome else {
        panic!("expected custom extractor success, got {outcome:?}");
    };
    assert_eq!(backend.child_requests.first().map(|r| r.2), Some(24));
    assert_eq!(captured.nodes.len(), 21);
    assert_eq!(captured.adapter_id, "custom-chat");

    // Kernel MUST reject every invalid custom graph with BoundaryUnverified!
    enum BadKind {
        Empty,
        Cyclic,
        DanglingParent,
        UninspectedHandle,
        DuplicateHandle,
        MultipleFocused,
        ExceedsMaxOutputNodes,
    }
    struct BadAdapter(BadKind);
    impl AppAdapter for BadAdapter {
        fn spec(&self) -> &'static AppAdapterSpec {
            &CUSTOM_SPEC
        }
        fn extract_surface(&self, ctx: &mut dyn SafeSurfaceContext) -> Option<CustomSurfaceResult> {
            let root = ctx.root();
            let _ = ctx.inspect(root);
            let h1 = SurfaceHandle(1);
            let h2 = SurfaceHandle(2);
            let _ = ctx.inspect(h1);
            let _ = ctx.inspect(h2);
            let node = |h, parent, focused| CustomSurfaceNode {
                handle: h,
                parent,
                role: "container",
                ax_role: Some("AXGroup".to_string()),
                text: None,
                is_focused: focused,
                observed_at_ms: 1,
                bounds: None,
                bounds_observed_at_ms: None,
            };
            let nodes = match self.0 {
                BadKind::Empty => vec![],
                BadKind::Cyclic => vec![node(root, Some(h1), false), node(h1, Some(root), false)],
                BadKind::DanglingParent => {
                    vec![node(root, None, false), node(h1, Some(SurfaceHandle(99)), false)]
                }
                BadKind::UninspectedHandle => {
                    vec![node(root, None, false), node(SurfaceHandle(15), Some(root), false)]
                }
                BadKind::DuplicateHandle => {
                    vec![node(root, None, false), node(h1, Some(root), false), node(h1, Some(root), false)]
                }
                BadKind::MultipleFocused => {
                    vec![node(root, None, false), node(h1, Some(root), true), node(h2, Some(root), true)]
                }
                BadKind::ExceedsMaxOutputNodes => {
                    vec![node(root, None, false), node(h1, Some(root), false), node(h2, Some(root), false)]
                }
            };
            Some(CustomSurfaceResult {
                nodes,
                complete: false,
                missing_reasons: Vec::new(),
            })
        }
    }

    for (kind, max_nodes, label) in [
        (BadKind::Empty, 48, "empty"),
        (BadKind::Cyclic, 48, "cyclic"),
        (BadKind::DanglingParent, 48, "dangling parent"),
        (BadKind::UninspectedHandle, 48, "uninspected handle"),
        (BadKind::DuplicateHandle, 48, "duplicate handle"),
        (BadKind::MultipleFocused, 48, "multiple focused"),
        (BadKind::ExceedsMaxOutputNodes, 2, "exceeds max_output_nodes"),
    ] {
        let mut b = MockSurfaceBackend::new(graph.clone());
        let res = SurfaceCaptureRunner::run(
            &BadAdapter(kind),
            &app,
            &policy,
            "window",
            max_nodes,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut b,
        );
        assert_eq!(
            res,
            SurfaceCaptureOutcome::Failure(SurfaceReadFailure::BoundaryUnverified),
            "invalid custom graph ({label}) must fail closed with BoundaryUnverified"
        );
    }
}

// ============================================================================
// Test 3: Hard Kernel Denylist, Desktop Lock, & Protected Field Gates
// ============================================================================
#[test]
fn hard_kernel_denylist_desktop_and_protected_field_gates_are_unbypassable() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    static ROGUE_SPEC: AppAdapterSpec = AppAdapterSpec {
        id: "rogue",
        display_name: "Rogue",
        match_application_ids: &["1password.exe", "org.example.app"],
        activation: ActivationMode::None,
        window_anchor: WindowAnchorPolicy::FocusedOnly,
        static_text_probe: StaticTextPolicy::Standard,
        preferred_roles: &[],
        ignored_roles: &[],
        ignored_subroles: &[],
        page_size: 8,
        max_node_text_units: 128,
        block_private_windows: false,
        collapse_empty_containers: false,
    };

    struct RogueAdapter {
        executed: AtomicBool,
        leaked: Mutex<Option<String>>,
    }
    impl AppAdapter for RogueAdapter {
        fn spec(&self) -> &'static AppAdapterSpec {
            &ROGUE_SPEC
        }
        fn extract_surface(&self, ctx: &mut dyn SafeSurfaceContext) -> Option<CustomSurfaceResult> {
            self.executed.store(true, Ordering::SeqCst);
            // Attempt to read password nodes directly WITHOUT calling inspect() first!
            let secret = ctx
                .text(SurfaceHandle(1), None)
                .or_else(|| ctx.text(SurfaceHandle(2), None));
            *self.leaked.lock().unwrap() = secret;
            let root = ctx.root();
            let root_info = ctx.inspect(root)?;
            let safe_info = ctx.inspect(SurfaceHandle(3))?;
            let safe_text = ctx.text(SurfaceHandle(3), None)?;
            Some(CustomSurfaceResult {
                nodes: vec![
                    CustomSurfaceNode {
                        handle: root,
                        parent: None,
                        role: "container",
                        ax_role: Some(root_info.role),
                        text: None,
                        is_focused: false,
                        observed_at_ms: 1,
                        bounds: None,
                        bounds_observed_at_ms: None,
                    },
                    CustomSurfaceNode {
                        handle: SurfaceHandle(3),
                        parent: Some(root),
                        role: "text",
                        ax_role: Some(safe_info.role),
                        text: Some(safe_text),
                        is_focused: false,
                        observed_at_ms: 1,
                        bounds: None,
                        bounds_observed_at_ms: None,
                    },
                ],
                complete: true,
                missing_reasons: Vec::new(),
            })
        }
    }

    let clock = FakeClock::new();
    let mut nodes = HashMap::new();
    nodes.insert(0, MockNode::new("AXWindow").children(vec![1, 2, 3]));
    nodes.insert(1, MockNode::new("AXSecureTextField").parent(0).text("hunter2"));
    nodes.insert(
        2,
        MockNode::new("AXTextField")
            .parent(0)
            .protected()
            .text("secret-token"),
    );
    nodes.insert(3, MockNode::new("AXTextField").parent(0).text("public-note"));

    let policy = denylist_policy();

    // 1. Mandatory 1Password denylist blocks BEFORE adapter or backend runs!
    let rogue = RogueAdapter {
        executed: AtomicBool::new(false),
        leaked: Mutex::new(None),
    };
    let mut pw_backend = MockSurfaceBackend::new(nodes.clone());
    let denied = SurfaceCaptureRunner::run(
        &rogue,
        &id("1password.exe"),
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut pw_backend,
    );
    assert_eq!(
        denied,
        SurfaceCaptureOutcome::Failure(SurfaceReadFailure::SecurityExcluded)
    );
    assert!(!rogue.executed.load(Ordering::SeqCst));
    assert!(pw_backend.inspected_indices.is_empty());

    // 2. Direct ctx.text() on AXSecureTextField & protected field returns None with ZERO backend text calls!
    let mut mixed_backend = MockSurfaceBackend::new(nodes.clone());
    let allowed = id("org.example.app");
    let mixed = SurfaceCaptureRunner::run(
        &rogue,
        &allowed,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut mixed_backend,
    );
    assert!(rogue.executed.load(Ordering::SeqCst));
    assert!(rogue.leaked.lock().unwrap().is_none());
    assert_eq!(
        mixed_backend.text_reads,
        vec![3],
        "backend text reader must NEVER be invoked for protected nodes 1 or 2"
    );
    let SurfaceCaptureOutcome::Success(tree) = mixed else {
        panic!("expected safe sibling capture to succeed, got {mixed:?}");
    };
    assert_eq!(texts_of(&tree), vec!["public-note"]);

    // 3. Desktop lock mid-read wipes context and fails closed with SecurityExcluded.
    let mut locking_backend = MockSurfaceBackend::new(nodes);
    locking_backend.on_child_page = Some(Box::new(|desktop_failure| {
        *desktop_failure = Some(SurfaceReadFailure::SecurityExcluded);
    }));
    let locked = SurfaceCaptureRunner::run(
        &GENERIC_ADAPTER,
        &allowed,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut locking_backend,
    );
    assert_eq!(
        locked,
        SurfaceCaptureOutcome::Failure(SurfaceReadFailure::SecurityExcluded)
    );
}

// ============================================================================
// Test 4: Unified ReadBudget Call Ceiling Reserve & Oversized Text Poisoning
// ============================================================================
#[test]
fn unified_read_budget_enforces_call_ceiling_reserve_and_oversized_text_poisoning() {
    let clock = FakeClock::new();
    let mut graph = HashMap::new();
    graph.insert(0, MockNode::new("AXWindow").children((1..=20).collect()));
    for i in 1..=20 {
        graph.insert(i, MockNode::new("AXStaticText").parent(0).text(format!("Item {i}")));
    }
    let app = id("org.example.app");
    let policy = allowlist_policy(&["org.example.app"]);

    // Tight call budget: 14 total with 8 reserved -> only 6 exploration calls.
    let mut backend = MockSurfaceBackend::new(graph);
    let outcome = SurfaceCaptureRunner::run(
        &GENERIC_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 14, 8, 256),
        &clock,
        &mut backend,
    );
    let SurfaceCaptureOutcome::Success(partial) = outcome else {
        panic!("expected partial tree with reserved validation calls, got {outcome:?}");
    };
    assert!(!partial.complete);
    assert!(partial.reasons.iter().any(|r| r == "tree-call-budget"));
    assert!(partial.nodes.len() < 10);

    // Oversized text response poisons ReadBudget and aborts with BoundaryUnverified.
    let mut small = HashMap::new();
    small.insert(0, MockNode::new("AXWindow").children(vec![1]));
    small.insert(1, MockNode::new("AXTextField").parent(0).text("short"));
    let mut oversized_backend = MockSurfaceBackend::new(small);
    oversized_backend.on_text_read = Some(Box::new(|_| {
        Some(BackendTextRead::Text {
            value: "X".repeat(500),
            complete: false,
            reasons: vec!["text-budget".to_string()],
        })
    }));
    let poisoned = SurfaceCaptureRunner::run(
        &GENERIC_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 32),
        &clock,
        &mut oversized_backend,
    );
    assert_eq!(
        poisoned,
        SurfaceCaptureOutcome::Failure(SurfaceReadFailure::BoundaryUnverified)
    );
}

// ============================================================================
// Test 5: Non-Root Leaf Failures & Role/PID Mismatches Preserve Captured Nodes
// ============================================================================
#[test]
fn non_root_leaf_failures_and_mismatches_preserve_captured_nodes_as_partial() {
    let clock = FakeClock::new();
    let policy = denylist_policy();

    // 1. Mid-read call budget exhaustion on a non-root leaf preserves prior captured sibling.
    let mut nodes1 = HashMap::new();
    nodes1.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1, 2])
            .window_title("Docs - Google Chrome"),
    );
    nodes1.insert(
        1,
        MockNode::new("AXStaticText")
            .parent(0)
            .text("First captured paragraph"),
    );
    nodes1.insert(
        2,
        MockNode::new("AXStaticText")
            .parent(0)
            .text("Second paragraph hits budget"),
    );
    let mut b1 = MockSurfaceBackend::new(nodes1);
    b1.on_text_read = Some(Box::new(|idx| {
        (idx == 2).then(|| BackendTextRead::Unavailable {
            reasons: vec!["tree-call-budget".to_string()],
        })
    }));
    let SurfaceCaptureOutcome::Success(tree1) = SurfaceCaptureRunner::run(
        &BROWSER_FAMILY_ADAPTER,
        &id("chrome.exe"),
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut b1,
    ) else {
        panic!("expected partial tree on leaf budget exhaustion");
    };
    assert!(!tree1.complete);
    assert!(tree1.reasons.iter().any(|r| r == "tree-call-budget"));
    assert!(texts_of(&tree1).contains(&"First captured paragraph"));

    // 2. Single StaticText probe failure preserves other captured leaves as partial.
    let mut nodes2 = HashMap::new();
    nodes2.insert(0, MockNode::new("AXWindow").children(vec![1, 2]));
    nodes2.insert(
        1,
        MockNode::new("AXStaticText")
            .parent(0)
            .text("Hello from chat")
            .reported_length(0),
    );
    nodes2.insert(
        2,
        MockNode::new("AXStaticText")
            .parent(0)
            .text("Broken probe leaf")
            .reported_length(0),
    );
    let mut b2 = MockSurfaceBackend::new(nodes2);
    b2.on_text_read = Some(Box::new(|idx| {
        (idx == 2).then(|| BackendTextRead::Unavailable {
            reasons: vec![
                "static-text-length-unverified".to_string(),
                "node-text-unavailable".to_string(),
            ],
        })
    }));
    let SurfaceCaptureOutcome::Success(tree2) = SurfaceCaptureRunner::run(
        &QQ_ADAPTER,
        &id("qq.exe"),
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut b2,
    ) else {
        panic!("expected partial tree on single StaticText probe failure");
    };
    assert!(!tree2.complete);
    assert!(tree2.reasons.iter().any(|r| r == "static-text-length-unverified"));
    assert!(texts_of(&tree2).contains(&"Hello from chat"));

    // 3. Non-root PID mismatch (pruned) + dynamic DOM role change between inspect & read_text.
    let mut nodes3 = HashMap::new();
    nodes3.insert(0, MockNode::new("AXWindow").children(vec![1, 2, 3]));
    nodes3.insert(1, MockNode::new("AXStaticText").parent(0).text("Stable message"));
    nodes3.insert(2, MockNode::new("AXStaticText").parent(0).text("Mutating DOM text"));
    nodes3.insert(
        3,
        MockNode::new("AXStaticText")
            .parent(0)
            .text("Renderer child PID node"),
    );
    let mut b3 = MockSurfaceBackend::new(nodes3);
    let mut node2_inspections = 0usize;
    b3.on_inspect = Some(Box::new(move |idx, _| {
        if idx == 3 {
            return Some(BackendInspection::Pruned(
                WeightedSurfaceTraversalReason::SecurityPruned,
            ));
        }
        if idx == 2 {
            node2_inspections += 1;
            if node2_inspections >= 2 {
                return Some(BackendInspection::Allowed(Box::new(BackendAllowedNode {
                    role: "AXGroup".to_string(),
                    category: "container",
                    subrole: SubroleRead::NoValue,
                    protected_content: ProtectedContentRead::Value(false),
                    child_count: 0,
                    is_focused: false,
                    observed_at_ms: 1_002,
                    is_enabled: None,
                    display_text: None,
                    window_title: None,
                    absolute_rect: None,
                    identifier: None,
                    class_name: None,
                    label: None,
                    is_offscreen: false,
                    strict_security: None,
                })));
            }
        }
        None
    }));
    let SurfaceCaptureOutcome::Success(tree3) = SurfaceCaptureRunner::run(
        &FEISHU_ADAPTER,
        &id("feishu.exe"),
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut b3,
    ) else {
        panic!("expected partial tree on non-root PID/role mismatch");
    };
    assert!(!tree3.complete);
    assert!(tree3.reasons.iter().any(|r| r == "node-role-changed"));
    assert!(tree3.reasons.iter().any(|r| r == "tree-security-pruned"));
    let t3 = texts_of(&tree3);
    assert!(t3.contains(&"Stable message"));
    assert!(!t3.contains(&"Mutating DOM text"));
    assert!(!t3.contains(&"Renderer child PID node"));
}

// ============================================================================
// Test 6: WeChatAdapter (Qt 4.x + Dotted Windows Qt AutomationId + DuiLib AXRow)
// ============================================================================
#[test]
fn wechat_adapter_extracts_chat_pane_tail_and_skips_session_list_and_virtual_cells() {
    assert!(matches_wechat_id(Some("chat_message_list"), "chat_message_list"));
    assert!(matches_wechat_id(
        Some("MainWindow.centralWidget.splitter.chat_message_list"),
        "chat_message_list"
    ));
    assert!(!matches_wechat_id(
        Some("other_chat_message_list"),
        "chat_message_list"
    ));
    assert!(!matches_wechat_id(None, "chat_message_list"));

    let clock = FakeClock::new();

    // Run both exact Qt identifiers AND Windows dot-qualified Qt 4.x AutomationIds!
    for prefix in ["", "MainWindow.centralWidget.splitter."] {
        let q = |name: &str| format!("{prefix}{name}");
        let mut nodes = HashMap::new();
        nodes.insert(
            0,
            MockNode::new("AXWindow")
                .children(vec![1])
                .bounds(100.0, 200.0, 1000.0, 700.0),
        );
        nodes.insert(1, MockNode::new("AXGroup").children(vec![2]).parent(0));
        nodes.insert(
            2,
            MockNode::new("AXSplitGroup")
                .children(vec![3, 4, 5])
                .parent(1)
                .identifier(q("main_window_main_splitter_view")),
        );
        nodes.insert(
            3,
            MockNode::new("AXButton")
                .children(vec![30])
                .parent(2)
                .display_text("WeChat"),
        );
        nodes.insert(30, MockNode::new("AXStaticText").parent(3).text("Left nav noise"));
        nodes.insert(4, MockNode::new("AXButton").parent(2).display_text("Contacts"));
        nodes.insert(
            5,
            MockNode::new("AXSplitGroup")
                .children(vec![6, 7])
                .parent(2)
                .identifier(q("main_window_sub_splitter_view")),
        );

        let session_rows: Vec<usize> = (500..550).collect();
        nodes.insert(
            6,
            MockNode::new("AXList")
                .children(session_rows.clone())
                .parent(5)
                .identifier(q("session_list")),
        );
        for row_id in session_rows {
            nodes.insert(
                row_id,
                MockNode::new("AXStaticText")
                    .parent(6)
                    .text(format!("Session preview {row_id}")),
            );
        }

        nodes.insert(7, MockNode::new("AXGroup").children(vec![8]).parent(5));
        nodes.insert(8, MockNode::new("AXSplitGroup").children(vec![9, 12]).parent(7));
        nodes.insert(9, MockNode::new("AXGroup").children(vec![10]).parent(8));
        nodes.insert(
            10,
            MockNode::new("AXStaticText")
                .children(vec![11])
                .parent(9)
                .identifier(q("big_title_line_h_view")),
        );
        nodes.insert(
            11,
            MockNode::new("AXStaticText")
                .parent(10)
                .text("文件传输助手")
                .reported_length(0)
                .bounds(360.0, 220.0, 200.0, 28.0)
                .identifier(q("current_chat_name_label")),
        );
        nodes.insert(12, MockNode::new("AXSplitGroup").children(vec![13, 14]).parent(8));

        let message_ids: Vec<usize> = (1000..1120).collect();
        nodes.insert(
            13,
            MockNode::new("AXList")
                .children(message_ids)
                .parent(12)
                .bounds(340.0, 260.0, 640.0, 480.0)
                .identifier(q("chat_message_list")),
        );
        for offset in 0..120usize {
            let nid = 1000 + offset;
            if offset < 88 {
                nodes.insert(
                    nid,
                    MockNode::new("AXStaticText")
                        .parent(13)
                        .text(format!("Old msg {offset}"))
                        .reported_length(0)
                        .bounds(360.0, 270.0, 220.0, 24.0)
                        .identifier(q("chat_bubble_item_view")),
                );
            } else if offset < 92 {
                nodes.insert(
                    nid,
                    MockNode::new("AXStaticText")
                        .parent(13)
                        .text("")
                        .reported_length(0)
                        .bounds(100.0, 200.0, 0.0, 0.0)
                        .identifier(q("virtual_cell")),
                );
            } else if offset == 92 {
                nodes.insert(
                    nid,
                    MockNode::new("AXStaticText")
                        .parent(13)
                        .text("Hidden zero-size placeholder")
                        .reported_length(0)
                        .bounds(100.0, 200.0, 0.0, 0.0),
                );
            } else if offset == 93 {
                nodes.insert(
                    nid,
                    MockNode::new("AXStaticText")
                        .parent(13)
                        .text("14:20")
                        .reported_length(0)
                        .bounds(600.0, 280.0, 60.0, 16.0),
                );
            } else {
                nodes.insert(
                    nid,
                    MockNode::new("AXStaticText")
                        .parent(13)
                        .text(format!("Recent msg {offset}"))
                        .reported_length(0)
                        .bounds(360.0, 300.0 + (offset - 94) as f64 * 20.0, 260.0, 18.0)
                        .identifier(q("chat_bubble_item_view")),
                );
            }
        }
        nodes.insert(
            14,
            MockNode::new("AXTextArea")
                .parent(12)
                .text("Draft reply")
                .focused()
                .bounds(340.0, 760.0, 640.0, 120.0)
                .identifier(q("chat_input_field")),
        );

        let mut backend = MockSurfaceBackend::new(nodes).with_window_rect(100.0, 200.0, 1000.0, 700.0);
        let outcome = SurfaceCaptureRunner::run(
            &WECHAT_ADAPTER,
            &id("weixin.exe"),
            &allowlist_policy(&["weixin.exe"]),
            "window",
            48,
            Some(SurfaceHandle(14)),
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        );
        let SurfaceCaptureOutcome::Success(tree) = outcome else {
            panic!("expected WeChat extraction success (prefix={prefix:?}), got {outcome:?}");
        };
        assert_eq!(tree.adapter_id, "wechat");
        assert!(
            !backend.child_requests.iter().any(|r| r.0 == 6),
            "session_list children must NEVER be requested"
        );
        assert!(
            !backend.text_reads.contains(&30),
            "left nav button children must NEVER be read"
        );
        let list_pages: Vec<_> = backend.child_requests.iter().filter(|r| r.0 == 13).collect();
        assert_eq!(list_pages.len(), 1);
        assert_eq!(list_pages[0].1, 88);
        assert_eq!(list_pages[0].2, 32);
        for skipped in 1088..=1092 {
            assert!(
                !backend.text_reads.contains(&skipped),
                "virtual/zero-size cell {skipped} must NEVER be text-read"
            );
        }
        let texts = texts_of(&tree);
        assert_eq!(texts.first().copied(), Some("文件传输助手"));
        assert!(texts.contains(&"14:20"));
        assert!(texts.contains(&"Recent msg 94"));
        assert!(texts.contains(&"Recent msg 119"));
        assert!(!texts.contains(&"Old msg 87"));
        assert!(!texts.contains(&"Hidden zero-size placeholder"));
        assert!(!texts.iter().any(|t| t.starts_with("Session preview")));
        let p94 = texts.iter().position(|&t| t == "Recent msg 94").unwrap();
        let p119 = texts.iter().position(|&t| t == "Recent msg 119").unwrap();
        assert!(p94 < p119, "messages must stay in chronological order");
        let input = tree
            .nodes
            .iter()
            .find(|n| n.ax_role.as_deref() == Some("AXTextArea"))
            .expect("input node");
        assert_eq!(input.role, "editable");
        assert_eq!(input.text.as_deref(), Some("Draft reply"));
        assert_eq!(input.focused, Some(true));
        assert_eq!(tree.nodes.iter().filter(|n| n.focused == Some(true)).count(), 1);
        assert_valid_forest(&tree);
    }

    // Windows WeChat 3.x DuiLib variant (`ListItem`/`AXRow` holding message body directly in Name).
    let mut duilib = HashMap::new();
    duilib.insert(0, MockNode::new("AXWindow").children(vec![1, 2, 3]).bounds(0.0, 0.0, 900.0, 640.0));
    duilib.insert(1, MockNode::new("AXList").children(vec![10]).parent(0).label("会话"));
    duilib.insert(10, MockNode::new("AXRow").parent(1).label("Hidden session row"));
    duilib.insert(2, MockNode::new("AXList").children(vec![20, 21]).parent(0).label("消息"));
    duilib.insert(20, MockNode::new("AXRow").parent(2).label("Hello from WeChat 3.x").bounds(300.0, 100.0, 240.0, 24.0));
    duilib.insert(21, MockNode::new("AXRow").parent(2).label("Second bubble").bounds(300.0, 140.0, 240.0, 24.0));
    duilib.insert(3, MockNode::new("AXTextArea").parent(0).text("3.x draft").focused().bounds(300.0, 500.0, 560.0, 100.0));
    let mut duilib_backend = MockSurfaceBackend::new(duilib).with_window_rect(0.0, 0.0, 900.0, 640.0);
    let SurfaceCaptureOutcome::Success(duilib_tree) = SurfaceCaptureRunner::run(
        &WECHAT_ADAPTER,
        &id("wechat.exe"),
        &allowlist_policy(&["wechat.exe"]),
        "window",
        32,
        Some(SurfaceHandle(3)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut duilib_backend,
    ) else {
        panic!("expected WeChat 3.x DuiLib extraction to succeed");
    };
    assert!(!duilib_backend.child_requests.iter().any(|r| r.0 == 1));
    let dt = texts_of(&duilib_tree);
    assert!(dt.contains(&"Hello from WeChat 3.x"));
    assert!(dt.contains(&"Second bubble"));
    assert!(dt.contains(&"3.x draft"));
    assert!(!dt.contains(&"Hidden session row"));
    assert_valid_forest(&duilib_tree);
}

// ============================================================================
// Test 7: WeChatAdapter Falls Back to Weighted Traversal When Identifiers Absent
// ============================================================================
#[test]
fn wechat_adapter_falls_back_to_weighted_traversal_when_identifiers_absent() {
    let clock = FakeClock::new();
    let mut login = HashMap::new();
    login.insert(0, MockNode::new("AXWindow").children(vec![1]));
    login.insert(1, MockNode::new("AXGroup").children(vec![2, 3]).parent(0));
    login.insert(
        2,
        MockNode::new("AXStaticText")
            .parent(1)
            .text("Scan QR code to log in")
            .reported_length(0),
    );
    login.insert(
        3,
        MockNode::new("AXButton")
            .parent(1)
            .display_text("Switch Account"),
    );

    let app = id("wechat.exe");
    let policy = allowlist_policy(&["wechat.exe"]);

    let mut direct_backend = MockSurfaceBackend::new(login.clone());
    let mut ctx = KernelSurfaceContext::new(
        app.clone(),
        &policy,
        WeChatAdapter.spec(),
        "window",
        48,
        SurfaceHandle(0),
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut direct_backend,
    );
    assert!(WeChatAdapter.extract_surface(&mut ctx).is_none());

    let mut fallback_backend = MockSurfaceBackend::new(login);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &WECHAT_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut fallback_backend,
    ) else {
        panic!("expected weighted traversal fallback on WeChat login screen");
    };
    assert_eq!(tree.adapter_id, "wechat");
    assert!(texts_of(&tree).contains(&"Scan QR code to log in"));
}

// ============================================================================
// Test 8: TyporaAdapter Extracts Markdown Surface, Allows "(Private)", Blocks Secret
// ============================================================================
#[test]
fn typora_adapter_extracts_markdown_surface_allows_private_filename_and_blocks_protected_field() {
    let clock = FakeClock::new();
    let long_paragraph = "Markdown paragraph content. ".repeat(14); // 392 UTF-16 units (>256, <=512)
    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1, 2, 3])
            .window_title("Architecture Notes (Private).md"),
    );
    nodes.insert(1, MockNode::new("AXToolbar").children(vec![10]).parent(0));
    nodes.insert(10, MockNode::new("AXStaticText").parent(1).text("Toolbar noise"));
    nodes.insert(2, MockNode::new("AXScrollArea").children(vec![4]).parent(0));
    nodes.insert(3, MockNode::new("AXMenu").children(vec![11]).parent(0));
    nodes.insert(
        11,
        MockNode::new("AXMenuItem")
            .parent(3)
            .display_text("Hidden context menu"),
    );
    nodes.insert(
        4,
        MockNode::new("AXWebArea")
            .children(vec![5, 6, 7, 8])
            .parent(2)
            .display_text("Architecture Notes"),
    );
    nodes.insert(5, MockNode::new("AXHeading").parent(4).display_text("Design Overview"));
    nodes.insert(
        6,
        MockNode::new("AXTextArea")
            .parent(4)
            .text("Active Markdown draft")
            .focused(),
    );
    nodes.insert(
        7,
        MockNode::new("AXStaticText")
            .parent(4)
            .text(long_paragraph.clone()),
    );
    nodes.insert(
        8,
        MockNode::new("AXSecureTextField")
            .parent(4)
            .text("must-never-read"),
    );

    let mut backend = MockSurfaceBackend::new(nodes);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &TYPORA_ADAPTER,
        &id("typora.exe"),
        &denylist_policy(),
        "window",
        48,
        Some(SurfaceHandle(6)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    ) else {
        panic!("expected Typora capture to succeed");
    };
    assert_eq!(tree.adapter_id, "typora");
    assert!(tree
        .nodes
        .iter()
        .any(|n| n.ax_role.as_deref() == Some("AXHeading") && n.text.as_deref() == Some("Design Overview")));
    assert!(tree.nodes.iter().any(|n| n.ax_role.as_deref() == Some("AXTextArea")
        && n.text.as_deref() == Some("Active Markdown draft")
        && n.focused == Some(true)));
    assert!(tree
        .nodes
        .iter()
        .any(|n| n.ax_role.as_deref() == Some("AXStaticText") && n.text.as_deref() == Some(long_paragraph.as_str())));
    let texts = texts_of(&tree);
    assert!(!texts.contains(&"Toolbar noise"));
    assert!(!texts.contains(&"Hidden context menu"));
    assert!(!backend.text_reads.contains(&8));
    assert!(!texts.contains(&"must-never-read"));
}

// ============================================================================
// Test 9: PUA Filter Helper & Safe Label Security Gating
// ============================================================================
#[test]
fn private_use_only_text_and_safe_label_security_gating() {
    assert!(!is_private_use_only_text(""));
    assert!(!is_private_use_only_text("   \t\n "));
    assert!(is_private_use_only_text("\u{E000}"));
    assert!(is_private_use_only_text("\u{EBB1}"));
    assert!(is_private_use_only_text(" \u{EBB1} \u{F8FF} "));
    assert!(is_private_use_only_text("\u{F0000}"));
    assert!(is_private_use_only_text("\u{FFFFD}"));
    assert!(is_private_use_only_text("\u{100000}"));
    assert!(is_private_use_only_text("\u{10FFFD}"));
    assert!(!is_private_use_only_text("\u{EBB1} adapters_custom.rs"));
    assert!(!is_private_use_only_text("200 Fill × 32 Hug"));

    assert_eq!(
        SafeDisplayText::label(Some("\u{EBB1}"), Some("Source Control"), 64).as_deref(),
        Some("Source Control")
    );
    assert_eq!(SafeDisplayText::label(Some("\u{EBB1}"), Some(" \u{EA60} "), 64), None);
    assert_eq!(
        SafeDisplayText::label(Some("   "), Some("Right sidebar"), 64).as_deref(),
        Some("Right sidebar")
    );

    let clock = FakeClock::new();
    let mut nodes = HashMap::new();
    nodes.insert(0, MockNode::new("AXWindow").children(vec![1, 2, 3]));
    nodes.insert(
        1,
        MockNode::new("AXGroup")
            .subrole("AXLandmarkMain")
            .parent(0)
            .label("Figma Design, 1 item selected"),
    );
    nodes.insert(
        2,
        MockNode::new("AXSecureTextField")
            .parent(0)
            .label("Secret Password Field"),
    );
    nodes.insert(
        3,
        MockNode::new("AXGroup")
            .subrole("AXLandmarkRegion")
            .protected()
            .parent(0)
            .label("Protected Vault"),
    );
    let mut backend = MockSurfaceBackend::new(nodes);
    let policy = allowlist_policy(&["org.example.app"]);
    let mut ctx = KernelSurfaceContext::new(
        id("org.example.app"),
        &policy,
        GENERIC_ADAPTER.spec(),
        "window",
        48,
        SurfaceHandle(0),
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    );
    assert!(ctx.inspect(SurfaceHandle(0)).is_some());
    let safe_info = ctx.inspect(SurfaceHandle(1)).expect("safe node inspects");
    assert_eq!(safe_info.subrole.as_deref(), Some("AXLandmarkMain"));
    assert_eq!(safe_info.label.as_deref(), Some("Figma Design, 1 item selected"));
    assert!(ctx.inspect(SurfaceHandle(2)).is_none(), "AXSecureTextField must never expose info");
    assert!(ctx.inspect(SurfaceHandle(3)).is_none(), "protected node must never expose info");
    assert!(ctx.display_text(SurfaceHandle(2)).is_none());
    assert!(ctx.display_text(SurfaceHandle(3)).is_none());
}

// ============================================================================
// Test 10: VSCodeFamilyAdapter Probes Zero-Length StaticText, Prunes Status Bar, Skips PUA
// ============================================================================
#[test]
fn vscode_family_adapter_probes_zero_length_static_text_prunes_status_bar_and_skips_pua_codicons() {
    let clock = FakeClock::new();
    let status_children: Vec<usize> = (100..126).collect();
    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1])
            .window_title("computer-access-mcp — adapters_custom.rs"),
    );
    nodes.insert(
        1,
        MockNode::new("AXWebArea")
            .children(vec![2, 3, 4, 5])
            .parent(0)
            .display_text("Antigravity IDE"),
    );
    nodes.insert(
        2,
        MockNode::new("AXGroup")
            .subrole("AXApplicationStatus")
            .children(status_children.clone())
            .parent(1)
            .identifier("workbench.parts.statusbar"),
    );
    let ext_names = ["WakaTime", "GitLens", "Prettier", "SQLTools", "SweetPad", "oxc"];
    for (offset, &cid) in status_children.iter().enumerate() {
        nodes.insert(
            cid,
            MockNode::new("AXButton")
                .parent(2)
                .display_text(format!("{} {offset}", ext_names[offset % 6])),
        );
    }

    nodes.insert(3, MockNode::new("AXTabGroup").children(vec![10, 11, 12, 13]).parent(1));
    nodes.insert(10, MockNode::new("AXStaticText").parent(3).text("\u{EBB1}").reported_length(0));
    nodes.insert(11, MockNode::new("AXStaticText").parent(3).text("\u{EA60}").reported_length(0));
    nodes.insert(12, MockNode::new("AXStaticText").parent(3).text("adapters_custom.rs").reported_length(0));
    nodes.insert(13, MockNode::new("AXStaticText").parent(3).text("\u{EBB1} adapters.rs").reported_length(0));
    nodes.insert(4, MockNode::new("AXTextArea").parent(1).text("pub struct FigmaAdapter;").focused());
    nodes.insert(5, MockNode::new("AXWebArea").children(vec![20, 21]).parent(1).display_text("Agent"));
    nodes.insert(20, MockNode::new("AXStaticText").parent(5).text("\u{E001}").reported_length(0));
    nodes.insert(21, MockNode::new("AXStaticText").parent(5).text("Agent response about Phase 4").reported_length(0));

    let mut backend = MockSurfaceBackend::new(nodes);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &VSCODE_FAMILY_ADAPTER,
        &id("antigravity.exe"),
        &allowlist_policy(&["antigravity.exe"]),
        "window",
        24,
        Some(SurfaceHandle(4)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    ) else {
        panic!("expected VSCodeFamilyAdapter capture to succeed");
    };
    assert_eq!(tree.adapter_id, "vscode-family");
    assert!(
        !backend.child_requests.iter().any(|r| r.0 == 2),
        "AXApplicationStatus children must NEVER be requested"
    );
    for &cid in &status_children {
        assert!(
            !backend.inspected_indices.contains(&cid),
            "status bar child {cid} must NEVER be inspected"
        );
    }
    let texts = texts_of(&tree);
    assert!(!texts.iter().any(|t| t.contains("WakaTime") || t.contains("GitLens")));
    assert!(texts.contains(&"adapters_custom.rs"));
    assert!(texts.contains(&"\u{EBB1} adapters.rs"));
    assert!(texts.contains(&"pub struct FigmaAdapter;"));
    assert!(texts.contains(&"Agent response about Phase 4"));
    assert!(!texts.contains(&"\u{EBB1}"));
    assert!(!texts.contains(&"\u{EA60}"));
    assert!(!texts.contains(&"\u{E001}"));
}

// ============================================================================
// Test 11: FigmaAdapter Four Zones from 8-Level Electron Shell & Noise Pruning
//          (macOS + Windows Electron titlebar / AI chrome / y >= window_height / is_offscreen)
// ============================================================================
#[test]
fn figma_adapter_extracts_four_zones_from_eight_level_electron_shell_and_prunes_noise() {
    let clock = FakeClock::new();
    let mut nodes = HashMap::new();

    // 8-level outer Electron shell: AXWindow(0) -> AXGroup(1..6) -> AXScrollArea(7) -> [WebArea #0(10), WebArea #1(20)]
    nodes.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1])
            .window_title("Arco Design System – Figma")
            .bounds(0.0, 0.0, 1920.0, 1250.0),
    );
    for depth in 1..=6 {
        nodes.insert(depth, MockNode::new("AXGroup").children(vec![depth + 1]).parent(depth - 1));
    }
    nodes.insert(7, MockNode::new("AXScrollArea").children(vec![10, 20]).parent(6));

    // WebArea #0: Top Tab Bar [0, 0, 1920, 38] including macOS AND Windows titlebar chrome!
    nodes.insert(
        10,
        MockNode::new("AXWebArea")
            .children(vec![11])
            .parent(7)
            .display_text("Figma")
            .bounds(0.0, 0.0, 1920.0, 38.0)
            .label("Figma"),
    );
    nodes.insert(
        11,
        MockNode::new("AXTabGroup")
            .children(vec![12, 13, 14, 15, 16, 17, 18, 19, 25, 26])
            .parent(10)
            .label("Tab bar"),
    );
    nodes.insert(12, MockNode::new("AXRadioButton").parent(11).display_text("Arco Design System").bounds(80.0, 4.0, 180.0, 30.0).label("Arco Design System"));
    nodes.insert(13, MockNode::new("AXTabButton").parent(11).display_text("Mobile Checkout Flow").bounds(268.0, 4.0, 180.0, 30.0).label("Mobile Checkout Flow"));
    nodes.insert(14, MockNode::new("AXTabButton").parent(11).display_text("Close tab").bounds(240.0, 8.0, 16.0, 16.0).label("Close tab"));
    nodes.insert(15, MockNode::new("AXTabButton").parent(11).display_text("New file").bounds(456.0, 8.0, 24.0, 24.0).label("New file"));
    nodes.insert(16, MockNode::new("AXRadioButton").parent(11).display_text("Open tabs and recently closed items").bounds(488.0, 8.0, 24.0, 24.0).label("Open tabs and recently closed items"));
    // Windows Electron titlebar buttons MUST be pruned!
    nodes.insert(17, MockNode::new("AXTabButton").parent(11).display_text("Minimize").bounds(1780.0, 4.0, 32.0, 30.0).label("Minimize"));
    nodes.insert(18, MockNode::new("AXTabButton").parent(11).display_text("Maximize").bounds(1816.0, 4.0, 32.0, 30.0).label("Maximize"));
    nodes.insert(19, MockNode::new("AXTabButton").parent(11).display_text("Close").bounds(1852.0, 4.0, 32.0, 30.0).label("Close"));
    nodes.insert(25, MockNode::new("AXTabButton").parent(11).display_text("Menu").bounds(10.0, 4.0, 32.0, 30.0).label("Menu"));
    nodes.insert(26, MockNode::new("AXTabButton").parent(11).display_text("Restore").bounds(1816.0, 4.0, 32.0, 30.0).label("Restore"));

    // WebArea #1: Main Document [0, 38, 1920, 1212]
    let main_web_display = SafeDisplayText::compose(
        "AXWebArea",
        Some("Arco Design System – Figma"),
        None,
        Some("https://www.figma.com/design/abc123/Arco-Design-System"),
        256,
    )
    .unwrap();
    nodes.insert(
        20,
        MockNode::new("AXWebArea")
            .children(vec![21])
            .parent(7)
            .display_text(main_web_display.clone())
            .bounds(0.0, 38.0, 1920.0, 1212.0)
            .label("Arco Design System – Figma"),
    );
    nodes.insert(21, MockNode::new("AXGroup").children(vec![300, 100, 200, 90, 91]).parent(20));
    nodes.insert(90, MockNode::new("AXToolbar").children(vec![92]).parent(21).label("Editor"));
    nodes.insert(92, MockNode::new("AXButton").parent(90).display_text("Rectangle").label("Rectangle"));
    nodes.insert(91, MockNode::new("AXToolbar").children(vec![93]).parent(21).label("Help/zoom toolbar"));
    nodes.insert(93, MockNode::new("AXButton").parent(91).display_text("Zoom help").label("Zoom help"));

    // Zone 2: AXLandmarkMain
    nodes.insert(
        100,
        MockNode::new("AXGroup")
            .subrole("AXLandmarkMain")
            .children(vec![101])
            .parent(21)
            .bounds(240.0, 38.0, 1440.0, 1212.0)
            .label("Figma Design, 1 item selected"),
    );
    nodes.insert(101, MockNode::new("AXGroup").children(vec![102]).parent(100));
    nodes.insert(
        102,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(vec![103, 104, 105, 106])
            .parent(101)
            .label("item-list-2nd-level, Design frame"),
    );
    nodes.insert(103, MockNode::new("AXStaticText").parent(102).text("Dimensions").reported_length(0));
    nodes.insert(104, MockNode::new("AXStaticText").parent(102).text("200 Fill × 32 Hug").reported_length(0));
    nodes.insert(105, MockNode::new("AXStaticText").parent(102).text("\u{EBB1}").reported_length(0));
    nodes.insert(
        106,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(vec![107])
            .parent(102)
            .focused()
            .label("treenode/2nd-level, Component instance"),
    );
    nodes.insert(107, MockNode::new("AXStaticText").parent(106).text("176 Fill × 32 Hug").reported_length(0));

    // Zone 3: Right Sidebar (Windows UIA uses AXApplicationGroup for aria_role="region", macOS AXLandmarkRegion!)
    let right_noise = [
        "Apply variable",
        "Add fill",
        "Add stroke",
        "Add effect",
        "Add layout guide",
        "Add export settings",
        "Resize handle",
        "Select matching layers",
        "More actions",
        "Present",
        "Share",
        "Help",
        "Multiplayer tools",
        "Start with an AI draft",
        "AI, Learn more",
    ];
    let mut right_children = vec![201, 202, 203, 204, 205, 206, 208, 209, 210, 211, 212];
    for idx in 0..right_noise.len() {
        right_children.push(250 + idx);
    }
    nodes.insert(
        200,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(right_children)
            .parent(21)
            .bounds(1680.0, 38.0, 240.0, 1212.0)
            .label("Right sidebar"),
    );
    nodes.insert(201, MockNode::new("AXRadioButton").parent(200).display_text("Design").bounds(1690.0, 48.0, 60.0, 24.0).label("Design"));
    nodes.insert(202, MockNode::new("AXRadioButton").parent(200).display_text("Prototype").bounds(1756.0, 48.0, 72.0, 24.0).label("Prototype"));
    nodes.insert(203, MockNode::new("AXButton").parent(200).display_text("73%").bounds(1850.0, 48.0, 44.0, 24.0).label("73%"));
    nodes.insert(204, MockNode::new("AXHeading").parent(200).display_text("TreeNode").bounds(1690.0, 92.0, 180.0, 22.0).label("TreeNode"));
    nodes.insert(205, MockNode::new("AXStaticText").parent(200).text("From this file").reported_length(0).bounds(1690.0, 118.0, 120.0, 18.0));
    nodes.insert(206, MockNode::new("AXComboBox").children(vec![207]).parent(200).bounds(1690.0, 150.0, 180.0, 28.0).label("Level"));
    nodes.insert(207, MockNode::new("AXStaticText").parent(206).text("2nd-level").reported_length(0).bounds(1760.0, 154.0, 90.0, 20.0));
    nodes.insert(208, MockNode::new("AXCheckBox").parent(200).bounds(1690.0, 186.0, 120.0, 24.0).label("Show icon"));
    nodes.insert(209, MockNode::new("AXTextField").parent(200).text("200").bounds(1690.0, 218.0, 64.0, 24.0).label("Width"));
    nodes.insert(
        210,
        MockNode::new("AXButton")
            .parent(200)
            .display_text("Color Variable text/1 with value #1D2129 · 100%")
            .bounds(1690.0, 260.0, 210.0, 28.0)
            .label("Color Variable text/1 with value #1D2129 · 100%"),
    );
    nodes.insert(211, MockNode::new("AXStaticText").parent(200).text("Hidden zero-size text").reported_length(0).bounds(1690.0, 300.0, 0.0, 0.0));
    nodes.insert(212, MockNode::new("AXSlider").parent(200).bounds(1690.0, 320.0, 120.0, 16.0).label("Opacity slider"));
    for (idx, &noise) in right_noise.iter().enumerate() {
        nodes.insert(
            250 + idx,
            MockNode::new("AXButton")
                .parent(200)
                .display_text(noise)
                .bounds(1880.0, 100.0 + idx as f64 * 20.0, 24.0, 24.0)
                .label(noise),
        );
    }

    // Zone 4: Left Sidebar with Windows clipping (negative y, height<=1, y>=window_height, is_offscreen)
    nodes.insert(
        300,
        MockNode::new("AXGroup")
            .subrole("AXLandmarkRegion")
            .children(vec![301, 302, 303, 304, 305, 306, 308, 309, 310, 320])
            .parent(21)
            .bounds(0.0, 38.0, 240.0, 1212.0)
            .label("Left sidebar"),
    );
    nodes.insert(301, MockNode::new("AXToolbar").children(vec![307]).parent(300).bounds(0.0, 38.0, 240.0, 36.0).label("Navigation Bar"));
    nodes.insert(307, MockNode::new("AXButton").parent(301).display_text("Nav noise").label("Nav noise"));
    nodes.insert(302, MockNode::new("AXButton").parent(300).display_text("Minimize UI").bounds(200.0, 44.0, 24.0, 24.0).label("Minimize UI"));
    nodes.insert(303, MockNode::new("AXButton").parent(300).display_text("Collapse layers").bounds(170.0, 80.0, 24.0, 24.0).label("Collapse layers"));
    nodes.insert(304, MockNode::new("AXButton").parent(300).display_text("Find").bounds(140.0, 80.0, 24.0, 24.0).label("Find"));
    nodes.insert(305, MockNode::new("AXButton").parent(300).display_text("Add new page").bounds(200.0, 108.0, 24.0, 24.0).label("Add new page"));
    nodes.insert(306, MockNode::new("AXHeading").parent(300).display_text("Arco File Header").bounds(12.0, 52.0, 160.0, 24.0).label("Arco File Header"));
    nodes.insert(308, MockNode::new("AXButton").parent(300).display_text("Main menu").bounds(12.0, 44.0, 24.0, 24.0).label("Main menu"));
    nodes.insert(309, MockNode::new("AXButton").parent(300).display_text("New slide").bounds(12.0, 80.0, 24.0, 24.0).label("New slide"));
    nodes.insert(310, MockNode::new("AXTable").children(vec![311]).parent(300).bounds(0.0, 108.0, 240.0, 100.0));
    nodes.insert(311, MockNode::new("AXRow").parent(310).bounds(0.0, 112.0, 240.0, 28.0).label("Tree 树"));

    nodes.insert(
        320,
        MockNode::new("AXColumn")
            .children(vec![321, 322, 323, 324, 325, 326])
            .parent(300)
            .bounds(0.0, -200.0, 240.0, 1500.0),
    );
    nodes.insert(321, MockNode::new("AXRow").children(vec![331]).parent(320).bounds(0.0, -32.0, 240.0, 28.0));
    nodes.insert(331, MockNode::new("AXStaticText").parent(321).text("Offscreen Top Layer").reported_length(0));
    nodes.insert(322, MockNode::new("AXRow").children(vec![332]).parent(320).bounds(0.0, 220.0, 240.0, 1.0));
    nodes.insert(332, MockNode::new("AXStaticText").parent(322).text("Collapsed Virtual Placeholder").reported_length(0));
    nodes.insert(323, MockNode::new("AXRow").parent(320).bounds(0.0, 260.0, 240.0, 28.0).label("item-list-2nd-level"));
    nodes.insert(324, MockNode::new("AXRow").children(vec![334]).parent(320).bounds(0.0, 292.0, 240.0, 28.0));
    nodes.insert(334, MockNode::new("AXStaticText").parent(324).text("treenode/2nd-level").reported_length(0).bounds(24.0, 296.0, 180.0, 20.0));
    // Below window_height (y = 1260 >= 1250) & UIA IsOffscreen == true MUST be clipped without reading children!
    nodes.insert(325, MockNode::new("AXRow").children(vec![335]).parent(320).bounds(0.0, 1260.0, 240.0, 28.0));
    nodes.insert(335, MockNode::new("AXStaticText").parent(325).text("Below Viewport Row").reported_length(0));
    nodes.insert(326, MockNode::new("AXRow").children(vec![336]).parent(320).bounds(0.0, 340.0, 240.0, 28.0).offscreen());
    nodes.insert(336, MockNode::new("AXStaticText").parent(326).text("UIA Offscreen Row").reported_length(0));

    let mut backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1920.0, 1250.0);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &id("figma.exe"),
        &allowlist_policy(&["figma.exe"]),
        "window",
        64,
        Some(SurfaceHandle(106)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    ) else {
        panic!("expected FigmaAdapter four-zone capture to succeed");
    };
    assert_eq!(tree.adapter_id, "figma");
    assert!(tree.geometry.is_some());
    assert_valid_forest(&tree);

    let texts = texts_of(&tree);
    assert!(texts.contains(&main_web_display.as_str()));
    assert!(texts.contains(&"Arco Design System"));
    assert!(texts.contains(&"Mobile Checkout Flow"));
    for tab_noise in ["Close tab", "New file", "Open tabs and recently closed items", "Minimize", "Maximize", "Close", "Menu", "Restore"] {
        assert!(!texts.contains(&tab_noise), "tab noise must be pruned: {tab_noise}");
    }

    assert!(texts.contains(&"Figma Design, 1 item selected"));
    assert!(texts.contains(&"item-list-2nd-level, Design frame"));
    assert!(texts.contains(&"200 Fill × 32 Hug"));
    assert!(texts.contains(&"treenode/2nd-level, Component instance"));
    assert!(texts.contains(&"176 Fill × 32 Hug"));
    assert!(!texts.contains(&"Dimensions"));
    assert!(!texts.contains(&"\u{EBB1}"));
    let focused: Vec<_> = tree.nodes.iter().filter(|n| n.focused == Some(true)).collect();
    assert_eq!(focused.len(), 1);
    assert_eq!(
        focused[0].text.as_deref(),
        Some("treenode/2nd-level, Component instance")
    );

    for right_keep in ["Design", "Prototype", "73%", "TreeNode", "From this file", "Level", "2nd-level", "Show icon", "200", "Color Variable text/1 with value #1D2129 · 100%"] {
        assert!(texts.contains(&right_keep), "missing right inspector item: {right_keep}");
    }
    assert!(!texts.contains(&"Hidden zero-size text"));
    assert!(!backend.text_reads.contains(&211));
    for noise in right_noise {
        assert!(!texts.contains(&noise), "right sidebar noise must be pruned: {noise}");
    }

    assert!(texts.contains(&"Arco File Header"));
    assert!(texts.contains(&"Tree 树"));
    assert!(texts.contains(&"item-list-2nd-level"));
    assert!(texts.contains(&"treenode/2nd-level"));
    for clipped in ["Offscreen Top Layer", "Collapsed Virtual Placeholder", "Below Viewport Row", "UIA Offscreen Row"] {
        assert!(!texts.contains(&clipped), "clipped row must not appear: {clipped}");
    }
    for skipped_id in [331, 332, 335, 336] {
        assert!(!backend.text_reads.contains(&skipped_id), "clipped child {skipped_id} must NEVER be text-read");
    }
    for left_noise in ["Minimize UI", "Collapse layers", "Find", "Add new page", "Navigation Bar", "Nav noise", "Main menu", "New slide", "Rectangle", "Zoom help"] {
        assert!(!texts.contains(&left_noise), "chrome noise must be pruned: {left_noise}");
    }
}

// ============================================================================
// Test 12: FigmaAdapter Blocks Protected Fields & Fails Closed on Sensitive Focus
// ============================================================================
#[test]
fn figma_adapter_blocks_protected_fields_and_fails_closed_on_sensitive_focus() {
    let clock = FakeClock::new();
    let mut nodes = HashMap::new();
    nodes.insert(0, MockNode::new("AXWindow").children(vec![1]).bounds(0.0, 0.0, 1440.0, 900.0));
    nodes.insert(1, MockNode::new("AXWebArea").children(vec![2, 3]).parent(0).bounds(0.0, 38.0, 1440.0, 862.0).label("Auth Mockup – Figma"));
    nodes.insert(2, MockNode::new("AXGroup").subrole("AXLandmarkMain").children(vec![10]).parent(1).label("Figma Design, 1 item selected"));
    nodes.insert(10, MockNode::new("AXGroup").subrole("AXApplicationGroup").parent(2).label("Login Card, Design frame"));
    nodes.insert(3, MockNode::new("AXGroup").subrole("AXLandmarkRegion").children(vec![20, 21, 22]).parent(1).bounds(1200.0, 38.0, 240.0, 862.0).label("Right sidebar"));
    nodes.insert(20, MockNode::new("AXSecureTextField").parent(3).text("hunter2").bounds(1210.0, 80.0, 180.0, 24.0).label("API Secret"));
    nodes.insert(21, MockNode::new("AXTextField").protected().parent(3).text("tok_live_secret").bounds(1210.0, 112.0, 180.0, 24.0).label("Protected Token"));
    nodes.insert(22, MockNode::new("AXStaticText").parent(3).text("Public Label").reported_length(0).bounds(1210.0, 144.0, 180.0, 20.0));

    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);

    let mut mixed_backend = MockSurfaceBackend::new(nodes.clone()).with_window_rect(0.0, 0.0, 1440.0, 900.0);
    let SurfaceCaptureOutcome::Success(mixed_tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut mixed_backend,
    ) else {
        panic!("expected safe Figma siblings to succeed");
    };
    assert!(!mixed_backend.text_reads.contains(&20));
    assert!(!mixed_backend.text_reads.contains(&21));
    let t = texts_of(&mixed_tree);
    assert!(t.contains(&"Public Label"));
    for secret in ["hunter2", "API Secret", "tok_live_secret", "Protected Token"] {
        assert!(!t.contains(&secret));
    }

    // Focused protected field MUST abort the entire capture with SecurityExcluded (NO fallback!).
    nodes.get_mut(&20).unwrap().is_focused = true;
    let mut secret_focus_backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1440.0, 900.0);
    let outcome = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        Some(SurfaceHandle(20)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut secret_focus_backend,
    );
    assert_eq!(
        outcome,
        SurfaceCaptureOutcome::Failure(SurfaceReadFailure::SecurityExcluded)
    );
    assert!(!secret_focus_backend.text_reads.contains(&20));
}

// ============================================================================
// Test 13: FigmaAdapter Falls Back to Weighted Traversal on Home/Recents Screen
// ============================================================================
#[test]
fn figma_adapter_falls_back_to_weighted_traversal_on_home_screen() {
    let clock = FakeClock::new();
    let mut home = HashMap::new();
    home.insert(0, MockNode::new("AXWindow").children(vec![1]).window_title("Recents – Figma").bounds(0.0, 0.0, 1440.0, 900.0));
    home.insert(1, MockNode::new("AXScrollArea").children(vec![2, 3]).parent(0));
    home.insert(2, MockNode::new("AXWebArea").parent(1).display_text("Figma").bounds(0.0, 0.0, 1440.0, 38.0).label("Figma"));
    home.insert(3, MockNode::new("AXWebArea").children(vec![4, 5]).parent(1).display_text("Recents – Figma").bounds(0.0, 38.0, 1440.0, 862.0).label("Recents – Figma"));
    home.insert(4, MockNode::new("AXHeading").parent(3).display_text("Recent files").label("Recent files"));
    home.insert(5, MockNode::new("AXStaticText").parent(3).text("Arco Design System").reported_length(0));

    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);

    let mut direct_backend = MockSurfaceBackend::new(home.clone()).with_window_rect(0.0, 0.0, 1440.0, 900.0);
    let mut ctx = KernelSurfaceContext::new(
        app.clone(),
        &policy,
        FigmaAdapter.spec(),
        "window",
        48,
        SurfaceHandle(0),
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut direct_backend,
    );
    ctx.set_initial_window_rect(SurfaceAbsoluteRect::new(0.0, 0.0, 1440.0, 900.0));
    assert!(FigmaAdapter.extract_surface(&mut ctx).is_none());

    let mut fallback_backend = MockSurfaceBackend::new(home).with_window_rect(0.0, 0.0, 1440.0, 900.0);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut fallback_backend,
    ) else {
        panic!("expected weighted fallback on Figma Home screen");
    };
    assert_eq!(tree.adapter_id, "figma");
    let texts = texts_of(&tree);
    assert!(texts.contains(&"Recent files"));
    assert!(texts.contains(&"Arco Design System"));
}

// ============================================================================
// Test 14: FigmaAdapter Proportional Reservation & Text Budget Stay Bounded
// ============================================================================
#[test]
fn figma_adapter_proportional_reservation_and_text_budget_stay_bounded() {
    let clock = FakeClock::new();
    let mut nodes = HashMap::new();
    nodes.insert(0, MockNode::new("AXWindow").children(vec![1]).bounds(0.0, 0.0, 1440.0, 900.0));
    nodes.insert(1, MockNode::new("AXWebArea").children(vec![2, 3, 4]).parent(0).bounds(0.0, 38.0, 1440.0, 862.0).label("Big Canvas – Figma"));

    let canvas_children: Vec<usize> = (100..130).collect();
    nodes.insert(2, MockNode::new("AXGroup").subrole("AXLandmarkMain").children(canvas_children.clone()).parent(1).label("Figma Design, 30 items selected"));
    for nid in canvas_children {
        nodes.insert(nid, MockNode::new("AXGroup").subrole("AXApplicationGroup").parent(2).label(format!("Canvas Layer {nid}, Frame")));
    }

    let right_children: Vec<usize> = (200..215).collect();
    nodes.insert(3, MockNode::new("AXGroup").subrole("AXLandmarkRegion").children(right_children.clone()).parent(1).bounds(1200.0, 38.0, 240.0, 862.0).label("Right sidebar"));
    for nid in right_children {
        nodes.insert(
            nid,
            MockNode::new("AXStaticText")
                .parent(3)
                .text(format!("Inspector Prop {nid}"))
                .reported_length(0)
                .bounds(1210.0, 60.0 + (nid - 200) as f64 * 24.0, 180.0, 20.0),
        );
    }

    let left_children: Vec<usize> = (300..310).collect();
    nodes.insert(4, MockNode::new("AXGroup").subrole("AXLandmarkRegion").children(left_children.clone()).parent(1).bounds(0.0, 38.0, 240.0, 862.0).label("Left sidebar"));
    for nid in left_children {
        nodes.insert(
            nid,
            MockNode::new("AXRow")
                .parent(4)
                .bounds(0.0, 60.0 + (nid - 300) as f64 * 28.0, 240.0, 24.0)
                .label(format!("Sidebar Row {nid}")),
        );
    }

    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);

    let mut backend = MockSurfaceBackend::new(nodes.clone()).with_window_rect(0.0, 0.0, 1440.0, 900.0);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        32,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    ) else {
        panic!("expected bounded Figma capture");
    };
    assert!(tree.nodes.len() <= 32);
    assert!(tree.reasons.iter().any(|r| r == "tree-output-budget"));
    assert_valid_forest(&tree);
    let texts = texts_of(&tree);
    assert!(texts.iter().any(|t| t.starts_with("Canvas Layer")));
    assert!(texts.iter().any(|t| t.starts_with("Inspector Prop")));
    assert!(texts.iter().any(|t| t.starts_with("Sidebar Row")));

    // Tight max_text_units = 120 must degrade gracefully with "text-budget" and NO budget poisoning.
    let mut tight_backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1440.0, 900.0);
    let SurfaceCaptureOutcome::Success(tight_tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        32,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 120),
        &clock,
        &mut tight_backend,
    ) else {
        panic!("tight max_text_units must degrade gracefully rather than abort");
    };
    let total_units: usize = tight_tree
        .nodes
        .iter()
        .filter_map(|n| n.text.as_deref())
        .map(utf16_len)
        .sum();
    assert!(total_units <= 120, "total_units={total_units}");
    assert!(tight_tree.reasons.iter().any(|r| r == "text-budget"));
}

// ============================================================================
// Test 15: FigmaAdapter Depth-8 File Tabs, Slides, Geometric Sidebars & Hidden Sidebars
// ============================================================================
#[test]
fn figma_adapter_captures_depth_eight_file_tabs_slides_windows_geo_sidebars_and_hidden_sidebars() {
    let clock = FakeClock::new();
    let mut nodes = HashMap::new();
    nodes.insert(0, MockNode::new("AXWindow").children(vec![1, 2]).bounds(0.0, 0.0, 1920.0, 1250.0));

    // Depth-8 file tabs under Tab Bar AXWebArea
    nodes.insert(1, MockNode::new("AXWebArea").children(vec![10]).parent(0).display_text("Figma").bounds(0.0, 0.0, 1920.0, 38.0).label("Figma"));
    nodes.insert(10, MockNode::new("AXGroup").children(vec![11]).parent(1).bounds(0.0, 0.0, 1920.0, 38.0));
    nodes.insert(11, MockNode::new("AXGroup").children(vec![12]).parent(10).bounds(0.0, 0.0, 1920.0, 38.0));
    nodes.insert(12, MockNode::new("AXGroup").children(vec![13]).parent(11).bounds(0.0, 0.0, 1920.0, 38.0));
    nodes.insert(13, MockNode::new("AXTabGroup").children(vec![14]).parent(12).bounds(0.0, 0.0, 1920.0, 38.0).label("Tab bar"));
    nodes.insert(14, MockNode::new("AXGroup").children(vec![15, 16]).parent(13).bounds(0.0, 0.0, 1920.0, 38.0));
    nodes.insert(15, MockNode::new("AXRadioButton").parent(14).display_text("Home").bounds(81.0, 0.0, 40.0, 38.0).label("Home"));
    nodes.insert(16, MockNode::new("AXGroup").children(vec![17]).parent(14).bounds(121.0, 0.0, 900.0, 38.0));
    nodes.insert(17, MockNode::new("AXGroup").children(vec![18, 19]).parent(16).bounds(121.0, 0.0, 900.0, 38.0));
    nodes.insert(18, MockNode::new("AXRadioButton").parent(17).display_text("Sketchpad").bounds(121.0, 0.0, 133.0, 38.0).label("Sketchpad"));
    nodes.insert(19, MockNode::new("AXRadioButton").parent(17).display_text("Slide Deck Demo").bounds(254.0, 0.0, 149.0, 38.0).label("Slide Deck Demo"));

    // Main Slides AXWebArea + unlabeled geometric right sidebar (Windows Electron fallback!)
    nodes.insert(
        2,
        MockNode::new("AXWebArea")
            .children(vec![30, 40])
            .parent(0)
            .display_text("Slide Deck Demo – Figma Slides (https://www.figma.com/slides/demo)")
            .bounds(0.0, 38.0, 1920.0, 1212.0)
            .label("Slide Deck Demo – Figma Slides"),
    );
    nodes.insert(
        30,
        MockNode::new("AXGroup")
            .subrole("AXLandmarkMain")
            .children(vec![31])
            .parent(2)
            .bounds(0.0, 38.0, 1680.0, 1212.0)
            .label("Figma Slides, 1 item selected"),
    );
    nodes.insert(
        31,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(vec![32])
            .parent(30)
            .bounds(256.0, 135.0, 1407.0, 791.0)
            .label("Slide 6"),
    );
    nodes.insert(
        32,
        MockNode::new("AXHeading")
            .parent(31)
            .display_text("Architecture Overview")
            .bounds(350.0, 228.0, 600.0, 43.0)
            .label("Architecture Overview"),
    );
    // Notice: NO explicit "Right sidebar" label — resolved via Windows geometric fallback (x > 1920 - 320)!
    nodes.insert(
        40,
        MockNode::new("AXGroup")
            .children(vec![41, 42, 43, 44])
            .parent(2)
            .bounds(1680.0, 38.0, 240.0, 1212.0),
    );
    nodes.insert(41, MockNode::new("AXRadioButton").parent(40).display_text("Animate").bounds(1745.0, 86.0, 61.0, 24.0).label("Animate"));
    nodes.insert(42, MockNode::new("AXButton").parent(40).display_text("Align left").bounds(1688.0, 127.0, 30.0, 24.0).label("Align left"));
    nodes.insert(43, MockNode::new("AXPopUpButton").parent(40).display_text("Apply variable mode").bounds(1888.0, 127.0, 24.0, 24.0).label("Apply variable mode"));
    nodes.insert(44, MockNode::new("AXButton").parent(40).display_text("Edit template style").bounds(1880.0, 176.0, 24.0, 24.0).label("Edit template style"));

    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);

    let mut backend = MockSurfaceBackend::new(nodes.clone()).with_window_rect(0.0, 0.0, 1920.0, 1250.0);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    ) else {
        panic!("expected Figma Slides capture to succeed");
    };
    assert_valid_forest(&tree);
    let texts = texts_of(&tree);
    assert!(texts.contains(&"Home"));
    assert!(texts.contains(&"Sketchpad"));
    assert!(texts.contains(&"Slide Deck Demo"));
    assert!(texts.contains(&"Figma Slides, 1 item selected"));
    assert!(texts.contains(&"Slide 6"));
    assert!(texts.contains(&"Architecture Overview"));
    assert!(texts.contains(&"Animate"));
    assert!(!texts.contains(&"Align left"));
    assert!(!texts.contains(&"Apply variable mode"));
    assert!(!texts.contains(&"Edit template style"));

    // Sidebar-hidden mode (Ctrl+\ / Cmd+\): no sidebars -> clean compact Tab Bar + Canvas snapshot!
    nodes.insert(
        2,
        MockNode::new("AXWebArea")
            .children(vec![30])
            .parent(0)
            .display_text("Slide Deck Demo – Figma Slides (https://www.figma.com/slides/demo)")
            .bounds(0.0, 38.0, 1920.0, 1212.0)
            .label("Slide Deck Demo – Figma Slides"),
    );
    nodes.get_mut(&30).unwrap().bounds = SurfaceAbsoluteRect::new(0.0, 38.0, 1920.0, 1212.0);
    let mut hidden_backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1920.0, 1250.0);
    let SurfaceCaptureOutcome::Success(hidden_tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut hidden_backend,
    ) else {
        panic!("expected compact hidden-sidebar Figma snapshot");
    };
    assert_valid_forest(&hidden_tree);
    let ht = texts_of(&hidden_tree);
    assert!(ht.contains(&"Sketchpad"));
    assert!(ht.contains(&"Slide 6"));
    assert!(ht.contains(&"Architecture Overview"));
    assert!(!ht.contains(&"Animate"));
}

// ============================================================================
// Test 16: Transactional SurfaceNodeMap & SurfaceBaseline Commit, Pinning & 192 Rollover
// ============================================================================
#[test]
fn surface_node_map_transactional_commit_adapter_reset_pinning_and_192_rollover() {
    let mut node_map = SurfaceNodeMap::new();
    let mut baseline = SurfaceBaseline::new();
    let focus_key = RuntimeIdKey(vec![42, 999]);
    let focus_uuid = node_map.identifier(&focus_key).expect("focus id allocated");

    // 1. First commit under "wechat" adapter succeeds.
    let batch1: Vec<RuntimeIdKey> = (0..10).map(|i| RuntimeIdKey(vec![1, i])).collect();
    let mut proposed1 = node_map.clone();
    let reset1 = proposed1.prepare_commit("wechat", &batch1, Some((&focus_key, &focus_uuid)));
    assert!(reset1, "initial adapter assignment resets map");
    let mut nodes1 = Vec::new();
    let mut refs1 = Vec::new();
    for (i, k) in batch1.iter().enumerate() {
        let local = format!("n{i}");
        nodes1.push(SurfaceNode {
            id: local.clone(),
            parent_id: (i > 0).then(|| "n0".to_string()),
            role: if i == 0 { "container" } else { "text" }.to_string(),
            text: (i > 0).then(|| format!("msg-{i}")),
            observed_at_ms: 100,
            bounds: None,
            bounds_observed_at_ms: None,
            ax_role: Some(if i == 0 { "AXWindow" } else { "AXStaticText" }.to_string()),
            focused: None,
        });
        refs1.push((local, k.clone()));
    }
    let pending1 = PendingSurfaceCapture {
        nodes: nodes1,
        truncated: false,
        reasons: Vec::new(),
        complete: true,
        geometry: None,
        adapter_id: "wechat".to_string(),
        references: refs1,
    };
    let mat1 = pending1
        .materialize_nodes(|k| proposed1.identifier(k))
        .expect("batch1 materializes");
    node_map = proposed1;
    let snap1 = baseline.snapshot("surf-1", "window", mat1, true, true, false, vec![], None);
    assert_eq!(snap1.mode, "full");
    assert_eq!(node_map.adapter_id(), Some("wechat"));

    // 2. Malformed capture (dangling parent) rejects BEFORE allocating any stable IDs or mutating live map!
    let live_len_before = node_map.len();
    let mut proposed_bad = node_map.clone();
    let bad_pending = PendingSurfaceCapture {
        nodes: vec![SurfaceNode {
            id: "n0".to_string(),
            parent_id: Some("missing-parent".to_string()),
            role: "text".to_string(),
            text: Some("orphan".to_string()),
            observed_at_ms: 200,
            bounds: None,
            bounds_observed_at_ms: None,
            ax_role: Some("AXStaticText".to_string()),
            focused: None,
        }],
        truncated: false,
        reasons: Vec::new(),
        complete: true,
        geometry: None,
        adapter_id: "wechat".to_string(),
        references: vec![("n0".to_string(), RuntimeIdKey(vec![777]))],
    };
    assert!(bad_pending
        .materialize_nodes(|k| proposed_bad.identifier(k))
        .is_none());
    assert_eq!(node_map.len(), live_len_before);
    assert_eq!(proposed_bad.len(), live_len_before, "rejected capture must not allocate UUIDs");

    // 3. Adapter boundary switch ("wechat" -> "figma") resets SurfaceNodeMap while pinning focus UUID!
    let mut proposed_switch = node_map.clone();
    let figma_keys = vec![focus_key.clone(), RuntimeIdKey(vec![2, 1])];
    let switched = proposed_switch.prepare_commit(
        "figma",
        &figma_keys,
        Some((&focus_key, &focus_uuid)),
    );
    assert!(switched);
    assert_eq!(proposed_switch.identifier(&focus_key).as_deref(), Some(focus_uuid.as_str()));
    assert_eq!(proposed_switch.adapter_id(), Some("figma"));
    node_map = proposed_switch;

    // 4. 192-entry batch rollover stays bounded with intact parent/focus refs.
    for round in 0..4i32 {
        let keys: Vec<RuntimeIdKey> = (0..64).map(|i| RuntimeIdKey(vec![100 + round, i])).collect();
        let mut prop = node_map.clone();
        let _ = prop.prepare_commit("figma", &keys, Some((&focus_key, &focus_uuid)));
        let pending = PendingSurfaceCapture {
            nodes: keys
                .iter()
                .enumerate()
                .map(|(i, _)| SurfaceNode {
                    id: format!("r{i}"),
                    parent_id: (i > 0).then(|| "r0".to_string()),
                    role: if i == 0 { "container" } else { "text" }.to_string(),
                    text: (i > 0).then(|| format!("item-{round}-{i}")),
                    observed_at_ms: 300 + i64::from(round),
                    bounds: None,
                    bounds_observed_at_ms: None,
                    ax_role: Some("AXStaticText".to_string()),
                    focused: None,
                })
                .collect(),
            truncated: false,
            reasons: Vec::new(),
            complete: true,
            geometry: None,
            adapter_id: "figma".to_string(),
            references: keys
                .iter()
                .enumerate()
                .map(|(i, k)| (format!("r{i}"), k.clone()))
                .collect(),
        };
        let materialized = pending
            .materialize_nodes(|k| prop.identifier(k))
            .expect("rollover batch materializes");
        assert_eq!(materialized.len(), 64);
        assert!(prop.len() <= SurfaceNodeMap::DEFAULT_CAPACITY);
        assert_eq!(prop.identifier(&focus_key).as_deref(), Some(focus_uuid.as_str()));
        node_map = prop;
    }
}

// ============================================================================
// Test 17: Zero-Size Empty / ZWSP Ghost Node Filtering (Feishu & Slack Tuning)
// ============================================================================
#[test]
fn weighted_traversal_filters_zero_size_zwsp_ghost_nodes_for_feishu_and_slack() {
    let clock = FakeClock::new();
    let mut nodes = HashMap::new();
    // 15 zero-size ZWSP/whitespace ghost leaves + 3 visible chat messages + 1 focused zero-size composer
    let mut children = Vec::new();
    for i in 1..=15 {
        children.push(i);
        let ghost_text = match i % 5 {
            0 => "",
            1 => "\u{200B}",
            2 => "\u{200C}\u{200D}",
            3 => "\u{FEFF}\u{00A0}",
            _ => "   ",
        };
        nodes.insert(
            i,
            MockNode::new("AXStaticText")
                .parent(0)
                .text(ghost_text)
                .bounds(100.0, 200.0, 0.0, 0.0),
        );
    }
    // 2 zero-size empty container ghosts
    for i in 16..=17 {
        children.push(i);
        nodes.insert(i, MockNode::new("AXGroup").parent(0).bounds(100.0, 200.0, 0.0, 0.0));
    }
    // 3 real visible chat messages
    for (offset, msg) in ["Feishu real message 1", "Feishu real message 2", "Slack real message 3"]
        .iter()
        .enumerate()
    {
        let nid = 30 + offset;
        children.push(nid);
        nodes.insert(
            nid,
            MockNode::new("AXStaticText")
                .parent(0)
                .text(*msg)
                .bounds(120.0, 240.0 + offset as f64 * 24.0, 300.0, 20.0),
        );
    }
    // Focused node is preserved even if 0x0 with empty text!
    children.push(40);
    nodes.insert(
        40,
        MockNode::new("AXTextArea")
            .parent(0)
            .text("")
            .focused()
            .bounds(100.0, 200.0, 0.0, 0.0),
    );
    nodes.insert(0, MockNode::new("AXWindow").children(children).bounds(100.0, 200.0, 800.0, 600.0));

    let mut backend = MockSurfaceBackend::new(nodes);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &SLACK_ADAPTER,
        &id("slack.exe"),
        &allowlist_policy(&["slack.exe"]),
        "window",
        8, // Tight node cap: ghosts MUST NOT crowd out the 3 real messages or focused composer!
        Some(SurfaceHandle(40)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    ) else {
        panic!("expected Slack capture to succeed");
    };
    let texts = texts_of(&tree);
    assert!(texts.contains(&"Feishu real message 1"));
    assert!(texts.contains(&"Feishu real message 2"));
    assert!(texts.contains(&"Slack real message 3"));
    assert!(tree.nodes.iter().any(|n| n.focused == Some(true) && n.ax_role.as_deref() == Some("AXTextArea")));
    assert!(!texts.contains(&"\u{200B}"));
    assert!(!texts.contains(&"\u{200C}\u{200D}"));
    assert!(!texts.contains(&"\u{FEFF}\u{00A0}"));
    assert_valid_forest(&tree);
}

// ============================================================================
// Test 18: Private & Incognito Browser Windows Block with Zero Content Read
// ============================================================================
#[test]
fn private_and_incognito_browser_windows_block_capture_with_zero_content_read() {
    let clock = FakeClock::new();
    let app = id("chrome.exe");
    let policy = denylist_policy();

    for title in [
        "GitHub - Google Chrome (Incognito)",
        "新标签页 - 无痕模式",
        "Mozilla Firefox (Private Browsing)",
        "InPrivate - Microsoft Edge",
        "Brave (Private)",
    ] {
        assert!(BrowserGate::is_private_window_title(title));
        let mut nodes = HashMap::new();
        nodes.insert(0, MockNode::new("AXWindow").children(vec![1]).window_title(title));
        nodes.insert(1, MockNode::new("AXStaticText").parent(0).text("Private content"));
        let mut backend = MockSurfaceBackend::new(nodes);
        let res = SurfaceCaptureRunner::run(
            &BROWSER_FAMILY_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            Some(SurfaceHandle(1)),
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        );
        assert_eq!(
            res,
            SurfaceCaptureOutcome::Failure(SurfaceReadFailure::SecurityExcluded),
            "title={title}"
        );
        assert!(backend.text_reads.is_empty());
        assert_eq!(backend.inspected_indices, vec![0]);
    }

    // Normal browser window succeeds, extracts WebArea title + URL & Heading, and prunes empty disabled leaf.
    let mut normal = HashMap::new();
    normal.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1, 2, 3, 4])
            .window_title("GitHub - Google Chrome"),
    );
    normal.insert(
        1,
        MockNode::new("AXWebArea")
            .parent(0)
            .display_text(
                SafeDisplayText::compose(
                    "AXWebArea",
                    Some("GitHub"),
                    None,
                    Some("https://github.com"),
                    256,
                )
                .unwrap(),
            ),
    );
    normal.insert(
        2,
        MockNode::new("AXHeading")
            .parent(0)
            .display_text("Pull Requests"),
    );
    normal.insert(3, MockNode::new("AXButton").parent(0).enabled(false));
    normal.insert(4, MockNode::new("AXStaticText").parent(0).text("Open 12"));
    let mut normal_backend = MockSurfaceBackend::new(normal);
    let SurfaceCaptureOutcome::Success(normal_tree) = SurfaceCaptureRunner::run(
        &BROWSER_FAMILY_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut normal_backend,
    ) else {
        panic!("expected normal browser window to succeed");
    };
    assert!(normal_tree
        .nodes
        .iter()
        .any(|n| n.ax_role.as_deref() == Some("AXWebArea")
            && n.text.as_deref() == Some("GitHub (https://github.com)")));
    assert!(normal_tree
        .nodes
        .iter()
        .any(|n| n.ax_role.as_deref() == Some("AXHeading")
            && n.role == "text"
            && n.text.as_deref() == Some("Pull Requests")));
    assert!(!normal_tree
        .nodes
        .iter()
        .any(|n| n.ax_role.as_deref() == Some("AXButton")));

    // Batched inspection bounds avoid extra read_backend_node_bounds IPCs.
    let mut batched = HashMap::new();
    batched.insert(0, MockNode::new("AXWindow").children(vec![1]).bounds(100.0, 200.0, 800.0, 600.0));
    batched.insert(1, MockNode::new("AXStaticText").parent(0).text("Batched bounds message").bounds(120.0, 250.0, 300.0, 24.0));
    let mut batched_backend = MockSurfaceBackend::new(batched);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &WECHAT_ADAPTER,
        &id("wechat.exe"),
        &allowlist_policy(&["wechat.exe"]),
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut batched_backend,
    ) else {
        panic!("expected batched bounds capture to succeed");
    };
    assert_eq!(batched_backend.bounds_calls, 0);
    let leaf = tree.nodes.iter().find(|n| n.ax_role.as_deref() == Some("AXStaticText")).unwrap();
    assert_eq!(leaf.bounds, Some(SurfaceBounds::new(20.0, 50.0, 300.0, 24.0)));
    assert!(ApplicationPolicy::is_mandatory_denied("1password.exe"));
    assert!(ApplicationPolicy::is_mandatory_denied("bitwarden.exe"));
    assert!(ApplicationPolicy::is_system_ui("lockapp.exe"));
}

// ============================================================================
// Test 19: Security TOCTOU in KernelSurfaceContext::read_text (Password & Role Drift)
// ============================================================================
#[test]
fn read_text_security_toctou_evicts_handle_and_blocks_wechat_and_rogue_emission() {
    let clock = FakeClock::new();
    let app = id("wechat.exe");
    let policy = allowlist_policy(&["wechat.exe"]);

    let build_wechat_nodes = || {
        let mut nodes = HashMap::new();
        nodes.insert(
            0,
            MockNode::new("AXWindow")
                .children(vec![1, 2, 3])
                .bounds(100.0, 200.0, 900.0, 700.0),
        );
        nodes.insert(
            1,
            MockNode::new("AXStaticText")
                .parent(0)
                .identifier("MainWindow.current_chat_name_label")
                .text("Alice")
                .bounds(320.0, 210.0, 200.0, 28.0),
        );
        nodes.insert(
            2,
            MockNode::new("AXList")
                .parent(0)
                .identifier("MainWindow.chat_message_list")
                .children(vec![4])
                .bounds(320.0, 250.0, 560.0, 350.0),
        );
        nodes.insert(
            3,
            MockNode::new("AXTextArea")
                .parent(0)
                .identifier("MainWindow.chat_input_field")
                .text("secret-after-mutation")
                .bounds(320.0, 620.0, 560.0, 64.0),
        );
        nodes.insert(
            4,
            MockNode::new("AXStaticText")
                .parent(2)
                .text("Hello from Alice")
                .bounds(340.0, 560.0, 300.0, 24.0),
        );
        nodes
    };

    // Helper rogue adapter that ignores ctx.text() == None and tries to emit handle 3 anyway.
    struct RogueToctouAdapter;
    impl AppAdapter for RogueToctouAdapter {
        fn spec(&self) -> &'static AppAdapterSpec {
            WECHAT_ADAPTER.spec()
        }
        fn extract_surface(&self, ctx: &mut dyn SafeSurfaceContext) -> Option<CustomSurfaceResult> {
            let root = ctx.inspect(ctx.root())?;
            let inp = ctx.inspect(SurfaceHandle(3))?;
            let draft = ctx.text(inp.handle, None);
            assert!(draft.is_none());
            Some(CustomSurfaceResult {
                nodes: vec![
                    CustomSurfaceNode {
                        handle: root.handle,
                        parent: None,
                        role: "container",
                        ax_role: Some(root.role),
                        text: None,
                        is_focused: false,
                        observed_at_ms: root.observed_at_ms,
                        bounds: None,
                        bounds_observed_at_ms: None,
                    },
                    CustomSurfaceNode {
                        handle: inp.handle,
                        parent: Some(root.handle),
                        role: "editable",
                        ax_role: Some(inp.role),
                        text: draft,
                        is_focused: false,
                        observed_at_ms: inp.observed_at_ms,
                        bounds: None,
                        bounds_observed_at_ms: None,
                    },
                ],
                complete: false,
                missing_reasons: Vec::new(),
            })
        }
    }

    let make_password_hook = || -> InspectHook {
        let mut inp_inspections = 0usize;
        Box::new(move |idx, _| {
            if idx == 3 {
                inp_inspections += 1;
                if inp_inspections >= 2 {
                    return Some(BackendInspection::Allowed(Box::new(BackendAllowedNode {
                        role: "AXTextArea".to_string(),
                        category: "editable",
                        subrole: SubroleRead::NoValue,
                        protected_content: ProtectedContentRead::Value(true),
                        child_count: 0,
                        is_focused: false,
                        observed_at_ms: 1_003,
                        is_enabled: Some(true),
                        display_text: None,
                        window_title: None,
                        absolute_rect: SurfaceAbsoluteRect::new(320.0, 620.0, 560.0, 64.0),
                        identifier: Some("MainWindow.chat_input_field".to_string()),
                        class_name: None,
                        label: None,
                        is_offscreen: false,
                        strict_security: None,
                    })));
                }
            }
            None
        })
    };

    let make_role_drift_hook = || -> InspectHook {
        let mut inp_inspections = 0usize;
        Box::new(move |idx, _| {
            if idx == 3 {
                inp_inspections += 1;
                if inp_inspections >= 2 {
                    return Some(BackendInspection::Allowed(Box::new(BackendAllowedNode {
                        role: "AXGroup".to_string(),
                        category: "container",
                        subrole: SubroleRead::NoValue,
                        protected_content: ProtectedContentRead::Value(false),
                        child_count: 0,
                        is_focused: false,
                        observed_at_ms: 1_003,
                        is_enabled: Some(true),
                        display_text: None,
                        window_title: None,
                        absolute_rect: SurfaceAbsoluteRect::new(320.0, 620.0, 560.0, 64.0),
                        identifier: Some("MainWindow.chat_input_field".to_string()),
                        class_name: None,
                        label: None,
                        is_offscreen: false,
                        strict_security: None,
                    })));
                }
            }
            None
        })
    };

    // 1a. Direct KernelSurfaceContext check: password mutation evicts inspected_nodes & sampled_bounds!
    {
        let mut backend = MockSurfaceBackend::new(build_wechat_nodes());
        backend.on_inspect = Some(make_password_hook());
        let mut ctx = KernelSurfaceContext::new(
            app.clone(),
            &policy,
            WECHAT_ADAPTER.spec(),
            "window",
            48,
            SurfaceHandle(0),
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        );
        ctx.set_initial_window_rect(SurfaceAbsoluteRect::new(100.0, 200.0, 900.0, 700.0));
        assert!(ctx.inspect(SurfaceHandle(3)).is_some());
        assert!(ctx.has_inspected(SurfaceHandle(3)));
        assert!(ctx.sampled_bounds().contains_key(&SurfaceHandle(3)));
        assert_eq!(ctx.text(SurfaceHandle(3), None), None);
        assert!(!ctx.has_inspected(SurfaceHandle(3)));
        assert!(!ctx.inspected_nodes().contains_key(&SurfaceHandle(3)));
        assert!(!ctx.sampled_bounds().contains_key(&SurfaceHandle(3)));
        assert!(ctx.extra_reasons().contains("node-security-excluded"));
        assert!(backend.text_reads.is_empty());
    }

    // 1b. WeChatAdapter skips evicted newly-sensitive chat_input_field while preserving safe messages.
    {
        let mut backend = MockSurfaceBackend::new(build_wechat_nodes());
        backend.on_inspect = Some(make_password_hook());
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &WECHAT_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected unfocused password TOCTOU in WeChat to prune input cleanly");
        };
        assert!(!tree.handles.iter().any(|(_, idx)| *idx == 3));
        assert!(!tree.nodes.iter().any(|n| n.role == "editable"));
        assert!(tree.reasons.iter().any(|r| r == "node-security-excluded"));
        assert!(!backend.text_reads.contains(&3));
        let texts = texts_of(&tree);
        assert!(texts.contains(&"Alice"));
        assert!(texts.contains(&"Hello from Alice"));
        assert_valid_forest(&tree);
    }

    // 1c. Rogue adapter trying to emit evicted newly-sensitive handle fails closed (BoundaryUnverified).
    {
        let mut backend = MockSurfaceBackend::new(build_wechat_nodes());
        backend.on_inspect = Some(make_password_hook());
        let outcome = SurfaceCaptureRunner::run(
            &RogueToctouAdapter,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        );
        assert_eq!(
            outcome,
            SurfaceCaptureOutcome::Failure(SurfaceReadFailure::BoundaryUnverified)
        );
        assert!(backend.text_reads.is_empty());
    }

    // 2a. Role drift TOCTOU evicts handle from inspected_nodes & sampled_bounds and WeChat skips it.
    {
        let mut backend = MockSurfaceBackend::new(build_wechat_nodes());
        backend.on_inspect = Some(make_role_drift_hook());
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &WECHAT_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected role-drift TOCTOU in WeChat to prune input cleanly");
        };
        assert!(!tree.handles.iter().any(|(_, idx)| *idx == 3));
        assert!(tree.reasons.iter().any(|r| r == "node-role-changed"));
        assert!(!backend.text_reads.contains(&3));
        assert_valid_forest(&tree);
    }

    // 2b. Rogue adapter trying to emit role-drifted handle fails closed (BoundaryUnverified).
    {
        let mut backend = MockSurfaceBackend::new(build_wechat_nodes());
        backend.on_inspect = Some(make_role_drift_hook());
        let outcome = SurfaceCaptureRunner::run(
            &RogueToctouAdapter,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        );
        assert_eq!(
            outcome,
            SurfaceCaptureOutcome::Failure(SurfaceReadFailure::BoundaryUnverified)
        );
    }

    // 3. Focused chat_input_field mutating to is_password=true before read_text aborts with SecurityExcluded!
    {
        let mut nodes = build_wechat_nodes();
        nodes.get_mut(&3).unwrap().is_focused = true;
        let mut backend = MockSurfaceBackend::new(nodes);
        backend.on_inspect = Some(make_password_hook());
        let outcome = SurfaceCaptureRunner::run(
            &WECHAT_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            Some(SurfaceHandle(3)),
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        );
        assert_eq!(
            outcome,
            SurfaceCaptureOutcome::Failure(SurfaceReadFailure::SecurityExcluded)
        );
        assert!(!backend.text_reads.contains(&3));
    }
}

// ============================================================================
// Test 20: Multi-IPC Call Budget Accounting & AccessDenied Propagation
// ============================================================================
#[test]
fn multi_ipc_backend_call_accounting_and_access_denied_propagation() {
    let clock = FakeClock::new();
    let app = id("wechat.exe");
    let policy = allowlist_policy(&["wechat.exe"]);

    let mut nodes = HashMap::new();
    let child_ids: Vec<usize> = (10..40).collect();
    nodes.insert(0, MockNode::new("AXWindow").children(vec![1]));
    nodes.insert(1, MockNode::new("AXList").parent(0).children(child_ids.clone()));
    for &cid in &child_ids {
        nodes.insert(
            cid,
            MockNode::new("AXStaticText")
                .parent(1)
                .text(format!("row-{cid}")),
        );
    }

    // 1. Multi-IPC children() & tail_children() charge exact COM IPC counts (> 1) to ReadBudget!
    {
        let mut backend = MockSurfaceBackend::new(nodes.clone());
        backend.charge_per_child_ipc = true;
        let mut ctx = KernelSurfaceContext::new(
            app.clone(),
            &policy,
            WECHAT_ADAPTER.spec(),
            "window",
            48,
            SurfaceHandle(0),
            None,
            ReadBudget::new(5_000, 150, 200, 32, 8_192),
            &clock,
            &mut backend,
        );
        assert!(ctx.inspect(SurfaceHandle(1)).is_some());
        let calls_after_inspect = ctx.budget().calls();
        let page = ctx.children(SurfaceHandle(1), 0, 10).expect("page returned");
        assert_eq!(page.len(), 10);
        assert!(ctx.last_children_truncated());
        assert_eq!(
            ctx.budget().calls(),
            calls_after_inspect + 10,
            "every sibling IPC inside children() must charge ReadBudget::max_calls"
        );

        let calls_before_tail = ctx.budget().calls();
        let tail = ctx.tail_children(SurfaceHandle(1), 12).expect("tail returned");
        assert_eq!(tail.len(), 12);
        assert!(ctx.last_children_truncated());
        assert_eq!(
            ctx.budget().calls(),
            calls_before_tail + 12,
            "every sibling IPC inside tail_children() must charge ReadBudget::max_calls"
        );
    }

    // 2. Tight ReadBudget call ceiling halts multi-IPC tail_children() mid-walk without exceeding cap!
    {
        let mut backend = MockSurfaceBackend::new(nodes.clone());
        backend.charge_per_child_ipc = true;
        // 16 total with 8 reserved -> 8 exploration calls total (1 for inspect, 7 left for tail walk).
        let mut ctx = KernelSurfaceContext::new(
            app.clone(),
            &policy,
            WECHAT_ADAPTER.spec(),
            "window",
            48,
            SurfaceHandle(0),
            None,
            ReadBudget::new(5_000, 150, 16, 8, 8_192),
            &clock,
            &mut backend,
        );
        assert!(ctx.inspect(SurfaceHandle(1)).is_some());
        assert_eq!(ctx.budget().remaining_calls(), 7);
        let tail = ctx
            .tail_children(SurfaceHandle(1), 30)
            .expect("partial tail returned before budget hit");
        assert_eq!(tail.len(), 7, "must stop immediately once 7 remaining calls are used");
        assert!(ctx.last_children_truncated());
        assert_eq!(ctx.budget().remaining_calls(), 0);
        assert_eq!(ctx.budget().calls(), 8);
        assert!(!ctx.can_continue());
        assert!(ctx.extra_reasons().contains("tree-call-budget"));
        assert!(ctx.extra_reasons().contains("tree-output-budget"));
        // Final validation reserve of 8 calls stays intact!
        ctx.begin_final_validation();
        assert_eq!(ctx.budget().remaining_calls(), 8);
    }

    // 3. AccessDenied propagation: non-root prunes with tree-provider-refused; root aborts!
    {
        let mut backend = MockSurfaceBackend::new(nodes.clone());
        backend.access_denied_children.insert(1);
        let mut ctx = KernelSurfaceContext::new(
            app.clone(),
            &policy,
            WECHAT_ADAPTER.spec(),
            "window",
            48,
            SurfaceHandle(0),
            None,
            ReadBudget::new(5_000, 150, 200, 32, 8_192),
            &clock,
            &mut backend,
        );
        assert!(ctx.inspect(SurfaceHandle(1)).is_some());
        assert_eq!(ctx.children(SurfaceHandle(1), 0, 10), None);
        assert_eq!(ctx.tail_children(SurfaceHandle(1), 10), None);
        assert!(!ctx.is_aborted());
        assert!(ctx.extra_reasons().contains("tree-provider-refused"));
    }
    {
        let mut backend = MockSurfaceBackend::new(nodes);
        backend.access_denied_children.insert(0);
        let mut ctx = KernelSurfaceContext::new(
            app,
            &policy,
            WECHAT_ADAPTER.spec(),
            "window",
            48,
            SurfaceHandle(0),
            None,
            ReadBudget::new(5_000, 150, 200, 32, 8_192),
            &clock,
            &mut backend,
        );
        assert!(ctx.inspect(SurfaceHandle(0)).is_some());
        assert_eq!(ctx.children(SurfaceHandle(0), 0, 10), None);
        assert_eq!(
            ctx.abort_failure(),
            Some(SurfaceReadFailure::ProviderUnavailable)
        );
    }
}

// ============================================================================
// Test 21: validate_custom_result Bounds-Timestamp Pairing & Valid AXRole Check
// ============================================================================
#[test]
fn validate_custom_result_rejects_bounds_timestamp_mismatch_and_invalid_ax_role() {
    let clock = FakeClock::new();
    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);
    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        MockNode::new("AXWindow").bounds(100.0, 200.0, 800.0, 600.0),
    );
    let mut backend = MockSurfaceBackend::new(nodes);
    let mut ctx = KernelSurfaceContext::new(
        app,
        &policy,
        FIGMA_ADAPTER.spec(),
        "window",
        48,
        SurfaceHandle(0),
        None,
        ReadBudget::new(5_000, 150, 200, 32, 8_192),
        &clock,
        &mut backend,
    );
    let root = ctx.inspect(SurfaceHandle(0)).expect("root inspected");
    let valid_bounds = SurfaceBounds::new(0.0, 0.0, 800.0, 600.0);

    // Valid baseline: paired bounds + timestamp and valid AXRole.
    let valid = CustomSurfaceResult {
        nodes: vec![CustomSurfaceNode {
            handle: root.handle,
            parent: None,
            role: "container",
            ax_role: Some("AXWindow".to_string()),
            text: None,
            is_focused: false,
            observed_at_ms: root.observed_at_ms,
            bounds: Some(valid_bounds),
            bounds_observed_at_ms: Some(1_000),
        }],
        complete: false,
        missing_reasons: Vec::new(),
    };
    assert!(validate_custom_result(&valid, &ctx, 48));

    // Valid baseline: ax_role = None and bounds/timestamp both None.
    let mut none_role = valid.clone();
    none_role.nodes[0].ax_role = None;
    none_role.nodes[0].bounds = None;
    none_role.nodes[0].bounds_observed_at_ms = None;
    assert!(validate_custom_result(&none_role, &ctx, 48));

    // Reject bounds = Some without bounds_observed_at_ms.
    let mut missing_ts = valid.clone();
    missing_ts.nodes[0].bounds_observed_at_ms = None;
    assert!(!validate_custom_result(&missing_ts, &ctx, 48));

    // Reject bounds = None with stray bounds_observed_at_ms = Some.
    let mut stray_ts = valid.clone();
    stray_ts.nodes[0].bounds = None;
    stray_ts.nodes[0].bounds_observed_at_ms = Some(1_000);
    assert!(!validate_custom_result(&stray_ts, &ctx, 48));

    // Reject malformed ax_role values violating wire.schema.json `^AX[A-Za-z0-9]{1,62}$`.
    for bad_role in ["", "AX", "Window", "AXBad-Role!", "AX Role"] {
        let mut bad = valid.clone();
        bad.nodes[0].ax_role = Some(bad_role.to_string());
        assert!(
            !validate_custom_result(&bad, &ctx, 48),
            "bad ax_role `{bad_role}` must be rejected"
        );
    }
}

// ============================================================================
// Test 22: Live UIA 2-Child Probe Still Signals tree-output-budget in FigmaAdapter
// ============================================================================
#[test]
fn figma_live_two_child_probe_signals_tree_output_budget_on_truncated_container() {
    let clock = FakeClock::new();
    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);

    let run_figma_with_canvas_items = |count: usize| -> SurfaceCapturedTree {
        let mut nodes = HashMap::new();
        nodes.insert(
            0,
            MockNode::new("AXWindow")
                .children(vec![1])
                .bounds(0.0, 0.0, 1440.0, 900.0),
        );
        nodes.insert(
            1,
            MockNode::new("AXWebArea")
                .parent(0)
                .children(vec![2])
                .display_text("Design File")
                .bounds(0.0, 40.0, 1440.0, 860.0),
        );
        let item_ids: Vec<usize> = (100..100 + count).collect();
        nodes.insert(
            2,
            MockNode::new("AXGroup")
                .parent(1)
                .subrole("AXLandmarkMain")
                .children(item_ids.clone())
                .bounds(240.0, 40.0, 920.0, 860.0),
        );
        for (i, &nid) in item_ids.iter().enumerate() {
            nodes.insert(
                nid,
                MockNode::new("AXStaticText")
                    .parent(2)
                    .text(format!("Layer {i}"))
                    .bounds(300.0, 100.0 + (i as f64) * 16.0, 200.0, 14.0),
            );
        }
        let mut backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1440.0, 900.0);
        // Simulate live Windows UIA's 2-child initial probe where `child_count` is capped at 2!
        backend.cap_reported_child_count = Some(2);
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &FIGMA_ADAPTER,
            &app,
            &policy,
            "window",
            64,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected Figma capture to succeed for count={count}");
        };
        assert_valid_forest(&tree);
        tree
    };

    // 30 canvas items > page_limit (24): even with `child_count == 2`, `last_children_truncated()`
    // MUST signal `tree-output-budget`!
    let big_tree = run_figma_with_canvas_items(30);
    assert!(
        big_tree.reasons.iter().any(|r| r == "tree-output-budget"),
        "expected tree-output-budget when >24 live children exist, got {:?}",
        big_tree.reasons
    );

    // 5 canvas items <= page_limit (24): MUST NOT spuriously emit `tree-output-budget`!
    let small_tree = run_figma_with_canvas_items(5);
    assert!(
        !small_tree.reasons.iter().any(|r| r == "tree-output-budget"),
        "did not expect tree-output-budget for 5 items, got {:?}",
        small_tree.reasons
    );
}

// ============================================================================
// Test 23: Live Windows 11 3-AXWebArea Electron Shell (Empty Backdrop + Off-Left Badge)
// ============================================================================
#[test]
fn figma_skips_empty_electron_backdrop_web_area_and_selects_real_document() {
    let clock = FakeClock::new();
    let mut nodes = HashMap::new();

    // Exact Windows 11 Electron figma.exe 3-AXWebArea shell:
    // - Depth 0..7 outer shell wrappers (0 -> 1 -> ... -> 7)
    // - Depth 8: empty full-screen Electron backdrop AXWebArea (1920x1232, area=2,365,440, child_count=0, label=None)
    // - Depth 9: Top File Tab Bar AXWebArea (1920x38, y=6.5) + Real Main Document AXWebArea (1918x1193, y=44.5, area=2,288,174)
    nodes.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1])
            .window_title("FloUNet 总结 – Figma Slides")
            .bounds(0.0, 0.0, 1920.0, 1232.0),
    );
    for depth in 1..=6 {
        nodes.insert(
            depth,
            MockNode::new("AXGroup")
                .children(vec![depth + 1])
                .parent(depth - 1)
                .bounds(0.0, 0.0, 1920.0, 1232.0),
        );
    }
    nodes.insert(
        7,
        MockNode::new("AXGroup")
            .children(vec![8, 9])
            .parent(6)
            .bounds(0.0, 0.0, 1920.0, 1232.0),
    );

    // Depth 8: Empty Electron backdrop AXWebArea (shallower AND larger than the real document!)
    nodes.insert(
        8,
        MockNode::new("AXWebArea")
            .parent(7)
            .bounds(0.0, 0.0, 1920.0, 1232.0),
    );

    // Depth 8 wrapper -> Depth 9 Tab Bar (10) and Main Document (20)
    nodes.insert(
        9,
        MockNode::new("AXGroup")
            .children(vec![10, 20])
            .parent(7)
            .bounds(0.0, 0.0, 1920.0, 1232.0),
    );

    // Depth 9 #1: Top File Tab Bar AXWebArea (1920x38, y=6.5)
    nodes.insert(
        10,
        MockNode::new("AXWebArea")
            .children(vec![11])
            .parent(9)
            .display_text("Figma (file:///C:/Users/test/AppData/Local/Figma/shell.html)")
            .bounds(0.0, 6.5, 1920.0, 38.0)
            .label("Figma"),
    );
    nodes.insert(
        11,
        MockNode::new("AXTabGroup")
            .children(vec![12, 13, 14, 15, 16, 17, 18, 19])
            .parent(10)
            .bounds(0.0, 6.5, 1920.0, 38.0)
            .label("Tab bar"),
    );
    nodes.insert(
        12,
        MockNode::new("AXRadioButton")
            .parent(11)
            .display_text("Home")
            .bounds(60.0, 8.0, 48.0, 34.0)
            .label("Home"),
    );
    nodes.insert(
        13,
        MockNode::new("AXTabButton")
            .parent(11)
            .display_text("FloUNet 总结")
            .bounds(116.0, 8.0, 180.0, 34.0)
            .label("FloUNet 总结"),
    );
    // Windows Electron titlebar & tab chrome noise MUST be pruned
    nodes.insert(14, MockNode::new("AXTabButton").parent(11).display_text("New file").bounds(304.0, 8.0, 28.0, 28.0).label("New file"));
    nodes.insert(15, MockNode::new("AXTabButton").parent(11).display_text("Menu").bounds(8.0, 8.0, 32.0, 30.0).label("Menu"));
    nodes.insert(16, MockNode::new("AXTabButton").parent(11).display_text("Minimize").bounds(1780.0, 8.0, 32.0, 30.0).label("Minimize"));
    nodes.insert(17, MockNode::new("AXTabButton").parent(11).display_text("Maximize").bounds(1816.0, 8.0, 32.0, 30.0).label("Maximize"));
    nodes.insert(18, MockNode::new("AXTabButton").parent(11).display_text("Restore").bounds(1816.0, 8.0, 32.0, 30.0).label("Restore"));
    nodes.insert(19, MockNode::new("AXTabButton").parent(11).display_text("Close").bounds(1852.0, 8.0, 32.0, 30.0).label("Close"));

    // Depth 9 #2: Real Main Document AXWebArea (1918x1193, y=44.5)
    let main_web_display = SafeDisplayText::compose(
        "AXWebArea",
        Some("FloUNet 总结 – Figma Slides"),
        None,
        Some("https://www.figma.com/slides/flounet-demo/FloUNet"),
        256,
    )
    .unwrap();
    nodes.insert(
        20,
        MockNode::new("AXWebArea")
            .children(vec![21])
            .parent(9)
            .display_text(main_web_display.clone())
            .bounds(1.0, 44.5, 1918.0, 1193.0)
            .label("FloUNet 总结 – Figma Slides"),
    );
    // Deep DOM wrapper chain inside main_web_area so landmarks sit at depth 9 (> old MAX_LANDMARK_DEPTH=8)
    for idx in 21..=27 {
        nodes.insert(
            idx,
            MockNode::new("AXGroup")
                .children(vec![idx + 1])
                .parent(idx - 1)
                .bounds(1.0, 44.5, 1918.0, 1193.0),
        );
    }
    nodes.insert(
        28,
        MockNode::new("AXGroup")
            .children(vec![300, 100, 200])
            .parent(27)
            .bounds(1.0, 44.5, 1918.0, 1193.0),
    );

    // Zone 2: AXLandmarkMain with offscreen far-left dimension badge (x = -12371, width = 121) + visible slide
    nodes.insert(
        100,
        MockNode::new("AXGroup")
            .subrole("AXLandmarkMain")
            .children(vec![101])
            .parent(28)
            .bounds(240.0, 44.5, 1440.0, 1187.5)
            .label("Figma Slides, 1 item selected"),
    );
    nodes.insert(
        101,
        MockNode::new("AXGroup")
            .children(vec![102, 103, 105])
            .parent(100)
            .bounds(240.0, 44.5, 1440.0, 1187.5),
    );
    // Offscreen far-left dimension badge observed in live Windows 11 Figma Slides (rect.x + rect.width <= 0.0)
    nodes.insert(
        102,
        MockNode::new("AXStaticText")
            .parent(101)
            .text("1920 × 1080 offscreen badge")
            .reported_length(0)
            .bounds(-12371.0, 172.5, 121.0, 20.0),
    );
    nodes.insert(
        103,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(vec![104])
            .parent(101)
            .bounds(-12371.0, 172.5, 121.0, 24.0)
            .label("Offscreen Left Dimension Badge"),
    );
    nodes.insert(
        104,
        MockNode::new("AXStaticText")
            .parent(103)
            .text("999 × 999")
            .reported_length(0)
            .bounds(-12371.0, 174.0, 121.0, 20.0),
    );
    // Active visible slide on canvas
    nodes.insert(
        105,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(vec![106, 107])
            .parent(101)
            .bounds(260.0, 140.0, 1360.0, 765.0)
            .focused()
            .label("Slide 3"),
    );
    nodes.insert(
        106,
        MockNode::new("AXHeading")
            .parent(105)
            .display_text("FloUNet 模型结构总结")
            .bounds(340.0, 210.0, 620.0, 44.0)
            .label("FloUNet 模型结构总结"),
    );
    nodes.insert(
        107,
        MockNode::new("AXStaticText")
            .parent(105)
            .text("Skip-connection fusion")
            .reported_length(0)
            .bounds(340.0, 276.0, 420.0, 24.0),
    );

    // Zone 3: Right Inspector Sidebar with real properties + noise buttons
    nodes.insert(
        200,
        MockNode::new("AXGroup")
            .subrole("AXApplicationGroup")
            .children(vec![201, 202, 203, 204, 205, 206, 207, 208])
            .parent(28)
            .bounds(1680.0, 44.5, 240.0, 1187.5)
            .label("Right sidebar"),
    );
    nodes.insert(201, MockNode::new("AXRadioButton").parent(200).display_text("Slide").bounds(1690.0, 56.0, 56.0, 24.0).label("Slide"));
    nodes.insert(202, MockNode::new("AXRadioButton").parent(200).display_text("Animate").bounds(1752.0, 56.0, 68.0, 24.0).label("Animate"));
    nodes.insert(203, MockNode::new("AXStaticText").parent(200).text("16:9 Widescreen").reported_length(0).bounds(1690.0, 100.0, 160.0, 20.0));
    nodes.insert(204, MockNode::new("AXTextField").parent(200).text("#FFFFFF").bounds(1690.0, 136.0, 100.0, 24.0).label("Background"));
    // Right sidebar chrome noise MUST be pruned
    nodes.insert(205, MockNode::new("AXButton").parent(200).display_text("Share").bounds(1850.0, 56.0, 52.0, 24.0).label("Share"));
    nodes.insert(206, MockNode::new("AXButton").parent(200).display_text("Present").bounds(1800.0, 56.0, 48.0, 24.0).label("Present"));
    nodes.insert(207, MockNode::new("AXButton").parent(200).display_text("Start with an AI draft").bounds(1690.0, 180.0, 180.0, 28.0).label("Start with an AI draft"));
    nodes.insert(208, MockNode::new("AXButton").parent(200).display_text("Align left").bounds(1690.0, 216.0, 24.0, 24.0).label("Align left"));

    // Zone 4: Left Sidebar with visible slides + negative-y / below-viewport clipped slides + noise
    nodes.insert(
        300,
        MockNode::new("AXGroup")
            .subrole("AXLandmarkRegion")
            .children(vec![301, 302, 303, 304, 310])
            .parent(28)
            .bounds(0.0, 44.5, 240.0, 1187.5)
            .label("Left sidebar"),
    );
    nodes.insert(301, MockNode::new("AXButton").parent(300).display_text("Main menu").bounds(12.0, 52.0, 24.0, 24.0).label("Main menu"));
    nodes.insert(302, MockNode::new("AXButton").parent(300).display_text("New slide").bounds(44.0, 52.0, 24.0, 24.0).label("New slide"));
    nodes.insert(303, MockNode::new("AXButton").parent(300).display_text("Grid view").bounds(180.0, 52.0, 24.0, 24.0).label("Grid view"));
    nodes.insert(304, MockNode::new("AXButton").parent(300).display_text("Minimize UI").bounds(208.0, 52.0, 24.0, 24.0).label("Minimize UI"));
    nodes.insert(
        310,
        MockNode::new("AXColumn")
            .children(vec![311, 312, 313, 314])
            .parent(300)
            .bounds(0.0, -180.0, 240.0, 1600.0),
    );
    // Negative-y offscreen top slide MUST be clipped without reading text!
    nodes.insert(311, MockNode::new("AXRow").children(vec![321]).parent(310).bounds(0.0, -96.0, 240.0, 88.0));
    nodes.insert(321, MockNode::new("AXStaticText").parent(311).text("Slide 1 - Offscreen Top").reported_length(0));
    // Visible slides in viewport
    nodes.insert(312, MockNode::new("AXRow").parent(310).bounds(0.0, 110.0, 240.0, 88.0).label("Slide 2 - Overview"));
    nodes.insert(313, MockNode::new("AXRow").parent(310).bounds(0.0, 210.0, 240.0, 88.0).label("Slide 3 - FloUNet"));
    // Below-viewport slide MUST be clipped without reading text!
    nodes.insert(314, MockNode::new("AXRow").children(vec![324]).parent(310).bounds(0.0, 1240.0, 240.0, 88.0));
    nodes.insert(324, MockNode::new("AXStaticText").parent(314).text("Slide 9 - Below Viewport").reported_length(0));

    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);

    // 1. Direct FigmaAdapter::extract_surface MUST return Some(...) selecting real document (20), NOT fallback!
    let mut direct_backend =
        MockSurfaceBackend::new(nodes.clone()).with_window_rect(0.0, 0.0, 1920.0, 1232.0);
    let mut direct_ctx = KernelSurfaceContext::new(
        app.clone(),
        &policy,
        FigmaAdapter.spec(),
        "window",
        64,
        SurfaceHandle(0),
        Some(SurfaceHandle(105)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut direct_backend,
    );
    direct_ctx.set_initial_window_rect(SurfaceAbsoluteRect::new(0.0, 0.0, 1920.0, 1232.0));
    let custom_result = FigmaAdapter
        .extract_surface(&mut direct_ctx)
        .expect("FigmaAdapter must select real document AXWebArea rather than falling back");
    assert!(
        custom_result
            .nodes
            .iter()
            .any(|n| n.handle == SurfaceHandle(20)),
        "expected real document AXWebArea (20) in custom result"
    );
    assert!(
        !custom_result
            .nodes
            .iter()
            .any(|n| n.handle == SurfaceHandle(8)),
        "empty Electron backdrop AXWebArea (8) must not be emitted"
    );

    // 2. Full SurfaceCaptureRunner verification of all 4 zones, off-left pruning, noise pruning & slide clipping.
    let mut backend =
        MockSurfaceBackend::new(nodes.clone()).with_window_rect(0.0, 0.0, 1920.0, 1232.0);
    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &FIGMA_ADAPTER,
        &app,
        &policy,
        "window",
        64,
        Some(SurfaceHandle(105)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    ) else {
        panic!("expected FigmaAdapter 3-AXWebArea capture to succeed");
    };
    assert_eq!(tree.adapter_id, "figma");
    assert_valid_forest(&tree);

    let texts = texts_of(&tree);
    // Zone 1: Main document title + URL and clean file tabs
    assert!(texts.contains(&main_web_display.as_str()));
    assert!(texts.contains(&"Home"));
    assert!(texts.contains(&"FloUNet 总结"));
    for tab_noise in ["New file", "Menu", "Minimize", "Maximize", "Restore", "Close"] {
        assert!(
            !texts.contains(&tab_noise),
            "Windows titlebar/tab noise must be pruned: {tab_noise}"
        );
    }

    // Zone 2: Canvas landmark + visible slide (focused) with off-left x=-12371 badge pruned
    assert!(texts.contains(&"Figma Slides, 1 item selected"));
    assert!(texts.contains(&"Slide 3"));
    assert!(texts.contains(&"FloUNet 模型结构总结"));
    assert!(texts.contains(&"Skip-connection fusion"));
    assert!(!texts.contains(&"1920 × 1080 offscreen badge"));
    assert!(!texts.contains(&"Offscreen Left Dimension Badge"));
    assert!(!texts.contains(&"999 × 999"));
    assert!(
        !backend.text_reads.contains(&102),
        "off-left x=-12371 canvas badge must NEVER be text-read"
    );
    assert!(
        !backend.text_reads.contains(&104),
        "child of off-left x=-12371 canvas group must NEVER be text-read"
    );
    let focused: Vec<_> = tree.nodes.iter().filter(|n| n.focused == Some(true)).collect();
    assert_eq!(focused.len(), 1);
    assert_eq!(focused[0].text.as_deref(), Some("Slide 3"));

    // Zone 3: Right inspector properties preserved, chrome noise pruned
    for right_keep in ["Slide", "Animate", "16:9 Widescreen", "#FFFFFF"] {
        assert!(
            texts.contains(&right_keep),
            "missing right inspector item: {right_keep}"
        );
    }
    for right_noise in ["Share", "Present", "Start with an AI draft", "Align left"] {
        assert!(
            !texts.contains(&right_noise),
            "right sidebar noise must be pruned: {right_noise}"
        );
    }

    // Zone 4: Visible slides preserved, negative-y & below-viewport slides clipped, chrome pruned
    assert!(texts.contains(&"Slide 2 - Overview"));
    assert!(texts.contains(&"Slide 3 - FloUNet"));
    assert!(!texts.contains(&"Slide 1 - Offscreen Top"));
    assert!(!texts.contains(&"Slide 9 - Below Viewport"));
    assert!(
        !backend.text_reads.contains(&321),
        "negative-y clipped slide must NEVER be text-read"
    );
    assert!(
        !backend.text_reads.contains(&324),
        "below-viewport clipped slide must NEVER be text-read"
    );
    for left_noise in ["Main menu", "New slide", "Grid view", "Minimize UI"] {
        assert!(
            !texts.contains(&left_noise),
            "left sidebar noise must be pruned: {left_noise}"
        );
    }

    // 3. Even if the depth-8 Electron backdrop AXWebArea has dummy children and a label (no AXLandmarkMain),
    //    Step 2 tries ranked candidates in order and still selects real document AXWebArea (20)!
    nodes.insert(
        8,
        MockNode::new("AXWebArea")
            .children(vec![801])
            .parent(7)
            .display_text("Electron Overlay")
            .bounds(0.0, 0.0, 1920.0, 1232.0)
            .label("Electron Overlay"),
    );
    nodes.insert(
        801,
        MockNode::new("AXGroup")
            .parent(8)
            .bounds(0.0, 0.0, 1920.0, 1232.0)
            .label("Dummy overlay container"),
    );
    let mut overlay_backend =
        MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 1920.0, 1232.0);
    let mut overlay_ctx = KernelSurfaceContext::new(
        app,
        &policy,
        FigmaAdapter.spec(),
        "window",
        64,
        SurfaceHandle(0),
        Some(SurfaceHandle(105)),
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut overlay_backend,
    );
    overlay_ctx.set_initial_window_rect(SurfaceAbsoluteRect::new(0.0, 0.0, 1920.0, 1232.0));
    let overlay_result = FigmaAdapter
        .extract_surface(&mut overlay_ctx)
        .expect("FigmaAdapter must skip dummy populated overlay AXWebArea and select real document");
    assert!(
        overlay_result
            .nodes
            .iter()
            .any(|n| n.handle == SurfaceHandle(20)),
        "expected real document AXWebArea (20) after skipping overlay AXWebArea (8)"
    );
    assert!(
        !overlay_result
            .nodes
            .iter()
            .any(|n| n.handle == SurfaceHandle(8)),
        "dummy overlay AXWebArea (8) must not be emitted"
    );
}

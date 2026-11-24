//! Kernel security, budget, registry, declarative adapter, TOCTOU, and runner tests.

mod common;

use std::collections::HashMap;

use collector_core::adapters::kernel::{
    validate_custom_result, BackendAllowedNode, BackendCallBudget, BackendChildrenPage,
    BackendInspection, BackendTailChildrenRead, BackendTextRead, KernelSurfaceContext,
    SurfaceBackend, SurfaceCaptureOutcome, SurfaceCaptureRunner,
};
use collector_core::adapters::{
    ActivationMode, AdapterRegistry, AppAdapter, AppAdapterSpec, CustomSurfaceNode,
    CustomSurfaceResult, SafeDisplayText, SafeSurfaceContext, StaticTextPolicy, SurfaceHandle,
    WindowAnchorPolicy, BROWSER_FAMILY_ADAPTER, FEISHU_ADAPTER, FIGMA_ADAPTER, GENERIC_ADAPTER,
    QQ_ADAPTER, SLACK_ADAPTER, TYPORA_ADAPTER, VSCODE_FAMILY_ADAPTER, WECHAT_ADAPTER,
};
use collector_core::policy::{
    is_private_use_only_text, ApplicationPolicy, BrowserGate, ProtectedContentRead, ReadBudget,
    SubroleRead,
};
use collector_core::protocol_model::{
    CapturePolicy, CollectorClock, SecureStatus, SurfaceAbsoluteRect, SurfaceBaseline,
    SurfaceBounds, SurfaceNode, SurfaceReadFailure, MAX_SAFE_INTEGER,
};
use collector_core::uia_traversal::{
    PendingSurfaceCapture, RuntimeIdKey, SurfaceNodeMap, WeightedSurfaceTraversalReason,
};
use common::{
    allowlist_policy, assert_valid_forest, denylist_policy, id, texts_of, FakeClock, InspectHook,
    MockNode, MockSurfaceBackend,
};
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
        expand_text_wrapper_ids: &[],
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
        expand_text_wrapper_ids: &[],
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
    assert!(!is_private_use_only_text("\u{EBB1} kernel.rs"));
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
            .window_title("computer-access-mcp — kernel.rs"),
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
    nodes.insert(12, MockNode::new("AXStaticText").parent(3).text("kernel.rs").reported_length(0));
    nodes.insert(13, MockNode::new("AXStaticText").parent(3).text("\u{EBB1} mod.rs").reported_length(0));
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
    assert!(texts.contains(&"kernel.rs"));
    assert!(texts.contains(&"\u{EBB1} mod.rs"));
    assert!(texts.contains(&"pub struct FigmaAdapter;"));
    assert!(texts.contains(&"Agent response about Phase 4"));
    assert!(!texts.contains(&"\u{EBB1}"));
    assert!(!texts.contains(&"\u{EA60}"));
    assert!(!texts.contains(&"\u{E001}"));
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
    ctx.set_initial_window_rect(SurfaceAbsoluteRect::new(100.0, 200.0, 800.0, 600.0));
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
// Test 24: [P1-1] BackendCallBudget::try_consume Exact Boundary & Overflow Checks
// ============================================================================
#[test]
fn backend_call_budget_try_consume_handles_zero_and_oversized_counts() {
    let mut zero = BackendCallBudget::new(0);
    assert!(zero.try_consume(0));
    assert!(!zero.exhausted());
    assert!(!zero.try_consume(1), "limit=0 must reject count=1");
    assert_eq!(zero.used(), 0);
    assert_eq!(zero.remaining(), 0);
    assert!(zero.exhausted());

    let mut small = BackendCallBudget::new(2);
    assert!(!small.try_consume(3), "limit=2 must reject count=3");
    assert_eq!(small.used(), 0);
    assert_eq!(small.remaining(), 2);
    assert!(small.exhausted());

    let mut exact = BackendCallBudget::new(2);
    assert!(exact.try_consume(2));
    assert_eq!(exact.used(), 2);
    assert_eq!(exact.remaining(), 0);
    assert!(!exact.exhausted());
    assert!(!exact.try_consume(1));
    assert_eq!(exact.used(), 2);
    assert!(exact.exhausted());

    let mut huge = BackendCallBudget::new(5);
    assert!(!huge.try_consume(usize::MAX));
    assert_eq!(huge.used(), 0);
    assert!(huge.exhausted());
}

// ============================================================================
// Test 25: [P1-5] Security, Private-Title & Role-Drift Checks Run Before !calls_ok
// ============================================================================
#[test]
fn security_private_title_and_role_drift_run_before_call_budget_or_deadline_exit() {
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;

    struct StepClock {
        mono: Arc<AtomicI64>,
        unix: i64,
    }
    impl CollectorClock for StepClock {
        fn monotonic_ms(&self) -> i64 {
            self.mono.load(Ordering::SeqCst)
        }
        fn unix_ms(&self) -> i64 {
            self.unix
        }
    }

    #[derive(Clone, Copy)]
    enum TripMode {
        ExhaustCallBudget,
        CrossDeadline,
    }

    type MutateFn = Box<dyn FnMut(usize, bool, &mut BackendCallBudget) -> Option<BackendInspection>>;

    struct TripBackend {
        inner: MockSurfaceBackend,
        mutate: MutateFn,
    }

    impl SurfaceBackend for TripBackend {
        fn verify_desktop_and_application(&mut self) -> Option<SurfaceReadFailure> {
            self.inner.verify_desktop_and_application()
        }
        fn inspect_backend_node(
            &mut self,
            index: usize,
            is_root: bool,
            calls: &mut BackendCallBudget,
        ) -> BackendInspection {
            if let Some(custom) = (self.mutate)(index, is_root, calls) {
                return custom;
            }
            self.inner.inspect_backend_node(index, is_root, calls)
        }
        fn parent_backend_node(
            &mut self,
            index: usize,
            calls: &mut BackendCallBudget,
        ) -> collector_core::adapters::kernel::BackendParentRead {
            self.inner.parent_backend_node(index, calls)
        }
        fn children_backend_page(
            &mut self,
            index: usize,
            expected_role: &str,
            offset: usize,
            limit: usize,
            calls: &mut BackendCallBudget,
        ) -> BackendChildrenPage {
            self.inner
                .children_backend_page(index, expected_role, offset, limit, calls)
        }
        fn tail_children_backend(
            &mut self,
            index: usize,
            expected_role: &str,
            limit: usize,
            calls: &mut BackendCallBudget,
        ) -> BackendTailChildrenRead {
            self.inner
                .tail_children_backend(index, expected_role, limit, calls)
        }
        fn read_backend_node_text(
            &mut self,
            index: usize,
            expected_role: &str,
            max_units: usize,
            static_text_probe: StaticTextPolicy,
            calls: &mut BackendCallBudget,
        ) -> BackendTextRead {
            self.inner
                .read_backend_node_text(index, expected_role, max_units, static_text_probe, calls)
        }
        fn read_backend_node_bounds(
            &mut self,
            index: usize,
            window_rect: SurfaceAbsoluteRect,
        ) -> Option<(SurfaceBounds, i64)> {
            self.inner.read_backend_node_bounds(index, window_rect)
        }
        fn read_backend_window_rect(&mut self) -> Option<SurfaceAbsoluteRect> {
            self.inner.read_backend_window_rect()
        }
        fn verify_final_surface_boundary(&mut self) -> Option<SurfaceReadFailure> {
            self.inner.verify_final_surface_boundary()
        }
    }

    let make_allowed = |role: &str, protected: bool, title: Option<&str>, focused: bool| {
        BackendInspection::Allowed(Box::new(BackendAllowedNode {
            role: role.to_string(),
            category: if role == "AXGroup" { "container" } else { "editable" },
            subrole: SubroleRead::NoValue,
            protected_content: ProtectedContentRead::Value(protected),
            child_count: 0,
            is_focused: focused,
            observed_at_ms: 1_010,
            is_enabled: Some(true),
            display_text: None,
            window_title: title.map(str::to_string),
            absolute_rect: SurfaceAbsoluteRect::new(120.0, 220.0, 200.0, 24.0),
            identifier: None,
            class_name: None,
            label: None,
            is_offscreen: false,
            strict_security: None,
        }))
    };

    let policy = denylist_policy();
    let app = id("chrome.exe");

    for mode in [TripMode::ExhaustCallBudget, TripMode::CrossDeadline] {
        // 1. inspect_for_traversal: cached non-root handle turning sensitive on exact failing IPC MUST be evicted.
        {
            let mono = Arc::new(AtomicI64::new(1_000));
            let clock = StepClock {
                mono: Arc::clone(&mono),
                unix: 1_700_000_000_000,
            };
            let mut nodes = HashMap::new();
            nodes.insert(0, MockNode::new("AXWindow").children(vec![1]).window_title("Docs - Chrome"));
            nodes.insert(1, MockNode::new("AXTextField").parent(0).text("secret").bounds(120.0, 220.0, 200.0, 24.0));
            let mut calls_seen = 0usize;
            let mono_hook = Arc::clone(&mono);
            let mut backend = TripBackend {
                inner: MockSurfaceBackend::new(nodes),
                mutate: Box::new(move |idx, _, calls| {
                    if idx == 1 {
                        calls_seen += 1;
                        if calls_seen == 2 {
                            match mode {
                                TripMode::ExhaustCallBudget => {
                                    let _ = calls.try_consume(calls.remaining() + 1);
                                }
                                TripMode::CrossDeadline => {
                                    mono_hook.store(6_000, Ordering::SeqCst);
                                }
                            }
                            return Some(make_allowed("AXTextField", true, None, false));
                        }
                    }
                    None
                }),
            };
            let mut ctx = KernelSurfaceContext::new(
                app.clone(),
                &policy,
                BROWSER_FAMILY_ADAPTER.spec(),
                "window",
                48,
                SurfaceHandle(0),
                None,
                ReadBudget::new(5_000, 150, 40, 8, 8_192),
                &clock,
                &mut backend,
            );
            ctx.set_initial_window_rect(SurfaceAbsoluteRect::new(100.0, 200.0, 800.0, 600.0));
            assert!(ctx.inspect(SurfaceHandle(1)).is_some());
            assert!(ctx.has_inspected(SurfaceHandle(1)));
            assert!(ctx.sampled_bounds().contains_key(&SurfaceHandle(1)));
            assert!(ctx.inspect(SurfaceHandle(1)).is_none());
            assert!(!ctx.has_inspected(SurfaceHandle(1)), "newly sensitive handle must be evicted even on !calls_ok");
            assert!(!ctx.sampled_bounds().contains_key(&SurfaceHandle(1)));
        }

        // 2. inspect_for_traversal: cached non-root handle drifting role on exact failing IPC MUST be evicted.
        {
            let mono = Arc::new(AtomicI64::new(1_000));
            let clock = StepClock {
                mono: Arc::clone(&mono),
                unix: 1_700_000_000_000,
            };
            let mut nodes = HashMap::new();
            nodes.insert(0, MockNode::new("AXWindow").children(vec![1]).window_title("Docs - Chrome"));
            nodes.insert(1, MockNode::new("AXTextField").parent(0).text("note"));
            let mut calls_seen = 0usize;
            let mono_hook = Arc::clone(&mono);
            let mut backend = TripBackend {
                inner: MockSurfaceBackend::new(nodes),
                mutate: Box::new(move |idx, _, calls| {
                    if idx == 1 {
                        calls_seen += 1;
                        if calls_seen == 2 {
                            match mode {
                                TripMode::ExhaustCallBudget => {
                                    let _ = calls.try_consume(calls.remaining() + 1);
                                }
                                TripMode::CrossDeadline => {
                                    mono_hook.store(6_000, Ordering::SeqCst);
                                }
                            }
                            return Some(make_allowed("AXGroup", false, None, false));
                        }
                    }
                    None
                }),
            };
            let mut ctx = KernelSurfaceContext::new(
                app.clone(),
                &policy,
                BROWSER_FAMILY_ADAPTER.spec(),
                "window",
                48,
                SurfaceHandle(0),
                None,
                ReadBudget::new(5_000, 150, 40, 8, 8_192),
                &clock,
                &mut backend,
            );
            assert!(ctx.inspect(SurfaceHandle(1)).is_some());
            assert!(ctx.inspect(SurfaceHandle(1)).is_none());
            assert!(!ctx.has_inspected(SurfaceHandle(1)), "role-drifted handle must be evicted even on !calls_ok");
            assert!(ctx.extra_reasons().contains("node-role-changed"));
        }

        // 3. inspect_for_traversal: root turning into private browser title on exact failing IPC MUST abort SecurityExcluded.
        {
            let mono = Arc::new(AtomicI64::new(1_000));
            let clock = StepClock {
                mono: Arc::clone(&mono),
                unix: 1_700_000_000_000,
            };
            let mut nodes = HashMap::new();
            nodes.insert(0, MockNode::new("AXWindow").window_title("Docs - Google Chrome"));
            let mut calls_seen = 0usize;
            let mono_hook = Arc::clone(&mono);
            let mut backend = TripBackend {
                inner: MockSurfaceBackend::new(nodes),
                mutate: Box::new(move |idx, _, calls| {
                    if idx == 0 {
                        calls_seen += 1;
                        if calls_seen == 2 {
                            match mode {
                                TripMode::ExhaustCallBudget => {
                                    let _ = calls.try_consume(calls.remaining() + 1);
                                }
                                TripMode::CrossDeadline => {
                                    mono_hook.store(6_000, Ordering::SeqCst);
                                }
                            }
                            return Some(make_allowed(
                                "AXWindow",
                                false,
                                Some("Vault - Google Chrome (Incognito)"),
                                false,
                            ));
                        }
                    }
                    None
                }),
            };
            let mut ctx = KernelSurfaceContext::new(
                app.clone(),
                &policy,
                BROWSER_FAMILY_ADAPTER.spec(),
                "window",
                48,
                SurfaceHandle(0),
                None,
                ReadBudget::new(5_000, 150, 40, 8, 8_192),
                &clock,
                &mut backend,
            );
            assert!(ctx.inspect(SurfaceHandle(0)).is_some());
            assert!(ctx.inspect(SurfaceHandle(0)).is_none());
            assert_eq!(ctx.abort_failure(), Some(SurfaceReadFailure::SecurityExcluded));
            assert!(ctx.inspected_nodes().is_empty());
        }

        // 4. read_text: cached non-root handle turning sensitive on exact failing refresh IPC MUST be evicted.
        {
            let mono = Arc::new(AtomicI64::new(1_000));
            let clock = StepClock {
                mono: Arc::clone(&mono),
                unix: 1_700_000_000_000,
            };
            let mut nodes = HashMap::new();
            nodes.insert(0, MockNode::new("AXWindow").children(vec![1]).window_title("Docs - Chrome"));
            nodes.insert(1, MockNode::new("AXTextField").parent(0).text("hunter2").bounds(120.0, 220.0, 200.0, 24.0));
            let mut calls_seen = 0usize;
            let mono_hook = Arc::clone(&mono);
            let mut backend = TripBackend {
                inner: MockSurfaceBackend::new(nodes),
                mutate: Box::new(move |idx, _, calls| {
                    if idx == 1 {
                        calls_seen += 1;
                        if calls_seen == 2 {
                            match mode {
                                TripMode::ExhaustCallBudget => {
                                    let _ = calls.try_consume(calls.remaining() + 1);
                                }
                                TripMode::CrossDeadline => {
                                    mono_hook.store(6_000, Ordering::SeqCst);
                                }
                            }
                            return Some(make_allowed("AXTextField", true, None, false));
                        }
                    }
                    None
                }),
            };
            let mut ctx = KernelSurfaceContext::new(
                app.clone(),
                &policy,
                BROWSER_FAMILY_ADAPTER.spec(),
                "window",
                48,
                SurfaceHandle(0),
                None,
                ReadBudget::new(5_000, 150, 40, 8, 8_192),
                &clock,
                &mut backend,
            );
            ctx.set_initial_window_rect(SurfaceAbsoluteRect::new(100.0, 200.0, 800.0, 600.0));
            assert!(ctx.inspect(SurfaceHandle(1)).is_some());
            assert_eq!(ctx.text(SurfaceHandle(1), None), None);
            assert!(!ctx.has_inspected(SurfaceHandle(1)), "read_text must evict newly sensitive handle even on !inspect_calls_ok");
            assert!(!ctx.sampled_bounds().contains_key(&SurfaceHandle(1)));
            assert!(ctx.extra_reasons().contains("node-security-excluded"));
            assert!(backend.inner.text_reads.is_empty());
        }

        // 5. read_text: cached non-root handle drifting role on exact failing refresh IPC MUST be evicted.
        {
            let mono = Arc::new(AtomicI64::new(1_000));
            let clock = StepClock {
                mono: Arc::clone(&mono),
                unix: 1_700_000_000_000,
            };
            let mut nodes = HashMap::new();
            nodes.insert(0, MockNode::new("AXWindow").children(vec![1]).window_title("Docs - Chrome"));
            nodes.insert(1, MockNode::new("AXStaticText").parent(0).text("hello"));
            let mut calls_seen = 0usize;
            let mono_hook = Arc::clone(&mono);
            let mut backend = TripBackend {
                inner: MockSurfaceBackend::new(nodes),
                mutate: Box::new(move |idx, _, calls| {
                    if idx == 1 {
                        calls_seen += 1;
                        if calls_seen == 2 {
                            match mode {
                                TripMode::ExhaustCallBudget => {
                                    let _ = calls.try_consume(calls.remaining() + 1);
                                }
                                TripMode::CrossDeadline => {
                                    mono_hook.store(6_000, Ordering::SeqCst);
                                }
                            }
                            return Some(make_allowed("AXGroup", false, None, false));
                        }
                    }
                    None
                }),
            };
            let mut ctx = KernelSurfaceContext::new(
                app.clone(),
                &policy,
                BROWSER_FAMILY_ADAPTER.spec(),
                "window",
                48,
                SurfaceHandle(0),
                None,
                ReadBudget::new(5_000, 150, 40, 8, 8_192),
                &clock,
                &mut backend,
            );
            assert!(ctx.inspect(SurfaceHandle(1)).is_some());
            assert_eq!(ctx.text(SurfaceHandle(1), None), None);
            assert!(!ctx.has_inspected(SurfaceHandle(1)), "read_text must evict role-drifted handle even on !inspect_calls_ok");
            assert!(ctx.extra_reasons().contains("node-role-changed"));
            assert!(backend.inner.text_reads.is_empty());
        }

        // 6. read_text: focused handle turning sensitive on exact failing refresh IPC MUST abort SecurityExcluded.
        {
            let mono = Arc::new(AtomicI64::new(1_000));
            let clock = StepClock {
                mono: Arc::clone(&mono),
                unix: 1_700_000_000_000,
            };
            let mut nodes = HashMap::new();
            nodes.insert(0, MockNode::new("AXWindow").children(vec![1]).window_title("Docs - Chrome"));
            nodes.insert(1, MockNode::new("AXTextField").parent(0).focused().text("secret"));
            let mut calls_seen = 0usize;
            let mono_hook = Arc::clone(&mono);
            let mut backend = TripBackend {
                inner: MockSurfaceBackend::new(nodes),
                mutate: Box::new(move |idx, _, calls| {
                    if idx == 1 {
                        calls_seen += 1;
                        if calls_seen == 2 {
                            match mode {
                                TripMode::ExhaustCallBudget => {
                                    let _ = calls.try_consume(calls.remaining() + 1);
                                }
                                TripMode::CrossDeadline => {
                                    mono_hook.store(6_000, Ordering::SeqCst);
                                }
                            }
                            return Some(make_allowed("AXSecureTextField", true, None, true));
                        }
                    }
                    None
                }),
            };
            let mut ctx = KernelSurfaceContext::new(
                app.clone(),
                &policy,
                BROWSER_FAMILY_ADAPTER.spec(),
                "window",
                48,
                SurfaceHandle(0),
                Some(SurfaceHandle(1)),
                ReadBudget::new(5_000, 150, 40, 8, 8_192),
                &clock,
                &mut backend,
            );
            assert!(ctx.inspect(SurfaceHandle(1)).is_some());
            assert_eq!(ctx.text(SurfaceHandle(1), None), None);
            assert_eq!(ctx.abort_failure(), Some(SurfaceReadFailure::SecurityExcluded));
            assert!(ctx.inspected_nodes().is_empty());
            assert!(backend.inner.text_reads.is_empty());
        }
    }
}

// ============================================================================
// Test 26: [P1-6] Readable-Text-Role Body Never Leaks via label or display_text
// ============================================================================
#[test]
fn readable_text_roles_never_leak_body_via_label_or_display_text_under_strict_security() {
    let clock = FakeClock::new();
    let app = id("org.example.app");
    let strict_policy = CapturePolicy {
        enabled: true,
        application_scope: Some("allowlist".to_string()),
        allowed_application_ids: vec!["org.example.app".to_string()],
        capture_scope: Some("window".to_string()),
        field_security: Some("strict".to_string()),
        ..CapturePolicy::default()
    };

    let mut nodes = HashMap::new();
    nodes.insert(0, MockNode::new("AXWindow").children(vec![1, 2, 3, 4, 5]));
    nodes.insert(
        1,
        MockNode::new("AXStaticText")
            .parent(0)
            .label("Unverified Static Body")
            .display_text("Unverified Static Body")
            .text("Unverified Static Body"),
    );
    nodes.insert(
        2,
        MockNode::new("AXTextField")
            .parent(0)
            .label("Unverified Field Secret")
            .text("Unverified Field Secret"),
    );
    nodes.insert(
        3,
        MockNode::new("AXTextArea")
            .parent(0)
            .label("Unverified Area Secret")
            .text("Unverified Area Secret"),
    );
    nodes.insert(
        4,
        MockNode::new("AXStaticText")
            .parent(0)
            .label("Strict Verified Text")
            .text("Strict Verified Text")
            .strict_security(SecureStatus::Safe),
    );
    nodes.insert(
        5,
        MockNode::new("AXButton")
            .parent(0)
            .label("Submit")
            .display_text("Submit"),
    );

    let mut backend = MockSurfaceBackend::new(nodes);
    let mut ctx = KernelSurfaceContext::new(
        app,
        &strict_policy,
        GENERIC_ADAPTER.spec(),
        "window",
        48,
        SurfaceHandle(0),
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    );

    for raw_idx in [1usize, 2, 3, 4] {
        let h = SurfaceHandle(raw_idx);
        let info = ctx.inspect(h).expect("non-sensitive readable text role inspects");
        assert_eq!(
            info.label, None,
            "readable text role node {raw_idx} must NOT expose body via AdapterNodeInfo.label"
        );
        assert_eq!(
            ctx.display_text(h),
            None,
            "readable text role node {raw_idx} must NOT expose body via display_text"
        );
    }
    assert_eq!(
        ctx.budget().text_units(),
        0,
        "inspecting readable text roles must NOT charge display_text units"
    );

    // Unverified AXStaticText/AXTextField/AXTextArea MUST be rejected under strict field_security.
    assert_eq!(ctx.text(SurfaceHandle(1), None), None);
    assert!(!ctx.has_inspected(SurfaceHandle(1)));
    assert_eq!(ctx.text(SurfaceHandle(2), None), None);
    assert_eq!(ctx.text(SurfaceHandle(3), None), None);

    // Verified Safe AXStaticText succeeds through ctx.text(), and refreshed info STILL suppresses label/display_text.
    assert_eq!(
        ctx.text(SurfaceHandle(4), None).as_deref(),
        Some("Strict Verified Text")
    );
    assert_eq!(
        ctx.inspected_nodes()
            .get(&SurfaceHandle(4))
            .and_then(|i| i.label.as_deref()),
        None
    );
    assert_eq!(ctx.display_text(SurfaceHandle(4)), None);

    // Non-text button still exposes its safe label & display_text.
    let btn = ctx.inspect(SurfaceHandle(5)).expect("button inspects");
    assert_eq!(btn.label.as_deref(), Some("Submit"));
    assert_eq!(ctx.display_text(SurfaceHandle(5)).as_deref(), Some("Submit"));
}

// ============================================================================
// Test 27: [P1-7] validate_custom_result Enforces Text Cap, Bounds, Timestamps & AXRole
// ============================================================================
#[test]
fn validate_custom_result_enforces_text_cap_bounds_timestamps_and_inspected_ax_role() {
    let clock = FakeClock::new();
    let app = id("figma.exe");
    let policy = allowlist_policy(&["figma.exe"]);
    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1, 2])
            .bounds(100.0, 200.0, 800.0, 600.0),
    );
    nodes.insert(
        1,
        MockNode::new("AXStaticText")
            .parent(0)
            .text("alpha")
            .bounds(120.0, 240.0, 100.0, 20.0),
    );
    nodes.insert(2, MockNode::new("AXGroup").parent(0)); // intentionally no bounds!

    // 1. Tight text budget (32 UTF-16 units) rejects cumulative text > max_text_units.
    {
        let mut backend = MockSurfaceBackend::new(nodes.clone());
        let mut ctx = KernelSurfaceContext::new(
            app.clone(),
            &policy,
            FIGMA_ADAPTER.spec(),
            "window",
            48,
            SurfaceHandle(0),
            None,
            ReadBudget::new(5_000, 150, 200, 32, 32),
            &clock,
            &mut backend,
        );
        ctx.set_initial_window_rect(SurfaceAbsoluteRect::new(100.0, 200.0, 800.0, 600.0));
        let r0 = ctx.inspect(SurfaceHandle(0)).unwrap();
        let r1 = ctx.inspect(SurfaceHandle(1)).unwrap();
        let r2 = ctx.inspect(SurfaceHandle(2)).unwrap();
        let sampled_0 = ctx.bounds(SurfaceHandle(0)).unwrap();

        let make_valid = || CustomSurfaceResult {
            nodes: vec![
                CustomSurfaceNode {
                    handle: r0.handle,
                    parent: None,
                    role: "container",
                    ax_role: Some("AXWindow".to_string()),
                    text: None,
                    is_focused: false,
                    observed_at_ms: r0.observed_at_ms,
                    bounds: Some(sampled_0.0),
                    bounds_observed_at_ms: Some(sampled_0.1),
                },
                CustomSurfaceNode {
                    handle: r1.handle,
                    parent: Some(r0.handle),
                    role: "text",
                    ax_role: Some("AXStaticText".to_string()),
                    text: Some("a".repeat(16)),
                    is_focused: false,
                    observed_at_ms: r1.observed_at_ms,
                    bounds: None,
                    bounds_observed_at_ms: None,
                },
                CustomSurfaceNode {
                    handle: r2.handle,
                    parent: Some(r0.handle),
                    role: "container",
                    ax_role: Some("AXGroup".to_string()),
                    text: Some("b".repeat(16)),
                    is_focused: false,
                    observed_at_ms: r2.observed_at_ms,
                    bounds: None,
                    bounds_observed_at_ms: None,
                },
            ],
            complete: false,
            missing_reasons: Vec::new(),
        };
        assert!(validate_custom_result(&make_valid(), &ctx, 48));

        // Exceeds ctx.budget().max_text_units (33 > 32)
        let mut over_budget = make_valid();
        over_budget.nodes[2].text = Some("b".repeat(17));
        assert!(!validate_custom_result(&over_budget, &ctx, 48));

        // Invalid bounds: NaN, Infinity, negative width/height, oversized
        for bad_b in [
            SurfaceBounds::new(f64::NAN, 0.0, 100.0, 20.0),
            SurfaceBounds::new(f64::INFINITY, 0.0, 100.0, 20.0),
            SurfaceBounds::new(0.0, 0.0, -1.0, 20.0),
            SurfaceBounds::new(0.0, 0.0, 100.0, -5.0),
            SurfaceBounds::new(2_000_000.0, 0.0, 100.0, 20.0),
        ] {
            let mut bad = make_valid();
            bad.nodes[0].bounds = Some(bad_b);
            assert!(!validate_custom_result(&bad, &ctx, 48));
        }

        // Forged bounds mismatched vs ctx.sampled_bounds()
        let mut shifted = make_valid();
        shifted.nodes[0].bounds = Some(SurfaceBounds::new(1.0, 0.0, 800.0, 600.0));
        assert!(!validate_custom_result(&shifted, &ctx, 48));

        // Forged bounds_observed_at_ms mismatched vs ctx.sampled_bounds()
        let mut wrong_bounds_ts = make_valid();
        wrong_bounds_ts.nodes[0].bounds_observed_at_ms = Some(sampled_0.1 + 1);
        assert!(!validate_custom_result(&wrong_bounds_ts, &ctx, 48));

        // Forged bounds on handle 2 which was never sampled in ctx.sampled_bounds()
        let mut unsampled = make_valid();
        unsampled.nodes[2].bounds = Some(SurfaceBounds::new(0.0, 0.0, 10.0, 10.0));
        unsampled.nodes[2].bounds_observed_at_ms = Some(1_002);
        assert!(!validate_custom_result(&unsampled, &ctx, 48));

        // Negative or > MAX_SAFE_INTEGER timestamps
        let mut neg_obs = make_valid();
        neg_obs.nodes[0].observed_at_ms = -1;
        assert!(!validate_custom_result(&neg_obs, &ctx, 48));

        let mut huge_obs = make_valid();
        huge_obs.nodes[0].observed_at_ms = MAX_SAFE_INTEGER + 1;
        assert!(!validate_custom_result(&huge_obs, &ctx, 48));

        let mut neg_bounds_ts = make_valid();
        neg_bounds_ts.nodes[0].bounds_observed_at_ms = Some(-5);
        assert!(!validate_custom_result(&neg_bounds_ts, &ctx, 48));

        // Forged ax_role: AXSecureTextField or mismatched vs inspected.role
        let mut secure_role = make_valid();
        secure_role.nodes[1].ax_role = Some("AXSecureTextField".to_string());
        assert!(!validate_custom_result(&secure_role, &ctx, 48));

        let mut mismatched_role = make_valid();
        mismatched_role.nodes[0].ax_role = Some("AXGroup".to_string());
        assert!(!validate_custom_result(&mismatched_role, &ctx, 48));
    }

    // 2. Hard contract cap: cumulative UTF-16 > 8_192 MUST be rejected even with max budget.
    {
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
        let r0 = ctx.inspect(SurfaceHandle(0)).unwrap();
        let r1 = ctx.inspect(SurfaceHandle(1)).unwrap();
        let r2 = ctx.inspect(SurfaceHandle(2)).unwrap();
        let over_8192 = CustomSurfaceResult {
            nodes: vec![
                CustomSurfaceNode {
                    handle: r0.handle,
                    parent: None,
                    role: "container",
                    ax_role: Some("AXWindow".to_string()),
                    text: None,
                    is_focused: false,
                    observed_at_ms: r0.observed_at_ms,
                    bounds: None,
                    bounds_observed_at_ms: None,
                },
                CustomSurfaceNode {
                    handle: r1.handle,
                    parent: Some(r0.handle),
                    role: "text",
                    ax_role: Some("AXStaticText".to_string()),
                    text: Some("x".repeat(5_000)),
                    is_focused: false,
                    observed_at_ms: r1.observed_at_ms,
                    bounds: None,
                    bounds_observed_at_ms: None,
                },
                CustomSurfaceNode {
                    handle: r2.handle,
                    parent: Some(r0.handle),
                    role: "container",
                    ax_role: Some("AXGroup".to_string()),
                    text: Some("y".repeat(3_193)),
                    is_focused: false,
                    observed_at_ms: r2.observed_at_ms,
                    bounds: None,
                    bounds_observed_at_ms: None,
                },
            ],
            complete: false,
            missing_reasons: Vec::new(),
        };
        assert!(!validate_custom_result(&over_8192, &ctx, 48));
    }
}

// ============================================================================
// Test 28: [P1-8] Weighted Fallback Filters TOCTOU-Evicted Nodes & Single Focus
// ============================================================================
#[test]
fn weighted_fallback_filters_toctou_evicted_nodes_and_enforces_single_focus() {
    let clock = FakeClock::new();
    let app = id("org.example.app");
    let policy = allowlist_policy(&["org.example.app"]);

    // 1. Non-root, non-focus AXTextField turning sensitive before WeightedSurfaceWork::Text
    //    MUST be filtered out (never emitted in tree.nodes or tree.handles!).
    {
        let mut nodes = HashMap::new();
        nodes.insert(0, MockNode::new("AXWindow").children(vec![1, 2]));
        nodes.insert(1, MockNode::new("AXStaticText").parent(0).text("Safe visible text"));
        nodes.insert(2, MockNode::new("AXTextField").parent(0).text("Becomes password"));

        let mut backend = MockSurfaceBackend::new(nodes);
        let mut node2_count = 0usize;
        backend.on_inspect = Some(Box::new(move |idx, _| {
            if idx == 2 {
                node2_count += 1;
                if node2_count >= 2 {
                    return Some(BackendInspection::Allowed(Box::new(BackendAllowedNode {
                        role: "AXTextField".to_string(),
                        category: "editable",
                        subrole: SubroleRead::NoValue,
                        protected_content: ProtectedContentRead::Value(true),
                        child_count: 0,
                        is_focused: false,
                        observed_at_ms: 1_002,
                        is_enabled: Some(true),
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

        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected weighted capture to succeed with evicted leaf removed");
        };
        assert!(
            !tree.handles.iter().any(|(_, idx)| *idx == 2),
            "evicted newly-sensitive handle 2 must NEVER be emitted"
        );
        assert!(!tree.nodes.iter().any(|n| n.role == "editable"));
        assert!(!backend.text_reads.contains(&2));
        assert!(texts_of(&tree).contains(&"Safe visible text"));
        assert!(tree.reasons.iter().any(|r| r == "node-security-excluded"));
        assert!(!tree.complete);
        assert_valid_forest(&tree);
    }

    // 2. Duplicate focused hints in weighted traversal MUST emit at most ONE focused == Some(true).
    {
        let mut nodes = HashMap::new();
        nodes.insert(0, MockNode::new("AXWindow").children(vec![1, 2]));
        nodes.insert(1, MockNode::new("AXTextField").parent(0).focused().text("First focused"));
        nodes.insert(2, MockNode::new("AXTextField").parent(0).focused().text("Second focused"));

        // Unfocused hint (focus = None): at most 1 node has focused == Some(true).
        let mut b1 = MockSurfaceBackend::new(nodes.clone());
        let SurfaceCaptureOutcome::Success(t1) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut b1,
        ) else {
            panic!("expected capture with duplicate focus hints to succeed");
        };
        assert_eq!(
            t1.nodes.iter().filter(|n| n.focused == Some(true)).count(),
            1,
            "at most 1 emitted node may carry focused=true"
        );

        // Explicit focus = Some(SurfaceHandle(2)): exactly 1 focused node, matching handle 2.
        let mut b2 = MockSurfaceBackend::new(nodes);
        let SurfaceCaptureOutcome::Success(t2) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            Some(SurfaceHandle(2)),
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut b2,
        ) else {
            panic!("expected capture with explicit focus handle to succeed");
        };
        let focused_nodes: Vec<_> = t2.nodes.iter().filter(|n| n.focused == Some(true)).collect();
        assert_eq!(focused_nodes.len(), 1);
        assert_eq!(focused_nodes[0].text.as_deref(), Some("Second focused"));
    }
}

// ============================================================================
// Test 29: [P2-5] KernelSurfaceContext::bounds Charges Calls Even on None
// ============================================================================
#[test]
fn bounds_charges_call_budget_even_when_backend_returns_none() {
    let clock = FakeClock::new();
    let app = id("org.example.app");
    let policy = allowlist_policy(&["org.example.app"]);
    let mut nodes = HashMap::new();
    nodes.insert(0, MockNode::new("AXWindow").children(vec![1, 2]));
    nodes.insert(1, MockNode::new("AXGroup").parent(0)); // bounds: None
    nodes.insert(2, MockNode::new("AXStaticText").parent(0).text("No bounds text"));

    let mut backend = MockSurfaceBackend::new(nodes);
    let mut ctx = KernelSurfaceContext::new(
        app,
        &policy,
        GENERIC_ADAPTER.spec(),
        "window",
        48,
        SurfaceHandle(0),
        None,
        ReadBudget::new(5_000, 150, 200, 32, 8_192),
        &clock,
        &mut backend,
    );
    ctx.set_initial_window_rect(SurfaceAbsoluteRect::new(100.0, 200.0, 800.0, 600.0));
    assert!(ctx.inspect(SurfaceHandle(1)).is_some());
    let calls_before = ctx.budget().calls();
    assert_eq!(ctx.bounds(SurfaceHandle(1)), None);
    assert_eq!(
        ctx.budget().calls(),
        calls_before + 1,
        "bounds() must charge 1 backend call even when backend returns None"
    );
    assert!(ctx.extra_reasons().contains("geometry-unavailable"));

    // read_text() bounds fallback must also charge 1 backend call when returning None.
    assert!(ctx.inspect(SurfaceHandle(2)).is_some());
    let calls_before_text = ctx.budget().calls();
    assert_eq!(ctx.text(SurfaceHandle(2), None).as_deref(), Some("No bounds text"));
    // 1 refresh + 1 text read + 1 bounds probe = 3 calls
    assert_eq!(ctx.budget().calls(), calls_before_text + 3);
    drop(ctx);
    assert_eq!(backend.bounds_calls, 2);
}

// ============================================================================
// Test 31: [P2-7] Final Recheck Diagnostic, Prep Probe Charging, Unfocused Sensitive Abort & take_extra_reasons
// ============================================================================
#[test]
fn runner_and_context_diagnostics_unfocused_sensitive_abort_and_prep_accounting() {
    let clock = FakeClock::new();
    let app = id("org.example.app");
    let policy = allowlist_policy(&["org.example.app"]);

    // 1. Final window-rect recheck skipped (!can_recheck_window_rect() because remaining_calls < 8)
    //    MUST append "geometry-unavailable" and strip node bounds!
    {
        let mut nodes = HashMap::new();
        nodes.insert(0, MockNode::new("AXWindow").children((1..=10).collect()).bounds(0.0, 0.0, 800.0, 600.0));
        for i in 1..=10 {
            nodes.insert(i, MockNode::new("AXStaticText").parent(0).text(format!("Line {i}")).bounds(10.0, 20.0 * i as f64, 200.0, 18.0));
        }
        let mut backend = MockSurfaceBackend::new(nodes).with_window_rect(0.0, 0.0, 800.0, 600.0);
        // 12 total calls with 4 reserved -> 8 exploration calls exhausted -> at final validation remaining_calls == 4 < 8!
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 12, 4, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected partial capture when final window rect recheck is skipped");
        };
        assert!(tree.geometry.is_none());
        assert!(tree.nodes.iter().all(|n| n.bounds.is_none()));
        assert!(
            tree.reasons.iter().any(|r| r == "geometry-unavailable"),
            "skipped final window-rect recheck must record geometry-unavailable, got {:?}",
            tree.reasons
        );
    }

    // 2. SurfaceFocusAnchors::collect probes & work are charged even when prep.plan == None.
    {
        let mut nodes = HashMap::new();
        nodes.insert(0, MockNode::new("AXWindow").children(vec![1, 2, 3]));
        for i in 1..=3 {
            nodes.insert(i, MockNode::new("AXStaticText").parent(0).text(format!("Root leaf {i}")));
        }
        // Disconnected focus chain (50 -> 51 -> 52 -> None) so SurfaceFocusAnchors::collect fails with plan = None!
        nodes.insert(50, MockNode::new("AXTextField").parent(51).focused().text("Detached focus"));
        nodes.insert(51, MockNode::new("AXGroup").parent(52).children(vec![50]));
        nodes.insert(52, MockNode::new("AXGroup").children(vec![51]));

        // Baseline without focus anchor prep: fits within max_output_nodes=2 (max_work=16) without WorkBudget!
        let mut b_no_focus = MockSurfaceBackend::new(nodes.clone());
        let SurfaceCaptureOutcome::Success(tree_no_focus) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            2, // max_work = 16, max_probes = 12
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut b_no_focus,
        ) else {
            panic!("expected baseline weighted capture without focus");
        };
        assert!(
            !tree_no_focus.reasons.iter().any(|r| r == "weighted-work-budget"),
            "baseline without failed prep must fit within work budget, got {:?}",
            tree_no_focus.reasons
        );

        // With disconnected focus handle 50: prep.plan == None, yet prep.work/prep.probes MUST still be charged!
        let mut backend = MockSurfaceBackend::new(nodes);
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            2, // max_work = 16, max_probes = 12 -> prep cap work=8, probes=3 -> failed prep consumes 7 work & 3 probes
            Some(SurfaceHandle(50)),
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected weighted fallback after failed focus anchor prep");
        };
        assert!(
            backend.inspected_indices.contains(&50)
                && backend.inspected_indices.contains(&51)
                && backend.inspected_indices.contains(&52),
            "focus anchor preparation should probe disconnected focus chain"
        );
        assert!(
            tree.reasons.iter().any(|r| r == "weighted-work-budget"),
            "failed focus anchor prep work/probes MUST be charged to traversal even when prep.plan == None, got {:?}",
            tree.reasons
        );
    }

    // 3. Unfocused-window capture (focus == None) where a node reports node.is_focused == true
    //    and is sensitive MUST still abort with SecurityExcluded in BOTH inspect & read_text!
    {
        let mut nodes = HashMap::new();
        nodes.insert(0, MockNode::new("AXWindow").children(vec![1]));
        nodes.insert(1, MockNode::new("AXSecureTextField").parent(0).focused().text("hunter2"));
        let mut backend = MockSurfaceBackend::new(nodes);
        let outcome = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            None, // unfocused-window capture: self.focus == None!
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        );
        assert_eq!(
            outcome,
            SurfaceCaptureOutcome::Failure(SurfaceReadFailure::SecurityExcluded)
        );
    }
    {
        let mut nodes = HashMap::new();
        nodes.insert(0, MockNode::new("AXWindow").children(vec![1]));
        nodes.insert(1, MockNode::new("AXTextField").parent(0).focused().text("secret"));
        let mut backend = MockSurfaceBackend::new(nodes);
        let mut seen = 0usize;
        backend.on_inspect = Some(Box::new(move |idx, _| {
            if idx == 1 {
                seen += 1;
                if seen == 2 {
                    return Some(BackendInspection::Allowed(Box::new(BackendAllowedNode {
                        role: "AXTextField".to_string(),
                        category: "editable",
                        subrole: SubroleRead::NoValue,
                        protected_content: ProtectedContentRead::Value(true),
                        child_count: 0,
                        is_focused: true,
                        observed_at_ms: 1_001,
                        is_enabled: Some(true),
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
        let mut ctx = KernelSurfaceContext::new(
            app.clone(),
            &policy,
            GENERIC_ADAPTER.spec(),
            "window",
            48,
            SurfaceHandle(0),
            None, // self.focus == None!
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        );
        assert!(ctx.inspect(SurfaceHandle(1)).is_some());
        assert_eq!(ctx.text(SurfaceHandle(1), None), None);
        assert_eq!(
            ctx.abort_failure(),
            Some(SurfaceReadFailure::SecurityExcluded),
            "read_text must abort SecurityExcluded when node.is_focused == true even if ctx.focus() == None"
        );
    }

    // 4. take_extra_reasons() returns sorted reasons and drains extra_reasons.
    {
        let mut nodes = HashMap::new();
        nodes.insert(0, MockNode::new("AXWindow"));
        let mut backend = MockSurfaceBackend::new(nodes);
        let mut ctx = KernelSurfaceContext::new(
            app,
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
        ctx.note_missing_reason("z-reason");
        ctx.note_missing_reason("a-reason");
        assert_eq!(ctx.take_extra_reasons(), vec!["a-reason", "z-reason"]);
        assert!(ctx.extra_reasons().is_empty());
    }
}

// ============================================================================
// Test 32: [PR-B Gap #1] Lazy ResolvedCount Traversal & Custom Incremental Children Coexist
// ============================================================================
#[test]
fn runner_lazy_resolved_count_and_custom_incremental_children_coexist() {
    let clock = FakeClock::new();
    let app = id("org.example.app");
    let policy = allowlist_policy(&["org.example.app"]);

    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1, 22])
            .bounds(100.0, 200.0, 800.0, 600.0),
    );
    nodes.insert(
        1,
        MockNode::new("AXList")
            .parent(0)
            .children((2..=21).collect())
            .bounds(110.0, 210.0, 780.0, 500.0),
    );
    for i in 2..=21 {
        nodes.insert(
            i,
            MockNode::new("AXStaticText")
                .parent(1)
                .text(format!("Item {}", i - 1))
                .bounds(120.0, 220.0 + (i as f64) * 20.0, 300.0, 18.0),
        );
    }
    nodes.insert(
        22,
        MockNode::new("AXTextField")
            .parent(0)
            .focused()
            .text("Composer")
            .bounds(110.0, 720.0, 780.0, 32.0),
    );

    // 1. Custom adapter path (`SafeSurfaceContext::children`) MUST keep incremental `Values`,
    //    never returning `None` from `ResolvedCount` even when `lazy_resolve_on_traversal` is true.
    {
        let mut backend = MockSurfaceBackend::new(nodes.clone());
        backend.cap_reported_child_count = Some(2);
        backend.lazy_resolve_on_traversal = true;
        let mut ctx = KernelSurfaceContext::new(
            app.clone(),
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
        let list_info = ctx.inspect(SurfaceHandle(1)).expect("list inspected");
        assert_eq!(list_info.child_count, 2, "2-child probe hint reported");
        let page1 = ctx
            .children(SurfaceHandle(1), 0, 5)
            .expect("custom children() must return incremental Values");
        assert_eq!(
            page1,
            vec![
                SurfaceHandle(2),
                SurfaceHandle(3),
                SurfaceHandle(4),
                SurfaceHandle(5),
                SurfaceHandle(6),
            ]
        );
        assert!(ctx.last_children_truncated());
        let page2 = ctx
            .children(SurfaceHandle(1), 5, 5)
            .expect("custom children() page 2 must succeed");
        assert_eq!(
            page2,
            vec![
                SurfaceHandle(7),
                SurfaceHandle(8),
                SurfaceHandle(9),
                SurfaceHandle(10),
                SurfaceHandle(11),
            ]
        );
    }

    // 2. Weighted traversal path (`children_backend_for_traversal`) resolves `child_count = 2` ->
    //    `ResolvedCount(20)` and captures ALL 20 siblings with tail-first paging!
    {
        let mut backend = MockSurfaceBackend::new(nodes.clone());
        backend.cap_reported_child_count = Some(2);
        backend.lazy_resolve_on_traversal = true;
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            Some(SurfaceHandle(22)),
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected weighted traversal with lazy ResolvedCount to succeed");
        };
        assert!(
            tree.complete,
            "complete expected, reasons={:?}",
            tree.reasons
        );
        let texts = texts_of(&tree);
        for i in 1..=20 {
            let expected = format!("Item {i}");
            assert!(
                texts.contains(&expected.as_str()),
                "missing lazily-expanded sibling {expected}; got {texts:?}"
            );
        }
        // First actual page fetch on container 1 (after ResolvedCount(20)) must be tail-first!
        let list_reqs: Vec<(usize, usize)> = backend
            .child_requests
            .iter()
            .filter(|&&(idx, _, _)| idx == 1)
            .map(|&(_, off, lim)| (off, lim))
            .collect();
        assert!(
            !list_reqs.is_empty() && list_reqs[0].0 > 0,
            "expected tail-first paging after ResolvedCount(20), got {list_reqs:?}"
        );
        assert_valid_forest(&tree);
    }
}

// ============================================================================
// Test 33: [PR-B Gap #2] FilteredPuaStatic Preserves complete=true in Weighted & None in Custom
// ============================================================================
#[test]
fn runner_filtered_pua_static_preserves_complete_true_in_weighted_and_none_in_custom() {
    let clock = FakeClock::new();
    let app = id("org.example.app");
    let policy = allowlist_policy(&["org.example.app"]);

    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1, 2])
            .bounds(100.0, 200.0, 800.0, 600.0),
    );
    nodes.insert(
        1,
        MockNode::new("AXStaticText")
            .parent(0)
            .text("Visible header")
            .bounds(110.0, 220.0, 200.0, 20.0),
    );
    nodes.insert(
        2,
        MockNode::new("AXStaticText")
            .parent(0)
            .text("\u{E000}\u{E001}")
            .bounds(320.0, 220.0, 24.0, 24.0),
    );

    // 1. Weighted path: FilteredPuaStatic drops leaf cleanly with complete == true, reasons == [], 0 charge.
    {
        let mut backend = MockSurfaceBackend::new(nodes.clone());
        backend.on_text_read = Some(Box::new(|idx| {
            if idx == 2 {
                Some(BackendTextRead::FilteredPuaStatic {
                    value: "\u{E000}\u{E001}".to_string(),
                })
            } else {
                None
            }
        }));
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected weighted traversal with FilteredPuaStatic to succeed");
        };
        assert!(tree.complete, "expected complete=true, reasons={:?}", tree.reasons);
        assert!(!tree.truncated);
        assert!(tree.reasons.is_empty());
        assert_eq!(texts_of(&tree), vec!["Visible header"]);
        assert_eq!(tree.text_units, access_contract::utf16_len("Visible header"));
    }

    // 2. Custom `SafeSurfaceContext::text`: FilteredPuaStatic returns None with 0 text charge and 0 reasons.
    {
        let mut backend = MockSurfaceBackend::new(nodes.clone());
        backend.on_text_read = Some(Box::new(|idx| {
            if idx == 2 {
                Some(BackendTextRead::FilteredPuaStatic {
                    value: "\u{E000}\u{E001}".to_string(),
                })
            } else {
                None
            }
        }));
        let mut ctx = KernelSurfaceContext::new(
            app.clone(),
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
        assert!(ctx.inspect(SurfaceHandle(2)).is_some());
        assert_eq!(ctx.text(SurfaceHandle(2), None), None);
        assert_eq!(ctx.budget().text_units(), 0);
        assert!(ctx.extra_reasons().is_empty());
    }

    // 3. Defense-in-depth materialization strips unfocused pure-PUA text emitted by custom adapters
    //    while keeping focused pure-PUA text intact.
    {
        struct PuaEmittingCustomAdapter;
        impl AppAdapter for PuaEmittingCustomAdapter {
            fn spec(&self) -> &'static AppAdapterSpec {
                GENERIC_ADAPTER.spec()
            }
            fn extract_surface(&self, ctx: &mut dyn SafeSurfaceContext) -> Option<CustomSurfaceResult> {
                let root = ctx.inspect(ctx.root())?;
                let n1 = ctx.inspect(SurfaceHandle(1))?;
                let n2 = ctx.inspect(SurfaceHandle(2))?;
                Some(CustomSurfaceResult {
                    nodes: vec![
                        CustomSurfaceNode {
                            handle: root.handle,
                            parent: None,
                            role: "container",
                            ax_role: Some("AXWindow".to_string()),
                            text: None,
                            is_focused: false,
                            observed_at_ms: root.observed_at_ms,
                            bounds: None,
                            bounds_observed_at_ms: None,
                        },
                        CustomSurfaceNode {
                            handle: n1.handle,
                            parent: Some(root.handle),
                            role: "text",
                            ax_role: Some("AXStaticText".to_string()),
                            text: Some("\u{E000}\u{E001}".to_string()),
                            is_focused: false,
                            observed_at_ms: n1.observed_at_ms,
                            bounds: None,
                            bounds_observed_at_ms: None,
                        },
                        CustomSurfaceNode {
                            handle: n2.handle,
                            parent: Some(root.handle),
                            role: "text",
                            ax_role: Some("AXStaticText".to_string()),
                            text: Some("\u{E002}".to_string()),
                            is_focused: true,
                            observed_at_ms: n2.observed_at_ms,
                            bounds: None,
                            bounds_observed_at_ms: None,
                        },
                    ],
                    complete: true,
                    missing_reasons: Vec::new(),
                })
            }
        }

        let mut backend = MockSurfaceBackend::new(nodes);
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &PuaEmittingCustomAdapter,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected custom PUA defense-in-depth capture to succeed");
        };
        let unfocused = tree.nodes.iter().find(|n| n.id == "sample-1").expect("node 1");
        assert_eq!(unfocused.text, None, "unfocused pure-PUA text must be stripped");
        let focused = tree.nodes.iter().find(|n| n.id == "sample-2").expect("node 2");
        assert_eq!(focused.text.as_deref(), Some("\u{E002}"));
    }
}

// ============================================================================
// Test 34: [PR-B Gap #3] Custom Fallback Restores Text Budget & Clears charged_display_text
// ============================================================================
#[test]
fn runner_custom_fallback_restores_text_budget_and_clears_charged_display_text() {
    let clock = FakeClock::new();
    let app = id("org.example.app");
    let policy = allowlist_policy(&["org.example.app"]);

    // 1. Speculative custom text + display_text units are reclaimed on `None` fallback and
    //    `charged_display_text` is cleared so weighted traversal re-charges display_text cleanly.
    {
        struct SpeculativeFallbackAdapter;
        impl AppAdapter for SpeculativeFallbackAdapter {
            fn spec(&self) -> &'static AppAdapterSpec {
                GENERIC_ADAPTER.spec()
            }
            fn extract_surface(&self, ctx: &mut dyn SafeSurfaceContext) -> Option<CustomSurfaceResult> {
                let _ = ctx.inspect(SurfaceHandle(0));
                let _ = ctx.inspect(SurfaceHandle(1));
                let _ = ctx.inspect(SurfaceHandle(2));
                // Spend ALL 15 units of the 15-unit text budget speculatively: 10 (text) + 5 (display_text).
                assert_eq!(ctx.text(SurfaceHandle(1), None).as_deref(), Some("1234567890"));
                assert_eq!(ctx.display_text(SurfaceHandle(2)).as_deref(), Some("Btn12"));
                None
            }
        }

        let mut nodes = HashMap::new();
        nodes.insert(
            0,
            MockNode::new("AXWindow")
                .children(vec![1, 2])
                .bounds(100.0, 200.0, 800.0, 600.0),
        );
        nodes.insert(
            1,
            MockNode::new("AXStaticText")
                .parent(0)
                .text("1234567890")
                .bounds(110.0, 220.0, 200.0, 20.0),
        );
        nodes.insert(
            2,
            MockNode::new("AXButton")
                .parent(0)
                .display_text("Btn12")
                .label("Btn12")
                .bounds(110.0, 250.0, 80.0, 24.0),
        );

        let mut backend = MockSurfaceBackend::new(nodes);
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &SpeculativeFallbackAdapter,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 15), // exact fit for 10 + 5 units!
            &clock,
            &mut backend,
        ) else {
            panic!("expected weighted fallback after reclaimed text budget to succeed");
        };
        assert!(
            tree.complete,
            "reclaimed budget must let weighted fallback complete cleanly, reasons={:?}",
            tree.reasons
        );
        let texts = texts_of(&tree);
        assert!(texts.contains(&"1234567890"));
        assert!(texts.contains(&"Btn12"));
        assert_eq!(
            tree.text_units, 15,
            "charged_display_text must be cleared and re-charged (10 + 5 = 15)"
        );
    }

    // 2. Poisoned `text_violated` during custom probe MUST abort BoundaryUnverified (no fallback!).
    {
        struct ViolatingFallbackAdapter;
        impl AppAdapter for ViolatingFallbackAdapter {
            fn spec(&self) -> &'static AppAdapterSpec {
                GENERIC_ADAPTER.spec()
            }
            fn extract_surface(&self, ctx: &mut dyn SafeSurfaceContext) -> Option<CustomSurfaceResult> {
                let _ = ctx.inspect(SurfaceHandle(1));
                let _ = ctx.text(SurfaceHandle(1), Some(4));
                None
            }
        }

        let mut nodes = HashMap::new();
        nodes.insert(0, MockNode::new("AXWindow").children(vec![1]));
        nodes.insert(1, MockNode::new("AXStaticText").parent(0).text("short"));
        let mut backend = MockSurfaceBackend::new(nodes);
        backend.on_text_read = Some(Box::new(|idx| {
            if idx == 1 {
                // Violate requested limit=4 by returning 10 units!
                Some(BackendTextRead::Text {
                    value: "0123456789".to_string(),
                    complete: true,
                    reasons: Vec::new(),
                })
            } else {
                None
            }
        }));
        let outcome = SurfaceCaptureRunner::run(
            &ViolatingFallbackAdapter,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 100),
            &clock,
            &mut backend,
        );
        assert_eq!(
            outcome,
            SurfaceCaptureOutcome::Failure(SurfaceReadFailure::BoundaryUnverified)
        );
    }
}

// ============================================================================
// Test 35: [PR-B Gaps #4 & #10] Backend Missing Reasons & Weighted Text Truncation Propagation
// ============================================================================
#[test]
fn runner_propagates_backend_missing_reasons_and_text_truncation() {
    let clock = FakeClock::new();
    let app = id("org.example.app");
    let policy = allowlist_policy(&["org.example.app"]);

    let mut nodes = HashMap::new();
    nodes.insert(0, MockNode::new("AXWindow").children(vec![1]));
    nodes.insert(1, MockNode::new("AXStaticText").parent(0).text("Hello"));

    // 1. Backend partiality flags (`tree-provider-refused`, `tree-child-limit`) force incomplete/truncated.
    {
        let mut backend = MockSurfaceBackend::new(nodes.clone());
        backend.backend_reasons = vec!["tree-provider-refused", "tree-child-limit"];
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected weighted capture with backend missing reasons to succeed partially");
        };
        assert!(!tree.complete);
        assert!(tree.truncated);
        assert!(tree.reasons.iter().any(|r| r == "bounded-ax-tree"));
        assert!(tree.reasons.iter().any(|r| r == "tree-provider-refused"));
        assert!(tree.reasons.iter().any(|r| r == "tree-child-limit"));
    }

    // 2. Weighted `BackendTextRead::Text { complete: false, reasons: [] }` forces complete=false, truncated=true.
    {
        let mut backend = MockSurfaceBackend::new(nodes);
        backend.on_text_read = Some(Box::new(|idx| {
            if idx == 1 {
                Some(BackendTextRead::Text {
                    value: "Hel".to_string(),
                    complete: false,
                    reasons: Vec::new(),
                })
            } else {
                None
            }
        }));
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            None,
            ReadBudget::new(5_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected weighted capture with truncated text to succeed partially");
        };
        assert!(!tree.complete, "truncated text must force complete=false");
        assert!(tree.truncated, "truncated text must force truncated=true");
        assert!(tree.reasons.iter().any(|r| r == "bounded-ax-tree"));
    }
}

// ============================================================================
// Test 36: [PR-B Gaps #5 & #9] Focus-Anchor Sensitive Parent Aborts & Passes Prep Deadline
// ============================================================================
#[test]
fn runner_focus_anchor_sensitive_parent_aborts_and_passes_prep_deadline() {
    let clock = FakeClock::new(); // mono = 1_000
    let app = id("org.example.app");
    let policy = allowlist_policy(&["org.example.app"]);

    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1])
            .bounds(100.0, 200.0, 800.0, 600.0),
    );
    nodes.insert(
        1,
        MockNode::new("AXGroup")
            .parent(0)
            .children(vec![2])
            .bounds(110.0, 210.0, 780.0, 580.0),
    );
    nodes.insert(
        2,
        MockNode::new("AXTextField")
            .parent(1)
            .focused()
            .text("Draft")
            .bounds(120.0, 220.0, 300.0, 28.0),
    );

    // 1. Focus-anchor parent walk passes tightened prep deadline (1_000 + 160 = 1_160 < 9_850).
    {
        let mut backend = MockSurfaceBackend::new(nodes.clone());
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            Some(SurfaceHandle(2)),
            ReadBudget::new(10_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected focus-anchored weighted capture to succeed");
        };
        assert!(tree.complete);
        assert!(
            !backend.parent_deadlines.is_empty(),
            "parent_backend_node must be invoked during focus-anchor collection"
        );
        for &dl in &backend.parent_deadlines {
            assert_eq!(
                dl, 1_160,
                "parent_backend_node must receive tightened prep window deadline (now + 160ms)"
            );
        }
    }

    // 2. BackendParentRead::Fatal(SecurityExcluded) aborts immediately with ZERO weighted fallback.
    {
        let mut backend = MockSurfaceBackend::new(nodes);
        backend.on_parent = Some(Box::new(|idx, _| {
            if idx == 2 {
                Some(collector_core::adapters::kernel::BackendParentRead::Fatal(
                    SurfaceReadFailure::SecurityExcluded,
                ))
            } else {
                None
            }
        }));
        let outcome = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            Some(SurfaceHandle(2)),
            ReadBudget::new(10_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        );
        assert_eq!(
            outcome,
            SurfaceCaptureOutcome::Failure(SurfaceReadFailure::SecurityExcluded)
        );
        assert!(
            backend.text_reads.is_empty(),
            "sensitive parent abort must prevent weighted fallback text reads"
        );
    }
}

// ============================================================================
// Test 37: [PR-B Gaps #6 & #7] Region Scope Skips Custom Extractor & Text Wrapper Clean in Weighted
// ============================================================================
#[test]
fn runner_region_scope_skips_custom_extractor_and_expands_text_wrapper_clean_in_weighted() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let clock = FakeClock::new();

    // 1. `scope == "region"` skips custom `extract_surface` (even on custom adapters) while STILL
    //    running focus-anchor collection.
    {
        struct TrackingCustomAdapter {
            called: Arc<AtomicBool>,
        }
        impl AppAdapter for TrackingCustomAdapter {
            fn spec(&self) -> &'static AppAdapterSpec {
                WECHAT_ADAPTER.spec()
            }
            fn has_custom_extractor(&self) -> bool {
                true
            }
            fn extract_surface(&self, _ctx: &mut dyn SafeSurfaceContext) -> Option<CustomSurfaceResult> {
                self.called.store(true, Ordering::SeqCst);
                None
            }
        }

        let called = Arc::new(AtomicBool::new(false));
        let adapter = TrackingCustomAdapter {
            called: Arc::clone(&called),
        };
        let app = id("wechat.exe");
        let policy = CapturePolicy {
            capture_scope: Some("region".to_string()),
            ..allowlist_policy(&["wechat.exe"])
        };

        let mut nodes = HashMap::new();
        nodes.insert(
            0,
            MockNode::new("AXGroup")
                .children(vec![1])
                .bounds(100.0, 200.0, 800.0, 600.0),
        );
        nodes.insert(
            1,
            MockNode::new("AXGroup")
                .parent(0)
                .children(vec![2])
                .bounds(110.0, 210.0, 780.0, 580.0),
        );
        nodes.insert(
            2,
            MockNode::new("AXTextField")
                .parent(1)
                .focused()
                .text("Region input")
                .bounds(120.0, 220.0, 300.0, 28.0),
        );

        let mut backend = MockSurfaceBackend::new(nodes);
        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &adapter,
            &app,
            &policy,
            "region",
            48,
            Some(SurfaceHandle(2)),
            ReadBudget::new(10_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected region capture to succeed via weighted traversal");
        };
        assert!(
            !called.load(Ordering::SeqCst),
            "scope == \"region\" must NOT invoke custom extract_surface"
        );
        assert!(
            !backend.parent_deadlines.is_empty(),
            "scope == \"region\" must still collect focus anchors"
        );
        assert!(tree.complete, "reasons={:?}", tree.reasons);
        assert!(texts_of(&tree).contains(&"Region input"));
    }

    // 2. WeChat `big_title_line_h_view` (`expands_text_wrapper_id`) preserves `child_count > 0`
    //    for custom `AdapterNodeInfo` yet reports `child_count == 0` in weighted fallback so ZERO
    //    spurious `tree-children-inconsistent` reason is emitted!
    {
        let app = id("wechat.exe");
        let policy = allowlist_policy(&["wechat.exe"]);
        let mut nodes = HashMap::new();
        nodes.insert(
            0,
            MockNode::new("AXWindow")
                .children(vec![1])
                .bounds(100.0, 200.0, 800.0, 600.0),
        );
        nodes.insert(
            1,
            MockNode::new("AXStaticText")
                .parent(0)
                .identifier("MainWindow.big_title_line_h_view")
                .children(vec![2])
                .text("Chat Title Wrapper")
                .bounds(110.0, 210.0, 400.0, 32.0),
        );
        nodes.insert(
            2,
            MockNode::new("AXStaticText")
                .parent(1)
                .identifier("current_chat_name_label")
                .text("Alice")
                .bounds(120.0, 214.0, 200.0, 24.0),
        );

        // Verify custom `ctx.inspect` still sees child_count == 1 for WeChat custom adapter.
        {
            let mut b = MockSurfaceBackend::new(nodes.clone());
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
                &mut b,
            );
            let info = ctx.inspect(SurfaceHandle(1)).expect("wrapper inspected");
            assert_eq!(
                info.child_count, 1,
                "AdapterNodeInfo must preserve child_count for custom WeChat"
            );
        }

        // Weighted fallback (no chat_message_list -> WeChatAdapter returns None) must emit ZERO
        // `tree-children-inconsistent`!
        let mut backend = MockSurfaceBackend::new(nodes);
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
            panic!("expected WeChat weighted fallback to succeed");
        };
        assert!(
            !tree.reasons.iter().any(|r| r == "tree-children-inconsistent"),
            "expands_text_wrapper_id must not cause tree-children-inconsistent in weighted fallback: {:?}",
            tree.reasons
        );
        assert!(tree.complete, "reasons={:?}", tree.reasons);
    }
}

// ============================================================================
// Test 38: [PR-B Gap #8] Geometry observed_at_ms Clamped on Backward Wall Clock
// ============================================================================
#[test]
fn runner_geometry_observed_at_ms_clamped_on_backward_clock() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct BackwardUnixClock {
        calls: AtomicUsize,
    }
    impl CollectorClock for BackwardUnixClock {
        fn unix_ms(&self) -> i64 {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                1_700_000_005_000
            } else {
                // Wall clock jumps backward by 5 seconds before final geometry validation!
                1_700_000_000_000
            }
        }
        fn monotonic_ms(&self) -> i64 {
            1_000
        }
    }

    let clock = BackwardUnixClock {
        calls: AtomicUsize::new(0),
    };
    let app = id("org.example.app");
    let policy = allowlist_policy(&["org.example.app"]);

    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1])
            .bounds(100.0, 200.0, 800.0, 600.0),
    );
    nodes.insert(
        1,
        MockNode::new("AXStaticText")
            .parent(0)
            .text("Clock test")
            .bounds(110.0, 220.0, 200.0, 20.0),
    );
    let mut backend = MockSurfaceBackend::new(nodes).with_window_rect(100.0, 200.0, 800.0, 600.0);

    let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
        &GENERIC_ADAPTER,
        &app,
        &policy,
        "window",
        48,
        None,
        ReadBudget::new(5_000, 150, 768, 32, 8_192),
        &clock,
        &mut backend,
    ) else {
        panic!("expected capture with backward wall clock to succeed");
    };
    let geom = tree.geometry.expect("geometry present");
    assert!(
        geom.observed_at_ms >= 1_700_000_005_000,
        "geometry.observed_at_ms ({}) must be clamped >= run_start_unix_ms (1700000005000)",
        geom.observed_at_ms
    );
}

// ============================================================================
// Test 39: [PR-B Prep Window] Hitting prep_duration or prep_calls Does Not Pollute complete=true
// ============================================================================
#[test]
fn runner_prep_window_time_and_call_cap_do_not_pollute_reasons_or_complete() {
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;

    struct AtomicMonoClock {
        mono: Arc<AtomicI64>,
        unix: i64,
    }
    impl CollectorClock for AtomicMonoClock {
        fn unix_ms(&self) -> i64 {
            self.unix
        }
        fn monotonic_ms(&self) -> i64 {
            self.mono.load(Ordering::SeqCst)
        }
    }

    let app = id("org.example.app");
    let policy = allowlist_policy(&["org.example.app"]);

    let mut nodes = HashMap::new();
    nodes.insert(
        0,
        MockNode::new("AXWindow")
            .children(vec![1, 4])
            .bounds(100.0, 200.0, 800.0, 600.0),
    );
    nodes.insert(
        1,
        MockNode::new("AXGroup")
            .parent(0)
            .children(vec![2])
            .bounds(110.0, 210.0, 780.0, 400.0),
    );
    nodes.insert(
        2,
        MockNode::new("AXGroup")
            .parent(1)
            .children(vec![3])
            .bounds(120.0, 220.0, 760.0, 300.0),
    );
    nodes.insert(
        3,
        MockNode::new("AXTextField")
            .parent(2)
            .focused()
            .text("Focused field")
            .bounds(130.0, 230.0, 300.0, 28.0),
    );
    nodes.insert(
        4,
        MockNode::new("AXStaticText")
            .parent(0)
            .text("Sibling label")
            .bounds(110.0, 640.0, 300.0, 24.0),
    );

    // 1. Hitting the tightened 160ms prep deadline during focus-anchor collection MUST NOT insert
    //    `tree-time-budget` when ample global exploration time remains and main traversal completes.
    {
        let mono = Arc::new(AtomicI64::new(1_000));
        let clock = AtomicMonoClock {
            mono: Arc::clone(&mono),
            unix: 1_700_000_000_000,
        };
        let mono_hook = Arc::clone(&mono);
        let mut backend = MockSurfaceBackend::new(nodes.clone());
        backend.on_parent = Some(Box::new(move |idx, _| {
            if idx == 3 {
                // Step past prep_deadline (1_160) while still well below exploration_deadline (9_850).
                mono_hook.store(1_200, Ordering::SeqCst);
            }
            None
        }));

        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            Some(SurfaceHandle(3)),
            ReadBudget::new(10_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected weighted traversal to complete after prep timeout");
        };
        assert!(
            tree.complete,
            "hitting prep_duration must not break complete=true, reasons={:?}",
            tree.reasons
        );
        assert!(!tree.truncated);
        assert!(tree.reasons.is_empty(), "unexpected reasons={:?}", tree.reasons);
        let texts = texts_of(&tree);
        assert!(texts.contains(&"Focused field"));
        assert!(texts.contains(&"Sibling label"));
    }

    // 2. Hitting the 25% prep call ceiling (including multi-IPC BackendCallBudget::exhausted())
    //    MUST NOT insert `tree-call-budget` when global exploration calls remain and main traversal
    //    completes cleanly.
    {
        let clock = FakeClock::new();
        let mut backend = MockSurfaceBackend::new(nodes.clone());
        backend.on_parent = Some(Box::new(|idx, calls| {
            if idx == 3 {
                // Exhaust ONLY the prep-window BackendCallBudget ceiling (used == 0).
                let _ = calls.try_consume(calls.remaining() + 1);
                return Some(collector_core::adapters::kernel::BackendParentRead::None);
            }
            None
        }));

        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            Some(SurfaceHandle(3)),
            ReadBudget::new(10_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected weighted traversal to complete after prep call ceiling");
        };
        assert!(
            tree.complete,
            "hitting prep_calls ceiling (used=0) must not break complete=true, reasons={:?}",
            tree.reasons
        );
        assert!(!tree.truncated);
        assert!(tree.reasons.is_empty(), "unexpected reasons={:?}", tree.reasons);
        let texts = texts_of(&tree);
        assert!(texts.contains(&"Focused field"));
        assert!(texts.contains(&"Sibling label"));
    }

    // 3. Same check when a multi-IPC prep call consumes `used > 0` before hitting prep ceiling.
    {
        let clock = FakeClock::new();
        let mut backend = MockSurfaceBackend::new(nodes);
        backend.on_parent = Some(Box::new(|idx, calls| {
            if idx == 3 {
                assert!(calls.try_consume(1));
                let _ = calls.try_consume(calls.remaining() + 1);
                return Some(collector_core::adapters::kernel::BackendParentRead::None);
            }
            None
        }));

        let SurfaceCaptureOutcome::Success(tree) = SurfaceCaptureRunner::run(
            &GENERIC_ADAPTER,
            &app,
            &policy,
            "window",
            48,
            Some(SurfaceHandle(3)),
            ReadBudget::new(10_000, 150, 768, 32, 8_192),
            &clock,
            &mut backend,
        ) else {
            panic!("expected weighted traversal to complete after partial multi-IPC prep cap");
        };
        assert!(
            tree.complete,
            "hitting prep_calls ceiling (used>0) must not break complete=true, reasons={:?}",
            tree.reasons
        );
        assert!(!tree.truncated);
        assert!(tree.reasons.is_empty(), "unexpected reasons={:?}", tree.reasons);
        let texts = texts_of(&tree);
        assert!(texts.contains(&"Focused field"));
        assert!(texts.contains(&"Sibling label"));
    }
}

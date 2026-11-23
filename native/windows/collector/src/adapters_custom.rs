//! Phase 4 kernel-enforced `SafeSurfaceContext` framework, `SurfaceCaptureRunner`,
//! and custom `WeChatAdapter` & `FigmaAdapter` surface extractors.
//!
//! All four `AGENTS.md` invariants hold across both production (`LiveUiaSurfaceBackend`)
//! and unit-test (`MockSurfaceBackend`) backends because every adapter executes exclusively
//! through `KernelSurfaceContext<B>`.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use access_contract::utf16_len;

use crate::adapters::{
    AppAdapterSpec, SafeDisplayText, StaticTextPolicy, BROWSER_FAMILY_SPEC, FEISHU_ADAPTER_SPEC,
    FIGMA_ADAPTER_SPEC, GENERIC_ADAPTER_SPEC, QQ_ADAPTER_SPEC, SLACK_ADAPTER_SPEC,
    TERMINAL_FAMILY_SPEC, TYPORA_ADAPTER_SPEC, VSCODE_FAMILY_SPEC, WECHAT_ADAPTER_SPEC,
};
use crate::policy::{
    is_private_use_only_text, ApplicationPolicy, BrowserGate, ProtectedContentRead, ReadBudget,
    ResolvedAppIdentity, SubroleRead, TextSecurityGate,
};
use crate::protocol_model::{
    bounded_utf16_slice, CapturePolicy, CollectorClock, SecureStatus, SurfaceAbsoluteRect,
    SurfaceBounds, SurfaceGeometry, SurfaceNode, SurfaceReadFailure,
};
use crate::uia_traversal::{
    SurfaceFocusAnchorPlan, SurfaceFocusAnchors, WeightedSurfaceChildrenRead,
    WeightedSurfaceInspection, WeightedSurfaceMetadata, WeightedSurfaceTextRead,
    WeightedSurfaceTraversal, WeightedSurfaceTraversalLimits, WeightedSurfaceTraversalReason,
};

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
pub static WECHAT_ADAPTER: WeChatAdapter = WeChatAdapter;
pub static SLACK_ADAPTER: DeclarativeAdapter = DeclarativeAdapter {
    spec: &SLACK_ADAPTER_SPEC,
};
pub static TYPORA_ADAPTER: DeclarativeAdapter = DeclarativeAdapter {
    spec: &TYPORA_ADAPTER_SPEC,
};
pub static FIGMA_ADAPTER: FigmaAdapter = FigmaAdapter;

/// Resolve a custom extractor adapter by canonical `AppAdapterSpec::id`.
pub fn custom_adapter_by_id(id: &str) -> Option<&'static dyn AppAdapter> {
    match id {
        "wechat" => Some(&WECHAT_ADAPTER),
        "figma" => Some(&FIGMA_ADAPTER),
        _ => None,
    }
}

/// Resolve any built-in `AppAdapter` implementation by canonical `AppAdapterSpec::id`.
pub fn adapter_impl_by_id(id: &str) -> &'static dyn AppAdapter {
    match id {
        "vscode-family" => &VSCODE_FAMILY_ADAPTER,
        "browser-family" => &BROWSER_FAMILY_ADAPTER,
        "terminal-family" => &TERMINAL_FAMILY_ADAPTER,
        "qq" => &QQ_ADAPTER,
        "feishu" => &FEISHU_ADAPTER,
        "wechat" => &WECHAT_ADAPTER,
        "slack" => &SLACK_ADAPTER,
        "typora" => &TYPORA_ADAPTER,
        "figma" => &FIGMA_ADAPTER,
        _ => &GENERIC_ADAPTER,
    }
}

/// Backend node metadata returned from live UIA or mock tests into `KernelSurfaceContext`.
#[derive(Debug, Clone)]
pub struct BackendAllowedNode {
    pub role: String,
    pub category: &'static str,
    pub subrole: SubroleRead,
    pub protected_content: ProtectedContentRead,
    pub child_count: usize,
    pub is_focused: bool,
    pub observed_at_ms: i64,
    pub is_enabled: Option<bool>,
    pub display_text: Option<String>,
    pub window_title: Option<String>,
    pub absolute_rect: Option<SurfaceAbsoluteRect>,
    pub identifier: Option<String>,
    pub class_name: Option<String>,
    pub label: Option<String>,
    pub is_offscreen: bool,
    /// Optional platform-specific strict security classification (e.g. Windows `IsPassword == false`).
    pub strict_security: Option<SecureStatus>,
}

/// Result of inspecting a single backend node.
#[derive(Debug, Clone)]
pub enum BackendInspection {
    Allowed(Box<BackendAllowedNode>),
    Pruned(WeightedSurfaceTraversalReason),
    Fatal(SurfaceReadFailure),
}

/// Result of reading text from an approved backend node.
#[derive(Debug, Clone)]
pub enum BackendTextRead {
    Text {
        value: String,
        complete: bool,
        reasons: Vec<String>,
    },
    Unavailable {
        reasons: Vec<String>,
    },
    Fatal(SurfaceReadFailure),
}

/// Per-operation call-budget tracker passed from `KernelSurfaceContext` into `SurfaceBackend`
/// methods so multi-IPC operations meter every real COM IPC against `ReadBudget::max_calls`
/// and stop immediately when the remaining call ceiling is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCallBudget {
    limit: usize,
    used: usize,
    exhausted: bool,
}

impl BackendCallBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            used: 0,
            exhausted: false,
        }
    }

    /// Reserve `count` backend calls; returns `false` and marks `exhausted` if doing so would
    /// exceed the remaining call ceiling.
    pub fn try_consume(&mut self, count: usize) -> bool {
        if count == 0 {
            return true;
        }
        if self.used > self.limit.saturating_sub(count) {
            self.exhausted = true;
            return false;
        }
        self.used += count;
        true
    }

    pub fn used(&self) -> usize {
        self.used
    }

    pub fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.used)
    }

    pub fn exhausted(&self) -> bool {
        self.exhausted
    }
}

/// Result of reading a head-paged slice of children from a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendChildrenPage {
    Values {
        handles: Vec<usize>,
        /// True when additional siblings remain beyond this page or enumeration hit a cap/budget.
        truncated: bool,
    },
    ResolvedCount(usize),
    Unavailable(WeightedSurfaceTraversalReason),
    AccessDenied,
}

/// Result of reading tail children of a container (O(limit) on Windows UIA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendTailChildrenRead {
    Values {
        handles: Vec<usize>,
        truncated: bool,
    },
    Unavailable(WeightedSurfaceTraversalReason),
    AccessDenied,
}

/// Low-level platform or mock backend plugged into `KernelSurfaceContext<B>`.
pub trait SurfaceBackend {
    fn verify_desktop_and_application(&mut self) -> Option<SurfaceReadFailure>;

    fn inspect_backend_node(
        &mut self,
        index: usize,
        is_root: bool,
        calls: &mut BackendCallBudget,
    ) -> BackendInspection;

    /// Fresh metadata re-inspection invoked before every text read.
    /// Live UIA overrides this to run `BuildUpdatedCache`; mocks default to `inspect_backend_node`.
    fn refresh_backend_node(
        &mut self,
        index: usize,
        is_root: bool,
        calls: &mut BackendCallBudget,
    ) -> BackendInspection {
        self.inspect_backend_node(index, is_root, calls)
    }

    fn parent_backend_node(
        &mut self,
        index: usize,
        calls: &mut BackendCallBudget,
    ) -> Option<usize>;

    fn children_backend_page(
        &mut self,
        index: usize,
        expected_role: &str,
        offset: usize,
        limit: usize,
        calls: &mut BackendCallBudget,
    ) -> BackendChildrenPage;

    fn tail_children_backend(
        &mut self,
        index: usize,
        expected_role: &str,
        limit: usize,
        calls: &mut BackendCallBudget,
    ) -> BackendTailChildrenRead;

    fn read_backend_node_text(
        &mut self,
        index: usize,
        expected_role: &str,
        max_units: usize,
        static_text_probe: StaticTextPolicy,
        calls: &mut BackendCallBudget,
    ) -> BackendTextRead;

    fn read_backend_node_bounds(
        &mut self,
        index: usize,
        window_rect: SurfaceAbsoluteRect,
    ) -> Option<(SurfaceBounds, i64)>;

    fn read_backend_window_rect(&mut self) -> Option<SurfaceAbsoluteRect>;

    fn verify_final_surface_boundary(&mut self) -> Option<SurfaceReadFailure>;

    fn resolve_region_parent_root(&mut self) -> Option<usize> {
        None
    }
}

fn failure_priority(failure: SurfaceReadFailure) -> u8 {
    match failure {
        SurfaceReadFailure::SecurityExcluded => 10,
        SurfaceReadFailure::BoundaryMismatch => 9,
        SurfaceReadFailure::BoundaryUnverified => 8,
        SurfaceReadFailure::BoundaryAxFailed => 7,
        SurfaceReadFailure::BoundaryIncomplete => 6,
        SurfaceReadFailure::TimeBudget => 5,
        SurfaceReadFailure::CallBudget => 4,
        SurfaceReadFailure::NotStartedBudget => 3,
        SurfaceReadFailure::AnchorUnavailable => 2,
        SurfaceReadFailure::ProviderUnavailable => 1,
    }
}

/// Reusable kernel wrapper enforcing ALL unbypassable security, privacy, and `ReadBudget`
/// invariants across both live UIA (`LiveUiaSurfaceBackend`) and test mocks (`MockSurfaceBackend`).
pub struct KernelSurfaceContext<'a, B: SurfaceBackend> {
    resolved_identity: ResolvedAppIdentity,
    policy: &'a CapturePolicy,
    spec: &'static AppAdapterSpec,
    scope: String,
    max_output_nodes: usize,
    root: SurfaceHandle,
    focus: Option<SurfaceHandle>,
    budget: ReadBudget,
    clock: &'a dyn CollectorClock,
    backend: &'a mut B,
    call_ceiling_override: Option<usize>,
    deadline_override_ms: Option<i64>,
    abort_failure: Option<SurfaceReadFailure>,
    extra_reasons: BTreeSet<String>,
    inspected_nodes: HashMap<SurfaceHandle, AdapterNodeInfo>,
    sampled_bounds: HashMap<SurfaceHandle, (SurfaceBounds, i64)>,
    charged_display_text: HashMap<SurfaceHandle, String>,
    initial_window_rect: Option<SurfaceAbsoluteRect>,
    last_children_truncated: bool,
}

impl<'a, B: SurfaceBackend> KernelSurfaceContext<'a, B> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resolved_identity: ResolvedAppIdentity,
        policy: &'a CapturePolicy,
        spec: &'static AppAdapterSpec,
        scope: &str,
        max_output_nodes: usize,
        root: SurfaceHandle,
        focus: Option<SurfaceHandle>,
        budget: ReadBudget,
        clock: &'a dyn CollectorClock,
        backend: &'a mut B,
    ) -> Self {
        Self {
            resolved_identity,
            policy,
            spec,
            scope: scope.to_string(),
            max_output_nodes: max_output_nodes.clamp(1, 96),
            root,
            focus,
            budget,
            clock,
            backend,
            call_ceiling_override: None,
            deadline_override_ms: None,
            abort_failure: None,
            extra_reasons: BTreeSet::new(),
            inspected_nodes: HashMap::new(),
            sampled_bounds: HashMap::new(),
            charged_display_text: HashMap::new(),
            initial_window_rect: None,
            last_children_truncated: false,
        }
    }

    pub fn set_initial_window_rect(&mut self, rect: Option<SurfaceAbsoluteRect>) {
        self.initial_window_rect = rect;
    }

    pub fn initial_window_rect(&self) -> Option<SurfaceAbsoluteRect> {
        self.initial_window_rect
    }

    pub fn abort_failure(&self) -> Option<SurfaceReadFailure> {
        self.abort_failure
    }

    pub fn budget(&self) -> &ReadBudget {
        &self.budget
    }

    pub fn into_budget(self) -> ReadBudget {
        self.budget
    }

    pub fn extra_reasons(&self) -> &BTreeSet<String> {
        &self.extra_reasons
    }

    pub fn inspected_nodes(&self) -> &HashMap<SurfaceHandle, AdapterNodeInfo> {
        &self.inspected_nodes
    }

    pub fn sampled_bounds(&self) -> &HashMap<SurfaceHandle, (SurfaceBounds, i64)> {
        &self.sampled_bounds
    }

    pub fn effective_deadline_ms(&self) -> i64 {
        match self.deadline_override_ms {
            Some(ov) => self.budget.active_deadline_ms().min(ov),
            None => self.budget.active_deadline_ms(),
        }
    }

    fn effective_call_limit(&self) -> usize {
        match self.call_ceiling_override {
            Some(ov) => self.budget.active_call_limit().min(ov),
            None => self.budget.active_call_limit(),
        }
    }

    fn effective_remaining_calls(&self) -> usize {
        self.effective_call_limit()
            .saturating_sub(self.budget.calls())
    }

    fn commit_backend_calls(&mut self, call_budget: &BackendCallBudget) -> bool {
        if call_budget.exhausted() {
            if !self.budget.is_final_validation() {
                self.extra_reasons.insert("tree-call-budget".to_string());
            }
            if call_budget.used() == 0 {
                return false;
            }
            return self.record_backend_calls(call_budget.used());
        }
        let count = call_budget.used().max(1);
        self.record_backend_calls(count)
    }

    fn evict_handle(&mut self, handle: SurfaceHandle) {
        self.inspected_nodes.remove(&handle);
        self.sampled_bounds.remove(&handle);
        self.charged_display_text.remove(&handle);
    }

    pub fn record_backend_calls(&mut self, count: usize) -> bool {
        if self.abort_failure.is_some() || self.budget.text_violated() {
            return false;
        }
        let now = self.clock.monotonic_ms();
        if now >= self.effective_deadline_ms() {
            if !self.budget.is_final_validation() {
                self.extra_reasons.insert("tree-time-budget".to_string());
            }
            return false;
        }
        if let Some(ceiling) = self.call_ceiling_override {
            if self.budget.calls().saturating_add(count) > ceiling {
                return false;
            }
        }
        let ok = self.budget.consume_calls(count, now);
        if !ok && !self.budget.is_final_validation() {
            self.extra_reasons.insert("tree-call-budget".to_string());
        }
        ok
    }

    fn record_backend_text(&mut self, units: usize, requested: Option<usize>) -> bool {
        let ok = self.budget.consume_text(units, requested);
        if !ok {
            self.abort(SurfaceReadFailure::BoundaryUnverified);
        }
        ok
    }

    fn verify_kernel_gates(&mut self) -> bool {
        if self.abort_failure.is_some() || self.budget.text_violated() {
            return false;
        }
        if !self.policy.enabled
            || !ApplicationPolicy::allows_identity(self.policy, &self.resolved_identity)
            || !BrowserGate::allows_identity(&self.resolved_identity, self.policy, false)
        {
            self.abort(SurfaceReadFailure::SecurityExcluded);
            return false;
        }
        if let Some(failure) = self.backend.verify_desktop_and_application() {
            self.abort(failure);
            return false;
        }
        true
    }

    pub fn abort(&mut self, failure: SurfaceReadFailure) {
        self.abort_failure = match self.abort_failure {
            Some(existing) if failure_priority(existing) >= failure_priority(failure) => {
                Some(existing)
            }
            _ => Some(failure),
        };
        // Wipe all cached inspection/bounds/display text state on any kernel abort.
        self.inspected_nodes.clear();
        self.sampled_bounds.clear();
        self.charged_display_text.clear();
    }

    pub fn begin_final_validation(&mut self) {
        self.call_ceiling_override = None;
        self.deadline_override_ms = None;
        self.budget.begin_final_validation();
    }

    pub fn promote_region_root_if_applicable(&mut self) {
        if self.scope != "region"
            || !self.inspected_nodes.is_empty()
            || !self.verify_kernel_gates()
            || !self.can_continue()
        {
            return;
        }
        let before = self.budget.calls();
        if let Some(parent_idx) = self.backend.resolve_region_parent_root() {
            if self.budget.calls() == before {
                let _ = self.record_backend_calls(1);
            }
            self.root = SurfaceHandle(parent_idx);
        }
    }

    pub fn sample_window_rect(&mut self) -> Option<SurfaceAbsoluteRect> {
        if !self.verify_kernel_gates() || !self.can_continue() {
            return None;
        }
        let before = self.budget.calls();
        let rect = self.backend.read_backend_window_rect();
        if self.budget.calls() == before {
            let _ = self.record_backend_calls(1);
        }
        if self.abort_failure.is_none() {
            rect
        } else {
            None
        }
    }

    pub fn parent(&mut self, handle: SurfaceHandle) -> Option<SurfaceHandle> {
        if !self.verify_kernel_gates() || !self.can_continue() {
            return None;
        }
        let mut call_budget = BackendCallBudget::new(self.effective_remaining_calls());
        let parent_idx = self.backend.parent_backend_node(handle.0, &mut call_budget);
        if !self.commit_backend_calls(&call_budget) {
            return None;
        }
        if self.abort_failure.is_none() {
            parent_idx.map(SurfaceHandle)
        } else {
            None
        }
    }

    pub fn inspect_for_traversal(&mut self, handle: SurfaceHandle) -> WeightedSurfaceInspection {
        if !self.verify_kernel_gates() {
            return WeightedSurfaceInspection::Pruned(WeightedSurfaceTraversalReason::SecurityPruned);
        }
        if !self.can_continue() {
            let reason = if self.clock.monotonic_ms() >= self.effective_deadline_ms() {
                WeightedSurfaceTraversalReason::TimeBudget
            } else {
                WeightedSurfaceTraversalReason::WorkBudget
            };
            return WeightedSurfaceInspection::Pruned(reason);
        }
        let is_root = handle == self.root;
        let mut call_budget = BackendCallBudget::new(self.effective_remaining_calls());
        let outcome = self
            .backend
            .inspect_backend_node(handle.0, is_root, &mut call_budget);
        let calls_ok = self.commit_backend_calls(&call_budget);

        let node = match outcome {
            BackendInspection::Fatal(failure) => {
                self.abort(failure);
                return WeightedSurfaceInspection::Pruned(
                    WeightedSurfaceTraversalReason::SecurityPruned,
                );
            }
            BackendInspection::Pruned(reason) => {
                if matches!(
                    reason,
                    WeightedSurfaceTraversalReason::SecurityPruned
                        | WeightedSurfaceTraversalReason::UnsupportedRole
                        | WeightedSurfaceTraversalReason::ProviderRefused
                ) {
                    self.evict_handle(handle);
                }
                return WeightedSurfaceInspection::Pruned(reason);
            }
            BackendInspection::Allowed(node) => node,
        };
        if !calls_ok {
            let reason = if self.clock.monotonic_ms() >= self.effective_deadline_ms() {
                WeightedSurfaceTraversalReason::TimeBudget
            } else {
                WeightedSurfaceTraversalReason::WorkBudget
            };
            return WeightedSurfaceInspection::Pruned(reason);
        }

        // Hard unbypassable security gate BEFORE caching any metadata, label, or bounds!
        let sensitive_subrole = matches!(
            &node.subrole,
            SubroleRead::Value(sub) if TextSecurityGate::is_sensitive_subrole(sub)
        );
        if node.role == "AXSecureTextField"
            || node.protected_content == ProtectedContentRead::Value(true)
            || sensitive_subrole
        {
            self.evict_handle(handle);
            if is_root || Some(handle) == self.focus {
                self.abort(SurfaceReadFailure::SecurityExcluded);
            }
            return WeightedSurfaceInspection::Pruned(WeightedSurfaceTraversalReason::SecurityPruned);
        }

        if !TextSecurityGate::may_traverse(&node.subrole, node.protected_content) {
            self.evict_handle(handle);
            if is_root {
                self.abort(SurfaceReadFailure::BoundaryUnverified);
            }
            return WeightedSurfaceInspection::Pruned(WeightedSurfaceTraversalReason::SecurityPruned);
        }

        if is_root
            && BrowserGate::should_block_private_windows_identity(
                &self.resolved_identity,
                self.spec.block_private_windows,
            )
            && node
                .window_title
                .as_deref()
                .is_some_and(BrowserGate::is_private_window_title)
        {
            self.abort(SurfaceReadFailure::SecurityExcluded);
            return WeightedSurfaceInspection::Pruned(WeightedSurfaceTraversalReason::SecurityPruned);
        }

        let safe_subrole = match &node.subrole {
            SubroleRead::Value(sub) if !sub.is_empty() => Some(sub.clone()),
            _ => None,
        };

        if !is_root
            && !node.is_focused
            && (self.spec.ignores_role(&node.role)
                || safe_subrole
                    .as_deref()
                    .is_some_and(|s| self.spec.ignores_subrole(s)))
        {
            return WeightedSurfaceInspection::Pruned(
                WeightedSurfaceTraversalReason::UnsupportedRole,
            );
        }

        let mut bounded_display_text = self.charged_display_text.get(&handle).cloned();
        if bounded_display_text.is_none() {
            if let Some(ref raw) = node.display_text {
                if !raw.is_empty()
                    && !is_private_use_only_text(raw)
                    && SafeDisplayText::ALLOWED_ROLES.contains(&node.role.as_str())
                {
                    let cap = self
                        .spec
                        .max_node_text_units
                        .min(self.budget.remaining_text_units());
                    if cap > 0 {
                        let target_len = utf16_len(raw).min(cap);
                        if let Some(sliced) = bounded_utf16_slice(raw, 0, target_len) {
                            if !sliced.is_empty()
                                && self.budget.consume_text(utf16_len(&sliced), Some(cap))
                            {
                                bounded_display_text = Some(sliced.clone());
                                self.charged_display_text.insert(handle, sliced);
                            }
                        }
                    } else {
                        self.extra_reasons.insert("text-budget".to_string());
                    }
                }
            }
        }

        let safe_label = SafeDisplayText::label(
            node.label.as_deref(),
            bounded_display_text.as_deref(),
            self.spec.max_node_text_units,
        );

        let mut relative_bounds: Option<SurfaceBounds> = None;
        if let (Some(abs_rect), Some(win_rect)) = (node.absolute_rect, self.initial_window_rect) {
            if let Some(rel) = abs_rect.relative_to(win_rect) {
                self.sampled_bounds.insert(handle, (rel, node.observed_at_ms));
                relative_bounds = Some(rel);
            }
        }

        let info = AdapterNodeInfo {
            handle,
            role: node.role.clone(),
            subrole: safe_subrole.clone(),
            child_count: node.child_count,
            is_focused: node.is_focused,
            observed_at_ms: node.observed_at_ms,
            identifier: node.identifier,
            class_name: node.class_name,
            label: safe_label,
            is_offscreen: node.is_offscreen,
        };
        self.inspected_nodes.insert(handle, info);

        WeightedSurfaceInspection::Allowed(WeightedSurfaceMetadata {
            ax_role: Some(node.role),
            category: node.category,
            subrole: safe_subrole,
            child_count: node.child_count,
            is_focused: node.is_focused,
            observed_at_ms: node.observed_at_ms,
            is_enabled: node.is_enabled,
            display_text: bounded_display_text,
            bounds: relative_bounds,
            bounds_observed_at_ms: relative_bounds.map(|_| node.observed_at_ms),
        })
    }

    pub fn children_for_traversal(
        &mut self,
        handle: SurfaceHandle,
        offset: usize,
        limit: usize,
    ) -> WeightedSurfaceChildrenRead<SurfaceHandle> {
        self.last_children_truncated = false;
        if !self.verify_kernel_gates() {
            return WeightedSurfaceChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        }
        if limit == 0 {
            return WeightedSurfaceChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::InconsistentChildren,
            );
        }
        if !self.can_continue() {
            let reason = if self.clock.monotonic_ms() >= self.effective_deadline_ms() {
                WeightedSurfaceTraversalReason::TimeBudget
            } else {
                WeightedSurfaceTraversalReason::WorkBudget
            };
            return WeightedSurfaceChildrenRead::Unavailable(reason);
        }
        let expected_role = if let Some(cached) = self.inspected_nodes.get(&handle) {
            cached.role.clone()
        } else if let Some(fresh) = self.inspect(handle) {
            fresh.role
        } else {
            return WeightedSurfaceChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        };
        if !self.can_continue() {
            let reason = if self.clock.monotonic_ms() >= self.effective_deadline_ms() {
                WeightedSurfaceTraversalReason::TimeBudget
            } else {
                WeightedSurfaceTraversalReason::WorkBudget
            };
            return WeightedSurfaceChildrenRead::Unavailable(reason);
        }
        let clamped_limit = limit.min(64);
        let mut call_budget = BackendCallBudget::new(self.effective_remaining_calls());
        let page = self.backend.children_backend_page(
            handle.0,
            &expected_role,
            offset,
            clamped_limit,
            &mut call_budget,
        );
        let calls_ok = self.commit_backend_calls(&call_budget);
        if matches!(page, BackendChildrenPage::AccessDenied) {
            self.extra_reasons
                .insert("tree-provider-refused".to_string());
            if handle == self.root {
                self.abort(SurfaceReadFailure::ProviderUnavailable);
            }
            return WeightedSurfaceChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::ProviderRefused,
            );
        }
        if !calls_ok {
            let reason = if self.clock.monotonic_ms() >= self.effective_deadline_ms() {
                WeightedSurfaceTraversalReason::TimeBudget
            } else {
                WeightedSurfaceTraversalReason::WorkBudget
            };
            return WeightedSurfaceChildrenRead::Unavailable(reason);
        }
        if self.abort_failure.is_some() {
            return WeightedSurfaceChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        }
        match page {
            BackendChildrenPage::AccessDenied => unreachable!(),
            BackendChildrenPage::Unavailable(reason) => {
                WeightedSurfaceChildrenRead::Unavailable(reason)
            }
            BackendChildrenPage::ResolvedCount(count) => {
                WeightedSurfaceChildrenRead::ResolvedCount(count)
            }
            BackendChildrenPage::Values {
                handles: raw_handles,
                truncated,
            } => {
                if raw_handles.len() > clamped_limit {
                    return WeightedSurfaceChildrenRead::Unavailable(
                        WeightedSurfaceTraversalReason::InconsistentChildren,
                    );
                }
                self.last_children_truncated = truncated;
                WeightedSurfaceChildrenRead::Values(
                    raw_handles.into_iter().map(SurfaceHandle).collect(),
                )
            }
        }
    }

    pub fn read_text(
        &mut self,
        handle: SurfaceHandle,
        max_units: Option<usize>,
    ) -> Option<(String, bool, Vec<String>)> {
        if !self.verify_kernel_gates() || !self.can_continue() {
            return None;
        }

        // NEVER trust prior inspect() — ALWAYS re-verify fresh metadata before touching text!
        let mut inspect_calls = BackendCallBudget::new(self.effective_remaining_calls());
        let check = self.backend.refresh_backend_node(
            handle.0,
            handle == self.root,
            &mut inspect_calls,
        );
        let inspect_calls_ok = self.commit_backend_calls(&inspect_calls);

        let node = match check {
            BackendInspection::Fatal(failure) => {
                self.abort(failure);
                return None;
            }
            BackendInspection::Pruned(reason) => {
                if matches!(
                    reason,
                    WeightedSurfaceTraversalReason::SecurityPruned
                        | WeightedSurfaceTraversalReason::UnsupportedRole
                        | WeightedSurfaceTraversalReason::ProviderRefused
                ) {
                    self.evict_handle(handle);
                }
                let tag = match reason {
                    WeightedSurfaceTraversalReason::WorkBudget => "tree-call-budget",
                    WeightedSurfaceTraversalReason::TimeBudget => "tree-time-budget",
                    WeightedSurfaceTraversalReason::SecurityPruned => "node-security-excluded",
                    _ => "node-text-unavailable",
                };
                self.extra_reasons.insert(tag.to_string());
                return None;
            }
            BackendInspection::Allowed(node) => node,
        };
        if !inspect_calls_ok {
            return None;
        }

        if handle == self.root
            && BrowserGate::should_block_private_windows_identity(
                &self.resolved_identity,
                self.spec.block_private_windows,
            )
            && node
                .window_title
                .as_deref()
                .is_some_and(BrowserGate::is_private_window_title)
        {
            self.abort(SurfaceReadFailure::SecurityExcluded);
            return None;
        }

        let strict_override = node.strict_security;
        let security = TextSecurityGate::classify_metadata(
            Some(node.role.as_str()),
            &node.subrole,
            node.protected_content,
            self.policy,
            strict_override.map(|s| move || s),
        );
        if security == SecureStatus::Sensitive {
            self.evict_handle(handle);
            if handle == self.root || Some(handle) == self.focus {
                self.abort(SurfaceReadFailure::SecurityExcluded);
            }
            self.extra_reasons
                .insert("node-security-excluded".to_string());
            return None;
        }

        if let Some(prior) = self.inspected_nodes.get(&handle) {
            if prior.role != node.role {
                self.evict_handle(handle);
                if handle == self.root {
                    self.abort(SurfaceReadFailure::BoundaryMismatch);
                } else {
                    self.extra_reasons.insert("node-role-changed".to_string());
                }
                return None;
            }
        }

        if !TextSecurityGate::is_readable_text_role(Some(node.role.as_str()))
            || !self.policy.allows_secure(security)
        {
            self.evict_handle(handle);
            self.extra_reasons
                .insert("node-security-excluded".to_string());
            return None;
        }

        let safe_subrole = match &node.subrole {
            SubroleRead::Value(sub) if !sub.is_empty() => Some(sub.clone()),
            _ => None,
        };
        let safe_label = SafeDisplayText::label(
            node.label.as_deref(),
            self.charged_display_text.get(&handle).map(String::as_str),
            self.spec.max_node_text_units,
        );
        self.inspected_nodes.insert(
            handle,
            AdapterNodeInfo {
                handle,
                role: node.role.clone(),
                subrole: safe_subrole,
                child_count: node.child_count,
                is_focused: node.is_focused,
                observed_at_ms: node.observed_at_ms,
                identifier: node.identifier,
                class_name: node.class_name,
                label: safe_label,
                is_offscreen: node.is_offscreen,
            },
        );

        let default_cap = if self.scope == "window" {
            self.spec.max_node_text_units
        } else {
            self.budget.max_text_units
        };
        let node_limit = max_units
            .unwrap_or(default_cap)
            .min(self.budget.remaining_text_units());
        if node_limit == 0 {
            self.extra_reasons.insert("text-budget".to_string());
            return None;
        }
        if !self.can_continue() {
            return None;
        }

        let before_text = self.budget.text_units();
        let mut text_calls = BackendCallBudget::new(self.effective_remaining_calls());
        let result = self.backend.read_backend_node_text(
            handle.0,
            &node.role,
            node_limit,
            self.spec.static_text_probe,
            &mut text_calls,
        );
        let text_calls_ok = self.commit_backend_calls(&text_calls);

        match result {
            BackendTextRead::Fatal(failure) => {
                self.abort(failure);
                None
            }
            BackendTextRead::Unavailable { reasons } => {
                for r in reasons {
                    self.extra_reasons.insert(r);
                }
                None
            }
            BackendTextRead::Text {
                value,
                complete,
                reasons,
            } => {
                if !text_calls_ok {
                    return None;
                }
                let units = utf16_len(&value);
                if self.budget.text_units() == before_text {
                    if !self.record_backend_text(units, Some(node_limit)) {
                        return None;
                    }
                } else if units > node_limit || self.budget.text_violated() {
                    self.abort(SurfaceReadFailure::BoundaryUnverified);
                    return None;
                }
                if !self.verify_kernel_gates() {
                    return None;
                }
                for r in &reasons {
                    self.extra_reasons.insert(r.clone());
                }
                if let Some(win_rect) = self.initial_window_rect {
                    if self.can_continue() {
                        if let Some(abs_rect) = node.absolute_rect {
                            if let Some(rel) = abs_rect.relative_to(win_rect) {
                                self.sampled_bounds
                                    .insert(handle, (rel, node.observed_at_ms));
                            }
                        } else if !self.sampled_bounds.contains_key(&handle) {
                            let before_bounds = self.budget.calls();
                            if let Some(sampled) =
                                self.backend.read_backend_node_bounds(handle.0, win_rect)
                            {
                                if self.budget.calls() == before_bounds {
                                    let _ = self.record_backend_calls(1);
                                }
                                self.sampled_bounds.insert(handle, sampled);
                            } else {
                                self.extra_reasons.insert("geometry-unavailable".to_string());
                            }
                        }
                    }
                }
                Some((value, complete, reasons))
            }
        }
    }

    pub fn display_text_bounded(
        &mut self,
        handle: SurfaceHandle,
        max_units: Option<usize>,
    ) -> Option<String> {
        if self.abort_failure.is_some() || self.budget.text_violated() {
            return None;
        }
        if let Some(existing) = self.charged_display_text.get(&handle) {
            return Some(existing.clone());
        }
        let raw = self.inspected_nodes.get(&handle)?.label.clone()?;
        if raw.is_empty() {
            return None;
        }
        let cap = max_units
            .unwrap_or(self.spec.max_node_text_units)
            .min(self.budget.remaining_text_units());
        if cap == 0 {
            self.extra_reasons.insert("text-budget".to_string());
            return None;
        }
        let len = utf16_len(&raw).min(cap);
        let sliced = bounded_utf16_slice(&raw, 0, len)?;
        if sliced.is_empty() {
            return None;
        }
        if !self.budget.consume_text(utf16_len(&sliced), Some(cap)) {
            self.abort(SurfaceReadFailure::BoundaryUnverified);
            return None;
        }
        self.charged_display_text.insert(handle, sliced.clone());
        Some(sliced)
    }

    pub fn with_preparation_window<T>(
        &mut self,
        max_calls: usize,
        max_duration_ms: i64,
        f: impl FnOnce(&mut Self) -> T,
    ) -> T {
        let saved_ceiling = self.call_ceiling_override;
        let saved_deadline = self.deadline_override_ms;
        let now = self.clock.monotonic_ms();
        self.call_ceiling_override = Some(
            self.budget
                .active_call_limit()
                .min(self.budget.calls().saturating_add(max_calls)),
        );
        self.deadline_override_ms = Some(
            self.budget
                .active_deadline_ms()
                .min(now.saturating_add(max_duration_ms.max(0))),
        );
        let res = f(self);
        self.call_ceiling_override = saved_ceiling;
        self.deadline_override_ms = saved_deadline;
        res
    }
}

impl<B: SurfaceBackend> SafeSurfaceContext for KernelSurfaceContext<'_, B> {
    fn spec(&self) -> &'static AppAdapterSpec {
        self.spec
    }

    fn scope(&self) -> &str {
        &self.scope
    }

    fn max_output_nodes(&self) -> usize {
        self.max_output_nodes
    }

    fn window_size(&self) -> Option<(f64, f64)> {
        self.initial_window_rect.map(|r| (r.width, r.height))
    }

    fn root(&self) -> SurfaceHandle {
        self.root
    }

    fn focus(&self) -> Option<SurfaceHandle> {
        self.focus
    }

    fn is_aborted(&self) -> bool {
        self.abort_failure.is_some()
    }

    fn can_continue(&self) -> bool {
        if self.abort_failure.is_some() || self.budget.text_violated() {
            return false;
        }
        let now = self.clock.monotonic_ms();
        now < self.effective_deadline_ms() && self.budget.calls() < self.effective_call_limit()
    }

    fn has_inspected(&self, handle: SurfaceHandle) -> bool {
        self.inspected_nodes.contains_key(&handle)
    }

    fn inspect(&mut self, handle: SurfaceHandle) -> Option<AdapterNodeInfo> {
        match self.inspect_for_traversal(handle) {
            WeightedSurfaceInspection::Allowed(_) => self.inspected_nodes.get(&handle).cloned(),
            WeightedSurfaceInspection::Pruned(_) => None,
        }
    }

    fn children(
        &mut self,
        handle: SurfaceHandle,
        offset: usize,
        limit: usize,
    ) -> Option<Vec<SurfaceHandle>> {
        match self.children_for_traversal(handle, offset, limit) {
            WeightedSurfaceChildrenRead::Values(handles) => Some(handles),
            WeightedSurfaceChildrenRead::ResolvedCount(_)
            | WeightedSurfaceChildrenRead::Unavailable(_) => None,
        }
    }

    fn last_children_truncated(&self) -> bool {
        self.last_children_truncated
    }

    fn tail_children(&mut self, handle: SurfaceHandle, limit: usize) -> Option<Vec<SurfaceHandle>> {
        self.last_children_truncated = false;
        if !self.verify_kernel_gates() || limit == 0 || !self.can_continue() {
            return None;
        }
        let expected_role = if let Some(cached) = self.inspected_nodes.get(&handle) {
            cached.role.clone()
        } else {
            self.inspect(handle)?.role
        };
        if !self.can_continue() {
            return None;
        }
        let clamped_limit = limit.min(64);
        let mut call_budget = BackendCallBudget::new(self.effective_remaining_calls());
        let read = self.backend.tail_children_backend(
            handle.0,
            &expected_role,
            clamped_limit,
            &mut call_budget,
        );
        let calls_ok = self.commit_backend_calls(&call_budget);
        if matches!(read, BackendTailChildrenRead::AccessDenied) {
            self.extra_reasons
                .insert("tree-provider-refused".to_string());
            if handle == self.root {
                self.abort(SurfaceReadFailure::ProviderUnavailable);
            }
            return None;
        }
        if !calls_ok || self.abort_failure.is_some() {
            return None;
        }
        match read {
            BackendTailChildrenRead::AccessDenied => unreachable!(),
            BackendTailChildrenRead::Unavailable(_) => None,
            BackendTailChildrenRead::Values { handles, truncated } => {
                if handles.len() > clamped_limit {
                    return None;
                }
                self.last_children_truncated = truncated;
                if truncated {
                    self.extra_reasons.insert("tree-output-budget".to_string());
                }
                Some(handles.into_iter().map(SurfaceHandle).collect())
            }
        }
    }

    fn text(&mut self, handle: SurfaceHandle, max_units: Option<usize>) -> Option<String> {
        self.read_text(handle, max_units).map(|(t, _, _)| t)
    }

    fn display_text(&mut self, handle: SurfaceHandle) -> Option<String> {
        self.display_text_bounded(handle, None)
    }

    fn bounds(&mut self, handle: SurfaceHandle) -> Option<(SurfaceBounds, i64)> {
        if let Some(cached) = self.sampled_bounds.get(&handle) {
            return Some(*cached);
        }
        let win_rect = self.initial_window_rect?;
        if !self.verify_kernel_gates()
            || !self.can_continue()
            || !self.inspected_nodes.contains_key(&handle)
        {
            return None;
        }
        let before = self.budget.calls();
        let Some(sampled) = self.backend.read_backend_node_bounds(handle.0, win_rect) else {
            self.extra_reasons.insert("geometry-unavailable".to_string());
            return None;
        };
        if self.budget.calls() == before && !self.record_backend_calls(1) {
            return None;
        }
        self.sampled_bounds.insert(handle, sampled);
        Some(sampled)
    }

    fn note_missing_reason(&mut self, reason: &'static str) {
        self.extra_reasons.insert(reason.to_string());
    }
}

/// Validates a custom adapter's returned node graph against all kernel invariants before
/// materialization or live `SurfaceNodeMap` / `SurfaceBaseline` mutation.
pub fn validate_custom_result<B: SurfaceBackend>(
    result: &CustomSurfaceResult,
    ctx: &KernelSurfaceContext<'_, B>,
    max_output_nodes: usize,
) -> bool {
    if result.nodes.is_empty()
        || result.nodes.len() > max_output_nodes
        || result.nodes.len() > 96
    {
        return false;
    }
    let mut by_handle: HashMap<SurfaceHandle, &CustomSurfaceNode> =
        HashMap::with_capacity(result.nodes.len());
    let mut focus_count = 0usize;
    for node in &result.nodes {
        if !matches!(
            node.role,
            "text" | "editable" | "container" | "terminal" | "other"
        ) {
            return false;
        }
        if node.bounds.is_some() != node.bounds_observed_at_ms.is_some() {
            return false;
        }
        if !node
            .ax_role
            .as_deref()
            .is_none_or(access_contract::is_valid_ax_role)
        {
            return false;
        }
        if !ctx.inspected_nodes().contains_key(&node.handle) {
            return false;
        }
        if by_handle.insert(node.handle, node).is_some() {
            return false;
        }
        if node.is_focused {
            focus_count += 1;
        }
    }
    if focus_count > 1 {
        return false;
    }
    for node in &result.nodes {
        let mut seen = HashSet::new();
        seen.insert(node.handle);
        let mut current = node.parent;
        while let Some(parent) = current {
            if !seen.insert(parent) {
                return false;
            }
            let Some(ancestor) = by_handle.get(&parent) else {
                return false;
            };
            current = ancestor.parent;
        }
    }
    true
}

/// Complete surface capture output produced by `SurfaceCaptureRunner::run`.
#[derive(Debug, Clone, PartialEq)]
pub struct SurfaceCapturedTree {
    pub nodes: Vec<SurfaceNode>,
    pub handles: Vec<(String, usize)>,
    pub geometry: Option<SurfaceGeometry>,
    pub complete: bool,
    pub truncated: bool,
    pub reasons: Vec<String>,
    pub adapter_id: String,
    pub text_units: usize,
}

/// Outcome of `SurfaceCaptureRunner::run`.
#[derive(Debug, Clone, PartialEq)]
pub enum SurfaceCaptureOutcome {
    Success(SurfaceCapturedTree),
    Failure(SurfaceReadFailure),
}

/// Shared kernel-enforced runner orchestrating preflight checks, custom extraction,
/// automatic `WeightedSurfaceTraversal` fallback, and final boundary/geometry validation.
pub struct SurfaceCaptureRunner;

impl SurfaceCaptureRunner {
    #[allow(clippy::too_many_arguments)]
    pub fn run<B: SurfaceBackend>(
        adapter: &dyn AppAdapter,
        resolved_identity: &ResolvedAppIdentity,
        policy: &CapturePolicy,
        scope: &str,
        max_output_nodes: usize,
        focus: Option<SurfaceHandle>,
        budget: ReadBudget,
        clock: &dyn CollectorClock,
        backend: &mut B,
    ) -> SurfaceCaptureOutcome {
        if !policy.enabled
            || !ApplicationPolicy::allows_identity(policy, resolved_identity)
            || !BrowserGate::allows_identity(resolved_identity, policy, false)
        {
            return SurfaceCaptureOutcome::Failure(SurfaceReadFailure::SecurityExcluded);
        }
        let clamped_max_nodes = max_output_nodes.clamp(1, 96);
        if !budget.has_exploration_headroom(clock.monotonic_ms()) {
            return SurfaceCaptureOutcome::Failure(SurfaceReadFailure::NotStartedBudget);
        }
        if let Some(failure) = backend.verify_desktop_and_application() {
            return SurfaceCaptureOutcome::Failure(failure);
        }

        let mut ctx = KernelSurfaceContext::new(
            resolved_identity.clone(),
            policy,
            adapter.spec(),
            scope,
            clamped_max_nodes,
            SurfaceHandle(0),
            focus,
            budget,
            clock,
            backend,
        );

        if scope == "window"
            && BrowserGate::should_block_private_windows_identity(
                resolved_identity,
                adapter.spec().block_private_windows,
            )
        {
            let _ = ctx.inspect_for_traversal(ctx.root());
            if let Some(failure) = ctx.abort_failure() {
                return SurfaceCaptureOutcome::Failure(failure);
            }
        }

        ctx.promote_region_root_if_applicable();
        let initial_rect = ctx.sample_window_rect();
        ctx.set_initial_window_rect(initial_rect);
        if initial_rect.is_none() {
            ctx.note_missing_reason("geometry-unavailable");
        }
        if let Some(failure) = ctx.abort_failure() {
            return SurfaceCaptureOutcome::Failure(failure);
        }

        let extracted_nodes: Vec<CustomSurfaceNode>;
        let extraction_complete: bool;
        let mut reasons: BTreeSet<String> = BTreeSet::new();

        if let Some(custom) = adapter.extract_surface(&mut ctx) {
            if let Some(failure) = ctx.abort_failure() {
                return SurfaceCaptureOutcome::Failure(failure);
            }
            if ctx.budget().text_violated()
                || !validate_custom_result(&custom, &ctx, clamped_max_nodes)
            {
                return SurfaceCaptureOutcome::Failure(SurfaceReadFailure::BoundaryUnverified);
            }
            extracted_nodes = custom.nodes;
            extraction_complete = custom.complete;
            for r in custom.missing_reasons {
                reasons.insert(r);
            }
        } else {
            // CRITICAL: Aborted custom extraction MUST fail closed — NEVER fall back to weighted!
            if let Some(failure) = ctx.abort_failure() {
                return SurfaceCaptureOutcome::Failure(failure);
            }
            if ctx.budget().text_violated() {
                return SurfaceCaptureOutcome::Failure(SurfaceReadFailure::BoundaryUnverified);
            }

            let limits = WeightedSurfaceTraversalLimits::new(
                clamped_max_nodes,
                None,
                None,
                192,
                64,
                adapter.spec().page_size,
                4,
            );
            let preferred: HashSet<&str> = adapter.spec().preferred_roles.iter().copied().collect();
            let ignored: HashSet<&str> = adapter.spec().ignored_roles.iter().copied().collect();
            let ignored_sub: HashSet<&str> =
                adapter.spec().ignored_subroles.iter().copied().collect();

            let mut anchor_plan: Option<SurfaceFocusAnchorPlan<SurfaceHandle>> = None;
            let mut prep_work = 0usize;
            let mut prep_probes = 0usize;
            if scope == "window" {
                if let Some(focus_handle) = ctx.focus() {
                    let now = clock.monotonic_ms();
                    let exp_dl = ctx.budget().exploration_deadline_ms();
                    let prep_duration = if exp_dl == i64::MAX {
                        160
                    } else {
                        exp_dl.saturating_sub(now).checked_div(3).unwrap_or(0).min(160)
                    };
                    let prep_calls = (ctx.budget().remaining_calls() / 4).min(192);
                    if prep_calls >= 4 && prep_duration > 0 {
                        let root_h = ctx.root();
                        let prep = ctx.with_preparation_window(prep_calls, prep_duration, |c| {
                            let c_cell = RefCell::new(c);
                            SurfaceFocusAnchors::collect(
                                root_h,
                                focus_handle,
                                SurfaceFocusAnchors::MAXIMUM_HOPS,
                                SurfaceFocusAnchors::MAXIMUM_WORK.min(limits.max_work / 2),
                                SurfaceFocusAnchors::MAXIMUM_PROBES.min(limits.max_probes / 4),
                                |h| {
                                    let res = c_cell.borrow_mut().inspect_for_traversal(*h);
                                    if let WeightedSurfaceInspection::Allowed(ref meta) = res {
                                        if *h != focus_handle
                                            && meta
                                                .ax_role
                                                .as_deref()
                                                .and_then(WeightedSurfaceTraversal::role_policy)
                                                .is_some_and(|p| p.reads_text())
                                        {
                                            return WeightedSurfaceInspection::Pruned(
                                                WeightedSurfaceTraversalReason::UnsupportedRole,
                                            );
                                        }
                                    }
                                    res
                                },
                                |h| c_cell.borrow_mut().parent(*h),
                                || c_cell.borrow().can_continue(),
                            )
                        });
                        if let Some(plan) = prep.plan {
                            prep_work = plan.work;
                            prep_probes = plan.probes;
                            anchor_plan = Some(plan);
                        }
                    }
                }
            }
            if let Some(failure) = ctx.abort_failure() {
                return SurfaceCaptureOutcome::Failure(failure);
            }

            let root_h = ctx.root();
            let collapse_empty = adapter.spec().collapse_empty_containers;
            let walked = {
                let ctx_cell = RefCell::new(&mut ctx);
                WeightedSurfaceTraversal::run(
                    root_h,
                    limits,
                    &preferred,
                    &ignored,
                    &ignored_sub,
                    collapse_empty,
                    prep_work,
                    prep_probes,
                    anchor_plan.as_ref(),
                    |h| ctx_cell.borrow_mut().inspect_for_traversal(*h),
                    |h, offset, limit| {
                        ctx_cell
                            .borrow_mut()
                            .children_for_traversal(*h, offset, limit)
                    },
                    |h| {
                        let read = ctx_cell.borrow_mut().read_text(*h, None)?;
                        Some(WeightedSurfaceTextRead {
                            text: Some(read.0),
                            truncated: !read.1,
                        })
                    },
                    || ctx_cell.borrow().can_continue(),
                    || {
                        let c = ctx_cell.borrow();
                        !c.is_aborted()
                            && !c.budget().text_violated()
                            && clock.monotonic_ms() < c.effective_deadline_ms()
                    },
                )
            };

            if let Some(failure) = ctx.abort_failure() {
                return SurfaceCaptureOutcome::Failure(failure);
            }
            if ctx.budget().text_violated() {
                return SurfaceCaptureOutcome::Failure(SurfaceReadFailure::BoundaryUnverified);
            }

            extracted_nodes = walked
                .nodes
                .into_iter()
                .map(|sample| {
                    let bounds_entry = ctx.sampled_bounds().get(&sample.handle).copied();
                    let node_text = sample
                        .text_read
                        .as_ref()
                        .and_then(|t| t.text.clone())
                        .or_else(|| sample.metadata.display_text.clone());
                    let ax = sample.metadata.ax_role.as_deref();
                    let wire_role = if sample.text_read.is_some() {
                        if ax == Some("AXStaticText") {
                            "text"
                        } else if sample.metadata.category == "terminal" {
                            "terminal"
                        } else {
                            "editable"
                        }
                    } else if matches!(ax, Some("AXStaticText" | "AXHeading")) {
                        "text"
                    } else if ax
                        .and_then(WeightedSurfaceTraversal::role_policy)
                        .is_some_and(|p| p.reads_text())
                    {
                        if sample.metadata.category == "terminal" {
                            "terminal"
                        } else {
                            "editable"
                        }
                    } else {
                        "container"
                    };
                    CustomSurfaceNode {
                        handle: sample.handle,
                        parent: sample.parent,
                        role: wire_role,
                        ax_role: sample.metadata.ax_role,
                        text: node_text,
                        is_focused: sample.metadata.is_focused,
                        observed_at_ms: sample.metadata.observed_at_ms,
                        bounds: bounds_entry.map(|(b, _)| b),
                        bounds_observed_at_ms: bounds_entry.map(|(_, ts)| ts),
                    }
                })
                .collect();
            extraction_complete = walked.complete;
            for r in walked.reasons {
                reasons.insert(r.as_str().to_string());
            }
        }

        for r in ctx.extra_reasons() {
            reasons.insert(r.clone());
        }
        if ctx.budget().remaining_calls() == 0 {
            reasons.insert("tree-call-budget".to_string());
        }
        if clock.monotonic_ms() >= ctx.budget().exploration_deadline_ms() {
            reasons.insert("tree-time-budget".to_string());
        }

        // Final kernel validation phase using reserved calls & time.
        ctx.begin_final_validation();
        let mut geometry: Option<SurfaceGeometry> = None;
        if let Some(init_rect) = ctx.initial_window_rect() {
            if ctx.budget().can_recheck_window_rect() {
                let final_rect = ctx.sample_window_rect();
                if let Some(failure) = ctx.abort_failure() {
                    return SurfaceCaptureOutcome::Failure(failure);
                }
                geometry = init_rect.geometry_if_unchanged(final_rect, clock.unix_ms());
                if geometry.is_none() {
                    reasons.insert(
                        if final_rect.is_none() {
                            "geometry-unavailable"
                        } else {
                            "geometry-window-moved"
                        }
                        .to_string(),
                    );
                }
            }
        }

        let final_desktop = ctx.backend.verify_desktop_and_application();
        if let Some(failure) = final_desktop {
            return SurfaceCaptureOutcome::Failure(failure);
        }
        let final_boundary = ctx.backend.verify_final_surface_boundary();
        if let Some(failure) = final_boundary {
            return SurfaceCaptureOutcome::Failure(failure);
        }
        if clock.monotonic_ms() >= ctx.budget().deadline_ms {
            return SurfaceCaptureOutcome::Failure(SurfaceReadFailure::TimeBudget);
        }

        let ids_by_handle: HashMap<SurfaceHandle, String> = extracted_nodes
            .iter()
            .map(|n| (n.handle, format!("sample-{}", n.handle.0)))
            .collect();
        let mut nodes = Vec::with_capacity(extracted_nodes.len());
        let mut handles = Vec::with_capacity(extracted_nodes.len());
        for item in &extracted_nodes {
            let local_id = ids_by_handle
                .get(&item.handle)
                .cloned()
                .unwrap_or_else(|| format!("sample-{}", item.handle.0));
            let parent_id = item
                .parent
                .and_then(|p| ids_by_handle.get(&p))
                .cloned();
            nodes.push(SurfaceNode {
                id: local_id.clone(),
                parent_id,
                role: item.role.to_string(),
                text: item.text.clone(),
                observed_at_ms: item.observed_at_ms,
                bounds: geometry.as_ref().and(item.bounds),
                bounds_observed_at_ms: geometry.as_ref().and(item.bounds_observed_at_ms),
                ax_role: item.ax_role.clone(),
                focused: item.is_focused.then_some(true),
            });
            handles.push((local_id, item.handle.0));
        }

        let complete = extraction_complete && reasons.is_empty();
        let ordered_reasons = if complete {
            Vec::new()
        } else {
            let mut out = vec!["bounded-ax-tree".to_string()];
            for r in reasons.into_iter().filter(|r| r != "bounded-ax-tree").take(15) {
                out.push(r);
            }
            out
        };

        SurfaceCaptureOutcome::Success(SurfaceCapturedTree {
            nodes,
            handles,
            geometry,
            complete,
            truncated: !complete,
            reasons: ordered_reasons,
            adapter_id: adapter.spec().id.to_string(),
            text_units: ctx.budget().text_units(),
        })
    }
}

// ============================================================================
// Custom WeChatAdapter (Qt 4.x macOS/Windows + Win32 DuiLib 3.x parity)
// ============================================================================

/// Matches either exact Qt `objectName` / macOS `AXIdentifier` (`"chat_message_list"`)
/// OR the final `.`-delimited segment of Windows Qt `AutomationId` paths
/// (`"MainWindow.centralWidget.splitter.chat_message_list"`).
pub fn matches_wechat_id(identifier: Option<&str>, target: &str) -> bool {
    let Some(id) = identifier else {
        return false;
    };
    id == target || id.rsplit('.').next() == Some(target)
}

pub struct WeChatAdapter;

impl WeChatAdapter {
    const TAIL_MESSAGE_LIMIT: usize = 32;
    const MAX_LOCATOR_DEPTH: usize = 12;
    const MAX_LOCATOR_VISITS: usize = 80;
    const SKIPPED_CONTAINER_ROLES: &'static [&'static str] = &[
        "AXButton",
        "AXToolbar",
        "AXMenuBar",
        "AXMenu",
        "AXMenuItem",
        "AXScrollBar",
        "AXImage",
        "AXTable",
        "AXOutline",
    ];

    fn is_skipped_container_role(role: &str) -> bool {
        Self::SKIPPED_CONTAINER_ROLES.contains(&role)
    }

    fn is_duilib_session_list(info: &AdapterNodeInfo) -> bool {
        info.role == "AXList"
            && info.identifier.is_none()
            && info
                .label
                .as_deref()
                .is_some_and(|l| matches!(l, "会话" | "Chats" | "Session"))
    }

    fn is_duilib_message_list(info: &AdapterNodeInfo) -> bool {
        info.role == "AXList"
            && info.identifier.is_none()
            && info
                .label
                .as_deref()
                .is_some_and(|l| matches!(l, "消息" | "Messages"))
    }
}

impl AppAdapter for WeChatAdapter {
    fn spec(&self) -> &'static AppAdapterSpec {
        &WECHAT_ADAPTER_SPEC
    }

    fn extract_surface(&self, ctx: &mut dyn SafeSurfaceContext) -> Option<CustomSurfaceResult> {
        let root_handle = ctx.root();
        let root_info = ctx.inspect(root_handle)?;

        let mut chat_name_info: Option<AdapterNodeInfo> = None;
        let mut fallback_title_info: Option<AdapterNodeInfo> = None;
        let mut message_list_info: Option<AdapterNodeInfo> = None;
        let mut duilib_message_list_info: Option<AdapterNodeInfo> = None;
        let mut input_info: Option<AdapterNodeInfo> = None;

        // Check focused handle first when it directly identifies chat_input_field.
        if let Some(focus) = ctx.focus() {
            if let Some(focus_info) = ctx.inspect(focus) {
                if matches_wechat_id(focus_info.identifier.as_deref(), "chat_input_field") {
                    input_info = Some(focus_info);
                }
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        // Shallow BFS locating right chat pane elements while NEVER expanding session_list.
        let mut queue: VecDeque<(SurfaceHandle, usize)> = VecDeque::new();
        queue.push_back((root_handle, 0));
        let mut visited: HashSet<SurfaceHandle> = HashSet::new();
        visited.insert(root_handle);
        let mut inspected_count = 1usize;

        while let Some((handle, depth)) = queue.pop_front() {
            if inspected_count >= Self::MAX_LOCATOR_VISITS
                || !ctx.can_continue()
                || (chat_name_info.is_some()
                    && message_list_info.is_some()
                    && input_info.is_some())
            {
                break;
            }
            let info = if handle == root_handle {
                root_info.clone()
            } else {
                inspected_count += 1;
                let Some(fresh) = ctx.inspect(handle) else {
                    continue;
                };
                fresh
            };

            let id = info.identifier.as_deref();
            if matches_wechat_id(id, "session_list")
                || matches_wechat_id(id, "virtual_cell")
                || Self::is_duilib_session_list(&info)
            {
                continue;
            }
            if handle != root_handle && Self::is_skipped_container_role(&info.role) {
                continue;
            }

            if matches_wechat_id(id, "current_chat_name_label") {
                chat_name_info = Some(info);
                continue;
            }
            if matches_wechat_id(id, "big_title_line_h_view") && info.role == "AXStaticText" {
                fallback_title_info = Some(info);
                // Qt header views may nest current_chat_name_label inside AXStaticText!
                if chat_name_info.is_none() && depth < Self::MAX_LOCATOR_DEPTH {
                    if let Some(nested) = ctx.children(handle, 0, 8) {
                        for child in nested {
                            if visited.insert(child) {
                                queue.push_back((child, depth + 1));
                            }
                        }
                    }
                }
                continue;
            }
            if matches_wechat_id(id, "chat_message_list") {
                message_list_info = Some(info);
                continue;
            }
            if matches_wechat_id(id, "chat_input_field") {
                input_info = Some(info);
                continue;
            }
            if duilib_message_list_info.is_none() && Self::is_duilib_message_list(&info) {
                duilib_message_list_info = Some(info);
                continue;
            }

            if chat_name_info.is_some() && message_list_info.is_some() && input_info.is_some() {
                break;
            }
            if depth >= Self::MAX_LOCATOR_DEPTH
                || info.child_count == 0
                || matches!(
                    info.role.as_str(),
                    "AXList" | "AXStaticText" | "AXTextArea" | "AXTextField"
                )
            {
                continue;
            }

            if let Some(children) = ctx.children(handle, 0, 32) {
                for child in children {
                    if visited.insert(child) {
                        queue.push_back((child, depth + 1));
                    }
                }
            }
        }

        if ctx.is_aborted() {
            return None;
        }

        let using_duilib = message_list_info.is_none() && duilib_message_list_info.is_some();
        if message_list_info.is_none() {
            message_list_info = duilib_message_list_info;
        }

        // Accept focused AXTextArea fallback only when chat_message_list confirms chat UI.
        if input_info.is_none() && message_list_info.is_some() {
            if let Some(focus) = ctx.focus() {
                if let Some(focus_info) = ctx.inspect(focus) {
                    if focus_info.role == "AXTextArea"
                        || (using_duilib && focus_info.role == "AXTextField")
                    {
                        input_info = Some(focus_info);
                    }
                }
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        // Fall back to standard weighted traversal when neither chat list nor input is present
        // (e.g. login QR screen, settings, contacts).
        if message_list_info.is_none() && input_info.is_none() {
            return None;
        }

        let max_nodes = ctx.max_output_nodes().clamp(1, 96);
        let focus_handle = ctx.focus();
        let mut seen: HashSet<SurfaceHandle> = HashSet::new();
        seen.insert(root_handle);
        let mut focus_assigned = false;

        let make_node = |ctx: &mut dyn SafeSurfaceContext,
                         focus_assigned: &mut bool,
                         info: &AdapterNodeInfo,
                         parent: Option<SurfaceHandle>,
                         role: &'static str,
                         text: Option<String>|
         -> CustomSurfaceNode {
            let bounds = ctx.bounds(info.handle);
            let is_focused = !*focus_assigned
                && focus_handle
                    .map(|fh| fh == info.handle)
                    .unwrap_or(info.is_focused);
            if is_focused {
                *focus_assigned = true;
            }
            CustomSurfaceNode {
                handle: info.handle,
                parent,
                role,
                ax_role: Some(info.role.clone()),
                text,
                is_focused,
                observed_at_ms: info.observed_at_ms,
                bounds: bounds.map(|(b, _)| b),
                bounds_observed_at_ms: bounds.map(|(_, ts)| ts),
            }
        };

        let has_zero_size = |ctx: &mut dyn SafeSurfaceContext, handle: SurfaceHandle| -> bool {
            ctx.bounds(handle)
                .is_some_and(|(r, _)| r.width <= 0.0 || r.height <= 0.0)
        };

        let mut nodes: Vec<CustomSurfaceNode> =
            vec![make_node(ctx, &mut focus_assigned, &root_info, None, "container", None)];

        if let Some(ref title_info) = chat_name_info.or(fallback_title_info) {
            if nodes.len() < max_nodes && seen.insert(title_info.handle) {
                if let Some(title_text) = ctx.text(title_info.handle, None) {
                    if !title_text.trim().is_empty() {
                        nodes.push(make_node(
                            ctx,
                            &mut focus_assigned,
                            title_info,
                            Some(root_handle),
                            "text",
                            Some(title_text),
                        ));
                    }
                }
            }
        }

        let reserve_input_slot = usize::from(
            input_info
                .as_ref()
                .is_some_and(|inp| !seen.contains(&inp.handle)),
        );
        let mut truncated_tail = false;

        if let Some(ref list_info) = message_list_info {
            if nodes.len() + reserve_input_slot < max_nodes {
                let list_ready = list_info.handle == root_handle || seen.insert(list_info.handle);
                if list_ready {
                    if list_info.handle != root_handle {
                        nodes.push(make_node(
                            ctx,
                            &mut focus_assigned,
                            list_info,
                            Some(root_handle),
                            "container",
                            None,
                        ));
                    }
                    let message_slots = max_nodes.saturating_sub(nodes.len() + reserve_input_slot);
                    if list_info.child_count > Self::TAIL_MESSAGE_LIMIT {
                        truncated_tail = true;
                    }
                    if list_info.child_count > 0 && message_slots > 0 && ctx.can_continue() {
                        if let Some(tail_children) =
                            ctx.tail_children(list_info.handle, Self::TAIL_MESSAGE_LIMIT)
                        {
                            if ctx.last_children_truncated() {
                                truncated_tail = true;
                            }
                            let mut collected: Vec<CustomSurfaceNode> = Vec::new();
                            for child in tail_children.into_iter().rev() {
                                if collected.len() >= message_slots || !ctx.can_continue() {
                                    truncated_tail = true;
                                    break;
                                }
                                let Some(child_info) = ctx.inspect(child) else {
                                    continue;
                                };
                                if matches_wechat_id(
                                    child_info.identifier.as_deref(),
                                    "virtual_cell",
                                ) || has_zero_size(ctx, child)
                                {
                                    continue;
                                }
                                if child_info.role == "AXStaticText" {
                                    if collected.len() < message_slots
                                        && seen.insert(child_info.handle)
                                    {
                                        if let Some(body) = ctx.text(child_info.handle, None) {
                                            if !body.trim().is_empty() {
                                                collected.push(make_node(
                                                    ctx,
                                                    &mut focus_assigned,
                                                    &child_info,
                                                    Some(list_info.handle),
                                                    "text",
                                                    Some(body),
                                                ));
                                            }
                                        }
                                    }
                                } else if child_info.child_count > 0
                                    && !Self::is_skipped_container_role(&child_info.role)
                                {
                                    let before_unwrap = collected.len();
                                    if let Some(nested) = ctx.children(child, 0, 8) {
                                        for sub in nested.into_iter().rev() {
                                            if collected.len() >= message_slots
                                                || !ctx.can_continue()
                                            {
                                                truncated_tail = true;
                                                break;
                                            }
                                            let Some(sub_info) = ctx.inspect(sub) else {
                                                continue;
                                            };
                                            if matches_wechat_id(
                                                sub_info.identifier.as_deref(),
                                                "virtual_cell",
                                            ) || sub_info.role != "AXStaticText"
                                                || has_zero_size(ctx, sub)
                                            {
                                                continue;
                                            }
                                            if collected.len() < message_slots
                                                && seen.insert(sub_info.handle)
                                            {
                                                if let Some(body) = ctx.text(sub_info.handle, None)
                                                {
                                                    if !body.trim().is_empty() {
                                                        collected.push(make_node(
                                                            ctx,
                                                            &mut focus_assigned,
                                                            &sub_info,
                                                            Some(list_info.handle),
                                                            "text",
                                                            Some(body),
                                                        ));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    // Windows UIA ListItem (AXRow) fallback when row exposes message in Name.
                                    if collected.len() == before_unwrap
                                        && child_info.role == "AXRow"
                                        && collected.len() < message_slots
                                        && seen.insert(child_info.handle)
                                    {
                                        if let Some(label) = ctx.display_text(child_info.handle) {
                                            let trimmed = label.trim();
                                            if !trimmed.is_empty()
                                                && !is_private_use_only_text(trimmed)
                                            {
                                                collected.push(make_node(
                                                    ctx,
                                                    &mut focus_assigned,
                                                    &child_info,
                                                    Some(list_info.handle),
                                                    "text",
                                                    Some(trimmed.to_string()),
                                                ));
                                            }
                                        }
                                    }
                                } else if child_info.role == "AXRow"
                                    && collected.len() < message_slots
                                    && seen.insert(child_info.handle)
                                {
                                    // Leaf Windows UIA ListItem (AXRow) with message body directly in Name.
                                    if let Some(label) = ctx.display_text(child_info.handle) {
                                        let trimmed = label.trim();
                                        if !trimmed.is_empty()
                                            && !is_private_use_only_text(trimmed)
                                        {
                                            collected.push(make_node(
                                                ctx,
                                                &mut focus_assigned,
                                                &child_info,
                                                Some(list_info.handle),
                                                "text",
                                                Some(trimmed.to_string()),
                                            ));
                                        }
                                    }
                                }
                            }
                            nodes.extend(collected.into_iter().rev());
                        }
                    }
                }
            }
        }

        if let Some(ref inp) = input_info {
            if nodes.len() < max_nodes && seen.insert(inp.handle) {
                let draft = ctx.text(inp.handle, None);
                if draft.is_some() || ctx.has_inspected(inp.handle) {
                    nodes.push(make_node(
                        ctx,
                        &mut focus_assigned,
                        inp,
                        Some(root_handle),
                        "editable",
                        draft,
                    ));
                }
            }
        }

        if ctx.is_aborted() {
            return None;
        }
        Some(CustomSurfaceResult {
            nodes,
            complete: false,
            missing_reasons: if truncated_tail {
                vec!["tree-output-budget".to_string()]
            } else {
                Vec::new()
            },
        })
    }
}

// ============================================================================
// Custom FigmaAdapter (macOS + Windows 11 Electron Design & Slides parity)
// ============================================================================

pub struct FigmaAdapter;

impl FigmaAdapter {
    const MAX_SHELL_DEPTH: usize = 12;
    const MAX_SHELL_VISITS: usize = 64;
    const MAX_LANDMARK_DEPTH: usize = 12;
    const MAX_LANDMARK_VISITS: usize = 96;
    const MAX_ZONE_DEPTH: usize = 12;
    const MAX_TAB_DEPTH: usize = 10;
    const MAX_TAB_VISITS: usize = 64;
    const MAX_CANVAS_VISITS: usize = 80;
    const MAX_SIDEBAR_VISITS: usize = 120;

    const IGNORED_CHROME_ROLES: &'static [&'static str] = &[
        "AXToolbar",
        "AXMenuBar",
        "AXMenu",
        "AXMenuItem",
        "AXScrollBar",
        "AXSlider",
        "AXImage",
    ];

    const SHELL_SKIPPED_ROLES: &'static [&'static str] = &[
        "AXButton",
        "AXToolbar",
        "AXMenuBar",
        "AXMenu",
        "AXMenuItem",
        "AXScrollBar",
        "AXSlider",
        "AXStaticText",
        "AXTextField",
        "AXTextArea",
        "AXImage",
    ];

    const LANDMARK_LOCATOR_SKIPPED_ROLES: &'static [&'static str] = &[
        "AXButton",
        "AXToolbar",
        "AXMenuBar",
        "AXMenu",
        "AXMenuItem",
        "AXScrollBar",
        "AXSlider",
        "AXStaticText",
        "AXTextField",
        "AXTextArea",
        "AXComboBox",
        "AXCheckBox",
        "AXRadioButton",
        "AXTabButton",
        "AXTabGroup",
        "AXTable",
        "AXColumn",
        "AXOutline",
        "AXList",
        "AXImage",
        "AXHeading",
        "AXLink",
    ];

    const TAB_CHROME_NOISE: &'static [&'static str] = &[
        // macOS & shared Figma tab bar chrome
        "Close tab",
        "New file",
        "Open tabs and recently closed items",
        // Windows Electron titlebar chrome
        "Close",
        "Maximize",
        "Minimize",
        "Menu",
        "Restore",
    ];

    const RIGHT_SIDEBAR_CHROME_NOISE: &'static [&'static str] = &[
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
        "Start with an AI draft",
        "AI, Learn more",
    ];

    const LEFT_SIDEBAR_CHROME_NOISE: &'static [&'static str] = &[
        "Minimize UI",
        "Collapse layers",
        "Find",
        "Add new page",
        "Navigation Bar",
        "Resize handle",
        "Main menu",
        "Missing fonts",
        "Edit file menu",
        "New slide",
        "Add blank slide",
        "View mode",
        "Grid view",
        "Slide view",
    ];

    const LEFT_SIDEBAR_ITEM_ROLES: &'static [&'static str] = &[
        "AXRow",
        "AXCell",
        "AXStaticText",
        "AXHeading",
        "AXButton",
        "AXRadioButton",
        "AXTabButton",
        "AXTextField",
        "AXTextArea",
    ];

    fn is_ignored_chrome_role(role: &str) -> bool {
        Self::IGNORED_CHROME_ROLES.contains(&role)
    }

    fn is_shell_skipped_role(role: &str) -> bool {
        Self::SHELL_SKIPPED_ROLES.contains(&role)
    }

    fn is_landmark_skipped_role(role: &str) -> bool {
        Self::LANDMARK_LOCATOR_SKIPPED_ROLES.contains(&role)
    }

    fn is_tab_noise(label: &str) -> bool {
        Self::TAB_CHROME_NOISE.contains(&label)
    }

    fn is_right_sidebar_noise(label: &str) -> bool {
        Self::RIGHT_SIDEBAR_CHROME_NOISE.contains(&label)
    }

    fn is_left_sidebar_noise(label: &str) -> bool {
        Self::LEFT_SIDEBAR_CHROME_NOISE.contains(&label)
    }

    fn is_left_sidebar_item_role(role: &str) -> bool {
        Self::LEFT_SIDEBAR_ITEM_ROLES.contains(&role)
    }
}

struct FigmaEmitState {
    max_nodes: usize,
    focus_handle: Option<SurfaceHandle>,
    seen: HashSet<SurfaceHandle>,
    focus_assigned: bool,
    truncated: bool,
    nodes: Vec<CustomSurfaceNode>,
}

impl FigmaEmitState {
    fn make_node(
        &mut self,
        ctx: &mut dyn SafeSurfaceContext,
        info: &AdapterNodeInfo,
        parent: Option<SurfaceHandle>,
        role: &'static str,
        text: Option<String>,
    ) -> CustomSurfaceNode {
        let bounds = ctx.bounds(info.handle);
        let is_focused = !self.focus_assigned
            && self
                .focus_handle
                .map(|fh| fh == info.handle)
                .unwrap_or(info.is_focused);
        if is_focused {
            self.focus_assigned = true;
        }
        CustomSurfaceNode {
            handle: info.handle,
            parent,
            role,
            ax_role: Some(info.role.clone()),
            text,
            is_focused,
            observed_at_ms: info.observed_at_ms,
            bounds: bounds.map(|(b, _)| b),
            bounds_observed_at_ms: bounds.map(|(_, ts)| ts),
        }
    }

    fn has_zero_size(ctx: &mut dyn SafeSurfaceContext, handle: SurfaceHandle) -> bool {
        ctx.bounds(handle)
            .is_some_and(|(r, _)| r.width <= 0.0 || r.height <= 0.0)
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_canvas(
        &mut self,
        ctx: &mut dyn SafeSurfaceContext,
        parent_info: &AdapterNodeInfo,
        emitted_parent: SurfaceHandle,
        depth: usize,
        canvas_limit: usize,
        canvas_emitted: &mut usize,
        canvas_visits: &mut usize,
        canvas_visited: &mut HashSet<SurfaceHandle>,
    ) {
        if *canvas_emitted >= canvas_limit
            || self.nodes.len() >= self.max_nodes
            || *canvas_visits >= FigmaAdapter::MAX_CANVAS_VISITS
            || depth >= FigmaAdapter::MAX_ZONE_DEPTH
            || parent_info.child_count == 0
            || !ctx.can_continue()
            || ctx.is_aborted()
        {
            if parent_info.child_count > 0 && *canvas_emitted >= canvas_limit {
                self.truncated = true;
            }
            return;
        }
        let page_limit = 24usize;
        if parent_info.child_count > page_limit {
            self.truncated = true;
        }
        let Some(children) = ctx.children(parent_info.handle, 0, page_limit) else {
            return;
        };
        if ctx.last_children_truncated() {
            self.truncated = true;
        }
        for child in children {
            if *canvas_emitted >= canvas_limit || self.nodes.len() >= self.max_nodes {
                self.truncated = true;
                return;
            }
            if *canvas_visits >= FigmaAdapter::MAX_CANVAS_VISITS
                || !ctx.can_continue()
                || ctx.is_aborted()
            {
                return;
            }
            if !canvas_visited.insert(child) {
                continue;
            }
            *canvas_visits += 1;
            let Some(info) = ctx.inspect(child) else {
                continue;
            };
            if FigmaAdapter::is_ignored_chrome_role(&info.role) {
                continue;
            }
            let is_focus_node = self.focus_handle == Some(info.handle) || info.is_focused;
            // Prune offscreen / zero-size / negative-y / off-left non-focused canvas noise.
            if !is_focus_node {
                if info.is_offscreen {
                    continue;
                }
                if let Some((rect, _)) = ctx.bounds(info.handle) {
                    if rect.width <= 0.0
                        || rect.height <= 0.0
                        || rect.y < 0.0
                        || rect.x + rect.width <= 0.0
                    {
                        continue;
                    }
                }
            }
            if info.subrole.as_deref() == Some("AXApplicationGroup") {
                let label = ctx.display_text(info.handle);
                let mut next_parent = emitted_parent;
                if (label.is_some() || is_focus_node) && self.seen.insert(info.handle) {
                    let node =
                        self.make_node(ctx, &info, Some(emitted_parent), "container", label);
                    self.nodes.push(node);
                    *canvas_emitted += 1;
                    next_parent = info.handle;
                }
                if info.child_count > 0 {
                    self.walk_canvas(
                        ctx,
                        &info,
                        next_parent,
                        depth + 1,
                        canvas_limit,
                        canvas_emitted,
                        canvas_visits,
                        canvas_visited,
                    );
                }
            } else if info.role == "AXStaticText" {
                let Some(raw) = ctx.text(info.handle, None) else {
                    continue;
                };
                let trimmed = raw.trim();
                if trimmed.is_empty()
                    || is_private_use_only_text(trimmed)
                    || trimmed == "Dimensions"
                {
                    continue;
                }
                if self.seen.insert(info.handle) {
                    let node = self.make_node(
                        ctx,
                        &info,
                        Some(emitted_parent),
                        "text",
                        Some(trimmed.to_string()),
                    );
                    self.nodes.push(node);
                    *canvas_emitted += 1;
                }
            } else if matches!(info.role.as_str(), "AXTextField" | "AXTextArea") {
                let Some(raw) = ctx.text(info.handle, None) else {
                    continue;
                };
                let trimmed = raw.trim();
                if !is_focus_node && (trimmed.is_empty() || is_private_use_only_text(trimmed)) {
                    continue;
                }
                if self.seen.insert(info.handle) {
                    let node =
                        self.make_node(ctx, &info, Some(emitted_parent), "editable", Some(raw));
                    self.nodes.push(node);
                    *canvas_emitted += 1;
                }
            } else if info.role == "AXHeading" {
                if let Some(label) = ctx.display_text(info.handle) {
                    if !is_private_use_only_text(&label)
                        && label != "Dimensions"
                        && self.seen.insert(info.handle)
                    {
                        let node =
                            self.make_node(ctx, &info, Some(emitted_parent), "text", Some(label));
                        self.nodes.push(node);
                        *canvas_emitted += 1;
                        continue;
                    }
                }
                if info.child_count > 0 {
                    self.walk_canvas(
                        ctx,
                        &info,
                        emitted_parent,
                        depth + 1,
                        canvas_limit,
                        canvas_emitted,
                        canvas_visits,
                        canvas_visited,
                    );
                }
            } else if info.child_count > 0 {
                self.walk_canvas(
                    ctx,
                    &info,
                    emitted_parent,
                    depth + 1,
                    canvas_limit,
                    canvas_emitted,
                    canvas_visits,
                    canvas_visited,
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_right_sidebar(
        &mut self,
        ctx: &mut dyn SafeSurfaceContext,
        parent_info: &AdapterNodeInfo,
        emitted_parent: SurfaceHandle,
        parent_text: Option<&str>,
        depth: usize,
        right_limit: usize,
        right_emitted: &mut usize,
        right_visits: &mut usize,
        right_visited: &mut HashSet<SurfaceHandle>,
    ) {
        if *right_emitted >= right_limit
            || self.nodes.len() >= self.max_nodes
            || *right_visits >= FigmaAdapter::MAX_SIDEBAR_VISITS
            || depth >= FigmaAdapter::MAX_ZONE_DEPTH
            || parent_info.child_count == 0
            || !ctx.can_continue()
            || ctx.is_aborted()
        {
            if parent_info.child_count > 0 && *right_emitted >= right_limit {
                self.truncated = true;
            }
            return;
        }
        let page_limit = 24usize;
        if parent_info.child_count > page_limit {
            self.truncated = true;
        }
        let Some(children) = ctx.children(parent_info.handle, 0, page_limit) else {
            return;
        };
        if ctx.last_children_truncated() {
            self.truncated = true;
        }
        for child in children {
            if *right_emitted >= right_limit || self.nodes.len() >= self.max_nodes {
                self.truncated = true;
                return;
            }
            if *right_visits >= FigmaAdapter::MAX_SIDEBAR_VISITS
                || !ctx.can_continue()
                || ctx.is_aborted()
            {
                return;
            }
            if !right_visited.insert(child) {
                continue;
            }
            *right_visits += 1;
            let Some(info) = ctx.inspect(child) else {
                continue;
            };
            if FigmaAdapter::is_ignored_chrome_role(&info.role)
                || Self::has_zero_size(ctx, info.handle)
            {
                continue;
            }
            if info
                .label
                .as_deref()
                .is_some_and(FigmaAdapter::is_right_sidebar_noise)
            {
                continue;
            }
            let is_focus_node = self.focus_handle == Some(info.handle) || info.is_focused;
            match info.role.as_str() {
                "AXRadioButton" | "AXTabButton" | "AXButton" | "AXCheckBox" => {
                    if let Some(label) = ctx.display_text(info.handle) {
                        if !is_private_use_only_text(&label)
                            && !FigmaAdapter::is_right_sidebar_noise(&label)
                        {
                            if self.seen.insert(info.handle) {
                                let node = self.make_node(
                                    ctx,
                                    &info,
                                    Some(emitted_parent),
                                    "container",
                                    Some(label),
                                );
                                self.nodes.push(node);
                                *right_emitted += 1;
                            }
                            continue;
                        }
                    }
                    if info.child_count > 0 {
                        self.walk_right_sidebar(
                            ctx,
                            &info,
                            emitted_parent,
                            parent_text,
                            depth + 1,
                            right_limit,
                            right_emitted,
                            right_visits,
                            right_visited,
                        );
                    }
                }
                "AXHeading" => {
                    if let Some(label) = ctx.display_text(info.handle) {
                        if !is_private_use_only_text(&label)
                            && !FigmaAdapter::is_right_sidebar_noise(&label)
                        {
                            if self.seen.insert(info.handle) {
                                let node = self.make_node(
                                    ctx,
                                    &info,
                                    Some(emitted_parent),
                                    "text",
                                    Some(label),
                                );
                                self.nodes.push(node);
                                *right_emitted += 1;
                            }
                            continue;
                        }
                    }
                    if info.child_count > 0 {
                        self.walk_right_sidebar(
                            ctx,
                            &info,
                            emitted_parent,
                            parent_text,
                            depth + 1,
                            right_limit,
                            right_emitted,
                            right_visits,
                            right_visited,
                        );
                    }
                }
                "AXComboBox" | "AXPopUpButton" => {
                    let mut next_parent = emitted_parent;
                    let mut next_parent_text: Option<String> = parent_text.map(str::to_string);
                    if let Some(label) = ctx.display_text(info.handle) {
                        if !is_private_use_only_text(&label)
                            && !FigmaAdapter::is_right_sidebar_noise(&label)
                            && self.seen.insert(info.handle)
                        {
                            let node = self.make_node(
                                ctx,
                                &info,
                                Some(emitted_parent),
                                "container",
                                Some(label.clone()),
                            );
                            self.nodes.push(node);
                            *right_emitted += 1;
                            next_parent = info.handle;
                            next_parent_text = Some(label);
                        }
                    }
                    if info.child_count > 0 {
                        self.walk_right_sidebar(
                            ctx,
                            &info,
                            next_parent,
                            next_parent_text.as_deref(),
                            depth + 1,
                            right_limit,
                            right_emitted,
                            right_visits,
                            right_visited,
                        );
                    }
                }
                "AXTextField" | "AXTextArea" => {
                    let Some(raw) = ctx.text(info.handle, None) else {
                        continue;
                    };
                    let trimmed = raw.trim();
                    if !is_focus_node
                        && (trimmed.is_empty() || is_private_use_only_text(trimmed))
                    {
                        continue;
                    }
                    if self.seen.insert(info.handle) {
                        let node = self.make_node(
                            ctx,
                            &info,
                            Some(emitted_parent),
                            "editable",
                            Some(raw),
                        );
                        self.nodes.push(node);
                        *right_emitted += 1;
                    }
                }
                "AXStaticText" => {
                    let Some(raw) = ctx.text(info.handle, None) else {
                        continue;
                    };
                    let trimmed = raw.trim();
                    if trimmed.is_empty()
                        || is_private_use_only_text(trimmed)
                        || FigmaAdapter::is_right_sidebar_noise(trimmed)
                        || Some(trimmed) == parent_text
                    {
                        continue;
                    }
                    if self.seen.insert(info.handle) {
                        let node = self.make_node(
                            ctx,
                            &info,
                            Some(emitted_parent),
                            "text",
                            Some(trimmed.to_string()),
                        );
                        self.nodes.push(node);
                        *right_emitted += 1;
                    }
                }
                _ => {
                    if info.child_count > 0 {
                        self.walk_right_sidebar(
                            ctx,
                            &info,
                            emitted_parent,
                            parent_text,
                            depth + 1,
                            right_limit,
                            right_emitted,
                            right_visits,
                            right_visited,
                        );
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_left_sidebar(
        &mut self,
        ctx: &mut dyn SafeSurfaceContext,
        parent_info: &AdapterNodeInfo,
        left_sidebar_handle: SurfaceHandle,
        left_sidebar_bounds: Option<SurfaceBounds>,
        window_height: f64,
        depth: usize,
        left_visits: &mut usize,
        left_visited: &mut HashSet<SurfaceHandle>,
    ) {
        if self.nodes.len() >= self.max_nodes
            || *left_visits >= FigmaAdapter::MAX_SIDEBAR_VISITS
            || depth >= FigmaAdapter::MAX_ZONE_DEPTH
            || parent_info.child_count == 0
            || !ctx.can_continue()
            || ctx.is_aborted()
        {
            if parent_info.child_count > 0 && self.nodes.len() >= self.max_nodes {
                self.truncated = true;
            }
            return;
        }
        let page_cap = if matches!(
            parent_info.role.as_str(),
            "AXColumn" | "AXTable" | "AXOutline" | "AXList"
        ) {
            64usize
        } else {
            24usize
        };
        if parent_info.child_count > page_cap {
            self.truncated = true;
        }
        let Some(children) = ctx.children(parent_info.handle, 0, page_cap) else {
            return;
        };
        if ctx.last_children_truncated() {
            self.truncated = true;
        }
        for child in children {
            if self.nodes.len() >= self.max_nodes {
                self.truncated = true;
                return;
            }
            if *left_visits >= FigmaAdapter::MAX_SIDEBAR_VISITS
                || !ctx.can_continue()
                || ctx.is_aborted()
            {
                return;
            }
            if !left_visited.insert(child) {
                continue;
            }
            *left_visits += 1;
            let Some(info) = ctx.inspect(child) else {
                continue;
            };
            if FigmaAdapter::is_ignored_chrome_role(&info.role) {
                continue;
            }
            if info
                .label
                .as_deref()
                .is_some_and(FigmaAdapter::is_left_sidebar_noise)
            {
                continue;
            }
            let is_item = FigmaAdapter::is_left_sidebar_item_role(&info.role);
            if !Self::is_visible_in_left_sidebar(
                ctx,
                &info,
                !is_item,
                left_sidebar_bounds,
                window_height,
            ) {
                continue;
            }
            let is_focus_node = self.focus_handle == Some(info.handle) || info.is_focused;
            match info.role.as_str() {
                "AXRow" | "AXCell" | "AXRadioButton" | "AXTabButton" | "AXButton" => {
                    if let Some(label) = ctx.display_text(info.handle) {
                        if !is_private_use_only_text(&label)
                            && !FigmaAdapter::is_left_sidebar_noise(&label)
                        {
                            if self.seen.insert(info.handle) {
                                let node = self.make_node(
                                    ctx,
                                    &info,
                                    Some(left_sidebar_handle),
                                    "container",
                                    Some(label),
                                );
                                self.nodes.push(node);
                            }
                            continue;
                        }
                    }
                    if info.child_count > 0 {
                        self.walk_left_sidebar(
                            ctx,
                            &info,
                            left_sidebar_handle,
                            left_sidebar_bounds,
                            window_height,
                            depth + 1,
                            left_visits,
                            left_visited,
                        );
                    }
                }
                "AXHeading" => {
                    if let Some(label) = ctx.display_text(info.handle) {
                        if !is_private_use_only_text(&label)
                            && !FigmaAdapter::is_left_sidebar_noise(&label)
                        {
                            if self.seen.insert(info.handle) {
                                let node = self.make_node(
                                    ctx,
                                    &info,
                                    Some(left_sidebar_handle),
                                    "text",
                                    Some(label),
                                );
                                self.nodes.push(node);
                            }
                            continue;
                        }
                    }
                    if info.child_count > 0 {
                        self.walk_left_sidebar(
                            ctx,
                            &info,
                            left_sidebar_handle,
                            left_sidebar_bounds,
                            window_height,
                            depth + 1,
                            left_visits,
                            left_visited,
                        );
                    }
                }
                "AXTextField" | "AXTextArea" => {
                    let Some(raw) = ctx.text(info.handle, None) else {
                        continue;
                    };
                    let trimmed = raw.trim();
                    if !is_focus_node
                        && (trimmed.is_empty() || is_private_use_only_text(trimmed))
                    {
                        continue;
                    }
                    if self.seen.insert(info.handle) {
                        let node = self.make_node(
                            ctx,
                            &info,
                            Some(left_sidebar_handle),
                            "editable",
                            Some(raw),
                        );
                        self.nodes.push(node);
                    }
                }
                "AXStaticText" => {
                    let Some(raw) = ctx.text(info.handle, None) else {
                        continue;
                    };
                    let trimmed = raw.trim();
                    if trimmed.is_empty()
                        || is_private_use_only_text(trimmed)
                        || FigmaAdapter::is_left_sidebar_noise(trimmed)
                    {
                        continue;
                    }
                    if self.seen.insert(info.handle) {
                        let node = self.make_node(
                            ctx,
                            &info,
                            Some(left_sidebar_handle),
                            "text",
                            Some(trimmed.to_string()),
                        );
                        self.nodes.push(node);
                    }
                }
                _ => {
                    if info.child_count > 0 {
                        self.walk_left_sidebar(
                            ctx,
                            &info,
                            left_sidebar_handle,
                            left_sidebar_bounds,
                            window_height,
                            depth + 1,
                            left_visits,
                            left_visited,
                        );
                    }
                }
            }
        }
    }

    fn is_visible_in_left_sidebar(
        ctx: &mut dyn SafeSurfaceContext,
        info: &AdapterNodeInfo,
        is_container: bool,
        left_sidebar_bounds: Option<SurfaceBounds>,
        window_height: f64,
    ) -> bool {
        if info.is_offscreen {
            return false;
        }
        let Some((rect, _)) = ctx.bounds(info.handle) else {
            return true;
        };
        if rect.width <= 0.0 || rect.height <= 1.0 {
            return false;
        }
        if window_height > 0.0 && rect.y >= window_height {
            return false;
        }
        if let Some(sb) = left_sidebar_bounds {
            if rect.y >= sb.y + sb.height {
                return false;
            }
        }
        if is_container {
            rect.y + rect.height > 0.0
        } else {
            rect.y >= 0.0
        }
    }
}

impl AppAdapter for FigmaAdapter {
    fn spec(&self) -> &'static AppAdapterSpec {
        &FIGMA_ADAPTER_SPEC
    }

    fn extract_surface(&self, ctx: &mut dyn SafeSurfaceContext) -> Option<CustomSurfaceResult> {
        let root_handle = ctx.root();
        let root_info = ctx.inspect(root_handle)?;
        if ctx.is_aborted() {
            return None;
        }

        // Step 1: Shallow BFS through outer Electron shell to locate Tab Bar and Main Document AXWebAreas.
        let mut web_areas: Vec<AdapterNodeInfo> = Vec::new();
        let mut shell_queue: VecDeque<(SurfaceHandle, usize)> = VecDeque::new();
        shell_queue.push_back((root_handle, 0));
        let mut shell_visited: HashSet<SurfaceHandle> = HashSet::new();
        shell_visited.insert(root_handle);
        let mut shell_visits = 1usize;
        let mut early_exit_depth: Option<usize> = None;

        while let Some((handle, depth)) = shell_queue.pop_front() {
            if early_exit_depth.is_some_and(|done_depth| depth > done_depth)
                || shell_visits >= Self::MAX_SHELL_VISITS
                || !ctx.can_continue()
                || ctx.is_aborted()
            {
                break;
            }
            let info = if handle == root_handle {
                root_info.clone()
            } else {
                shell_visits += 1;
                let Some(fresh) = ctx.inspect(handle) else {
                    continue;
                };
                fresh
            };
            if info.role == "AXWebArea" {
                web_areas.push(info);
                if early_exit_depth.is_none() && web_areas.len() >= 2 {
                    let mut has_tab = false;
                    let mut has_main = false;
                    for area in &web_areas {
                        let is_populated_labeled = area.child_count > 0
                            && area
                                .label
                                .as_deref()
                                .is_some_and(|s| !s.trim().is_empty());
                        if let Some((rect, _)) = ctx.bounds(area.handle) {
                            if rect.height > 0.0 {
                                if rect.height <= 60.0 && rect.y < 60.0 {
                                    has_tab = true;
                                } else if rect.height > 100.0 && is_populated_labeled {
                                    has_main = true;
                                }
                            }
                        } else if area.label.as_deref() == Some("Figma") {
                            has_tab = true;
                        } else if is_populated_labeled {
                            has_main = true;
                        }
                    }
                    if has_tab && has_main {
                        early_exit_depth = Some(depth);
                    }
                }
                continue;
            }
            if early_exit_depth.is_some() {
                continue;
            }
            if handle != root_handle && Self::is_shell_skipped_role(&info.role) {
                continue;
            }
            if depth >= Self::MAX_SHELL_DEPTH || info.child_count == 0 {
                continue;
            }
            if let Some(children) = ctx.children(handle, 0, 32) {
                for child in children {
                    if shell_visited.insert(child) {
                        shell_queue.push_back((child, depth + 1));
                    }
                }
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        let mut tab_bar_web_area: Option<AdapterNodeInfo> = None;
        let mut raw_main_candidates: Vec<(AdapterNodeInfo, f64)> = Vec::new();

        for area in &web_areas {
            if let Some((rect, _)) = ctx.bounds(area.handle) {
                if rect.width > 0.0 && rect.height > 0.0 {
                    if rect.height <= 60.0 && rect.y < 60.0 {
                        if tab_bar_web_area
                            .as_ref()
                            .is_none_or(|prev| prev.child_count == 0 && area.child_count > 0)
                        {
                            tab_bar_web_area = Some(area.clone());
                        }
                    } else {
                        let area_size = rect.width * rect.height;
                        raw_main_candidates.push((area.clone(), area_size));
                    }
                    continue;
                }
            }
            if area.label.as_deref() == Some("Figma") {
                if tab_bar_web_area
                    .as_ref()
                    .is_none_or(|prev| prev.child_count == 0 && area.child_count > 0)
                {
                    tab_bar_web_area = Some(area.clone());
                }
            } else {
                raw_main_candidates.push((area.clone(), -1.0));
            }
        }
        if raw_main_candidates.is_empty() && web_areas.len() == 1 {
            if let Some(only) = web_areas.into_iter().next() {
                raw_main_candidates.push((only, 0.0));
            }
            tab_bar_web_area = None;
        }
        let has_populated_candidate = raw_main_candidates
            .iter()
            .any(|(area, _)| area.child_count > 0);
        let mut main_candidates: Vec<(AdapterNodeInfo, f64)> = if has_populated_candidate {
            raw_main_candidates
                .into_iter()
                .filter(|(area, _)| area.child_count > 0)
                .collect()
        } else {
            raw_main_candidates
        };
        if main_candidates.is_empty() {
            return None;
        }
        main_candidates.sort_by(|(a_info, a_area), (b_info, b_area)| {
            let a_key = (
                a_info.child_count > 0,
                a_info
                    .label
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty()),
            );
            let b_key = (
                b_info.child_count > 0,
                b_info
                    .label
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty()),
            );
            b_key.cmp(&a_key).then_with(|| b_area.total_cmp(a_area))
        });

        // Step 2: Bounded locator BFS inside ranked Main AXWebArea candidates to find
        // Canvas (`AXLandmarkMain`), Right Inspector, and Left Sidebar landmarks/containers.
        struct SelectedMainWebArea {
            main_web_area: AdapterNodeInfo,
            landmark_main: AdapterNodeInfo,
            right_sidebar: Option<AdapterNodeInfo>,
            left_sidebar: Option<AdapterNodeInfo>,
            lm_parents: HashMap<SurfaceHandle, SurfaceHandle>,
            geo_candidates: Vec<(AdapterNodeInfo, usize)>,
        }

        let mut selected: Option<SelectedMainWebArea> = None;

        for (candidate, _) in main_candidates {
            if !ctx.can_continue() || ctx.is_aborted() {
                break;
            }
            let mut landmark_main: Option<AdapterNodeInfo> = None;
            let mut right_sidebar: Option<AdapterNodeInfo> = None;
            let mut left_sidebar: Option<AdapterNodeInfo> = None;

            let mut lm_queue: VecDeque<(SurfaceHandle, usize)> = VecDeque::new();
            lm_queue.push_back((candidate.handle, 0));
            let mut lm_visited: HashSet<SurfaceHandle> = HashSet::new();
            lm_visited.insert(candidate.handle);
            let mut lm_parents: HashMap<SurfaceHandle, SurfaceHandle> = HashMap::new();
            let mut geo_candidates: Vec<(AdapterNodeInfo, usize)> = Vec::new();
            let mut lm_visits = 1usize;

            while let Some((handle, depth)) = lm_queue.pop_front() {
                if lm_visits >= Self::MAX_LANDMARK_VISITS
                    || !ctx.can_continue()
                    || ctx.is_aborted()
                    || (landmark_main.is_some()
                        && right_sidebar.is_some()
                        && left_sidebar.is_some())
                {
                    break;
                }
                let info = if handle == candidate.handle {
                    candidate.clone()
                } else {
                    lm_visits += 1;
                    let Some(fresh) = ctx.inspect(handle) else {
                        continue;
                    };
                    fresh
                };
                if handle != candidate.handle {
                    if info.subrole.as_deref() == Some("AXLandmarkMain") {
                        landmark_main = Some(info);
                        continue;
                    }
                    if matches!(
                        info.subrole.as_deref(),
                        Some("AXLandmarkRegion" | "AXApplicationGroup") | None
                    ) {
                        if let Some(ref lbl) = info.label {
                            let lowered = lbl.to_ascii_lowercase();
                            if lowered == "right sidebar" {
                                right_sidebar = Some(info);
                                continue;
                            }
                            if lowered == "left sidebar" {
                                left_sidebar = Some(info);
                                continue;
                            }
                        }
                    }
                    if Self::is_landmark_skipped_role(&info.role) {
                        continue;
                    }
                    if info.child_count > 0 {
                        geo_candidates.push((info.clone(), depth));
                    }
                }
                if depth >= Self::MAX_LANDMARK_DEPTH || info.child_count == 0 {
                    continue;
                }
                if let Some(children) = ctx.children(handle, 0, 32) {
                    for child in children {
                        if lm_visited.insert(child) {
                            lm_parents.insert(child, handle);
                            lm_queue.push_back((child, depth + 1));
                        }
                    }
                }
            }
            if ctx.is_aborted() {
                return None;
            }
            if let Some(lm) = landmark_main {
                selected = Some(SelectedMainWebArea {
                    main_web_area: candidate,
                    landmark_main: lm,
                    right_sidebar,
                    left_sidebar,
                    lm_parents,
                    geo_candidates,
                });
                break;
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        // Fall back to standard weighted traversal on Home / Recents / File Browser screens without canvas.
        let SelectedMainWebArea {
            main_web_area,
            landmark_main,
            mut right_sidebar,
            mut left_sidebar,
            lm_parents,
            geo_candidates,
        } = selected?;

        // Geometric fallback for Windows Electron sidebars lacking explicit "Right/Left sidebar" ARIA label.
        if right_sidebar.is_none() || left_sidebar.is_none() {
            let mut main_ancestors: HashSet<SurfaceHandle> = HashSet::new();
            let mut cur = Some(landmark_main.handle);
            while let Some(h) = cur {
                main_ancestors.insert(h);
                cur = lm_parents.get(&h).copied();
            }
            let win_width = ctx
                .window_size()
                .map(|(w, _)| w)
                .or_else(|| ctx.bounds(main_web_area.handle).map(|(r, _)| r.x + r.width));
            let main_rect = ctx.bounds(landmark_main.handle).map(|(r, _)| r);

            let mut best_right: Option<(AdapterNodeInfo, usize, f64)> = None;
            let mut best_left: Option<(AdapterNodeInfo, usize, f64)> = None;

            for (cand, depth) in geo_candidates {
                if main_ancestors.contains(&cand.handle) {
                    continue;
                }
                let Some((rect, _)) = ctx.bounds(cand.handle) else {
                    continue;
                };
                if rect.width <= 80.0 || rect.width > 420.0 || rect.height <= 200.0 {
                    continue;
                }
                let area = rect.width * rect.height;
                if right_sidebar.is_none() {
                    let on_right = win_width.is_some_and(|ww| rect.x > ww - 320.0)
                        && main_rect.is_none_or(|mr| rect.x >= mr.x + mr.width - 24.0);
                    if on_right
                        && best_right
                            .as_ref()
                            .is_none_or(|(_, d, a)| depth < *d || (depth == *d && area > *a))
                    {
                        best_right = Some((cand.clone(), depth, area));
                    }
                }
                if left_sidebar.is_none() {
                    let on_left = rect.x >= -8.0
                        && rect.x < 320.0
                        && (rect.x + rect.width) <= 420.0
                        && main_rect.is_none_or(|mr| rect.x + rect.width <= mr.x + 24.0);
                    if on_left
                        && best_left
                            .as_ref()
                            .is_none_or(|(_, d, a)| depth < *d || (depth == *d && area > *a))
                    {
                        best_left = Some((cand, depth, area));
                    }
                }
            }
            if right_sidebar.is_none() {
                right_sidebar = best_right.map(|(info, _, _)| info);
            }
            if left_sidebar.is_none() {
                left_sidebar = best_left.map(|(info, _, _)| info);
            }
        }

        // Step 3: Emit four prioritized zones within max_nodes.
        let max_nodes = ctx.max_output_nodes().clamp(1, 96);
        let mut emit = FigmaEmitState {
            max_nodes,
            focus_handle: ctx.focus(),
            seen: HashSet::new(),
            focus_assigned: false,
            truncated: false,
            nodes: Vec::new(),
        };

        // Zone 1: Root + Main AXWebArea (title + URL) + Open File Tabs.
        emit.seen.insert(root_handle);
        let root_text = if main_web_area.handle == root_handle {
            ctx.display_text(main_web_area.handle)
        } else {
            None
        };
        let root_node = emit.make_node(ctx, &root_info, None, "container", root_text);
        emit.nodes.push(root_node);

        if main_web_area.handle != root_handle
            && emit.nodes.len() < max_nodes
            && emit.seen.insert(main_web_area.handle)
        {
            let main_text = ctx.display_text(main_web_area.handle);
            let main_node =
                emit.make_node(ctx, &main_web_area, Some(root_handle), "container", main_text);
            emit.nodes.push(main_node);
        }

        if let Some(ref tab_bar) = tab_bar_web_area {
            if tab_bar.handle != root_handle
                && tab_bar.handle != main_web_area.handle
                && emit.nodes.len() + 2 <= max_nodes
                && ctx.can_continue()
                && !ctx.is_aborted()
            {
                let max_tab_items = max_nodes
                    .saturating_sub(emit.nodes.len() + 1)
                    .clamp(1, 10);
                let mut collected_tabs: Vec<(AdapterNodeInfo, String)> = Vec::new();
                let mut tab_queue: VecDeque<(SurfaceHandle, usize)> = VecDeque::new();
                tab_queue.push_back((tab_bar.handle, 0));
                let mut tab_visited: HashSet<SurfaceHandle> = HashSet::new();
                tab_visited.insert(tab_bar.handle);
                let mut tab_visits = 1usize;

                while let Some((handle, depth)) = tab_queue.pop_front() {
                    if tab_visits >= Self::MAX_TAB_VISITS
                        || collected_tabs.len() >= max_tab_items
                        || !ctx.can_continue()
                        || ctx.is_aborted()
                    {
                        break;
                    }
                    let info = if handle == tab_bar.handle {
                        tab_bar.clone()
                    } else {
                        tab_visits += 1;
                        let Some(fresh) = ctx.inspect(handle) else {
                            continue;
                        };
                        if Self::is_ignored_chrome_role(&fresh.role) {
                            continue;
                        }
                        fresh
                    };
                    if matches!(info.role.as_str(), "AXRadioButton" | "AXTabButton") {
                        // Prune zero-size leaf tabs only; Windows Electron wraps the visible 38pt
                        // tab strip inside a 0x0 CSS layout AXGroup that must still be traversed.
                        if FigmaEmitState::has_zero_size(ctx, info.handle) {
                            continue;
                        }
                        let mut tab_label = ctx.display_text(info.handle);
                        if tab_label.is_none() && info.child_count > 0 {
                            if let Some(tab_children) = ctx.children(info.handle, 0, 4) {
                                for child in tab_children {
                                    if !ctx.can_continue() || ctx.is_aborted() {
                                        break;
                                    }
                                    if let Some(child_info) = ctx.inspect(child) {
                                        if child_info.role == "AXStaticText" {
                                            if let Some(raw) = ctx.text(child, None) {
                                                let trimmed = raw.trim();
                                                if !trimmed.is_empty()
                                                    && !is_private_use_only_text(trimmed)
                                                {
                                                    tab_label = Some(trimmed.to_string());
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(label) = tab_label {
                            if !label.is_empty()
                                && !is_private_use_only_text(&label)
                                && !Self::is_tab_noise(&label)
                            {
                                collected_tabs.push((info, label));
                            }
                        }
                        continue;
                    }
                    if depth >= Self::MAX_TAB_DEPTH
                        || info.child_count == 0
                        || matches!(
                            info.role.as_str(),
                            "AXButton" | "AXStaticText" | "AXTextField" | "AXTextArea"
                        )
                    {
                        continue;
                    }
                    if let Some(children) = ctx.children(handle, 0, 24) {
                        for child in children {
                            if tab_visited.insert(child) {
                                tab_queue.push_back((child, depth + 1));
                            }
                        }
                    }
                }

                if !collected_tabs.is_empty()
                    && emit.nodes.len() < max_nodes
                    && emit.seen.insert(tab_bar.handle)
                {
                    let tab_bar_text = ctx.display_text(tab_bar.handle);
                    let tab_bar_node = emit.make_node(
                        ctx,
                        tab_bar,
                        Some(root_handle),
                        "container",
                        tab_bar_text,
                    );
                    emit.nodes.push(tab_bar_node);
                    for (tab_info, tab_text) in collected_tabs {
                        if emit.nodes.len() >= max_nodes {
                            break;
                        }
                        if emit.seen.insert(tab_info.handle) {
                            let tab_node = emit.make_node(
                                ctx,
                                &tab_info,
                                Some(tab_bar.handle),
                                "container",
                                Some(tab_text),
                            );
                            emit.nodes.push(tab_node);
                        }
                    }
                }
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        // Proportional slot reservation so Right Inspector and Left Sidebar are never starved.
        let remaining_after_header = max_nodes.saturating_sub(emit.nodes.len());
        let has_right = right_sidebar.is_some();
        let has_left = left_sidebar.is_some();
        let reserve_pool = remaining_after_header.saturating_sub(1);
        let desired_right = if has_right {
            (remaining_after_header * 45 / 100).clamp(18, 24)
        } else {
            0
        };
        let desired_left = if has_left {
            (remaining_after_header * 25 / 100).clamp(8, 18)
        } else {
            0
        };
        let (right_reserve, left_reserve) = if desired_right + desired_left <= reserve_pool {
            (desired_right, desired_left)
        } else if reserve_pool == 0 {
            (0, 0)
        } else {
            let rr = if has_right {
                (reserve_pool * 2 / 3).max(1)
            } else {
                0
            };
            let lr = if has_left {
                reserve_pool.saturating_sub(rr)
            } else {
                0
            };
            (rr, lr)
        };
        let canvas_limit = remaining_after_header.saturating_sub(right_reserve + left_reserve);

        // Zone 2: Selected Canvas / Slides Hierarchy (`AXLandmarkMain`).
        if canvas_limit > 0
            && emit.nodes.len() < max_nodes
            && emit.seen.insert(landmark_main.handle)
        {
            let lm_text = ctx.display_text(landmark_main.handle);
            let lm_node = emit.make_node(
                ctx,
                &landmark_main,
                Some(main_web_area.handle),
                "container",
                lm_text,
            );
            emit.nodes.push(lm_node);
            let mut canvas_emitted = 1usize;
            let mut canvas_visits = 0usize;
            let mut canvas_visited: HashSet<SurfaceHandle> = HashSet::new();
            canvas_visited.insert(landmark_main.handle);
            emit.walk_canvas(
                ctx,
                &landmark_main,
                landmark_main.handle,
                0,
                canvas_limit,
                &mut canvas_emitted,
                &mut canvas_visits,
                &mut canvas_visited,
            );
        }
        if ctx.is_aborted() {
            return None;
        }

        // Zone 3: Right Design/Prototype/Animate Inspector.
        if let Some(ref right_sb) = right_sidebar {
            if emit.nodes.len() < max_nodes && ctx.can_continue() {
                let remaining_for_right = max_nodes.saturating_sub(emit.nodes.len() + left_reserve);
                let right_limit = if has_left {
                    right_reserve.max(28).min(remaining_for_right)
                } else {
                    max_nodes.saturating_sub(emit.nodes.len())
                };
                if right_limit > 0 && emit.seen.insert(right_sb.handle) {
                    let rs_text = ctx.display_text(right_sb.handle);
                    let rs_node = emit.make_node(
                        ctx,
                        right_sb,
                        Some(main_web_area.handle),
                        "container",
                        rs_text,
                    );
                    emit.nodes.push(rs_node);
                    let mut right_emitted = 1usize;
                    let mut right_visits = 0usize;
                    let mut right_visited: HashSet<SurfaceHandle> = HashSet::new();
                    right_visited.insert(right_sb.handle);
                    emit.walk_right_sidebar(
                        ctx,
                        right_sb,
                        right_sb.handle,
                        None,
                        0,
                        right_limit,
                        &mut right_emitted,
                        &mut right_visits,
                        &mut right_visited,
                    );
                }
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        // Zone 4: Left Sidebar (visible file header + strictly viewport-clipped Pages / Layers / Slides).
        if let Some(ref left_sb) = left_sidebar {
            if emit.nodes.len() < max_nodes && ctx.can_continue() && emit.seen.insert(left_sb.handle)
            {
                let left_sb_bounds = ctx.bounds(left_sb.handle).map(|(b, _)| b);
                let window_height = ctx.window_size().map(|(_, h)| h).unwrap_or(0.0);
                let ls_text = ctx.display_text(left_sb.handle);
                let ls_node = emit.make_node(
                    ctx,
                    left_sb,
                    Some(main_web_area.handle),
                    "container",
                    ls_text,
                );
                emit.nodes.push(ls_node);
                let mut left_visits = 0usize;
                let mut left_visited: HashSet<SurfaceHandle> = HashSet::new();
                left_visited.insert(left_sb.handle);
                emit.walk_left_sidebar(
                    ctx,
                    left_sb,
                    left_sb.handle,
                    left_sb_bounds,
                    window_height,
                    0,
                    &mut left_visits,
                    &mut left_visited,
                );
            }
        }
        if ctx.is_aborted() {
            return None;
        }

        Some(CustomSurfaceResult {
            nodes: emit.nodes,
            complete: false,
            missing_reasons: if emit.truncated {
                vec!["tree-output-budget".to_string()]
            } else {
                Vec::new()
            },
        })
    }
}

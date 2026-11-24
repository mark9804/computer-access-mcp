//! Kernel-enforced `SafeSurfaceContext` implementation (`KernelSurfaceContext`),
//! `validate_custom_result`, and `SurfaceCaptureRunner`.
//!
//! All internal security, privacy, and `ReadBudget` state fields and helper methods of
//! `KernelSurfaceContext` are strictly module-private inside this module. Custom adapters
//! interact exclusively through `&mut dyn SafeSurfaceContext` and never import `kernel`.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};

use access_contract::utf16_len;

use super::{
    AdapterNodeInfo, AppAdapter, AppAdapterSpec, CustomSurfaceNode, CustomSurfaceResult,
    SafeDisplayText, SafeSurfaceContext, StaticTextPolicy, SurfaceHandle,
};
use crate::policy::{
    is_private_use_only_text, ApplicationPolicy, BrowserGate, ProtectedContentRead, ReadBudget,
    ResolvedAppIdentity, SubroleRead, TextSecurityGate,
};
use crate::protocol_model::{
    bounded_utf16_slice, CapturePolicy, CollectorClock, SecureStatus, SurfaceAbsoluteRect,
    SurfaceBounds, SurfaceGeometry, SurfaceNode, SurfaceReadFailure, MAX_SAFE_INTEGER,
};
use crate::uia_traversal::{
    SurfaceFocusAnchorPlan, SurfaceFocusAnchors, WeightedSurfaceChildrenRead,
    WeightedSurfaceInspection, WeightedSurfaceMetadata, WeightedSurfaceTextRead,
    WeightedSurfaceTraversal, WeightedSurfaceTraversalLimits, WeightedSurfaceTraversalReason,
};
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
    /// Unfocused pure-PUA `AXStaticText` preserved solely so `WeightedSurfaceTraversal::is_excluded_leaf`
    /// drops the leaf cleanly with `complete = true`, zero `ReadBudget` text charge, and zero
    /// `ProviderRefused` reasons. Custom adapters (`SafeSurfaceContext::text`) observe `None`.
    FilteredPuaStatic {
        value: String,
    },
    Unavailable {
        reasons: Vec<String>,
    },
    Fatal(SurfaceReadFailure),
}

/// Result of resolving a backend node's parent (e.g. during focus-anchor path collection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendParentRead {
    Node(usize),
    None,
    Fatal(SurfaceReadFailure),
}

/// Per-operation call-budget tracker passed from `KernelSurfaceContext` into `SurfaceBackend`
/// methods so multi-IPC operations meter every real COM IPC against `ReadBudget::max_calls`
/// and stop immediately when the remaining call ceiling or active deadline is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCallBudget {
    limit: usize,
    used: usize,
    exhausted: bool,
    deadline_ms: i64,
}

impl BackendCallBudget {
    pub fn new(limit: usize) -> Self {
        Self::with_deadline(limit, i64::MAX)
    }

    pub fn with_deadline(limit: usize, deadline_ms: i64) -> Self {
        Self {
            limit,
            used: 0,
            exhausted: false,
            deadline_ms,
        }
    }

    /// Reserve `count` backend calls; returns `false` and marks `exhausted` if doing so would
    /// exceed the remaining call ceiling.
    pub fn try_consume(&mut self, count: usize) -> bool {
        if count == 0 {
            return true;
        }
        if count > self.limit.saturating_sub(self.used) {
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

    pub fn deadline_ms(&self) -> i64 {
        self.deadline_ms
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
    ) -> BackendParentRead;

    fn children_backend_page(
        &mut self,
        index: usize,
        expected_role: &str,
        offset: usize,
        limit: usize,
        calls: &mut BackendCallBudget,
    ) -> BackendChildrenPage;

    /// Weighted-traversal child paging hook. Defaults to `children_backend_page`; live UIA
    /// overrides this to lazily expand head-64 + tail-64 (128 max) siblings and emit
    /// `ResolvedCount(total)` on first expansion while keeping incremental `Values` for custom
    /// adapters (`SafeSurfaceContext::children`).
    fn children_backend_for_traversal(
        &mut self,
        index: usize,
        expected_role: &str,
        offset: usize,
        limit: usize,
        calls: &mut BackendCallBudget,
    ) -> BackendChildrenPage {
        self.children_backend_page(index, expected_role, offset, limit, calls)
    }

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

    /// Report any non-fatal backend-level partiality reasons accumulated during capture
    /// (e.g. `"tree-provider-refused"`, `"tree-child-limit"`).
    fn backend_missing_reasons(&self) -> Vec<&'static str> {
        Vec::new()
    }
}

enum KernelTextRead {
    Text {
        value: String,
        complete: bool,
    },
    FilteredPuaStatic(String),
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

    fn initial_window_rect(&self) -> Option<SurfaceAbsoluteRect> {
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

    pub fn take_extra_reasons(&mut self) -> Vec<String> {
        std::mem::take(&mut self.extra_reasons)
            .into_iter()
            .collect()
    }

    pub fn inspected_nodes(&self) -> &HashMap<SurfaceHandle, AdapterNodeInfo> {
        &self.inspected_nodes
    }

    pub fn sampled_bounds(&self) -> &HashMap<SurfaceHandle, (SurfaceBounds, i64)> {
        &self.sampled_bounds
    }

    fn has_sampled_bounds_matching(
        &self,
        handle: SurfaceHandle,
        bounds: SurfaceBounds,
        observed_at_ms: i64,
    ) -> bool {
        self.sampled_bounds
            .get(&handle)
            .is_some_and(|&(b, ts)| b == bounds && ts == observed_at_ms)
    }

    fn effective_deadline_ms(&self) -> i64 {
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

    fn new_call_budget(&self) -> BackendCallBudget {
        BackendCallBudget::with_deadline(
            self.effective_remaining_calls(),
            self.effective_deadline_ms(),
        )
    }

    fn reset_for_weighted_fallback(&mut self, prior_text_units: usize) {
        self.budget.restore_text_units(prior_text_units);
        self.charged_display_text.clear();
    }

    fn commit_backend_calls(&mut self, call_budget: &BackendCallBudget) -> bool {
        if call_budget.exhausted() {
            let hit_global_limit = self.call_ceiling_override.is_none()
                || self.budget.calls().saturating_add(call_budget.used())
                    >= self.budget.active_call_limit();
            if !self.budget.is_final_validation() && hit_global_limit {
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

    fn record_backend_calls(&mut self, count: usize) -> bool {
        if self.abort_failure.is_some() || self.budget.text_violated() {
            return false;
        }
        let now = self.clock.monotonic_ms();
        if now >= self.effective_deadline_ms() {
            if !self.budget.is_final_validation() && now >= self.budget.active_deadline_ms() {
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

    fn abort(&mut self, failure: SurfaceReadFailure) {
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

    fn promote_region_root_if_applicable(&mut self) {
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

    fn sample_window_rect(&mut self) -> Option<SurfaceAbsoluteRect> {
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

    fn parent(&mut self, handle: SurfaceHandle) -> Option<SurfaceHandle> {
        if !self.verify_kernel_gates() || !self.can_continue() {
            return None;
        }
        let mut call_budget = self.new_call_budget();
        let outcome = self.backend.parent_backend_node(handle.0, &mut call_budget);
        let calls_ok = self.commit_backend_calls(&call_budget);
        match outcome {
            BackendParentRead::Fatal(failure) => {
                self.abort(failure);
                None
            }
            BackendParentRead::None => None,
            BackendParentRead::Node(parent_idx) => {
                if calls_ok && self.abort_failure.is_none() {
                    Some(SurfaceHandle(parent_idx))
                } else {
                    None
                }
            }
        }
    }

    fn inspect_for_traversal(&mut self, handle: SurfaceHandle) -> WeightedSurfaceInspection {
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
        let mut call_budget = self.new_call_budget();
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
        // Hard unbypassable security, private-title, and role-drift gates MUST run BEFORE
        // checking `!calls_ok` so a cached handle mutating on the exact IPC that exhausts
        // budget or crosses deadline is ALWAYS evicted (or aborts capture on root/focus).
        let sensitive_subrole = matches!(
            &node.subrole,
            SubroleRead::Value(sub) if TextSecurityGate::is_sensitive_subrole(sub)
        );
        if node.role == "AXSecureTextField"
            || node.protected_content == ProtectedContentRead::Value(true)
            || sensitive_subrole
            || node.strict_security == Some(SecureStatus::Sensitive)
        {
            self.evict_handle(handle);
            if is_root || Some(handle) == self.focus || node.is_focused {
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

        if let Some(prior) = self.inspected_nodes.get(&handle) {
            if prior.role != node.role {
                self.evict_handle(handle);
                if is_root {
                    self.abort(SurfaceReadFailure::BoundaryMismatch);
                } else {
                    self.extra_reasons.insert("node-role-changed".to_string());
                }
                return WeightedSurfaceInspection::Pruned(
                    WeightedSurfaceTraversalReason::UnsupportedRole,
                );
            }
        }

        if !calls_ok {
            let reason = if self.clock.monotonic_ms() >= self.effective_deadline_ms() {
                WeightedSurfaceTraversalReason::TimeBudget
            } else {
                WeightedSurfaceTraversalReason::WorkBudget
            };
            return WeightedSurfaceInspection::Pruned(reason);
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

        let is_readable_text_role = TextSecurityGate::is_readable_text_role(Some(&node.role))
            || node.role == "AXSecureTextField";
        let mut bounded_display_text = if is_readable_text_role {
            None
        } else {
            self.charged_display_text.get(&handle).cloned()
        };
        if !is_readable_text_role && bounded_display_text.is_none() {
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

        let safe_label = if is_readable_text_role {
            None
        } else {
            SafeDisplayText::label(
                node.label.as_deref(),
                bounded_display_text.as_deref(),
                self.spec.max_node_text_units,
            )
        };

        let mut relative_bounds: Option<SurfaceBounds> = None;
        if let (Some(abs_rect), Some(win_rect)) = (node.absolute_rect, self.initial_window_rect) {
            if let Some(rel) = abs_rect.relative_to(win_rect) {
                self.sampled_bounds.insert(handle, (rel, node.observed_at_ms));
                relative_bounds = Some(rel);
            }
        }

        let traversal_child_count = if is_readable_text_role
            && self.spec.expands_text_wrapper_id(node.identifier.as_deref())
        {
            0
        } else {
            node.child_count
        };

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
            child_count: traversal_child_count,
            is_focused: node.is_focused,
            observed_at_ms: node.observed_at_ms,
            is_enabled: node.is_enabled,
            display_text: bounded_display_text,
            bounds: relative_bounds,
            bounds_observed_at_ms: relative_bounds.map(|_| node.observed_at_ms),
        })
    }

    fn children_for_traversal(
        &mut self,
        handle: SurfaceHandle,
        offset: usize,
        limit: usize,
    ) -> WeightedSurfaceChildrenRead<SurfaceHandle> {
        self.read_children_page(handle, offset, limit, true)
    }

    fn read_children_page(
        &mut self,
        handle: SurfaceHandle,
        offset: usize,
        limit: usize,
        for_traversal: bool,
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
        let mut call_budget = self.new_call_budget();
        let page = if for_traversal {
            self.backend.children_backend_for_traversal(
                handle.0,
                &expected_role,
                offset,
                clamped_limit,
                &mut call_budget,
            )
        } else {
            self.backend.children_backend_page(
                handle.0,
                &expected_role,
                offset,
                clamped_limit,
                &mut call_budget,
            )
        };
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

    fn read_text_internal(
        &mut self,
        handle: SurfaceHandle,
        max_units: Option<usize>,
    ) -> Option<KernelTextRead> {
        if !self.verify_kernel_gates() || !self.can_continue() {
            return None;
        }

        // NEVER trust prior inspect() — ALWAYS re-verify fresh metadata before touching text!
        let mut inspect_calls = self.new_call_budget();
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
        // Run ALL security, private-title, may_traverse, role-drift, and allows_secure checks
        // BEFORE early-returning on `!inspect_calls_ok` so stale cached handles are ALWAYS
        // evicted (or abort capture on root/focus) even when budget/deadline trips on this IPC.
        let is_root = handle == self.root;
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
            if is_root || Some(handle) == self.focus || node.is_focused {
                self.abort(SurfaceReadFailure::SecurityExcluded);
            }
            self.extra_reasons
                .insert("node-security-excluded".to_string());
            return None;
        }

        if !TextSecurityGate::may_traverse(&node.subrole, node.protected_content) {
            self.evict_handle(handle);
            if is_root {
                self.abort(SurfaceReadFailure::BoundaryUnverified);
            } else {
                self.extra_reasons
                    .insert("node-security-excluded".to_string());
            }
            return None;
        }

        if let Some(prior) = self.inspected_nodes.get(&handle) {
            if prior.role != node.role {
                self.evict_handle(handle);
                if is_root {
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

        if !inspect_calls_ok {
            return None;
        }

        let safe_subrole = match &node.subrole {
            SubroleRead::Value(sub) if !sub.is_empty() => Some(sub.clone()),
            _ => None,
        };
        // Never leak readable-text-role body/Name via AdapterNodeInfo.label.
        let safe_label = None;
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
        let mut text_calls = self.new_call_budget();
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
            BackendTextRead::FilteredPuaStatic { value } => {
                if !text_calls_ok || !self.verify_kernel_gates() {
                    return None;
                }
                if node.role == "AXStaticText"
                    && !node.is_focused
                    && is_private_use_only_text(&value)
                {
                    Some(KernelTextRead::FilteredPuaStatic(value))
                } else {
                    None
                }
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
                            let sampled = self.backend.read_backend_node_bounds(handle.0, win_rect);
                            let bounds_calls_ok = if self.budget.calls() == before_bounds {
                                self.record_backend_calls(1)
                            } else {
                                true
                            };
                            if let Some(sampled) = sampled {
                                if bounds_calls_ok {
                                    self.sampled_bounds.insert(handle, sampled);
                                }
                            } else {
                                self.extra_reasons.insert("geometry-unavailable".to_string());
                            }
                        }
                    }
                }
                Some(KernelTextRead::Text { value, complete })
            }
        }
    }

    fn read_text_for_traversal(
        &mut self,
        handle: SurfaceHandle,
    ) -> Option<WeightedSurfaceTextRead> {
        match self.read_text_internal(handle, None)? {
            KernelTextRead::Text { value, complete } => Some(WeightedSurfaceTextRead {
                text: Some(value),
                truncated: !complete,
            }),
            KernelTextRead::FilteredPuaStatic(value) => Some(WeightedSurfaceTextRead {
                text: Some(value),
                truncated: false,
            }),
        }
    }

    fn display_text_bounded(
        &mut self,
        handle: SurfaceHandle,
        max_units: Option<usize>,
    ) -> Option<String> {
        if self.abort_failure.is_some() || self.budget.text_violated() {
            return None;
        }
        let info = self.inspected_nodes.get(&handle)?;
        if TextSecurityGate::is_readable_text_role(Some(&info.role))
            || info.role == "AXSecureTextField"
        {
            return None;
        }
        if let Some(existing) = self.charged_display_text.get(&handle) {
            return Some(existing.clone());
        }
        let raw = info.label.clone()?;
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

    fn with_preparation_window<T>(
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
        match self.read_children_page(handle, offset, limit, false) {
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
        let mut call_budget = self.new_call_budget();
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
        match self.read_text_internal(handle, max_units) {
            Some(KernelTextRead::Text { value, .. }) => Some(value),
            Some(KernelTextRead::FilteredPuaStatic(_)) | None => None,
        }
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
        let sampled = self.backend.read_backend_node_bounds(handle.0, win_rect);
        let calls_ok = if self.budget.calls() == before {
            self.record_backend_calls(1)
        } else {
            true
        };
        let Some(sampled) = sampled else {
            self.extra_reasons.insert("geometry-unavailable".to_string());
            return None;
        };
        if !calls_ok {
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
    let max_text_cap = ctx.budget().max_text_units.min(8_192);
    let mut total_text_units = 0usize;
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
        if !(0..=MAX_SAFE_INTEGER).contains(&node.observed_at_ms) {
            return false;
        }
        let Some(inspected) = ctx.inspected_nodes().get(&node.handle) else {
            return false;
        };
        if let Some(ref ax_role) = node.ax_role {
            if !access_contract::is_valid_ax_role(ax_role)
                || ax_role == "AXSecureTextField"
                || ax_role != &inspected.role
            {
                return false;
            }
        }
        match (node.bounds, node.bounds_observed_at_ms) {
            (Some(bounds), Some(ts)) => {
                if !bounds.is_valid()
                    || !(0..=MAX_SAFE_INTEGER).contains(&ts)
                    || !ctx.has_sampled_bounds_matching(node.handle, bounds, ts)
                {
                    return false;
                }
            }
            (None, None) => {}
            _ => return false,
        }
        if let Some(ref text) = node.text {
            let units = utf16_len(text);
            if units > max_text_cap.saturating_sub(total_text_units) {
                return false;
            }
            total_text_units += units;
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
        let run_start_unix_ms = clock.unix_ms();
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
        let prior_text_units = ctx.budget().text_units();

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

        let custom_opt = if scope == "window" {
            adapter.extract_surface(&mut ctx)
        } else {
            None
        };
        if let Some(custom) = custom_opt {
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
            ctx.reset_for_weighted_fallback(prior_text_units);

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
            if matches!(scope, "window" | "region") {
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
                        prep_work = prep.work;
                        prep_probes = prep.probes;
                        anchor_plan = prep.plan;
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
                    |h| ctx_cell.borrow_mut().read_text_for_traversal(*h),
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

            let walked_parents: HashMap<SurfaceHandle, Option<SurfaceHandle>> = walked
                .nodes
                .iter()
                .map(|s| (s.handle, s.parent))
                .collect();
            let surviving: HashSet<SurfaceHandle> = walked
                .nodes
                .iter()
                .filter_map(|s| {
                    if !ctx.inspected_nodes().contains_key(&s.handle) {
                        return None;
                    }
                    let mut seen = HashSet::new();
                    seen.insert(s.handle);
                    let mut cur = s.parent;
                    while let Some(anc) = cur {
                        if !seen.insert(anc)
                            || !walked_parents.contains_key(&anc)
                            || !ctx.inspected_nodes().contains_key(&anc)
                        {
                            return None;
                        }
                        cur = walked_parents.get(&anc).copied().flatten();
                    }
                    Some(s.handle)
                })
                .collect();
            let evicted_any = surviving.len() < walked.nodes.len();
            let explicit_focus_surviving = ctx.focus().filter(|fh| {
                surviving.contains(fh)
                    && walked
                        .nodes
                        .iter()
                        .any(|s| s.handle == *fh && s.metadata.is_focused)
            });
            let mut saw_focused = false;
            let mut any_text_truncated = false;
            extracted_nodes = walked
                .nodes
                .into_iter()
                .filter(|sample| surviving.contains(&sample.handle))
                .map(|sample| {
                    if sample.text_read.as_ref().is_some_and(|t| t.truncated) {
                        any_text_truncated = true;
                    }
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
                    let is_focused = if let Some(fh) = explicit_focus_surviving {
                        if sample.handle == fh && !saw_focused {
                            saw_focused = true;
                            true
                        } else {
                            false
                        }
                    } else if sample.metadata.is_focused && !saw_focused {
                        saw_focused = true;
                        true
                    } else {
                        false
                    };
                    CustomSurfaceNode {
                        handle: sample.handle,
                        parent: sample.parent,
                        role: wire_role,
                        ax_role: sample.metadata.ax_role,
                        text: node_text,
                        is_focused,
                        observed_at_ms: sample.metadata.observed_at_ms,
                        bounds: bounds_entry.map(|(b, _)| b),
                        bounds_observed_at_ms: bounds_entry.map(|(_, ts)| ts),
                    }
                })
                .collect();
            extraction_complete = walked.complete && !evicted_any && !any_text_truncated;
            for r in walked.reasons {
                reasons.insert(r.as_str().to_string());
            }
        }

        for r in ctx.extra_reasons() {
            reasons.insert(r.clone());
        }
        for r in ctx.backend.backend_missing_reasons() {
            reasons.insert(r.to_string());
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
                geometry = init_rect
                    .geometry_if_unchanged(final_rect, clock.unix_ms().max(run_start_unix_ms));
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
            } else {
                reasons.insert("geometry-unavailable".to_string());
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
        let mut emitted_focused = false;
        for item in &extracted_nodes {
            let local_id = ids_by_handle
                .get(&item.handle)
                .cloned()
                .unwrap_or_else(|| format!("sample-{}", item.handle.0));
            let parent_id = item
                .parent
                .and_then(|p| ids_by_handle.get(&p))
                .cloned();
            let focused = if item.is_focused && !emitted_focused {
                emitted_focused = true;
                Some(true)
            } else {
                None
            };
            let text = item
                .text
                .clone()
                .filter(|t| item.is_focused || !is_private_use_only_text(t));
            nodes.push(SurfaceNode {
                id: local_id.clone(),
                parent_id,
                role: item.role.to_string(),
                text,
                observed_at_ms: item.observed_at_ms,
                bounds: geometry.as_ref().and(item.bounds),
                bounds_observed_at_ms: geometry.as_ref().and(item.bounds_observed_at_ms),
                ax_role: item.ax_role.clone(),
                focused,
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

//! Shared mock surface backend and assertion helpers for Windows adapter integration tests.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use history_contract::utf16_len;
use collector_core::adapters::kernel::{
    BackendAllowedNode, BackendCallBudget, BackendChildrenPage, BackendInspection,
    BackendParentRead, BackendTailChildrenRead, BackendTextRead, SurfaceBackend,
    SurfaceCapturedTree,
};
use collector_core::adapters::StaticTextPolicy;
use collector_core::policy::{ProtectedContentRead, ResolvedAppIdentity, SubroleRead};
use collector_core::protocol_model::{
    bounded_utf16_slice, CapturePolicy, CollectorClock, SecureStatus, SurfaceAbsoluteRect,
    SurfaceBounds, SurfaceNode, SurfaceReadFailure,
};
use collector_core::uia_traversal::WeightedSurfaceTraversalReason;
pub struct FakeClock {
    pub mono: i64,
    pub unix: i64,
}

impl FakeClock {
    pub fn new() -> Self {
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
pub struct MockNode {
    pub role: &'static str,
    pub category: &'static str,
    pub subrole: SubroleRead,
    pub protected_content: ProtectedContentRead,
    pub children: Vec<usize>,
    pub parent: Option<usize>,
    pub text: Option<String>,
    pub reported_length: Option<usize>,
    pub is_focused: bool,
    pub is_enabled: Option<bool>,
    pub display_text: Option<String>,
    pub window_title: Option<String>,
    pub bounds: Option<SurfaceAbsoluteRect>,
    pub identifier: Option<String>,
    pub class_name: Option<String>,
    pub label: Option<String>,
    pub is_offscreen: bool,
    pub strict_security: Option<SecureStatus>,
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
            strict_security: None,
        }
    }
}

impl MockNode {
    pub fn new(role: &'static str) -> Self {
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

    pub fn children(mut self, c: Vec<usize>) -> Self {
        self.children = c;
        self
    }

    pub fn parent(mut self, p: usize) -> Self {
        self.parent = Some(p);
        self
    }

    pub fn text(mut self, t: impl Into<String>) -> Self {
        self.text = Some(t.into());
        self
    }

    pub fn reported_length(mut self, len: usize) -> Self {
        self.reported_length = Some(len);
        self
    }

    pub fn focused(mut self) -> Self {
        self.is_focused = true;
        self
    }

    pub fn enabled(mut self, v: bool) -> Self {
        self.is_enabled = Some(v);
        self
    }

    pub fn display_text(mut self, dt: impl Into<String>) -> Self {
        self.display_text = Some(dt.into());
        self
    }

    pub fn window_title(mut self, wt: impl Into<String>) -> Self {
        self.window_title = Some(wt.into());
        self
    }

    pub fn bounds(mut self, x: f64, y: f64, w: f64, h: f64) -> Self {
        self.bounds = SurfaceAbsoluteRect::new(x, y, w, h);
        self
    }

    pub fn identifier(mut self, id: impl Into<String>) -> Self {
        self.identifier = Some(id.into());
        self
    }

    pub fn label(mut self, lbl: impl Into<String>) -> Self {
        self.label = Some(lbl.into());
        self
    }

    pub fn subrole(mut self, sr: &str) -> Self {
        self.subrole = SubroleRead::Value(sr.to_string());
        self
    }

    pub fn protected(mut self) -> Self {
        self.protected_content = ProtectedContentRead::Value(true);
        self
    }

    pub fn offscreen(mut self) -> Self {
        self.is_offscreen = true;
        self
    }

    pub fn strict_security(mut self, status: SecureStatus) -> Self {
        self.strict_security = Some(status);
        self
    }
}

pub type InspectHook = Box<dyn FnMut(usize, bool) -> Option<BackendInspection>>;
pub type ChildHook = Box<dyn FnMut(&mut Option<SurfaceReadFailure>)>;
pub type TextHook = Box<dyn FnMut(usize) -> Option<BackendTextRead>>;
pub type ParentHook = Box<dyn FnMut(usize, &mut BackendCallBudget) -> Option<BackendParentRead>>;

pub struct MockSurfaceBackend {
    pub nodes: HashMap<usize, MockNode>,
    pub desktop_failure: Option<SurfaceReadFailure>,
    pub final_boundary_failure: Option<SurfaceReadFailure>,
    pub window_rect: Option<SurfaceAbsoluteRect>,
    pub inspected_indices: Vec<usize>,
    pub child_requests: Vec<(usize, usize, usize)>,
    pub text_reads: Vec<usize>,
    pub bounds_calls: usize,
    pub charge_per_child_ipc: bool,
    pub cap_reported_child_count: Option<usize>,
    pub lazy_resolve_on_traversal: bool,
    pub traversal_expanded: HashSet<usize>,
    pub access_denied_children: HashSet<usize>,
    pub backend_reasons: Vec<&'static str>,
    pub parent_deadlines: Vec<i64>,
    pub on_inspect: Option<InspectHook>,
    pub on_child_page: Option<ChildHook>,
    pub on_text_read: Option<TextHook>,
    pub on_parent: Option<ParentHook>,
}

impl MockSurfaceBackend {
    pub fn new(nodes: HashMap<usize, MockNode>) -> Self {
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
            lazy_resolve_on_traversal: false,
            traversal_expanded: HashSet::new(),
            access_denied_children: HashSet::new(),
            backend_reasons: Vec::new(),
            parent_deadlines: Vec::new(),
            on_inspect: None,
            on_child_page: None,
            on_text_read: None,
            on_parent: None,
        }
    }

    pub fn with_window_rect(mut self, x: f64, y: f64, w: f64, h: f64) -> Self {
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
            strict_security: node.strict_security,
        }))
    }

    fn parent_backend_node(
        &mut self,
        index: usize,
        calls: &mut BackendCallBudget,
    ) -> BackendParentRead {
        self.parent_deadlines.push(calls.deadline_ms());
        if let Some(ref mut hook) = self.on_parent {
            if let Some(custom) = hook(index, calls) {
                return custom;
            }
        }
        match self.nodes.get(&index).and_then(|n| n.parent) {
            Some(p) => BackendParentRead::Node(p),
            None => BackendParentRead::None,
        }
    }

    fn children_backend_for_traversal(
        &mut self,
        index: usize,
        expected_role: &str,
        offset: usize,
        limit: usize,
        calls: &mut BackendCallBudget,
    ) -> BackendChildrenPage {
        if self.lazy_resolve_on_traversal && self.traversal_expanded.insert(index) {
            if let Some(node) = self.nodes.get(&index) {
                let hinted = self
                    .cap_reported_child_count
                    .map_or(node.children.len(), |cap| node.children.len().min(cap));
                if node.children.len() != hinted {
                    return BackendChildrenPage::ResolvedCount(node.children.len());
                }
            }
        }
        self.children_backend_page(index, expected_role, offset, limit, calls)
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

    fn backend_missing_reasons(&self) -> Vec<&'static str> {
        self.backend_reasons.clone()
    }
}

pub fn id(app_id: &str) -> ResolvedAppIdentity {
    ResolvedAppIdentity::from_single(app_id.to_string()).expect("valid app id")
}

pub fn allowlist_policy(apps: &[&str]) -> CapturePolicy {
    CapturePolicy {
        enabled: true,
        application_scope: Some("allowlist".to_string()),
        allowed_application_ids: apps.iter().map(|s| s.to_string()).collect(),
        capture_scope: Some("window".to_string()),
        field_security: Some("denylist".to_string()),
        ..CapturePolicy::default()
    }
}

pub fn denylist_policy() -> CapturePolicy {
    CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        capture_scope: Some("window".to_string()),
        field_security: Some("denylist".to_string()),
        ..CapturePolicy::default()
    }
}

pub fn assert_valid_forest(tree: &SurfaceCapturedTree) {
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

pub fn texts_of(tree: &SurfaceCapturedTree) -> Vec<&str> {
    tree.nodes.iter().filter_map(|n| n.text.as_deref()).collect()
}


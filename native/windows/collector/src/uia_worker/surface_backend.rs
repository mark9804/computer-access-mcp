//! Live Windows UI Automation `SurfaceBackend` implementation (`LiveUiaSurfaceBackend`) and
//! unified single-path `capture_surface_tree` delegating both custom and weighted captures
//! through `adapters::kernel::SurfaceCaptureRunner::run`.
//!
//! Layer 1 module — imports only Layer 0 leaves (`target_verify`, `text_read`).

use std::collections::{HashMap, HashSet};

use access_contract::utf16_len;
use windows::Win32::UI::Accessibility::IUIAutomationElement;

use super::target_verify::{
    check_desktop_status, classify_element_security, is_allowed_process_id,
    read_window_title_ephemeral, ReadTarget, VerifiedTarget,
};
use super::text_read::{
    read_safe_display_url_post_gate, read_uia_node_text_bounded, UiaNodeTextOutcome,
};
use crate::adapters::kernel::{
    BackendAllowedNode, BackendCallBudget, BackendChildrenPage, BackendInspection,
    BackendParentRead, BackendTailChildrenRead, BackendTextRead, SurfaceBackend,
    SurfaceCaptureOutcome, SurfaceCaptureRunner,
};
use crate::adapters::{AdapterRegistry, SafeDisplayText, StaticTextPolicy, SurfaceHandle};
use crate::policy::{
    is_native_richedit_class, ApplicationPolicy, BrowserGate, PhaseBudget, ReadBudget, SubroleRead,
    TextSecurityGate,
};
use crate::protocol_model::{
    CapturePolicy, CollectorClock, DesktopStatus, SurfaceAbsoluteRect, SurfaceBounds,
    SurfaceReadFailure,
};
use crate::uia_com::{window_rect_logical, UiaCallError, UiaClient, UiaElementMetadata};
use crate::uia_traversal::{
    PendingSurfaceCapture, RuntimeIdKey, WeightedSurfaceTraversal, WeightedSurfaceTraversalReason,
};
use crate::worker_ipc::ReadTicket;

const MAX_CHILDREN_PER_CONTAINER: usize = 128;
const MAX_HEAD_CHILDREN_PER_CONTAINER: usize = 64;
const MAX_TAIL_CHILDREN_PER_CONTAINER: usize = 64;
const MAX_SURFACE_INTERNED_ELEMENTS: usize = 576;

struct InternedElement {
    element: IUIAutomationElement,
    runtime_id: RuntimeIdKey,
    meta: UiaElementMetadata,
    children_probed: bool,
    children_loaded: bool,
    children: Vec<usize>,
    last_probed_child: Option<IUIAutomationElement>,
    children_truncated: bool,
    /// Post-security-gate cached URL for `AXWebArea` / `AXLink` (`None` = not fetched yet).
    cached_url: Option<Option<String>>,
}

struct SurfaceCaptureStore {
    items: Vec<InternedElement>,
    by_runtime_id: HashMap<RuntimeIdKey, usize>,
}

impl SurfaceCaptureStore {
    fn new() -> Self {
        Self {
            items: Vec::with_capacity(64),
            by_runtime_id: HashMap::with_capacity(64),
        }
    }

    fn intern(
        &mut self,
        element: IUIAutomationElement,
        mut meta: UiaElementMetadata,
    ) -> Option<usize> {
        if meta.runtime_id.is_empty() {
            // Synthesize deterministic local key only if provider omitted RuntimeId.
            let synthetic = vec![-1, self.items.len() as i32];
            meta.runtime_id = RuntimeIdKey(synthetic);
        }
        if let Some(&idx) = self.by_runtime_id.get(&meta.runtime_id) {
            return Some(idx);
        }
        if self.items.len() >= MAX_SURFACE_INTERNED_ELEMENTS {
            return None;
        }
        let idx = self.items.len();
        let rid = meta.runtime_id.clone();
        self.items.push(InternedElement {
            element,
            runtime_id: rid.clone(),
            meta,
            children_probed: false,
            children_loaded: false,
            children: Vec::new(),
            last_probed_child: None,
            children_truncated: false,
            cached_url: None,
        });
        self.by_runtime_id.insert(rid, idx);
        Some(idx)
    }
}

struct LiveUiaSurfaceBackend<'a> {
    uia: &'a UiaClient,
    target: ReadTarget<'a>,
    verified: &'a VerifiedTarget,
    policy: &'a CapturePolicy,
    clock: &'a dyn CollectorClock,
    capture_start_ms: i64,
    exploration_deadline_ms: i64,
    is_terminal: bool,
    root_handle: usize,
    focus_handle: Option<usize>,
    focused_runtime_id: Option<&'a RuntimeIdKey>,
    already_read_focus_text: Option<&'a str>,
    initial_window_rect: Option<SurfaceAbsoluteRect>,
    initial_rect_sampled: bool,
    store: &'a mut SurfaceCaptureStore,
    weighted_children_expanded: HashSet<usize>,
    saw_provider_refused: bool,
    saw_children_truncated: bool,
}

impl<'a> LiveUiaSurfaceBackend<'a> {
    fn active_deadline_ms(&self, calls: &BackendCallBudget) -> i64 {
        calls.deadline_ms().min(self.exploration_deadline_ms)
    }

    fn build_allowed_node(
        &mut self,
        index: usize,
        is_root: bool,
        calls: &mut BackendCallBudget,
    ) -> BackendInspection {
        if index >= self.store.items.len() {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::ProviderRefused);
        }
        let (meta, runtime_id, children_probed, parent_elem) = {
            let item = &self.store.items[index];
            (
                item.meta.clone(),
                item.runtime_id.clone(),
                item.children_probed,
                item.element.clone(),
            )
        };
        let is_focused = Some(index) == self.focus_handle
            || self
                .focused_runtime_id
                .is_some_and(|rid| !rid.is_empty() && runtime_id == *rid);
        let has_sensitive_focus = is_focused || meta.has_keyboard_focus == Some(true);

        if meta.is_sensitive() {
            if is_root || has_sensitive_focus {
                return BackendInspection::Fatal(SurfaceReadFailure::SecurityExcluded);
            }
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::SecurityPruned);
        }
        if !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password) {
            if is_root {
                return BackendInspection::Fatal(SurfaceReadFailure::BoundaryUnverified);
            }
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::SecurityPruned);
        }
        if !is_allowed_process_id(meta.process_id, self.verified) {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::ProviderRefused);
        }

        let subrole_str = match &meta.subrole_read {
            SubroleRead::Value(s) => Some(s.as_str()),
            _ => None,
        };
        if !is_root
            && !is_focused
            && (meta
                .mapped
                .ax_role
                .is_some_and(|r| self.verified.spec.ignores_role(r))
                || subrole_str.is_some_and(|s| self.verified.spec.ignores_subrole(s)))
        {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::UnsupportedRole);
        }
        // Short-circuit unmapped controls before running the 2-child COM probe (Document 50030
        // always maps to a concrete `Some(...)` role, so `None` can never upgrade on child probe).
        if meta.mapped.ax_role.is_none() {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::UnsupportedRole);
        }

        let reads_text = meta
            .mapped
            .ax_role
            .and_then(WeightedSurfaceTraversal::role_policy)
            .is_some_and(|p| p.reads_text());
        let needs_document_child_probe = meta.control_type == 50030
            && meta.mapped.ax_role != Some("AXWebArea")
            && !is_native_richedit_class(meta.class_name.as_deref());
        let expands_text_wrapper = self
            .verified
            .spec
            .expands_text_wrapper_id(meta.automation_id.as_deref());

        let active_dl = self.active_deadline_ms(calls);
        if (!reads_text || needs_document_child_probe || expands_text_wrapper)
            && !children_probed
        {
            let mut child_handles = Vec::new();
            let mut last_probed: Option<IUIAutomationElement> = None;
            let mut loaded_all = false;
            let mut truncated_children = false;
            let mut has_any_child = false;

            let rem = active_dl.saturating_sub(self.clock.monotonic_ms());
            if rem <= 0 {
                return BackendInspection::Pruned(WeightedSurfaceTraversalReason::TimeBudget);
            }
            if !calls.try_consume(1) {
                return BackendInspection::Pruned(WeightedSurfaceTraversalReason::WorkBudget);
            }
            self.uia.apply_timeouts(rem);
            match self.uia.first_child_element(&parent_elem) {
                Ok(Some(first_el)) => {
                    has_any_child = true;
                    match self.uia.read_cached_metadata(
                        &first_el,
                        self.verified.dpi,
                        false,
                        self.is_terminal,
                    ) {
                        Ok(cmeta) => {
                            if is_allowed_process_id(cmeta.process_id, self.verified) {
                                if let Some(ch_idx) = self.store.intern(first_el.clone(), cmeta) {
                                    child_handles.push(ch_idx);
                                } else {
                                    truncated_children = true;
                                }
                            }
                        }
                        Err(UiaCallError::AccessDenied) => {
                            if is_root || is_focused {
                                return BackendInspection::Fatal(
                                    SurfaceReadFailure::ProviderUnavailable,
                                );
                            }
                            self.saw_provider_refused = true;
                            truncated_children = true;
                        }
                        Err(UiaCallError::Unavailable) => {
                            self.saw_provider_refused = true;
                            truncated_children = true;
                        }
                    }
                    let rem2 = active_dl.saturating_sub(self.clock.monotonic_ms());
                    if rem2 > 0 && calls.try_consume(1) {
                        self.uia.apply_timeouts(rem2);
                        match self.uia.next_sibling_element(&first_el) {
                            Ok(Some(second_el)) => {
                                match self.uia.read_cached_metadata(
                                    &second_el,
                                    self.verified.dpi,
                                    false,
                                    self.is_terminal,
                                ) {
                                    Ok(cmeta) => {
                                        if is_allowed_process_id(cmeta.process_id, self.verified) {
                                            if let Some(ch_idx) =
                                                self.store.intern(second_el.clone(), cmeta)
                                            {
                                                if !child_handles.contains(&ch_idx) {
                                                    child_handles.push(ch_idx);
                                                }
                                            } else {
                                                truncated_children = true;
                                            }
                                        }
                                    }
                                    Err(UiaCallError::AccessDenied) => {
                                        if is_root || is_focused {
                                            return BackendInspection::Fatal(
                                                SurfaceReadFailure::ProviderUnavailable,
                                            );
                                        }
                                        self.saw_provider_refused = true;
                                        truncated_children = true;
                                    }
                                    Err(UiaCallError::Unavailable) => {
                                        self.saw_provider_refused = true;
                                        truncated_children = true;
                                    }
                                }
                                last_probed = Some(second_el);
                            }
                            Ok(None) => {
                                loaded_all = !truncated_children;
                            }
                            Err(UiaCallError::AccessDenied) => {
                                if is_root || is_focused {
                                    return BackendInspection::Fatal(
                                        SurfaceReadFailure::ProviderUnavailable,
                                    );
                                }
                                self.saw_provider_refused = true;
                                last_probed = Some(first_el);
                                truncated_children = true;
                            }
                            Err(UiaCallError::Unavailable) => {
                                self.saw_provider_refused = true;
                                last_probed = Some(first_el);
                                truncated_children = true;
                            }
                        }
                    } else if child_handles.is_empty() && !truncated_children {
                        return BackendInspection::Pruned(if rem2 <= 0 {
                            WeightedSurfaceTraversalReason::TimeBudget
                        } else {
                            WeightedSurfaceTraversalReason::WorkBudget
                        });
                    } else {
                        // Keep `children_loaded = false` and resume lazily from `first_el` in
                        // `children_backend_for_traversal` without permanently poisoning
                        // `saw_children_truncated` when a tightened prep window pauses probing.
                        last_probed = Some(first_el);
                    }
                }
                Ok(None) => {
                    loaded_all = true;
                }
                Err(UiaCallError::AccessDenied) => {
                    if is_root || is_focused {
                        return BackendInspection::Fatal(SurfaceReadFailure::ProviderUnavailable);
                    }
                    self.saw_provider_refused = true;
                    truncated_children = true;
                }
                Err(UiaCallError::Unavailable) => {
                    self.saw_provider_refused = true;
                    truncated_children = true;
                }
            }

            if has_any_child
                && self.store.items[index].meta.control_type == 50030
                && !is_native_richedit_class(self.store.items[index].meta.class_name.as_deref())
            {
                let m = &self.store.items[index].meta;
                let updated = crate::policy::map_uia_control_type_to_ax(
                    50030,
                    false,
                    m.supports_text_pattern || m.supports_text_pattern2,
                    m.is_read_only,
                    true,
                    true,
                    false,
                    m.supports_scroll_pattern,
                    self.is_terminal,
                );
                self.store.items[index].meta.mapped = updated;
                self.store.items[index].cached_url = None;
            }
            if truncated_children {
                self.saw_children_truncated = true;
            }
            self.store.items[index].children = child_handles;
            self.store.items[index].last_probed_child = last_probed;
            self.store.items[index].children_probed = true;
            self.store.items[index].children_loaded = loaded_all && !truncated_children;
            self.store.items[index].children_truncated |= truncated_children;
        }

        let effective_meta = self.store.items[index].meta.clone();
        let Some(ax_role) = effective_meta.mapped.ax_role else {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::UnsupportedRole);
        };

        let effective_reads_text = WeightedSurfaceTraversal::role_policy(ax_role)
            .is_some_and(|p| p.reads_text());
        let child_count = if effective_reads_text && !expands_text_wrapper {
            0
        } else {
            self.store.items[index].children.len()
        };

        let url = match read_safe_display_url_post_gate(
            self.uia,
            &parent_elem,
            &effective_meta,
            &mut self.store.items[index].cached_url,
            self.verified.spec,
            active_dl,
            self.clock,
            || self.clock.monotonic_ms() < active_dl && calls.try_consume(1),
        ) {
            Ok(u) => u,
            Err(UiaCallError::AccessDenied) => {
                if is_root {
                    return BackendInspection::Fatal(SurfaceReadFailure::ProviderUnavailable);
                }
                self.saw_provider_refused = true;
                return BackendInspection::Pruned(WeightedSurfaceTraversalReason::ProviderRefused);
            }
            Err(UiaCallError::Unavailable) => None,
        };

        let display_text = SafeDisplayText::compose(
            ax_role,
            effective_meta.name.as_deref(),
            effective_meta.safe_description(),
            url.as_deref(),
            self.verified.spec.max_node_text_units,
        );
        let label = effective_meta
            .name
            .clone()
            .or_else(|| effective_meta.safe_description().map(str::to_string));

        let obs_ms = self.clock.unix_ms().max(self.capture_start_ms);
        let strict_security = Some(classify_element_security(&effective_meta, self.policy));

        BackendInspection::Allowed(Box::new(BackendAllowedNode {
            role: ax_role.to_string(),
            category: effective_meta.mapped.category,
            subrole: effective_meta.subrole_read.clone(),
            protected_content: effective_meta.is_password,
            child_count,
            is_focused,
            observed_at_ms: obs_ms,
            is_enabled: effective_meta.is_enabled,
            display_text,
            window_title: is_root
                .then(|| read_window_title_ephemeral(self.verified.hwnd))
                .flatten(),
            absolute_rect: effective_meta.logical_rect,
            identifier: effective_meta.automation_id.clone(),
            class_name: effective_meta.class_name.clone(),
            label,
            is_offscreen: effective_meta.is_offscreen == Some(true),
            strict_security,
        }))
    }
}

impl SurfaceBackend for LiveUiaSurfaceBackend<'_> {
    fn verify_desktop_and_application(&mut self) -> Option<SurfaceReadFailure> {
        if check_desktop_status(self.target) != DesktopStatus::Unlocked {
            return Some(SurfaceReadFailure::SecurityExcluded);
        }
        if !self.policy.enabled
            || !ApplicationPolicy::allows_identity(self.policy, &self.verified.resolved)
            || !BrowserGate::allows_identity(&self.verified.resolved, self.policy, false)
        {
            return Some(SurfaceReadFailure::SecurityExcluded);
        }
        None
    }

    fn inspect_backend_node(
        &mut self,
        index: usize,
        is_root: bool,
        calls: &mut BackendCallBudget,
    ) -> BackendInspection {
        self.build_allowed_node(index, is_root, calls)
    }

    fn refresh_backend_node(
        &mut self,
        index: usize,
        is_root: bool,
        calls: &mut BackendCallBudget,
    ) -> BackendInspection {
        let Some(item) = self.store.items.get(index) else {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::ProviderRefused);
        };
        let elem = item.element.clone();
        let has_children_hint = !item.children.is_empty();
        let was_focused = Some(index) == self.focus_handle
            || self
                .focused_runtime_id
                .is_some_and(|rid| !rid.is_empty() && item.runtime_id == *rid);
        let rem = self
            .active_deadline_ms(calls)
            .saturating_sub(self.clock.monotonic_ms());
        if rem <= 0 {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::TimeBudget);
        }
        if !calls.try_consume(1) {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::WorkBudget);
        }
        self.uia.apply_timeouts(rem);
        let refreshed = match self.uia.refresh_metadata(&elem) {
            Ok(el) => el,
            Err(_) => {
                if is_root || was_focused {
                    return BackendInspection::Fatal(SurfaceReadFailure::BoundaryAxFailed);
                }
                self.saw_provider_refused = true;
                return BackendInspection::Pruned(WeightedSurfaceTraversalReason::ProviderRefused);
            }
        };
        let fresh_meta = match self.uia.read_cached_metadata(
            &refreshed,
            self.verified.dpi,
            has_children_hint,
            self.is_terminal,
        ) {
            Ok(m) => m,
            Err(_) => {
                if is_root || was_focused {
                    return BackendInspection::Fatal(SurfaceReadFailure::BoundaryAxFailed);
                }
                self.saw_provider_refused = true;
                return BackendInspection::Pruned(WeightedSurfaceTraversalReason::ProviderRefused);
            }
        };
        self.store.items[index].meta = fresh_meta;
        self.store.items[index].cached_url = None;
        self.build_allowed_node(index, is_root, calls)
    }

    fn parent_backend_node(
        &mut self,
        index: usize,
        calls: &mut BackendCallBudget,
    ) -> BackendParentRead {
        let Some(item) = self.store.items.get(index) else {
            return BackendParentRead::None;
        };
        let elem = item.element.clone();
        let rem = self
            .active_deadline_ms(calls)
            .saturating_sub(self.clock.monotonic_ms());
        if rem <= 0 || !calls.try_consume(1) {
            return BackendParentRead::None;
        }
        self.uia.apply_timeouts(rem);
        let parent = match self.uia.parent_element(&elem) {
            Ok(Some(p)) => p,
            Ok(None) | Err(UiaCallError::Unavailable) => return BackendParentRead::None,
            Err(UiaCallError::AccessDenied) => {
                self.saw_provider_refused = true;
                return BackendParentRead::None;
            }
        };
        let pmeta = match self
            .uia
            .read_cached_metadata(&parent, self.verified.dpi, true, self.is_terminal)
        {
            Ok(m) => m,
            Err(UiaCallError::Unavailable) => return BackendParentRead::None,
            Err(UiaCallError::AccessDenied) => {
                self.saw_provider_refused = true;
                return BackendParentRead::None;
            }
        };
        if pmeta.is_sensitive() {
            return BackendParentRead::Fatal(SurfaceReadFailure::SecurityExcluded);
        }
        if !TextSecurityGate::may_traverse(&pmeta.subrole_read, pmeta.is_password)
            || !is_allowed_process_id(pmeta.process_id, self.verified)
        {
            return BackendParentRead::None;
        }
        match self.store.intern(parent, pmeta) {
            Some(idx) => BackendParentRead::Node(idx),
            None => BackendParentRead::None,
        }
    }

    fn children_backend_page(
        &mut self,
        index: usize,
        expected_role: &str,
        offset: usize,
        limit: usize,
        calls: &mut BackendCallBudget,
    ) -> BackendChildrenPage {
        let Some(item) = self.store.items.get(index) else {
            return BackendChildrenPage::Unavailable(
                WeightedSurfaceTraversalReason::ProviderRefused,
            );
        };
        if item.meta.is_sensitive() || item.meta.mapped.ax_role != Some(expected_role) {
            return BackendChildrenPage::Unavailable(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        }
        let target_len = offset.saturating_add(limit).min(MAX_CHILDREN_PER_CONTAINER);
        // Load one extra sibling when below MAX_CHILDREN_PER_CONTAINER so callers learn
        // whether additional siblings remain beyond this page even after a 2-child probe.
        let load_target = target_len
            .saturating_add(1)
            .min(MAX_CHILDREN_PER_CONTAINER);
        let needs_more = !item.children_loaded && item.children.len() < load_target;
        let active_dl = self.active_deadline_ms(calls);
        if needs_more {
            let (parent_elem, mut child_handles, last_probed) = {
                let it = &mut self.store.items[index];
                (
                    it.element.clone(),
                    std::mem::take(&mut it.children),
                    it.last_probed_child.take(),
                )
            };
            let mut seen_children: HashSet<usize> = child_handles.iter().copied().collect();
            let mut cur_prev = last_probed;
            let mut loaded_all = false;
            let mut truncated_children = false;
            let mut access_denied = false;

            let max_steps = load_target
                .saturating_sub(child_handles.len())
                .saturating_mul(2)
                .clamp(16, MAX_CHILDREN_PER_CONTAINER);
            let mut steps = 0usize;

            if cur_prev.is_none() && child_handles.is_empty() {
                let rem = active_dl.saturating_sub(self.clock.monotonic_ms());
                if rem > 0 && calls.try_consume(1) {
                    self.uia.apply_timeouts(rem);
                    steps += 1;
                    match self.uia.first_child_element(&parent_elem) {
                        Ok(Some(first_el)) => {
                            match self.uia.read_cached_metadata(
                                &first_el,
                                self.verified.dpi,
                                false,
                                self.is_terminal,
                            ) {
                                Ok(cmeta) => {
                                    if is_allowed_process_id(cmeta.process_id, self.verified) {
                                        if let Some(ch_idx) =
                                            self.store.intern(first_el.clone(), cmeta)
                                        {
                                            if seen_children.insert(ch_idx) {
                                                child_handles.push(ch_idx);
                                            }
                                            cur_prev = Some(first_el);
                                        } else {
                                            truncated_children = true;
                                        }
                                    } else {
                                        cur_prev = Some(first_el);
                                    }
                                }
                                Err(UiaCallError::AccessDenied) => {
                                    access_denied = true;
                                    self.saw_provider_refused = true;
                                    truncated_children = true;
                                }
                                Err(UiaCallError::Unavailable) => {
                                    self.saw_provider_refused = true;
                                    truncated_children = true;
                                }
                            }
                        }
                        Ok(None) => {
                            loaded_all = true;
                        }
                        Err(UiaCallError::AccessDenied) => {
                            access_denied = true;
                            self.saw_provider_refused = true;
                            truncated_children = true;
                        }
                        Err(UiaCallError::Unavailable) => {
                            self.saw_provider_refused = true;
                            truncated_children = true;
                        }
                    }
                } else {
                    truncated_children = true;
                }
            }

            while !access_denied && !truncated_children {
                let Some(prev_el) = cur_prev.take() else {
                    break;
                };
                if child_handles.len() >= load_target {
                    cur_prev = Some(prev_el);
                    break;
                }
                if steps >= max_steps {
                    cur_prev = Some(prev_el);
                    truncated_children = true;
                    break;
                }
                let rem = active_dl.saturating_sub(self.clock.monotonic_ms());
                if rem <= 0 || !calls.try_consume(1) {
                    cur_prev = Some(prev_el);
                    truncated_children = true;
                    break;
                }
                steps += 1;
                self.uia.apply_timeouts(rem);
                match self.uia.next_sibling_element(&prev_el) {
                    Ok(Some(next_el)) => {
                        match self.uia.read_cached_metadata(
                            &next_el,
                            self.verified.dpi,
                            false,
                            self.is_terminal,
                        ) {
                            Ok(cmeta) => {
                                if is_allowed_process_id(cmeta.process_id, self.verified) {
                                    if let Some(ch_idx) =
                                        self.store.intern(next_el.clone(), cmeta)
                                    {
                                        if seen_children.insert(ch_idx) {
                                            child_handles.push(ch_idx);
                                        } else {
                                            loaded_all = true;
                                            break;
                                        }
                                    } else {
                                        cur_prev = Some(prev_el);
                                        truncated_children = true;
                                        break;
                                    }
                                }
                                cur_prev = Some(next_el);
                            }
                            Err(UiaCallError::AccessDenied) => {
                                access_denied = true;
                                self.saw_provider_refused = true;
                                truncated_children = true;
                                break;
                            }
                            Err(UiaCallError::Unavailable) => {
                                self.saw_provider_refused = true;
                                cur_prev = Some(prev_el);
                                truncated_children = true;
                                break;
                            }
                        }
                    }
                    Ok(None) => {
                        loaded_all = true;
                        break;
                    }
                    Err(UiaCallError::AccessDenied) => {
                        access_denied = true;
                        self.saw_provider_refused = true;
                        truncated_children = true;
                        break;
                    }
                    Err(UiaCallError::Unavailable) => {
                        self.saw_provider_refused = true;
                        cur_prev = Some(prev_el);
                        truncated_children = true;
                        break;
                    }
                }
            }

            if truncated_children {
                self.saw_children_truncated = true;
            }
            let it = &mut self.store.items[index];
            it.children = child_handles;
            it.last_probed_child = cur_prev;
            it.children_probed = true;
            if loaded_all && !access_denied && !truncated_children {
                it.children_loaded = true;
            }
            it.children_truncated |= truncated_children;

            if access_denied {
                return BackendChildrenPage::AccessDenied;
            }
        }

        let it = &self.store.items[index];
        let total = it.children.len();
        if offset >= total {
            return BackendChildrenPage::Values {
                handles: Vec::new(),
                truncated: !it.children_loaded || it.children_truncated,
            };
        }
        let end = offset.saturating_add(limit).min(total);
        let truncated = end < total || !it.children_loaded || it.children_truncated;
        BackendChildrenPage::Values {
            handles: it.children[offset..end].to_vec(),
            truncated,
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
        let Some(item) = self.store.items.get(index) else {
            return BackendChildrenPage::Unavailable(
                WeightedSurfaceTraversalReason::ProviderRefused,
            );
        };
        if item.meta.is_sensitive() || item.meta.mapped.ax_role != Some(expected_role) {
            return BackendChildrenPage::Unavailable(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        }

        let needs_lazy_load =
            !item.children_loaded && !self.weighted_children_expanded.contains(&index);
        let active_dl = self.active_deadline_ms(calls);

        if needs_lazy_load {
            let (parent_elem, mut child_handles, last_probed, hint_count) = {
                let it = &mut self.store.items[index];
                let hint_count = it.children.len();
                (
                    it.element.clone(),
                    std::mem::take(&mut it.children),
                    it.last_probed_child.take(),
                    hint_count,
                )
            };
            let mut seen_children: HashSet<usize> = child_handles.iter().copied().collect();
            let mut loaded_all = false;
            let mut truncated_children = false;
            let mut provider_refused = false;
            let mut access_denied = false;
            let mut more_after_head: Option<IUIAutomationElement> = None;

            // 1. Continue walking head siblings up to MAX_HEAD_CHILDREN_PER_CONTAINER (64).
            let mut cur_prev = last_probed;
            if cur_prev.is_none() && child_handles.is_empty() {
                let rem = active_dl.saturating_sub(self.clock.monotonic_ms());
                if rem > 0 && calls.try_consume(1) {
                    self.uia.apply_timeouts(rem);
                    match self.uia.first_child_element(&parent_elem) {
                        Ok(Some(first_el)) => {
                            match self.uia.read_cached_metadata(
                                &first_el,
                                self.verified.dpi,
                                false,
                                self.is_terminal,
                            ) {
                                Ok(cmeta) => {
                                    if is_allowed_process_id(cmeta.process_id, self.verified) {
                                        if let Some(ch_idx) =
                                            self.store.intern(first_el.clone(), cmeta)
                                        {
                                            if seen_children.insert(ch_idx) {
                                                child_handles.push(ch_idx);
                                            }
                                        } else {
                                            truncated_children = true;
                                        }
                                    }
                                    cur_prev = Some(first_el);
                                }
                                Err(UiaCallError::AccessDenied) => {
                                    access_denied = true;
                                    provider_refused = true;
                                    truncated_children = true;
                                }
                                Err(UiaCallError::Unavailable) => {
                                    provider_refused = true;
                                    truncated_children = true;
                                    cur_prev = Some(first_el);
                                }
                            }
                        }
                        Ok(None) => {
                            loaded_all = true;
                        }
                        Err(UiaCallError::AccessDenied) => {
                            access_denied = true;
                            provider_refused = true;
                            truncated_children = true;
                        }
                        Err(UiaCallError::Unavailable) => {
                            provider_refused = true;
                            truncated_children = true;
                        }
                    }
                } else {
                    truncated_children = true;
                }
            }

            let mut head_steps = 0usize;
            let max_head_steps = MAX_CHILDREN_PER_CONTAINER;
            while let Some(prev_el) = cur_prev.take() {
                if truncated_children || access_denied || head_steps >= max_head_steps {
                    cur_prev = Some(prev_el);
                    truncated_children = true;
                    break;
                }
                head_steps += 1;
                let rem = active_dl.saturating_sub(self.clock.monotonic_ms());
                if rem <= 0 || !calls.try_consume(1) {
                    cur_prev = Some(prev_el);
                    truncated_children = true;
                    break;
                }
                self.uia.apply_timeouts(rem);
                let next_el = match self.uia.next_sibling_element(&prev_el) {
                    Ok(Some(el)) => el,
                    Ok(None) => {
                        loaded_all = !truncated_children;
                        break;
                    }
                    Err(UiaCallError::AccessDenied) => {
                        cur_prev = Some(prev_el);
                        access_denied = true;
                        provider_refused = true;
                        truncated_children = true;
                        break;
                    }
                    Err(UiaCallError::Unavailable) => {
                        cur_prev = Some(prev_el);
                        provider_refused = true;
                        truncated_children = true;
                        break;
                    }
                };
                if child_handles.len() >= MAX_HEAD_CHILDREN_PER_CONTAINER {
                    more_after_head = Some(next_el);
                    break;
                }
                match self.uia.read_cached_metadata(
                    &next_el,
                    self.verified.dpi,
                    false,
                    self.is_terminal,
                ) {
                    Ok(cmeta) => {
                        if is_allowed_process_id(cmeta.process_id, self.verified) {
                            if let Some(ch_idx) = self.store.intern(next_el.clone(), cmeta) {
                                if seen_children.insert(ch_idx) {
                                    child_handles.push(ch_idx);
                                } else {
                                    loaded_all = !truncated_children;
                                    break;
                                }
                            } else {
                                cur_prev = Some(prev_el);
                                truncated_children = true;
                                break;
                            }
                        }
                    }
                    Err(UiaCallError::AccessDenied) => {
                        cur_prev = Some(prev_el);
                        access_denied = true;
                        provider_refused = true;
                        truncated_children = true;
                        break;
                    }
                    Err(UiaCallError::Unavailable) => {
                        cur_prev = Some(prev_el);
                        provider_refused = true;
                        truncated_children = true;
                        break;
                    }
                }
                cur_prev = Some(next_el);
            }

            // 2. If container has > 64 children, also walk tail siblings backward (up to 64)
            // so bottom-aligned chat lists (Feishu/Slack) expose the newest messages for
            // SurfaceChildFrontier's tail-first paging!
            if let Some(extra_head_el) = more_after_head {
                let mut tail_handles: Vec<usize> = Vec::new();
                let mut tail_seen: HashSet<usize> = HashSet::new();
                let mut met_head = false;
                let mut last_child_absent = false;
                let tail_cap = MAX_CHILDREN_PER_CONTAINER
                    .saturating_sub(child_handles.len())
                    .min(MAX_TAIL_CHILDREN_PER_CONTAINER);
                let rem_tail_start = active_dl.saturating_sub(self.clock.monotonic_ms());
                if tail_cap > 0 && rem_tail_start > 0 && calls.try_consume(1) {
                    self.uia.apply_timeouts(rem_tail_start);
                    let mut tail_cur = match self.uia.last_child_element(&parent_elem) {
                        Ok(Some(el)) => Some(el),
                        Ok(None) => {
                            last_child_absent = true;
                            None
                        }
                        Err(UiaCallError::AccessDenied) => {
                            access_denied = true;
                            provider_refused = true;
                            truncated_children = true;
                            None
                        }
                        Err(UiaCallError::Unavailable) => {
                            provider_refused = true;
                            truncated_children = true;
                            None
                        }
                    };
                    let mut tail_steps = 0usize;
                    let max_tail_steps = MAX_CHILDREN_PER_CONTAINER;
                    while let Some(tail_el) = tail_cur {
                        if tail_steps >= max_tail_steps {
                            truncated_children = true;
                            break;
                        }
                        tail_steps += 1;
                        match self.uia.read_cached_metadata(
                            &tail_el,
                            self.verified.dpi,
                            false,
                            self.is_terminal,
                        ) {
                            Ok(cmeta) => {
                                if is_allowed_process_id(cmeta.process_id, self.verified) {
                                    if let Some(ch_idx) = self.store.intern(tail_el.clone(), cmeta)
                                    {
                                        if seen_children.contains(&ch_idx) {
                                            met_head = true;
                                            break;
                                        }
                                        if !tail_seen.insert(ch_idx) {
                                            break;
                                        }
                                        tail_handles.push(ch_idx);
                                    } else {
                                        truncated_children = true;
                                        break;
                                    }
                                }
                            }
                            Err(UiaCallError::AccessDenied) => {
                                access_denied = true;
                                provider_refused = true;
                                truncated_children = true;
                                break;
                            }
                            Err(UiaCallError::Unavailable) => {
                                provider_refused = true;
                                truncated_children = true;
                                break;
                            }
                        }
                        if tail_handles.len() >= tail_cap {
                            truncated_children = true;
                            break;
                        }
                        let rem_step = active_dl.saturating_sub(self.clock.monotonic_ms());
                        if rem_step <= 0 || !calls.try_consume(1) {
                            truncated_children = true;
                            break;
                        }
                        self.uia.apply_timeouts(rem_step);
                        tail_cur = match self.uia.previous_sibling_element(&tail_el) {
                            Ok(opt) => opt,
                            Err(UiaCallError::AccessDenied) => {
                                access_denied = true;
                                provider_refused = true;
                                truncated_children = true;
                                break;
                            }
                            Err(UiaCallError::Unavailable) => {
                                provider_refused = true;
                                truncated_children = true;
                                break;
                            }
                        };
                    }
                } else {
                    truncated_children = true;
                }
                if tail_handles.is_empty() && !met_head {
                    // Only fall back to the peeked 65th head child when provider legitimately
                    // reported no LastChild (`Ok(None)`), never on `Unavailable`/`AccessDenied`.
                    if last_child_absent {
                        if let Ok(cmeta) = self.uia.read_cached_metadata(
                            &extra_head_el,
                            self.verified.dpi,
                            false,
                            self.is_terminal,
                        ) {
                            if is_allowed_process_id(cmeta.process_id, self.verified) {
                                if let Some(ch_idx) = self.store.intern(extra_head_el, cmeta) {
                                    if seen_children.insert(ch_idx) {
                                        child_handles.push(ch_idx);
                                    }
                                }
                            }
                        }
                    }
                    truncated_children = true;
                } else {
                    tail_handles.reverse();
                    child_handles.extend(tail_handles);
                    if met_head && !truncated_children {
                        loaded_all = true;
                    } else {
                        truncated_children = true;
                    }
                }
            }

            let total = child_handles.len();
            if truncated_children {
                self.saw_children_truncated = true;
            }
            if provider_refused {
                self.saw_provider_refused = true;
            }
            {
                let it = &mut self.store.items[index];
                it.children = child_handles;
                it.last_probed_child = cur_prev;
                it.children_probed = true;
                if loaded_all && !access_denied && !truncated_children {
                    it.children_loaded = true;
                }
                it.children_truncated |= truncated_children;
            }
            self.weighted_children_expanded.insert(index);

            if access_denied && (index == self.root_handle || total == 0) {
                return BackendChildrenPage::AccessDenied;
            }
            if provider_refused && total == 0 && hint_count > 0 {
                return BackendChildrenPage::Unavailable(
                    WeightedSurfaceTraversalReason::ProviderRefused,
                );
            }
            if total != hint_count {
                return BackendChildrenPage::ResolvedCount(total);
            }
        }

        let it = &self.store.items[index];
        let total = it.children.len();
        if offset >= total {
            return BackendChildrenPage::Values {
                handles: Vec::new(),
                truncated: !it.children_loaded || it.children_truncated,
            };
        }
        let end = offset.saturating_add(limit).min(total);
        let truncated = end < total || !it.children_loaded || it.children_truncated;
        BackendChildrenPage::Values {
            handles: it.children[offset..end].to_vec(),
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
        let Some(item) = self.store.items.get(index) else {
            return BackendTailChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::ProviderRefused,
            );
        };
        if item.meta.is_sensitive() || item.meta.mapped.ax_role != Some(expected_role) {
            return BackendTailChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        }
        let capped_limit = limit.min(MAX_TAIL_CHILDREN_PER_CONTAINER);
        if capped_limit == 0 {
            return BackendTailChildrenRead::Values {
                handles: Vec::new(),
                truncated: false,
            };
        }
        let parent_elem = item.element.clone();
        let active_dl = self.active_deadline_ms(calls);
        let rem = active_dl.saturating_sub(self.clock.monotonic_ms());
        if rem <= 0 {
            return BackendTailChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::TimeBudget,
            );
        }
        if !calls.try_consume(1) {
            return BackendTailChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::WorkBudget,
            );
        }
        self.uia.apply_timeouts(rem);

        let mut tail_handles: Vec<usize> = Vec::with_capacity(capped_limit);
        let mut tail_seen: HashSet<usize> = HashSet::with_capacity(capped_limit);
        let mut truncated = false;

        let mut cur = match self.uia.last_child_element(&parent_elem) {
            Ok(opt) => opt,
            Err(UiaCallError::AccessDenied) => {
                self.saw_provider_refused = true;
                self.saw_children_truncated = true;
                return BackendTailChildrenRead::AccessDenied;
            }
            Err(UiaCallError::Unavailable) => {
                self.saw_provider_refused = true;
                self.saw_children_truncated = true;
                return BackendTailChildrenRead::Unavailable(
                    WeightedSurfaceTraversalReason::ProviderRefused,
                );
            }
        };
        if cur.is_none() {
            // Provider did not expose LastChild; fall back to any head children if present.
            let it = &self.store.items[index];
            let fallback_children = it.children.clone();
            let start = fallback_children.len().saturating_sub(capped_limit);
            return BackendTailChildrenRead::Values {
                handles: fallback_children[start..].to_vec(),
                truncated: start > 0 || !it.children_loaded || it.children_truncated,
            };
        }

        let max_steps = capped_limit
            .saturating_mul(2)
            .clamp(16, MAX_CHILDREN_PER_CONTAINER);
        let mut steps = 0usize;

        while let Some(tail_el) = cur {
            if steps >= max_steps {
                truncated = true;
                self.saw_children_truncated = true;
                break;
            }
            steps += 1;

            match self.uia.read_cached_metadata(
                &tail_el,
                self.verified.dpi,
                false,
                self.is_terminal,
            ) {
                Ok(cmeta) => {
                    if is_allowed_process_id(cmeta.process_id, self.verified) {
                        if let Some(ch_idx) = self.store.intern(tail_el.clone(), cmeta) {
                            if !tail_seen.insert(ch_idx) {
                                break;
                            }
                            tail_handles.push(ch_idx);
                        } else {
                            truncated = true;
                            self.saw_children_truncated = true;
                            break;
                        }
                    }
                }
                Err(UiaCallError::AccessDenied) => {
                    self.saw_provider_refused = true;
                    self.saw_children_truncated = true;
                    return BackendTailChildrenRead::AccessDenied;
                }
                Err(UiaCallError::Unavailable) => {
                    self.saw_provider_refused = true;
                    self.saw_children_truncated = true;
                    truncated = true;
                    break;
                }
            }

            let rem_step = active_dl.saturating_sub(self.clock.monotonic_ms());
            if rem_step <= 0 || !calls.try_consume(1) {
                truncated = true;
                self.saw_children_truncated = true;
                break;
            }
            self.uia.apply_timeouts(rem_step);
            let prev = match self.uia.previous_sibling_element(&tail_el) {
                Ok(opt) => opt,
                Err(UiaCallError::AccessDenied) => {
                    self.saw_provider_refused = true;
                    self.saw_children_truncated = true;
                    return BackendTailChildrenRead::AccessDenied;
                }
                Err(UiaCallError::Unavailable) => {
                    self.saw_provider_refused = true;
                    self.saw_children_truncated = true;
                    truncated = true;
                    break;
                }
            };
            if tail_handles.len() >= capped_limit {
                if prev.is_some() {
                    truncated = true;
                }
                break;
            }
            cur = prev;
        }

        tail_handles.reverse();
        BackendTailChildrenRead::Values {
            handles: tail_handles,
            truncated,
        }
    }

    fn read_backend_node_text(
        &mut self,
        index: usize,
        expected_role: &str,
        max_units: usize,
        static_text_probe: StaticTextPolicy,
        calls: &mut BackendCallBudget,
    ) -> BackendTextRead {
        let Some(item) = self.store.items.get(index) else {
            return BackendTextRead::Unavailable {
                reasons: vec!["node-text-unavailable".to_string()],
            };
        };
        let meta = item.meta.clone();
        let elem = item.element.clone();
        let runtime_id = item.runtime_id.clone();
        let is_focused = Some(index) == self.focus_handle
            || self
                .focused_runtime_id
                .is_some_and(|rid| !rid.is_empty() && runtime_id == *rid);
        let active_dl = self.active_deadline_ms(calls);

        match read_uia_node_text_bounded(
            self.uia,
            &elem,
            &meta,
            expected_role,
            max_units,
            static_text_probe,
            is_focused,
            self.already_read_focus_text,
            active_dl,
            self.clock,
            || self.clock.monotonic_ms() < active_dl && calls.try_consume(1),
        ) {
            UiaNodeTextOutcome::Text {
                value,
                is_unfocused_pua_static: true,
                ..
            } => BackendTextRead::FilteredPuaStatic { value },
            UiaNodeTextOutcome::Text {
                value,
                truncated,
                reasons,
                is_unfocused_pua_static: false,
            } => BackendTextRead::Text {
                value,
                complete: !truncated,
                reasons,
            },
            UiaNodeTextOutcome::Unavailable => BackendTextRead::Unavailable {
                reasons: vec!["node-text-unavailable".to_string()],
            },
        }
    }

    fn read_backend_node_bounds(
        &mut self,
        index: usize,
        window_rect: SurfaceAbsoluteRect,
    ) -> Option<(SurfaceBounds, i64)> {
        let rect = self.store.items.get(index)?.meta.logical_rect?;
        let rel = rect.relative_to(window_rect)?;
        let obs_ms = self.clock.unix_ms().max(self.capture_start_ms);
        Some((rel, obs_ms))
    }

    fn read_backend_window_rect(&mut self) -> Option<SurfaceAbsoluteRect> {
        // First sample uses the pre-read window rect when available so end-of-capture validation
        // catches window movement across the entire read; final validation always rechecks live.
        if !self.initial_rect_sampled {
            self.initial_rect_sampled = true;
            if let Some(rect) = self.initial_window_rect {
                return Some(rect);
            }
        }
        window_rect_logical(self.verified.hwnd).map(|(_, logical, _)| logical)
    }

    fn verify_final_surface_boundary(&mut self) -> Option<SurfaceReadFailure> {
        self.verify_desktop_and_application()
    }

    fn backend_missing_reasons(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.saw_provider_refused {
            out.push("tree-provider-refused");
        }
        if self.saw_children_truncated {
            out.push("tree-child-limit");
        }
        out
    }
}

/// Unified live surface tree capture delegating both custom (`WeChatAdapter`, `FigmaAdapter`)
/// and declarative weighted captures through `SurfaceCaptureRunner::run` + `LiveUiaSurfaceBackend`.
#[allow(clippy::too_many_arguments)]
pub(super) fn capture_surface_tree(
    uia: &UiaClient,
    registry: &AdapterRegistry,
    target: ReadTarget<'_>,
    verified: &VerifiedTarget,
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
    scope: &str,
    focused_elem: Option<&IUIAutomationElement>,
    focused_runtime_id: Option<&RuntimeIdKey>,
    already_read_focus_text: Option<&str>,
    max_nodes: usize,
    max_text_units: usize,
    optional_deadline_ms: i64,
    capture_start_ms: i64,
    is_terminal: bool,
) -> Result<(PendingSurfaceCapture, usize), SurfaceReadFailure> {
    let now = clock.monotonic_ms();
    let Some(exploration_deadline) =
        PhaseBudget::surface_exploration_deadline(now, optional_deadline_ms)
    else {
        return Err(SurfaceReadFailure::NotStartedBudget);
    };

    let surface_text_cap = max_text_units
        .min(ticket.policy.max_text_code_units)
        .min(8_192);
    let mut budget = ReadBudget::new(
        optional_deadline_ms,
        ReadBudget::DEFAULT_FINAL_VALIDATION_RESERVE_MS,
        ReadBudget::DEFAULT_MAX_CALLS,
        ReadBudget::DEFAULT_FINAL_VALIDATION_RESERVE_CALLS,
        surface_text_cap,
    );
    if !budget.has_exploration_headroom(now) {
        return Err(SurfaceReadFailure::NotStartedBudget);
    }

    uia.apply_timeouts(exploration_deadline.saturating_sub(now));

    let window_elem = uia
        .element_from_hwnd(verified.hwnd)
        .map_err(|_| SurfaceReadFailure::ProviderUnavailable)?;
    if !budget.consume_calls(1, clock.monotonic_ms()) {
        return Err(SurfaceReadFailure::CallBudget);
    }
    let window_meta = uia
        .read_cached_metadata(&window_elem, verified.dpi, true, is_terminal)
        .map_err(|_| SurfaceReadFailure::ProviderUnavailable)?;
    if window_meta.is_sensitive() {
        return Err(SurfaceReadFailure::SecurityExcluded);
    }
    if !TextSecurityGate::may_traverse(&window_meta.subrole_read, window_meta.is_password) {
        return Err(SurfaceReadFailure::SecurityExcluded);
    }

    // Determine traversal root (region prefers enclosing container around focused field,
    // pre-interned at handle `0` with fail-closed security/provider checks).
    let (root_elem, root_meta) = if scope == "region" {
        let mut chosen = (window_elem.clone(), window_meta.clone());
        if let Some(fe) = focused_elem {
            let rem = exploration_deadline.saturating_sub(clock.monotonic_ms());
            if rem > 0 && budget.consume_calls(1, clock.monotonic_ms()) {
                uia.apply_timeouts(rem);
                match uia.parent_element(fe) {
                    Ok(Some(parent)) => {
                        match uia.read_cached_metadata(&parent, verified.dpi, true, is_terminal) {
                            Ok(pmeta) => {
                                if pmeta.is_sensitive() {
                                    return Err(SurfaceReadFailure::SecurityExcluded);
                                }
                                if TextSecurityGate::may_traverse(
                                    &pmeta.subrole_read,
                                    pmeta.is_password,
                                ) && is_allowed_process_id(pmeta.process_id, verified)
                                    && matches!(
                                        pmeta.mapped.ax_role,
                                        Some(
                                            "AXGroup"
                                                | "AXScrollArea"
                                                | "AXSplitGroup"
                                                | "AXList"
                                                | "AXTable"
                                                | "AXOutline"
                                                | "AXRow"
                                                | "AXCell"
                                        )
                                    )
                                {
                                    chosen = (parent, pmeta);
                                }
                            }
                            Err(UiaCallError::AccessDenied) => {
                                return Err(SurfaceReadFailure::ProviderUnavailable);
                            }
                            Err(UiaCallError::Unavailable) => {}
                        }
                    }
                    Ok(None) | Err(UiaCallError::Unavailable) => {}
                    Err(UiaCallError::AccessDenied) => {
                        return Err(SurfaceReadFailure::ProviderUnavailable);
                    }
                }
            }
        }
        chosen
    } else {
        (window_elem, window_meta)
    };

    let mut store = SurfaceCaptureStore::new();
    let root_handle = store
        .intern(root_elem, root_meta)
        .ok_or(SurfaceReadFailure::ProviderUnavailable)?;
    debug_assert_eq!(root_handle, 0);

    let mut focus_handle: Option<usize> = None;
    if let Some(fe) = focused_elem {
        if let Ok(fmeta) = uia.read_cached_metadata(fe, verified.dpi, false, is_terminal) {
            if fmeta.is_sensitive() {
                return Err(SurfaceReadFailure::SecurityExcluded);
            }
            focus_handle = store.intern(fe.clone(), fmeta);
        }
    }

    let adapter = registry.adapter_impl_for_identity(&verified.resolved);
    let mut live_backend = LiveUiaSurfaceBackend {
        uia,
        target,
        verified,
        policy: &ticket.policy,
        clock,
        capture_start_ms,
        exploration_deadline_ms: exploration_deadline,
        is_terminal,
        root_handle,
        focus_handle,
        focused_runtime_id,
        already_read_focus_text,
        initial_window_rect: verified.initial_logical_rect,
        initial_rect_sampled: false,
        store: &mut store,
        weighted_children_expanded: HashSet::new(),
        saw_provider_refused: false,
        saw_children_truncated: false,
    };

    let mut tree = match SurfaceCaptureRunner::run(
        adapter,
        &verified.resolved,
        &ticket.policy,
        scope,
        max_nodes,
        focus_handle.map(SurfaceHandle),
        budget,
        clock,
        &mut live_backend,
    ) {
        SurfaceCaptureOutcome::Success(tree) => tree,
        SurfaceCaptureOutcome::Failure(err) => return Err(err),
    };

    if let Some(ref mut g) = tree.geometry {
        g.observed_at_ms = g.observed_at_ms.max(capture_start_ms);
    }
    if focused_elem.is_none() {
        for node in &mut tree.nodes {
            node.focused = None;
        }
    }

    let total_surface_units: usize = tree
        .nodes
        .iter()
        .filter_map(|n| n.text.as_deref())
        .map(utf16_len)
        .sum();
    let references: Vec<(String, RuntimeIdKey)> = tree
        .handles
        .into_iter()
        .map(|(local_id, idx)| (local_id, store.items[idx].runtime_id.clone()))
        .collect();

    Ok((
        PendingSurfaceCapture {
            nodes: tree.nodes,
            truncated: tree.truncated,
            reasons: tree.reasons,
            complete: tree.complete,
            geometry: tree.geometry,
            adapter_id: tree.adapter_id,
            references,
        },
        total_surface_units,
    ))
}

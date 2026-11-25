//! Bounded UIA menu ancestor walking, leaf child classification, `MenuBar` ownership verification,
//! and `MenuPathResolver` integration.
//!
//! Layer 1c submodule — imports `state` + `privacy` only (NEVER imports `mod`).

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Accessibility::IUIAutomationElement;

use super::privacy::{
    is_document_or_renderer_host, is_system_menu_bar, meta_is_safe_for_bound, root_hwnd_for_raw,
    window_class_name, BoundMenuWindow, MenuWalkContext,
};
use super::state::{
    is_allowed_menu_bar_wrapper_fields, is_renderer_host_class, MAX_MENU_BAR_ITEM_WRAPPER_HOPS,
};
use crate::menu_action_core::{
    is_menu_structure_control_type, MenuNodeSnapshot, MenuPathLimits, MenuPathResolver,
    ResolvedMenuPath, Win32MenuBarLink, UIA_BUTTON_CONTROL_TYPE, UIA_CUSTOM_CONTROL_TYPE,
    UIA_GROUP_CONTROL_TYPE, UIA_MENU_BAR_CONTROL_TYPE, UIA_MENU_CONTROL_TYPE,
    UIA_MENU_ITEM_CONTROL_TYPE, UIA_PANE_CONTROL_TYPE, UIA_WINDOW_CONTROL_TYPE,
};
use crate::policy::TextSecurityGate;
use crate::protocol_model::CollectorClock;
use crate::uia_com::{UiaCallError, UiaClient, UiaElementMetadata};
use crate::uia_traversal::RuntimeIdKey;

/// Maximum direct children scanned on a leaf `MenuItem` to distinguish visual children
/// (`Text`/`Image`/`Group`) from nested menu structure (`Menu`/`MenuItem`).
const MAX_LEAF_MENU_CHILD_SCAN: usize = 8;

/// Maximum ancestor hops walked when verifying a nested Electron/WinUI 3 `MenuBar` belongs to
/// `bound_hwnd`.
const MAX_MENU_BAR_WINDOW_HOPS: usize = MenuPathLimits::MAX_ABOVE_MENU_BAR_HOPS;

/// Element handle carried during `MenuPathResolver` ancestor walks so cached metadata and
/// `RuntimeIdKey` comparisons avoid redundant COM IPCs.
pub(super) struct WalkHandle {
    pub(super) elem: IUIAutomationElement,
    pub(super) runtime_id: RuntimeIdKey,
    pub(super) cached_meta: Option<UiaElementMetadata>,
    /// Optional precomputed `(child_count, is_submenu_opener)` leaf checks so `handle_focus_changed`
    /// never repeats `has_menu_child` / `is_submenu_opener` COM IPCs inside `inspect_walk_handle`.
    pub(super) precomputed_leaf_checks: Option<(Option<usize>, Option<bool>)>,
}

impl WalkHandle {
    pub(super) fn from_cached(elem: IUIAutomationElement, meta: UiaElementMetadata) -> Self {
        let runtime_id = meta.runtime_id.clone();
        Self {
            elem,
            runtime_id,
            cached_meta: Some(meta),
            precomputed_leaf_checks: None,
        }
    }

    pub(super) fn from_uncached(elem: IUIAutomationElement) -> Self {
        Self {
            elem,
            runtime_id: RuntimeIdKey(Vec::new()),
            cached_meta: None,
            precomputed_leaf_checks: None,
        }
    }

    pub(super) fn from_open_menu(elem: IUIAutomationElement, runtime_id: RuntimeIdKey) -> Self {
        Self {
            elem,
            runtime_id,
            cached_meta: None,
            precomputed_leaf_checks: None,
        }
    }

    pub(super) fn with_leaf_checks(
        mut self,
        child_count: Option<usize>,
        is_submenu_opener: Option<bool>,
    ) -> Self {
        self.precomputed_leaf_checks = Some((child_count, is_submenu_opener));
        self
    }
}

pub(super) fn preferred_meta_title(meta: &UiaElementMetadata) -> Option<String> {
    meta.name
        .as_deref()
        .and_then(MenuPathLimits::sanitize_segment)
        .or_else(|| {
            meta.safe_description()
                .and_then(MenuPathLimits::sanitize_segment)
        })
}

pub(super) fn is_allowed_menu_bar_wrapper(meta: &UiaElementMetadata) -> bool {
    is_allowed_menu_bar_wrapper_fields(
        meta.control_type,
        meta.mapped.ax_role,
        meta.class_name.as_deref(),
    )
}

/// Structural-only `ControlType` filter run on `FocusChanged` BEFORE heavy browser chrome
/// inspection or any `metadata_cache` (`Name`/`Title`/`Value`) read.
pub(super) fn is_structural_menu_focus_candidate(
    uia: &UiaClient,
    focused: &IUIAutomationElement,
    control_type: i32,
    is_browser: bool,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> bool {
    if matches!(
        control_type,
        UIA_MENU_ITEM_CONTROL_TYPE | UIA_MENU_CONTROL_TYPE | UIA_MENU_BAR_CONTROL_TYPE
    ) {
        return true;
    }
    if control_type != UIA_BUTTON_CONTROL_TYPE {
        return false;
    }
    // For `Button (50000)`: in browsers check ONLY the immediate parent's ControlType (`MenuBar` /
    // `MenuItem`) so web-page `<button>` focus never triggers `is_private_browser_window_chrome`;
    // in non-browsers allow up to `MAX_MENU_BAR_ITEM_WRAPPER_HOPS` structural wrapper hops
    // (`Custom` / `Group` / `Pane`).
    let max_hops = if is_browser {
        0
    } else {
        MAX_MENU_BAR_ITEM_WRAPPER_HOPS
    };
    let mut cur = focused.clone();
    for _ in 0..=max_hops {
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return false;
        }
        uia.apply_timeouts(rem.min(25));
        let Ok(Some(parent)) = uia.parent_element_raw(&cur) else {
            return false;
        };
        let Ok(pct) = uia.current_control_type(&parent) else {
            return false;
        };
        if matches!(pct, UIA_MENU_BAR_CONTROL_TYPE | UIA_MENU_ITEM_CONTROL_TYPE) {
            return true;
        }
        if !matches!(
            pct,
            UIA_CUSTOM_CONTROL_TYPE | UIA_GROUP_CONTROL_TYPE | UIA_PANE_CONTROL_TYPE
        ) {
            return false;
        }
        cur = parent;
    }
    false
}

/// Checks whether `elem` (with cached `meta`) is a top-level item (`MenuItem`, `MenuBarItem`, or
/// `Button`) whose direct parent or ancestor within `<= MAX_MENU_BAR_ITEM_WRAPPER_HOPS` allowlisted
/// safe transparent wrapper hops (`Custom 50025` / `Group 50026` / `Pane 50033`) is a verified
/// non-`SystemMenuBar` `MenuBar (50010)` belonging to `bound.hwnd`.
pub(super) fn detect_verified_menu_bar_item(
    uia: &UiaClient,
    elem: &IUIAutomationElement,
    meta: &UiaElementMetadata,
    bound: &BoundMenuWindow,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Option<String> {
    let ctx = bound.walk_ctx();
    if !meta_is_safe_for_bound(meta, ctx.expected_pid, ctx.raw_pid)
        || meta.is_enabled == Some(false)
    {
        return None;
    }

    let is_bar_item_candidate = meta.control_type == UIA_MENU_ITEM_CONTROL_TYPE
        || meta.control_type == UIA_BUTTON_CONTROL_TYPE
        || meta.mapped.ax_role == Some("AXMenuBarItem");
    if !is_bar_item_candidate {
        return None;
    }

    let mut title = preferred_meta_title(meta);

    let started_as_button = meta.control_type == UIA_BUTTON_CONTROL_TYPE;
    let mut cur = elem.clone();
    // Allow direct parent (hop 0) or up to `MAX_MENU_BAR_ITEM_WRAPPER_HOPS` explicit allowlisted
    // wrapper hops (`Custom 50025`, `Group 50026`, `Pane 50033`, plus enclosing `MenuItem 50011`
    // only on `started_as_button && hop == 0`) to reach `MenuBar (50010)`.
    for hop in 0..=MAX_MENU_BAR_ITEM_WRAPPER_HOPS {
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return None;
        }
        uia.apply_timeouts(rem.min(40));
        let Ok(Some(parent)) = uia.parent_element(&cur) else {
            return None;
        };
        if uia.is_root_desktop_element(&parent) {
            return None;
        }
        let Ok(pmeta) = uia.read_cached_metadata(&parent, ctx.dpi, false, false) else {
            return None;
        };
        if !meta_is_safe_for_bound(&pmeta, ctx.expected_pid, ctx.raw_pid) {
            return None;
        }
        if pmeta.control_type == UIA_MENU_BAR_CONTROL_TYPE {
            if is_system_menu_bar(&pmeta) {
                return None;
            }
            if let Some(ref expected_bar) = bound.app_menu_bar {
                let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
                if rem <= 0 {
                    return None;
                }
                uia.apply_timeouts(rem);
                if !uia.compare_elements(&parent, expected_bar) {
                    return None;
                }
            }
            if !menu_bar_belongs_to_window(uia, &parent, &pmeta, &ctx, deadline_ms, clock) {
                return None;
            }
            return title;
        }
        if pmeta.control_type == UIA_MENU_ITEM_CONTROL_TYPE {
            if started_as_button && hop == 0 && pmeta.is_enabled != Some(false) {
                if title.is_none() {
                    title = preferred_meta_title(&pmeta);
                }
                cur = parent;
                continue;
            }
            return None;
        }
        if !is_allowed_menu_bar_wrapper(&pmeta) {
            return None;
        }
        cur = parent;
    }
    None
}

/// Bounded scan (up to `MAX_LEAF_MENU_CHILD_SCAN = 8` direct children) returning `Ok(true)` ONLY
/// if any direct child has `control_type == UIA_MENU_CONTROL_TYPE (50009)` or
/// `UIA_MENU_ITEM_CONTROL_TYPE (50011)`, ignoring visual children (`Text`, `Image`, `Group`) and
/// failing closed (`Err`) on COM error, deadline expiry, unsafe child metadata, or `> 8` children.
pub(super) fn has_menu_child(
    uia: &UiaClient,
    elem: &IUIAutomationElement,
    dpi: u32,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Result<bool, UiaCallError> {
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if rem <= 0 {
        return Err(UiaCallError::Unavailable);
    }
    uia.apply_timeouts(rem);
    let mut cur = uia.first_child_element(elem)?;
    for _ in 0..MAX_LEAF_MENU_CHILD_SCAN {
        let Some(child) = cur else {
            return Ok(false);
        };
        let meta = uia.read_cached_metadata(&child, dpi, false, false)?;
        if meta.control_type == 0
            || meta.is_sensitive()
            || !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password)
        {
            return Err(UiaCallError::Unavailable);
        }
        if is_menu_structure_control_type(meta.control_type) {
            return Ok(true);
        }
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return Err(UiaCallError::Unavailable);
        }
        uia.apply_timeouts(rem);
        cur = uia.next_sibling_element(&child)?;
    }
    // Fail closed if the MenuItem has more than 8 direct children whose ControlTypes weren't scanned.
    if cur.is_some() {
        return Err(UiaCallError::Unavailable);
    }
    Ok(false)
}

pub(super) fn walk_handles_same(
    uia: &UiaClient,
    a: &WalkHandle,
    b: &WalkHandle,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> bool {
    if !a.runtime_id.is_empty() && !b.runtime_id.is_empty() {
        return a.runtime_id == b.runtime_id;
    }
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if rem <= 0 {
        return false;
    }
    uia.apply_timeouts(rem);
    uia.compare_elements(&a.elem, &b.elem)
}

pub(super) fn menu_bar_belongs_to_window(
    uia: &UiaClient,
    bar_elem: &IUIAutomationElement,
    bar_meta: &UiaElementMetadata,
    ctx: &MenuWalkContext,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> bool {
    if ctx.hwnd.0.is_null() {
        return false;
    }
    let is_safe_node = |m: &UiaElementMetadata| {
        meta_is_safe_for_bound(m, ctx.expected_pid, ctx.raw_pid)
            && !is_system_menu_bar(m)
            && (!ctx.is_browser || !is_document_or_renderer_host(m))
    };
    if !is_safe_node(bar_meta) {
        return false;
    }
    let check_native_hwnd = |native: HWND| -> Result<bool, ()> {
        if ctx.is_browser
            && native != ctx.hwnd
            && window_class_name(native)
                .as_deref()
                .is_some_and(is_renderer_host_class)
        {
            return Err(());
        }
        if native == ctx.hwnd {
            return Ok(true);
        }
        Ok(root_hwnd_for_raw(native.0 as isize) == ctx.hwnd)
    };

    let mut matched_window = false;
    if let Some(native) = bar_meta.native_hwnd {
        match check_native_hwnd(native) {
            Ok(true) => {
                matched_window = true;
                if !ctx.is_browser && native == ctx.hwnd {
                    return true;
                }
            }
            Ok(false) => {}
            Err(()) => return false,
        }
    }
    // Walk up to `MAX_MENU_BAR_WINDOW_HOPS` (20) ancestors verifying PID, sensitivity,
    // `may_traverse`, non-`SystemMenuBar`, and (for browsers) rejecting `Document (50030)` /
    // `AXWebArea` / `AXDocument` / renderer HWNDs at EVERY hop until reaching `Window
    // (ctx.hwnd)` or Desktop root.
    let mut cur = bar_elem.clone();
    for _ in 0..MAX_MENU_BAR_WINDOW_HOPS {
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return false;
        }
        uia.apply_timeouts(rem);
        let parent = match uia.parent_element(&cur) {
            Ok(Some(p)) => p,
            Ok(None) => return matched_window,
            Err(_) => return false,
        };
        if uia.is_root_desktop_element(&parent) {
            return matched_window;
        }
        let Ok(pmeta) = uia.read_cached_metadata(&parent, ctx.dpi, false, false) else {
            return false;
        };
        if !is_safe_node(&pmeta) {
            return false;
        }
        if let Some(native) = pmeta.native_hwnd {
            match check_native_hwnd(native) {
                Ok(true) => {
                    matched_window = true;
                    if !ctx.is_browser {
                        return true;
                    }
                    if pmeta.control_type == UIA_WINDOW_CONTROL_TYPE && native == ctx.hwnd {
                        return true;
                    }
                }
                Ok(false) => {}
                Err(()) => return false,
            }
        }
        cur = parent;
    }
    false
}

/// Verifies ONCE that a reached `MenuBar (50010)` belongs to `ctx.hwnd` (reused as the custom
/// `bar_verifier` for `MenuPathResolver::resolve_with_bar_verifier` and
/// `classify_opened_menu_with_bar_verifier` so the `MenuBar -> Window` COM walk never duplicates).
pub(super) fn verify_walk_menu_bar_owner(
    uia: &UiaClient,
    handle: &WalkHandle,
    ctx: &MenuWalkContext,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> bool {
    let meta = match handle.cached_meta {
        Some(ref cached) => cached.clone(),
        None => {
            let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
            if rem <= 0 {
                return false;
            }
            uia.apply_timeouts(rem);
            let Ok(refreshed) = uia.refresh_metadata(&handle.elem) else {
                return false;
            };
            let Ok(m) = uia.read_cached_metadata(&refreshed, ctx.dpi, false, false) else {
                return false;
            };
            m
        }
    };
    menu_bar_belongs_to_window(uia, &handle.elem, &meta, ctx, deadline_ms, clock)
}

pub(super) fn inspect_walk_handle(
    uia: &UiaClient,
    handle: &WalkHandle,
    is_leaf: bool,
    dpi: u32,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Option<MenuNodeSnapshot> {
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if rem <= 0 {
        return None;
    }
    uia.apply_timeouts(rem);

    let meta = match handle.cached_meta {
        Some(ref cached) => cached.clone(),
        None => {
            let refreshed = uia.refresh_metadata(&handle.elem).ok()?;
            uia.read_cached_metadata(&refreshed, dpi, false, false)
                .ok()?
        }
    };

    if meta.is_sensitive() || !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password)
    {
        return None;
    }

    let (child_count, is_submenu_opener) = if is_leaf {
        if let Some(precomputed) = handle.precomputed_leaf_checks {
            precomputed
        } else {
            if clock.monotonic_ms() >= deadline_ms {
                return None;
            }
            let child_count = match has_menu_child(uia, &handle.elem, dpi, deadline_ms, clock) {
                Ok(false) => Some(0),
                Ok(true) => Some(1),
                Err(UiaCallError::AccessDenied | UiaCallError::Unavailable) => None,
            };
            let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
            if rem <= 0 {
                return None;
            }
            uia.apply_timeouts(rem);
            let opener = match uia.is_submenu_opener(&handle.elem) {
                Ok(v) => Some(v),
                Err(_) => Some(true), // fail closed if ExpandCollapse status cannot be verified
            };
            (child_count, opener)
        }
    } else {
        (None, None)
    };

    Some(MenuNodeSnapshot {
        pid: meta.process_id,
        control_type: Some(meta.control_type),
        role: meta.mapped.ax_role.map(str::to_string),
        subrole: meta.subrole_read.clone(),
        protected_content: meta.is_password,
        enabled: meta.is_enabled,
        title: meta.name.clone(),
        description: meta.safe_description().map(str::to_string),
        automation_id: meta.automation_id.clone(),
        class_name: meta.class_name.clone(),
        child_count,
        is_submenu_opener,
    })
}

pub(super) fn parent_walk_handle(
    uia: &UiaClient,
    handle: &WalkHandle,
    dpi: u32,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Option<WalkHandle> {
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if rem <= 0 {
        return None;
    }
    uia.apply_timeouts(rem);
    let parent = uia.parent_element(&handle.elem).ok()??;
    // Treat the Windows UIA Desktop root (`#32769` / `GetRootElement()`) as the top of the tree
    // (`None`) so Win32 `#32768` popups parented to Desktop can still match `Win32MenuBarLink`
    // while foreign application windows remain rejected by PID checks.
    if uia.is_root_desktop_element(&parent) {
        return None;
    }
    let meta = uia.read_cached_metadata(&parent, dpi, false, false).ok()?;
    Some(WalkHandle::from_cached(parent, meta))
}

pub(super) fn resolve_uia_menu_leaf_handle(
    uia: &UiaClient,
    leaf_handle: WalkHandle,
    ctx: &MenuWalkContext,
    app_menu_bar: Option<&IUIAutomationElement>,
    win32_link: Option<&Win32MenuBarLink>,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Option<ResolvedMenuPath> {
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if rem <= 0 {
        return None;
    }
    uia.apply_timeouts(rem);

    let bar_handle = app_menu_bar.map(|bar| {
        uia.refresh_metadata(bar)
            .ok()
            .and_then(|c| {
                uia.read_cached_metadata(&c, ctx.dpi, false, false)
                    .ok()
                    .map(|m| WalkHandle::from_cached(c, m))
            })
            .unwrap_or_else(|| WalkHandle::from_uncached(bar.clone()))
    });

    MenuPathResolver::resolve_with_bar_verifier(
        leaf_handle,
        ctx.expected_pid,
        ctx.raw_host_pid(),
        bar_handle.as_ref(),
        None,
        win32_link,
        !ctx.is_browser,
        |a, b| walk_handles_same(uia, a, b, deadline_ms, clock),
        |handle, is_leaf| inspect_walk_handle(uia, handle, is_leaf, ctx.dpi, deadline_ms, clock),
        |handle| parent_walk_handle(uia, handle, ctx.dpi, deadline_ms, clock),
        |bar_handle| verify_walk_menu_bar_owner(uia, bar_handle, ctx, deadline_ms, clock),
        || clock.monotonic_ms() < deadline_ms,
    )
}

fn resolve_uia_menu_leaf_internal(
    uia: &UiaClient,
    leaf_elem: IUIAutomationElement,
    ctx: &MenuWalkContext,
    app_menu_bar: Option<&IUIAutomationElement>,
    win32_link: Option<&Win32MenuBarLink>,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Option<ResolvedMenuPath> {
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if rem <= 0 {
        return None;
    }
    uia.apply_timeouts(rem);
    let refreshed_leaf = uia.refresh_metadata(&leaf_elem).ok()?;
    let leaf_meta = uia
        .read_cached_metadata(&refreshed_leaf, ctx.dpi, false, false)
        .ok()?;
    resolve_uia_menu_leaf_handle(
        uia,
        WalkHandle::from_cached(refreshed_leaf, leaf_meta),
        ctx,
        app_menu_bar,
        win32_link,
        deadline_ms,
        clock,
    )
}

/// Deterministic integration-test helper exercising the real MTA `UiaClient` ancestor walker and
/// `MenuPathResolver` against a live Win32 `IUIAutomationElement` leaf and target `HWND`.
#[allow(clippy::too_many_arguments)]
pub fn resolve_uia_menu_leaf_for_test(
    uia: &UiaClient,
    leaf_elem: &IUIAutomationElement,
    bound_hwnd: HWND,
    expected_pid: u32,
    dpi: u32,
    app_menu_bar: Option<&IUIAutomationElement>,
    win32_link: Option<&Win32MenuBarLink>,
    clock: &dyn CollectorClock,
) -> Option<ResolvedMenuPath> {
    let deadline_ms = clock.monotonic_ms().saturating_add(500);
    let ctx = MenuWalkContext {
        hwnd: bound_hwnd,
        expected_pid,
        raw_pid: 0,
        is_browser: false,
        dpi,
    };
    resolve_uia_menu_leaf_internal(
        uia,
        leaf_elem.clone(),
        &ctx,
        app_menu_bar,
        win32_link,
        deadline_ms,
        clock,
    )
}

/// Deterministic integration-test helper exercising `has_menu_child` against a live Win32 UIA
/// element (distinguishing visual leaf children like `Text`/`Image`/`Group` from nested
/// `Menu`/`MenuItem` children).
pub fn has_menu_child_for_test(
    uia: &UiaClient,
    elem: &IUIAutomationElement,
    dpi: u32,
    clock: &dyn CollectorClock,
) -> Result<bool, UiaCallError> {
    let deadline_ms = clock.monotonic_ms().saturating_add(500);
    has_menu_child(uia, elem, dpi, deadline_ms, clock)
}

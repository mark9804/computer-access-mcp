//! MTA COM initialization, Per-Monitor V2 DPI normalization, cached pre-read `IUIAutomation`
//! helpers, safe `TextPattern`/`ValuePattern` extraction, and WinEvent dirty-wakeup watcher.

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Once};
use std::thread::{self, JoinHandle};

use access_contract::utf16_len;
use windows::core::{Interface, BOOL, HRESULT};
use windows::Win32::Foundation::{
    E_ACCESSDENIED, HWND, LPARAM, RECT, S_FALSE, S_OK, WPARAM,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    SAFEARRAY,
};
use windows::Win32::System::Ole::{
    SafeArrayAccessData, SafeArrayDestroy, SafeArrayGetLBound, SafeArrayGetUBound,
    SafeArrayUnaccessData,
};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::System::Variant::{VARIANT, VT_ARRAY, VT_BOOL, VT_BSTR, VT_I4};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, CUIAutomation8, HeadingLevel_None, IUIAutomation, IUIAutomation2,
    IUIAutomationCacheRequest, IUIAutomationElement, IUIAutomationTextPattern,
    IUIAutomationTextPattern2, IUIAutomationTextRange, IUIAutomationTreeWalker,
    IUIAutomationValuePattern, SetWinEventHook, TextPatternRangeEndpoint_End,
    TextPatternRangeEndpoint_Start, UIA_AriaPropertiesPropertyId, UIA_AriaRolePropertyId,
    UIA_AutomationIdPropertyId, UIA_BoundingRectanglePropertyId, UIA_ClassNamePropertyId,
    UIA_ControlTypePropertyId, UIA_FullDescriptionPropertyId, UIA_HasKeyboardFocusPropertyId,
    UIA_HeadingLevelPropertyId, UIA_HelpTextPropertyId, UIA_IsContentElementPropertyId,
    UIA_IsControlElementPropertyId, UIA_IsEnabledPropertyId, UIA_IsKeyboardFocusablePropertyId,
    UIA_IsOffscreenPropertyId, UIA_IsPasswordPropertyId, UIA_IsScrollPatternAvailablePropertyId,
    UIA_IsTextPattern2AvailablePropertyId, UIA_IsTextPatternAvailablePropertyId,
    UIA_IsValuePatternAvailablePropertyId, UIA_LandmarkTypePropertyId,
    UIA_LocalizedControlTypePropertyId, UIA_NamePropertyId, UIA_NativeWindowHandlePropertyId,
    UIA_ProcessIdPropertyId, UIA_RuntimeIdPropertyId, UIA_TextPattern2Id, UIA_TextPatternId,
    UIA_ValueIsReadOnlyPropertyId, UIA_ValuePatternId, UnhookWinEvent, HWINEVENTHOOK,
};
use windows::Win32::UI::HiDpi::{
    GetDpiForWindow, SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, EnumChildWindows, GetClassNameW, GetMessageW, GetWindowRect, PeekMessageW,
    PostThreadMessageW, TranslateMessage, EVENT_OBJECT_FOCUS, EVENT_OBJECT_TEXTSELECTIONCHANGED,
    EVENT_OBJECT_VALUECHANGE, EVENT_SYSTEM_FOREGROUND, MSG, PM_NOREMOVE, WINEVENT_OUTOFCONTEXT,
    WINEVENT_SKIPOWNPROCESS, WM_QUIT,
};

use crate::adapters::{ActivationMode, AppAdapterSpec};
use crate::policy::{
    aria_properties_has_multiline, map_uia_control_type_to_ax, resolve_uia_subrole, BrowserGate,
    MappedRole, ProtectedContentRead, SubroleRead,
};
use crate::protocol_model::{
    bounded_utf16_slice, AxEnablementResult, CapturePolicy, CollectorClock, SelectionReadResult,
    SurfaceAbsoluteRect, SystemCollectorClock, TextSelection,
};
use crate::uia_traversal::RuntimeIdKey;

static DPI_INIT: Once = Once::new();

/// Enable Per-Monitor V2 DPI awareness once per process so UIA `BoundingRectangle` and
/// `GetWindowRect` consistently return physical pixels. Ignores already-set errors.
pub fn ensure_per_monitor_dpi_aware() {
    DPI_INIT.call_once(|| {
        // SAFETY: Process-wide DPI context call; safe to ignore if already set by manifest/caller.
        unsafe {
            let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        }
    });
}

/// Query effective window DPI with a `96` fallback.
pub fn window_dpi(hwnd: HWND) -> u32 {
    if hwnd.0.is_null() {
        return 96;
    }
    // SAFETY: Standard Win32 DPI query on live HWND.
    let dpi = unsafe { GetDpiForWindow(hwnd) };
    if dpi == 0 {
        96
    } else {
        dpi
    }
}

/// Read top-level window physical rect and normalize into logical points using `GetDpiForWindow`.
pub fn window_rect_logical(hwnd: HWND) -> Option<(RECT, SurfaceAbsoluteRect, u32)> {
    if hwnd.0.is_null() {
        return None;
    }
    let mut rect = RECT::default();
    // SAFETY: Standard Win32 window rect query.
    unsafe {
        GetWindowRect(hwnd, &mut rect).ok()?;
    }
    let dpi = window_dpi(hwnd);
    let width = (i64::from(rect.right) - i64::from(rect.left)).max(0) as f64;
    let height = (i64::from(rect.bottom) - i64::from(rect.top)).max(0) as f64;
    let logical =
        SurfaceAbsoluteRect::from_physical_pixels(rect.left as f64, rect.top as f64, width, height, dpi)?;
    Some((rect, logical, dpi))
}

struct RendererChildCollector {
    children: Vec<HWND>,
}

unsafe extern "system" fn enum_renderer_child_windows(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let collector = &mut *(lparam.0 as *mut RendererChildCollector);
    if collector.children.len() >= 4 {
        return BOOL(0);
    }
    let mut class_buf = [0u16; 128];
    let len = GetClassNameW(hwnd, &mut class_buf);
    if len > 0 {
        if let Ok(class_name) = String::from_utf16(&class_buf[..len as usize]) {
            if class_name.eq_ignore_ascii_case("Chrome_RenderWidgetHostHWND")
                || class_name.eq_ignore_ascii_case("MozillaCompositorWindowClass")
            {
                collector.children.push(hwnd);
            }
        }
    }
    BOOL(1)
}

fn find_renderer_child_hwnds(parent: HWND) -> Vec<HWND> {
    let mut collector = RendererChildCollector {
        children: Vec::new(),
    };
    // SAFETY: Valid parent HWND and stack-local collector during synchronous EnumChildWindows.
    unsafe {
        let _ = EnumChildWindows(
            Some(parent),
            Some(enum_renderer_child_windows),
            LPARAM(&mut collector as *mut RendererChildCollector as isize),
        );
    }
    collector.children
}

/// Bounded per-session FIFO cache of HWNDs already warmed for Chromium/Electron UIA activation,
/// ensuring warmup probes execute at most once per HWND per session.
#[derive(Debug)]
pub struct WarmedHwndCache {
    order: VecDeque<isize>,
    set: HashSet<isize>,
    capacity: usize,
}

impl Default for WarmedHwndCache {
    fn default() -> Self {
        Self::new()
    }
}

impl WarmedHwndCache {
    pub const DEFAULT_CAPACITY: usize = 64;

    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            order: VecDeque::with_capacity(cap),
            set: HashSet::with_capacity(cap),
            capacity: cap,
        }
    }

    pub fn contains(&self, hwnd: isize) -> bool {
        hwnd != 0 && self.set.contains(&hwnd)
    }

    pub fn insert(&mut self, hwnd: isize) {
        if hwnd == 0 || self.set.contains(&hwnd) {
            return;
        }
        while self.order.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            }
        }
        self.order.push_back(hwnd);
        self.set.insert(hwnd);
    }

    pub fn clear(&mut self) {
        self.order.clear();
        self.set.clear();
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

struct TimeoutRestoreGuard<'a> {
    uia: &'a UiaClient,
    read_deadline_ms: i64,
}

impl<'a> TimeoutRestoreGuard<'a> {
    fn new(uia: &'a UiaClient, read_deadline_ms: i64) -> Self {
        Self {
            uia,
            read_deadline_ms,
        }
    }
}

impl Drop for TimeoutRestoreGuard<'_> {
    fn drop(&mut self) {
        let remaining = self
            .read_deadline_ms
            .saturating_sub(SystemCollectorClock::monotonic_ms_now());
        self.uia.apply_timeouts(remaining);
    }
}

/// Perform bounded `IUIAutomation::ElementFromHandle` warmup for Chromium/Electron/browser windows
/// (renderer child `Chrome_RenderWidgetHostHWND` / `MozillaCompositorWindowClass` windows and
/// top-level `hwnd`) when `policy.ax_compatibility == Some(true)` within a hard 100ms budget.
///
/// Uses `UIAutomationCore` (`ElementFromHandle` + lightweight `CurrentControlType`) instead of raw
/// `WM_GETOBJECT` so marshaled COM providers are cleanly consumed and released with zero `LRESULT`
/// leaks. Cached per HWND in `warmed_cache` so each HWND is warmed at most once per session.
#[allow(clippy::too_many_arguments)]
pub fn warmup_window_uia(
    uia: &UiaClient,
    hwnd: HWND,
    spec: &AppAdapterSpec,
    policy: &CapturePolicy,
    read_only: bool,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
    warmed_cache: Option<&mut WarmedHwndCache>,
) -> AxEnablementResult {
    if policy.ax_compatibility != Some(true) {
        return AxEnablementResult {
            status: "disabled".to_string(),
            attribute: "none".to_string(),
            changed: false,
        };
    }
    let attribute = match spec.activation {
        ActivationMode::None => {
            return AxEnablementResult {
                status: "unsupported".to_string(),
                attribute: "none".to_string(),
                changed: false,
            };
        }
        ActivationMode::ManualAccessibility => "manual",
        ActivationMode::EnhancedUi => "enhanced",
    };
    if read_only {
        return AxEnablementResult {
            status: "already-enabled".to_string(),
            attribute: attribute.to_string(),
            changed: false,
        };
    }
    if hwnd.0.is_null() {
        return AxEnablementResult {
            status: "write-failed".to_string(),
            attribute: attribute.to_string(),
            changed: false,
        };
    }
    let raw_hwnd = hwnd.0 as isize;
    if warmed_cache
        .as_deref()
        .is_some_and(|cache| cache.contains(raw_hwnd))
    {
        return AxEnablementResult {
            status: "already-enabled".to_string(),
            attribute: attribute.to_string(),
            changed: false,
        };
    }

    let now = clock.monotonic_ms();
    let remaining = deadline_ms.saturating_sub(now).min(100);
    if remaining < 10 {
        return AxEnablementResult {
            status: "write-failed".to_string(),
            attribute: attribute.to_string(),
            changed: false,
        };
    }

    let _restore_guard = TimeoutRestoreGuard::new(uia, deadline_ms);
    let warmup_deadline = now.saturating_add(remaining);
    let renderer_children = find_renderer_child_hwnds(hwnd);
    let mut any_ok = false;

    for child_hwnd in &renderer_children {
        let child_rem = warmup_deadline.saturating_sub(clock.monotonic_ms());
        if child_rem < 10 {
            break;
        }
        uia.apply_timeouts(child_rem.min(60));
        if uia.probe_hwnd_uia(*child_hwnd) {
            any_ok = true;
        }
    }

    let top_rem = warmup_deadline.saturating_sub(clock.monotonic_ms());
    if top_rem >= 10 {
        uia.apply_timeouts(top_rem.min(80));
        if uia.probe_hwnd_uia(hwnd) {
            any_ok = true;
        }
    }

    if any_ok {
        if let Some(cache) = warmed_cache {
            cache.insert(raw_hwnd);
        }
        AxEnablementResult {
            status: "enabled".to_string(),
            attribute: attribute.to_string(),
            changed: true,
        }
    } else {
        AxEnablementResult {
            status: "write-failed".to_string(),
            attribute: attribute.to_string(),
            changed: false,
        }
    }
}

/// RAII Multi-Threaded Apartment (MTA) COM guard. NEVER initializes STA.
///
/// NOTE: Any struct holding COM interfaces alongside `ComGuard` MUST declare all COM interface
/// fields BEFORE `ComGuard` so Rust drops COM pointers before `CoUninitialize()` executes.
pub struct ComGuard {
    should_uninit: bool,
}

impl ComGuard {
    pub fn init_mta() -> Result<Self, HRESULT> {
        ensure_per_monitor_dpi_aware();
        // SAFETY: Standard Win32 MTA COM initialization for the current thread.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr == S_OK || hr == S_FALSE {
            Ok(Self {
                should_uninit: true,
            })
        } else {
            // Reject RPC_E_CHANGED_MODE (STA) and any COM initialization error.
            Err(hr)
        }
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.should_uninit {
            // SAFETY: Balanced with `CoInitializeEx` returning S_OK / S_FALSE on this thread.
            unsafe {
                CoUninitialize();
            }
        }
    }
}

/// Classification of UIA COM failures distinguishing UIPI access denial from generic provider errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiaCallError {
    AccessDenied,
    Unavailable,
}

impl UiaCallError {
    pub fn from_error(err: &windows::core::Error) -> Self {
        if err.code() == E_ACCESSDENIED {
            Self::AccessDenied
        } else {
            Self::Unavailable
        }
    }
}

/// Safe pre-read metadata snapshot for a single UIA element.
///
/// INVARIANT: Never fetches `Value` or `Text` patterns; whenever `is_password == Value(true)` or
/// any sensitive indicator is observed, `name` and `automation_id` are immediately cleared to `None`.
#[derive(Debug, Clone)]
pub struct UiaElementMetadata {
    pub runtime_id: RuntimeIdKey,
    pub process_id: u32,
    pub control_type: i32,
    pub is_password: ProtectedContentRead,
    pub is_enabled: Option<bool>,
    pub is_control_element: Option<bool>,
    pub is_content_element: Option<bool>,
    pub is_offscreen: Option<bool>,
    pub is_keyboard_focusable: Option<bool>,
    pub has_keyboard_focus: Option<bool>,
    pub native_hwnd: Option<HWND>,
    pub name: Option<String>,
    pub localized_control_type: Option<String>,
    pub automation_id: Option<String>,
    pub class_name: Option<String>,
    pub aria_role: Option<String>,
    pub aria_properties: Option<String>,
    pub landmark_type: Option<i32>,
    pub help_text: Option<String>,
    pub full_description: Option<String>,
    pub heading_level: i32,
    pub supports_text_pattern: bool,
    pub supports_text_pattern2: bool,
    pub supports_value_pattern: bool,
    pub supports_scroll_pattern: bool,
    pub value_is_read_only: Option<bool>,
    pub is_read_only: bool,
    pub logical_rect: Option<SurfaceAbsoluteRect>,
    pub subrole_read: SubroleRead,
    pub mapped: MappedRole,
}

impl UiaElementMetadata {
    pub fn is_sensitive(&self) -> bool {
        self.mapped.ax_role == Some("AXSecureTextField")
            || self.is_password == ProtectedContentRead::Value(true)
            || matches!(
                &self.subrole_read,
                SubroleRead::Value(v) if crate::policy::TextSecurityGate::is_sensitive_subrole(v)
            )
    }

    /// Safe pre-cached description (`HelpText` or `FullDescription`), always `None` when sensitive.
    pub fn safe_description(&self) -> Option<&str> {
        if self.is_sensitive() {
            return None;
        }
        self.help_text
            .as_deref()
            .or(self.full_description.as_deref())
    }

    /// True when this element is a focused editable `contenteditable` composer (`Group`/`Custom`/
    /// `Document` with `TextPattern` + non-password + editable proof) suitable for focused
    /// `text.snapshot` extraction without changing surface container traversal.
    pub fn is_focused_editable_content(&self) -> bool {
        crate::policy::is_focused_editable_content_control(
            self.control_type,
            self.is_password,
            self.supports_text_pattern || self.supports_text_pattern2,
            self.supports_value_pattern,
            self.value_is_read_only,
            self.is_keyboard_focusable,
            self.has_keyboard_focus,
            self.aria_role.as_deref(),
            self.class_name.as_deref(),
        )
    }

    pub fn is_multiline_edit(&self) -> bool {
        if self.control_type == 50004
            && (self.supports_text_pattern || self.supports_text_pattern2)
        {
            // Single-line Win32 EDIT vs multiline RichEdit/EDIT: check ES_MULTILINE window style
            // if native HWND is available; otherwise treat TextPattern-capable Edit as multiline
            // only when aria_role/class indicates multiline or height > 44pt.
            if let Some(hwnd) = self.native_hwnd {
                if !hwnd.0.is_null() {
                    // ES_MULTILINE = 0x0004
                    let style = get_window_style(hwnd);
                    return (style & 0x0004) != 0;
                }
            }
            if aria_properties_has_multiline(self.aria_properties.as_deref()) {
                return true;
            }
            if let Some(ref class_name) = self.class_name {
                let lower = class_name.to_ascii_lowercase();
                if lower.contains("richedit") {
                    return true;
                }
            }
            if let Some(rect) = self.logical_rect {
                return rect.height >= 44.0;
            }
            return true;
        }
        self.supports_text_pattern || self.supports_text_pattern2
    }
}

fn get_window_style(hwnd: HWND) -> u32 {
    use windows::Win32::UI::WindowsAndMessaging::{GetWindowLongW, GWL_STYLE};
    // SAFETY: Standard Win32 style inspection on live HWND.
    unsafe { GetWindowLongW(hwnd, GWL_STYLE) as u32 }
}

/// RAII wrapper for raw `*mut SAFEARRAY` returned by `IUIAutomationElement::GetRuntimeId`.
struct OwnedSafeArray(*mut SAFEARRAY);

impl Drop for OwnedSafeArray {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Owned SAFEARRAY returned directly by COM out-parameter.
            unsafe {
                let _ = SafeArrayDestroy(self.0);
            }
        }
    }
}

fn read_i32_safearray(psa: *mut SAFEARRAY) -> Option<Vec<i32>> {
    const MAX_I32_SAFEARRAY_ELEMENTS: i64 = 4_096;
    if psa.is_null() {
        return None;
    }
    // SAFETY: Caller passes a SAFEARRAY pointer; dimensions, element byte width, and bounds are
    // strictly validated in i64 before accessing data, and SafeArrayUnaccessData always runs.
    unsafe {
        if (*psa).cDims != 1 || (*psa).cbElements != std::mem::size_of::<i32>() as u32 {
            return None;
        }
        let lbound = SafeArrayGetLBound(psa, 1).ok()?;
        let ubound = SafeArrayGetUBound(psa, 1).ok()?;
        let count = i64::from(ubound) - i64::from(lbound) + 1;
        if !(0..=MAX_I32_SAFEARRAY_ELEMENTS).contains(&count) {
            return None;
        }
        if count == 0 {
            return Some(Vec::new());
        }
        let len = count as usize;
        let mut ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        SafeArrayAccessData(psa, &mut ptr).ok()?;
        let out = if ptr.is_null() {
            None
        } else {
            let mut values = Vec::with_capacity(len);
            let base = ptr as *const i32;
            for i in 0..len {
                values.push(core::ptr::read_unaligned(base.add(i)));
            }
            Some(values)
        };
        let _ = SafeArrayUnaccessData(psa);
        out
    }
}

fn variant_as_bool(var: &VARIANT) -> Option<bool> {
    if var.vt() != VT_BOOL {
        return None;
    }
    // SAFETY: Checked vt == VT_BOOL.
    unsafe { Some(var.Anonymous.Anonymous.Anonymous.boolVal.as_bool()) }
}

fn variant_as_i32(var: &VARIANT) -> Option<i32> {
    if var.vt() != VT_I4 {
        return None;
    }
    // SAFETY: Checked vt == VT_I4.
    unsafe { Some(var.Anonymous.Anonymous.Anonymous.lVal) }
}

fn variant_as_i32_array(var: &VARIANT) -> Option<Vec<i32>> {
    // Strictly require exact `VT_ARRAY | VT_I4` (rejecting VT_BYREF and any other flag bits).
    if var.vt().0 != (VT_ARRAY.0 | VT_I4.0) {
        return None;
    }
    // SAFETY: Exact vt == (VT_ARRAY | VT_I4). VARIANT Drop calls VariantClear so we do NOT destroy parray.
    let psa = unsafe { var.Anonymous.Anonymous.Anonymous.parray };
    read_i32_safearray(psa)
}

fn cached_bool_prop(elem: &IUIAutomationElement, prop_id: windows::Win32::UI::Accessibility::UIA_PROPERTY_ID) -> Option<bool> {
    // SAFETY: Standard cached property lookup.
    let var = unsafe { elem.GetCachedPropertyValue(prop_id).ok()? };
    variant_as_bool(&var)
}

fn cached_i32_prop(elem: &IUIAutomationElement, prop_id: windows::Win32::UI::Accessibility::UIA_PROPERTY_ID) -> Option<i32> {
    // SAFETY: Standard cached property lookup.
    let var = unsafe { elem.GetCachedPropertyValue(prop_id).ok()? };
    variant_as_i32(&var)
}

fn cached_bstr_prop(elem: &IUIAutomationElement, prop_id: windows::Win32::UI::Accessibility::UIA_PROPERTY_ID) -> Option<String> {
    // SAFETY: Standard cached property lookup; borrows BSTR inside VARIANT without taking ownership.
    let var = unsafe { elem.GetCachedPropertyValue(prop_id).ok()? };
    if var.vt() != VT_BSTR {
        return None;
    }
    let s = unsafe { (*var.Anonymous.Anonymous.Anonymous.bstrVal).to_string() };
    (!s.is_empty()).then_some(s)
}

fn non_empty_bstr(bstr: windows::core::BSTR) -> Option<String> {
    let s = bstr.to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// 3-state fail-closed verdict returned by `UiaClient::is_private_browser_window_chrome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateChromeVerdict {
    /// Unambiguous private/incognito/InPrivate native browser chrome indicator detected.
    Private,
    /// Native browser frame chrome scanned completely within bounds with zero private indicators.
    VerifiedNormal,
    /// Probe hit deadline, node/depth/sibling budget cap, or UIA traversal error — callers MUST fail closed.
    Inconclusive,
}

const BOOKMARK_TOOLBAR_KEYWORDS: &[&str] = &[
    "bookmark",
    "favorite",
    "书签",
    "書籤",
    "收藏夹",
    "收藏夾",
    "ブックマーク",
    "お気に入り",
    "북마크",
    "즐겨찾기",
    "lesezeichen",
    "marque-pages",
    "favoris",
    "marcadores",
    "segnalibri",
    "preferiti",
    "закладки",
    "избранное",
];

/// Pure predicate deciding whether a browser UIA node belongs to web content, open tabs, address
/// edits, menus, extensions, or bookmark toolbars (including Firefox `PersonalToolbar` / bookmark
/// `ToolBar` without `Chrome_*` class names) and MUST be skipped cleanly without consuming the
/// chrome-probe node budget.
pub fn should_skip_chrome_probe_node(
    control_type: i32,
    class_name: Option<&str>,
    automation_id: Option<&str>,
    name: Option<&str>,
) -> bool {
    // HARD PRIVACY & FALSE-POSITIVE GATE: NEVER enter web Document content, open tabs,
    // address bar / text edits, menus, or scrollbars.
    if matches!(
        control_type,
        50030 | 50018 | 50019 | 50004 | 50009 | 50010 | 50011 | 50014
    ) {
        return true;
    }

    if let Some(cls) = class_name {
        if cls.eq_ignore_ascii_case("Chrome_RenderWidgetHostHWND")
            || cls.eq_ignore_ascii_case("MozillaCompositorWindowClass")
            || cls.eq_ignore_ascii_case("BookmarkBarView")
            || cls.eq_ignore_ascii_case("BookmarkButton")
            || cls.eq_ignore_ascii_case("FavoritesBar")
            || cls.eq_ignore_ascii_case("ToolbarActionView")
            || cls.eq_ignore_ascii_case("ExtensionsToolbarContainer")
        {
            return true;
        }
    }

    if let Some(aid) = automation_id {
        if aid.eq_ignore_ascii_case("PersonalToolbar")
            || aid.eq_ignore_ascii_case("PlacesToolbar")
            || aid.eq_ignore_ascii_case("PlacesToolbarItems")
            || aid.eq_ignore_ascii_case("bookmarks-menu-button")
            || aid.eq_ignore_ascii_case("sidebar-box")
        {
            return true;
        }
    }

    // Exclude Firefox / Chromium / Edge bookmark & favorites toolbars (especially Firefox ToolBar
    // containers lacking Chromium `Chrome_*` class names where user-titled bookmark items live).
    if control_type == 50021 {
        let is_chromium_class = class_name.is_some_and(|cls| {
            cls.len() >= 7 && cls.as_bytes()[..7].eq_ignore_ascii_case(b"chrome_")
        });
        if !is_chromium_class {
            if let Some(aid) = automation_id {
                let lower_aid = aid.to_ascii_lowercase();
                if lower_aid.contains("bookmark")
                    || lower_aid.contains("places")
                    || lower_aid.contains("favorite")
                {
                    return true;
                }
            }
            if let Some(label) = name {
                let lower_name = label.to_lowercase();
                if BOOKMARK_TOOLBAR_KEYWORDS
                    .iter()
                    .any(|kw| lower_name.contains(kw))
                {
                    return true;
                }
            }
        }
    }

    false
}

enum ChromeWalkStep {
    Element(IUIAutomationElement),
    End,
    Error(UiaCallError),
}

fn classify_chrome_walk(res: windows::core::Result<IUIAutomationElement>) -> ChromeWalkStep {
    match res {
        Ok(el) => ChromeWalkStep::Element(el),
        Err(e) if e.code() == S_OK || e.code() == S_FALSE => ChromeWalkStep::End,
        Err(e) if e.code() == E_ACCESSDENIED => ChromeWalkStep::Error(UiaCallError::AccessDenied),
        Err(_) => ChromeWalkStep::Error(UiaCallError::Unavailable),
    }
}

/// MTA `IUIAutomation` client holding cached walker and pre-read metadata `IUIAutomationCacheRequest`.
pub struct UiaClient {
    automation: IUIAutomation,
    automation2: Option<IUIAutomation2>,
    walker: IUIAutomationTreeWalker,
    metadata_cache: IUIAutomationCacheRequest,
    chrome_probe_cache: IUIAutomationCacheRequest,
}

impl UiaClient {
    pub fn new() -> Result<Self, UiaCallError> {
        // SAFETY: Caller has initialized MTA COM on this thread via `ComGuard`.
        let automation: IUIAutomation = unsafe {
            CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER)
                .or_else(|_| CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER))
                .map_err(|e| UiaCallError::from_error(&e))?
        };
        let automation2 = automation.cast::<IUIAutomation2>().ok();
        // SAFETY: Standard UIA ControlViewWalker and CacheRequest creation.
        let walker = unsafe {
            automation
                .ControlViewWalker()
                .map_err(|e| UiaCallError::from_error(&e))?
        };
        let metadata_cache = Self::build_safe_metadata_cache(&automation)?;
        let chrome_probe_cache = Self::build_chrome_probe_cache(&automation)?;
        Ok(Self {
            automation,
            automation2,
            walker,
            metadata_cache,
            chrome_probe_cache,
        })
    }

    fn build_chrome_probe_cache(
        automation: &IUIAutomation,
    ) -> Result<IUIAutomationCacheRequest, UiaCallError> {
        // SAFETY: Minimal 4-property cache request for pre-read private browser chrome detection.
        // INVARIANT: NEVER add Value/Text/LegacyIAccessibleValue properties!
        unsafe {
            let req = automation
                .CreateCacheRequest()
                .map_err(|e| UiaCallError::from_error(&e))?;
            for prop in [
                UIA_ControlTypePropertyId,
                UIA_ClassNamePropertyId,
                UIA_AutomationIdPropertyId,
                UIA_NamePropertyId,
            ] {
                let _ = req.AddProperty(prop);
            }
            Ok(req)
        }
    }

    fn build_safe_metadata_cache(
        automation: &IUIAutomation,
    ) -> Result<IUIAutomationCacheRequest, UiaCallError> {
        // SAFETY: Adding ONLY safe pre-read metadata property IDs.
        // INVARIANT: NEVER add UIA_ValueValuePropertyId, UIA_LegacyIAccessibleValuePropertyId,
        // or UIA_TextPatternId/UIA_ValuePatternId to the pre-read cache request!
        unsafe {
            let req = automation
                .CreateCacheRequest()
                .map_err(|e| UiaCallError::from_error(&e))?;
            for prop in [
                UIA_ControlTypePropertyId,
                UIA_LocalizedControlTypePropertyId,
                UIA_IsPasswordPropertyId,
                UIA_IsEnabledPropertyId,
                UIA_NamePropertyId,
                UIA_AutomationIdPropertyId,
                UIA_BoundingRectanglePropertyId,
                UIA_ProcessIdPropertyId,
                UIA_RuntimeIdPropertyId,
                UIA_ClassNamePropertyId,
                UIA_AriaRolePropertyId,
                UIA_AriaPropertiesPropertyId,
                UIA_LandmarkTypePropertyId,
                UIA_HelpTextPropertyId,
                UIA_FullDescriptionPropertyId,
                UIA_IsControlElementPropertyId,
                UIA_IsContentElementPropertyId,
                UIA_IsOffscreenPropertyId,
                UIA_IsKeyboardFocusablePropertyId,
                UIA_IsTextPatternAvailablePropertyId,
                UIA_IsTextPattern2AvailablePropertyId,
                UIA_IsValuePatternAvailablePropertyId,
                UIA_IsScrollPatternAvailablePropertyId,
                UIA_ValueIsReadOnlyPropertyId,
                UIA_HeadingLevelPropertyId,
                UIA_HasKeyboardFocusPropertyId,
                UIA_NativeWindowHandlePropertyId,
            ] {
                let _ = req.AddProperty(prop);
            }
            Ok(req)
        }
    }

    /// Clamp `IUIAutomation2` connection and transaction timeouts to the remaining read deadline
    /// (never 0 or unbounded).
    pub fn apply_timeouts(&self, remaining_ms: i64) {
        if let Some(ref uia2) = self.automation2 {
            let tx_ms = remaining_ms.clamp(25, 5_000) as u32;
            let conn_ms = tx_ms.clamp(25, 500);
            // SAFETY: Valid bounded non-zero timeout values in milliseconds.
            unsafe {
                let _ = uia2.SetConnectionTimeout(conn_ms);
                let _ = uia2.SetTransactionTimeout(tx_ms);
            }
        }
    }

    /// Lightweight `IUIAutomation::ElementFromHandle` + `CurrentControlType` warmup probe.
    /// Cleanly hydrates Chromium/Electron/Mozilla UIA trees via `UIAutomationCore` and drops the
    /// COM reference immediately on scope exit (eliminating raw `WM_GETOBJECT` `LRESULT` leaks).
    pub fn probe_hwnd_uia(&self, hwnd: HWND) -> bool {
        if hwnd.0.is_null() {
            return false;
        }
        // SAFETY: Valid live HWND; UIAutomationCore owns provider marshaling & cleanup.
        let Ok(el) = (unsafe { self.automation.ElementFromHandle(hwnd) }) else {
            return false;
        };
        let _ = unsafe { el.CurrentControlType() };
        true
    }

    pub fn element_from_hwnd(&self, hwnd: HWND) -> Result<IUIAutomationElement, UiaCallError> {
        // SAFETY: Valid live HWND and pre-built safe metadata cache request.
        unsafe {
            self.automation
                .ElementFromHandleBuildCache(hwnd, &self.metadata_cache)
                .map_err(|e| UiaCallError::from_error(&e))
        }
    }

    pub fn focused_element(&self) -> Result<IUIAutomationElement, UiaCallError> {
        // SAFETY: Fetches currently focused UIA element with safe metadata cache only.
        unsafe {
            self.automation
                .GetFocusedElementBuildCache(&self.metadata_cache)
                .map_err(|e| UiaCallError::from_error(&e))
        }
    }

    pub fn refresh_metadata(
        &self,
        elem: &IUIAutomationElement,
    ) -> Result<IUIAutomationElement, UiaCallError> {
        // SAFETY: Re-fetches safe cached metadata properties on an existing element.
        unsafe {
            elem.BuildUpdatedCache(&self.metadata_cache)
                .map_err(|e| UiaCallError::from_error(&e))
        }
    }

    pub fn parent_element(
        &self,
        elem: &IUIAutomationElement,
    ) -> Result<Option<IUIAutomationElement>, UiaCallError> {
        // SAFETY: ControlViewWalker parent lookup with safe metadata cache.
        match unsafe {
            self.walker
                .GetParentElementBuildCache(elem, &self.metadata_cache)
        } {
            Ok(parent) => Ok(Some(parent)),
            Err(e) if e.code() == S_OK => Ok(None),
            Err(e) => {
                let ce = UiaCallError::from_error(&e);
                if ce == UiaCallError::AccessDenied {
                    Err(ce)
                } else {
                    Ok(None)
                }
            }
        }
    }

    pub fn first_child_element(
        &self,
        elem: &IUIAutomationElement,
    ) -> Result<Option<IUIAutomationElement>, UiaCallError> {
        // SAFETY: ControlViewWalker first child lookup with safe metadata cache.
        match unsafe {
            self.walker
                .GetFirstChildElementBuildCache(elem, &self.metadata_cache)
        } {
            Ok(child) => Ok(Some(child)),
            Err(e) if e.code() == E_ACCESSDENIED => Err(UiaCallError::AccessDenied),
            Err(_) => Ok(None),
        }
    }

    pub fn next_sibling_element(
        &self,
        elem: &IUIAutomationElement,
    ) -> Result<Option<IUIAutomationElement>, UiaCallError> {
        // SAFETY: ControlViewWalker next sibling lookup with safe metadata cache.
        match unsafe {
            self.walker
                .GetNextSiblingElementBuildCache(elem, &self.metadata_cache)
        } {
            Ok(sib) => Ok(Some(sib)),
            Err(e) if e.code() == E_ACCESSDENIED => Err(UiaCallError::AccessDenied),
            Err(_) => Ok(None),
        }
    }

    pub fn last_child_element(
        &self,
        elem: &IUIAutomationElement,
    ) -> Result<Option<IUIAutomationElement>, UiaCallError> {
        // SAFETY: ControlViewWalker last child lookup with safe metadata cache.
        match unsafe {
            self.walker
                .GetLastChildElementBuildCache(elem, &self.metadata_cache)
        } {
            Ok(child) => Ok(Some(child)),
            Err(e) if e.code() == E_ACCESSDENIED => Err(UiaCallError::AccessDenied),
            Err(_) => Ok(None),
        }
    }

    pub fn previous_sibling_element(
        &self,
        elem: &IUIAutomationElement,
    ) -> Result<Option<IUIAutomationElement>, UiaCallError> {
        // SAFETY: ControlViewWalker previous sibling lookup with safe metadata cache.
        match unsafe {
            self.walker
                .GetPreviousSiblingElementBuildCache(elem, &self.metadata_cache)
        } {
            Ok(sib) => Ok(Some(sib)),
            Err(e) if e.code() == E_ACCESSDENIED => Err(UiaCallError::AccessDenied),
            Err(_) => Ok(None),
        }
    }

    /// Bounded 3-state fail-closed inspection of a browser window's **non-Document** native frame
    /// chrome to detect Windows Incognito / InPrivate / Private Browsing windows whose
    /// `GetWindowTextW` omits private indicators on navigated tabs.
    ///
    /// - Returns `PrivateChromeVerdict::Private` if any non-skipped chrome badge/button matches
    ///   `BrowserGate::is_private_chrome_indicator` (`crate::policy::is_private_chrome_label`).
    /// - Returns `PrivateChromeVerdict::VerifiedNormal` ONLY when the chrome scan completes cleanly
    ///   without deadline expiry, node/depth/sibling budget exhaustion, or UIA traversal errors.
    /// - Returns `PrivateChromeVerdict::Inconclusive` (or `Err(AccessDenied)`) otherwise so callers
    ///   fail closed.
    /// - ALWAYS restores `IUIAutomation2` timeouts to `restore_read_deadline_ms` on every exit path.
    ///
    /// PRIVACY INVARIANT: Uses `chrome_probe_cache` (`ControlType`, `ClassName`, `AutomationId`,
    /// `Name` ONLY — NEVER `Value` or `Text`), and skips `Document`, `Tab`, `TabItem`, `Edit`,
    /// menus, scrollbars, and bookmark toolbars (`BookmarkBarView` / Firefox `PersonalToolbar`)
    /// without consuming the chrome node budget.
    pub fn is_private_browser_window_chrome(
        &self,
        hwnd: HWND,
        chrome_deadline_ms: i64,
        restore_read_deadline_ms: i64,
    ) -> Result<PrivateChromeVerdict, UiaCallError> {
        const MAX_CHROME_NODES: usize = 128;
        const MAX_CHROME_DEPTH: usize = 16;
        const MAX_SIBLING_HOPS: usize = 96;

        let _restore_guard = TimeoutRestoreGuard::new(self, restore_read_deadline_ms);

        if hwnd.0.is_null() {
            return Ok(PrivateChromeVerdict::Inconclusive);
        }
        let now = SystemCollectorClock::monotonic_ms_now();
        let effective_deadline = chrome_deadline_ms.min(restore_read_deadline_ms);
        if now >= effective_deadline {
            return Ok(PrivateChromeVerdict::Inconclusive);
        }
        self.apply_timeouts(effective_deadline.saturating_sub(now));

        // SAFETY: Valid live HWND and minimal 4-property chrome probe cache request.
        let root = match unsafe {
            self.automation
                .ElementFromHandleBuildCache(hwnd, &self.chrome_probe_cache)
        } {
            Ok(el) => el,
            Err(e) if e.code() == E_ACCESSDENIED => return Err(UiaCallError::AccessDenied),
            Err(_) => return Ok(PrivateChromeVerdict::Inconclusive),
        };

        let mut queue: VecDeque<(IUIAutomationElement, usize)> = VecDeque::with_capacity(32);
        queue.push_back((root, 0));
        let mut inspected: usize = 0;
        let mut truncated = false;

        while let Some((elem, depth)) = queue.pop_front() {
            if SystemCollectorClock::monotonic_ms_now() >= effective_deadline {
                return Ok(PrivateChromeVerdict::Inconclusive);
            }

            // SAFETY: Reads strictly from pre-populated 4-property chrome_probe_cache.
            let control_type = match unsafe { elem.CachedControlType() } {
                Ok(ct) => ct.0,
                Err(e) if e.code() == E_ACCESSDENIED => return Err(UiaCallError::AccessDenied),
                Err(_) => return Ok(PrivateChromeVerdict::Inconclusive),
            };
            let class_name = unsafe { elem.CachedClassName().ok().and_then(non_empty_bstr) };
            let automation_id =
                unsafe { elem.CachedAutomationId().ok().and_then(non_empty_bstr) };
            let name = unsafe { elem.CachedName().ok().and_then(non_empty_bstr) };

            if should_skip_chrome_probe_node(
                control_type,
                class_name.as_deref(),
                automation_id.as_deref(),
                name.as_deref(),
            ) {
                continue;
            }

            if inspected >= MAX_CHROME_NODES {
                return Ok(PrivateChromeVerdict::Inconclusive);
            }
            inspected += 1;

            // Check labels on Button/Image/Text/Custom controls (Custom is counted once here when popped).
            if matches!(control_type, 50000 | 50006 | 50020 | 50025) {
                if let Some(ref label) = name {
                    if BrowserGate::is_private_chrome_indicator(class_name.as_deref(), label) {
                        return Ok(PrivateChromeVerdict::Private);
                    }
                }
            }

            // Only descend into native chrome container controls.
            if !matches!(
                control_type,
                50032 | 50033 | 50026 | 50021 | 50037 | 50025 | 50034
            ) {
                continue;
            }
            if depth >= MAX_CHROME_DEPTH {
                truncated = true;
                continue;
            }

            // On ToolBar (50021), walk tail-to-head because Chromium/Edge/Firefox place the
            // profile/Incognito/InPrivate toolbar button near the right end of the toolbar.
            let remaining =
                effective_deadline.saturating_sub(SystemCollectorClock::monotonic_ms_now());
            if remaining <= 0 {
                return Ok(PrivateChromeVerdict::Inconclusive);
            }
            self.apply_timeouts(remaining);
            let walk_tail_first = control_type == 50021;
            let first_step = if walk_tail_first {
                classify_chrome_walk(unsafe {
                    self.walker
                        .GetLastChildElementBuildCache(&elem, &self.chrome_probe_cache)
                })
            } else {
                classify_chrome_walk(unsafe {
                    self.walker
                        .GetFirstChildElementBuildCache(&elem, &self.chrome_probe_cache)
                })
            };
            let mut cur = match first_step {
                ChromeWalkStep::Element(c) => Some(c),
                ChromeWalkStep::End => None,
                ChromeWalkStep::Error(UiaCallError::AccessDenied) => {
                    return Err(UiaCallError::AccessDenied);
                }
                ChromeWalkStep::Error(UiaCallError::Unavailable) => {
                    return Ok(PrivateChromeVerdict::Inconclusive);
                }
            };

            let mut siblings_walked: usize = 0;
            let mut priority_children: Vec<(IUIAutomationElement, usize)> = Vec::new();
            while let Some(child) = cur {
                if SystemCollectorClock::monotonic_ms_now() >= effective_deadline {
                    return Ok(PrivateChromeVerdict::Inconclusive);
                }
                if siblings_walked >= MAX_SIBLING_HOPS {
                    truncated = true;
                    break;
                }
                siblings_walked += 1;

                let child_ct = match unsafe { child.CachedControlType() } {
                    Ok(ct) => ct.0,
                    Err(e) if e.code() == E_ACCESSDENIED => {
                        return Err(UiaCallError::AccessDenied);
                    }
                    Err(_) => return Ok(PrivateChromeVerdict::Inconclusive),
                };
                let child_cls =
                    unsafe { child.CachedClassName().ok().and_then(non_empty_bstr) };
                let child_aid =
                    unsafe { child.CachedAutomationId().ok().and_then(non_empty_bstr) };
                let child_name = unsafe { child.CachedName().ok().and_then(non_empty_bstr) };

                if !should_skip_chrome_probe_node(
                    child_ct,
                    child_cls.as_deref(),
                    child_aid.as_deref(),
                    child_name.as_deref(),
                ) {
                    let is_container = matches!(
                        child_ct,
                        50032 | 50033 | 50026 | 50021 | 50037 | 50025 | 50034
                    );
                    if is_container {
                        // Enqueue container (including Custom 50025) so it is counted & checked
                        // exactly once when popped from `queue` (never double-counted).
                        if inspected + queue.len() + priority_children.len() < MAX_CHROME_NODES {
                            if matches!(child_ct, 50021 | 50037) || walk_tail_first {
                                priority_children.push((child.clone(), depth + 1));
                            } else {
                                queue.push_back((child.clone(), depth + 1));
                            }
                        } else {
                            truncated = true;
                        }
                    } else if matches!(child_ct, 50000 | 50006 | 50020) {
                        if inspected >= MAX_CHROME_NODES {
                            return Ok(PrivateChromeVerdict::Inconclusive);
                        }
                        inspected += 1;
                        if let Some(ref label) = child_name {
                            if BrowserGate::is_private_chrome_indicator(
                                child_cls.as_deref(),
                                label,
                            ) {
                                return Ok(PrivateChromeVerdict::Private);
                            }
                        }
                    }
                }

                let remaining =
                    effective_deadline.saturating_sub(SystemCollectorClock::monotonic_ms_now());
                if remaining <= 0 {
                    return Ok(PrivateChromeVerdict::Inconclusive);
                }
                self.apply_timeouts(remaining);
                let next_step = if walk_tail_first {
                    classify_chrome_walk(unsafe {
                        self.walker
                            .GetPreviousSiblingElementBuildCache(&child, &self.chrome_probe_cache)
                    })
                } else {
                    classify_chrome_walk(unsafe {
                        self.walker
                            .GetNextSiblingElementBuildCache(&child, &self.chrome_probe_cache)
                    })
                };
                cur = match next_step {
                    ChromeWalkStep::Element(sib) => Some(sib),
                    ChromeWalkStep::End => None,
                    ChromeWalkStep::Error(UiaCallError::AccessDenied) => {
                        return Err(UiaCallError::AccessDenied);
                    }
                    ChromeWalkStep::Error(UiaCallError::Unavailable) => {
                        return Ok(PrivateChromeVerdict::Inconclusive);
                    }
                };
            }
            // Push prioritized children in reverse so tail-first / ToolBar order is preserved at front.
            for item in priority_children.into_iter().rev() {
                queue.push_front(item);
            }
        }

        if truncated {
            Ok(PrivateChromeVerdict::Inconclusive)
        } else {
            Ok(PrivateChromeVerdict::VerifiedNormal)
        }
    }

    /// Enumerate direct ControlView children (bounded to `cap` elements) using the cached walker.
    pub fn direct_children_bounded(
        &self,
        elem: &IUIAutomationElement,
        cap: usize,
        mut can_continue: impl FnMut() -> bool,
    ) -> Result<Vec<IUIAutomationElement>, UiaCallError> {
        let mut out = Vec::new();
        if cap == 0 || !can_continue() {
            return Ok(out);
        }
        let mut cur = self.first_child_element(elem)?;
        while let Some(child) = cur {
            out.push(child.clone());
            if out.len() >= cap || !can_continue() {
                break;
            }
            cur = self.next_sibling_element(&child)?;
        }
        Ok(out)
    }

    /// Extract the `RuntimeIdKey` from a cached element (falling back to live `GetRuntimeId`).
    pub fn runtime_id(&self, elem: &IUIAutomationElement) -> Option<RuntimeIdKey> {
        // SAFETY: Read cached VT_ARRAY|VT_I4 RuntimeId first to avoid an extra cross-process call.
        if let Ok(var) = unsafe { elem.GetCachedPropertyValue(UIA_RuntimeIdPropertyId) } {
            if let Some(ids) = variant_as_i32_array(&var) {
                if !ids.is_empty() {
                    return Some(RuntimeIdKey(ids));
                }
            }
        }
        // SAFETY: Fallback live GetRuntimeId; OwnedSafeArray frees the returned SAFEARRAY on drop.
        let psa = unsafe { elem.GetRuntimeId().ok()? };
        let guard = OwnedSafeArray(psa);
        let ids = read_i32_safearray(guard.0)?;
        (!ids.is_empty()).then_some(RuntimeIdKey(ids))
    }

    /// Decode pre-cached safe metadata from an `IUIAutomationElement`.
    ///
    /// PRIVACY INVARIANT: Checks `UIA_IsPasswordPropertyId` FIRST; if `true` or any sensitive
    /// subrole/aria indicator is present, `name` and `automation_id` are suppressed immediately.
    pub fn read_cached_metadata(
        &self,
        elem: &IUIAutomationElement,
        dpi: u32,
        has_children_hint: bool,
        is_terminal_app: bool,
    ) -> Result<UiaElementMetadata, UiaCallError> {
        // SAFETY: All calls read strictly from the pre-populated metadata cache.
        let is_password = match unsafe { elem.CachedIsPassword() } {
            Ok(b) => ProtectedContentRead::Value(b.as_bool()),
            Err(e) if e.code() == E_ACCESSDENIED => return Err(UiaCallError::AccessDenied),
            Err(_) => ProtectedContentRead::Failure,
        };

        let control_type = match unsafe { elem.CachedControlType() } {
            Ok(ct) => ct.0,
            Err(e) if e.code() == E_ACCESSDENIED => return Err(UiaCallError::AccessDenied),
            Err(_) => 0,
        };

        let process_id = match unsafe { elem.CachedProcessId() } {
            Ok(pid) if pid > 0 => pid as u32,
            Err(e) if e.code() == E_ACCESSDENIED => return Err(UiaCallError::AccessDenied),
            _ => 0,
        };

        let runtime_id = self
            .runtime_id(elem)
            .unwrap_or_else(|| RuntimeIdKey(Vec::new()));

        let is_enabled = unsafe { elem.CachedIsEnabled().ok().map(|b| b.as_bool()) };
        let is_control_element = unsafe { elem.CachedIsControlElement().ok().map(|b| b.as_bool()) };
        let is_content_element = unsafe { elem.CachedIsContentElement().ok().map(|b| b.as_bool()) };
        let is_offscreen = unsafe { elem.CachedIsOffscreen().ok().map(|b| b.as_bool()) };
        let is_keyboard_focusable =
            unsafe { elem.CachedIsKeyboardFocusable().ok().map(|b| b.as_bool()) };
        let has_keyboard_focus = unsafe { elem.CachedHasKeyboardFocus().ok().map(|b| b.as_bool()) };
        let native_hwnd = unsafe {
            elem.CachedNativeWindowHandle()
                .ok()
                .filter(|h| !h.0.is_null())
        };

        let localized_control_type = unsafe {
            elem.CachedLocalizedControlType()
                .ok()
                .and_then(non_empty_bstr)
        };
        let class_name = unsafe { elem.CachedClassName().ok().and_then(non_empty_bstr) };
        let aria_role = unsafe { elem.CachedAriaRole().ok().and_then(non_empty_bstr) };
        let landmark_type = cached_i32_prop(elem, UIA_LandmarkTypePropertyId);
        let heading_level =
            cached_i32_prop(elem, UIA_HeadingLevelPropertyId).unwrap_or(HeadingLevel_None.0);

        let supports_text_pattern =
            cached_bool_prop(elem, UIA_IsTextPatternAvailablePropertyId).unwrap_or(false);
        let supports_text_pattern2 =
            cached_bool_prop(elem, UIA_IsTextPattern2AvailablePropertyId).unwrap_or(false);
        let supports_value_pattern =
            cached_bool_prop(elem, UIA_IsValuePatternAvailablePropertyId).unwrap_or(false);
        let supports_scroll_pattern =
            cached_bool_prop(elem, UIA_IsScrollPatternAvailablePropertyId).unwrap_or(false);
        let value_is_read_only = cached_bool_prop(elem, UIA_ValueIsReadOnlyPropertyId);
        let is_read_only = value_is_read_only.unwrap_or(false);

        let logical_rect = unsafe { elem.CachedBoundingRectangle().ok() }.and_then(|r| {
            let w = (i64::from(r.right) - i64::from(r.left)) as f64;
            let h = (i64::from(r.bottom) - i64::from(r.top)) as f64;
            if w < 0.0 || h < 0.0 {
                return None;
            }
            SurfaceAbsoluteRect::from_physical_pixels(r.left as f64, r.top as f64, w, h, dpi)
        });

        let is_password_bool = is_password == ProtectedContentRead::Value(true);

        // Determine sensitive subrole evidence from AriaRole / LocalizedControlType before reading
        // Name, AutomationId, HelpText, FullDescription, or AriaProperties.
        let sensitive_aria = aria_role
            .as_deref()
            .is_some_and(crate::policy::TextSecurityGate::is_sensitive_subrole);
        let sensitive_lct = localized_control_type
            .as_deref()
            .is_some_and(crate::policy::TextSecurityGate::is_sensitive_subrole);
        let effective_password = is_password_bool || sensitive_aria || sensitive_lct;

        // PRIVACY INVARIANT: Never retain Name, AutomationId, HelpText, FullDescription, or
        // AriaProperties for password/sensitive controls!
        let (name, automation_id, help_text, full_description, aria_properties) =
            if effective_password {
                (None, None, None, None, None)
            } else {
                let n = unsafe { elem.CachedName().ok().and_then(non_empty_bstr) };
                let a = unsafe { elem.CachedAutomationId().ok().and_then(non_empty_bstr) };
                let ht = unsafe { elem.CachedHelpText().ok().and_then(non_empty_bstr) }
                    .or_else(|| cached_bstr_prop(elem, UIA_HelpTextPropertyId));
                let fd = cached_bstr_prop(elem, UIA_FullDescriptionPropertyId);
                let ap = unsafe { elem.CachedAriaProperties().ok().and_then(non_empty_bstr) }
                    .or_else(|| cached_bstr_prop(elem, UIA_AriaPropertiesPropertyId));
                (n, a, ht, fd, ap)
            };

        let is_web_surface = class_name.as_deref().is_some_and(|c| {
            c.eq_ignore_ascii_case("Chrome_RenderWidgetHostHWND")
                || c.eq_ignore_ascii_case("MozillaCompositorWindowClass")
        }) || aria_role.as_deref().is_some_and(|r| {
            matches!(
                r.to_ascii_lowercase().as_str(),
                "document" | "webarea" | "rootwebarea"
            )
        });

        let is_heading = heading_level > HeadingLevel_None.0
            || aria_role
                .as_deref()
                .is_some_and(|r| r.eq_ignore_ascii_case("heading"));

        let is_multiline = if control_type == 50004 {
            let aria_multi = aria_properties_has_multiline(aria_properties.as_deref());
            if let Some(hwnd) = native_hwnd {
                (get_window_style(hwnd) & 0x0004) != 0 || aria_multi
            } else {
                aria_multi
                    || class_name
                        .as_deref()
                        .is_some_and(|c| c.to_ascii_lowercase().contains("richedit"))
                    || (aria_role
                        .as_deref()
                        .is_some_and(|r| r.eq_ignore_ascii_case("textbox"))
                        && logical_rect.is_some_and(|r| r.height >= 44.0))
            }
        } else {
            supports_text_pattern || supports_text_pattern2
        };

        let mapped = map_uia_control_type_to_ax(
            control_type,
            effective_password,
            is_multiline,
            is_read_only,
            has_children_hint,
            is_web_surface,
            is_heading,
            supports_scroll_pattern,
            is_terminal_app,
        );

        let subrole_read = resolve_uia_subrole(
            control_type,
            effective_password,
            mapped.subrole,
            landmark_type,
            aria_role.as_deref(),
            automation_id.as_deref(),
        );

        Ok(UiaElementMetadata {
            runtime_id,
            process_id,
            control_type,
            is_password: if effective_password {
                ProtectedContentRead::Value(true)
            } else {
                is_password
            },
            is_enabled,
            is_control_element,
            is_content_element,
            is_offscreen,
            is_keyboard_focusable,
            has_keyboard_focus,
            native_hwnd,
            name,
            localized_control_type,
            automation_id,
            class_name,
            aria_role,
            aria_properties,
            landmark_type,
            help_text,
            full_description,
            heading_level,
            supports_text_pattern,
            supports_text_pattern2,
            supports_value_pattern,
            supports_scroll_pattern,
            value_is_read_only,
            is_read_only,
            logical_rect,
            subrole_read,
            mapped,
        })
    }

    /// Obtain `IUIAutomationTextPattern` (preferring `TextPattern2` upcast to `TextPattern` if needed).
    pub fn get_text_pattern(
        &self,
        elem: &IUIAutomationElement,
    ) -> Result<Option<IUIAutomationTextPattern>, UiaCallError> {
        // SAFETY: Only invoked AFTER `TextSecurityGate` approves the element.
        unsafe {
            match elem.GetCurrentPatternAs::<IUIAutomationTextPattern>(UIA_TextPatternId) {
                Ok(pat) => Ok(Some(pat)),
                Err(e) if e.code() == E_ACCESSDENIED => Err(UiaCallError::AccessDenied),
                Err(_) => {
                    match elem.GetCurrentPatternAs::<IUIAutomationTextPattern2>(UIA_TextPattern2Id)
                    {
                        Ok(pat2) => Ok(pat2.cast::<IUIAutomationTextPattern>().ok()),
                        Err(e) if e.code() == E_ACCESSDENIED => Err(UiaCallError::AccessDenied),
                        Err(_) => Ok(None),
                    }
                }
            }
        }
    }

    /// Obtain `IUIAutomationValuePattern`.
    pub fn get_value_pattern(
        &self,
        elem: &IUIAutomationElement,
    ) -> Result<Option<IUIAutomationValuePattern>, UiaCallError> {
        // SAFETY: Only invoked AFTER `TextSecurityGate` approves the element.
        unsafe {
            match elem.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId) {
                Ok(pat) => Ok(Some(pat)),
                Err(e) if e.code() == E_ACCESSDENIED => Err(UiaCallError::AccessDenied),
                Err(_) => Ok(None),
            }
        }
    }
}

/// Bounded UTF-16 text read extracted from UIA `TextPattern` (prefix mode).
pub struct UiaPrefixTextRead {
    pub text: String,
    pub total_length: Option<usize>,
    pub selection: Option<TextSelection>,
    pub complete: bool,
    pub truncated: bool,
    pub missing_reasons: Vec<String>,
}

/// Bounded UTF-16 text read extracted from UIA `TextPattern` (visible-range mode).
pub struct UiaVisibleTextRead {
    pub text: String,
    pub range_start: usize,
    pub total_length: usize,
    pub selection: Option<TextSelection>,
    pub truncated: bool,
    pub missing_reasons: Vec<String>,
}

const MAX_BOUNDED_MEASURE_UNITS: i32 = 262_144;

fn bstr_to_string_lossy(bstr: &windows::core::BSTR) -> String {
    String::from_utf16_lossy(bstr)
}

fn measure_range_offset_bounded(
    doc_range: &IUIAutomationTextRange,
    target_range: &IUIAutomationTextRange,
    max_units: usize,
) -> Option<usize> {
    // SAFETY: Standard UIA TextRange endpoint comparison & bounded GetText.
    unsafe {
        let cmp = target_range
            .CompareEndpoints(
                TextPatternRangeEndpoint_Start,
                doc_range,
                TextPatternRangeEndpoint_Start,
            )
            .ok()?;
        if cmp < 0 {
            return None;
        }
        if cmp == 0 {
            return Some(0);
        }
        let prefix = doc_range.Clone().ok()?;
        prefix
            .MoveEndpointByRange(
                TextPatternRangeEndpoint_End,
                target_range,
                TextPatternRangeEndpoint_Start,
            )
            .ok()?;
        let probe_limit = (max_units.saturating_add(1)).min(MAX_BOUNDED_MEASURE_UNITS as usize) as i32;
        let bstr = prefix.GetText(probe_limit).ok()?;
        let units = bstr.len();
        if units > max_units {
            None
        } else {
            Some(units)
        }
    }
}

/// Read bounded prefix text (`<= max_units` UTF-16 code units) + optional caret/selection offset
/// from an approved element's `IUIAutomationTextPattern`.
pub fn read_text_pattern_prefix(
    pattern: &IUIAutomationTextPattern,
    max_units: usize,
    can_read_selection: impl FnOnce() -> bool,
) -> Option<UiaPrefixTextRead> {
    let limit = max_units.clamp(1, 8_192);
    // SAFETY: Standard UIA TextPattern DocumentRange + bounded GetText(limit + 2) so a
    // 2-code-unit UTF-16 surrogate pair starting right at `limit` cannot hide truncation.
    let doc_range = unsafe { pattern.DocumentRange().ok()? };
    let probe = unsafe { doc_range.GetText((limit + 2) as i32).ok()? };
    let raw = bstr_to_string_lossy(&probe);
    let raw_units = utf16_len(&raw);

    let (text, total_length, complete, truncated, missing_reasons) = if raw_units <= limit {
        (raw, Some(raw_units), true, false, Vec::new())
    } else {
        let sliced = bounded_utf16_slice(&raw, 0, limit)?;
        (
            sliced,
            None,
            false,
            true,
            vec!["text-budget".to_string()],
        )
    };
    let actual_len = utf16_len(&text);

    let mut selection = None;
    if can_read_selection() {
        // SAFETY: Optional bounded selection offset computation within [0, actual_len].
        if let Ok(sel_arr) = unsafe { pattern.GetSelection() } {
            if unsafe { sel_arr.Length().unwrap_or(0) } > 0 {
                if let Ok(sel_range) = unsafe { sel_arr.GetElement(0) } {
                    if let Some(sel_start) =
                        measure_range_offset_bounded(&doc_range, &sel_range, actual_len)
                    {
                        if let Ok(sel_bstr) =
                            unsafe { sel_range.GetText((actual_len.saturating_sub(sel_start) + 1) as i32) }
                        {
                            let sel_len = sel_bstr.len();
                            if sel_start <= actual_len && sel_len <= actual_len - sel_start {
                                selection = Some(TextSelection::new(sel_start, sel_len));
                            }
                        }
                    }
                }
            }
        }
    }

    Some(UiaPrefixTextRead {
        text,
        total_length,
        selection,
        complete,
        truncated,
        missing_reasons,
    })
}

/// Finalize a UIA visible-range slice after clamping to `limit` and `max_avail` and trimming
/// any split UTF-16 surrogate pair.
///
/// Returns `(final_text, truncated, short_read)` where:
/// - `short_read` is `true` whenever `utf16_len(&final_text) < utf16_len(&raw_str)`
///   (budget truncation, `max_avail` clamping, or surrogate-pair trimming);
/// - `truncated` is `true` whenever `short_read` OR `vis_count > 1` (additional visible
///   ranges were dropped);
/// - returns `None` when slicing yields 0 UTF-16 code units.
pub fn finalize_visible_range_text(
    raw_str: String,
    limit: usize,
    max_avail: usize,
    vis_count: i32,
) -> Option<(String, bool, bool)> {
    let raw_len = utf16_len(&raw_str);
    let target_len = raw_len.min(limit).min(max_avail);
    let final_text = if target_len == raw_len {
        raw_str
    } else {
        bounded_utf16_slice(&raw_str, 0, target_len)?
    };
    let actual_len = utf16_len(&final_text);
    if actual_len == 0 {
        return None;
    }
    let short_read = actual_len < raw_len;
    let truncated = short_read || vis_count > 1;
    Some((final_text, truncated, short_read))
}

/// Compute coverage `missingReasons` for a visible-range UIA read.
pub fn visible_range_missing_reasons(
    raw_len: usize,
    limit: usize,
    short_read: bool,
) -> Vec<String> {
    let mut missing_reasons = vec!["visible-range-only".to_string()];
    if raw_len > limit {
        missing_reasons.push("text-budget".to_string());
    }
    if short_read {
        missing_reasons.push("range-short-read".to_string());
    }
    missing_reasons
}

/// Read bounded visible-range text (`<= max_units` UTF-16 code units) from `IUIAutomationTextPattern`.
pub fn read_text_pattern_visible(
    pattern: &IUIAutomationTextPattern,
    max_units: usize,
    can_read_selection: impl FnOnce() -> bool,
) -> Option<UiaVisibleTextRead> {
    let limit = max_units.clamp(1, 8_192);
    // SAFETY: Standard UIA TextPattern DocumentRange + GetVisibleRanges.
    let doc_range = unsafe { pattern.DocumentRange().ok()? };
    let doc_probe = unsafe { doc_range.GetText(MAX_BOUNDED_MEASURE_UNITS).ok()? };
    if doc_probe.len() >= MAX_BOUNDED_MEASURE_UNITS as usize {
        // Cannot prove exact totalLength within bounded measurement cap.
        return None;
    }
    let total_length = utf16_len(&bstr_to_string_lossy(&doc_probe));

    if total_length == 0 {
        return Some(UiaVisibleTextRead {
            text: String::new(),
            range_start: 0,
            total_length: 0,
            selection: Some(TextSelection::new(0, 0)),
            truncated: false,
            missing_reasons: vec!["visible-range-only".to_string()],
        });
    }

    let vis_arr = unsafe { pattern.GetVisibleRanges().ok()? };
    let vis_count = unsafe { vis_arr.Length().ok()? };
    let mut chosen: Option<(IUIAutomationTextRange, String, usize)> = None;
    for i in 0..vis_count.min(16) {
        let Ok(vis) = (unsafe { vis_arr.GetElement(i) }) else {
            continue;
        };
        let Ok(raw_bstr) = (unsafe { vis.GetText((limit + 2) as i32) }) else {
            continue;
        };
        let raw_str = bstr_to_string_lossy(&raw_bstr);
        if raw_str.is_empty() {
            continue;
        }
        let raw_len = utf16_len(&raw_str);
        chosen = Some((vis, raw_str, raw_len));
        break;
    }

    let (vis_range, raw_str, raw_len) = chosen?;
    let range_start = measure_range_offset_bounded(&doc_range, &vis_range, total_length)?;
    let max_avail = total_length.saturating_sub(range_start);
    let (text, truncated, short_read) =
        finalize_visible_range_text(raw_str, limit, max_avail, vis_count)?;
    let actual_len = utf16_len(&text);
    let missing_reasons = visible_range_missing_reasons(raw_len, limit, short_read);

    let mut selection = None;
    if can_read_selection() {
        if let Ok(sel_arr) = unsafe { pattern.GetSelection() } {
            if unsafe { sel_arr.Length().unwrap_or(0) } > 0 {
                if let Ok(sel_range) = unsafe { sel_arr.GetElement(0) } {
                    if let Some(sel_start) =
                        measure_range_offset_bounded(&doc_range, &sel_range, total_length)
                    {
                        if let Ok(sel_bstr) = unsafe { sel_range.GetText((actual_len + 1) as i32) }
                        {
                            let sel_len = sel_bstr.len();
                            if sel_start >= range_start
                                && sel_start - range_start <= actual_len
                                && sel_len <= actual_len - (sel_start - range_start)
                            {
                                selection = Some(TextSelection::new(sel_start, sel_len));
                            }
                        }
                    }
                }
            }
        }
    }

    Some(UiaVisibleTextRead {
        text,
        range_start,
        total_length,
        selection,
        truncated,
        missing_reasons,
    })
}

/// Read bounded selection text (`<= max_units` UTF-16 code units) from `IUIAutomationTextPattern`.
pub fn read_text_pattern_selection(
    pattern: &IUIAutomationTextPattern,
    max_units: usize,
) -> Option<SelectionReadResult> {
    let limit = max_units.clamp(1, 8_192);
    // SAFETY: Standard UIA TextPattern GetSelection + bounded GetText(limit + 1).
    let sel_arr = unsafe { pattern.GetSelection().ok()? };
    if unsafe { sel_arr.Length().ok()? } <= 0 {
        return None;
    }
    let sel_range = unsafe { sel_arr.GetElement(0).ok()? };
    let raw_bstr = unsafe { sel_range.GetText((limit + 2) as i32).ok()? };
    let raw = bstr_to_string_lossy(&raw_bstr);
    let raw_units = utf16_len(&raw);
    let truncated = raw_units > limit;
    let text = if truncated {
        bounded_utf16_slice(&raw, 0, limit)?
    } else {
        raw
    };
    let range_start = unsafe { pattern.DocumentRange().ok() }
        .and_then(|doc| {
            measure_range_offset_bounded(&doc, &sel_range, MAX_BOUNDED_MEASURE_UNITS as usize)
        })
        .unwrap_or(0);
    let mut missing_reasons = vec!["selection-only".to_string()];
    if truncated {
        missing_reasons.push("text-budget".to_string());
    }
    Some(SelectionReadResult {
        text,
        source: "uia.text".to_string(),
        range_start,
        truncated,
        missing_reasons,
    })
}

/// Read bounded prefix text (`<= max_units` UTF-16 code units) from `IUIAutomationValuePattern`.
/// NEVER use this for `rangeBasis == "visible"`.
pub fn read_value_pattern_prefix(
    pattern: &IUIAutomationValuePattern,
    max_units: usize,
) -> Option<UiaPrefixTextRead> {
    let limit = max_units.clamp(1, 8_192);
    // SAFETY: Invoked only after TextSecurityGate approves the element.
    let raw_bstr = unsafe { pattern.CurrentValue().ok()? };
    let raw = bstr_to_string_lossy(&raw_bstr);
    let total = utf16_len(&raw);
    if total <= limit {
        Some(UiaPrefixTextRead {
            text: raw,
            total_length: Some(total),
            selection: None,
            complete: true,
            truncated: false,
            missing_reasons: Vec::new(),
        })
    } else {
        let sliced = bounded_utf16_slice(&raw, 0, limit)?;
        Some(UiaPrefixTextRead {
            text: sliced,
            total_length: Some(total),
            selection: None,
            complete: false,
            truncated: true,
            missing_reasons: vec!["text-budget".to_string()],
        })
    }
}

/// Pure PID-filtering decision for WinEvent callbacks: returns `(set_dirty, set_focus_invalidated)`.
///
/// - `EVENT_SYSTEM_FOREGROUND` ALWAYS wakes both bits regardless of PID so app switches rebind immediately.
/// - `EVENT_OBJECT_FOCUS` wakes both bits ONLY for the bound `target_pid` / `raw_target_pid` (or when unbound `0`),
///   preventing background focus noise from thrashing `node_map` / `baseline`.
/// - `EVENT_OBJECT_VALUECHANGE` and `EVENT_OBJECT_TEXTSELECTIONCHANGED` wake `dirty` ONLY for the bound PID.
pub fn classify_win_event(
    event: u32,
    event_pid: u32,
    target_pid: u32,
    raw_target_pid: u32,
) -> (bool, bool) {
    let matches_target = target_pid == 0
        || (event_pid != 0
            && (event_pid == target_pid || (raw_target_pid != 0 && event_pid == raw_target_pid)));
    match event {
        EVENT_SYSTEM_FOREGROUND => (true, true),
        EVENT_OBJECT_FOCUS if matches_target => (true, true),
        EVENT_OBJECT_VALUECHANGE | EVENT_OBJECT_TEXTSELECTIONCHANGED if matches_target => {
            (true, false)
        }
        _ => (false, false),
    }
}

struct WinEventThreadContext {
    dirty: Arc<AtomicBool>,
    focus_invalidated: Arc<AtomicBool>,
    target_pid: Arc<AtomicU32>,
    raw_target_pid: Arc<AtomicU32>,
}

thread_local! {
    static WINEVENT_CTX: RefCell<Option<WinEventThreadContext>> = const { RefCell::new(None) };
}

unsafe extern "system" fn win_event_callback(
    _hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    _id_object: i32,
    _id_child: i32,
    _id_event_thread: u32,
    _event_time: u32,
) {
    // Privacy invariant: callback carries NO text, titles, or window contents — only dirty bits.
    WINEVENT_CTX.with(|cell| {
        if let Some(ref ctx) = *cell.borrow() {
            let expected_pid = ctx.target_pid.load(Ordering::Acquire);
            let raw_pid = ctx.raw_target_pid.load(Ordering::Acquire);
            let event_pid = if event == EVENT_SYSTEM_FOREGROUND || hwnd.0.is_null() {
                0
            } else {
                let mut pid: u32 = 0;
                // SAFETY: Read-only Win32 PID query.
                windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId(
                    hwnd,
                    Some(&mut pid),
                );
                pid
            };
            let (set_dirty, set_focus_invalidated) =
                classify_win_event(event, event_pid, expected_pid, raw_pid);
            if set_dirty {
                ctx.dirty.store(true, Ordering::Release);
            }
            if set_focus_invalidated {
                ctx.focus_invalidated.store(true, Ordering::Release);
            }
        }
    });
}

/// Lightweight background Win32 message-pump thread listening for WinEvent foreground, focus,
/// value, and selection changes with `WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS`.
pub struct WinEventWatcher {
    dirty: Arc<AtomicBool>,
    focus_invalidated: Arc<AtomicBool>,
    target_pid: Arc<AtomicU32>,
    raw_target_pid: Arc<AtomicU32>,
    thread_id: u32,
    active: bool,
    handle: Option<JoinHandle<()>>,
}

impl WinEventWatcher {
    pub fn start() -> Self {
        Self::start_for_pid(0)
    }

    pub fn start_for_pid(initial_pid: u32) -> Self {
        let dirty = Arc::new(AtomicBool::new(false));
        let focus_invalidated = Arc::new(AtomicBool::new(false));
        let target_pid = Arc::new(AtomicU32::new(initial_pid));
        let raw_target_pid = Arc::new(AtomicU32::new(initial_pid));

        let d = Arc::clone(&dirty);
        let fi = Arc::clone(&focus_invalidated);
        let tp = Arc::clone(&target_pid);
        let rtp = Arc::clone(&raw_target_pid);

        let (tx, rx) = mpsc::sync_channel::<(u32, bool)>(1);
        let handle = thread::spawn(move || {
            // SAFETY: Force creation of thread message queue before signaling thread_id to caller.
            let tid = unsafe {
                let mut msg = MSG::default();
                let _ = PeekMessageW(&mut msg, None, 0, 0, PM_NOREMOVE);
                GetCurrentThreadId()
            };

            WINEVENT_CTX.with(|cell| {
                *cell.borrow_mut() = Some(WinEventThreadContext {
                    dirty: d,
                    focus_invalidated: fi,
                    target_pid: tp,
                    raw_target_pid: rtp,
                });
            });

            let flags = WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS;
            let mut hooks: Vec<HWINEVENTHOOK> = Vec::with_capacity(4);
            for event in [
                EVENT_SYSTEM_FOREGROUND,
                EVENT_OBJECT_FOCUS,
                EVENT_OBJECT_VALUECHANGE,
                EVENT_OBJECT_TEXTSELECTIONCHANGED,
            ] {
                // SAFETY: Out-of-context hook pumped on this thread's GetMessageW loop.
                let h = unsafe {
                    SetWinEventHook(event, event, None, Some(win_event_callback), 0, 0, flags)
                };
                if !h.is_invalid() && !h.0.is_null() {
                    hooks.push(h);
                }
            }
            let any_active = !hooks.is_empty();
            let _ = tx.send((tid, any_active));

            if any_active {
                let mut msg = MSG::default();
                // SAFETY: Standard Win32 message pump until WM_QUIT (0) or error (-1).
                // Check `.0 > 0` explicitly because `BOOL(-1).as_bool()` is `true`!
                unsafe {
                    while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            }

            for hook in hooks {
                // SAFETY: Unhooking handle registered on this exact thread.
                unsafe {
                    let _ = UnhookWinEvent(hook);
                }
            }
            WINEVENT_CTX.with(|cell| {
                *cell.borrow_mut() = None;
            });
        });

        let (thread_id, active) = rx.recv().unwrap_or((0, false));
        Self {
            dirty,
            focus_invalidated,
            target_pid,
            raw_target_pid,
            thread_id,
            active,
            handle: Some(handle),
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn set_target_pid(&self, pid: u32) {
        self.target_pid.store(pid, Ordering::Release);
        self.raw_target_pid.store(pid, Ordering::Release);
    }

    pub fn set_target_pids(&self, effective_pid: u32, raw_pid: u32) {
        self.target_pid.store(effective_pid, Ordering::Release);
        self.raw_target_pid.store(raw_pid, Ordering::Release);
    }

    pub fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::AcqRel)
    }

    pub fn take_focus_invalidated(&self) -> bool {
        self.focus_invalidated.swap(false, Ordering::AcqRel)
    }

    pub fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            if self.thread_id != 0 {
                // SAFETY: Posting WM_QUIT terminates the watcher's GetMessageW loop immediately.
                unsafe {
                    let _ = PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
                }
            }
            let _ = handle.join();
            self.active = false;
            self.thread_id = 0;
        }
    }
}

impl Drop for WinEventWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Com::{ADVANCED_FEATURE_FLAGS, SAFEARRAY, SAFEARRAYBOUND};
    use windows::Win32::System::Ole::SafeArrayCreate;
    use windows::Win32::System::Variant::{VARENUM, VT_BYREF, VT_I2};

    fn make_i32_safearray(values: &[i32]) -> OwnedSafeArray {
        let bound = SAFEARRAYBOUND {
            cElements: values.len() as u32,
            lLbound: 0,
        };
        // SAFETY: Valid 1-D VT_I4 SAFEARRAY creation and initialization.
        unsafe {
            let psa = SafeArrayCreate(VT_I4, 1, &bound);
            assert!(!psa.is_null(), "SafeArrayCreate(VT_I4, 1) must succeed");
            if !values.is_empty() {
                let mut ptr: *mut core::ffi::c_void = core::ptr::null_mut();
                SafeArrayAccessData(psa, &mut ptr).expect("SafeArrayAccessData");
                core::ptr::copy_nonoverlapping(values.as_ptr(), ptr as *mut i32, values.len());
                let _ = SafeArrayUnaccessData(psa);
            }
            OwnedSafeArray(psa)
        }
    }

    #[test]
    fn safearray_i32_reads_valid_1d_and_rejects_bad_dims_elem_size_and_overflow() {
        let valid = make_i32_safearray(&[42, 7, -9]);
        assert_eq!(read_i32_safearray(valid.0), Some(vec![42, 7, -9]));

        let empty = make_i32_safearray(&[]);
        assert_eq!(read_i32_safearray(empty.0), Some(Vec::new()));

        assert_eq!(read_i32_safearray(core::ptr::null_mut()), None);

        // Reject cDims != 1 (2-D SAFEARRAY).
        let bounds_2d = [
            SAFEARRAYBOUND {
                cElements: 2,
                lLbound: 0,
            },
            SAFEARRAYBOUND {
                cElements: 2,
                lLbound: 0,
            },
        ];
        // SAFETY: Valid 2-D SAFEARRAY freed via OwnedSafeArray.
        let psa_2d = OwnedSafeArray(unsafe { SafeArrayCreate(VT_I4, 2, bounds_2d.as_ptr()) });
        assert!(!psa_2d.0.is_null());
        assert_eq!(read_i32_safearray(psa_2d.0), None);

        // Reject cbElements != 4 (VT_I2 SAFEARRAY has cbElements == 2).
        let bound_i2 = SAFEARRAYBOUND {
            cElements: 3,
            lLbound: 0,
        };
        // SAFETY: Valid 1-D VT_I2 SAFEARRAY freed via OwnedSafeArray.
        let psa_i2 = OwnedSafeArray(unsafe { SafeArrayCreate(VT_I2, 1, &bound_i2) });
        assert!(!psa_i2.0.is_null());
        assert_eq!(read_i32_safearray(psa_i2.0), None);

        // Reject count > 4096.
        let bound_big = SAFEARRAYBOUND {
            cElements: 4_097,
            lLbound: 0,
        };
        // SAFETY: Valid 1-D VT_I4 SAFEARRAY freed via OwnedSafeArray.
        let psa_big = OwnedSafeArray(unsafe { SafeArrayCreate(VT_I4, 1, &bound_big) });
        assert!(!psa_big.0.is_null());
        assert_eq!(read_i32_safearray(psa_big.0), None);

        // Reject extreme i32 bounds that would overflow i32 arithmetic without i64 widening.
        let mut fake = SAFEARRAY {
            cDims: 1,
            fFeatures: ADVANCED_FEATURE_FLAGS(0),
            cbElements: 4,
            cLocks: 0,
            pvData: core::ptr::null_mut(),
            rgsabound: [SAFEARRAYBOUND {
                cElements: u32::MAX,
                lLbound: i32::MIN,
            }],
        };
        assert_eq!(read_i32_safearray(&mut fake as *mut SAFEARRAY), None);
    }

    #[test]
    fn variant_as_i32_array_requires_exact_vt_array_i4_and_rejects_vt_byref() {
        let sa = make_i32_safearray(&[10, 20, 30]);

        // Valid exact VT_ARRAY | VT_I4.
        let mut exact_var = VARIANT::default();
        // SAFETY: Manually populating VARIANT with owned SAFEARRAY; we clear vt/parray before drop
        // so OwnedSafeArray handles SafeArrayDestroy without double-free.
        unsafe {
            let inner = &mut *exact_var.Anonymous.Anonymous;
            inner.vt = VARENUM(VT_ARRAY.0 | VT_I4.0);
            inner.Anonymous.parray = sa.0;
        }
        assert_eq!(variant_as_i32_array(&exact_var), Some(vec![10, 20, 30]));
        unsafe {
            let inner = &mut *exact_var.Anonymous.Anonymous;
            inner.vt = VARENUM(0);
            inner.Anonymous.parray = core::ptr::null_mut();
        }

        // VT_ARRAY | VT_I4 | VT_BYREF MUST be rejected (prevents dereferencing pparray as parray).
        let mut byref_var = VARIANT::default();
        let mut raw_ptr: *mut SAFEARRAY = sa.0;
        unsafe {
            let inner = &mut *byref_var.Anonymous.Anonymous;
            inner.vt = VARENUM(VT_ARRAY.0 | VT_I4.0 | VT_BYREF.0);
            inner.Anonymous.pparray = &mut raw_ptr;
        }
        assert_eq!(variant_as_i32_array(&byref_var), None);
        unsafe {
            let inner = &mut *byref_var.Anonymous.Anonymous;
            inner.vt = VARENUM(0);
            inner.Anonymous.pparray = core::ptr::null_mut();
        }
    }

    #[test]
    fn warmed_hwnd_cache_evicts_fifo_at_capacity() {
        let mut cache = WarmedHwndCache::with_capacity(2);
        assert!(cache.is_empty());
        cache.insert(0);
        assert!(cache.is_empty());

        cache.insert(101);
        cache.insert(202);
        assert!(cache.contains(101));
        assert!(cache.contains(202));
        assert_eq!(cache.len(), 2);

        // Duplicate insert does not evict.
        cache.insert(101);
        assert_eq!(cache.len(), 2);

        // Inserting 3rd evicts oldest (101).
        cache.insert(303);
        assert!(!cache.contains(101));
        assert!(cache.contains(202));
        assert!(cache.contains(303));

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn chrome_probe_skip_excludes_firefox_bookmarks_and_chromium_tabs_while_keeping_private_chrome()
    {
        // Hard-skipped web content, tabs, edits, menus.
        assert!(should_skip_chrome_probe_node(50030, None, None, Some("Document")));
        assert!(should_skip_chrome_probe_node(50018, None, Some("tabbrowser-tabs"), None));
        assert!(should_skip_chrome_probe_node(50019, None, None, Some("Incognito Wiki")));
        assert!(should_skip_chrome_probe_node(50004, None, None, Some("Address bar")));

        // Chromium bookmark bar / buttons / extensions skipped.
        assert!(should_skip_chrome_probe_node(
            50021,
            Some("BookmarkBarView"),
            None,
            Some("Bookmarks")
        ));
        assert!(should_skip_chrome_probe_node(
            50000,
            Some("BookmarkButton"),
            None,
            Some("Incognito docs")
        ));

        // Firefox PersonalToolbar / PlacesToolbar / localized bookmark ToolBar without Chrome_* class skipped.
        assert!(should_skip_chrome_probe_node(
            50021,
            None,
            Some("PersonalToolbar"),
            Some("Bookmarks Toolbar")
        ));
        assert!(should_skip_chrome_probe_node(
            50026,
            None,
            Some("PlacesToolbarItems"),
            None
        ));
        assert!(should_skip_chrome_probe_node(
            50021,
            None,
            None,
            Some("书签工具栏")
        ));

        // Firefox's own TabsToolbar / Navigation toolbar & Private Browsing badge MUST STILL be scanned!
        assert!(!should_skip_chrome_probe_node(
            50021,
            None,
            Some("TabsToolbar"),
            Some("Browser tabs")
        ));
        assert!(!should_skip_chrome_probe_node(
            50021,
            None,
            Some("nav-bar"),
            Some("Navigation")
        ));
        assert!(!should_skip_chrome_probe_node(
            50000,
            Some("AvatarToolbarButton"),
            None,
            Some("Incognito")
        ));
        assert!(!should_skip_chrome_probe_node(
            50020,
            None,
            Some("private-browsing-indicator-with-label"),
            Some("Private Browsing")
        ));
    }

    #[test]
    fn visible_range_finalization_tracks_max_avail_surrogate_trim_multi_range_and_short_read() {
        // 1. Clean unclipped single visible range -> truncated=false, short_read=false.
        let (text, truncated, short_read) =
            finalize_visible_range_text("Hello world".to_string(), 32, 32, 1)
                .expect("unclipped visible range");
        assert_eq!(text, "Hello world");
        assert!(!truncated);
        assert!(!short_read);
        assert_eq!(
            visible_range_missing_reasons(11, 32, short_read),
            vec!["visible-range-only"]
        );

        // 2. max_avail clamping when raw_len <= limit MUST set truncated=true and emit range-short-read.
        let (text, truncated, short_read) =
            finalize_visible_range_text("abcdef".to_string(), 10, 4, 1)
                .expect("max_avail clamped");
        assert_eq!(text, "abcd");
        assert!(truncated);
        assert!(short_read);
        assert_eq!(
            visible_range_missing_reasons(6, 10, short_read),
            vec!["visible-range-only", "range-short-read"]
        );

        // 3. Surrogate-pair trimming via max_avail when raw_len <= limit ("a🙂b" = 4 UTF-16 units;
        // max_avail = 2 splits "🙂" so slice trims to "a" = 1 UTF-16 unit).
        let (text, truncated, short_read) =
            finalize_visible_range_text("a🙂b".to_string(), 10, 2, 1)
                .expect("surrogate trimmed via max_avail");
        assert_eq!(text, "a");
        assert!(truncated);
        assert!(short_read);
        assert_eq!(
            visible_range_missing_reasons(4, 10, short_read),
            vec!["visible-range-only", "range-short-read"]
        );

        // 4. Surrogate-pair trimming via limit ("a🙂b", limit = 2 -> "a", budget + short-read).
        let (text, truncated, short_read) =
            finalize_visible_range_text("a🙂b".to_string(), 2, 10, 1)
                .expect("surrogate trimmed via limit");
        assert_eq!(text, "a");
        assert!(truncated);
        assert!(short_read);
        assert_eq!(
            visible_range_missing_reasons(4, 2, short_read),
            vec!["visible-range-only", "text-budget", "range-short-read"]
        );

        // 5. Multiple visible ranges (vis_count > 1) MUST mark truncated=true even when the chosen
        // first range itself is unclipped.
        let (text, truncated, short_read) =
            finalize_visible_range_text("visible-one".to_string(), 32, 32, 2)
                .expect("multi visible range");
        assert_eq!(text, "visible-one");
        assert!(truncated);
        assert!(!short_read);
        assert_eq!(
            visible_range_missing_reasons(11, 32, short_read),
            vec!["visible-range-only"]
        );

        // 6. Leading surrogate pair trimmed to 0 UTF-16 units or max_avail == 0 returns None.
        assert_eq!(finalize_visible_range_text("🙂".to_string(), 1, 10, 1), None);
        assert_eq!(finalize_visible_range_text("abc".to_string(), 10, 0, 1), None);
    }
}

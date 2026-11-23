//! MTA COM initialization, Per-Monitor V2 DPI normalization, cached pre-read `IUIAutomation`
//! helpers, safe `TextPattern`/`ValuePattern` extraction, and WinEvent dirty-wakeup watcher.

use std::cell::RefCell;
use std::collections::VecDeque;
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
use windows::Win32::System::Variant::{VARIANT, VT_ARRAY, VT_BOOL, VT_I4};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, CUIAutomation8, HeadingLevel_None, IUIAutomation, IUIAutomation2,
    IUIAutomationCacheRequest, IUIAutomationElement, IUIAutomationTextPattern,
    IUIAutomationTextPattern2, IUIAutomationTextRange, IUIAutomationTreeWalker,
    IUIAutomationValuePattern, SetWinEventHook, TextPatternRangeEndpoint_End,
    TextPatternRangeEndpoint_Start, UIA_AriaRolePropertyId, UIA_AutomationIdPropertyId,
    UIA_BoundingRectanglePropertyId, UIA_ClassNamePropertyId, UIA_ControlTypePropertyId,
    UIA_HasKeyboardFocusPropertyId, UIA_HeadingLevelPropertyId, UIA_IsContentElementPropertyId,
    UIA_IsControlElementPropertyId, UIA_IsEnabledPropertyId, UIA_IsKeyboardFocusablePropertyId,
    UIA_IsOffscreenPropertyId, UIA_IsPasswordPropertyId, UIA_IsScrollPatternAvailablePropertyId,
    UIA_IsTextPattern2AvailablePropertyId, UIA_IsTextPatternAvailablePropertyId,
    UIA_IsValuePatternAvailablePropertyId, UIA_LocalizedControlTypePropertyId, UIA_NamePropertyId,
    UIA_NativeWindowHandlePropertyId, UIA_ProcessIdPropertyId, UIA_RuntimeIdPropertyId,
    UIA_TextPattern2Id, UIA_TextPatternId, UIA_ValueIsReadOnlyPropertyId, UIA_ValuePatternId,
    UnhookWinEvent, HWINEVENTHOOK,
};
use windows::Win32::UI::HiDpi::{
    GetDpiForWindow, SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, EnumChildWindows, GetClassNameW, GetMessageW, GetWindowRect, PeekMessageW,
    PostThreadMessageW, SendMessageTimeoutW, TranslateMessage, EVENT_OBJECT_FOCUS,
    EVENT_OBJECT_TEXTSELECTIONCHANGED, EVENT_OBJECT_VALUECHANGE, EVENT_SYSTEM_FOREGROUND, MSG,
    OBJID_CLIENT, PM_NOREMOVE, SMTO_ABORTIFHUNG, WINEVENT_OUTOFCONTEXT, WINEVENT_SKIPOWNPROCESS,
    WM_GETOBJECT, WM_QUIT,
};

use crate::adapters::{ActivationMode, AppAdapterSpec};
use crate::policy::{
    map_uia_control_type_to_ax, BrowserGate, MappedRole, ProtectedContentRead, SubroleRead,
};
use crate::protocol_model::{
    bounded_utf16_slice, AxEnablementResult, CapturePolicy, CollectorClock, SelectionReadResult,
    SurfaceAbsoluteRect, SystemCollectorClock, TextSelection,
};
use crate::uia_traversal::RuntimeIdKey;

/// Win32 `UiaRootObjectId` (`-25`) sent via `WM_GETOBJECT` to hydrate Chromium/Electron UIA trees.
const UIA_ROOT_OBJECT_ID: isize = -25;

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
    let width = (rect.right - rect.left).max(0) as f64;
    let height = (rect.bottom - rect.top).max(0) as f64;
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

/// Perform bounded `WM_GETOBJECT` warmup for Chromium/Electron/browser windows (both top-level
/// `hwnd` and child `Chrome_RenderWidgetHostHWND` / `MozillaCompositorWindowClass` windows with
/// `UiaRootObjectId = -25`) when `policy.ax_compatibility == Some(true)` within a hard 100ms budget.
pub fn warmup_window_uia(
    hwnd: HWND,
    spec: &AppAdapterSpec,
    policy: &CapturePolicy,
    read_only: bool,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
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
    let now = clock.monotonic_ms();
    let remaining = deadline_ms.saturating_sub(now).min(100);
    if remaining < 10 {
        return AxEnablementResult {
            status: "write-failed".to_string(),
            attribute: attribute.to_string(),
            changed: false,
        };
    }
    let warmup_deadline = now.saturating_add(remaining);
    let renderer_children = find_renderer_child_hwnds(hwnd);
    let top_timeout_ms = if renderer_children.is_empty() {
        remaining.min(80)
    } else {
        remaining.min(40)
    } as u32;
    let mut result_out: usize = 0;
    // SAFETY: Bounded non-blocking SMTO_ABORTIFHUNG WM_GETOBJECT probe to wake Chromium/Electron UIA trees.
    let sent_top = unsafe {
        SendMessageTimeoutW(
            hwnd,
            WM_GETOBJECT,
            WPARAM(0),
            LPARAM(OBJID_CLIENT.0 as isize),
            SMTO_ABORTIFHUNG,
            top_timeout_ms,
            Some(&mut result_out),
        )
    };
    let mut any_sent = sent_top.0 != 0;

    // Also hydrate child Chromium/Electron/Mozilla renderer HWNDs with UiaRootObjectId (-25).
    for child_hwnd in renderer_children {
        let child_rem = warmup_deadline.saturating_sub(clock.monotonic_ms());
        if child_rem < 10 {
            break;
        }
        let child_timeout_ms = child_rem.min(60) as u32;
        let mut child_result: usize = 0;
        // SAFETY: Bounded SMTO_ABORTIFHUNG WM_GETOBJECT(UiaRootObjectId) probe on live child HWND.
        let sent_child = unsafe {
            SendMessageTimeoutW(
                child_hwnd,
                WM_GETOBJECT,
                WPARAM(0),
                LPARAM(UIA_ROOT_OBJECT_ID),
                SMTO_ABORTIFHUNG,
                child_timeout_ms,
                Some(&mut child_result),
            )
        };
        if sent_child.0 != 0 {
            any_sent = true;
        }
    }

    if any_sent {
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
    if psa.is_null() {
        return None;
    }
    // SAFETY: Valid 1-D SAFEARRAY of VT_I4 elements; data pointer unlocked before return.
    unsafe {
        let lbound = SafeArrayGetLBound(psa, 1).ok()?;
        let ubound = SafeArrayGetUBound(psa, 1).ok()?;
        if ubound < lbound {
            return Some(Vec::new());
        }
        let len = (ubound - lbound + 1) as usize;
        if len > 256 {
            return None;
        }
        let mut ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        SafeArrayAccessData(psa, &mut ptr).ok()?;
        let out = if ptr.is_null() {
            None
        } else {
            let slice = core::slice::from_raw_parts(ptr as *const i32, len);
            Some(slice.to_vec())
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
    let vt = var.vt().0;
    if (vt & VT_ARRAY.0) == 0 || (vt & 0x0FFF) != VT_I4.0 {
        return None;
    }
    // SAFETY: Checked VT_ARRAY | VT_I4. VARIANT Drop calls VariantClear so we do NOT destroy parray.
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

fn non_empty_bstr(bstr: windows::core::BSTR) -> Option<String> {
    let s = bstr.to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
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
        // SAFETY: Minimal 3-property cache request for pre-read private browser chrome detection.
        // INVARIANT: NEVER add Value/Text/LegacyIAccessibleValue properties!
        unsafe {
            let req = automation
                .CreateCacheRequest()
                .map_err(|e| UiaCallError::from_error(&e))?;
            for prop in [
                UIA_ControlTypePropertyId,
                UIA_ClassNamePropertyId,
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

    /// Bounded shallow inspection of a browser window's **non-Document** native frame chrome
    /// (capped at 48 chrome nodes and <= 25ms) to detect Windows Incognito / InPrivate / Private
    /// Browsing windows whose `GetWindowTextW` omits private indicators on navigated tabs.
    ///
    /// PRIVACY INVARIANT: Uses `chrome_probe_cache` (`ControlType`, `ClassName`, `Name` ONLY —
    /// NEVER `Value` or `Text`), and explicitly skips `ControlType::Document (50030)` (plus `Tab`,
    /// `TabItem`, `Edit`, menus, and bookmarks) so web page content is NEVER inspected.
    pub fn is_private_browser_window_chrome(
        &self,
        hwnd: HWND,
        deadline_ms: i64,
    ) -> Result<bool, UiaCallError> {
        const MAX_CHROME_NODES: usize = 48;
        const MAX_CHROME_DEPTH: usize = 12;
        const MAX_SIBLINGS_PER_NODE: usize = 24;

        if hwnd.0.is_null() {
            return Ok(false);
        }
        let now = SystemCollectorClock::monotonic_ms_now();
        let effective_deadline = deadline_ms.min(now.saturating_add(25));
        if now >= effective_deadline {
            return Ok(false);
        }
        self.apply_timeouts(effective_deadline.saturating_sub(now));

        // SAFETY: Valid live HWND and minimal 3-property chrome probe cache request.
        let root = unsafe {
            self.automation
                .ElementFromHandleBuildCache(hwnd, &self.chrome_probe_cache)
                .map_err(|e| UiaCallError::from_error(&e))?
        };

        let mut queue: VecDeque<(IUIAutomationElement, usize)> = VecDeque::with_capacity(32);
        queue.push_back((root, 0));
        let mut inspected: usize = 0;

        while let Some((elem, depth)) = queue.pop_front() {
            if inspected >= MAX_CHROME_NODES
                || SystemCollectorClock::monotonic_ms_now() >= effective_deadline
            {
                break;
            }
            inspected += 1;

            // SAFETY: Reads strictly from pre-populated 3-property chrome_probe_cache.
            let control_type = match unsafe { elem.CachedControlType() } {
                Ok(ct) => ct.0,
                Err(e) if e.code() == E_ACCESSDENIED => return Err(UiaCallError::AccessDenied),
                Err(_) => 0,
            };

            // HARD PRIVACY & FALSE-POSITIVE GATE: NEVER enter web Document content, open tabs,
            // address bar / text edits, menus, or scrollbars.
            if matches!(
                control_type,
                50030 | 50018 | 50019 | 50004 | 50009 | 50010 | 50011 | 50014
            ) {
                continue;
            }

            let class_name = unsafe { elem.CachedClassName().ok().and_then(non_empty_bstr) };
            if let Some(ref cls) = class_name {
                if cls.eq_ignore_ascii_case("Chrome_RenderWidgetHostHWND")
                    || cls.eq_ignore_ascii_case("MozillaCompositorWindowClass")
                    || cls.eq_ignore_ascii_case("BookmarkBarView")
                    || cls.eq_ignore_ascii_case("BookmarkButton")
                    || cls.eq_ignore_ascii_case("ToolbarActionView")
                    || cls.eq_ignore_ascii_case("ExtensionsToolbarContainer")
                {
                    continue;
                }
            }

            // Check root if it happens to be Button/Text/Custom (children are checked immediately below).
            if depth == 0 && matches!(control_type, 50000 | 50020 | 50025) {
                let name = unsafe { elem.CachedName().ok().and_then(non_empty_bstr) };
                if let Some(ref label) = name {
                    if BrowserGate::is_private_chrome_indicator(class_name.as_deref(), label) {
                        return Ok(true);
                    }
                }
            }

            if depth >= MAX_CHROME_DEPTH {
                continue;
            }
            // Only descend into native chrome container controls.
            if !matches!(
                control_type,
                50032 | 50033 | 50026 | 50021 | 50037 | 50025 | 50034
            ) {
                continue;
            }

            // On ToolBar (50021), walk tail-to-head because Chromium/Edge/Firefox place the
            // profile/Incognito/InPrivate toolbar button near the right end of the toolbar.
            let walk_tail_first = control_type == 50021;
            let mut cur = if walk_tail_first {
                match unsafe {
                    self.walker
                        .GetLastChildElementBuildCache(&elem, &self.chrome_probe_cache)
                } {
                    Ok(c) => Some(c),
                    Err(e) if e.code() == E_ACCESSDENIED => return Err(UiaCallError::AccessDenied),
                    Err(_) => None,
                }
            } else {
                match unsafe {
                    self.walker
                        .GetFirstChildElementBuildCache(&elem, &self.chrome_probe_cache)
                } {
                    Ok(c) => Some(c),
                    Err(e) if e.code() == E_ACCESSDENIED => return Err(UiaCallError::AccessDenied),
                    Err(_) => None,
                }
            };

            let mut siblings_walked: usize = 0;
            let mut priority_children: Vec<(IUIAutomationElement, usize)> = Vec::new();
            while let Some(child) = cur {
                if siblings_walked >= MAX_SIBLINGS_PER_NODE
                    || inspected >= MAX_CHROME_NODES
                    || SystemCollectorClock::monotonic_ms_now() >= effective_deadline
                {
                    break;
                }
                siblings_walked += 1;
                let child_ct = unsafe { child.CachedControlType().ok().map(|ct| ct.0).unwrap_or(0) };
                // Skip Document/Tab/TabItem/Edit/Menu/ScrollBar so web/tab content is NEVER touched.
                if !matches!(
                    child_ct,
                    50030 | 50018 | 50019 | 50004 | 50009 | 50010 | 50011 | 50014
                ) {
                    let child_cls =
                        unsafe { child.CachedClassName().ok().and_then(non_empty_bstr) };
                    let skip_class = child_cls.as_deref().is_some_and(|cls| {
                        cls.eq_ignore_ascii_case("Chrome_RenderWidgetHostHWND")
                            || cls.eq_ignore_ascii_case("MozillaCompositorWindowClass")
                            || cls.eq_ignore_ascii_case("BookmarkBarView")
                            || cls.eq_ignore_ascii_case("BookmarkButton")
                            || cls.eq_ignore_ascii_case("ToolbarActionView")
                            || cls.eq_ignore_ascii_case("ExtensionsToolbarContainer")
                    });
                    if !skip_class {
                        if matches!(child_ct, 50000 | 50020 | 50025) {
                            inspected += 1;
                            let child_name =
                                unsafe { child.CachedName().ok().and_then(non_empty_bstr) };
                            if let Some(ref label) = child_name {
                                if BrowserGate::is_private_chrome_indicator(
                                    child_cls.as_deref(),
                                    label,
                                ) {
                                    return Ok(true);
                                }
                            }
                        }
                        if matches!(
                            child_ct,
                            50032 | 50033 | 50026 | 50021 | 50037 | 50025 | 50034
                        ) && inspected + queue.len() + priority_children.len() < MAX_CHROME_NODES
                        {
                            if matches!(child_ct, 50021 | 50037) || walk_tail_first {
                                priority_children.push((child.clone(), depth + 1));
                            } else {
                                queue.push_back((child.clone(), depth + 1));
                            }
                        }
                    }
                }
                cur = if walk_tail_first {
                    match unsafe {
                        self.walker
                            .GetPreviousSiblingElementBuildCache(&child, &self.chrome_probe_cache)
                    } {
                        Ok(sib) => Some(sib),
                        Err(e) if e.code() == E_ACCESSDENIED => {
                            return Err(UiaCallError::AccessDenied)
                        }
                        Err(_) => None,
                    }
                } else {
                    match unsafe {
                        self.walker
                            .GetNextSiblingElementBuildCache(&child, &self.chrome_probe_cache)
                    } {
                        Ok(sib) => Some(sib),
                        Err(e) if e.code() == E_ACCESSDENIED => {
                            return Err(UiaCallError::AccessDenied)
                        }
                        Err(_) => None,
                    }
                };
            }
            // Push prioritized children in reverse so tail-first / ToolBar order is preserved at front.
            for item in priority_children.into_iter().rev() {
                queue.push_front(item);
            }
        }

        Ok(false)
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
            let w = (r.right - r.left) as f64;
            let h = (r.bottom - r.top) as f64;
            if w < 0.0 || h < 0.0 {
                return None;
            }
            SurfaceAbsoluteRect::from_physical_pixels(r.left as f64, r.top as f64, w, h, dpi)
        });

        let is_password_bool = is_password == ProtectedContentRead::Value(true);

        // Determine sensitive subrole evidence from AriaRole / LocalizedControlType before reading Name.
        let sensitive_aria = aria_role
            .as_deref()
            .is_some_and(crate::policy::TextSecurityGate::is_sensitive_subrole);
        let sensitive_lct = localized_control_type
            .as_deref()
            .is_some_and(crate::policy::TextSecurityGate::is_sensitive_subrole);
        let effective_password = is_password_bool || sensitive_aria || sensitive_lct;

        let is_web_surface = class_name.as_deref().is_some_and(|c| {
            c.eq_ignore_ascii_case("Chrome_RenderWidgetHostHWND")
                || c.eq_ignore_ascii_case("MozillaCompositorWindowClass")
        }) || aria_role.as_deref().is_some_and(|r| {
            matches!(
                r.to_ascii_lowercase().as_str(),
                "document" | "webarea" | "rootwebarea" | "application" | "main"
            )
        });

        let is_heading = heading_level > HeadingLevel_None.0
            || aria_role
                .as_deref()
                .is_some_and(|r| r.eq_ignore_ascii_case("heading"));

        let is_multiline = if control_type == 50004 {
            if let Some(hwnd) = native_hwnd {
                (get_window_style(hwnd) & 0x0004) != 0
            } else {
                class_name
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

        let subrole_read = if effective_password {
            SubroleRead::Value("AXSecureTextField".to_string())
        } else if let Some(sub) = mapped.subrole {
            SubroleRead::Value(sub.to_string())
        } else if aria_role
            .as_deref()
            .is_some_and(|r| r.eq_ignore_ascii_case("searchbox"))
        {
            SubroleRead::Value("AXSearchField".to_string())
        } else {
            SubroleRead::NoValue
        };

        // PRIVACY INVARIANT: Never retain Name or AutomationId for password/sensitive controls!
        let (name, automation_id) = if effective_password {
            (None, None)
        } else {
            let n = unsafe { elem.CachedName().ok().and_then(non_empty_bstr) };
            let a = unsafe { elem.CachedAutomationId().ok().and_then(non_empty_bstr) };
            (n, a)
        };

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
    let truncated = raw_len > limit;
    let target_len = raw_len.min(limit).min(max_avail);
    let text = if target_len == raw_len {
        raw_str
    } else {
        bounded_utf16_slice(&raw_str, 0, target_len)?
    };
    let actual_len = utf16_len(&text);
    if actual_len == 0 {
        return None;
    }

    let mut missing_reasons = vec!["visible-range-only".to_string()];
    if truncated {
        missing_reasons.push("text-budget".to_string());
    }

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
                // SAFETY: Standard Win32 message pump until WM_QUIT is posted by stop().
                unsafe {
                    while GetMessageW(&mut msg, None, 0, 0).as_bool() {
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

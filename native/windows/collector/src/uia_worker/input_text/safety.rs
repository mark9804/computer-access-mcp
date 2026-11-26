//! Pre-read and post-read live privacy & editable-field safety gates for Windows `input.text`.
//!
//! Layer 1b submodule of `uia_worker::input_text` — imports ONLY Layer 0 (`target_verify`,
//! `input_hook::qpc_ns_now`) and core modules (`adapters`, `desktop`, `input_text_core`, `policy`,
//! `protocol_model`, `uia_com`, `uia_traversal`). ZERO imports of `menu_action`, `read_pipeline`,
//! or `session`.

use std::sync::atomic::{AtomicU64, Ordering};

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{
    GetAncestor, GetClassNameW, GetForegroundWindow, GetGUIThreadInfo, GetWindowLongW,
    GetWindowThreadProcessId, GA_ROOT, GUITHREADINFO, GUI_INMENUMODE, GUI_POPUPMENUMODE,
    GWL_STYLE,
};

use crate::adapters::AdapterRegistry;
use crate::desktop::assess_windows_desktop;
use crate::input_text_core::{
    InputTextApprovedContext, InputTextContext, InputTextFieldRole, InputTextGapReason,
    InputTextSafetyRequest,
};
use crate::policy::{ApplicationPolicy, BrowserGate, ResolvedAppIdentity};
use crate::protocol_model::{
    ApplicationIdentity, CapturePolicy, CollectorClock, DesktopStatus, SecureStatus,
};
use crate::uia_com::{PrivateChromeVerdict, UiaClient, UiaElementMetadata};
use crate::uia_traversal::RuntimeIdKey;
use crate::uia_worker::input_hook::qpc_ns_now;
use crate::uia_worker::target_verify::{
    classify_element_security_with_role, read_window_title_ephemeral,
    resolve_application_identity_for_hwnd,
};

/// Win32 Edit control password style (`ES_PASSWORD = 0x0020`).
const ES_PASSWORD_STYLE: u32 = 0x0020;

/// UIA `Edit` control type ID (`UIA_EditControlTypeId = 50004`).
const UIA_EDIT_CONTROL_TYPE: i32 = 50004;

/// Maximum per-event UIA safety verification timeout (ms), clamped to caller deadline & policy.
const MAX_INPUT_SAFETY_UIA_TIMEOUT_MS: i64 = 100;

/// Maximum native browser chrome scan slice inside a single input safety verification (ms).
const MAX_INPUT_SAFETY_CHROME_MS: i64 = 80;

/// Controls whether `verify_live_input_safety` runs the heavy full-tree browser chrome UIA walk
/// (`Full`) or skips ONLY that redundant second chrome walk on the Post-Gate pass ~5µs after
/// Pre-Gate already verified `PrivateChromeVerdict::VerifiedNormal` for the exact same keystroke /
/// IME commit (`PostReadFast`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::uia_worker) enum SafetyPassKind {
    /// Full live verification including `is_private_browser_window_chrome` (`VerifiedNormal`).
    /// Always used on Pre-Gate, IME commit Pre-Gate, and all Flush/Barrier revalidations.
    Full,
    /// Post-Gate pass inside the exact same keystroke / IME commit after Pre-Gate succeeded.
    /// Still runs ALL live gates (deadline, desktop unlocked, `focus_epoch`, `GetForegroundWindow`,
    /// `GetGUIThreadInfo` / `ES_PASSWORD` / menu mode, dual-ID identity and policy, ephemeral
    /// browser title, fresh UIA `focused_element()`, `read_cached_metadata`, sensitivity,
    /// `RuntimeIdKey`, editable role, `TextSecurityGate`, and final post-check), skipping ONLY the
    /// redundant second 80ms browser chrome tree walk.
    PostReadFast,
}

/// Select `SafetyPassKind::Full` on Pre-Gate and `SafetyPassKind::PostReadFast` ONLY once Pre-Gate
/// succeeded within the same event.
#[inline]
pub(in crate::uia_worker) const fn select_safety_pass_kind(
    pre_gate_chrome_verified: bool,
) -> SafetyPassKind {
    if pre_gate_chrome_verified {
        SafetyPassKind::PostReadFast
    } else {
        SafetyPassKind::Full
    }
}

/// Verified focused editable field bound by `read_pipeline.rs` after full pre/post-read gates.
#[derive(Clone)]
pub(in crate::uia_worker) struct BoundInputField {
    pub hwnd: HWND,
    pub raw_pid: u32,
    pub app: ApplicationIdentity,
    pub resolved: ResolvedAppIdentity,
    pub is_browser: bool,
    pub dpi: u32,
    pub is_terminal: bool,
    pub focus_runtime_id: RuntimeIdKey,
    pub focus_role: InputTextFieldRole,
    pub context: InputTextContext,
    pub policy: CapturePolicy,
    pub expected_focus_epoch: u64,
}

#[inline]
fn raw_hwnd_has_es_password_bit(hwnd: HWND) -> bool {
    if hwnd.0.is_null() {
        return false;
    }
    // SAFETY: Fast read-only Win32 window style lookup (zero cross-process IPC).
    let style = unsafe { GetWindowLongW(hwnd, GWL_STYLE) } as u32;
    (style & ES_PASSWORD_STYLE) != 0
}

/// Returns `true` when `hwnd` is a non-null Edit / RichEdit / Password-class Win32 window carrying
/// `ES_PASSWORD` (`0x0020`) in `GWL_STYLE`.
///
/// Checking an Edit/RichEdit/Password window class avoids false positives on unrelated Win32
/// common controls that reuse low-16 style bit `0x0020` (e.g. `TVS_SHOWSELALWAYS`,
/// `LVS_SORTDESCENDING`, `CBS_OWNERDRAWVARIABLE`, `DS_LOCALEDIT`).
pub fn hwnd_has_es_password_style(hwnd: HWND) -> bool {
    if !raw_hwnd_has_es_password_bit(hwnd) {
        return false;
    }
    let mut cls_buf = [0u16; 128];
    // SAFETY: Fast read-only Win32 class name query on live HWND.
    let len = unsafe { GetClassNameW(hwnd, &mut cls_buf) };
    if len <= 0 {
        return false;
    }
    let Ok(class_name) = String::from_utf16(&cls_buf[..len as usize]) else {
        return false;
    };
    let lower = class_name.to_ascii_lowercase();
    lower.contains("edit") || lower.contains("password")
}

/// Shared sensitivity check combining UIA `is_sensitive()` (`UIA_IsPasswordPropertyId`, sensitive
/// `AriaRole` / `LocalizedControlType` / `AriaProperties` `roledescription=`) and Win32
/// `ES_PASSWORD` (`0x0020`) style checks.
pub(in crate::uia_worker) fn is_sensitive_or_es_password_meta(meta: &UiaElementMetadata) -> bool {
    meta.is_sensitive()
        || meta.native_hwnd.is_some_and(hwnd_has_es_password_style)
        || (meta.control_type == UIA_EDIT_CONTROL_TYPE
            && meta.native_hwnd.is_some_and(raw_hwnd_has_es_password_bit))
}

/// Query foreground GUI thread focus HWND, active menu mode, and pre-UIA `ES_PASSWORD` status
/// via `GetWindowThreadProcessId` + `GetGUIThreadInfo` (zero blocking IPC).
///
/// Returns `Some((hwnd_focus, in_menu_mode, is_es_password))`.
pub fn query_foreground_gui_state(fg_hwnd: HWND) -> Option<(HWND, bool, bool)> {
    if fg_hwnd.0.is_null() {
        return None;
    }
    // SAFETY: Fast read-only Win32 thread ID query.
    let fg_tid = unsafe { GetWindowThreadProcessId(fg_hwnd, None) };
    if fg_tid == 0 {
        return None;
    }
    let mut gui = GUITHREADINFO {
        cbSize: std::mem::size_of::<GUITHREADINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: Fast kernel GUI thread info query (no `AttachThreadInput`, no cross-process IPC).
    unsafe { GetGUIThreadInfo(fg_tid, &mut gui).ok()? };
    let in_menu_mode = (gui.flags.0 & (GUI_INMENUMODE.0 | GUI_POPUPMENUMODE.0)) != 0;
    let is_es_password = hwnd_has_es_password_style(gui.hwndFocus);
    Some((gui.hwndFocus, in_menu_mode, is_es_password))
}

fn focused_meta_belongs_to_bound(meta: &UiaElementMetadata, bound: &BoundInputField) -> bool {
    let pid_ok = meta.process_id == 0
        || meta.process_id == bound.app.process_id
        || (bound.raw_pid != 0 && meta.process_id == bound.raw_pid);
    if !pid_ok {
        return false;
    }
    if let Some(native) = meta.native_hwnd {
        if native == bound.hwnd {
            return true;
        }
        // SAFETY: Fast read-only Win32 root ancestor query.
        let root = unsafe { GetAncestor(native, GA_ROOT) };
        return root == bound.hwnd;
    }
    // Virtual UIA fragment without native HWND: require explicit PID match against bound app/host.
    meta.process_id == bound.app.process_id
        || (bound.raw_pid != 0 && meta.process_id == bound.raw_pid)
}

/// Full synchronous live pre/post safety gate for Windows `input.text` events, TSF IME commits,
/// due flushes, and read-barrier drains.
///
/// PRIVACY INVARIANT:
/// - Never permanently latches `secure_input_detected` on a normal Windows password field
///   (`ES_PASSWORD` / `UIA_IsPasswordPropertyId`); returns `Err(InputTextGapReason::PolicyBoundary)`
///   so `InputTextSession` purges & zeroizes buffers and disarms `context_ready = false` until
///   focus returns to a verified non-password editable field.
#[allow(clippy::too_many_arguments)]
pub(in crate::uia_worker) fn verify_live_input_safety(
    uia: &UiaClient,
    registry: &AdapterRegistry,
    bound: &BoundInputField,
    request: InputTextSafetyRequest<'_>,
    focus_epoch_atomic: &AtomicU64,
    pass_kind: SafetyPassKind,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Result<InputTextApprovedContext, InputTextGapReason> {
    // 1. Deadline gate.
    if clock.monotonic_ms() >= deadline_ms {
        return Err(InputTextGapReason::VerificationTimeout);
    }

    if !bound.policy.enabled
        || bound.policy.input_text != Some(true)
        || !bound.policy.has_valid_text_settings()
        || !bound.context.is_valid()
        || bound.focus_runtime_id.is_empty()
    {
        return Err(InputTextGapReason::Stale);
    }

    // 2. Unlocked desktop gate.
    if assess_windows_desktop().status != DesktopStatus::Unlocked {
        return Err(InputTextGapReason::Stale);
    }

    // 3. Atomic focus epoch gate (sub-10ms flicker rejection).
    if focus_epoch_atomic.load(Ordering::Acquire) != bound.expected_focus_epoch {
        return Err(InputTextGapReason::TargetMismatch);
    }

    // 4. Foreground HWND gate.
    // SAFETY: Fast read-only foreground window lookup.
    let fg = unsafe { GetForegroundWindow() };
    if fg.0.is_null() || fg != bound.hwnd {
        return Err(InputTextGapReason::TargetMismatch);
    }

    // 5. Fast pre-UIA GUI thread check (ES_PASSWORD and active menu mode).
    match query_foreground_gui_state(bound.hwnd) {
        Some((_, _, true)) => return Err(InputTextGapReason::PolicyBoundary),
        Some((_, true, false)) | None => return Err(InputTextGapReason::Stale),
        Some((_, false, false)) => {}
    }

    // 6. Request PID / context consistency check.
    match request {
        InputTextSafetyRequest::Event(meta) => {
            if meta.target_process_id != bound.app.process_id {
                return Err(InputTextGapReason::process_mismatch(
                    bound.app.process_id,
                    i64::from(meta.target_process_id),
                ));
            }
        }
        InputTextSafetyRequest::Flush(old) => {
            if *old != bound.context {
                return Err(InputTextGapReason::context_mismatch(old, &bound.context));
            }
        }
    }

    // 7. Re-verify dual-ID application identity & policy allowlist/denylist/browser gates.
    let Some((_, current_app, current_resolved)) =
        resolve_application_identity_for_hwnd(bound.hwnd, None, None)
    else {
        return Err(InputTextGapReason::Stale);
    };
    if current_app != bound.app || current_resolved != bound.resolved {
        return Err(InputTextGapReason::TargetMismatch);
    }
    if !ApplicationPolicy::allows_identity(&bound.policy, &current_resolved)
        || !BrowserGate::allows_identity(&current_resolved, &bound.policy, false)
    {
        return Err(InputTextGapReason::PolicyBoundary);
    }

    // 8. Browser private window title & fail-closed native chrome gate.
    let spec = registry.adapter_for_identity(&current_resolved);
    let requires_browser_check = bound.is_browser
        || BrowserGate::is_known_browser_identity(&current_resolved)
        || BrowserGate::should_block_private_windows_identity(
            &current_resolved,
            spec.block_private_windows,
        );
    if requires_browser_check {
        let Some(title) = read_window_title_ephemeral(bound.hwnd) else {
            return Err(InputTextGapReason::PolicyBoundary);
        };
        if BrowserGate::is_private_window_title(&title) {
            return Err(InputTextGapReason::PolicyBoundary);
        }
        drop(title);

        let run_chrome_walk =
            pass_kind == SafetyPassKind::Full || matches!(request, InputTextSafetyRequest::Flush(_));
        if run_chrome_walk {
            let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
            if rem <= 0 {
                return Err(InputTextGapReason::VerificationTimeout);
            }
            let chrome_deadline = clock
                .monotonic_ms()
                .saturating_add(MAX_INPUT_SAFETY_CHROME_MS)
                .min(deadline_ms);
            match uia.is_private_browser_window_chrome(bound.hwnd, chrome_deadline, deadline_ms) {
                Ok(PrivateChromeVerdict::VerifiedNormal) => {}
                Ok(PrivateChromeVerdict::Private) => return Err(InputTextGapReason::PolicyBoundary),
                Ok(PrivateChromeVerdict::Inconclusive) | Err(_) => {
                    return Err(if clock.monotonic_ms() >= deadline_ms {
                        InputTextGapReason::VerificationTimeout
                    } else {
                        InputTextGapReason::Stale
                    });
                }
            }
        }
    }

    // 9. Bounded UIA timeout clamped to <= min(100ms, policy.read_timeout_ms) and remaining budget.
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if rem <= 0 {
        return Err(InputTextGapReason::VerificationTimeout);
    }
    let bounded_timeout = rem
        .min(MAX_INPUT_SAFETY_UIA_TIMEOUT_MS)
        .min(bound.policy.read_timeout_ms.max(25));
    uia.apply_timeouts(bounded_timeout);

    // 10. Fresh UIA focused element + safe cached metadata verification.
    let elem = match uia.focused_element() {
        Ok(el) => el,
        Err(_) => {
            return Err(if clock.monotonic_ms() >= deadline_ms {
                InputTextGapReason::VerificationTimeout
            } else {
                InputTextGapReason::Stale
            });
        }
    };
    let meta = match uia.read_cached_metadata(&elem, bound.dpi, false, bound.is_terminal) {
        Ok(m) => m,
        Err(_) => {
            return Err(if clock.monotonic_ms() >= deadline_ms {
                InputTextGapReason::VerificationTimeout
            } else {
                InputTextGapReason::Stale
            });
        }
    };

    if is_sensitive_or_es_password_meta(&meta) {
        return Err(InputTextGapReason::PolicyBoundary);
    }
    if meta.runtime_id.is_empty() || meta.runtime_id != bound.focus_runtime_id {
        return Err(InputTextGapReason::TargetMismatch);
    }
    if !focused_meta_belongs_to_bound(&meta, bound) {
        return Err(InputTextGapReason::TargetMismatch);
    }

    let effective_role = if meta.is_focused_editable_content() {
        Some("AXTextArea")
    } else {
        meta.mapped.ax_role
    };
    let role = if meta.is_read_only {
        None
    } else {
        match effective_role {
            Some("AXTextField") => Some(InputTextFieldRole::TextField),
            Some("AXTextArea") => Some(InputTextFieldRole::TextArea),
            _ => None,
        }
    };
    let Some(role) = role else {
        return Err(InputTextGapReason::RoleNotEditable);
    };
    if role != bound.focus_role {
        return Err(InputTextGapReason::TargetMismatch);
    }

    let sec = classify_element_security_with_role(&meta, effective_role, &bound.policy);
    if sec == SecureStatus::Sensitive {
        return Err(InputTextGapReason::PolicyBoundary);
    }
    if !bound.policy.allows_secure(sec) {
        return Err(InputTextGapReason::FieldSecurityUnknown);
    }
    if sec != bound.context.secure_status {
        return Err(InputTextGapReason::Stale);
    }

    // 11. Final post-check immediately before issuing approval.
    if clock.monotonic_ms() >= deadline_ms {
        return Err(InputTextGapReason::VerificationTimeout);
    }
    if assess_windows_desktop().status != DesktopStatus::Unlocked {
        return Err(InputTextGapReason::Stale);
    }
    if focus_epoch_atomic.load(Ordering::Acquire) != bound.expected_focus_epoch {
        return Err(InputTextGapReason::TargetMismatch);
    }
    // SAFETY: Fast read-only foreground window lookup.
    if unsafe { GetForegroundWindow() } != bound.hwnd {
        return Err(InputTextGapReason::TargetMismatch);
    }
    match query_foreground_gui_state(bound.hwnd) {
        Some((_, _, true)) => return Err(InputTextGapReason::PolicyBoundary),
        Some((_, true, false)) | None => return Err(InputTextGapReason::Stale),
        Some((_, false, false)) => {}
    }

    // 12. Issue fresh approval timestamped strictly on the worker QPC monotonic clock.
    Ok(InputTextApprovedContext {
        context: bound.context.clone(),
        metadata_monotonic_ns: qpc_ns_now(),
        role,
    })
}

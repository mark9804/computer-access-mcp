//! Pure + safe Win32 key translation (`ToUnicodeEx(0x0004)` non-mutating, `VK_PACKET` surrogate
//! assembly, `VK_PROCESSKEY` detection) and bounded legacy IMM32 open-status probing.
//!
//! Layer 1a submodule of `uia_worker::input_text` — imports ONLY Layer 0 (`input_hook`) and
//! `input_text_core`. ZERO imports of `safety`, `menu_action`, `read_pipeline`, or `session`.

use std::sync::atomic::{compiler_fence, Ordering};

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Input::Ime::ImmGetDefaultIMEWnd;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyboardLayout, ToUnicodeEx, HKL, VK_CAPITAL, VK_CONTROL, VK_ESCAPE, VK_LCONTROL, VK_LMENU,
    VK_LSHIFT, VK_LWIN, VK_MENU, VK_NUMLOCK, VK_PACKET, VK_PROCESSKEY, VK_RCONTROL, VK_RETURN,
    VK_RMENU, VK_RSHIFT, VK_RWIN, VK_SCROLL, VK_SHIFT,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetWindowThreadProcessId, SendMessageTimeoutW, SMTO_ABORTIFHUNG, SMTO_BLOCK, WM_IME_CONTROL,
};

use crate::input_text_core::{
    InputTextUnicodeRead, PendingSurrogate, SurrogateAssemblyOutcome, WindowsModifierState,
};
use crate::uia_worker::input_hook::{
    MOD_BIT_CAPS_LOCK, MOD_BIT_LCONTROL, MOD_BIT_LLKHF_ALTDOWN, MOD_BIT_LMENU, MOD_BIT_LSHIFT,
    MOD_BIT_LWIN, MOD_BIT_RCONTROL, MOD_BIT_RMENU, MOD_BIT_RSHIFT, MOD_BIT_RWIN,
};

/// Win10 1607+ `ToUnicodeEx` `wFlags` bit preventing kernel dead-key state mutation.
pub const TO_UNICODE_NO_STATE_MUTATION_FLAG: u32 = 0x0004;

/// Win32 `imm.h` `IMC_GETCONVERSIONMODE` (`0x0001`) sub-command for `WM_IME_CONTROL`.
const IMC_GETCONVERSIONMODE: usize = 0x0001;
/// Win32 `imm.h` `IMC_GETOPENSTATUS` (`0x0005`) sub-command for `WM_IME_CONTROL` (not re-exported
/// by `windows 0.62` alongside `IMC_SETOPENSTATUS = 0x0006`).
const IMC_GETOPENSTATUS: usize = 0x0005;
/// Win32 `imm.h` `IME_CMODE_NATIVE` (`0x0001`) conversion-mode bit indicating active native CJK
/// conversion (vs alphanumeric / English pass-through).
const IME_CMODE_NATIVE: usize = 0x0001;

/// `VK_RETURN` (`0x0D`).
pub const VK_RETURN_CODE: u32 = VK_RETURN.0 as u32;
/// `VK_ESCAPE` (`0x1B`).
pub const VK_ESCAPE_CODE: u32 = VK_ESCAPE.0 as u32;
/// `VK_PROCESSKEY` (`0xE5`, 229) emitted when an IME claims the keystroke.
pub const VK_PROCESSKEY_CODE: u32 = VK_PROCESSKEY.0 as u32;
/// `VK_PACKET` (`0xE7`, 231) carrying a UTF-16 code unit in `scan_code`.
pub const VK_PACKET_CODE: u32 = VK_PACKET.0 as u32;

/// Per-step ceiling (ms) for the two-step native IME probe (combined cap `12 + 12 = 24ms <= 25ms`).
const IMM32_NATIVE_STEP_TIMEOUT_MS: u32 = 12;

/// Map `RawKeyDownSnapshot::mod_bits` (`MOD_BIT_*`) into platform-free [`WindowsModifierState`].
///
/// Honors `MOD_BIT_LLKHF_ALTDOWN` as `left_alt = true` if neither `MOD_BIT_LMENU` nor
/// `MOD_BIT_RMENU` was set (preserving exact `AltGr` detection when `RMENU` is set).
pub fn mod_bits_to_windows_modifiers(mod_bits: u16) -> WindowsModifierState {
    let raw_lmenu = (mod_bits & MOD_BIT_LMENU) != 0;
    let raw_rmenu = (mod_bits & MOD_BIT_RMENU) != 0;
    let altdown_fallback = (mod_bits & MOD_BIT_LLKHF_ALTDOWN) != 0 && !raw_lmenu && !raw_rmenu;

    WindowsModifierState {
        left_ctrl: (mod_bits & MOD_BIT_LCONTROL) != 0,
        right_ctrl: (mod_bits & MOD_BIT_RCONTROL) != 0,
        left_alt: raw_lmenu || altdown_fallback,
        right_alt: raw_rmenu,
        left_shift: (mod_bits & MOD_BIT_LSHIFT) != 0,
        right_shift: (mod_bits & MOD_BIT_RSHIFT) != 0,
        left_win: (mod_bits & MOD_BIT_LWIN) != 0,
        right_win: (mod_bits & MOD_BIT_RWIN) != 0,
    }
}

/// Returns `true` for standalone modifier / lock virtual keys that never produce character text
/// and should be ignored before calling `ToUnicodeEx` (preventing spurious UIA safety IPCs/gaps).
pub fn is_modifier_only_vk(vk_code: u32) -> bool {
    matches!(
        vk_code,
        x if x == u32::from(VK_SHIFT.0)
            || x == u32::from(VK_CONTROL.0)
            || x == u32::from(VK_MENU.0)
            || x == u32::from(VK_LSHIFT.0)
            || x == u32::from(VK_RSHIFT.0)
            || x == u32::from(VK_LCONTROL.0)
            || x == u32::from(VK_RCONTROL.0)
            || x == u32::from(VK_LMENU.0)
            || x == u32::from(VK_RMENU.0)
            || x == u32::from(VK_LWIN.0)
            || x == u32::from(VK_RWIN.0)
            || x == u32::from(VK_CAPITAL.0)
            || x == u32::from(VK_NUMLOCK.0)
            || x == u32::from(VK_SCROLL.0)
    )
}

/// Returns `true` for virtual keys that commonly toggle CJK IME open / native conversion mode
/// (`Shift`, `LShift`, `RShift`, `CapsLock`, `Space`, `VK_KANA`/`VK_HANGUL` `0x15`, `VK_KANJI`
/// `0x19`) and must immediately invalidate any cached legacy IMM32 probe.
pub fn is_imm32_toggle_vk(vk_code: u32) -> bool {
    const VK_KANA_OR_HANGUL: u32 = 0x15;
    const VK_KANJI_CODE: u32 = 0x19;
    const VK_SPACE_CODE: u32 = 0x20;
    vk_code == u32::from(VK_SHIFT.0)
        || vk_code == u32::from(VK_LSHIFT.0)
        || vk_code == u32::from(VK_RSHIFT.0)
        || vk_code == u32::from(VK_CAPITAL.0)
        || vk_code == VK_SPACE_CODE
        || vk_code == VK_KANA_OR_HANGUL
        || vk_code == VK_KANJI_CODE
}

/// Returns `true` for raw ASCII letters (`'A'..='Z'`) or `VK_RETURN` virtual keys suppressed on
/// legacy non-TSF controls when IMM32 native CJK conversion mode is active.
pub fn is_imm32_suppressed_vk(vk_code: u32) -> bool {
    (0x41..=0x5A).contains(&vk_code) || vk_code == VK_RETURN_CODE
}

/// Build the minimal 256-byte `lpKeyState` table for `ToUnicodeEx`.
///
/// Populates ONLY:
/// - `VK_SHIFT` / `VK_LSHIFT` / `VK_RSHIFT` (`0x80`)
/// - `VK_CAPITAL` (`0x01` when `MOD_BIT_CAPS_LOCK` is set)
/// - When `is_altgr == true`, ALSO `VK_CONTROL` / `VK_LCONTROL` / `VK_MENU` / `VK_RMENU` (`0x80`)
///
/// INVARIANT: NEVER populates raw `Ctrl` or `Win` bits for shortcuts (shortcuts never call
/// `ToUnicodeEx`).
pub fn build_minimal_key_state(mod_bits: u16, is_altgr: bool) -> [u8; 256] {
    let mut state = [0u8; 256];
    let lshift = (mod_bits & MOD_BIT_LSHIFT) != 0;
    let rshift = (mod_bits & MOD_BIT_RSHIFT) != 0;
    if lshift {
        state[usize::from(VK_LSHIFT.0)] = 0x80;
    }
    if rshift {
        state[usize::from(VK_RSHIFT.0)] = 0x80;
    }
    if lshift || rshift {
        state[usize::from(VK_SHIFT.0)] = 0x80;
    }
    if (mod_bits & MOD_BIT_CAPS_LOCK) != 0 {
        state[usize::from(VK_CAPITAL.0)] = 0x01;
    }
    if is_altgr {
        state[usize::from(VK_CONTROL.0)] = 0x80;
        state[usize::from(VK_LCONTROL.0)] = 0x80;
        state[usize::from(VK_MENU.0)] = 0x80;
        state[usize::from(VK_RMENU.0)] = 0x80;
    }
    state
}

/// Feed a `VK_PACKET` (`0xE7`) `scan_code` UTF-16 code unit into [`PendingSurrogate`].
///
/// - Complete BMP scalar or assembled surrogate pair -> `InputTextUnicodeRead::Text(s)`
/// - `PendingHigh` / `DroppedOrphan` -> `InputTextUnicodeRead::Text(String::new())` (cleanly
///   mapped to `Ignored` by `InputTextReadGate`, never emitting U+FFFD).
pub fn translate_vk_packet(
    scan_code: u32,
    unix_ms: i64,
    pending_surrogate: &mut PendingSurrogate,
) -> InputTextUnicodeRead {
    let unit = (scan_code & 0xFFFF) as u16;
    match pending_surrogate.push(unit, unix_ms) {
        SurrogateAssemblyOutcome::Text(text) => InputTextUnicodeRead::Text(text),
        SurrogateAssemblyOutcome::PendingHigh | SurrogateAssemblyOutcome::DroppedOrphan => {
            InputTextUnicodeRead::Text(String::new())
        }
    }
}

/// Core non-mutating `ToUnicodeEx(..., wFlags = 0x0004, Some(hkl))` translation using an explicit
/// `HKL`, stack `[u16; 16]` buffer, and mandatory zeroization on every exit path.
pub fn translate_vk_with_layout(
    vk_code: u32,
    scan_code: u32,
    mod_bits: u16,
    is_altgr: bool,
    hkl: HKL,
) -> InputTextUnicodeRead {
    if vk_code == VK_PROCESSKEY_CODE || is_modifier_only_vk(vk_code) {
        return InputTextUnicodeRead::Text(String::new());
    }
    if vk_code == VK_RETURN_CODE {
        return InputTextUnicodeRead::Text("\r".to_string());
    }

    let key_state = build_minimal_key_state(mod_bits, is_altgr);
    let mut buf = [0u16; 16];
    // SAFETY: `TO_UNICODE_NO_STATE_MUTATION_FLAG` (0x0004, Win10 1607+) guarantees `ToUnicodeEx`
    // NEVER mutates OS dead-key state. `buf` is zeroized unconditionally before returning.
    let ret = unsafe {
        ToUnicodeEx(
            vk_code,
            scan_code,
            &key_state,
            &mut buf,
            TO_UNICODE_NO_STATE_MUTATION_FLAG,
            Some(hkl),
        )
    };

    let outcome = if ret <= 0 {
        // `ret == 0` (no translation) or `ret < 0` (dead key): cleanly ignored without mutating
        // OS dead-key state or emitting an error gap.
        InputTextUnicodeRead::Text(String::new())
    } else {
        let count = ret as usize;
        if count >= buf.len() {
            InputTextUnicodeRead::Saturated
        } else {
            match String::from_utf16(&buf[..count]) {
                Ok(text) => InputTextUnicodeRead::Text(text),
                Err(_) => InputTextUnicodeRead::Unavailable,
            }
        }
    };

    for u in buf.iter_mut() {
        // SAFETY: Valid mutable reference to initialized stack u16; volatile write resists DSE.
        unsafe {
            core::ptr::write_volatile(u as *mut u16, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
    outcome
}

/// Translate a non-shortcut, non-`VK_PACKET`, non-`VK_PROCESSKEY` keystroke using the focused
/// window thread's active `HKL` (falling back to the current thread layout if `focus_tid == 0`
/// or `GetKeyboardLayout(focus_tid)` is null).
pub fn translate_key_to_unicode(
    vk_code: u32,
    scan_code: u32,
    mod_bits: u16,
    is_altgr: bool,
    focus_hwnd: HWND,
) -> InputTextUnicodeRead {
    if vk_code == VK_PROCESSKEY_CODE || is_modifier_only_vk(vk_code) {
        return InputTextUnicodeRead::Text(String::new());
    }
    if vk_code == VK_RETURN_CODE {
        return InputTextUnicodeRead::Text("\r".to_string());
    }

    let focus_tid = if !focus_hwnd.0.is_null() {
        // SAFETY: Fast read-only Win32 thread ID lookup.
        unsafe { GetWindowThreadProcessId(focus_hwnd, None) }
    } else {
        0
    };
    // SAFETY: Read-only keyboard layout lookup; fallback to current thread layout if unavailable.
    let mut hkl = unsafe { GetKeyboardLayout(focus_tid) };
    if hkl.0.is_null() && focus_tid != 0 {
        hkl = unsafe { GetKeyboardLayout(0) };
    }
    translate_vk_with_layout(vk_code, scan_code, mod_bits, is_altgr, hkl)
}

/// Testable public helper invoking `ToUnicodeEx(..., wFlags = 0x0004)` directly with an optional
/// `HKL` override (defaults to the current thread's active keyboard layout).
pub fn translate_vk_non_mutating_for_test(
    vk_code: u32,
    scan_code: u32,
    mod_bits: u16,
    is_altgr: bool,
    hkl_override: Option<HKL>,
) -> InputTextUnicodeRead {
    let hkl = hkl_override.unwrap_or_else(|| {
        // SAFETY: Read-only current-thread keyboard layout lookup.
        unsafe { GetKeyboardLayout(0) }
    });
    translate_vk_with_layout(vk_code, scan_code, mod_bits, is_altgr, hkl)
}

/// Bounded two-step legacy IMM32 native-IME probe using `ImmGetDefaultIMEWnd` +
/// `SendMessageTimeoutW(..., SMTO_ABORTIFHUNG | SMTO_BLOCK, ...)` with a combined timeout strictly
/// clamped to `min(max_total_timeout_ms, 24)` ms (`<= 12 ms` per step).
///
/// Returns:
/// - `Some(true)` ONLY when the target window's IME is BOTH open AND in native CJK conversion mode
///   (`(conversion_mode & IME_CMODE_NATIVE) != 0`).
/// - `Some(false)` when the IME is closed OR in English/alphanumeric mode.
/// - `None` if `focus_hwnd` is null, remaining budget `< 2 ms`, has no default IME window, or
///   either probe times out/fails.
///
/// INVARIANT: NEVER calls blocking `SendMessageW`.
pub fn query_imm32_native_ime_active_bounded(
    focus_hwnd: HWND,
    max_total_timeout_ms: u32,
) -> Option<bool> {
    if focus_hwnd.0.is_null() || max_total_timeout_ms < 2 {
        return None;
    }
    let step_timeout_ms = (max_total_timeout_ms / 2).clamp(1, IMM32_NATIVE_STEP_TIMEOUT_MS);
    // SAFETY: Fast read-only default IME window lookup; returns null if unavailable.
    let ime_wnd = unsafe { ImmGetDefaultIMEWnd(focus_hwnd) };
    if ime_wnd.0.is_null() {
        return None;
    }

    let mut open_status: usize = 0;
    // SAFETY: Bounded `SendMessageTimeoutW` with `SMTO_ABORTIFHUNG | SMTO_BLOCK`.
    let open_sent = unsafe {
        SendMessageTimeoutW(
            ime_wnd,
            WM_IME_CONTROL,
            WPARAM(IMC_GETOPENSTATUS),
            LPARAM(0),
            SMTO_ABORTIFHUNG | SMTO_BLOCK,
            step_timeout_ms,
            Some(&mut open_status),
        )
    };
    if open_sent.0 == 0 {
        return None;
    }
    if open_status == 0 {
        return Some(false);
    }

    let mut conv_mode: usize = 0;
    // SAFETY: Bounded `SendMessageTimeoutW` with `SMTO_ABORTIFHUNG | SMTO_BLOCK`
    // (combined worst-case timeout budget across both steps: `<= min(max_total_timeout_ms, 24) ms`).
    let conv_sent = unsafe {
        SendMessageTimeoutW(
            ime_wnd,
            WM_IME_CONTROL,
            WPARAM(IMC_GETCONVERSIONMODE),
            LPARAM(0),
            SMTO_ABORTIFHUNG | SMTO_BLOCK,
            step_timeout_ms,
            Some(&mut conv_mode),
        )
    };
    if conv_sent.0 == 0 {
        return None;
    }
    Some((conv_mode & IME_CMODE_NATIVE) != 0)
}

//! Control-process Win32 Raw Input activity monitor (`input.activity` / `win32.listen-only`).
//!
//! Architecture & invariants:
//! - Runs on a lightweight `raw-input` thread in the control process with a hidden
//!   `HWND_MESSAGE` window; ZERO COM/UIA calls, ZERO `WH_*_LL` hooks, ZERO cross-process
//!   `SendMessageW`.
//! - Registers `RIDEV_INPUTSINK` (physically listen-only) for Generic Desktop Mouse and Keyboard
//!   plus `WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)` for `<1ms` lock and
//!   console/RDP disconnect latching.
//! - Strictly acyclic: zero imports from `crate::uia_worker`.
//! - Pre-read privacy gates execute BEFORE `GetRawInputData`: locked/secure desktop, excluded or
//!   unresolved apps, and private browser titles are rejected before reading raw HID payloads.
//! - Zero keycode, Unicode, or cursor coordinate retention: ephemeral bitsets and RDP absolute
//!   drag anchors are cleared on release, foreground change, boundary reset, and lock/disconnect.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use windows::core::PCWSTR;
use windows::Win32::Devices::HumanInterfaceDevice::{
    HID_USAGE_GENERIC_KEYBOARD, HID_USAGE_GENERIC_MOUSE, HID_USAGE_PAGE_GENERIC,
};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, WTSUnRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, DESKTOP_CONTROL_FLAGS,
    DESKTOP_READOBJECTS, UOI_NAME,
};
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    VK_CONTROL, VK_LCONTROL, VK_LMENU, VK_LSHIFT, VK_LWIN, VK_MENU, VK_PACKET, VK_PROCESSKEY,
    VK_RCONTROL, VK_RMENU, VK_RSHIFT, VK_RWIN, VK_SHIFT,
};
use windows::Win32::UI::Input::{
    GetRawInputData, RegisterRawInputDevices, HRAWINPUT, MOUSE_MOVE_ABSOLUTE, RAWINPUT,
    RAWINPUTDEVICE, RAWINPUTHEADER, RAWKEYBOARD, RAWMOUSE, RIDEV_INPUTSINK, RIDEV_REMOVE,
    RID_INPUT, RIM_TYPEKEYBOARD, RIM_TYPEMOUSE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetAncestor, GetCursorPos,
    GetForegroundWindow, GetMessageW, GetWindowLongPtrW, PostMessageW, PostQuitMessage,
    PostThreadMessageW, SetWindowLongPtrW, UnregisterClassW, WindowFromPoint, CREATESTRUCTW,
    GA_ROOT, GWLP_USERDATA, HCURSOR, HICON, HWND_MESSAGE, MSG, RI_KEY_BREAK, RI_KEY_E0, RI_KEY_E1,
    RI_MOUSE_HWHEEL, RI_MOUSE_LEFT_BUTTON_DOWN, RI_MOUSE_LEFT_BUTTON_UP,
    RI_MOUSE_MIDDLE_BUTTON_DOWN, RI_MOUSE_MIDDLE_BUTTON_UP, RI_MOUSE_RIGHT_BUTTON_DOWN,
    RI_MOUSE_RIGHT_BUTTON_UP, RI_MOUSE_WHEEL, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_DESTROY,
    WM_INPUT, WM_NCCREATE, WM_QUIT, WM_WTSSESSION_CHANGE, WNDCLASS_STYLES, WNDPROC,
    WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK, WTS_SESSION_LOGOFF,
};

use crate::desktop::{assess_windows_desktop, DesktopBoundaryLatch};
use crate::ownership::current_wts_session_id;
use crate::policy::{
    read_window_title_ephemeral, resolve_application_identity_for_hwnd, ApplicationPolicy,
    BrowserGate, ResolvedAppIdentity,
};
use crate::protocol_model::{
    ApplicationIdentity, CapturePolicy, DesktopStatus, InputActivityCategory, InputActivitySample,
    SystemCollectorClock,
};

/// Maximum accepted age of a Raw Input event (200ms) matching macOS `InputActivityFreshness`.
pub const MAX_EVENT_AGE_NS: u64 = 200_000_000;

/// Maximum accepted Win32 message-queue delay (200ms) for a dispatched `WM_INPUT` message.
pub const MAX_MESSAGE_QUEUE_DELAY_MS: u32 = 200;

/// Hard upper bound on queued `RawInputNotice` entries so bursty input cannot grow RAM unboundedly.
pub const MAX_QUEUED_NOTICES: usize = 512;

const MOUSE_BTN_LEFT: u8 = 0b001;
const MOUSE_BTN_RIGHT: u8 = 0b010;
const MOUSE_BTN_MIDDLE: u8 = 0b100;

const STOP_CLOSE_WAIT_MS: u64 = 500;
const STOP_QUIT_WAIT_MS: u64 = 1_500;

static NEXT_CLASS_SEQ: AtomicU64 = AtomicU64::new(1);

/// Current system-wide monotonic QPC timestamp in nanoseconds.
pub fn monotonic_qpc_ns_now() -> u64 {
    let mut freq: i64 = 0;
    let mut counter: i64 = 0;
    // SAFETY: QueryPerformanceFrequency and QueryPerformanceCounter always succeed on Windows XP+.
    unsafe {
        let _ = QueryPerformanceFrequency(&mut freq);
        let _ = QueryPerformanceCounter(&mut counter);
    }
    if freq <= 0 || counter <= 0 {
        return 0;
    }
    let ns = (counter as u128).saturating_mul(1_000_000_000) / (freq as u128);
    u64::try_from(ns).unwrap_or(u64::MAX)
}

/// Pure freshness & epoch-fence predicate mirroring macOS `InputActivityFreshness::accepts`.
pub fn accepts_qpc_timestamp(
    event_qpc_ns: u64,
    now_qpc_ns: u64,
    accept_after_qpc_ns: u64,
) -> bool {
    event_qpc_ns > accept_after_qpc_ns
        && event_qpc_ns <= now_qpc_ns
        && now_qpc_ns - event_qpc_ns <= MAX_EVENT_AGE_NS
}

/// Compute wrapping 32-bit tick queue delay (`now_tick - msg_time`) in milliseconds.
/// Returns `0` if `msg_time` appears slightly ahead of `now_tick` (timer jitter/wrap).
fn message_queue_delay_ms(now_tick_ms: u32, msg_time_ms: u32) -> u32 {
    let delta = now_tick_ms.wrapping_sub(msg_time_ms);
    if delta >= 0x8000_0000 {
        0
    } else {
        delta
    }
}

/// Ephemeral Raw Input mouse packet fields (copied onto stack and discarded immediately).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RawMouseEvent {
    pub flags: u16,
    pub button_flags: u16,
    pub last_x: i32,
    pub last_y: i32,
}

/// Ephemeral Raw Input keyboard packet fields (copied onto stack and discarded immediately).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RawKeyboardEvent {
    pub make_code: u16,
    pub flags: u16,
    pub vkey: u16,
}

/// Pure, platform-independent classifier for Win32 Raw Input mouse and keyboard packets.
///
/// Tracks ONLY ephemeral held-button bits, an ephemeral `[u64; 4]` held-keys bitset (for
/// autorepeat suppression), left/right Ctrl/Alt/Win modifier flags (for European AltGr
/// disambiguation), and an ephemeral previous RDP/tablet absolute coordinate pair while a mouse
/// button is held. All state is cleared on release and on every boundary reset.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RawInputClassifier {
    held_buttons: u8,
    last_abs_pos: Option<(i32, i32)>,
    held_keys: [u64; 4],
    lctrl: bool,
    rctrl: bool,
    lalt: bool,
    ralt: bool,
    lwin: bool,
    rwin: bool,
}

impl RawInputClassifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all ephemeral held buttons, held keys bitset, modifier latches, and RDP absolute coords.
    pub fn clear(&mut self) {
        self.held_buttons = 0;
        self.last_abs_pos = None;
        self.held_keys = [0; 4];
        self.lctrl = false;
        self.rctrl = false;
        self.lalt = false;
        self.ralt = false;
        self.lwin = false;
        self.rwin = false;
    }

    pub fn held_buttons_mask(&self) -> u8 {
        self.held_buttons
    }

    pub fn has_last_abs_pos(&self) -> bool {
        self.last_abs_pos.is_some()
    }

    pub fn is_altgr_active(&self) -> bool {
        self.lctrl && self.ralt && !self.rctrl && !self.lalt && !self.lwin && !self.rwin
    }

    /// Classify a Raw Input mouse packet into zero or more coarse `InputActivityCategory` values.
    ///
    /// Allocates NOTHING when returning an empty `Vec` (the common non-dragging move case).
    pub fn classify_mouse(&mut self, ev: RawMouseEvent) -> Vec<InputActivityCategory> {
        let mut out = Vec::new();
        let bf = u32::from(ev.button_flags);

        // 1. Apply button-down transitions.
        if (bf & RI_MOUSE_LEFT_BUTTON_DOWN) != 0 {
            self.held_buttons |= MOUSE_BTN_LEFT;
        }
        if (bf & RI_MOUSE_RIGHT_BUTTON_DOWN) != 0 {
            self.held_buttons |= MOUSE_BTN_RIGHT;
        }
        if (bf & RI_MOUSE_MIDDLE_BUTTON_DOWN) != 0 {
            self.held_buttons |= MOUSE_BTN_MIDDLE;
        }

        // 2. Apply button-up transitions and emit pointer releases.
        if (bf & RI_MOUSE_LEFT_BUTTON_UP) != 0 {
            self.held_buttons &= !MOUSE_BTN_LEFT;
            out.push(InputActivityCategory::PointerRelease);
        }
        if (bf & RI_MOUSE_RIGHT_BUTTON_UP) != 0 {
            self.held_buttons &= !MOUSE_BTN_RIGHT;
            out.push(InputActivityCategory::PointerRelease);
        }
        if (bf & RI_MOUSE_MIDDLE_BUTTON_UP) != 0 {
            self.held_buttons &= !MOUSE_BTN_MIDDLE;
            out.push(InputActivityCategory::PointerRelease);
        }

        // 3. Classify drag movement while any button (left|right|middle) remains held.
        let is_absolute = (ev.flags & MOUSE_MOVE_ABSOLUTE.0) != 0;
        if self.held_buttons == 0 {
            // Never retain previous absolute coordinates once all buttons are released.
            self.last_abs_pos = None;
        } else if is_absolute {
            // Some virtual/RDP drivers send button-only packets tagged MOUSE_MOVE_ABSOLUTE with
            // (0, 0) coordinates; ignore those dummy coordinates so they don't trigger a false drag.
            if ev.button_flags == 0 || ev.last_x != 0 || ev.last_y != 0 {
                let current = (ev.last_x, ev.last_y);
                if let Some(prev) = self.last_abs_pos {
                    if prev != current {
                        out.push(InputActivityCategory::DragSample);
                    }
                }
                self.last_abs_pos = Some(current);
            }
        } else {
            // Relative movement clears any stale absolute coordinate anchor.
            self.last_abs_pos = None;
            if ev.last_x != 0 || ev.last_y != 0 {
                out.push(InputActivityCategory::DragSample);
            }
        }

        // 4. Classify vertical and horizontal scroll wheel packets.
        if (bf & RI_MOUSE_WHEEL) != 0 {
            out.push(InputActivityCategory::ScrollSample);
        }
        if (bf & RI_MOUSE_HWHEEL) != 0 {
            out.push(InputActivityCategory::ScrollSample);
        }

        out
    }

    /// Classify a Raw Input keyboard packet.
    ///
    /// Emits `Some(InputActivityCategory::ShortcutPress)` ONLY on a non-autorepeat make of a
    /// non-modifier key while `(Ctrl || Win) && !altgr_active`.
    pub fn classify_keyboard(&mut self, ev: RawKeyboardEvent) -> Option<InputActivityCategory> {
        // Ignore invalid / overrun sentinel VKeys (e.g. 0x00, 0xFF fake shift/overrun).
        if ev.vkey == 0 || ev.vkey >= 0xFF {
            return None;
        }
        // Ignore Pause/Break E1 prefix sequences so fake 0x1D make codes cannot latch Ctrl.
        if (u32::from(ev.flags) & RI_KEY_E1) != 0 {
            return None;
        }

        let is_break = (u32::from(ev.flags) & RI_KEY_BREAK) != 0;
        let is_e0 = (u32::from(ev.flags) & RI_KEY_E0) != 0;
        let pressed = !is_break;
        let vk = ev.vkey;

        // Track left/right Ctrl, Alt, and Win accurately (handling generic VK_CONTROL/VK_MENU + RI_KEY_E0).
        if vk == VK_CONTROL.0 {
            if is_e0 {
                self.rctrl = pressed;
            } else {
                self.lctrl = pressed;
            }
            return None;
        }
        if vk == VK_LCONTROL.0 {
            self.lctrl = pressed;
            return None;
        }
        if vk == VK_RCONTROL.0 {
            self.rctrl = pressed;
            return None;
        }
        if vk == VK_MENU.0 {
            if is_e0 {
                self.ralt = pressed;
            } else {
                self.lalt = pressed;
            }
            return None;
        }
        if vk == VK_LMENU.0 {
            self.lalt = pressed;
            return None;
        }
        if vk == VK_RMENU.0 {
            self.ralt = pressed;
            return None;
        }
        if vk == VK_LWIN.0 {
            self.lwin = pressed;
            return None;
        }
        if vk == VK_RWIN.0 {
            self.rwin = pressed;
            return None;
        }

        // Shift and IME/synthetic sentinel keys never trigger shortcut counts.
        if vk == VK_SHIFT.0
            || vk == VK_LSHIFT.0
            || vk == VK_RSHIFT.0
            || vk == VK_PROCESSKEY.0
            || vk == VK_PACKET.0
        {
            return None;
        }

        let word = (vk >> 6) as usize;
        let bit = 1u64 << (vk & 63);
        if is_break {
            self.held_keys[word] &= !bit;
            return None;
        }

        let was_held = (self.held_keys[word] & bit) != 0;
        self.held_keys[word] |= bit;
        if was_held {
            // Suppress hardware/OS keyboard autorepeat.
            return None;
        }

        let has_ctrl_or_win = self.lctrl || self.rctrl || self.lwin || self.rwin;
        if has_ctrl_or_win && !self.is_altgr_active() {
            Some(InputActivityCategory::ShortcutPress)
        } else {
            None
        }
    }
}

/// Notifications emitted by `RawInputActivityMonitor` to the control loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawInputNotice {
    Activity {
        sample: InputActivitySample,
        resolved: ResolvedAppIdentity,
    },
    ExcludedApplication,
    DesktopBoundaryLost,
}

/// Errors that can occur while starting the Win32 Raw Input activity monitor thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawInputStartError {
    ModuleHandleFailed,
    ClassRegistrationFailed,
    WindowCreationFailed,
    RawInputRegistrationFailed,
    WtsRegistrationFailed,
    ThreadSpawnFailed,
    StartupChannelClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForegroundGateVerdict {
    Disabled,
    Excluded,
    Allowed,
}

fn evaluate_foreground_gate(
    policy: &CapturePolicy,
    resolved: &ResolvedAppIdentity,
    ephemeral_title: Option<&str>,
) -> ForegroundGateVerdict {
    if !policy.enabled || policy.input_activity != Some(true) {
        return ForegroundGateVerdict::Disabled;
    }
    if !ApplicationPolicy::allows_identity(policy, resolved)
        || !BrowserGate::allows_identity(resolved, policy, false)
    {
        return ForegroundGateVerdict::Excluded;
    }
    if BrowserGate::is_known_browser_identity(resolved) {
        let Some(title) = ephemeral_title else {
            return ForegroundGateVerdict::Excluded;
        };
        if BrowserGate::is_private_window_title(title) {
            return ForegroundGateVerdict::Excluded;
        }
    }
    ForegroundGateVerdict::Allowed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FastDesktopCheck {
    Default,
    SecureOrLocked,
    OtherOrUnavailable,
}

/// Non-blocking single-call Win32 input desktop probe (`OpenInputDesktop("Default")`).
/// Fails closed on UAC / Winlogon Secure Desktop (`ERROR_ACCESS_DENIED`), screen-saver, or error.
fn fast_input_desktop_check() -> FastDesktopCheck {
    // SAFETY: OpenInputDesktop handle closed via CloseDesktop before returning.
    unsafe {
        let hdesk = match OpenInputDesktop(
            DESKTOP_CONTROL_FLAGS(0),
            false,
            DESKTOP_READOBJECTS,
        ) {
            Ok(h) => h,
            Err(err) => {
                if err.code() == ERROR_ACCESS_DENIED.to_hresult() {
                    return FastDesktopCheck::SecureOrLocked;
                }
                return FastDesktopCheck::OtherOrUnavailable;
            }
        };
        let mut buf = [0u16; 128];
        let mut needed: u32 = 0;
        let ok = GetUserObjectInformationW(
            HANDLE(hdesk.0),
            UOI_NAME,
            Some(buf.as_mut_ptr() as *mut c_void),
            (buf.len() * 2) as u32,
            Some(&mut needed),
        )
        .is_ok();
        let _ = CloseDesktop(hdesk);
        if !ok {
            return FastDesktopCheck::OtherOrUnavailable;
        }
        let units = (needed as usize / 2).min(buf.len());
        let len = buf[..units].iter().position(|&c| c == 0).unwrap_or(units);
        let Ok(name) = String::from_utf16(&buf[..len]) else {
            return FastDesktopCheck::OtherOrUnavailable;
        };
        if name.eq_ignore_ascii_case("default") {
            FastDesktopCheck::Default
        } else if name.eq_ignore_ascii_case("winlogon")
            || name.eq_ignore_ascii_case("screen-saver")
        {
            FastDesktopCheck::SecureOrLocked
        } else {
            FastDesktopCheck::OtherOrUnavailable
        }
    }
}

/// Inactive-window mouse privacy gate: reads ephemeral `GetCursorPos` on the stack and verifies
/// `GetAncestor(WindowFromPoint(pt), GA_ROOT) == fg` without retaining or emitting coordinates.
fn cursor_point_belongs_to_foreground(fg: HWND) -> bool {
    if fg.0.is_null() {
        return false;
    }
    let mut pt = POINT::default();
    // SAFETY: Stack-local POINT populated by Win32 GetCursorPos and never stored or emitted.
    if unsafe { GetCursorPos(&mut pt).is_err() } {
        return false;
    }
    // SAFETY: Kernel window hit-test; does not send cross-process messages.
    let hit = unsafe { WindowFromPoint(pt) };
    if hit.0.is_null() {
        return false;
    }
    // SAFETY: Walks kernel window parent chain to top-level root HWND.
    let root = unsafe { GetAncestor(hit, GA_ROOT) };
    root == fg
}

/// Bounded notice queue preserving priority security signals (`DesktopBoundaryLost` and
/// `ExcludedApplication`) while capping RAM under bursty input.
#[derive(Debug, Default)]
struct BoundedNoticeQueue {
    items: VecDeque<RawInputNotice>,
    capacity: usize,
}

impl BoundedNoticeQueue {
    fn new(capacity: usize) -> Self {
        Self {
            items: VecDeque::with_capacity(capacity.min(64)),
            capacity: capacity.max(1),
        }
    }

    fn push_activity(&mut self, sample: InputActivitySample, resolved: ResolvedAppIdentity) {
        if self.items.len() >= self.capacity {
            return;
        }
        self.items
            .push_back(RawInputNotice::Activity { sample, resolved });
    }

    fn push_excluded(&mut self) {
        if matches!(
            self.items.back(),
            Some(RawInputNotice::ExcludedApplication | RawInputNotice::DesktopBoundaryLost)
        ) {
            return;
        }
        while self.items.len() >= self.capacity {
            if let Some(pos) = self
                .items
                .iter()
                .position(|n| matches!(n, RawInputNotice::Activity { .. }))
            {
                self.items.remove(pos);
            } else {
                self.items.pop_front();
            }
        }
        self.items.push_back(RawInputNotice::ExcludedApplication);
    }

    fn push_desktop_boundary_lost(&mut self) {
        // Purge all queued activity notices on lock/disconnect so stale events cannot drain.
        self.items.clear();
        self.items.push_back(RawInputNotice::DesktopBoundaryLost);
    }

    fn clear_activity_only(&mut self) {
        self.items
            .retain(|n| !matches!(n, RawInputNotice::Activity { .. }));
    }

    fn drain(&mut self) -> Vec<RawInputNotice> {
        self.items.drain(..).collect()
    }
}

struct SharedMonitorState {
    healthy: AtomicBool,
    stopping: AtomicBool,
    desktop_latched: AtomicBool,
    accept_after_qpc_ns: AtomicU64,
    boundary_generation: AtomicU64,
    policy_generation: AtomicU64,
    policy: Mutex<Option<CapturePolicy>>,
    notices: Mutex<BoundedNoticeQueue>,
    exit_signal: (Mutex<bool>, Condvar),
}

impl SharedMonitorState {
    fn new(initial_accept_after_qpc_ns: u64) -> Self {
        Self {
            healthy: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            desktop_latched: AtomicBool::new(false),
            accept_after_qpc_ns: AtomicU64::new(initial_accept_after_qpc_ns),
            boundary_generation: AtomicU64::new(1),
            policy_generation: AtomicU64::new(1),
            policy: Mutex::new(None),
            notices: Mutex::new(BoundedNoticeQueue::new(MAX_QUEUED_NOTICES)),
            exit_signal: (Mutex::new(false), Condvar::new()),
        }
    }

    fn latch_desktop_boundary_lost(&self) {
        self.desktop_latched.store(true, Ordering::Release);
        self.accept_after_qpc_ns
            .fetch_max(monotonic_qpc_ns_now(), Ordering::AcqRel);
        self.boundary_generation.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut q) = self.notices.lock() {
            q.push_desktop_boundary_lost();
        }
    }

    fn push_excluded(&self) {
        if let Ok(mut q) = self.notices.lock() {
            q.push_excluded();
        }
    }

    fn push_activity(&self, sample: InputActivitySample, resolved: ResolvedAppIdentity) {
        if let Ok(mut q) = self.notices.lock() {
            q.push_activity(sample, resolved);
        }
    }

    fn snapshot_policy(&self) -> Option<CapturePolicy> {
        self.policy.lock().ok().and_then(|guard| guard.clone())
    }

    fn signal_exited(&self) {
        self.healthy.store(false, Ordering::Release);
        let (lock, cv) = &self.exit_signal;
        if let Ok(mut exited) = lock.lock() {
            *exited = true;
            cv.notify_all();
        }
    }
}

struct ThreadExitGuard {
    shared: Arc<SharedMonitorState>,
}

impl Drop for ThreadExitGuard {
    fn drop(&mut self) {
        self.shared.signal_exited();
    }
}

struct ThreadWindowState {
    shared: Arc<SharedMonitorState>,
    expected_session_id: Option<u32>,
    classifier: RawInputClassifier,
    seen_boundary_gen: u64,
    seen_policy_gen: u64,
    last_fg_hwnd: Option<isize>,
    last_excluded_fg_hwnd: Option<isize>,
    current_msg_time_ms: Option<u32>,
    wts_registered: bool,
    window_destroyed: bool,
}

impl ThreadWindowState {
    fn sync_boundary(&mut self) -> u64 {
        let current_gen = self.shared.boundary_generation.load(Ordering::Acquire);
        if current_gen != self.seen_boundary_gen {
            self.classifier.clear();
            self.last_fg_hwnd = None;
            self.seen_boundary_gen = current_gen;
        }
        let current_policy_gen = self.shared.policy_generation.load(Ordering::Acquire);
        if current_policy_gen != self.seen_policy_gen {
            self.last_excluded_fg_hwnd = None;
            self.seen_policy_gen = current_policy_gen;
        }
        current_gen
    }

    fn record_excluded_foreground(&mut self, fg_raw: isize) -> bool {
        self.classifier.clear();
        self.last_fg_hwnd = None;
        if self.last_excluded_fg_hwnd == Some(fg_raw) {
            return false;
        }
        self.last_excluded_fg_hwnd = Some(fg_raw);
        self.shared.push_excluded();
        true
    }

    fn handle_wts_session_change(&mut self, event_code: u32, session_id: u32) {
        if !matches!(
            event_code,
            WTS_SESSION_LOCK
                | WTS_CONSOLE_DISCONNECT
                | WTS_REMOTE_DISCONNECT
                | WTS_SESSION_LOGOFF
        ) {
            return;
        }
        // Fail closed if expected_session_id was unavailable or matches this session.
        if self
            .expected_session_id
            .is_some_and(|expected| expected != session_id)
        {
            return;
        }
        self.classifier.clear();
        self.last_fg_hwnd = None;
        self.last_excluded_fg_hwnd = None;
        self.shared.latch_desktop_boundary_lost();
        self.seen_boundary_gen = self.shared.boundary_generation.load(Ordering::Acquire);
    }

    fn handle_raw_input(&mut self, lparam: LPARAM) {
        let start_gen = self.sync_boundary();
        if self.shared.stopping.load(Ordering::Acquire)
            || self.shared.desktop_latched.load(Ordering::Acquire)
        {
            self.classifier.clear();
            self.last_fg_hwnd = None;
            self.last_excluded_fg_hwnd = None;
            return;
        }

        let Some(policy) = self.shared.snapshot_policy() else {
            self.classifier.clear();
            self.last_fg_hwnd = None;
            self.last_excluded_fg_hwnd = None;
            return;
        };
        if !policy.enabled || policy.input_activity != Some(true) {
            self.classifier.clear();
            self.last_fg_hwnd = None;
            self.last_excluded_fg_hwnd = None;
            return;
        }

        // Capture arrival timestamps and reject queued/stale messages before reading raw input.
        let now_qpc_ns = monotonic_qpc_ns_now();
        let queue_delay_ms = match self.current_msg_time_ms {
            Some(msg_time_ms) => {
                // SAFETY: Standard Win32 32-bit tick count matching MSG.time.
                let now_tick_ms = unsafe { GetTickCount() };
                message_queue_delay_ms(now_tick_ms, msg_time_ms)
            }
            None => 0,
        };
        if queue_delay_ms > MAX_MESSAGE_QUEUE_DELAY_MS {
            return;
        }
        let event_qpc_ns = now_qpc_ns.saturating_sub(u64::from(queue_delay_ms) * 1_000_000);
        let accept_after = self.shared.accept_after_qpc_ns.load(Ordering::Acquire);
        if !accepts_qpc_timestamp(event_qpc_ns, now_qpc_ns, accept_after) {
            return;
        }
        let callback_time_ms = SystemCollectorClock::unix_ms_now();

        // Fast WTS session + OpenInputDesktop("Default") gate (fails closed on UAC / Secure Desktop).
        let live_sid = current_wts_session_id();
        if live_sid.is_none() || live_sid != self.expected_session_id {
            self.classifier.clear();
            self.last_fg_hwnd = None;
            self.last_excluded_fg_hwnd = None;
            self.shared.latch_desktop_boundary_lost();
            self.seen_boundary_gen = self.shared.boundary_generation.load(Ordering::Acquire);
            return;
        }
        match fast_input_desktop_check() {
            FastDesktopCheck::Default => {}
            FastDesktopCheck::SecureOrLocked => {
                self.classifier.clear();
                self.last_fg_hwnd = None;
                self.last_excluded_fg_hwnd = None;
                self.shared.latch_desktop_boundary_lost();
                self.seen_boundary_gen = self.shared.boundary_generation.load(Ordering::Acquire);
                return;
            }
            FastDesktopCheck::OtherOrUnavailable => {
                self.classifier.clear();
                self.last_fg_hwnd = None;
                self.last_excluded_fg_hwnd = None;
                return;
            }
        }

        // Resolve foreground window & run dual-ID privacy gates BEFORE calling GetRawInputData.
        // SAFETY: Standard Win32 foreground window lookup.
        let fg = unsafe { GetForegroundWindow() };
        if fg.0.is_null() {
            self.classifier.clear();
            self.last_fg_hwnd = None;
            self.last_excluded_fg_hwnd = None;
            return;
        }
        let fg_raw = fg.0 as isize;
        if self.last_fg_hwnd != Some(fg_raw) {
            // Clear held buttons/keys/RDP coords across any foreground HWND change.
            self.classifier.clear();
            self.last_fg_hwnd = Some(fg_raw);
        }

        let Some((_, app, resolved)) = resolve_application_identity_for_hwnd(fg, None, None) else {
            // Fail closed on unresolved HWND or unresolved ApplicationFrameHost.exe.
            self.classifier.clear();
            self.last_fg_hwnd = None;
            self.last_excluded_fg_hwnd = None;
            return;
        };

        let ephemeral_title = if BrowserGate::is_known_browser_identity(&resolved) {
            read_window_title_ephemeral(fg)
        } else {
            None
        };
        match evaluate_foreground_gate(&policy, &resolved, ephemeral_title.as_deref()) {
            ForegroundGateVerdict::Allowed => {
                self.last_excluded_fg_hwnd = None;
            }
            ForegroundGateVerdict::Excluded => {
                let _ = self.record_excluded_foreground(fg_raw);
                return;
            }
            ForegroundGateVerdict::Disabled => {
                self.classifier.clear();
                self.last_fg_hwnd = None;
                self.last_excluded_fg_hwnd = None;
                return;
            }
        }

        // Read raw HID input into a stack-allocated buffer (never retained past this function).
        let mut raw = RAWINPUT::default();
        let mut size = std::mem::size_of::<RAWINPUT>() as u32;
        let header_size = std::mem::size_of::<RAWINPUTHEADER>() as u32;
        // SAFETY: Stack-allocated RAWINPUT buffer with matching size and header size.
        let copied = unsafe {
            GetRawInputData(
                HRAWINPUT(lparam.0 as *mut c_void),
                RID_INPUT,
                Some(&mut raw as *mut RAWINPUT as *mut c_void),
                &mut size,
                header_size,
            )
        };
        if copied == u32::MAX || copied < header_size {
            return;
        }

        let min_mouse_size = std::mem::size_of::<RAWINPUTHEADER>() + std::mem::size_of::<RAWMOUSE>();
        let min_kbd_size =
            std::mem::size_of::<RAWINPUTHEADER>() + std::mem::size_of::<RAWKEYBOARD>();
        let (categories, is_mouse) = if raw.header.dwType == RIM_TYPEMOUSE.0
            && (copied as usize) >= min_mouse_size
        {
            // SAFETY: dwType == RIM_TYPEMOUSE and copied >= header + RAWMOUSE selects data.mouse.
            let mouse = unsafe { raw.data.mouse };
            // SAFETY: Reading the standard usButtonFlags struct variant of RAWMOUSE's union.
            let button_flags = unsafe { mouse.Anonymous.Anonymous.usButtonFlags };
            let ev = RawMouseEvent {
                flags: mouse.usFlags.0,
                button_flags,
                last_x: mouse.lLastX,
                last_y: mouse.lLastY,
            };
            (self.classifier.classify_mouse(ev), true)
        } else if raw.header.dwType == RIM_TYPEKEYBOARD.0 && (copied as usize) >= min_kbd_size {
            // SAFETY: dwType == RIM_TYPEKEYBOARD and copied >= header + RAWKEYBOARD selects data.keyboard.
            let kbd = unsafe { raw.data.keyboard };
            let ev = RawKeyboardEvent {
                make_code: kbd.MakeCode,
                flags: kbd.Flags,
                vkey: kbd.VKey,
            };
            match self.classifier.classify_keyboard(ev) {
                Some(cat) => (vec![cat], false),
                None => (Vec::new(), false),
            }
        } else {
            return;
        };

        if categories.is_empty() {
            return;
        }

        // Inactive-window mouse privacy gate: mouse activity over an adjacent window (e.g.
        // 1Password) must NEVER be misattributed to the foreground window.
        if is_mouse && !cursor_point_belongs_to_foreground(fg) {
            return;
        }

        // Post-gate recheck: confirm foreground window, desktop, boundary epoch, and <=200ms age.
        // SAFETY: Standard Win32 foreground window lookup.
        let post_fg = unsafe { GetForegroundWindow() };
        if post_fg != fg
            || self.shared.stopping.load(Ordering::Acquire)
            || self.shared.desktop_latched.load(Ordering::Acquire)
            || self.shared.boundary_generation.load(Ordering::Acquire) != start_gen
        {
            return;
        }
        if fast_input_desktop_check() != FastDesktopCheck::Default {
            self.classifier.clear();
            self.last_fg_hwnd = None;
            self.shared.latch_desktop_boundary_lost();
            self.seen_boundary_gen = self.shared.boundary_generation.load(Ordering::Acquire);
            return;
        }
        let post_qpc_ns = monotonic_qpc_ns_now();
        let latest_accept_after = self.shared.accept_after_qpc_ns.load(Ordering::Acquire);
        if !accepts_qpc_timestamp(event_qpc_ns, post_qpc_ns, latest_accept_after) {
            return;
        }

        for category in categories {
            self.shared.push_activity(
                InputActivitySample {
                    application: app.clone(),
                    exe_name: resolved.exe_name.clone(),
                    category,
                    callback_time_ms,
                },
                resolved.clone(),
            );
        }
    }
}

unsafe extern "system" fn raw_input_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_NCCREATE => {
            let create = lparam.0 as *const CREATESTRUCTW;
            if !create.is_null() {
                let state_ptr = (*create).lpCreateParams as isize;
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr);
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_INPUT => {
            let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut ThreadWindowState;
            if !ptr.is_null() {
                (*ptr).handle_raw_input(lparam);
            }
            // MSDN requires calling DefWindowProcW on WM_INPUT so the system can perform cleanup.
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_WTSSESSION_CHANGE => {
            let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut ThreadWindowState;
            if !ptr.is_null() {
                (*ptr).handle_wts_session_change(wparam.0 as u32, lparam.0 as u32);
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut ThreadWindowState;
            if !ptr.is_null() {
                // Access fields strictly via raw pointers so no `&mut` alias is held across Win32
                // calls or `SetWindowLongPtrW`.
                let wts_reg = core::ptr::addr_of!((*ptr).wts_registered).read();
                if wts_reg {
                    let _ = WTSUnRegisterSessionNotification(hwnd);
                    core::ptr::addr_of_mut!((*ptr).wts_registered).write(false);
                }
                core::ptr::addr_of_mut!((*ptr).window_destroyed).write(true);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn register_raw_input_devices(hwnd: HWND) -> Result<(), RawInputStartError> {
    let devices = [
        RAWINPUTDEVICE {
            usUsagePage: HID_USAGE_PAGE_GENERIC,
            usUsage: HID_USAGE_GENERIC_MOUSE,
            dwFlags: RIDEV_INPUTSINK,
            hwndTarget: hwnd,
        },
        RAWINPUTDEVICE {
            usUsagePage: HID_USAGE_PAGE_GENERIC,
            usUsage: HID_USAGE_GENERIC_KEYBOARD,
            dwFlags: RIDEV_INPUTSINK,
            hwndTarget: hwnd,
        },
    ];
    // SAFETY: Valid RAWINPUTDEVICE array and exact element struct size.
    unsafe {
        RegisterRawInputDevices(&devices, std::mem::size_of::<RAWINPUTDEVICE>() as u32)
            .map_err(|_| RawInputStartError::RawInputRegistrationFailed)
    }
}

fn unregister_raw_input_devices() {
    // MSDN: RIDEV_REMOVE requires hwndTarget to be NULL.
    let devices = [
        RAWINPUTDEVICE {
            usUsagePage: HID_USAGE_PAGE_GENERIC,
            usUsage: HID_USAGE_GENERIC_MOUSE,
            dwFlags: RIDEV_REMOVE,
            hwndTarget: HWND::default(),
        },
        RAWINPUTDEVICE {
            usUsagePage: HID_USAGE_PAGE_GENERIC,
            usUsage: HID_USAGE_GENERIC_KEYBOARD,
            dwFlags: RIDEV_REMOVE,
            hwndTarget: HWND::default(),
        },
    ];
    // SAFETY: Valid RAWINPUTDEVICE array with RIDEV_REMOVE and NULL hwndTarget.
    unsafe {
        let _ = RegisterRawInputDevices(&devices, std::mem::size_of::<RAWINPUTDEVICE>() as u32);
    }
}

/// ABI-identical `WNDCLASSEXW` layout avoiding `Win32_Graphics_Gdi` (only `hbr_background`
/// uses an `HBRUSH` pointer, which is always NULL for a message-only `HWND_MESSAGE` window).
#[repr(C)]
struct RawInputWndClassExW {
    cb_size: u32,
    style: WNDCLASS_STYLES,
    lpfn_wnd_proc: WNDPROC,
    cb_cls_extra: i32,
    cb_wnd_extra: i32,
    h_instance: HINSTANCE,
    h_icon: HICON,
    h_cursor: HCURSOR,
    hbr_background: *mut c_void,
    lpsz_menu_name: PCWSTR,
    lpsz_class_name: PCWSTR,
    h_icon_sm: HICON,
}

#[link(name = "user32")]
extern "system" {
    fn RegisterClassExW(lpwcx: *const RawInputWndClassExW) -> u16;
}

struct MonitorStartup {
    thread_id: u32,
    hwnd_raw: isize,
}

struct RawWindowResources {
    state_ptr: *mut ThreadWindowState,
    hinstance: HINSTANCE,
    class_name: Vec<u16>,
    class_registered: bool,
    hwnd: Option<HWND>,
    raw_input_registered: bool,
}

impl Drop for RawWindowResources {
    fn drop(&mut self) {
        if self.raw_input_registered {
            unregister_raw_input_devices();
            self.raw_input_registered = false;
        }
        if let Some(hwnd) = self.hwnd.take() {
            // SAFETY: Owning message-loop thread; read/write fields via raw pointers without
            // holding any unique `&mut` or `Box` alias while `DestroyWindow` re-enters
            // `raw_input_wnd_proc`.
            unsafe {
                let destroyed = core::ptr::addr_of!((*self.state_ptr).window_destroyed).read();
                if !destroyed {
                    let wts_reg = core::ptr::addr_of!((*self.state_ptr).wts_registered).read();
                    if wts_reg {
                        let _ = WTSUnRegisterSessionNotification(hwnd);
                        core::ptr::addr_of_mut!((*self.state_ptr).wts_registered).write(false);
                    }
                    let _ = DestroyWindow(hwnd);
                }
            }
        }
        if self.class_registered {
            // SAFETY: Class was registered on this thread and its HWND is now destroyed.
            unsafe {
                let _ = UnregisterClassW(PCWSTR(self.class_name.as_ptr()), Some(self.hinstance));
            }
            self.class_registered = false;
        }
        if !self.state_ptr.is_null() {
            // SAFETY: Window is destroyed and `GWLP_USERDATA` has been cleared; no Win32 callback
            // can dereference `state_ptr` again, so reclaiming the heap allocation is unique.
            unsafe {
                drop(Box::from_raw(self.state_ptr));
            }
            self.state_ptr = core::ptr::null_mut();
        }
    }
}

fn run_raw_input_thread(
    shared: Arc<SharedMonitorState>,
    startup_tx: mpsc::SyncSender<Result<MonitorStartup, RawInputStartError>>,
) {
    let _exit_guard = ThreadExitGuard {
        shared: Arc::clone(&shared),
    };

    // SAFETY: Passing None returns the executable module HMODULE.
    let Ok(hmodule) = (unsafe { GetModuleHandleW(None) }) else {
        let _ = startup_tx.send(Err(RawInputStartError::ModuleHandleFailed));
        return;
    };
    let hinstance = HINSTANCE(hmodule.0);

    let seq = NEXT_CLASS_SEQ.fetch_add(1, Ordering::Relaxed);
    let class_name: Vec<u16> = format!("ComputerAccessRawInput_{}_{}\0", std::process::id(), seq)
        .encode_utf16()
        .collect();

    let wnd_class = RawInputWndClassExW {
        cb_size: std::mem::size_of::<RawInputWndClassExW>() as u32,
        style: WNDCLASS_STYLES(0),
        lpfn_wnd_proc: Some(raw_input_wnd_proc),
        cb_cls_extra: 0,
        cb_wnd_extra: 0,
        h_instance: hinstance,
        h_icon: HICON::default(),
        h_cursor: HCURSOR::default(),
        hbr_background: core::ptr::null_mut(),
        lpsz_menu_name: PCWSTR::null(),
        lpsz_class_name: PCWSTR(class_name.as_ptr()),
        h_icon_sm: HICON::default(),
    };

    // SAFETY: Unique per-instance class name, exact Win32 WNDCLASSEXW layout, unregistered before
    // thread exit by `RawWindowResources::drop`.
    let atom = unsafe { RegisterClassExW(&wnd_class) };
    if atom == 0 {
        let _ = startup_tx.send(Err(RawInputStartError::ClassRegistrationFailed));
        return;
    }

    let state_ptr = Box::into_raw(Box::new(ThreadWindowState {
        shared: Arc::clone(&shared),
        expected_session_id: current_wts_session_id(),
        classifier: RawInputClassifier::new(),
        seen_boundary_gen: shared.boundary_generation.load(Ordering::Acquire),
        seen_policy_gen: shared.policy_generation.load(Ordering::Acquire),
        last_fg_hwnd: None,
        last_excluded_fg_hwnd: None,
        current_msg_time_ms: None,
        wts_registered: false,
        window_destroyed: false,
    }));

    let mut resources = RawWindowResources {
        state_ptr,
        hinstance,
        class_name,
        class_registered: true,
        hwnd: None,
        raw_input_registered: false,
    };

    // SAFETY: Message-only window owned exclusively by this thread; `state_ptr` stays raw until
    // `RawWindowResources::drop` reclaims it strictly after `DestroyWindow` & `UnregisterClassW`.
    let hwnd = match unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(resources.class_name.as_ptr()),
            PCWSTR::null(),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(hinstance),
            Some(resources.state_ptr as *const c_void),
        )
    } {
        Ok(h) if !h.0.is_null() => h,
        _ => {
            let _ = startup_tx.send(Err(RawInputStartError::WindowCreationFailed));
            return;
        }
    };
    resources.hwnd = Some(hwnd);

    if let Err(err) = register_raw_input_devices(hwnd) {
        let _ = startup_tx.send(Err(err));
        return;
    }
    resources.raw_input_registered = true;

    // SAFETY: Valid HWND_MESSAGE handle owned by this thread; unregistered on WM_DESTROY / cleanup.
    if unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION).is_err() } {
        let _ = startup_tx.send(Err(RawInputStartError::WtsRegistrationFailed));
        return;
    }
    // SAFETY: Owning thread; write via raw pointer with no active `&mut` alias.
    unsafe {
        core::ptr::addr_of_mut!((*resources.state_ptr).wts_registered).write(true);
    }

    // SAFETY: Standard Win32 current thread ID lookup.
    let thread_id = unsafe { GetCurrentThreadId() };
    shared.healthy.store(true, Ordering::Release);
    if startup_tx
        .send(Ok(MonitorStartup {
            thread_id,
            hwnd_raw: hwnd.0 as isize,
        }))
        .is_err()
    {
        shared.healthy.store(false, Ordering::Release);
        return;
    }

    let mut msg = MSG::default();
    loop {
        // SAFETY: Standard Win32 thread message loop for this thread's HWND_MESSAGE window.
        let status = unsafe { GetMessageW(&mut msg, None, 0, 0) };
        if status.0 <= 0 {
            break;
        }
        // SAFETY: Owning thread; write via raw pointer before DispatchMessageW re-enters WndProc.
        unsafe {
            core::ptr::addr_of_mut!((*resources.state_ptr).current_msg_time_ms)
                .write(Some(msg.time));
        }
        // SAFETY: Dispatches message retrieved by GetMessageW on this thread.
        unsafe {
            let _ = DispatchMessageW(&msg);
        }
        // SAFETY: Owning thread; `state_ptr` remains allocated until `resources` drops.
        unsafe {
            core::ptr::addr_of_mut!((*resources.state_ptr).current_msg_time_ms).write(None);
        }
    }

    shared.healthy.store(false, Ordering::Release);
    drop(resources);
}

/// Control-process Win32 Raw Input activity monitor with `<1ms` WTS session-change latching.
pub struct RawInputActivityMonitor {
    shared: Arc<SharedMonitorState>,
    thread_id: u32,
    hwnd_raw: isize,
    handle: Option<JoinHandle<()>>,
}

impl RawInputActivityMonitor {
    /// Spawn the lightweight `raw-input` thread, register Raw Input (`RIDEV_INPUTSINK`) and WTS
    /// session notifications, and wait until the message window is live.
    ///
    /// Starts with policy unset (fail-closed) until `set_policy` is called.
    pub fn start() -> Result<Self, RawInputStartError> {
        let shared = Arc::new(SharedMonitorState::new(monotonic_qpc_ns_now()));
        let (tx, rx) = mpsc::sync_channel(1);
        let thread_shared = Arc::clone(&shared);
        let handle = thread::Builder::new()
            .name("raw-input".to_string())
            .spawn(move || run_raw_input_thread(thread_shared, tx))
            .map_err(|_| RawInputStartError::ThreadSpawnFailed)?;

        match rx.recv() {
            Ok(Ok(startup)) => Ok(Self {
                shared,
                thread_id: startup.thread_id,
                hwnd_raw: startup.hwnd_raw,
                handle: Some(handle),
            }),
            Ok(Err(err)) => {
                let _ = handle.join();
                Err(err)
            }
            Err(_) => {
                let _ = handle.join();
                Err(RawInputStartError::StartupChannelClosed)
            }
        }
    }

    /// Update the active capture policy, clear ephemeral input state, and advance the QPC fence.
    pub fn set_policy(&self, policy: Option<CapturePolicy>, accept_after_qpc_ns: u64) {
        if let Ok(mut guard) = self.shared.policy.lock() {
            *guard = policy;
        }
        self.shared
            .policy_generation
            .fetch_add(1, Ordering::AcqRel);
        self.reset_boundary(accept_after_qpc_ns);
    }

    /// Advance the monotonic QPC fence, clear ephemeral held buttons/keys/RDP coords on the
    /// raw-input thread, and discard any queued pre-boundary activity notices.
    ///
    /// Does NOT clear a sticky `desktop_latched` lock/disconnect state.
    pub fn reset_boundary(&self, accept_after_qpc_ns: u64) -> u64 {
        let target = if accept_after_qpc_ns == 0 {
            monotonic_qpc_ns_now()
        } else {
            accept_after_qpc_ns
        };
        let prev = self
            .shared
            .accept_after_qpc_ns
            .fetch_max(target, Ordering::AcqRel);
        self.shared
            .boundary_generation
            .fetch_add(1, Ordering::AcqRel);
        if let Ok(mut q) = self.shared.notices.lock() {
            q.clear_activity_only();
        }
        prev.max(target)
    }

    /// Clear the sticky WTS desktop lock/disconnect latch ONLY on explicit user `start`/`resume`,
    /// advancing the QPC fence and clearing ephemeral input state.
    pub fn reset_desktop_latch_for_user_action(&self, accept_after_qpc_ns: u64) -> u64 {
        self.shared.desktop_latched.store(false, Ordering::Release);
        self.shared
            .policy_generation
            .fetch_add(1, Ordering::AcqRel);
        self.reset_boundary(accept_after_qpc_ns)
    }

    /// Current monotonic QPC fence timestamp in nanoseconds.
    pub fn accept_after_qpc_ns(&self) -> u64 {
        self.shared.accept_after_qpc_ns.load(Ordering::Acquire)
    }

    /// Returns `true` if `WM_WTSSESSION_CHANGE` or Secure Desktop detection latched a boundary loss.
    pub fn is_desktop_latched(&self) -> bool {
        self.shared.desktop_latched.load(Ordering::Acquire)
    }

    /// Returns `true` while the raw-input message pump is active and healthy.
    pub fn is_healthy(&self) -> bool {
        self.shared.healthy.load(Ordering::Acquire) && !self.shared.stopping.load(Ordering::Acquire)
    }

    /// Drain all queued `RawInputNotice` items in FIFO order.
    pub fn drain_events(&self) -> Vec<RawInputNotice> {
        self.shared
            .notices
            .lock()
            .map(|mut q| q.drain())
            .unwrap_or_default()
    }

    /// Stop the raw-input thread cleanly (posts `WM_CLOSE`, falls back to `WM_QUIT`, unregisters
    /// WTS & Raw Input, destroys window, and joins with a bounded wait).
    pub fn stop(&mut self) {
        self.shared.stopping.store(true, Ordering::Release);
        self.shared.healthy.store(false, Ordering::Release);

        let Some(handle) = self.handle.take() else {
            return;
        };

        let hwnd = HWND(self.hwnd_raw as *mut c_void);
        if !hwnd.0.is_null() {
            // SAFETY: Posting WM_CLOSE to our own HWND_MESSAGE window initiates clean teardown.
            let posted = unsafe { PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)).is_ok() };
            if !posted && self.thread_id != 0 {
                // SAFETY: Fallback WM_QUIT directly to the raw-input message thread.
                unsafe {
                    let _ = PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
                }
            }
        } else if self.thread_id != 0 {
            // SAFETY: Posting WM_QUIT terminates GetMessageW loop immediately.
            unsafe {
                let _ = PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
            }
        }

        let mut exited = self.wait_for_exit(Duration::from_millis(STOP_CLOSE_WAIT_MS));
        if !exited && self.thread_id != 0 {
            // SAFETY: Escalate with WM_QUIT if WM_CLOSE has not exited within the initial bound.
            unsafe {
                let _ = PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
            }
            exited = self.wait_for_exit(Duration::from_millis(STOP_QUIT_WAIT_MS));
        }

        if exited {
            let _ = handle.join();
        }
        self.hwnd_raw = 0;
        self.thread_id = 0;
    }

    fn wait_for_exit(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let (lock, cv) = &self.shared.exit_signal;
        let Ok(mut guard) = lock.lock() else {
            return false;
        };
        while !*guard {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match cv.wait_timeout(guard, remaining) {
                Ok((g, _)) => guard = g,
                Err(_) => return false,
            }
        }
        true
    }

    /// Raw `HWND_MESSAGE` handle value (`0` after `stop()`), enabling live Win32 `WM_WTSSESSION_CHANGE`
    /// integration tests against the running message pump.
    pub fn message_window_raw_hwnd(&self) -> isize {
        self.hwnd_raw
    }

    #[cfg(test)]
    fn hwnd_for_test(&self) -> HWND {
        HWND(self.hwnd_raw as *mut c_void)
    }
}

impl Drop for RawInputActivityMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

fn validate_input_activity_inner(
    expected_app: Option<&ApplicationIdentity>,
    expected_resolved: &ResolvedAppIdentity,
    policy: &CapturePolicy,
    monitor_healthy: bool,
) -> bool {
    if !monitor_healthy || !policy.enabled || policy.input_activity != Some(true) {
        return false;
    }
    if !ApplicationPolicy::allows_identity(policy, expected_resolved)
        || !BrowserGate::allows_identity(expected_resolved, policy, false)
    {
        return false;
    }

    let assessment = assess_windows_desktop();
    let mut latch = DesktopBoundaryLatch::new();
    if latch.observe(&assessment) != DesktopStatus::Unlocked {
        return false;
    }

    // SAFETY: Standard Win32 foreground window lookup.
    let fg = unsafe { GetForegroundWindow() };
    if fg.0.is_null() {
        return false;
    }
    let Some((_, app, resolved)) = resolve_application_identity_for_hwnd(fg, None, None) else {
        return false;
    };
    if resolved != *expected_resolved {
        return false;
    }
    if let Some(expected_app) = expected_app {
        if &app != expected_app {
            return false;
        }
    }

    let ephemeral_title = if BrowserGate::is_known_browser_identity(&resolved) {
        read_window_title_ephemeral(fg)
    } else {
        None
    };
    if evaluate_foreground_gate(policy, &resolved, ephemeral_title.as_deref())
        != ForegroundGateVerdict::Allowed
    {
        return false;
    }

    // Post-check foreground window stability after reading ephemeral title.
    // SAFETY: Standard Win32 foreground window lookup.
    unsafe { GetForegroundWindow() == fg }
}

/// Full flush-time validation helper for `WindowsEnvironment::validate_input_activity()`.
///
/// Re-runs full dual-sampled `assess_windows_desktop()` via `DesktopBoundaryLatch`, resolves the
/// fresh foreground window via `resolve_application_identity_for_hwnd`, verifies exact dual-ID
/// match plus `ApplicationPolicy`/`BrowserGate`, and checks non-private browser window titles.
pub fn validate_input_activity_context(
    expected: &ResolvedAppIdentity,
    policy: &CapturePolicy,
    monitor_healthy: bool,
) -> bool {
    validate_input_activity_inner(None, expected, policy, monitor_healthy)
}

/// Strict flush-time validation helper verifying both `ApplicationIdentity` (including exact
/// `process_id` and `process_start_time`) and dual-ID `ResolvedAppIdentity`.
pub fn validate_input_activity_application(
    expected_app: &ApplicationIdentity,
    expected_resolved: &ResolvedAppIdentity,
    policy: &CapturePolicy,
    monitor_healthy: bool,
) -> bool {
    validate_input_activity_inner(Some(expected_app), expected_resolved, policy, monitor_healthy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use windows::Win32::UI::WindowsAndMessaging::{IsWindow, SendMessageW};

    // Serialize live Win32 monitor tests because RegisterRawInputDevices is process-wide.
    static LIVE_MONITOR_LOCK: StdMutex<()> = StdMutex::new(());

    fn mouse_ev(flags: u16, button_flags: u16, last_x: i32, last_y: i32) -> RawMouseEvent {
        RawMouseEvent {
            flags,
            button_flags,
            last_x,
            last_y,
        }
    }

    fn key_ev(vkey: u16, flags: u16) -> RawKeyboardEvent {
        RawKeyboardEvent {
            make_code: 0,
            flags,
            vkey,
        }
    }

    #[test]
    fn classifier_pointer_releases_and_relative_drag_samples() {
        let mut c = RawInputClassifier::new();

        // Plain relative movement with no button held emits nothing.
        assert!(c.classify_mouse(mouse_ev(0, 0, 12, -4)).is_empty());
        assert_eq!(c.held_buttons_mask(), 0);

        // Press left button, then move -> DragSample.
        assert!(c
            .classify_mouse(mouse_ev(0, RI_MOUSE_LEFT_BUTTON_DOWN as u16, 0, 0))
            .is_empty());
        assert_eq!(c.held_buttons_mask(), MOUSE_BTN_LEFT);

        // Zero movement while held emits nothing.
        assert!(c.classify_mouse(mouse_ev(0, 0, 0, 0)).is_empty());

        // Non-zero relative movement while held emits DragSample.
        assert_eq!(
            c.classify_mouse(mouse_ev(0, 0, 5, 0)),
            vec![InputActivityCategory::DragSample]
        );
        assert_eq!(
            c.classify_mouse(mouse_ev(0, 0, 0, -3)),
            vec![InputActivityCategory::DragSample]
        );

        // Right & middle button press/release also count as PointerRelease and keep drag active.
        assert!(c
            .classify_mouse(mouse_ev(0, RI_MOUSE_RIGHT_BUTTON_DOWN as u16, 0, 0))
            .is_empty());
        assert_eq!(
            c.classify_mouse(mouse_ev(0, RI_MOUSE_LEFT_BUTTON_UP as u16, 0, 0)),
            vec![InputActivityCategory::PointerRelease]
        );
        // Right button is still held -> movement still drags!
        assert_eq!(
            c.classify_mouse(mouse_ev(0, 0, 2, 1)),
            vec![InputActivityCategory::DragSample]
        );
        assert_eq!(
            c.classify_mouse(mouse_ev(0, RI_MOUSE_RIGHT_BUTTON_UP as u16, 0, 0)),
            vec![InputActivityCategory::PointerRelease]
        );
        assert_eq!(c.held_buttons_mask(), 0);

        // Middle button release.
        assert!(c
            .classify_mouse(mouse_ev(0, RI_MOUSE_MIDDLE_BUTTON_DOWN as u16, 0, 0))
            .is_empty());
        assert_eq!(
            c.classify_mouse(mouse_ev(0, RI_MOUSE_MIDDLE_BUTTON_UP as u16, 0, 0)),
            vec![InputActivityCategory::PointerRelease]
        );

        // Movement after all buttons released emits nothing.
        assert!(c.classify_mouse(mouse_ev(0, 0, 10, 10)).is_empty());
    }

    #[test]
    fn classifier_rdp_absolute_drag_and_coordinate_clearing() {
        let mut c = RawInputClassifier::new();
        let abs = MOUSE_MOVE_ABSOLUTE.0;

        // Absolute move without button held never stores coords or emits drag.
        assert!(c.classify_mouse(mouse_ev(abs, 0, 10_000, 20_000)).is_empty());
        assert!(!c.has_last_abs_pos());

        // Press left button at (10_000, 20_000): seeds anchor without phantom drag.
        assert!(c
            .classify_mouse(mouse_ev(
                abs,
                RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                10_000,
                20_000
            ))
            .is_empty());
        assert!(c.has_last_abs_pos());

        // Stationary absolute coordinate while held emits nothing.
        assert!(c.classify_mouse(mouse_ev(abs, 0, 10_000, 20_000)).is_empty());

        // Changed absolute coordinate emits DragSample.
        assert_eq!(
            c.classify_mouse(mouse_ev(abs, 0, 10_500, 20_000)),
            vec![InputActivityCategory::DragSample]
        );

        // Button release clears absolute coordinate anchor immediately.
        assert_eq!(
            c.classify_mouse(mouse_ev(
                abs,
                RI_MOUSE_LEFT_BUTTON_UP as u16,
                10_500,
                20_000
            )),
            vec![InputActivityCategory::PointerRelease]
        );
        assert!(!c.has_last_abs_pos());

        // New drag at a completely different screen position must NOT phantom-drag from old anchor.
        assert!(c
            .classify_mouse(mouse_ev(
                abs,
                RI_MOUSE_LEFT_BUTTON_DOWN as u16,
                50_000,
                60_000
            ))
            .is_empty());
        assert!(c.has_last_abs_pos());

        // Boundary clear wipes both held buttons and ephemeral absolute coordinates.
        c.clear();
        assert_eq!(c.held_buttons_mask(), 0);
        assert!(!c.has_last_abs_pos());
        assert!(c.classify_mouse(mouse_ev(abs, 0, 51_000, 60_000)).is_empty());

        // RDP/virtual driver sending dummy (0, 0) on MOUSE_MOVE_ABSOLUTE button-down must NOT
        // seed (0, 0) as a drag anchor and produce a phantom drag on the first real coordinate.
        assert!(c
            .classify_mouse(mouse_ev(abs, RI_MOUSE_LEFT_BUTTON_DOWN as u16, 0, 0))
            .is_empty());
        assert!(!c.has_last_abs_pos());
        assert!(c.classify_mouse(mouse_ev(abs, 0, 32_000, 32_000)).is_empty());
        assert!(c.has_last_abs_pos());
        assert_eq!(
            c.classify_mouse(mouse_ev(abs, 0, 32_100, 32_000)),
            vec![InputActivityCategory::DragSample]
        );
    }

    #[test]
    fn classifier_scroll_wheel_and_hwheel() {
        let mut c = RawInputClassifier::new();
        assert_eq!(
            c.classify_mouse(mouse_ev(0, RI_MOUSE_WHEEL as u16, 0, 0)),
            vec![InputActivityCategory::ScrollSample]
        );
        assert_eq!(
            c.classify_mouse(mouse_ev(0, RI_MOUSE_HWHEEL as u16, 0, 0)),
            vec![InputActivityCategory::ScrollSample]
        );
    }

    #[test]
    fn classifier_shortcuts_autorepeat_e0_and_altgr() {
        let mut c = RawInputClassifier::new();
        let make = 0u16;
        let brk = RI_KEY_BREAK as u16;
        let e0 = RI_KEY_E0 as u16;
        let e1 = RI_KEY_E1 as u16;
        let vk_c: u16 = 0x43;
        let vk_q: u16 = 0x51;

        // Plain typing without Ctrl/Win never counts.
        assert_eq!(c.classify_keyboard(key_ev(vk_c, make)), None);
        assert_eq!(c.classify_keyboard(key_ev(vk_c, brk)), None);

        // LCtrl (generic VK_CONTROL without E0) + C -> ShortcutPress once; autorepeat suppressed.
        assert_eq!(c.classify_keyboard(key_ev(VK_CONTROL.0, make)), None);
        assert_eq!(
            c.classify_keyboard(key_ev(vk_c, make)),
            Some(InputActivityCategory::ShortcutPress)
        );
        // Autorepeat make while C still held -> suppressed!
        assert_eq!(c.classify_keyboard(key_ev(vk_c, make)), None);
        // Break C then press C again -> counts again.
        assert_eq!(c.classify_keyboard(key_ev(vk_c, brk)), None);
        assert_eq!(
            c.classify_keyboard(key_ev(vk_c, make)),
            Some(InputActivityCategory::ShortcutPress)
        );
        assert_eq!(c.classify_keyboard(key_ev(vk_c, brk)), None);
        assert_eq!(c.classify_keyboard(key_ev(VK_CONTROL.0, brk)), None);

        // Win + C counts as ShortcutPress.
        assert_eq!(c.classify_keyboard(key_ev(VK_LWIN.0, make)), None);
        assert_eq!(
            c.classify_keyboard(key_ev(vk_c, make)),
            Some(InputActivityCategory::ShortcutPress)
        );
        assert_eq!(c.classify_keyboard(key_ev(vk_c, brk)), None);
        assert_eq!(c.classify_keyboard(key_ev(VK_LWIN.0, brk)), None);

        // European AltGr (LCtrl + RAlt via VK_MENU|RI_KEY_E0) + Q MUST NOT count as a shortcut!
        assert_eq!(c.classify_keyboard(key_ev(VK_CONTROL.0, make)), None);
        assert_eq!(c.classify_keyboard(key_ev(VK_MENU.0, make | e0)), None);
        assert!(c.is_altgr_active());
        assert_eq!(c.classify_keyboard(key_ev(vk_q, make)), None);
        assert_eq!(c.classify_keyboard(key_ev(vk_q, brk)), None);
        assert_eq!(c.classify_keyboard(key_ev(VK_MENU.0, brk | e0)), None);
        assert_eq!(c.classify_keyboard(key_ev(VK_CONTROL.0, brk)), None);
        assert!(!c.is_altgr_active());

        // LCtrl + LAlt (VK_MENU without E0) + C IS a real shortcut (NOT AltGr!).
        assert_eq!(c.classify_keyboard(key_ev(VK_CONTROL.0, make)), None);
        assert_eq!(c.classify_keyboard(key_ev(VK_MENU.0, make)), None);
        assert!(!c.is_altgr_active());
        assert_eq!(
            c.classify_keyboard(key_ev(vk_c, make)),
            Some(InputActivityCategory::ShortcutPress)
        );
        assert_eq!(c.classify_keyboard(key_ev(vk_c, brk)), None);
        assert_eq!(c.classify_keyboard(key_ev(VK_MENU.0, brk)), None);
        assert_eq!(c.classify_keyboard(key_ev(VK_CONTROL.0, brk)), None);

        // RCtrl (VK_CONTROL|RI_KEY_E0) + RAlt (VK_MENU|RI_KEY_E0) + C IS a shortcut (not AltGr).
        assert_eq!(c.classify_keyboard(key_ev(VK_CONTROL.0, make | e0)), None);
        assert_eq!(c.classify_keyboard(key_ev(VK_MENU.0, make | e0)), None);
        assert!(!c.is_altgr_active());
        assert_eq!(
            c.classify_keyboard(key_ev(vk_c, make)),
            Some(InputActivityCategory::ShortcutPress)
        );
        c.clear();

        // Pause/Break E1 sequence must not latch Ctrl.
        assert_eq!(c.classify_keyboard(key_ev(VK_CONTROL.0, make | e1)), None);
        assert_eq!(c.classify_keyboard(key_ev(vk_c, make)), None);

        // Pure modifier combinations (Ctrl + Shift) never count as ShortcutPress.
        c.clear();
        assert_eq!(c.classify_keyboard(key_ev(VK_CONTROL.0, make)), None);
        assert_eq!(c.classify_keyboard(key_ev(VK_SHIFT.0, make)), None);
        assert_eq!(c.classify_keyboard(key_ev(VK_LSHIFT.0, make)), None);
        assert_eq!(c.classify_keyboard(key_ev(VK_RSHIFT.0, make)), None);
    }

    #[test]
    fn freshness_and_foreground_privacy_gate_fail_closed() {
        // Freshness boundary checks.
        assert!(accepts_qpc_timestamp(1_000, 1_000, 999));
        assert!(accepts_qpc_timestamp(1_000, 1_000 + MAX_EVENT_AGE_NS, 999));
        assert!(!accepts_qpc_timestamp(1_000, 1_000 + MAX_EVENT_AGE_NS + 1, 999));
        assert!(!accepts_qpc_timestamp(1_000, 1_000, 1_000)); // not strictly after fence
        assert!(!accepts_qpc_timestamp(1_001, 1_000, 999)); // future timestamp

        // Queue delay wrapping checks.
        assert_eq!(message_queue_delay_ms(1_050, 1_000), 50);
        assert_eq!(message_queue_delay_ms(10, u32::MAX - 5), 16);
        assert_eq!(message_queue_delay_ms(1_000, 1_010), 0);

        // Dual-ID mandatory exclusion (MSIX Bitwarden must be excluded even under denylist).
        let mut denylist_policy = CapturePolicy {
            enabled: true,
            input_activity: Some(true),
            application_scope: Some("denylist".to_string()),
            allow_browser_content: Some(true),
            ..CapturePolicy::default()
        };
        let msix_bitwarden = ResolvedAppIdentity::from_parts(
            Some("bitwarden.desktop".to_string()),
            Some("bitwarden.exe".to_string()),
        )
        .expect("valid dual-ID");
        assert_eq!(
            evaluate_foreground_gate(&denylist_policy, &msix_bitwarden, None),
            ForegroundGateVerdict::Excluded
        );

        // Known browser private title & missing title fail closed; normal title allowed.
        let chrome = ResolvedAppIdentity::from_single("chrome.exe".to_string()).unwrap();
        assert_eq!(
            evaluate_foreground_gate(
                &denylist_policy,
                &chrome,
                Some("New Tab - Google Chrome (Incognito)")
            ),
            ForegroundGateVerdict::Excluded
        );
        assert_eq!(
            evaluate_foreground_gate(&denylist_policy, &chrome, None),
            ForegroundGateVerdict::Excluded
        );
        assert_eq!(
            evaluate_foreground_gate(&denylist_policy, &chrome, Some("Docs - Google Chrome")),
            ForegroundGateVerdict::Allowed
        );

        // Browser disallowed when allow_browser_content is false.
        denylist_policy.allow_browser_content = Some(false);
        assert_eq!(
            evaluate_foreground_gate(&denylist_policy, &chrome, Some("Docs - Google Chrome")),
            ForegroundGateVerdict::Excluded
        );

        // Normal allowed app works; disabled input_activity returns Disabled.
        let notepad = ResolvedAppIdentity::from_single("notepad.exe".to_string()).unwrap();
        assert_eq!(
            evaluate_foreground_gate(&denylist_policy, &notepad, None),
            ForegroundGateVerdict::Allowed
        );
        denylist_policy.input_activity = Some(false);
        assert_eq!(
            evaluate_foreground_gate(&denylist_policy, &notepad, None),
            ForegroundGateVerdict::Disabled
        );
    }

    #[test]
    fn bounded_notice_queue_caps_activity_and_preserves_security_notices() {
        let mut q = BoundedNoticeQueue::new(4);
        let app = ApplicationIdentity {
            application_id: "notepad.exe".to_string(),
            process_id: 1234,
            process_start_time: "unix-ms:1000.000".to_string(),
        };
        let resolved = ResolvedAppIdentity::from_single("notepad.exe".to_string()).unwrap();
        for i in 0..10 {
            q.push_activity(
                InputActivitySample {
                    application: app.clone(),
                    exe_name: resolved.exe_name.clone(),
                    category: InputActivityCategory::PointerRelease,
                    callback_time_ms: 10_000 + i,
                },
                resolved.clone(),
            );
        }
        assert_eq!(q.items.len(), 4);

        // ExcludedApplication evicts an Activity entry when full and coalesces duplicates.
        q.push_excluded();
        q.push_excluded();
        assert_eq!(q.items.len(), 4);
        assert_eq!(q.items.back(), Some(&RawInputNotice::ExcludedApplication));

        // DesktopBoundaryLost purges all queued Activity notices immediately.
        q.push_desktop_boundary_lost();
        assert_eq!(q.drain(), vec![RawInputNotice::DesktopBoundaryLost]);
    }

    #[test]
    fn live_monitor_start_fence_wts_latch_and_clean_stop() {
        let _guard = LIVE_MONITOR_LOCK.lock().expect("live monitor lock");

        let mut monitor = RawInputActivityMonitor::start().expect("RawInputActivityMonitor::start");
        assert!(monitor.is_healthy());
        assert!(!monitor.is_desktop_latched());

        let hwnd = monitor.hwnd_for_test();
        assert!(!hwnd.0.is_null());
        // SAFETY: Live HWND_MESSAGE created by the monitor thread.
        assert!(unsafe { IsWindow(Some(hwnd)).as_bool() });

        // reset_boundary strictly advances the monotonic QPC fence.
        let initial_fence = monitor.accept_after_qpc_ns();
        let target_fence = initial_fence.saturating_add(5_000_000);
        let updated = monitor.reset_boundary(target_fence);
        assert!(updated >= target_fence);
        assert_eq!(monitor.accept_after_qpc_ns(), updated);
        // Never regresses on older timestamp.
        assert_eq!(monitor.reset_boundary(initial_fence), updated);

        // Simulate WM_WTSSESSION_CHANGE(WTS_SESSION_LOCK) for this session -> <1ms sticky latch!
        let sid = current_wts_session_id().unwrap_or(0);
        // SAFETY: Sending WM_WTSSESSION_CHANGE directly to our own test HWND_MESSAGE window.
        unsafe {
            let _ = SendMessageW(
                hwnd,
                WM_WTSSESSION_CHANGE,
                Some(WPARAM(WTS_SESSION_LOCK as usize)),
                Some(LPARAM(sid as isize)),
            );
        }
        assert!(monitor.is_desktop_latched());
        assert_eq!(
            monitor.drain_events(),
            vec![RawInputNotice::DesktopBoundaryLost]
        );

        // Normal reset_boundary MUST NOT unlatch a locked desktop.
        let _ = monitor.reset_boundary(monotonic_qpc_ns_now());
        assert!(monitor.is_desktop_latched());

        // Explicit user-action reset clears the sticky desktop latch.
        let _ = monitor.reset_desktop_latch_for_user_action(monotonic_qpc_ns_now());
        assert!(!monitor.is_desktop_latched());

        // WTS_CONSOLE_DISCONNECT and WTS_REMOTE_DISCONNECT also latch immediately.
        for code in [WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT] {
            // SAFETY: Sending WM_WTSSESSION_CHANGE directly to our own test HWND_MESSAGE window.
            unsafe {
                let _ = SendMessageW(
                    hwnd,
                    WM_WTSSESSION_CHANGE,
                    Some(WPARAM(code as usize)),
                    Some(LPARAM(sid as isize)),
                );
            }
            assert!(monitor.is_desktop_latched());
            assert_eq!(
                monitor.drain_events(),
                vec![RawInputNotice::DesktopBoundaryLost]
            );
            let _ = monitor.reset_desktop_latch_for_user_action(monotonic_qpc_ns_now());
            assert!(!monitor.is_desktop_latched());
        }

        // Clean stop joins thread, unregisters WTS & Raw Input, and destroys window.
        monitor.stop();
        assert!(!monitor.is_healthy());
        // SAFETY: Verify HWND is no longer a valid window handle after stop().
        assert!(!unsafe { IsWindow(Some(hwnd)).as_bool() });

        // Idempotent second stop().
        monitor.stop();
    }

    #[test]
    fn live_monitor_drop_cleans_up_without_hanging() {
        let _guard = LIVE_MONITOR_LOCK.lock().expect("live monitor lock");

        let hwnd = {
            let monitor =
                RawInputActivityMonitor::start().expect("RawInputActivityMonitor::start");
            assert!(monitor.is_healthy());
            let policy = CapturePolicy {
                input_activity: Some(true),
                ..CapturePolicy::default()
            };
            monitor.set_policy(Some(policy), monotonic_qpc_ns_now());
            monitor.hwnd_for_test()
        };

        // After Drop, the message window MUST be destroyed cleanly.
        // SAFETY: Verifying dropped monitor's HWND is destroyed.
        assert!(!unsafe { IsWindow(Some(hwnd)).as_bool() });
    }

    #[test]
    fn validate_input_activity_context_rejects_unhealthy_or_disabled() {
        let app = ApplicationIdentity {
            application_id: "notepad.exe".to_string(),
            process_id: 1234,
            process_start_time: "unix-ms:1000.000".to_string(),
        };
        let resolved = ResolvedAppIdentity::from_single("notepad.exe".to_string()).unwrap();
        let mut policy = CapturePolicy {
            enabled: true,
            input_activity: Some(true),
            application_scope: Some("denylist".to_string()),
            ..CapturePolicy::default()
        };

        assert!(!validate_input_activity_context(&resolved, &policy, false));
        assert!(!validate_input_activity_application(
            &app, &resolved, &policy, false
        ));

        policy.input_activity = Some(false);
        assert!(!validate_input_activity_context(&resolved, &policy, true));
        assert!(!validate_input_activity_application(
            &app, &resolved, &policy, true
        ));

        policy.input_activity = Some(true);
        let denied = ResolvedAppIdentity::from_single("1password.exe".to_string()).unwrap();
        assert!(!validate_input_activity_context(&denied, &policy, true));
    }

    #[test]
    fn excluded_foreground_notice_deduplicates_per_hwnd_and_resets_on_policy_change() {
        let shared = Arc::new(SharedMonitorState::new(0));
        let mut state = ThreadWindowState {
            shared: Arc::clone(&shared),
            expected_session_id: Some(1),
            classifier: RawInputClassifier::new(),
            seen_boundary_gen: shared.boundary_generation.load(Ordering::Acquire),
            seen_policy_gen: shared.policy_generation.load(Ordering::Acquire),
            last_fg_hwnd: Some(0x100),
            last_excluded_fg_hwnd: None,
            current_msg_time_ms: None,
            wts_registered: false,
            window_destroyed: false,
        };

        // First excluded event on HWND 0x100 emits a single ExcludedApplication notice.
        assert!(state.record_excluded_foreground(0x100));
        assert_eq!(state.last_fg_hwnd, None);
        assert_eq!(
            shared.notices.lock().unwrap().drain(),
            vec![RawInputNotice::ExcludedApplication]
        );

        // Subsequent mouse/key moves while still focused on excluded HWND 0x100 emit nothing.
        for _ in 0..10 {
            assert!(!state.record_excluded_foreground(0x100));
        }
        assert!(shared.notices.lock().unwrap().drain().is_empty());

        // Plain boundary_generation bump (from engine reset_boundary) must NOT create a loop.
        shared.boundary_generation.fetch_add(1, Ordering::AcqRel);
        let _ = state.sync_boundary();
        assert!(!state.record_excluded_foreground(0x100));
        assert!(shared.notices.lock().unwrap().drain().is_empty());

        // Switching to a different excluded HWND emits once for the new HWND.
        assert!(state.record_excluded_foreground(0x200));
        assert!(!state.record_excluded_foreground(0x200));
        assert_eq!(
            shared.notices.lock().unwrap().drain(),
            vec![RawInputNotice::ExcludedApplication]
        );

        // Policy change clears dedup so the HWND is re-evaluated cleanly.
        shared.policy_generation.fetch_add(1, Ordering::AcqRel);
        let _ = state.sync_boundary();
        assert!(state.record_excluded_foreground(0x200));
        assert_eq!(
            shared.notices.lock().unwrap().drain(),
            vec![RawInputNotice::ExcludedApplication]
        );
    }
}

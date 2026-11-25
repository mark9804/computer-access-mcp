//! Ultra-fast dedicated Win32 low-level hook thread (`WH_KEYBOARD_LL` + `WH_MOUSE_LL`) for
//! menu-scoped passive commit signals (`MenuCommitSignal`), with a clean optional PR 5B slot for
//! `input.text` raw key snapshotting (`RawKeyHookEvent`).
//!
//! Layer 0 leaf module — imports no sibling `uia_worker` modules.
//!
//! # Critical Hook Safety Invariant
//! - Hook callbacks (`low_level_keyboard_proc`, `low_level_mouse_proc`) MUST complete in `<10µs`
//!   and ALWAYS return `CallNextHookEx` immediately.
//! - NEVER block, NEVER call UIA/COM/`SendMessage`, NEVER call `ToUnicodeEx`, and NEVER read or
//!   retain mouse coordinates (`MSLLHOOKSTRUCT.pt` is never even dereferenced).
//! - Gated by `menu_open: Arc<AtomicBool>`: when `menu_open` is `false` (and `keyboard_slot` is
//!   `None` in PR 5A), callbacks perform a single `Ordering::Relaxed` atomic load and immediately
//!   return `CallNextHookEx`.
//! - When `menu_open` is `true`, emits ONLY coarse [`MenuCommitSignal`] values (`LeftButtonUp`,
//!   `Return`, `Escape`) via non-blocking `try_send` to a bounded `mpsc::sync_channel(32)`.
//!
//! # PR 5B Extension Seam (`input.text` Raw Key Snapshotting)
//! PR 5B can supply `Some(KeyboardHookSlot)` via [`MenuCommitHook::try_start_with_keyboard_slot`]
//! so the same dedicated `"input-hook"` thread snapshots raw key-down metadata (`vk_code`,
//! `scan_code`, `flags`, `mod_bits`, `fg_hwnd`, `focus_epoch`, timestamps) into a bounded
//! `mpsc::sync_channel(64)` without installing a second `WH_KEYBOARD_LL` hook or rewriting the
//! hook thread.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, Ordering};
use std::sync::mpsc::{self, TrySendError};
use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle};

use windows::Win32::Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, GetKeyState, VK_CAPITAL, VK_ESCAPE, VK_LCONTROL, VK_LMENU, VK_LSHIFT,
    VK_LWIN, VK_RCONTROL, VK_RETURN, VK_RMENU, VK_RSHIFT, VK_RWIN,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetForegroundWindow, GetMessageW, PeekMessageW,
    PostThreadMessageW, SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx, HC_ACTION, HHOOK,
    KBDLLHOOKSTRUCT, LLKHF_ALTDOWN, MSG, PM_NOREMOVE, WH_KEYBOARD_LL, WH_MOUSE_LL, WM_KEYDOWN,
    WM_LBUTTONUP, WM_QUIT, WM_RBUTTONDOWN, WM_SYSKEYDOWN,
};

use crate::protocol_model::SystemCollectorClock;

/// Bounded channel capacity for coarse menu commit signals emitted while a menu is open.
#[allow(dead_code)] // Consumed by Wave 3 menu_action_session.
pub(crate) const MENU_COMMIT_CHANNEL_CAPACITY: usize = 32;

/// Bounded channel capacity for PR 5B `input.text` raw key-down hook snapshots.
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) const RAW_KEY_EVENT_CHANNEL_CAPACITY: usize = 64;

/// Modifier bitmask flags captured in [`RawKeyDownSnapshot::mod_bits`] for PR 5B `input.text`.
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) const MOD_BIT_LSHIFT: u16 = 1 << 0;
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) const MOD_BIT_RSHIFT: u16 = 1 << 1;
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) const MOD_BIT_LCONTROL: u16 = 1 << 2;
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) const MOD_BIT_RCONTROL: u16 = 1 << 3;
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) const MOD_BIT_LMENU: u16 = 1 << 4;
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) const MOD_BIT_RMENU: u16 = 1 << 5;
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) const MOD_BIT_LWIN: u16 = 1 << 6;
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) const MOD_BIT_RWIN: u16 = 1 << 7;
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) const MOD_BIT_CAPS_LOCK: u16 = 1 << 8;
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) const MOD_BIT_LLKHF_ALTDOWN: u16 = 1 << 9;

/// Monotonic QPC timestamp in nanoseconds (process-cached frequency for `<1µs` hook callbacks).
pub(crate) fn qpc_ns_now() -> u64 {
    static QPC_FREQ: OnceLock<u64> = OnceLock::new();
    let freq = *QPC_FREQ.get_or_init(|| {
        let mut f: i64 = 0;
        // SAFETY: QueryPerformanceFrequency always succeeds on Windows XP+.
        unsafe {
            let _ = QueryPerformanceFrequency(&mut f);
        }
        if f > 0 {
            f as u64
        } else {
            0
        }
    });
    if freq == 0 {
        return 0;
    }
    let mut counter: i64 = 0;
    // SAFETY: QueryPerformanceCounter always succeeds on Windows XP+.
    unsafe {
        let _ = QueryPerformanceCounter(&mut counter);
    }
    if counter <= 0 {
        return 0;
    }
    ((counter as u128 * 1_000_000_000_u128) / (freq as u128)) as u64
}

/// Coarse menu-scoped passive commit / cancel signal emitted ONLY while `menu_open` is `true`.
///
/// PRIVACY INVARIANT: Carries ZERO mouse coordinates, ZERO key text, and ZERO window handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuCommitSignal {
    LeftButtonUp { qpc_ns: u64, unix_ms: i64 },
    Return { qpc_ns: u64, unix_ms: i64 },
    Escape { qpc_ns: u64, unix_ms: i64 },
    /// Right-click (`WM_RBUTTONDOWN`) while a menu is open: disarms active menu-bar links
    /// immediately (zero coordinates, never dereferences `MSLLHOOKSTRUCT`).
    Cancel { qpc_ns: u64, unix_ms: i64 },
}

impl MenuCommitSignal {
    pub fn qpc_ns(&self) -> u64 {
        match *self {
            Self::LeftButtonUp { qpc_ns, .. }
            | Self::Return { qpc_ns, .. }
            | Self::Escape { qpc_ns, .. }
            | Self::Cancel { qpc_ns, .. } => qpc_ns,
        }
    }

    pub fn monotonic_ms(&self) -> i64 {
        (self.qpc_ns() / 1_000_000) as i64
    }

    pub fn unix_ms(&self) -> i64 {
        match *self {
            Self::LeftButtonUp { unix_ms, .. }
            | Self::Return { unix_ms, .. }
            | Self::Escape { unix_ms, .. }
            | Self::Cancel { unix_ms, .. } => unix_ms,
        }
    }
}

/// PR 5B raw key-down metadata snapshot captured in `<10µs` on the `input-hook` thread without
/// calling `ToUnicodeEx` or any COM/UIA API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) struct RawKeyDownSnapshot {
    pub(crate) vk_code: u32,
    pub(crate) scan_code: u32,
    pub(crate) flags: u32,
    pub(crate) is_sys_key: bool,
    pub(crate) qpc_ns: u64,
    pub(crate) unix_ms: i64,
    pub(crate) fg_hwnd: isize,
    pub(crate) focus_epoch: u64,
    pub(crate) mod_bits: u16,
}

/// PR 5B event delivered from the `input-hook` thread to `InputTextSession` on the worker main MTA
/// thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) enum RawKeyHookEvent {
    KeyDown(RawKeyDownSnapshot),
    BoundaryMismatch { qpc_ns: u64, unix_ms: i64 },
}

/// Optional PR 5B keyboard capture slot attached to the shared `input-hook` thread (default `None`
/// in PR 5A so inactive hooks perform zero extra atomic loads).
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) struct KeyboardHookSlot {
    pub(crate) active: Arc<AtomicBool>,
    pub(crate) retiring: Arc<AtomicBool>,
    pub(crate) secure_input_blocked: Arc<AtomicBool>,
    pub(crate) context_ready: Arc<AtomicBool>,
    pub(crate) bound_hwnd: Arc<AtomicIsize>,
    pub(crate) focus_epoch: Arc<AtomicU64>,
    pub(crate) backpressure: Arc<AtomicBool>,
    pub(crate) tx: mpsc::SyncSender<RawKeyHookEvent>,
}

/// Create a bounded channel sized to [`RAW_KEY_EVENT_CHANNEL_CAPACITY`] (64) for PR 5B raw key
/// hook events.
#[allow(dead_code)] // PR 5B extension seam.
pub(crate) fn create_raw_key_channel() -> (
    mpsc::SyncSender<RawKeyHookEvent>,
    mpsc::Receiver<RawKeyHookEvent>,
) {
    mpsc::sync_channel(RAW_KEY_EVENT_CHANNEL_CAPACITY)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuCommitKeyKind {
    Return,
    Escape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuCommitMouseKind {
    LeftButtonUp,
    Cancel,
}

#[inline]
fn classify_menu_mouse_message(msg: u32, menu_open: bool) -> Option<MenuCommitMouseKind> {
    if !menu_open {
        return None;
    }
    if msg == WM_LBUTTONUP {
        Some(MenuCommitMouseKind::LeftButtonUp)
    } else if msg == WM_RBUTTONDOWN {
        Some(MenuCommitMouseKind::Cancel)
    } else {
        None
    }
}

#[inline]
fn classify_menu_key_message(msg: u32, vk_code: u32, menu_open: bool) -> Option<MenuCommitKeyKind> {
    if !menu_open || (msg != WM_KEYDOWN && msg != WM_SYSKEYDOWN) {
        return None;
    }
    if vk_code == u32::from(VK_RETURN.0) {
        Some(MenuCommitKeyKind::Return)
    } else if vk_code == u32::from(VK_ESCAPE.0) {
        Some(MenuCommitKeyKind::Escape)
    } else {
        None
    }
}

#[inline]
fn is_key_down_async(vk: u16) -> bool {
    // SAFETY: Fast user32 async key-state query (no blocking IPC, no dead-key state mutation).
    (unsafe { GetAsyncKeyState(i32::from(vk)) } as u16 & 0x8000) != 0
}

fn snapshot_modifier_bits(flags: u32) -> u16 {
    let mut bits = 0u16;
    if is_key_down_async(VK_LSHIFT.0) {
        bits |= MOD_BIT_LSHIFT;
    }
    if is_key_down_async(VK_RSHIFT.0) {
        bits |= MOD_BIT_RSHIFT;
    }
    if is_key_down_async(VK_LCONTROL.0) {
        bits |= MOD_BIT_LCONTROL;
    }
    if is_key_down_async(VK_RCONTROL.0) {
        bits |= MOD_BIT_RCONTROL;
    }
    if is_key_down_async(VK_LMENU.0) {
        bits |= MOD_BIT_LMENU;
    }
    if is_key_down_async(VK_RMENU.0) {
        bits |= MOD_BIT_RMENU;
    }
    if is_key_down_async(VK_LWIN.0) {
        bits |= MOD_BIT_LWIN;
    }
    if is_key_down_async(VK_RWIN.0) {
        bits |= MOD_BIT_RWIN;
    }
    // SAFETY: Fast toggle-state check for CapsLock (bit 0 = toggled).
    if (unsafe { GetKeyState(i32::from(VK_CAPITAL.0)) } & 0x0001) != 0 {
        bits |= MOD_BIT_CAPS_LOCK;
    }
    if (flags & LLKHF_ALTDOWN.0) != 0 {
        bits |= MOD_BIT_LLKHF_ALTDOWN;
    }
    bits
}

struct InputHookThreadContext {
    menu_open: Arc<AtomicBool>,
    menu_tx: mpsc::SyncSender<MenuCommitSignal>,
    menu_dropped: Arc<AtomicU64>,
    keyboard_slot: Option<KeyboardHookSlot>,
}

thread_local! {
    static INPUT_HOOK_CTX: RefCell<Option<InputHookThreadContext>> = const { RefCell::new(None) };
}

fn dispatch_mouse_hook_event(ctx: &InputHookThreadContext, msg: u32) {
    // Fast path: when menu_open is false (99.9% of the time in PR 5A), perform ONLY a single
    // Ordering::Relaxed atomic load and return immediately without reading coordinates.
    let menu_open = ctx.menu_open.load(Ordering::Relaxed);
    let Some(kind) = classify_menu_mouse_message(msg, menu_open) else {
        return;
    };
    let qpc_ns = qpc_ns_now();
    let unix_ms = SystemCollectorClock::unix_ms_now();
    let signal = match kind {
        MenuCommitMouseKind::LeftButtonUp => MenuCommitSignal::LeftButtonUp { qpc_ns, unix_ms },
        MenuCommitMouseKind::Cancel => MenuCommitSignal::Cancel { qpc_ns, unix_ms },
    };
    if let Err(TrySendError::Full(_)) = ctx.menu_tx.try_send(signal) {
        ctx.menu_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

fn dispatch_keyboard_hook_event(
    ctx: &InputHookThreadContext,
    msg: u32,
    kb: &KBDLLHOOKSTRUCT,
    fg_hwnd_override: Option<isize>,
) {
    // Fast path in PR 5A: `keyboard_slot` is `None`, so when `menu_open` is `false` we execute a
    // SINGLE `Ordering::Relaxed` atomic load and return immediately.
    let menu_open = ctx.menu_open.load(Ordering::Relaxed);
    let kb_active = ctx
        .keyboard_slot
        .as_ref()
        .is_some_and(|slot| slot.active.load(Ordering::Relaxed));

    if !menu_open && !kb_active {
        return;
    }

    let menu_key = classify_menu_key_message(msg, kb.vkCode, menu_open);
    let should_run_kb = kb_active
        && (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN)
        && ctx.keyboard_slot.as_ref().is_some_and(|slot| {
            !slot.retiring.load(Ordering::Relaxed)
                && !slot.secure_input_blocked.load(Ordering::Relaxed)
                && slot.context_ready.load(Ordering::Relaxed)
        });

    if menu_key.is_none() && !should_run_kb {
        return;
    }

    let qpc_ns = qpc_ns_now();
    let unix_ms = SystemCollectorClock::unix_ms_now();

    if let Some(kind) = menu_key {
        let signal = match kind {
            MenuCommitKeyKind::Return => MenuCommitSignal::Return { qpc_ns, unix_ms },
            MenuCommitKeyKind::Escape => MenuCommitSignal::Escape { qpc_ns, unix_ms },
        };
        if let Err(TrySendError::Full(_)) = ctx.menu_tx.try_send(signal) {
            ctx.menu_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    if should_run_kb {
        if let Some(ref slot) = ctx.keyboard_slot {
            let fg_raw = fg_hwnd_override.unwrap_or_else(|| {
                // SAFETY: Fast read-only foreground HWND lookup (no IPC/SendMessage).
                unsafe { GetForegroundWindow().0 as isize }
            });
            let bound = slot.bound_hwnd.load(Ordering::Relaxed);
            let event = if fg_raw == 0 || bound == 0 || fg_raw != bound {
                RawKeyHookEvent::BoundaryMismatch { qpc_ns, unix_ms }
            } else {
                RawKeyHookEvent::KeyDown(RawKeyDownSnapshot {
                    vk_code: kb.vkCode,
                    scan_code: kb.scanCode,
                    flags: kb.flags.0,
                    is_sys_key: msg == WM_SYSKEYDOWN,
                    qpc_ns,
                    unix_ms,
                    fg_hwnd: fg_raw,
                    focus_epoch: slot.focus_epoch.load(Ordering::Relaxed),
                    mod_bits: snapshot_modifier_bits(kb.flags.0),
                })
            };
            if let Err(TrySendError::Full(_)) = slot.tx.try_send(event) {
                slot.backpressure.store(true, Ordering::Release);
            }
        }
    }
}

unsafe extern "system" fn low_level_mouse_proc(
    n_code: i32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Only WM_LBUTTONUP (commit) and WM_RBUTTONDOWN (cancel) are relevant; skip TLS touch
        // entirely for WM_MOUSEMOVE etc.
        // PRIVACY INVARIANT: Never dereference `l_param` (`MSLLHOOKSTRUCT`) or read cursor coordinates.
        if n_code == HC_ACTION as i32 {
            let msg = w_param.0 as u32;
            if msg == WM_LBUTTONUP || msg == WM_RBUTTONDOWN {
                INPUT_HOOK_CTX.with(|cell| {
                    if let Ok(guard) = cell.try_borrow() {
                        if let Some(ref ctx) = *guard {
                            dispatch_mouse_hook_event(ctx, msg);
                        }
                    }
                });
            }
        }
    }));
    CallNextHookEx(None, n_code, w_param, l_param)
}

unsafe extern "system" fn low_level_keyboard_proc(
    n_code: i32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if n_code == HC_ACTION as i32 {
            let msg = w_param.0 as u32;
            if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) && l_param.0 != 0 {
                INPUT_HOOK_CTX.with(|cell| {
                    if let Ok(guard) = cell.try_borrow() {
                        if let Some(ref ctx) = *guard {
                            // Fast gate before copying KBDLLHOOKSTRUCT: single Relaxed atomic load
                            // when menu_open is false and PR 5B keyboard_slot is None.
                            let menu_open = ctx.menu_open.load(Ordering::Relaxed);
                            let kb_active = ctx
                                .keyboard_slot
                                .as_ref()
                                .is_some_and(|slot| slot.active.load(Ordering::Relaxed));
                            if menu_open || kb_active {
                                // SAFETY: Win32 guarantees `l_param` points to a valid
                                // `KBDLLHOOKSTRUCT` when `n_code == HC_ACTION` in `WH_KEYBOARD_LL`.
                                let kb = unsafe { *(l_param.0 as *const KBDLLHOOKSTRUCT) };
                                dispatch_keyboard_hook_event(ctx, msg, &kb, None);
                            }
                        }
                    }
                });
            }
        }
    }));
    CallNextHookEx(None, n_code, w_param, l_param)
}

/// Dedicated `"input-hook"` OS thread installing `WH_KEYBOARD_LL` and `WH_MOUSE_LL` hooks for
/// menu-scoped passive commit signals (and optional PR 5B raw key snapshotting).
///
/// Degrades gracefully: [`Self::try_start`] returns `None` if thread creation or hook installation
/// fails, without crashing or blocking UIA `Invoke_Invoked`.
pub struct MenuCommitHook {
    menu_open: Arc<AtomicBool>,
    menu_rx: mpsc::Receiver<MenuCommitSignal>,
    menu_dropped: Arc<AtomicU64>,
    stop_requested: Arc<AtomicBool>,
    thread_id: u32,
    handle: Option<JoinHandle<()>>,
}

#[allow(dead_code)] // PR 5B keyboard-slot seam remains crate-internal until PR 5B.
impl MenuCommitHook {
    /// Start the dedicated `"input-hook"` thread for menu-scoped passive commit signals only
    /// (`keyboard_slot = None` in PR 5A).
    ///
    /// Returns `None` cleanly if spawning the hook thread or installing either low-level hook
    /// fails.
    pub fn try_start(menu_open: Arc<AtomicBool>) -> Option<Self> {
        Self::try_start_with_keyboard_slot(menu_open, None)
    }

    /// Start the dedicated `"input-hook"` thread with an optional PR 5B [`KeyboardHookSlot`].
    ///
    /// Returns `None` cleanly if spawning the hook thread or installing either low-level hook
    /// fails (joining the thread cleanly before returning so no OS thread or hook leaks).
    pub(crate) fn try_start_with_keyboard_slot(
        menu_open: Arc<AtomicBool>,
        keyboard_slot: Option<KeyboardHookSlot>,
    ) -> Option<Self> {
        let (menu_tx, menu_rx) = mpsc::sync_channel(MENU_COMMIT_CHANNEL_CAPACITY);
        let menu_dropped = Arc::new(AtomicU64::new(0));
        let stop_requested = Arc::new(AtomicBool::new(false));

        let menu_open_bg = Arc::clone(&menu_open);
        let menu_dropped_bg = Arc::clone(&menu_dropped);
        let stop_requested_bg = Arc::clone(&stop_requested);

        let (startup_tx, startup_rx) = mpsc::sync_channel::<Result<u32, ()>>(1);

        let handle = thread::Builder::new()
            .name("input-hook".to_string())
            .spawn(move || {
                // SAFETY: Force creation of the thread message queue BEFORE publishing `tid` so
                // an immediate `PostThreadMessageW(tid, WM_QUIT, ...)` from `stop()` never races
                // queue initialization.
                let tid = unsafe {
                    let mut init_msg = MSG::default();
                    let _ = PeekMessageW(&mut init_msg, None, 0, 0, PM_NOREMOVE);
                    GetCurrentThreadId()
                };

                INPUT_HOOK_CTX.with(|cell| {
                    *cell.borrow_mut() = Some(InputHookThreadContext {
                        menu_open: menu_open_bg,
                        menu_tx,
                        menu_dropped: menu_dropped_bg,
                        keyboard_slot,
                    });
                });

                // SAFETY: `GetModuleHandleW(None)` retrieves the current process module handle for
                // global low-level hooks (`dwThreadId = 0`); `None` is also valid on Vista+.
                let hmod: Option<HINSTANCE> = unsafe {
                    GetModuleHandleW(None)
                        .ok()
                        .map(|m| HINSTANCE(m.0))
                };

                // SAFETY: Global low-level hooks pumped on this exact thread's `GetMessageW` loop.
                let kb_hook: Option<HHOOK> = unsafe {
                    SetWindowsHookExW(WH_KEYBOARD_LL, Some(low_level_keyboard_proc), hmod, 0).ok()
                };
                let mouse_hook: Option<HHOOK> = if kb_hook.is_some() {
                    // SAFETY: Global low-level mouse hook pumped on this exact thread.
                    unsafe {
                        SetWindowsHookExW(WH_MOUSE_LL, Some(low_level_mouse_proc), hmod, 0).ok()
                    }
                } else {
                    None
                };

                let both_installed = kb_hook.is_some() && mouse_hook.is_some();
                if both_installed {
                    let _ = startup_tx.send(Ok(tid));
                    if !stop_requested_bg.load(Ordering::Acquire) {
                        let mut msg = MSG::default();
                        // SAFETY: Standard Win32 message pump until WM_QUIT (0) or error (-1).
                        // Check `.0 > 0` explicitly because `BOOL(-1).as_bool()` is `true`!
                        unsafe {
                            while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
                                let _ = TranslateMessage(&msg);
                                DispatchMessageW(&msg);
                                if stop_requested_bg.load(Ordering::Acquire) {
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    let _ = startup_tx.send(Err(()));
                }

                if let Some(hook) = mouse_hook {
                    // SAFETY: Unhooking handle registered on this exact thread.
                    unsafe {
                        let _ = UnhookWindowsHookEx(hook);
                    }
                }
                if let Some(hook) = kb_hook {
                    // SAFETY: Unhooking handle registered on this exact thread.
                    unsafe {
                        let _ = UnhookWindowsHookEx(hook);
                    }
                }

                INPUT_HOOK_CTX.with(|cell| {
                    *cell.borrow_mut() = None;
                });
            })
            .ok()?;

        match startup_rx.recv() {
            Ok(Ok(thread_id)) if thread_id != 0 => Some(Self {
                menu_open,
                menu_rx,
                menu_dropped,
                stop_requested,
                thread_id,
                handle: Some(handle),
            }),
            _ => {
                let _ = handle.join();
                None
            }
        }
    }

    /// Borrow the shared `menu_open` atomic gate.
    pub fn menu_open(&self) -> &Arc<AtomicBool> {
        &self.menu_open
    }

    /// Toggle whether the menu commit fast path is armed.
    pub fn set_menu_open(&self, open: bool) {
        self.menu_open.store(open, Ordering::Release);
    }

    /// Inspect whether the menu commit fast path is currently armed.
    pub fn is_menu_open(&self) -> bool {
        self.menu_open.load(Ordering::Acquire)
    }

    /// True while the background `"input-hook"` thread has not been stopped.
    pub fn is_running(&self) -> bool {
        self.handle.is_some() && self.thread_id != 0
    }

    /// Win32 thread ID of the running `"input-hook"` thread (or `0` after [`Self::stop`]).
    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }

    /// Non-blockingly receive one queued [`MenuCommitSignal`].
    pub fn try_recv(&self) -> Result<MenuCommitSignal, mpsc::TryRecvError> {
        self.menu_rx.try_recv()
    }

    /// Drain all currently queued [`MenuCommitSignal`] values without blocking.
    pub fn drain_signals(&self) -> Vec<MenuCommitSignal> {
        let mut out = Vec::new();
        while let Ok(sig) = self.menu_rx.try_recv() {
            out.push(sig);
        }
        out
    }

    /// Total menu commit signals dropped due to bounded channel backpressure.
    pub fn dropped_menu_signals(&self) -> u64 {
        self.menu_dropped.load(Ordering::Relaxed)
    }

    /// Read and reset the menu commit drop counter.
    pub fn take_dropped_menu_signals(&self) -> u64 {
        self.menu_dropped.swap(0, Ordering::AcqRel)
    }

    #[cfg(test)]
    pub(super) fn inject_dropped_menu_signals_for_test(&self, count: u64) {
        self.menu_dropped.fetch_add(count, Ordering::AcqRel);
    }

    /// Stop the `"input-hook"` thread cleanly by posting `WM_QUIT`, unhooking both low-level
    /// hooks on the hook thread, and joining the thread. Safe to call multiple times.
    pub fn stop(&mut self) {
        self.stop_requested.store(true, Ordering::Release);
        self.menu_open.store(false, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let tid = self.thread_id;
            self.thread_id = 0;
            if tid != 0 {
                // SAFETY: Posting WM_QUIT wakes and exits the hook thread's `GetMessageW` loop.
                unsafe {
                    let _ = PostThreadMessageW(tid, WM_QUIT, WPARAM(0), LPARAM(0));
                }
            }
            let _ = handle.join();
        }
    }
}

impl Drop for MenuCommitHook {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{Duration, Instant};

    use windows::Win32::UI::Input::KeyboardAndMouse::{VK_A, VK_SPACE};
    use windows::Win32::UI::WindowsAndMessaging::{
        KBDLLHOOKSTRUCT_FLAGS, WM_KEYUP, WM_MOUSEMOVE, WM_RBUTTONUP,
    };

    fn make_kb(vk_code: u32, scan_code: u32, flags: u32) -> KBDLLHOOKSTRUCT {
        KBDLLHOOKSTRUCT {
            vkCode: vk_code,
            scanCode: scan_code,
            flags: KBDLLHOOKSTRUCT_FLAGS(flags),
            time: 0,
            dwExtraInfo: 0,
        }
    }

    fn make_test_ctx(
        menu_open: bool,
        keyboard_slot: Option<KeyboardHookSlot>,
    ) -> (InputHookThreadContext, mpsc::Receiver<MenuCommitSignal>) {
        let (menu_tx, menu_rx) = mpsc::sync_channel(MENU_COMMIT_CHANNEL_CAPACITY);
        let ctx = InputHookThreadContext {
            menu_open: Arc::new(AtomicBool::new(menu_open)),
            menu_tx,
            menu_dropped: Arc::new(AtomicU64::new(0)),
            keyboard_slot,
        };
        (ctx, menu_rx)
    }

    #[test]
    fn menu_open_false_suppresses_all_mouse_and_keyboard_signals() {
        let (ctx, rx) = make_test_ctx(false, None);

        dispatch_mouse_hook_event(&ctx, WM_LBUTTONUP);
        dispatch_mouse_hook_event(&ctx, WM_RBUTTONDOWN);
        dispatch_keyboard_hook_event(&ctx, WM_KEYDOWN, &make_kb(u32::from(VK_RETURN.0), 0x1C, 0), None);
        dispatch_keyboard_hook_event(&ctx, WM_KEYDOWN, &make_kb(u32::from(VK_ESCAPE.0), 0x01, 0), None);
        dispatch_keyboard_hook_event(&ctx, WM_SYSKEYDOWN, &make_kb(u32::from(VK_RETURN.0), 0x1C, 0), None);

        assert!(rx.try_recv().is_err());
        assert_eq!(ctx.menu_dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn menu_open_true_emits_only_coarse_commit_and_escape_signals() {
        let (ctx, rx) = make_test_ctx(true, None);

        // Non-matching events must be ignored completely.
        dispatch_mouse_hook_event(&ctx, WM_MOUSEMOVE);
        dispatch_mouse_hook_event(&ctx, WM_RBUTTONUP);
        dispatch_keyboard_hook_event(&ctx, WM_KEYUP, &make_kb(u32::from(VK_RETURN.0), 0x1C, 0), None);
        dispatch_keyboard_hook_event(&ctx, WM_KEYDOWN, &make_kb(u32::from(VK_A.0), 0x1E, 0), None);
        dispatch_keyboard_hook_event(&ctx, WM_KEYDOWN, &make_kb(u32::from(VK_SPACE.0), 0x39, 0), None);
        assert!(rx.try_recv().is_err());

        // Coarse signals: LeftButtonUp, Return, Escape, Cancel (WM_RBUTTONDOWN).
        dispatch_mouse_hook_event(&ctx, WM_LBUTTONUP);
        dispatch_keyboard_hook_event(&ctx, WM_KEYDOWN, &make_kb(u32::from(VK_RETURN.0), 0x1C, 0), None);
        dispatch_keyboard_hook_event(&ctx, WM_SYSKEYDOWN, &make_kb(u32::from(VK_ESCAPE.0), 0x01, 0), None);
        dispatch_mouse_hook_event(&ctx, WM_RBUTTONDOWN);

        let s1 = rx.try_recv().expect("LeftButtonUp");
        assert!(matches!(s1, MenuCommitSignal::LeftButtonUp { .. }));
        assert!(s1.qpc_ns() > 0);
        assert!(s1.unix_ms() > 0);

        let s2 = rx.try_recv().expect("Return");
        assert!(matches!(s2, MenuCommitSignal::Return { .. }));
        assert!(s2.qpc_ns() >= s1.qpc_ns());

        let s3 = rx.try_recv().expect("Escape");
        assert!(matches!(s3, MenuCommitSignal::Escape { .. }));
        assert!(s3.monotonic_ms() >= 0);

        let s4 = rx.try_recv().expect("Cancel on WM_RBUTTONDOWN");
        assert!(matches!(s4, MenuCommitSignal::Cancel { .. }));
        assert!(s4.qpc_ns() >= s3.qpc_ns());
        assert!(s4.unix_ms() > 0);

        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn menu_commit_channel_bounds_backpressure_without_blocking() {
        let (ctx, rx) = make_test_ctx(true, None);
        for _ in 0..(MENU_COMMIT_CHANNEL_CAPACITY + 5) {
            dispatch_mouse_hook_event(&ctx, WM_LBUTTONUP);
        }
        assert_eq!(ctx.menu_dropped.load(Ordering::Relaxed), 5);

        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, MENU_COMMIT_CHANNEL_CAPACITY);
    }

    #[test]
    fn optional_pr5b_keyboard_slot_enforces_boundary_mismatch_and_active_gates() {
        let (kb_tx, kb_rx) = create_raw_key_channel();
        let active = Arc::new(AtomicBool::new(true));
        let retiring = Arc::new(AtomicBool::new(false));
        let secure_input_blocked = Arc::new(AtomicBool::new(false));
        let context_ready = Arc::new(AtomicBool::new(true));
        let bound_hwnd = Arc::new(AtomicIsize::new(0x1234));
        let focus_epoch = Arc::new(AtomicU64::new(7));
        let backpressure = Arc::new(AtomicBool::new(false));

        let slot = KeyboardHookSlot {
            active: Arc::clone(&active),
            retiring: Arc::clone(&retiring),
            secure_input_blocked: Arc::clone(&secure_input_blocked),
            context_ready: Arc::clone(&context_ready),
            bound_hwnd: Arc::clone(&bound_hwnd),
            focus_epoch: Arc::clone(&focus_epoch),
            backpressure: Arc::clone(&backpressure),
            tx: kb_tx,
        };
        let (ctx, menu_rx) = make_test_ctx(false, Some(slot));

        // 1. Matching foreground HWND snapshots key metadata cleanly without firing menu signals.
        dispatch_keyboard_hook_event(
            &ctx,
            WM_KEYDOWN,
            &make_kb(u32::from(VK_A.0), 0x1E, 0),
            Some(0x1234),
        );
        assert!(menu_rx.try_recv().is_err());
        match kb_rx.try_recv().expect("KeyDown snapshot") {
            RawKeyHookEvent::KeyDown(snap) => {
                assert_eq!(snap.vk_code, u32::from(VK_A.0));
                assert_eq!(snap.scan_code, 0x1E);
                assert_eq!(snap.fg_hwnd, 0x1234);
                assert_eq!(snap.focus_epoch, 7);
                assert!(!snap.is_sys_key);
            }
            other => panic!("expected KeyDown, got {other:?}"),
        }

        // 2. Mismatched foreground HWND emits BoundaryMismatch without inspecting key.
        dispatch_keyboard_hook_event(
            &ctx,
            WM_KEYDOWN,
            &make_kb(u32::from(VK_A.0), 0x1E, 0),
            Some(0x9999),
        );
        assert!(matches!(
            kb_rx.try_recv().expect("BoundaryMismatch"),
            RawKeyHookEvent::BoundaryMismatch { .. }
        ));

        // 3. Secure input / retiring / !context_ready / !active gates suppress dispatch.
        secure_input_blocked.store(true, Ordering::Release);
        dispatch_keyboard_hook_event(
            &ctx,
            WM_KEYDOWN,
            &make_kb(u32::from(VK_A.0), 0x1E, 0),
            Some(0x1234),
        );
        assert!(kb_rx.try_recv().is_err());
        secure_input_blocked.store(false, Ordering::Release);

        retiring.store(true, Ordering::Release);
        dispatch_keyboard_hook_event(
            &ctx,
            WM_KEYDOWN,
            &make_kb(u32::from(VK_A.0), 0x1E, 0),
            Some(0x1234),
        );
        assert!(kb_rx.try_recv().is_err());
        retiring.store(false, Ordering::Release);

        context_ready.store(false, Ordering::Release);
        dispatch_keyboard_hook_event(
            &ctx,
            WM_KEYDOWN,
            &make_kb(u32::from(VK_A.0), 0x1E, 0),
            Some(0x1234),
        );
        assert!(kb_rx.try_recv().is_err());
        context_ready.store(true, Ordering::Release);

        active.store(false, Ordering::Release);
        dispatch_keyboard_hook_event(
            &ctx,
            WM_KEYDOWN,
            &make_kb(u32::from(VK_A.0), 0x1E, 0),
            Some(0x1234),
        );
        assert!(kb_rx.try_recv().is_err());
        assert!(!backpressure.load(Ordering::Acquire));
    }

    #[test]
    fn live_win32_menu_commit_hook_toggles_menu_open_and_stops_cleanly() {
        let menu_open = Arc::new(AtomicBool::new(false));
        let mut hook = MenuCommitHook::try_start(Arc::clone(&menu_open))
            .expect("MenuCommitHook::try_start must install WH_KEYBOARD_LL and WH_MOUSE_LL");

        assert!(hook.is_running());
        assert_ne!(hook.thread_id(), 0);
        assert!(!hook.is_menu_open());
        assert_eq!(hook.dropped_menu_signals(), 0);

        // Toggle via shared Arc<AtomicBool> and via helper method.
        menu_open.store(true, Ordering::Release);
        assert!(hook.is_menu_open());
        hook.set_menu_open(false);
        assert!(!menu_open.load(Ordering::Acquire));
        assert!(hook.drain_signals().is_empty());

        // Explicit stop() must post WM_QUIT, unhook both hooks, and join cleanly without hang.
        let stop_start = Instant::now();
        hook.stop();
        assert!(
            stop_start.elapsed() < Duration::from_secs(3),
            "MenuCommitHook::stop exceeded 3s"
        );
        assert!(!hook.is_running());
        assert_eq!(hook.thread_id(), 0);

        // Idempotent second stop().
        hook.stop();

        // Second lifecycle exercising Drop-driven teardown + PR 5B keyboard slot plumbing.
        let (kb_tx, _kb_rx) = create_raw_key_channel();
        let slot = KeyboardHookSlot {
            active: Arc::new(AtomicBool::new(false)),
            retiring: Arc::new(AtomicBool::new(false)),
            secure_input_blocked: Arc::new(AtomicBool::new(false)),
            context_ready: Arc::new(AtomicBool::new(false)),
            bound_hwnd: Arc::new(AtomicIsize::new(0)),
            focus_epoch: Arc::new(AtomicU64::new(0)),
            backpressure: Arc::new(AtomicBool::new(false)),
            tx: kb_tx,
        };
        let drop_start = Instant::now();
        {
            let hook2 = MenuCommitHook::try_start_with_keyboard_slot(
                Arc::new(AtomicBool::new(false)),
                Some(slot),
            )
            .expect("MenuCommitHook::try_start_with_keyboard_slot");
            assert!(hook2.is_running());
            assert_ne!(hook2.thread_id(), 0);
        }
        assert!(
            drop_start.elapsed() < Duration::from_secs(3),
            "MenuCommitHook Drop teardown exceeded 3s"
        );

        fn assert_send<T: Send>() {}
        assert_send::<MenuCommitSignal>();
        assert_send::<RawKeyHookEvent>();
        assert_send::<KeyboardHookSlot>();
        assert_send::<MenuCommitHook>();
    }
}

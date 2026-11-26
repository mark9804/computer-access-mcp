//! Live Windows `input.text` (`win32.unicode`) + hybrid TSF/IMM32 CJK IME session running inside
//! the isolated `--ax-worker --session-worker yes` process.
//!
//! Layer 1 module — strictly acyclic 3-submodule DAG:
//! - Layer 1a (`translate`): `ToUnicodeEx(0x0004)` non-mutating translation, `VK_PACKET` surrogate
//!   assembly, modifier bitset normalization, bounded IMM32 open-status probing
//! - Layer 1b (`safety`): pre/post-read privacy & editable-field gates (`ES_PASSWORD`, UIA
//!   `IsPassword`, focus epoch, private browser chrome, strict editable role verification)
//! - Layer 1c (`mod`): [`InputTextSession`] lifecycle, causal QPC event merge, IME composition
//!   coordination, debounced flush, and read-barrier draining
//!
//! Imports ONLY Layer 0 `uia_worker` leaves (`target_verify`, `uia_events`, `input_hook`) and core
//! modules (`adapters`, `desktop`, `input_text_core`, `policy`, `protocol_model`, `uia_com`,
//! `uia_traversal`). ZERO imports of `menu_action`, `read_pipeline`, or `session`.

pub mod safety;
pub mod translate;

use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};

use windows::Win32::Foundation::HWND;

pub(in crate::uia_worker) use safety::{is_sensitive_or_es_password_meta, BoundInputField};
pub use safety::{hwnd_has_es_password_style, query_foreground_gui_state};
pub use translate::{
    build_minimal_key_state, is_imm32_suppressed_vk, is_imm32_toggle_vk, is_modifier_only_vk,
    mod_bits_to_windows_modifiers, query_imm32_native_ime_active_bounded,
    query_imm32_open_status_bounded, translate_key_to_unicode, translate_vk_non_mutating_for_test,
    translate_vk_packet, TO_UNICODE_NO_STATE_MUTATION_FLAG, VK_ESCAPE_CODE, VK_PACKET_CODE,
    VK_PROCESSKEY_CODE, VK_RETURN_CODE,
};

use safety::{select_safety_pass_kind, verify_live_input_safety, SafetyPassKind};
use crate::adapters::AdapterRegistry;
use crate::input_text_core::{
    ImeCompositionState, InputTextAccumulator, InputTextApprovedContext, InputTextCaptureDecision,
    InputTextCaptureStep, InputTextEventMetadata, InputTextGapReason, InputTextGapRecord,
    InputTextLimits, InputTextReadGate, InputTextRecord, InputTextSafetyRequest, InputTextSource,
    InputTextUnicodeRead, PendingSurrogate,
};
use crate::policy::ResolvedAppIdentity;
use crate::protocol_model::{ApplicationIdentity, CapturePolicy, CollectorClock};
use crate::uia_com::UiaClient;
use crate::uia_worker::input_hook::{
    create_raw_key_channel, qpc_ns_now, KeyboardHookSlot, RawKeyDownSnapshot, RawKeyHookEvent,
};
use crate::uia_worker::target_verify::resolve_application_identity_for_hwnd;
use crate::uia_worker::uia_events::{
    create_text_edit_event_channel, RawUiaTextEditEvent, SensitiveText, TextEditHookGates,
    UiaTextEditEventKind, UiaTextEditEventSubscription,
};

/// Hard aggregate poll time budget (ms) across all drained raw-key & UIA TextEdit events per tick.
/// Sized to accommodate a single fallback 150 ms browser chrome verification if a proof expires
/// during continuous typing while remaining below `InputTextLimits::MAX_EVENT_AGE_NS` (200 ms).
const INPUT_POLL_BUDGET_MS: i64 = 180;

/// Per-event / per-flush safety verification budget (ms), clamped to caller deadline.
const INPUT_EVENT_SAFETY_BUDGET_MS: i64 = 160;

/// Maximum diagnostic gap records retained per read cycle (matching macOS `Session.swift`).
const MAX_INPUT_GAPS: usize = 4;

/// Short cache TTL (ms) for bounded legacy non-TSF IMM32 native-mode probes.
const IMM32_PROBE_CACHE_TTL_MS: i64 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Imm32ProbeCacheEntry {
    hwnd: isize,
    focus_epoch: u64,
    checked_mono_ms: i64,
    active: bool,
}

fn zeroize_input_record(record: InputTextRecord) {
    let mut bytes = record.text.into_bytes();
    bytes.fill(0);
    black_box(&bytes);
}

fn detach_text_edit_subscription_with_budget(
    sub: UiaTextEditEventSubscription,
    retiring: bool,
    uia: Option<&UiaClient>,
    budget: Option<(i64, &dyn CollectorClock)>,
) {
    if retiring {
        sub.abandon_for_process_exit();
        return;
    }
    if let Some((deadline_ms, clock)) = budget {
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 15 {
            sub.abandon_for_process_exit();
            return;
        }
        let per_call_ms = (rem / 2).clamp(1, 40) as u32;
        if let Some(u) = uia {
            u.apply_timeouts(i64::from(per_call_ms));
        }
        sub.detach_with_timeout(per_call_ms);
        if let Some(u) = uia {
            u.apply_timeouts(deadline_ms.saturating_sub(clock.monotonic_ms()));
        }
    } else {
        if let Some(u) = uia {
            u.apply_timeouts(40);
        }
        sub.detach();
    }
}

enum MergedInputEvent {
    TextEdit(RawUiaTextEditEvent),
    KeyHook(RawKeyHookEvent),
}

impl MergedInputEvent {
    fn qpc_ns(&self) -> u64 {
        match self {
            Self::TextEdit(ev) => ev.observed_qpc_ns,
            Self::KeyHook(RawKeyHookEvent::KeyDown(snap)) => snap.qpc_ns,
            Self::KeyHook(RawKeyHookEvent::BoundaryMismatch { qpc_ns, .. }) => *qpc_ns,
        }
    }

    /// Deterministic tie-breaker when two streams carry an identical QPC timestamp:
    /// `BoundaryMismatch` (0) < `Composition` (1) < `CompositionFinalized` (2) < `KeyDown` (3).
    fn tie_priority(&self) -> u8 {
        match self {
            Self::KeyHook(RawKeyHookEvent::BoundaryMismatch { .. }) => 0,
            Self::TextEdit(RawUiaTextEditEvent {
                kind: UiaTextEditEventKind::Composition,
                ..
            }) => 1,
            Self::TextEdit(RawUiaTextEditEvent {
                kind: UiaTextEditEventKind::CompositionFinalized { .. },
                ..
            }) => 2,
            Self::KeyHook(RawKeyHookEvent::KeyDown(_)) => 3,
        }
    }
}

/// Stateful live Windows `input.text` (`win32.unicode`) + hybrid TSF/IMM32 CJK IME session owned
/// exclusively by `LiveUiaSession` inside the isolated `--ax-worker --session-worker yes` process.
///
/// Field drop order note: `text_edit_sub` holds COM interfaces and is released explicitly on
/// [`Self::retire_for_process_exit`] before `UiaClient` and `ComGuard` drop.
pub struct InputTextSession {
    active: Arc<AtomicBool>,
    retiring_flag: Arc<AtomicBool>,
    secure_input_blocked: Arc<AtomicBool>,
    context_ready: Arc<AtomicBool>,
    bound_hwnd: Arc<AtomicIsize>,
    focus_epoch: Arc<AtomicU64>,
    backpressure: Arc<AtomicBool>,

    raw_key_rx: Option<mpsc::Receiver<RawKeyHookEvent>>,
    text_edit_sub: Option<UiaTextEditEventSubscription>,
    text_edit_hwnd_raw: isize,
    text_edit_rx: Option<mpsc::Receiver<RawUiaTextEditEvent>>,

    bound: Option<BoundInputField>,
    accumulator: InputTextAccumulator,
    completed: Vec<InputTextRecord>,
    input_gaps: Vec<InputTextGapRecord>,
    pending_surrogate: PendingSurrogate,

    ime_state: ImeCompositionState,
    ime_last_composition_qpc_ns: u64,
    imm32_probe_cache: Option<Imm32ProbeCacheEntry>,

    accept_after_qpc_ns: u64,
    dirty: bool,
    submit_dirty: bool,
    input_failure: Option<String>,
    secure_input_detected: bool,
    hook_attempted: bool,
    retiring: bool,
}

impl InputTextSession {
    pub fn new(focus_epoch: Arc<AtomicU64>) -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            retiring_flag: Arc::new(AtomicBool::new(false)),
            secure_input_blocked: Arc::new(AtomicBool::new(false)),
            context_ready: Arc::new(AtomicBool::new(false)),
            bound_hwnd: Arc::new(AtomicIsize::new(0)),
            focus_epoch,
            backpressure: Arc::new(AtomicBool::new(false)),
            raw_key_rx: None,
            text_edit_sub: None,
            text_edit_hwnd_raw: 0,
            text_edit_rx: None,
            bound: None,
            accumulator: InputTextAccumulator::default(),
            completed: Vec::new(),
            input_gaps: Vec::new(),
            pending_surrogate: PendingSurrogate::new(),
            ime_state: ImeCompositionState::new(),
            ime_last_composition_qpc_ns: 0,
            imm32_probe_cache: None,
            accept_after_qpc_ns: qpc_ns_now(),
            dirty: false,
            submit_dirty: false,
            input_failure: None,
            secure_input_detected: false,
            hook_attempted: false,
            retiring: false,
        }
    }

    /// Create the bounded raw-key channel and [`KeyboardHookSlot`] wired to this session's atomic
    /// control gates and shared `WinEventWatcher` focus epoch.
    pub fn create_keyboard_slot(&mut self) -> KeyboardHookSlot {
        let (tx, rx) = create_raw_key_channel();
        self.raw_key_rx = Some(rx);
        self.backpressure.store(false, Ordering::Release);
        KeyboardHookSlot {
            active: Arc::clone(&self.active),
            retiring: Arc::clone(&self.retiring_flag),
            secure_input_blocked: Arc::clone(&self.secure_input_blocked),
            context_ready: Arc::clone(&self.context_ready),
            bound_hwnd: Arc::clone(&self.bound_hwnd),
            focus_epoch: Arc::clone(&self.focus_epoch),
            backpressure: Arc::clone(&self.backpressure),
            tx,
        }
    }

    pub fn current_focus_epoch(&self) -> u64 {
        self.focus_epoch.load(Ordering::Acquire)
    }

    /// True while this session has both `context_ready == true` and an active verified field binding.
    pub fn is_context_armed(&self) -> bool {
        self.context_ready.load(Ordering::Acquire) && self.bound.is_some()
    }

    pub fn mark_hook_attempted(&mut self) {
        self.hook_attempted = true;
    }

    pub fn was_hook_attempted(&self) -> bool {
        self.hook_attempted
    }

    pub fn mark_input_failure(&mut self, reason: &str) {
        if self.input_failure.is_none() {
            self.input_failure = Some(reason.to_string());
        }
        self.active.store(false, Ordering::Release);
        self.context_ready.store(false, Ordering::Release);
        self.bound_hwnd.store(0, Ordering::Release);
        self.clear_all_buffers();
        self.bound = None;
        self.dirty = true;
    }

    pub fn input_failure(&self) -> Option<&str> {
        self.input_failure.as_deref()
    }

    pub fn secure_input_detected(&self) -> bool {
        self.secure_input_detected
    }

    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    pub fn take_submit_dirty(&mut self) -> bool {
        std::mem::take(&mut self.submit_dirty)
    }

    pub fn ime_last_composition_qpc_ns(&self) -> u64 {
        self.ime_last_composition_qpc_ns
    }

    fn text_edit_gates(&self) -> TextEditHookGates {
        TextEditHookGates {
            active: Arc::clone(&self.active),
            retiring: Arc::clone(&self.retiring_flag),
            secure_input_blocked: Arc::clone(&self.secure_input_blocked),
            context_ready: Arc::clone(&self.context_ready),
            bound_hwnd: Arc::clone(&self.bound_hwnd),
        }
    }

    fn clear_all_buffers(&mut self) {
        self.accumulator.clear();
        for rec in self.completed.drain(..) {
            zeroize_input_record(rec);
        }
        self.pending_surrogate.clear();
        self.ime_state.reset();
        self.imm32_probe_cache = None;
    }

    fn drain_and_discard_channels(&mut self) {
        if let Some(ref rx) = self.raw_key_rx {
            while rx.try_recv().is_ok() {}
        }
        if let Some(ref rx) = self.text_edit_rx {
            // `SensitiveText` inside discarded `CompositionFinalized` events zeroizes on drop.
            while rx.try_recv().is_ok() {}
        }
        if let Some(ref sub) = self.text_edit_sub {
            let _ = sub.take_dropped_count();
        }
        self.backpressure.store(false, Ordering::Release);
    }

    fn record_gap(&mut self, reason: InputTextGapReason) {
        if self.input_gaps.len() < MAX_INPUT_GAPS {
            self.input_gaps.push(InputTextGapRecord::new(reason));
        }
    }

    fn discard_with_gap(&mut self, reason: InputTextGapReason) {
        self.clear_all_buffers();
        self.accept_after_qpc_ns = qpc_ns_now();
        self.record_gap(reason);
        self.dirty = true;
    }

    fn detach_text_edit_sub(
        &mut self,
        uia: Option<&UiaClient>,
        budget: Option<(i64, &dyn CollectorClock)>,
    ) {
        if let Some(sub) = self.text_edit_sub.take() {
            detach_text_edit_subscription_with_budget(sub, self.retiring, uia, budget);
        }
        self.text_edit_hwnd_raw = 0;
        self.text_edit_rx = None;
    }

    fn attach_text_edit_sub(
        &mut self,
        uia: &UiaClient,
        hwnd: HWND,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        let Some(automation3) = uia.automation3() else {
            return;
        };
        if self.retiring || hwnd.0.is_null() {
            return;
        }
        let hwnd_raw = hwnd.0 as isize;
        if self.text_edit_sub.is_some() && self.text_edit_hwnd_raw == hwnd_raw {
            return;
        }

        self.detach_text_edit_sub(Some(uia), Some((deadline_ms, clock)));
        let deadline = clock.monotonic_ms().saturating_add(60).min(deadline_ms);
        let rem = deadline.saturating_sub(clock.monotonic_ms());
        if rem <= 15 {
            return;
        }
        uia.apply_timeouts(rem);
        let Ok(root) = uia.element_from_hwnd(hwnd) else {
            uia.apply_timeouts(deadline_ms.saturating_sub(clock.monotonic_ms()));
            return;
        };
        let rem_attach = deadline.saturating_sub(clock.monotonic_ms());
        if rem_attach <= 15 {
            uia.apply_timeouts(deadline_ms.saturating_sub(clock.monotonic_ms()));
            return;
        }
        let (tx, rx) = create_text_edit_event_channel();
        uia.apply_timeouts(rem_attach);
        if let Ok(sub) = UiaTextEditEventSubscription::attach(
            uia.automation(),
            automation3,
            &root,
            self.text_edit_gates(),
            tx,
        ) {
            self.text_edit_sub = Some(sub);
            self.text_edit_hwnd_raw = hwnd_raw;
            self.text_edit_rx = Some(rx);
        }
        uia.apply_timeouts(deadline_ms.saturating_sub(clock.monotonic_ms()));
    }

    fn disarm_on_policy_boundary(
        &mut self,
        uia: Option<&UiaClient>,
        budget: Option<(i64, &dyn CollectorClock)>,
    ) {
        // CRITICAL: Never latch `secure_input_detected = true` on a normal Windows password box
        // (`ES_PASSWORD` / `UIA_IsPasswordPropertyId`). Only disarm `context_ready`, purge buffers,
        // and detach the TextEdit subscription so capture resumes cleanly once focus returns to a
        // normal editable field.
        self.context_ready.store(false, Ordering::Release);
        self.bound_hwnd.store(0, Ordering::Release);
        self.bound = None;
        self.clear_all_buffers();
        self.accept_after_qpc_ns = qpc_ns_now();
        self.detach_text_edit_sub(uia, budget);
        self.drain_and_discard_channels();
    }

    /// Synchronize or establish binding on a verified editable focused field after final post-read
    /// revalidation in `read_pipeline.rs`.
    pub(in crate::uia_worker) fn sync_binding(
        &mut self,
        uia: &UiaClient,
        new_bound: BoundInputField,
        changed: bool,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        if self.retiring
            || self.secure_input_detected
            || self.input_failure.is_some()
            || !new_bound.policy.enabled
            || new_bound.policy.input_text != Some(true)
            || new_bound.hwnd.0.is_null()
            || new_bound.focus_runtime_id.is_empty()
            || !new_bound.context.is_valid()
        {
            self.invalidate(Some(uia), Some(deadline_ms), clock);
            return;
        }

        let same_field = !changed
            && self.bound.as_ref().is_some_and(|prev| {
                prev.hwnd == new_bound.hwnd
                    && prev.app == new_bound.app
                    && prev.resolved == new_bound.resolved
                    && prev.focus_runtime_id == new_bound.focus_runtime_id
                    && prev.focus_role == new_bound.focus_role
                    && prev.context == new_bound.context
                    && prev.policy == new_bound.policy
                    && prev.expected_focus_epoch == new_bound.expected_focus_epoch
                    && prev.chrome_verified_normal == new_bound.chrome_verified_normal
            });

        if !same_field {
            self.context_ready.store(false, Ordering::Release);
            self.clear_all_buffers();
            self.input_gaps.clear();
            self.accept_after_qpc_ns = qpc_ns_now();
            self.drain_and_discard_channels();
            self.accumulator = InputTextAccumulator::from_policy(&new_bound.policy);
            if self.text_edit_hwnd_raw != (new_bound.hwnd.0 as isize) {
                self.detach_text_edit_sub(Some(uia), Some((deadline_ms, clock)));
            }
        }

        let hwnd = new_bound.hwnd;
        self.bound = Some(new_bound);
        self.bound_hwnd.store(hwnd.0 as isize, Ordering::Release);
        self.active.store(true, Ordering::Release);
        self.context_ready.store(true, Ordering::Release);

        // Attach (or reuse) bounded TSF `UiaTextEditEventSubscription` on `hwnd`; degrades
        // gracefully to `None` if `IUIAutomation3` or deadline budget is unavailable.
        self.attach_text_edit_sub(uia, hwnd, deadline_ms, clock);
    }

    /// Advance the bound field's `VerifiedNormal` browser chrome timestamp strictly when `hwnd`,
    /// `app`, `resolved`, and `expected_focus_epoch` all match the currently bound field.
    pub(in crate::uia_worker) fn refresh_verified_chrome_proof(
        &mut self,
        hwnd: HWND,
        app: &ApplicationIdentity,
        resolved: &ResolvedAppIdentity,
        focus_epoch: u64,
        chrome_verified_at_mono_ms: i64,
    ) {
        if hwnd.0.is_null() {
            return;
        }
        if let Some(ref mut b) = self.bound {
            if b.hwnd == hwnd
                && b.app == *app
                && b.resolved == *resolved
                && b.expected_focus_epoch == focus_epoch
                && (!b.chrome_verified_normal
                    || chrome_verified_at_mono_ms >= b.chrome_verified_at_mono_ms)
            {
                b.chrome_verified_normal = true;
                b.chrome_verified_at_mono_ms = chrome_verified_at_mono_ms;
            }
        }
    }

    /// Clear binding, zeroize all buffers, disarm `context_ready`, bump QPC fence, and detach
    /// the active `UiaTextEditEventSubscription` within bounded remaining deadline.
    pub fn invalidate(
        &mut self,
        uia: Option<&UiaClient>,
        deadline_ms: Option<i64>,
        clock: &dyn CollectorClock,
    ) {
        self.context_ready.store(false, Ordering::Release);
        self.bound_hwnd.store(0, Ordering::Release);
        self.bound = None;
        self.clear_all_buffers();
        self.input_gaps.clear();
        self.accept_after_qpc_ns = qpc_ns_now();
        let budget = deadline_ms.map(|dl| (dl, clock));
        self.detach_text_edit_sub(uia, budget);
        self.drain_and_discard_channels();
    }

    /// Immediately purge buffers & disarm context on `WinEventWatcher` focus/foreground
    /// invalidation so keystrokes across a focus transition are never misattributed.
    pub fn on_focus_invalidated(&mut self, uia: Option<&UiaClient>, clock: &dyn CollectorClock) {
        if self.bound.is_none()
            && self.accumulator.pending().is_none()
            && self.completed.is_empty()
            && self.text_edit_sub.is_none()
        {
            self.context_ready.store(false, Ordering::Release);
            self.bound_hwnd.store(0, Ordering::Release);
            self.imm32_probe_cache = None;
            self.accept_after_qpc_ns = qpc_ns_now();
            self.drain_and_discard_channels();
            return;
        }
        let deadline = clock.monotonic_ms().saturating_add(40);
        self.invalidate(uia, Some(deadline), clock);
    }

    /// One-way Secure Input suppression for this session worker (only on explicit Secure Input
    /// notices — NEVER triggered by normal Win32 password boxes).
    pub fn suppress_secure_input(
        &mut self,
        uia: Option<&UiaClient>,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        self.secure_input_detected = true;
        self.secure_input_blocked.store(true, Ordering::Release);
        self.active.store(false, Ordering::Release);
        self.invalidate(uia, Some(deadline_ms), clock);
    }

    /// Process-exit safe retirement (`LiveUiaSession::retire_healthy()` and `Drop`): silences
    /// hooks, abandons remote UIA COM TextEdit handlers without blocking, and zeroizes buffers.
    pub fn retire_for_process_exit(&mut self) {
        self.retiring = true;
        self.retiring_flag.store(true, Ordering::Release);
        self.active.store(false, Ordering::Release);
        self.context_ready.store(false, Ordering::Release);
        self.bound_hwnd.store(0, Ordering::Release);
        if let Some(sub) = self.text_edit_sub.take() {
            sub.abandon_for_process_exit();
        }
        self.text_edit_hwnd_raw = 0;
        self.text_edit_rx = None;
        self.raw_key_rx = None;
        self.clear_all_buffers();
        self.bound = None;
        self.input_gaps.clear();
        self.dirty = false;
        self.submit_dirty = false;
    }

    fn drain_merged_events(&mut self) -> (Vec<MergedInputEvent>, bool) {
        let mut overflowed = self.backpressure.swap(false, Ordering::AcqRel);
        if let Some(ref sub) = self.text_edit_sub {
            if sub.take_dropped_count() > 0 {
                overflowed = true;
            }
        }
        if overflowed {
            self.drain_and_discard_channels();
            return (Vec::new(), true);
        }

        let mut merged = Vec::new();
        if let Some(ref rx) = self.text_edit_rx {
            while let Ok(ev) = rx.try_recv() {
                merged.push(MergedInputEvent::TextEdit(ev));
            }
        }
        if let Some(ref rx) = self.raw_key_rx {
            while let Ok(ev) = rx.try_recv() {
                merged.push(MergedInputEvent::KeyHook(ev));
            }
        }
        merged.sort_by_key(|e| (e.qpc_ns(), e.tie_priority()));
        (merged, false)
    }

    /// Poll queued hook & TSF TextEdit events, enforce live safety gates, and flush due buffers.
    pub fn poll(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        hook_healthy: bool,
        clock: &dyn CollectorClock,
    ) {
        if self.retiring || self.secure_input_detected || self.input_failure.is_some() {
            return;
        }
        if self.hook_attempted && !hook_healthy {
            self.mark_input_failure("input-monitoring-disabled");
            let dl = clock.monotonic_ms().saturating_add(40);
            self.detach_text_edit_sub(Some(uia), Some((dl, clock)));
            self.drain_and_discard_channels();
            return;
        }

        let poll_deadline = clock.monotonic_ms().saturating_add(INPUT_POLL_BUDGET_MS);
        self.drain_and_process_queued_events(uia, registry, poll_deadline, clock);

        if self.retiring || self.secure_input_detected || self.input_failure.is_some() {
            return;
        }

        // Auto-expire stale IME composition state after `IME_COMPOSITION_MAX_MS` (5s).
        let now_unix = clock.unix_ms();
        let _ = self.ime_state.refresh_decay(now_unix);
        self.pending_surrogate.expire_if_stale(now_unix);

        // Flush pending buffer if due (500ms debounce or 2000ms max wait), revalidating once.
        let Some((start_ms, end_ms, pending_ctx)) = self
            .accumulator
            .pending()
            .map(|p| (p.interval_start_ms, p.interval_end_ms, p.context.clone()))
        else {
            return;
        };
        if now_unix < end_ms
            || now_unix.saturating_sub(start_ms) > InputTextLimits::MAX_INTERVAL_SPAN_MS
        {
            self.discard_with_gap(InputTextGapReason::Stale);
            return;
        }
        if !self.accumulator.is_due(now_unix) {
            return;
        }

        let Some(bound) = self.bound.clone() else {
            self.discard_with_gap(InputTextGapReason::Stale);
            return;
        };
        let flush_deadline = clock
            .monotonic_ms()
            .saturating_add(INPUT_EVENT_SAFETY_BUDGET_MS)
            .min(poll_deadline);
        let focus_epoch = Arc::clone(&self.focus_epoch);
        let mut refreshed_chrome_mono_ms = None;
        let flush_result = InputTextReadGate::revalidate_buffered_context(
            &pending_ctx,
            &bound.policy,
            qpc_ns_now,
            |req| {
                verify_live_input_safety(
                    uia,
                    registry,
                    &bound,
                    req,
                    &focus_epoch,
                    SafetyPassKind::Full,
                    flush_deadline,
                    clock,
                    Some(&mut refreshed_chrome_mono_ms),
                )
            },
            |_| {},
        );
        if let Some(ts) = refreshed_chrome_mono_ms {
            self.refresh_verified_chrome_proof(
                bound.hwnd,
                &bound.app,
                &bound.resolved,
                bound.expected_focus_epoch,
                ts,
            );
        }
        match flush_result {
            Ok(approved) => {
                if let Some(record) = self.accumulator.take_due(clock.unix_ms(), Some(&approved)) {
                    if !record.is_valid() {
                        zeroize_input_record(record);
                        self.discard_with_gap(InputTextGapReason::ReadError);
                    } else if self.completed.len() >= InputTextLimits::MAX_PENDING {
                        zeroize_input_record(record);
                        self.discard_with_gap(InputTextGapReason::Backpressure);
                    } else {
                        self.completed.push(record);
                        self.dirty = true;
                    }
                }
            }
            Err(reason) => {
                self.discard_with_gap(reason);
                if reason == InputTextGapReason::PolicyBoundary {
                    self.disarm_on_policy_boundary(Some(uia), Some((poll_deadline, clock)));
                }
            }
        }
    }

    fn drain_and_process_queued_events(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        let (events, overflowed) = self.drain_merged_events();
        if overflowed {
            self.discard_with_gap(InputTextGapReason::Backpressure);
            return;
        }
        if events.is_empty() {
            return;
        }

        for event in events {
            if self.retiring || self.secure_input_detected || self.input_failure.is_some() {
                break;
            }
            if event.qpc_ns() <= self.accept_after_qpc_ns {
                continue;
            }
            if !self.context_ready.load(Ordering::Acquire) || self.bound.is_none() {
                continue;
            }
            if clock.monotonic_ms() >= deadline_ms {
                self.discard_with_gap(InputTextGapReason::VerificationTimeout);
                break;
            }
            match event {
                MergedInputEvent::TextEdit(ev) => {
                    self.process_live_text_edit_event(uia, registry, ev, deadline_ms, clock);
                }
                MergedInputEvent::KeyHook(RawKeyHookEvent::BoundaryMismatch { .. }) => {
                    let had_buffered =
                        self.accumulator.pending().is_some() || !self.completed.is_empty();
                    self.disarm_on_policy_boundary(Some(uia), Some((deadline_ms, clock)));
                    if had_buffered {
                        self.record_gap(InputTextGapReason::TargetMismatch);
                        self.dirty = true;
                    }
                }
                MergedInputEvent::KeyHook(RawKeyHookEvent::KeyDown(snap)) => {
                    self.process_live_key_down(uia, registry, snap, deadline_ms, clock);
                }
            }
        }
    }

    fn process_live_text_edit_event(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        ev: RawUiaTextEditEvent,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        let Some(bound) = self.bound.clone() else {
            return;
        };
        let event_deadline = clock
            .monotonic_ms()
            .saturating_add(INPUT_EVENT_SAFETY_BUDGET_MS)
            .min(deadline_ms);
        let focus_epoch = Arc::clone(&self.focus_epoch);
        let after_ns = self.accept_after_qpc_ns;

        let target_pid = resolve_application_identity_for_hwnd(bound.hwnd, None, None)
            .map(|(_, app, _)| app.process_id)
            .unwrap_or(0);

        let mut pre_gate_chrome_verified = false;
        let mut refreshed_chrome_mono_ms = None;
        let policy_boundary = self.handle_text_edit_event_with_safety(
            ev,
            &bound.policy,
            target_pid,
            after_ns,
            qpc_ns_now,
            |req| {
                let pass_kind = select_safety_pass_kind(pre_gate_chrome_verified);
                let res = verify_live_input_safety(
                    uia,
                    registry,
                    &bound,
                    req,
                    &focus_epoch,
                    pass_kind,
                    event_deadline,
                    clock,
                    Some(&mut refreshed_chrome_mono_ms),
                );
                if res.is_ok() {
                    pre_gate_chrome_verified = true;
                }
                res
            },
        );
        if policy_boundary {
            self.disarm_on_policy_boundary(Some(uia), Some((deadline_ms, clock)));
        } else if let Some(ts) = refreshed_chrome_mono_ms {
            self.refresh_verified_chrome_proof(
                bound.hwnd,
                &bound.app,
                &bound.resolved,
                bound.expected_focus_epoch,
                ts,
            );
        }
    }

    fn process_live_key_down(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        snap: RawKeyDownSnapshot,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        let Some(bound) = self.bound.clone() else {
            return;
        };

        if snap.is_repeat {
            return;
        }
        if snap.focus_epoch != bound.expected_focus_epoch
            || snap.fg_hwnd != (bound.hwnd.0 as isize)
        {
            let had_buffered = self.accumulator.pending().is_some() || !self.completed.is_empty();
            self.disarm_on_policy_boundary(Some(uia), Some((deadline_ms, clock)));
            if had_buffered {
                self.record_gap(InputTextGapReason::TargetMismatch);
            }
            // Wake the session worker so a background focus-epoch bump re-establishes binding.
            self.dirty = true;
            return;
        }

        let event_deadline = clock
            .monotonic_ms()
            .saturating_add(INPUT_EVENT_SAFETY_BUDGET_MS)
            .min(deadline_ms);
        let focus_epoch = Arc::clone(&self.focus_epoch);
        let after_ns = self.accept_after_qpc_ns;
        let bound_hwnd = bound.hwnd;
        let tsf_active = self.text_edit_sub.is_some();
        let now_mono_ms = clock.monotonic_ms();
        let target_pid = resolve_application_identity_for_hwnd(
            HWND(snap.fg_hwnd as *mut core::ffi::c_void),
            None,
            None,
        )
        .map(|(_, app, _)| app.process_id)
        .unwrap_or(0);

        let mut pre_gate_chrome_verified = false;
        let mut refreshed_chrome_mono_ms = None;
        let policy_boundary = self.handle_key_down_with_providers(
            snap,
            &bound.policy,
            target_pid,
            after_ns,
            tsf_active,
            now_mono_ms,
            qpc_ns_now,
            |req| {
                let pass_kind = select_safety_pass_kind(pre_gate_chrome_verified);
                let res = verify_live_input_safety(
                    uia,
                    registry,
                    &bound,
                    req,
                    &focus_epoch,
                    pass_kind,
                    event_deadline,
                    clock,
                    Some(&mut refreshed_chrome_mono_ms),
                );
                if res.is_ok() {
                    pre_gate_chrome_verified = true;
                }
                res
            },
            |vk, scan, mod_bits, is_altgr| {
                let layout_hwnd = query_foreground_gui_state(bound_hwnd)
                    .map(|(fh, _, _)| if !fh.0.is_null() { fh } else { bound_hwnd })
                    .unwrap_or(bound_hwnd);
                translate_key_to_unicode(vk, scan, mod_bits, is_altgr, layout_hwnd)
            },
            || {
                let layout_hwnd = query_foreground_gui_state(bound_hwnd)
                    .map(|(fh, _, _)| if !fh.0.is_null() { fh } else { bound_hwnd })
                    .unwrap_or(bound_hwnd);
                query_imm32_native_ime_active_bounded(layout_hwnd)
            },
        );
        if policy_boundary {
            self.disarm_on_policy_boundary(Some(uia), Some((deadline_ms, clock)));
        } else if let Some(ts) = refreshed_chrome_mono_ms {
            self.refresh_verified_chrome_proof(
                bound.hwnd,
                &bound.app,
                &bound.resolved,
                bound.expected_focus_epoch,
                ts,
            );
        }
    }

    /// Pure/injectable TextEdit event handler used by both live `poll()` and deterministic tests.
    /// Returns `true` when `InputTextGapReason::PolicyBoundary` occurred so live callers disarm.
    fn handle_text_edit_event_with_safety<Now, Safety>(
        &mut self,
        ev: RawUiaTextEditEvent,
        policy: &CapturePolicy,
        target_pid: u32,
        after_ns: u64,
        now_ns: Now,
        safety_provider: Safety,
    ) -> bool
    where
        Now: Fn() -> u64,
        Safety: FnMut(InputTextSafetyRequest<'_>) -> Result<InputTextApprovedContext, InputTextGapReason>,
    {
        match ev.kind {
            UiaTextEditEventKind::Composition => {
                // Purge any raw Latin pinyin prefix buffered within `IME_PREFIX_PURGE_WINDOW_MS`
                // while preserving already-finalized IME commits; mark composition active.
                let _ = self
                    .ime_state
                    .on_composition_start(ev.observed_unix_ms, &mut self.accumulator);
                self.ime_last_composition_qpc_ns = ev.observed_qpc_ns;
                self.pending_surrogate.clear();
                false
            }
            UiaTextEditEventKind::CompositionFinalized { text, saturated } => {
                self.pending_surrogate.clear();
                if saturated {
                    drop(text);
                    self.ime_state.reset();
                    self.discard_with_gap(InputTextGapReason::Budget);
                    return false;
                }

                let metadata = InputTextEventMetadata {
                    target_process_id: target_pid,
                    timestamp_ns: ev.observed_qpc_ns,
                    callback_time_ms: ev.observed_unix_ms,
                };
                // Hold `SensitiveText` inside an Option so if Pre-Gate fails, `read_committed`
                // never runs and `SensitiveText::drop` zeroizes the UTF-8 buffer automatically.
                let mut sensitive_opt = Some(text);
                let decision = self.ime_state.on_composition_finalized(
                    metadata,
                    policy,
                    after_ns,
                    now_ns,
                    safety_provider,
                    || {
                        let committed = sensitive_opt
                            .take()
                            .map(SensitiveText::into_inner)
                            .unwrap_or_default();
                        InputTextUnicodeRead::Text(committed)
                    },
                    |_| {},
                );
                match decision {
                    InputTextCaptureDecision::Sample(sample) => {
                        match self.accumulator.ingest_into_completed(
                            &mut self.completed,
                            *sample,
                            InputTextSource::Win32Unicode,
                        ) {
                            Ok(_) => {
                                self.dirty = true;
                                false
                            }
                            Err(reason) => {
                                self.discard_with_gap(reason);
                                reason == InputTextGapReason::PolicyBoundary
                            }
                        }
                    }
                    InputTextCaptureDecision::Ignored => false,
                    InputTextCaptureDecision::Gap(reason) => {
                        self.discard_with_gap(reason);
                        reason == InputTextGapReason::PolicyBoundary
                    }
                }
            }
        }
    }

    fn is_legacy_imm32_native_active<Probe>(
        &mut self,
        hwnd: isize,
        focus_epoch: u64,
        now_mono_ms: i64,
        probe: Probe,
    ) -> bool
    where
        Probe: FnOnce() -> Option<bool>,
    {
        if let Some(entry) = self.imm32_probe_cache {
            if entry.hwnd == hwnd
                && entry.focus_epoch == focus_epoch
                && now_mono_ms >= entry.checked_mono_ms
                && now_mono_ms.saturating_sub(entry.checked_mono_ms) < IMM32_PROBE_CACHE_TTL_MS
            {
                return entry.active;
            }
        }
        let active = probe().unwrap_or(false);
        self.imm32_probe_cache = Some(Imm32ProbeCacheEntry {
            hwnd,
            focus_epoch,
            checked_mono_ms: now_mono_ms,
            active,
        });
        active
    }

    /// Pure/injectable key-down handler used by both live `poll()` and deterministic unit tests.
    /// Returns `true` when `InputTextGapReason::PolicyBoundary` occurred so live callers disarm.
    #[allow(clippy::too_many_arguments)]
    fn handle_key_down_with_providers<Now, Safety, Translate, Imm32Probe>(
        &mut self,
        snap: RawKeyDownSnapshot,
        policy: &CapturePolicy,
        target_pid: u32,
        after_ns: u64,
        tsf_active: bool,
        now_mono_ms: i64,
        now_ns: Now,
        safety_provider: Safety,
        translate_key: Translate,
        probe_imm32_native: Imm32Probe,
    ) -> bool
    where
        Now: Fn() -> u64,
        Safety: FnMut(InputTextSafetyRequest<'_>) -> Result<InputTextApprovedContext, InputTextGapReason>,
        Translate: FnOnce(u32, u32, u16, bool) -> InputTextUnicodeRead,
        Imm32Probe: FnOnce() -> Option<bool>,
    {
        if snap.is_repeat {
            return false;
        }
        if is_imm32_toggle_vk(snap.vk_code) {
            self.imm32_probe_cache = None;
        }
        if snap.vk_code == VK_PROCESSKEY_CODE {
            self.imm32_probe_cache = None;
            let _ = self
                .ime_state
                .on_composition_start(snap.unix_ms, &mut self.accumulator);
            self.ime_last_composition_qpc_ns = snap.qpc_ns;
            self.pending_surrogate.clear();
            return false;
        }
        if is_modifier_only_vk(snap.vk_code) {
            return false;
        }

        let norm = mod_bits_to_windows_modifiers(snap.mod_bits).normalize();
        if norm.is_shortcut {
            self.imm32_probe_cache = None;
        }

        // While TSF/IMM32 CJK IME composition is active, suppress raw Latin/candidate keystrokes
        // and `VK_RETURN` (so confirming a pinyin candidate never fires `submit_dirty` / `Return`).
        // `VK_ESCAPE` cancels composition cleanly; shortcuts and `VK_PACKET` pass through.
        if self.ime_state.should_suppress_raw_key(snap.unix_ms)
            && !norm.is_shortcut
            && snap.vk_code != VK_PACKET_CODE
        {
            if snap.vk_code == VK_ESCAPE_CODE {
                self.ime_state.reset();
                self.pending_surrogate.clear();
            }
            return false;
        }

        // Legacy non-TSF IMM32 fallback: when UIA `TextEdit` events are unavailable (`!tsf_active`),
        // probe bounded IMM32 native CJK conversion mode (cached <= 250ms and invalidated on
        // focus/context/toggle keys). Suppress raw ASCII letters (`A-Z`) and `VK_RETURN` while
        // native CJK mode is active so raw pinyin never leaks and Enter confirmation never fires a
        // spurious `Return` / `submitDirty` (committed text is captured by `text.snapshot`).
        if !tsf_active
            && !norm.is_shortcut
            && snap.vk_code != VK_PACKET_CODE
            && is_imm32_suppressed_vk(snap.vk_code)
            && self.is_legacy_imm32_native_active(
                snap.fg_hwnd,
                snap.focus_epoch,
                now_mono_ms,
                probe_imm32_native,
            )
        {
            return false;
        }

        let metadata = InputTextEventMetadata {
            target_process_id: target_pid,
            timestamp_ns: snap.qpc_ns,
            callback_time_ms: snap.unix_ms,
        };
        let is_packet = snap.vk_code == VK_PACKET_CODE;
        let is_altgr = norm.is_altgr;
        let pending_surrogate = &mut self.pending_surrogate;

        let step = InputTextReadGate::capture_with_accumulator(
            metadata,
            &norm.modifiers,
            InputTextSource::Win32Unicode,
            policy,
            after_ns,
            &mut self.accumulator,
            &mut self.completed,
            now_ns,
            safety_provider,
            || {
                if is_packet {
                    translate_vk_packet(snap.scan_code, snap.unix_ms, pending_surrogate)
                } else {
                    pending_surrogate.clear();
                    translate_key(snap.vk_code, snap.scan_code, snap.mod_bits, is_altgr)
                }
            },
            |_| {},
        );

        match step {
            InputTextCaptureStep::Buffered => {
                if !self.completed.is_empty() {
                    self.dirty = true;
                }
                false
            }
            InputTextCaptureStep::SealedReturn => {
                self.submit_dirty = true;
                self.dirty = true;
                false
            }
            InputTextCaptureStep::Ignored => {
                if !is_packet {
                    self.pending_surrogate.clear();
                }
                false
            }
            InputTextCaptureStep::Gap(reason) => {
                self.pending_surrogate.clear();
                self.ime_state.reset();
                self.accept_after_qpc_ns = qpc_ns_now();
                self.record_gap(reason);
                self.dirty = true;
                reason == InputTextGapReason::PolicyBoundary
            }
        }
    }

    /// Causal read-barrier drain called from `read_pipeline.rs` AFTER final post-read boundary &
    /// focus revalidation and BEFORE committing `pending_surface`.
    ///
    /// First performs a bounded drain of any already-queued hook / TSF TextEdit events prior to
    /// the barrier, then seals and revalidates buffered records via
    /// [`InputTextReadGate::drain_at_barrier`] within `remaining_budget_units` and `deadline_ms`.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::uia_worker) fn drain_at_barrier(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        policy: &CapturePolicy,
        remaining_budget_units: usize,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) -> (Vec<InputTextRecord>, Vec<InputTextGapRecord>) {
        if self.retiring || self.secure_input_detected || self.input_failure.is_some() {
            self.clear_all_buffers();
            self.input_gaps.clear();
            return (Vec::new(), Vec::new());
        }

        // 1. Bounded drain of already-queued events strictly prior to the snapshot barrier.
        if clock.monotonic_ms() < deadline_ms {
            let drain_events_deadline = clock
                .monotonic_ms()
                .saturating_add(INPUT_EVENT_SAFETY_BUDGET_MS)
                .min(deadline_ms);
            self.drain_and_process_queued_events(uia, registry, drain_events_deadline, clock);
        }

        // 2. Seal & revalidate any pending/completed records at the barrier.
        let records = if self.completed.is_empty() && self.accumulator.pending().is_none() {
            Vec::new()
        } else if let Some(bound) = self.bound.clone() {
            let focus_epoch = Arc::clone(&self.focus_epoch);
            let mut refreshed_chrome_mono_ms = None;
            let barrier_result = InputTextReadGate::drain_at_barrier(
                &mut self.completed,
                &mut self.accumulator,
                clock.unix_ms(),
                policy,
                remaining_budget_units,
                qpc_ns_now,
                |req| {
                    verify_live_input_safety(
                        uia,
                        registry,
                        &bound,
                        req,
                        &focus_epoch,
                        SafetyPassKind::Full,
                        deadline_ms,
                        clock,
                        Some(&mut refreshed_chrome_mono_ms),
                    )
                },
                |_| {},
            );
            if let Some(ts) = refreshed_chrome_mono_ms {
                self.refresh_verified_chrome_proof(
                    bound.hwnd,
                    &bound.app,
                    &bound.resolved,
                    bound.expected_focus_epoch,
                    ts,
                );
            }
            match barrier_result {
                Ok(drained) => drained,
                Err(reason) => {
                    self.record_gap(reason);
                    if reason == InputTextGapReason::PolicyBoundary {
                        self.disarm_on_policy_boundary(Some(uia), Some((deadline_ms, clock)));
                    } else {
                        self.accept_after_qpc_ns = qpc_ns_now();
                    }
                    Vec::new()
                }
            }
        } else {
            self.clear_all_buffers();
            Vec::new()
        };

        let gaps = std::mem::take(&mut self.input_gaps);
        (records, gaps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;

    use crate::input_text_core::{
        InputTextFieldRole, InputTextKind, InputTextModifier, InputTextPrivateState,
        InputTextSample,
    };
    use crate::protocol_model::{SecureStatus, TargetIdentity};
    use crate::uia_worker::input_hook::{
        MOD_BIT_CAPS_LOCK, MOD_BIT_LCONTROL, MOD_BIT_LLKHF_ALTDOWN, MOD_BIT_LMENU, MOD_BIT_LSHIFT,
        MOD_BIT_LWIN, MOD_BIT_RCONTROL, MOD_BIT_RMENU, MOD_BIT_RSHIFT, MOD_BIT_RWIN,
    };

    const BASE_QPC: u64 = 10_000_000_000;
    const BASE_UNIX: i64 = 1_700_000_000_000;

    fn test_policy() -> CapturePolicy {
        CapturePolicy {
            enabled: true,
            application_scope: Some("denylist".to_string()),
            input_text: Some(true),
            max_text_code_units: 2_048,
            ..CapturePolicy::default()
        }
    }

    fn test_context() -> crate::input_text_core::InputTextContext {
        crate::input_text_core::InputTextContext {
            target: TargetIdentity {
                device_id: "win-dev".to_string(),
                os_session_id: "wts-1".to_string(),
                desktop_id: "winsta0-default-wts-1".to_string(),
                process_id: 4242,
                process_start_time: "unix-ms:1700000000000.000".to_string(),
                application_id: "notepad.exe".to_string(),
                window_id: "win-1".to_string(),
                window_generation: 1,
            },
            surface_id: "surf-1".to_string(),
            capture_epoch: 1,
            foreground_generation: 1,
            focus_generation: 1,
            policy_revision: 1,
            field_security_mode: "strict".to_string(),
            secure_status: SecureStatus::Safe,
            private_state: InputTextPrivateState::Normal,
            exe_name: Some("notepad.exe".to_string()),
        }
    }

    fn make_key(vk_code: u32, scan_code: u32, mod_bits: u16, qpc_ns: u64, unix_ms: i64) -> RawKeyDownSnapshot {
        RawKeyDownSnapshot {
            vk_code,
            scan_code,
            flags: 0,
            is_sys_key: false,
            is_repeat: false,
            qpc_ns,
            unix_ms,
            fg_hwnd: 0x1000,
            focus_epoch: 1,
            mod_bits,
        }
    }

    #[test]
    fn mod_bits_mapping_handles_altgr_altdown_fallback_win_shift_and_capslock() {
        // AltGr (LCtrl + RAlt + LLKHF_ALTDOWN): RMENU is set so left_alt stays false -> is_altgr!
        let altgr = mod_bits_to_windows_modifiers(
            MOD_BIT_LCONTROL | MOD_BIT_RMENU | MOD_BIT_LLKHF_ALTDOWN | MOD_BIT_CAPS_LOCK,
        );
        assert!(altgr.is_altgr());
        assert!(!altgr.left_alt);
        assert!(altgr.right_alt);
        let norm = altgr.normalize();
        assert!(norm.is_altgr);
        assert!(!norm.is_shortcut);
        assert!(norm.modifiers.is_empty());

        // LLKHF_ALTDOWN fallback when neither LMENU nor RMENU bit was set -> left_alt = true.
        let fallback_alt = mod_bits_to_windows_modifiers(MOD_BIT_LLKHF_ALTDOWN);
        assert!(fallback_alt.left_alt);
        assert!(!fallback_alt.right_alt);
        assert!(!fallback_alt.is_altgr());
        assert_eq!(fallback_alt.normalize().modifiers, vec![InputTextModifier::Option]);

        // Win + Shift + RCtrl -> shortcut with canonical order [Command, Control, Shift].
        let combo = mod_bits_to_windows_modifiers(MOD_BIT_LWIN | MOD_BIT_RSHIFT | MOD_BIT_RCONTROL);
        let norm_combo = combo.normalize();
        assert!(!norm_combo.is_altgr);
        assert!(norm_combo.is_shortcut);
        assert_eq!(
            norm_combo.modifiers,
            vec![
                InputTextModifier::Command,
                InputTextModifier::Control,
                InputTextModifier::Shift,
            ]
        );

        // LCtrl + LAlt -> shortcut (NOT AltGr).
        let ctrl_lalt = mod_bits_to_windows_modifiers(MOD_BIT_LCONTROL | MOD_BIT_LMENU);
        assert!(!ctrl_lalt.is_altgr());
        assert!(ctrl_lalt.normalize().is_shortcut);
        assert!(mod_bits_to_windows_modifiers(MOD_BIT_RWIN).right_win);
        assert!(mod_bits_to_windows_modifiers(MOD_BIT_LSHIFT).left_shift);
    }

    #[test]
    fn build_minimal_key_state_excludes_raw_ctrl_and_win_unless_altgr() {
        use windows::Win32::UI::Input::KeyboardAndMouse::{
            VK_CAPITAL, VK_CONTROL, VK_LCONTROL, VK_LMENU, VK_LSHIFT, VK_LWIN, VK_MENU,
            VK_RCONTROL, VK_RMENU, VK_RSHIFT, VK_RWIN, VK_SHIFT,
        };

        // Raw Ctrl + Win + LAlt + LShift + CapsLock with is_altgr = false:
        // ONLY Shift & CapsLock may appear; Ctrl/Win/Alt MUST be 0!
        let st = build_minimal_key_state(
            MOD_BIT_LSHIFT
                | MOD_BIT_LCONTROL
                | MOD_BIT_RCONTROL
                | MOD_BIT_LMENU
                | MOD_BIT_LWIN
                | MOD_BIT_RWIN
                | MOD_BIT_CAPS_LOCK,
            false,
        );
        assert_eq!(st[usize::from(VK_SHIFT.0)], 0x80);
        assert_eq!(st[usize::from(VK_LSHIFT.0)], 0x80);
        assert_eq!(st[usize::from(VK_RSHIFT.0)], 0);
        assert_eq!(st[usize::from(VK_CAPITAL.0)], 0x01);
        assert_eq!(st[usize::from(VK_CONTROL.0)], 0);
        assert_eq!(st[usize::from(VK_LCONTROL.0)], 0);
        assert_eq!(st[usize::from(VK_RCONTROL.0)], 0);
        assert_eq!(st[usize::from(VK_MENU.0)], 0);
        assert_eq!(st[usize::from(VK_LMENU.0)], 0);
        assert_eq!(st[usize::from(VK_RMENU.0)], 0);
        assert_eq!(st[usize::from(VK_LWIN.0)], 0);
        assert_eq!(st[usize::from(VK_RWIN.0)], 0);

        // AltGr = true + RShift: sets Shift + LCtrl + RAlt (never RCtrl/LAlt/Win).
        let altgr_st = build_minimal_key_state(
            MOD_BIT_RSHIFT | MOD_BIT_LCONTROL | MOD_BIT_RMENU | MOD_BIT_LWIN,
            true,
        );
        assert_eq!(altgr_st[usize::from(VK_SHIFT.0)], 0x80);
        assert_eq!(altgr_st[usize::from(VK_RSHIFT.0)], 0x80);
        assert_eq!(altgr_st[usize::from(VK_CONTROL.0)], 0x80);
        assert_eq!(altgr_st[usize::from(VK_LCONTROL.0)], 0x80);
        assert_eq!(altgr_st[usize::from(VK_MENU.0)], 0x80);
        assert_eq!(altgr_st[usize::from(VK_RMENU.0)], 0x80);
        assert_eq!(altgr_st[usize::from(VK_RCONTROL.0)], 0);
        assert_eq!(altgr_st[usize::from(VK_LMENU.0)], 0);
        assert_eq!(altgr_st[usize::from(VK_LWIN.0)], 0);
        assert_eq!(altgr_st[usize::from(VK_RWIN.0)], 0);
    }

    #[test]
    fn ime_composition_purges_prefix_suppresses_return_admits_commit_and_expires_after_5s() {
        let mut session = InputTextSession::new(Arc::new(AtomicU64::new(1)));
        let policy = test_policy();
        let ctx = test_context();

        // 1. User types raw pinyin prefix "ni" before TSF fires Composition.
        for (i, ch) in ['n', 'i'].into_iter().enumerate() {
            let qpc = BASE_QPC + (i as u64 + 1) * 10_000_000;
            let unix = BASE_UNIX + (i as i64 + 1) * 10;
            let snap = make_key(u32::from(ch.to_ascii_uppercase() as u8), 0, 0, qpc, unix);
            let pb = session.handle_key_down_with_providers(
                snap,
                &policy,
                4242,
                BASE_QPC,
                true,
                1_000,
                || qpc,
                |_| {
                    Ok(InputTextApprovedContext {
                        context: ctx.clone(),
                        metadata_monotonic_ns: qpc,
                        role: InputTextFieldRole::TextArea,
                    })
                },
                |_, _, _, _| InputTextUnicodeRead::Text(ch.to_string()),
                || unreachable!("TSF-active control must not invoke legacy IMM32 probe"),
            );
            assert!(!pb);
        }
        assert_eq!(
            session.accumulator.pending().map(|p| p.text.as_str()),
            Some("ni")
        );

        // 2. TSF fires `Composition` within 500ms -> purges raw Latin prefix "ni" and arms IME!
        let comp_qpc = BASE_QPC + 30_000_000;
        let comp_unix = BASE_UNIX + 30;
        let pb = session.handle_text_edit_event_with_safety(
            RawUiaTextEditEvent {
                kind: UiaTextEditEventKind::Composition,
                sender: None,
                observed_qpc_ns: comp_qpc,
                observed_mono_ms: 1_030,
                observed_unix_ms: comp_unix,
            },
            &policy,
            4242,
            BASE_QPC,
            || comp_qpc,
            |_| unreachable!("Composition must not invoke safety/read"),
        );
        assert!(!pb);
        assert!(session.accumulator.pending().is_none());
        assert_eq!(session.ime_last_composition_qpc_ns(), comp_qpc);

        // 3. `VK_RETURN` during active IME composition MUST be suppressed (NO submit_dirty, NO translate)!
        let translate_called = Cell::new(false);
        let ret_qpc = BASE_QPC + 40_000_000;
        let ret_unix = BASE_UNIX + 40;
        session.handle_key_down_with_providers(
            make_key(VK_RETURN_CODE, 0x1C, 0, ret_qpc, ret_unix),
            &policy,
            4242,
            BASE_QPC,
            true,
            1_040,
            || ret_qpc,
            |_| unreachable!("suppressed IME Return must not call safety"),
            |_, _, _, _| {
                translate_called.set(true);
                InputTextUnicodeRead::Text("\r".to_string())
            },
            || unreachable!("TSF-active control must not invoke legacy IMM32 probe"),
        );
        assert!(!translate_called.get());
        assert!(!session.take_submit_dirty());
        assert!(session.completed.is_empty());

        // 4. `CompositionFinalized("你好")` runs Pre-Gate (Full) -> Read -> Post-Gate (PostReadFast)
        // and emits IME commit.
        let fin_qpc = BASE_QPC + 60_000_000;
        let fin_unix = BASE_UNIX + 60;
        let mut observed_passes = Vec::new();
        let mut pre_gate_verified = false;
        let pb = session.handle_text_edit_event_with_safety(
            RawUiaTextEditEvent {
                kind: UiaTextEditEventKind::CompositionFinalized {
                    text: SensitiveText::new("你好".to_string()),
                    saturated: false,
                },
                sender: None,
                observed_qpc_ns: fin_qpc,
                observed_mono_ms: 1_060,
                observed_unix_ms: fin_unix,
            },
            &policy,
            4242,
            BASE_QPC,
            || fin_qpc,
            |_| {
                let pass = select_safety_pass_kind(pre_gate_verified);
                observed_passes.push(pass);
                pre_gate_verified = true;
                Ok(InputTextApprovedContext {
                    context: ctx.clone(),
                    metadata_monotonic_ns: fin_qpc,
                    role: InputTextFieldRole::TextArea,
                })
            },
        );
        assert!(!pb);
        assert_eq!(
            observed_passes,
            vec![SafetyPassKind::Full, SafetyPassKind::PostReadFast],
            "IME commit must run Full on Pre-Gate and PostReadFast on Post-Gate"
        );
        let pending = session.accumulator.pending().expect("IME commit buffered");
        assert_eq!(pending.text, "你好");
        assert!(pending
            .extra_coverage_reasons
            .iter()
            .any(|r| r == "ime-composition-commit"));

        // 5. After CompositionFinalized, `VK_RETURN` is NO LONGER suppressed -> seals "你好" + Return
        // and sets `submit_dirty = true`!
        let submit_qpc = BASE_QPC + 80_000_000;
        let submit_unix = BASE_UNIX + 80;
        session.handle_key_down_with_providers(
            make_key(VK_RETURN_CODE, 0x1C, 0, submit_qpc, submit_unix),
            &policy,
            4242,
            BASE_QPC,
            true,
            1_080,
            || submit_qpc,
            |_| {
                Ok(InputTextApprovedContext {
                    context: ctx.clone(),
                    metadata_monotonic_ns: submit_qpc,
                    role: InputTextFieldRole::TextArea,
                })
            },
            |_, _, _, _| InputTextUnicodeRead::Text("\r".to_string()),
            || unreachable!("TSF-active control must not invoke legacy IMM32 probe"),
        );
        assert!(session.take_submit_dirty());
        assert!(session.take_dirty());
        assert_eq!(session.completed.len(), 2);
        assert_eq!(session.completed[0].event_kind, InputTextKind::Text);
        assert_eq!(session.completed[0].text, "你好");
        assert_eq!(session.completed[1].event_kind, InputTextKind::Return);

        // 6. `VK_PROCESSKEY` arms IME composition without calling translate, and expires after
        // `IME_COMPOSITION_MAX_MS` (5000ms)!
        let proc_qpc = BASE_QPC + 100_000_000;
        let proc_unix = BASE_UNIX + 100;
        session.handle_key_down_with_providers(
            make_key(VK_PROCESSKEY_CODE, 0, 0, proc_qpc, proc_unix),
            &policy,
            4242,
            BASE_QPC,
            true,
            1_100,
            || proc_qpc,
            |_| unreachable!("VK_PROCESSKEY must not invoke safety"),
            |_, _, _, _| unreachable!("VK_PROCESSKEY must NEVER invoke ToUnicodeEx"),
            || unreachable!("VK_PROCESSKEY must not invoke IMM32 probe"),
        );
        assert!(session.ime_state.is_composing(proc_unix + 100));
        // After 5001ms, composition expires cleanly so normal keystroke captures again!
        let after_expiry_unix = proc_unix + InputTextLimits::IME_COMPOSITION_MAX_MS + 1;
        let after_expiry_qpc = proc_qpc + 5_001_000_000;
        session.completed.clear();
        session.handle_key_down_with_providers(
            make_key(0x41, 0x1E, 0, after_expiry_qpc, after_expiry_unix),
            &policy,
            4242,
            BASE_QPC,
            true,
            6_101,
            || after_expiry_qpc,
            |_| {
                Ok(InputTextApprovedContext {
                    context: ctx.clone(),
                    metadata_monotonic_ns: after_expiry_qpc,
                    role: InputTextFieldRole::TextArea,
                })
            },
            |_, _, _, _| InputTextUnicodeRead::Text("a".to_string()),
            || unreachable!("TSF-active control must not invoke legacy IMM32 probe"),
        );
        assert_eq!(
            session.accumulator.pending().map(|p| p.text.as_str()),
            Some("a")
        );

        // 7. Saturated `CompositionFinalized` purges buffers and emits Budget gap.
        let sat_qpc = after_expiry_qpc + 10_000_000;
        let sat_unix = after_expiry_unix + 10;
        session.handle_text_edit_event_with_safety(
            RawUiaTextEditEvent {
                kind: UiaTextEditEventKind::CompositionFinalized {
                    text: SensitiveText::empty(),
                    saturated: true,
                },
                sender: None,
                observed_qpc_ns: sat_qpc,
                observed_mono_ms: 6_110,
                observed_unix_ms: sat_unix,
            },
            &policy,
            4242,
            BASE_QPC,
            || sat_qpc,
            |_| unreachable!("saturated event fails closed directly with Budget"),
        );
        assert!(session.accumulator.pending().is_none());
        assert_eq!(session.input_gaps.len(), 1);
        assert_eq!(session.input_gaps[0].reason, InputTextGapReason::Budget);
    }

    #[test]
    fn legacy_non_tsf_imm32_native_mode_suppresses_pinyin_and_return_while_english_passes_through() {
        use windows::Win32::UI::Input::KeyboardAndMouse::VK_LSHIFT;

        let mut session = InputTextSession::new(Arc::new(AtomicU64::new(1)));
        let policy = test_policy();
        let ctx = test_context();

        // 1. Legacy non-TSF control (`tsf_active = false`) in native CJK IME mode (`Some(true)`):
        // ASCII letters (`n`, `i`) and `VK_RETURN` are suppressed without calling `ToUnicodeEx`
        // or setting `submit_dirty`, and the 250ms cache ensures only ONE IMM32 probe runs!
        let probe_calls = Cell::new(0usize);
        for (i, vk) in [0x4Eu32, 0x49u32, VK_RETURN_CODE].into_iter().enumerate() {
            let qpc = BASE_QPC + (i as u64 + 1) * 10_000_000;
            let unix = BASE_UNIX + (i as i64 + 1) * 10;
            let mono = 1_000 + (i as i64) * 20;
            let pb = session.handle_key_down_with_providers(
                make_key(vk, 0, 0, qpc, unix),
                &policy,
                4242,
                BASE_QPC,
                false,
                mono,
                || qpc,
                |_| unreachable!("suppressed legacy IMM32 key must not run safety"),
                |_, _, _, _| unreachable!("suppressed legacy IMM32 key must not run ToUnicodeEx"),
                || {
                    probe_calls.set(probe_calls.get() + 1);
                    Some(true)
                },
            );
            assert!(!pb);
        }
        assert_eq!(probe_calls.get(), 1, "250ms cache must reuse first probe");
        assert!(session.accumulator.pending().is_none());
        assert!(session.completed.is_empty());
        assert!(!session.take_submit_dirty());

        // 2. Pressing `VK_LSHIFT` (IME Chinese<->English toggle) immediately clears the 250ms
        // cache even before 250ms elapses, so switching to English mode (`Some(false)`) lets
        // normal letters & Return pass through 100%!
        let shift_qpc = BASE_QPC + 40_000_000;
        let shift_unix = BASE_UNIX + 40;
        session.handle_key_down_with_providers(
            make_key(u32::from(VK_LSHIFT.0), 0x2A, MOD_BIT_LSHIFT, shift_qpc, shift_unix),
            &policy,
            4242,
            BASE_QPC,
            false,
            1_050,
            || shift_qpc,
            |_| unreachable!("modifier-only VK_LSHIFT must not call safety"),
            |_, _, _, _| unreachable!("modifier-only VK_LSHIFT must not translate"),
            || unreachable!("modifier-only VK_LSHIFT clears cache without probing"),
        );
        assert!(session.imm32_probe_cache.is_none());

        let mut key_safety_passes = Vec::new();
        let mut pre_gate_ok = false;
        let eng_qpc = BASE_QPC + 50_000_000;
        let eng_unix = BASE_UNIX + 50;
        session.handle_key_down_with_providers(
            make_key(0x41, 0x1E, 0, eng_qpc, eng_unix),
            &policy,
            4242,
            BASE_QPC,
            false,
            1_060,
            || eng_qpc,
            |_| {
                let pass = select_safety_pass_kind(pre_gate_ok);
                key_safety_passes.push(pass);
                pre_gate_ok = true;
                Ok(InputTextApprovedContext {
                    context: ctx.clone(),
                    metadata_monotonic_ns: eng_qpc,
                    role: InputTextFieldRole::TextField,
                })
            },
            |_, _, _, _| InputTextUnicodeRead::Text("a".to_string()),
            || {
                probe_calls.set(probe_calls.get() + 1);
                Some(false)
            },
        );
        assert_eq!(probe_calls.get(), 2, "VK_LSHIFT toggle must force fresh IMM32 probe");
        assert_eq!(
            key_safety_passes,
            vec![SafetyPassKind::Full, SafetyPassKind::PostReadFast],
            "same-keystroke Post-Gate must use PostReadFast after Pre-Gate Full succeeds"
        );
        assert_eq!(
            session.accumulator.pending().map(|p| p.text.as_str()),
            Some("a")
        );

        // Return in English mode (`Some(false)` cached within 250ms) seals text + Return and sets
        // `submit_dirty = true` without re-probing!
        let ret_qpc = BASE_QPC + 60_000_000;
        let ret_unix = BASE_UNIX + 60;
        session.handle_key_down_with_providers(
            make_key(VK_RETURN_CODE, 0x1C, 0, ret_qpc, ret_unix),
            &policy,
            4242,
            BASE_QPC,
            false,
            1_080,
            || ret_qpc,
            |_| {
                Ok(InputTextApprovedContext {
                    context: ctx.clone(),
                    metadata_monotonic_ns: ret_qpc,
                    role: InputTextFieldRole::TextField,
                })
            },
            |_, _, _, _| InputTextUnicodeRead::Text("\r".to_string()),
            || unreachable!("within 250ms TTL, cached English state must not re-probe"),
        );
        assert!(session.take_submit_dirty());
        assert_eq!(session.completed.len(), 2);
        assert_eq!(session.completed[0].text, "a");
        assert_eq!(session.completed[1].event_kind, InputTextKind::Return);

        // 3. After 250ms TTL expires (or `VK_KANJI` / `VK_HANGUL` / `VK_SPACE` toggle), cache
        // expires cleanly and re-probes; switching back to `Some(true)` suppresses again.
        let expired_qpc = BASE_QPC + 400_000_000;
        let expired_unix = BASE_UNIX + 400;
        session.completed.clear();
        session.handle_key_down_with_providers(
            make_key(0x42, 0x30, 0, expired_qpc, expired_unix),
            &policy,
            4242,
            BASE_QPC,
            false,
            1_060 + IMM32_PROBE_CACHE_TTL_MS,
            || expired_qpc,
            |_| unreachable!("re-probed native mode must suppress ASCII letter"),
            |_, _, _, _| unreachable!("re-probed native mode must not run ToUnicodeEx"),
            || {
                probe_calls.set(probe_calls.get() + 1);
                Some(true)
            },
        );
        assert_eq!(probe_calls.get(), 3, "TTL expiry must trigger fresh probe");
        assert!(session.accumulator.pending().is_none());

        // 4. `VK_KANJI` (0x19), `VK_HANGUL`/`VK_KANA` (0x15), and `VK_SPACE` (0x20) are all
        // recognized as IMM32 toggle keys; null HWND native probe returns `None` without blocking.
        assert!(is_imm32_toggle_vk(0x15));
        assert!(is_imm32_toggle_vk(0x19));
        assert!(is_imm32_toggle_vk(0x20));
        assert!(is_imm32_suppressed_vk(0x41));
        assert!(is_imm32_suppressed_vk(0x5A));
        assert!(is_imm32_suppressed_vk(VK_RETURN_CODE));
        assert!(!is_imm32_suppressed_vk(0x20));
        assert_eq!(query_imm32_native_ime_active_bounded(HWND::default()), None);
    }

    #[test]
    fn vk_packet_surrogate_assembly_and_policy_boundary_non_latching() {
        let mut session = InputTextSession::new(Arc::new(AtomicU64::new(1)));
        let policy = test_policy();
        let ctx = test_context();

        // 1. High surrogate (0xD83D) followed by low surrogate (0xDE00) -> "😀".
        let q1 = BASE_QPC + 10_000_000;
        let u1 = BASE_UNIX + 10;
        session.handle_key_down_with_providers(
            make_key(VK_PACKET_CODE, 0xD83D, 0, q1, u1),
            &policy,
            4242,
            BASE_QPC,
            false,
            1_010,
            || q1,
            |_| {
                Ok(InputTextApprovedContext {
                    context: ctx.clone(),
                    metadata_monotonic_ns: q1,
                    role: InputTextFieldRole::TextField,
                })
            },
            |_, _, _, _| unreachable!("VK_PACKET must not invoke ToUnicodeEx"),
            || unreachable!("VK_PACKET must bypass legacy IMM32 probe"),
        );
        assert!(session.accumulator.pending().is_none());
        assert!(session.pending_surrogate.has_pending());

        let q2 = BASE_QPC + 20_000_000;
        let u2 = BASE_UNIX + 20;
        session.handle_key_down_with_providers(
            make_key(VK_PACKET_CODE, 0xDE00, 0, q2, u2),
            &policy,
            4242,
            BASE_QPC,
            false,
            1_020,
            || q2,
            |_| {
                Ok(InputTextApprovedContext {
                    context: ctx.clone(),
                    metadata_monotonic_ns: q2,
                    role: InputTextFieldRole::TextField,
                })
            },
            |_, _, _, _| unreachable!("VK_PACKET must not invoke ToUnicodeEx"),
            || unreachable!("VK_PACKET must bypass legacy IMM32 probe"),
        );
        assert_eq!(
            session.accumulator.pending().map(|p| p.text.as_str()),
            Some("😀")
        );

        // 2. PolicyBoundary (e.g. ES_PASSWORD) purges buffers, returns true to disarm, and NEVER
        // latches `secure_input_detected`.
        let q3 = BASE_QPC + 30_000_000;
        let u3 = BASE_UNIX + 30;
        let pb = session.handle_key_down_with_providers(
            make_key(0x41, 0x1E, 0, q3, u3),
            &policy,
            4242,
            BASE_QPC,
            true,
            1_030,
            || q3,
            |_| Err(InputTextGapReason::PolicyBoundary),
            |_, _, _, _| unreachable!("Pre-Gate PolicyBoundary must never call ToUnicodeEx"),
            || None,
        );
        assert!(pb);
        assert!(!session.secure_input_detected());
        assert!(session.accumulator.pending().is_none());
        assert_eq!(
            session.input_gaps.last().map(|g| g.reason),
            Some(InputTextGapReason::PolicyBoundary)
        );

        // 3. `query_imm32_open_status_bounded(HWND::default())` returns None without blocking.
        assert_eq!(query_imm32_open_status_bounded(HWND::default()), None);

        // 4. Verify `InputTextSample` / `MergedInputEvent` causal ordering on tied QPC timestamps.
        let mut events = [
            MergedInputEvent::KeyHook(RawKeyHookEvent::KeyDown(make_key(
                0x41, 0x1E, 0, BASE_QPC, BASE_UNIX,
            ))),
            MergedInputEvent::TextEdit(RawUiaTextEditEvent {
                kind: UiaTextEditEventKind::CompositionFinalized {
                    text: SensitiveText::new("中".to_string()),
                    saturated: false,
                },
                sender: None,
                observed_qpc_ns: BASE_QPC,
                observed_mono_ms: 1_000,
                observed_unix_ms: BASE_UNIX,
            }),
            MergedInputEvent::TextEdit(RawUiaTextEditEvent {
                kind: UiaTextEditEventKind::Composition,
                sender: None,
                observed_qpc_ns: BASE_QPC,
                observed_mono_ms: 1_000,
                observed_unix_ms: BASE_UNIX,
            }),
            MergedInputEvent::KeyHook(RawKeyHookEvent::BoundaryMismatch {
                qpc_ns: BASE_QPC,
                unix_ms: BASE_UNIX,
            }),
        ];
        events.sort_by_key(|e| (e.qpc_ns(), e.tie_priority()));
        let priorities: Vec<u8> = events.iter().map(MergedInputEvent::tie_priority).collect();
        assert_eq!(priorities, vec![0, 1, 2, 3]);
        let _ = InputTextSample::ime_commit(ctx, "中".to_string(), BASE_UNIX);
    }

    #[test]
    fn refresh_verified_chrome_proof_updates_only_exact_bound_target_monotonically() {
        let mut session = InputTextSession::new(Arc::new(AtomicU64::new(7)));
        let hwnd = HWND(0x4000usize as *mut core::ffi::c_void);
        let app = ApplicationIdentity {
            application_id: "chrome.exe".to_string(),
            process_id: 9001,
            process_start_time: "unix-ms:1700000000000.000".to_string(),
        };
        let resolved = ResolvedAppIdentity::from_single("chrome.exe".to_string()).unwrap();
        session.bound = Some(BoundInputField {
            hwnd,
            raw_pid: 9001,
            app: app.clone(),
            resolved: resolved.clone(),
            is_browser: true,
            dpi: 96,
            is_terminal: false,
            focus_runtime_id: crate::uia_traversal::RuntimeIdKey(vec![42, 7]),
            focus_role: InputTextFieldRole::TextField,
            context: test_context(),
            policy: test_policy(),
            expected_focus_epoch: 7,
            chrome_verified_normal: true,
            chrome_verified_at_mono_ms: 5_000,
        });

        // Mismatched HWND, epoch, or PID must NOT update timestamp.
        session.refresh_verified_chrome_proof(
            HWND(0x5000usize as *mut core::ffi::c_void),
            &app,
            &resolved,
            7,
            6_000,
        );
        assert_eq!(session.bound.as_ref().unwrap().chrome_verified_at_mono_ms, 5_000);
        session.refresh_verified_chrome_proof(hwnd, &app, &resolved, 8, 6_000);
        assert_eq!(session.bound.as_ref().unwrap().chrome_verified_at_mono_ms, 5_000);

        // Regressing timestamp must NOT overwrite a newer proof.
        session.refresh_verified_chrome_proof(hwnd, &app, &resolved, 7, 4_500);
        assert_eq!(session.bound.as_ref().unwrap().chrome_verified_at_mono_ms, 5_000);

        // Exact match with advancing timestamp updates cleanly.
        session.refresh_verified_chrome_proof(hwnd, &app, &resolved, 7, 6_250);
        assert_eq!(session.bound.as_ref().unwrap().chrome_verified_at_mono_ms, 6_250);
    }
}

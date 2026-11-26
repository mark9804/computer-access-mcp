//! Non-blocking MTA COM UI Automation event subscriber (`UIA_MenuOpenedEventId`,
//! `UIA_MenuClosedEventId`, `UIA_Invoke_InvokedEventId`).
//!
//! Layer 0 leaf module — imports no sibling `uia_worker` modules.
//!
//! # Critical COM Safety Invariant
//! Inside `IUIAutomationEventHandler::HandleAutomationEvent`, NEVER call ANY UIA/COM methods on
//! `sender` (no property reads, no tree walks, no `SendMessage`, no `QueryInterface`). The handler
//! ONLY:
//! 1. Checks `active` (atomic fast-exit after `detach()` / `abandon_for_process_exit()`).
//! 2. Captures `sender.cloned().map(MtaElement)` (in-process atomic `IUnknown::AddRef` only),
//!    `event_id`, and monotonic/wall timestamps.
//! 3. Non-blockingly `try_send`s to a bounded `mpsc::sync_channel(UIA_MENU_EVENT_CHANNEL_CAPACITY)`.
//!
//! All UIA property reads and privacy gates execute strictly on the worker's main MTA thread after
//! draining the channel, covered by the worker watchdog and `IUIAutomation2` transaction timeouts.
//!
//! # PR 5B Extension Seam (`input.text` IME Composition Events)
//! PR 5B can add a sibling `UiaTextEditEventHandler` (`IUIAutomationTextEditTextChangedEventHandler`)
//! and `UiaTextEditEventSubscription` (`IUIAutomation3::AddTextEditTextChangedEventHandler` /
//! `RemoveTextEditTextChangedEventHandler`) directly in this module, reusing [`MtaElement`],
//! [`SubscriptionTeardown`], and the exact same non-blocking bounded-channel +
//! `detach` / `abandon_for_process_exit` lifecycle without modifying [`UiaMenuEventSubscription`].

use core::ffi::c_void;
use core::ptr::NonNull;
use std::fmt;
use std::mem::ManuallyDrop;
use std::sync::atomic::{compiler_fence, AtomicBool, AtomicIsize, AtomicU64, Ordering};
use std::sync::mpsc::{self, TrySendError};
use std::sync::Arc;

use windows::core::{
    imp::{self, IAgileObject, IMarshal, WeakRefCount},
    ComObject, ComObjectInner, ComObjectInterface, IUnknown, IUnknownImpl, Interface, InterfaceRef,
    Ref, BSTR, GUID, HRESULT,
};
use windows::Win32::Foundation::{SysStringLen, HWND};
use windows::Win32::System::Com::SAFEARRAY;
use windows::Win32::System::Ole::{
    SafeArrayAccessData, SafeArrayGetLBound, SafeArrayGetUBound, SafeArrayGetVartype,
    SafeArrayUnaccessData,
};
use windows::Win32::System::Variant::VT_BSTR;
use windows::Win32::UI::Accessibility::{
    IUIAutomation, IUIAutomation2, IUIAutomation3, IUIAutomationCacheRequest, IUIAutomationElement,
    IUIAutomationEventHandler, IUIAutomationEventHandler_Impl, IUIAutomationEventHandler_Vtbl,
    IUIAutomationTextEditTextChangedEventHandler,
    IUIAutomationTextEditTextChangedEventHandler_Impl,
    IUIAutomationTextEditTextChangedEventHandler_Vtbl, TextEditChangeType,
    TextEditChangeType_Composition, TextEditChangeType_CompositionFinalized, TreeScope_Subtree,
    UIA_Invoke_InvokedEventId, UIA_MenuClosedEventId, UIA_MenuOpenedEventId, UIA_EVENT_ID,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetClassNameW, GetForegroundWindow, GetGUIThreadInfo, GetWindowLongW, GetWindowThreadProcessId,
    GUITHREADINFO, GUI_INMENUMODE, GUI_POPUPMENUMODE, GWL_STYLE,
};

use crate::input_activity_win32::monotonic_qpc_ns_now;
use crate::protocol_model::SystemCollectorClock;

/// Bounded capacity of the MTA UIA menu event channel between UIA callback threads and the worker
/// main MTA thread.
pub const UIA_MENU_EVENT_CHANNEL_CAPACITY: usize = 32;

/// Exact set of UIA event IDs subscribed by [`UiaMenuEventSubscription`].
pub const MENU_SUBSCRIBED_EVENT_IDS: [UIA_EVENT_ID; 3] = [
    UIA_MenuOpenedEventId,
    UIA_MenuClosedEventId,
    UIA_Invoke_InvokedEventId,
];

/// `Send`-safe wrapper around an [`IUIAutomationElement`] obtained and consumed strictly inside the
/// process-wide COM Multi-Threaded Apartment (MTA).
///
/// # Safety / MTA Precondition
/// In COM's Multi-Threaded Apartment (`COINIT_MULTITHREADED`), raw interface pointers are directly
/// usable across every thread in the MTA without `IGlobalInterfaceTable` marshaling. Both UIA's
/// internal event callback RPC threads and the worker's main loop run in the MTA (initialized via
/// `CoInitializeEx(None, COINIT_MULTITHREADED)`), so passing an `AddRef`'d `IUIAutomationElement`
/// over an `mpsc` channel between them is zero-overhead and sound.
///
/// Callers MUST NOT construct, dereference, or drop `MtaElement` on an STA thread.
#[derive(Clone, Debug)]
pub struct MtaElement(IUIAutomationElement);

// SAFETY: Valid ONLY within the process COM Multi-Threaded Apartment (`COINIT_MULTITHREADED`),
// where COM interface pointers are apartment-agile across all MTA threads without marshaling.
unsafe impl Send for MtaElement {}

impl MtaElement {
    /// Wrap an `IUIAutomationElement` acquired on an MTA thread.
    ///
    /// # Safety
    /// Both the caller's thread and any thread that subsequently dereferences or drops the
    /// returned `MtaElement` MUST belong to the COM Multi-Threaded Apartment (`COINIT_MULTITHREADED`).
    pub unsafe fn from_mta(element: IUIAutomationElement) -> Self {
        Self(element)
    }

    /// Borrow the underlying `IUIAutomationElement` on an MTA thread.
    pub fn as_element(&self) -> &IUIAutomationElement {
        &self.0
    }

    /// Consume the wrapper and return the underlying `IUIAutomationElement` on an MTA thread.
    pub fn into_inner(self) -> IUIAutomationElement {
        self.0
    }
}

/// Typed classification of the UIA menu events subscribed by [`UiaMenuEventSubscription`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiaMenuEventKind {
    MenuOpened,
    MenuClosed,
    Invoked,
}

impl UiaMenuEventKind {
    pub fn from_event_id(event_id: UIA_EVENT_ID) -> Option<Self> {
        if event_id == UIA_MenuOpenedEventId {
            Some(Self::MenuOpened)
        } else if event_id == UIA_MenuClosedEventId {
            Some(Self::MenuClosed)
        } else if event_id == UIA_Invoke_InvokedEventId {
            Some(Self::Invoked)
        } else {
            None
        }
    }

    pub fn as_event_id(self) -> UIA_EVENT_ID {
        match self {
            Self::MenuOpened => UIA_MenuOpenedEventId,
            Self::MenuClosed => UIA_MenuClosedEventId,
            Self::Invoked => UIA_Invoke_InvokedEventId,
        }
    }
}

/// Raw UIA event payload enqueued from the non-blocking MTA COM callback thread for downstream
/// privacy-gated inspection on the worker main MTA thread.
///
/// Note: `sender` is `Option<MtaElement>` because Windows UIA routinely delivers
/// `UIA_MenuClosedEventId` with a `NULL` sender once the closed menu provider has been torn down.
#[derive(Debug)]
pub struct RawUiaMenuEvent {
    pub event_id: UIA_EVENT_ID,
    pub sender: Option<MtaElement>,
    pub observed_qpc_ns: u64,
    pub observed_mono_ms: i64,
    pub observed_unix_ms: i64,
}

impl RawUiaMenuEvent {
    pub fn kind(&self) -> Option<UiaMenuEventKind> {
        UiaMenuEventKind::from_event_id(self.event_id)
    }
}

/// Teardown policy for active UIA event subscriptions, mirroring macOS `ObserverTeardown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionTeardown {
    /// Normal rebind or channel disable: invoke `RemoveAutomationEventHandler` for all registered IDs.
    Detach,
    /// Process-exit retirement: skip remote `RemoveAutomationEventHandler` calls to prevent COM
    /// teardown deadlocks against hung target UI threads.
    AbandonForProcessExit,
}

/// Create a bounded channel sized to [`UIA_MENU_EVENT_CHANNEL_CAPACITY`] (32) for UIA menu events.
pub fn create_menu_event_channel() -> (
    mpsc::SyncSender<RawUiaMenuEvent>,
    mpsc::Receiver<RawUiaMenuEvent>,
) {
    mpsc::sync_channel(UIA_MENU_EVENT_CHANNEL_CAPACITY)
}

/// Non-blocking MTA COM `IUIAutomationEventHandler` implementation for menu lifecycle & invoke
/// events.
///
/// INVARIANT: Never calls any UIA/COM methods on `sender`; only clones the interface pointer
/// (`AddRef`) into [`MtaElement`] and performs a non-blocking `try_send`.
///
/// Note on COM vtable wiring: `windows::core::implement` (`windows-implement 0.60.2`) emits paths
/// anchored at `::windows_core::...`, which requires a direct `windows-core` entry in `Cargo.toml`.
/// Wiring the exact same `IUIAutomationEventHandler_Vtbl::new`, `IUnknownImpl`, `ComObjectInner`,
/// `IAgileObject`, and `IMarshal` (Free-Threaded Marshaler) layout directly against `windows::core`
/// keeps `Cargo.toml` and `Cargo.lock` untouched while delivering identical agile MTA COM ABI.
struct UiaMenuEventHandler {
    tx: mpsc::SyncSender<RawUiaMenuEvent>,
    active: Arc<AtomicBool>,
    dropped_count: Arc<AtomicU64>,
}

impl UiaMenuEventHandler {
    fn new(
        tx: mpsc::SyncSender<RawUiaMenuEvent>,
        active: Arc<AtomicBool>,
        dropped_count: Arc<AtomicU64>,
    ) -> Self {
        Self {
            tx,
            active,
            dropped_count,
        }
    }
}

#[repr(C)]
struct UiaMenuEventHandlerImpl {
    vtable: &'static IUIAutomationEventHandler_Vtbl,
    this: UiaMenuEventHandler,
    count: WeakRefCount,
}

impl UiaMenuEventHandlerImpl {
    const VTABLE: IUIAutomationEventHandler_Vtbl =
        IUIAutomationEventHandler_Vtbl::new::<Self, 0>();
}

impl IUnknownImpl for UiaMenuEventHandlerImpl {
    type Impl = UiaMenuEventHandler;

    #[inline(always)]
    fn get_impl(&self) -> &Self::Impl {
        &self.this
    }

    #[inline(always)]
    fn get_impl_mut(&mut self) -> &mut Self::Impl {
        &mut self.this
    }

    #[inline(always)]
    fn into_inner(self) -> Self::Impl {
        self.this
    }

    unsafe fn QueryInterface(
        &self,
        iid: *const GUID,
        interface: *mut *mut c_void,
    ) -> HRESULT {
        if iid.is_null() || interface.is_null() {
            return imp::E_POINTER;
        }
        let iid = *iid;
        if iid == IUnknown::IID
            || iid == IAgileObject::IID
            || IUIAutomationEventHandler_Vtbl::matches(&iid)
        {
            *interface = &self.vtable as *const _ as *mut c_void;
            self.count.add_ref();
            return HRESULT(0);
        }
        if iid == IMarshal::IID {
            return imp::marshaler(self.to_interface(), interface);
        }
        let tear_off = self.count.query(&iid, &self.vtable as *const _ as *mut _);
        if !tear_off.is_null() {
            *interface = tear_off;
            return HRESULT(0);
        }
        *interface = core::ptr::null_mut();
        imp::E_NOINTERFACE
    }

    #[inline(always)]
    fn AddRef(&self) -> u32 {
        self.count.add_ref()
    }

    #[inline(always)]
    unsafe fn Release(self_: *mut Self) -> u32 {
        let remaining = (*self_).count.release();
        if remaining == 0 {
            let _ = Box::from_raw(self_);
        }
        remaining
    }

    #[inline(always)]
    fn is_reference_count_one(&self) -> bool {
        self.count.is_one()
    }

    unsafe fn GetTrustLevel(&self, value: *mut i32) -> HRESULT {
        if value.is_null() {
            return imp::E_POINTER;
        }
        *value = 0;
        HRESULT(0)
    }

    fn to_object(&self) -> ComObject<Self::Impl> {
        self.count.add_ref();
        // SAFETY: `self` lives inside a heap-allocated `Box<UiaMenuEventHandlerImpl>` managed by
        // `ComObject` / COM refcounting.
        unsafe { ComObject::from_raw(NonNull::new_unchecked(self as *const Self as *mut Self)) }
    }
}

impl ComObjectInner for UiaMenuEventHandler {
    type Outer = UiaMenuEventHandlerImpl;

    fn into_object(self) -> ComObject<Self> {
        let boxed = Box::new(UiaMenuEventHandlerImpl {
            vtable: &UiaMenuEventHandlerImpl::VTABLE,
            this: self,
            count: WeakRefCount::new(),
        });
        // SAFETY: Boxed COM object transferred into `ComObject` with initial refcount 1.
        unsafe { ComObject::from_raw(Box::into_non_null(boxed)) }
    }
}

impl ComObjectInterface<IUnknown> for UiaMenuEventHandlerImpl {
    #[inline(always)]
    fn as_interface_ref(&self) -> InterfaceRef<'_, IUnknown> {
        // SAFETY: `self.vtable` starts with `IUnknown_Vtbl` (`#[repr(C)]`), matching `IUnknown`.
        unsafe { core::mem::transmute(&self.vtable) }
    }
}

impl ComObjectInterface<IUIAutomationEventHandler> for UiaMenuEventHandlerImpl {
    #[inline(always)]
    fn as_interface_ref(&self) -> InterfaceRef<'_, IUIAutomationEventHandler> {
        // SAFETY: `self.vtable` is `&'static IUIAutomationEventHandler_Vtbl` at offset 0.
        unsafe { core::mem::transmute(&self.vtable) }
    }
}

impl From<UiaMenuEventHandler> for IUIAutomationEventHandler {
    #[inline(always)]
    fn from(this: UiaMenuEventHandler) -> Self {
        ComObject::new(this).into_interface()
    }
}

impl IUIAutomationEventHandler_Impl for UiaMenuEventHandlerImpl {
    fn HandleAutomationEvent(
        &self,
        sender: Ref<IUIAutomationElement>,
        eventid: UIA_EVENT_ID,
    ) -> windows::core::Result<()> {
        if !self.this.active.load(Ordering::Acquire) {
            return Ok(());
        }

        // CRITICAL COM SAFETY INVARIANT:
        // NEVER invoke any UIA/COM method on `sender` here (no property reads, no tree walks,
        // no SendMessage). Only `sender.cloned()` (local in-process AddRef) + timestamps +
        // non-blocking `try_send`.
        // SAFETY: UIA invokes this handler inside the process MTA (`COINIT_MULTITHREADED`), and
        // `RawUiaMenuEvent` is consumed strictly on the worker's main MTA thread.
        let mta_sender = sender.cloned().map(|el| unsafe { MtaElement::from_mta(el) });
        let event = RawUiaMenuEvent {
            event_id: eventid,
            sender: mta_sender,
            observed_qpc_ns: monotonic_qpc_ns_now(),
            observed_mono_ms: SystemCollectorClock::monotonic_ms_now(),
            observed_unix_ms: SystemCollectorClock::unix_ms_now(),
        };

        if let Err(TrySendError::Full(_)) = self.this.tx.try_send(event) {
            self.this.dropped_count.fetch_add(1, Ordering::Relaxed);
        }

        Ok(())
    }
}

/// Active MTA UIA subscription for `UIA_MenuOpenedEventId`, `UIA_MenuClosedEventId`, and
/// `UIA_Invoke_InvokedEventId` on a target window subtree (`TreeScope_Subtree`).
///
/// Calls `RemoveAutomationEventHandler` for all registered events on [`Self::detach`] or [`Drop`],
/// unless explicitly retired via [`Self::abandon_for_process_exit`].
pub struct UiaMenuEventSubscription {
    automation: IUIAutomation,
    root: IUIAutomationElement,
    handler: IUIAutomationEventHandler,
    active: Arc<AtomicBool>,
    dropped_count: Arc<AtomicU64>,
    registered_events: Vec<UIA_EVENT_ID>,
    detached_or_abandoned: bool,
}

impl UiaMenuEventSubscription {
    /// Subscribe to `UIA_MenuOpenedEventId`, `UIA_MenuClosedEventId`, and
    /// `UIA_Invoke_InvokedEventId` on `root` with `TreeScope_Subtree`.
    ///
    /// Uses `cacherequest = None` so no element properties are read prior to the worker main
    /// thread's pre-read privacy gates. If any subscription call fails mid-way, already-registered
    /// handlers are rolled back cleanly before returning `Err`.
    pub fn attach(
        automation: &IUIAutomation,
        root: &IUIAutomationElement,
        tx: mpsc::SyncSender<RawUiaMenuEvent>,
    ) -> windows::core::Result<Self> {
        let active = Arc::new(AtomicBool::new(true));
        let dropped_count = Arc::new(AtomicU64::new(0));
        let handler: IUIAutomationEventHandler =
            UiaMenuEventHandler::new(tx, Arc::clone(&active), Arc::clone(&dropped_count)).into();

        let mut registered_events = Vec::with_capacity(MENU_SUBSCRIBED_EVENT_IDS.len());
        for &event_id in &MENU_SUBSCRIBED_EVENT_IDS {
            // SAFETY: Valid MTA `IUIAutomation`, target `root`, `TreeScope_Subtree`, null cache
            // request (no pre-gate property reads), and COM-refcounted `handler`.
            let res = unsafe {
                automation.AddAutomationEventHandler(
                    event_id,
                    root,
                    TreeScope_Subtree,
                    Option::<&IUIAutomationCacheRequest>::None,
                    &handler,
                )
            };
            match res {
                Ok(()) => registered_events.push(event_id),
                Err(err) => {
                    active.store(false, Ordering::Release);
                    for registered_id in registered_events.drain(..).rev() {
                        // SAFETY: Rolling back handler just registered on the same automation/root.
                        unsafe {
                            let _ = automation.RemoveAutomationEventHandler(
                                registered_id,
                                root,
                                &handler,
                            );
                        }
                    }
                    return Err(err);
                }
            }
        }

        Ok(Self {
            automation: automation.clone(),
            root: root.clone(),
            handler,
            active,
            dropped_count,
            registered_events,
            detached_or_abandoned: false,
        })
    }

    /// True while the subscription is active (neither detached nor abandoned).
    pub fn is_active(&self) -> bool {
        !self.detached_or_abandoned && self.active.load(Ordering::Acquire)
    }

    /// Number of event IDs currently registered on this subscription.
    pub fn subscribed_event_count(&self) -> usize {
        self.registered_events.len()
    }

    /// Total events dropped due to bounded channel backpressure since attach.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    /// Read and reset the count of events dropped due to bounded channel backpressure.
    pub fn take_dropped_count(&self) -> u64 {
        self.dropped_count.swap(0, Ordering::AcqRel)
    }

    /// Finish the subscription using the selected [`SubscriptionTeardown`] policy.
    pub fn finish(self, teardown: SubscriptionTeardown) {
        match teardown {
            SubscriptionTeardown::Detach => self.detach(),
            SubscriptionTeardown::AbandonForProcessExit => self.abandon_for_process_exit(),
        }
    }

    /// Unsubscribe cleanly by calling `RemoveAutomationEventHandler` for all registered event IDs
    /// using the default bounded 40ms per-call COM timeout.
    pub fn detach(mut self) {
        self.detach_in_place_with_timeout(40);
    }

    /// Unsubscribe cleanly using an explicit bounded per-call COM timeout (`1..=40` ms) so
    /// remaining read-ticket deadline clamps are never overwritten back up to 40ms.
    pub fn detach_with_timeout(mut self, timeout_ms: u32) {
        self.detach_in_place_with_timeout(timeout_ms.clamp(1, 40));
    }

    /// Silence callbacks and skip remote `RemoveAutomationEventHandler` calls on process-exit
    /// retirement, matching macOS `ObserverTeardown` and preventing COM teardown deadlocks.
    pub fn abandon_for_process_exit(mut self) {
        self.detached_or_abandoned = true;
        self.active.store(false, Ordering::Release);
        self.registered_events.clear();
    }

    fn detach_in_place_with_timeout(&mut self, timeout_ms: u32) {
        if self.detached_or_abandoned {
            return;
        }
        self.detached_or_abandoned = true;
        self.active.store(false, Ordering::Release);
        let bounded_ms = timeout_ms.clamp(1, 40);
        // Clamp IUIAutomation2 timeouts right before remote RemoveAutomationEventHandler calls
        // so detaching from a busy/unresponsive target window never stalls past caller budget.
        if let Ok(uia2) = self.automation.cast::<IUIAutomation2>() {
            // SAFETY: Bounded non-zero timeout values in milliseconds.
            unsafe {
                let _ = uia2.SetConnectionTimeout(bounded_ms);
                let _ = uia2.SetTransactionTimeout(bounded_ms);
            }
        }
        for event_id in self.registered_events.drain(..).rev() {
            // SAFETY: Balanced with `AddAutomationEventHandler` using the exact same `event_id`,
            // `root`, and `handler` inside MTA COM.
            unsafe {
                let _ = self
                    .automation
                    .RemoveAutomationEventHandler(event_id, &self.root, &self.handler);
            }
        }
    }
}

impl Drop for UiaMenuEventSubscription {
    fn drop(&mut self) {
        if !self.detached_or_abandoned {
            self.detach_in_place_with_timeout(40);
        }
    }
}

/// Bounded capacity of the MTA UIA TextEdit composition event channel between UIA callback threads
/// and the worker main MTA thread.
pub const TEXT_EDIT_EVENT_CHANNEL_CAPACITY: usize = 32;

/// Maximum UTF-16 code units extracted from a `TextEditChangeType_CompositionFinalized`
/// `SAFEARRAY(BSTR)` payload before marking the event saturated and zeroizing partial buffers.
pub const TEXT_EDIT_MAX_CODE_UNITS: usize = 2_048;

const MAX_TEXT_EDIT_EVENT_STRINGS: i64 = 64;

const TEXT_EDIT_SUBSCRIBED_CHANGE_TYPES: [TextEditChangeType; 2] = [
    TextEditChangeType_Composition,
    TextEditChangeType_CompositionFinalized,
];

fn zeroize_u8_slice(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: Valid mutable reference to an initialized byte; volatile write resists DSE.
        unsafe {
            core::ptr::write_volatile(b as *mut u8, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

fn zeroize_u16_slice(units: &mut [u16]) {
    for u in units.iter_mut() {
        // SAFETY: Valid mutable reference to an initialized u16; volatile write resists DSE.
        unsafe {
            core::ptr::write_volatile(u as *mut u16, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

fn zeroize_string_in_place(text: &mut str) {
    // SAFETY: Overwriting every byte with `0x00` (ASCII NUL) preserves UTF-8 validity before drop.
    let bytes = unsafe { text.as_bytes_mut() };
    zeroize_u8_slice(bytes);
}

/// Fast zero-IPC pre-check inside `HandleTextEditTextChangedEvent`: returns `true` (block) when
/// `fg_hwnd` cannot be queried, is in Win32 menu mode, or its focused Win32 Edit/Password control
/// carries `ES_PASSWORD` (`0x0020`).
fn foreground_gui_blocks_text_edit(fg_hwnd: HWND) -> bool {
    if fg_hwnd.0.is_null() {
        return true;
    }
    // SAFETY: Fast read-only Win32 thread ID + kernel GUITHREADINFO query (no cross-process IPC).
    let fg_tid = unsafe { GetWindowThreadProcessId(fg_hwnd, None) };
    if fg_tid == 0 {
        return true;
    }
    let mut gui = GUITHREADINFO {
        cbSize: std::mem::size_of::<GUITHREADINFO>() as u32,
        ..Default::default()
    };
    if unsafe { GetGUIThreadInfo(fg_tid, &mut gui) }.is_err() {
        return true;
    }
    if (gui.flags.0 & (GUI_INMENUMODE.0 | GUI_POPUPMENUMODE.0)) != 0 {
        return true;
    }
    if !gui.hwndFocus.0.is_null() {
        const ES_PASSWORD_STYLE: u32 = 0x0020;
        let style = unsafe { GetWindowLongW(gui.hwndFocus, GWL_STYLE) } as u32;
        if (style & ES_PASSWORD_STYLE) != 0 {
            let mut cls_buf = [0u16; 128];
            let len = unsafe { GetClassNameW(gui.hwndFocus, &mut cls_buf) };
            if len > 0 {
                if let Ok(cls) = String::from_utf16(&cls_buf[..len as usize]) {
                    let lower = cls.to_ascii_lowercase();
                    if lower.contains("edit") || lower.contains("password") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Zeroize-on-drop UTF-8 text wrapper for sensitive IME finalized composition strings in transit
/// between MTA UIA callback threads and the worker's privacy-gated pipeline.
///
/// `Debug` output is always redacted so sensitive text never leaks into logs or panic payloads.
#[derive(PartialEq, Eq)]
pub struct SensitiveText(String);

impl SensitiveText {
    pub fn new(text: String) -> Self {
        Self(text)
    }

    pub fn empty() -> Self {
        Self(String::new())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the container and transfer ownership of the underlying `String` without zeroizing
    /// the returned bytes.
    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for SensitiveText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SensitiveText([redacted; {} bytes])", self.0.len())
    }
}

impl Drop for SensitiveText {
    fn drop(&mut self) {
        zeroize_string_in_place(&mut self.0);
    }
}

/// Typed classification of UIA TextEdit events subscribed by [`UiaTextEditEventSubscription`].
#[derive(Debug, PartialEq, Eq)]
pub enum UiaTextEditEventKind {
    Composition,
    /// Valid empty `CompositionFinalized` (e.g. backspacing pinyin to empty or cancelling IME
    /// composition cleanly) so downstream `ime_state` resets immediately instead of stalling 5s.
    CompositionCleared,
    CompositionFinalized {
        text: SensitiveText,
        saturated: bool,
    },
}

/// Raw UIA TextEdit event payload enqueued from the non-blocking MTA COM callback thread for
/// downstream privacy-gated admission on the worker main MTA thread.
#[derive(Debug)]
pub struct RawUiaTextEditEvent {
    pub kind: UiaTextEditEventKind,
    pub sender: Option<MtaElement>,
    pub observed_qpc_ns: u64,
    pub observed_mono_ms: i64,
    pub observed_unix_ms: i64,
}

/// Atomic pre-read privacy and window-binding gates checked inside
/// `IUIAutomationTextEditTextChangedEventHandler::HandleTextEditTextChangedEvent` BEFORE touching
/// `eventStrings`.
#[derive(Clone)]
pub struct TextEditHookGates {
    pub active: Arc<AtomicBool>,
    pub retiring: Arc<AtomicBool>,
    pub secure_input_blocked: Arc<AtomicBool>,
    pub context_ready: Arc<AtomicBool>,
    pub bound_hwnd: Arc<AtomicIsize>,
    pub focus_epoch: Arc<AtomicU64>,
    pub expected_focus_epoch: Arc<AtomicU64>,
}

/// Create a bounded channel sized to [`TEXT_EDIT_EVENT_CHANNEL_CAPACITY`] (32) for UIA TextEdit
/// composition events.
pub fn create_text_edit_event_channel() -> (
    mpsc::SyncSender<RawUiaTextEditEvent>,
    mpsc::Receiver<RawUiaTextEditEvent>,
) {
    mpsc::sync_channel(TEXT_EDIT_EVENT_CHANNEL_CAPACITY)
}

#[derive(Debug, PartialEq, Eq)]
enum ExtractedTextEditStrings {
    Empty,
    Text(SensitiveText),
    Saturated,
}

struct SafeArrayAccessGuard(*const SAFEARRAY);

impl Drop for SafeArrayAccessGuard {
    fn drop(&mut self) {
        // SAFETY: Paired exclusively with a successful `SafeArrayAccessData(self.0, ...)`.
        unsafe {
            let _ = SafeArrayUnaccessData(self.0);
        }
    }
}

/// Safely extract and concatenate valid BSTR UTF-16 code units from a borrowed 1-D `VT_BSTR`
/// `SAFEARRAY` without ever taking ownership of or freeing the borrowed BSTRs.
///
/// Returns:
/// - `Some(ExtractedTextEditStrings::Empty)` for a well-formed 1-D `VT_BSTR` `SAFEARRAY` with
///   zero non-empty code units (e.g. cancelled/backspaced IME composition).
/// - `Some(ExtractedTextEditStrings::Text(..))` for non-empty valid UTF-16 within `<= 2048` units
///   decoded into a single pre-sized UTF-8 buffer (`units * 3` bytes, zero CJK reallocations).
/// - `Some(ExtractedTextEditStrings::Saturated)` when total UTF-16 code units exceed `2048`
///   (immediately zeroizing any partial UTF-16 buffer with volatile writes + `SeqCst` fence).
/// - `None` when the `SAFEARRAY` is null/malformed/wrong vartype/oversized or contains invalid UTF-16.
unsafe fn read_bstr_safearray_bounded(psa: *const SAFEARRAY) -> Option<ExtractedTextEditStrings> {
    if psa.is_null() {
        return None;
    }
    if (*psa).cDims != 1 || (*psa).cbElements != std::mem::size_of::<*mut u16>() as u32 {
        return None;
    }
    if SafeArrayGetVartype(psa).ok()? != VT_BSTR {
        return None;
    }

    let lbound = SafeArrayGetLBound(psa, 1).ok()?;
    let ubound = SafeArrayGetUBound(psa, 1).ok()?;
    let count = i64::from(ubound) - i64::from(lbound) + 1;
    if !(0..=MAX_TEXT_EDIT_EVENT_STRINGS).contains(&count) {
        return None;
    }
    if count == 0 {
        return Some(ExtractedTextEditStrings::Empty);
    }

    let mut data_ptr: *mut c_void = core::ptr::null_mut();
    SafeArrayAccessData(psa, &mut data_ptr).ok()?;
    let _access_guard = SafeArrayAccessGuard(psa);
    if data_ptr.is_null() {
        return None;
    }

    let elem_count = count as usize;
    let base = data_ptr as *const *const u16;

    // Pass 1: Sum total UTF-16 code units across all valid BSTRs before allocating so saturated
    // payloads fail early and valid multi-element arrays allocate `utf16_buf` ONCE with exact
    // capacity (never reallocating an earlier heap allocation without zeroizing it).
    let mut total_units: usize = 0;
    for i in 0..elem_count {
        let raw_bstr = core::ptr::read_unaligned(base.add(i));
        if raw_bstr.is_null() {
            continue;
        }
        // SAFETY: Borrowed COM BSTR inside locked SAFEARRAY; `ManuallyDrop` ensures we NEVER
        // call `SysFreeString` on COM's borrowed element.
        let borrowed = ManuallyDrop::new(BSTR::from_raw(raw_bstr));
        let unit_len = SysStringLen(&borrowed) as usize;
        if unit_len == 0 {
            continue;
        }
        total_units = total_units.saturating_add(unit_len);
        if total_units > TEXT_EDIT_MAX_CODE_UNITS {
            return Some(ExtractedTextEditStrings::Saturated);
        }
    }

    if total_units == 0 {
        return Some(ExtractedTextEditStrings::Empty);
    }

    // Pass 2: Allocate exact capacity once and copy every valid UTF-16 slice without reallocation.
    let mut utf16_buf: Vec<u16> = Vec::with_capacity(total_units);
    for i in 0..elem_count {
        let raw_bstr = core::ptr::read_unaligned(base.add(i));
        if raw_bstr.is_null() {
            continue;
        }
        // SAFETY: Borrowed COM BSTR inside locked SAFEARRAY; `ManuallyDrop` ensures we NEVER
        // call `SysFreeString` on COM's borrowed element.
        let borrowed = ManuallyDrop::new(BSTR::from_raw(raw_bstr));
        let unit_len = SysStringLen(&borrowed) as usize;
        if unit_len == 0 {
            continue;
        }
        if utf16_buf.len().saturating_add(unit_len) > total_units {
            zeroize_u16_slice(&mut utf16_buf);
            return Some(ExtractedTextEditStrings::Saturated);
        }
        let units = core::slice::from_raw_parts(raw_bstr, unit_len);
        utf16_buf.extend_from_slice(units);
    }

    if utf16_buf.is_empty() {
        return Some(ExtractedTextEditStrings::Empty);
    }

    // Worst-case UTF-8 expansion from valid UTF-16 is 3 bytes per BMP code unit (CJK / 3-byte
    // scalars; surrogate pairs take 2 UTF-16 units -> 4 UTF-8 bytes <= 6 bytes). Pre-allocating
    // `len * 3` guarantees zero heap reallocations and zero unzeroized old buffers!
    let mut out = String::with_capacity(utf16_buf.len().saturating_mul(3));
    let mut invalid = false;
    for decoded_ch in char::decode_utf16(utf16_buf.iter().copied()) {
        match decoded_ch {
            Ok(ch) => out.push(ch),
            Err(_) => {
                invalid = true;
                break;
            }
        }
    }
    zeroize_u16_slice(&mut utf16_buf);
    if invalid {
        zeroize_string_in_place(&mut out);
        return None;
    }
    Some(ExtractedTextEditStrings::Text(SensitiveText::new(out)))
}

/// Non-blocking MTA COM `IUIAutomationTextEditTextChangedEventHandler` implementation for hybrid
/// TSF/CJK IME composition (`Composition` / `CompositionFinalized`) events.
///
/// INVARIANT:
/// - NEVER calls any UIA/COM methods on `sender` (local in-process `AddRef` only).
/// - Enforces all atomic pre-gates (`subscription_active`, `gates.active`, `!retiring`,
///   `!secure_input_blocked`, `context_ready`, `expected_focus_epoch != 0 && focus_epoch == expected`),
///   Win32 `GetForegroundWindow() == bound_hwnd`, and fast zero-IPC `ES_PASSWORD` / menu-mode check
///   BEFORE touching `eventStrings`.
/// - NEVER reads `eventStrings` on `TextEditChangeType_Composition`.
struct UiaTextEditEventHandler {
    tx: mpsc::SyncSender<RawUiaTextEditEvent>,
    gates: TextEditHookGates,
    subscription_active: Arc<AtomicBool>,
    dropped_count: Arc<AtomicU64>,
}

impl UiaTextEditEventHandler {
    fn new(
        tx: mpsc::SyncSender<RawUiaTextEditEvent>,
        gates: TextEditHookGates,
        subscription_active: Arc<AtomicBool>,
        dropped_count: Arc<AtomicU64>,
    ) -> Self {
        Self {
            tx,
            gates,
            subscription_active,
            dropped_count,
        }
    }

    fn handle_event_with_fg(
        &self,
        sender: Option<&IUIAutomationElement>,
        text_edit_change_type: TextEditChangeType,
        event_strings: *const SAFEARRAY,
        fg_hwnd_override: Option<isize>,
    ) {
        let observed_qpc_ns = monotonic_qpc_ns_now();
        if !self.subscription_active.load(Ordering::Acquire)
            || !self.gates.active.load(Ordering::Acquire)
            || self.gates.retiring.load(Ordering::Acquire)
            || self.gates.secure_input_blocked.load(Ordering::Acquire)
            || !self.gates.context_ready.load(Ordering::Acquire)
        {
            return;
        }

        let expected_epoch = self.gates.expected_focus_epoch.load(Ordering::Acquire);
        let current_epoch = self.gates.focus_epoch.load(Ordering::Acquire);
        if expected_epoch == 0 || current_epoch != expected_epoch {
            return;
        }

        let bound_hwnd = self.gates.bound_hwnd.load(Ordering::Acquire);
        if bound_hwnd == 0 {
            return;
        }
        let fg_raw = fg_hwnd_override.unwrap_or_else(|| {
            // SAFETY: Fast read-only foreground HWND lookup (no COM, no SendMessage).
            unsafe { GetForegroundWindow().0 as isize }
        });
        if fg_raw == 0 || fg_raw != bound_hwnd {
            return;
        }
        if fg_hwnd_override.is_none()
            && foreground_gui_blocks_text_edit(HWND(fg_raw as *mut c_void))
        {
            return;
        }

        let kind = if text_edit_change_type == TextEditChangeType_Composition {
            // PRIVACY INVARIANT: NEVER read `event_strings` on intermediate `Composition` events.
            UiaTextEditEventKind::Composition
        } else if text_edit_change_type == TextEditChangeType_CompositionFinalized {
            // SAFETY: `event_strings` is validated for null, 1-D, pointer element width, VT_BSTR,
            // bounded length, and paired `SafeArrayAccessData`/`SafeArrayUnaccessData`.
            match unsafe { read_bstr_safearray_bounded(event_strings) } {
                Some(ExtractedTextEditStrings::Empty) => UiaTextEditEventKind::CompositionCleared,
                Some(ExtractedTextEditStrings::Text(text)) => {
                    UiaTextEditEventKind::CompositionFinalized {
                        text,
                        saturated: false,
                    }
                }
                Some(ExtractedTextEditStrings::Saturated) => {
                    UiaTextEditEventKind::CompositionFinalized {
                        text: SensitiveText::empty(),
                        saturated: true,
                    }
                }
                None => return,
            }
        } else {
            return;
        };

        // CRITICAL COM SAFETY INVARIANT:
        // NEVER invoke any UIA/COM method on `sender` here. Only `sender.cloned()` (local
        // in-process AddRef) + timestamps + non-blocking `try_send`.
        // SAFETY: UIA invokes this handler inside the process MTA (`COINIT_MULTITHREADED`), and
        // `RawUiaTextEditEvent` is consumed strictly on the worker's main MTA thread.
        let mta_sender = sender.cloned().map(|el| unsafe { MtaElement::from_mta(el) });
        let event = RawUiaTextEditEvent {
            kind,
            sender: mta_sender,
            observed_qpc_ns,
            observed_mono_ms: SystemCollectorClock::monotonic_ms_now(),
            observed_unix_ms: SystemCollectorClock::unix_ms_now(),
        };

        if let Err(TrySendError::Full(_)) = self.tx.try_send(event) {
            self.dropped_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[repr(C)]
struct UiaTextEditEventHandlerImpl {
    vtable: &'static IUIAutomationTextEditTextChangedEventHandler_Vtbl,
    this: UiaTextEditEventHandler,
    count: WeakRefCount,
}

impl UiaTextEditEventHandlerImpl {
    const VTABLE: IUIAutomationTextEditTextChangedEventHandler_Vtbl =
        IUIAutomationTextEditTextChangedEventHandler_Vtbl::new::<Self, 0>();
}

impl IUnknownImpl for UiaTextEditEventHandlerImpl {
    type Impl = UiaTextEditEventHandler;

    #[inline(always)]
    fn get_impl(&self) -> &Self::Impl {
        &self.this
    }

    #[inline(always)]
    fn get_impl_mut(&mut self) -> &mut Self::Impl {
        &mut self.this
    }

    #[inline(always)]
    fn into_inner(self) -> Self::Impl {
        self.this
    }

    unsafe fn QueryInterface(
        &self,
        iid: *const GUID,
        interface: *mut *mut c_void,
    ) -> HRESULT {
        if iid.is_null() || interface.is_null() {
            return imp::E_POINTER;
        }
        let iid = *iid;
        if iid == IUnknown::IID
            || iid == IAgileObject::IID
            || IUIAutomationTextEditTextChangedEventHandler_Vtbl::matches(&iid)
        {
            *interface = &self.vtable as *const _ as *mut c_void;
            self.count.add_ref();
            return HRESULT(0);
        }
        if iid == IMarshal::IID {
            return imp::marshaler(self.to_interface(), interface);
        }
        let tear_off = self.count.query(&iid, &self.vtable as *const _ as *mut _);
        if !tear_off.is_null() {
            *interface = tear_off;
            return HRESULT(0);
        }
        *interface = core::ptr::null_mut();
        imp::E_NOINTERFACE
    }

    #[inline(always)]
    fn AddRef(&self) -> u32 {
        self.count.add_ref()
    }

    #[inline(always)]
    unsafe fn Release(self_: *mut Self) -> u32 {
        let remaining = (*self_).count.release();
        if remaining == 0 {
            let _ = Box::from_raw(self_);
        }
        remaining
    }

    #[inline(always)]
    fn is_reference_count_one(&self) -> bool {
        self.count.is_one()
    }

    unsafe fn GetTrustLevel(&self, value: *mut i32) -> HRESULT {
        if value.is_null() {
            return imp::E_POINTER;
        }
        *value = 0;
        HRESULT(0)
    }

    fn to_object(&self) -> ComObject<Self::Impl> {
        self.count.add_ref();
        // SAFETY: `self` lives inside a heap-allocated `Box<UiaTextEditEventHandlerImpl>` managed
        // by `ComObject` / COM refcounting.
        unsafe { ComObject::from_raw(NonNull::new_unchecked(self as *const Self as *mut Self)) }
    }
}

impl ComObjectInner for UiaTextEditEventHandler {
    type Outer = UiaTextEditEventHandlerImpl;

    fn into_object(self) -> ComObject<Self> {
        let boxed = Box::new(UiaTextEditEventHandlerImpl {
            vtable: &UiaTextEditEventHandlerImpl::VTABLE,
            this: self,
            count: WeakRefCount::new(),
        });
        // SAFETY: Boxed COM object transferred into `ComObject` with initial refcount 1.
        unsafe { ComObject::from_raw(Box::into_non_null(boxed)) }
    }
}

impl ComObjectInterface<IUnknown> for UiaTextEditEventHandlerImpl {
    #[inline(always)]
    fn as_interface_ref(&self) -> InterfaceRef<'_, IUnknown> {
        // SAFETY: `self.vtable` starts with `IUnknown_Vtbl` (`#[repr(C)]`), matching `IUnknown`.
        unsafe { core::mem::transmute(&self.vtable) }
    }
}

impl ComObjectInterface<IUIAutomationTextEditTextChangedEventHandler>
    for UiaTextEditEventHandlerImpl
{
    #[inline(always)]
    fn as_interface_ref(
        &self,
    ) -> InterfaceRef<'_, IUIAutomationTextEditTextChangedEventHandler> {
        // SAFETY: `self.vtable` is `&'static IUIAutomationTextEditTextChangedEventHandler_Vtbl`
        // at offset 0.
        unsafe { core::mem::transmute(&self.vtable) }
    }
}

impl From<UiaTextEditEventHandler> for IUIAutomationTextEditTextChangedEventHandler {
    #[inline(always)]
    fn from(this: UiaTextEditEventHandler) -> Self {
        ComObject::new(this).into_interface()
    }
}

impl IUIAutomationTextEditTextChangedEventHandler_Impl for UiaTextEditEventHandlerImpl {
    fn HandleTextEditTextChangedEvent(
        &self,
        sender: Ref<IUIAutomationElement>,
        texteditchangetype: TextEditChangeType,
        eventstrings: *const SAFEARRAY,
    ) -> windows::core::Result<()> {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.this
                .handle_event_with_fg(sender.as_ref(), texteditchangetype, eventstrings, None);
        }));
        Ok(())
    }
}

/// Active MTA UIA subscription for `TextEditChangeType_Composition` and
/// `TextEditChangeType_CompositionFinalized` on a target window subtree (`TreeScope_Subtree`).
///
/// Registers a distinct COM handler identity per `TextEditChangeType` so
/// `IUIAutomation3::RemoveTextEditTextChangedEventHandler(root, handler)` (which takes no
/// `TextEditChangeType` argument) unambiguously detaches every registered subscription.
pub struct UiaTextEditEventSubscription {
    automation: IUIAutomation,
    automation3: IUIAutomation3,
    root: IUIAutomationElement,
    registered_handlers: Vec<IUIAutomationTextEditTextChangedEventHandler>,
    subscription_active: Arc<AtomicBool>,
    dropped_count: Arc<AtomicU64>,
    detached_or_abandoned: bool,
}

impl UiaTextEditEventSubscription {
    /// Subscribe to `TextEditChangeType_Composition` and `TextEditChangeType_CompositionFinalized`
    /// on `root` with `TreeScope_Subtree` and `cacherequest = None`.
    ///
    /// Rolls back already-registered handlers cleanly if a subsequent registration fails.
    pub fn attach(
        automation: &IUIAutomation,
        automation3: &IUIAutomation3,
        root: &IUIAutomationElement,
        gates: TextEditHookGates,
        tx: mpsc::SyncSender<RawUiaTextEditEvent>,
    ) -> windows::core::Result<Self> {
        let subscription_active = Arc::new(AtomicBool::new(true));
        let dropped_count = Arc::new(AtomicU64::new(0));
        let mut registered_handlers = Vec::with_capacity(TEXT_EDIT_SUBSCRIBED_CHANGE_TYPES.len());

        for &change_type in &TEXT_EDIT_SUBSCRIBED_CHANGE_TYPES {
            let handler: IUIAutomationTextEditTextChangedEventHandler =
                UiaTextEditEventHandler::new(
                    tx.clone(),
                    gates.clone(),
                    Arc::clone(&subscription_active),
                    Arc::clone(&dropped_count),
                )
                .into();

            // SAFETY: Valid MTA `IUIAutomation3`, target `root`, `TreeScope_Subtree`, null cache
            // request (no pre-gate property reads), and agile COM-refcounted `handler`.
            let res = unsafe {
                automation3.AddTextEditTextChangedEventHandler(
                    root,
                    TreeScope_Subtree,
                    change_type,
                    Option::<&IUIAutomationCacheRequest>::None,
                    &handler,
                )
            };
            match res {
                Ok(()) => registered_handlers.push(handler),
                Err(err) => {
                    subscription_active.store(false, Ordering::Release);
                    for registered in registered_handlers.drain(..).rev() {
                        // SAFETY: Rolling back handler just registered on the same automation3/root.
                        unsafe {
                            let _ = automation3
                                .RemoveTextEditTextChangedEventHandler(root, &registered);
                        }
                    }
                    return Err(err);
                }
            }
        }

        Ok(Self {
            automation: automation.clone(),
            automation3: automation3.clone(),
            root: root.clone(),
            registered_handlers,
            subscription_active,
            dropped_count,
            detached_or_abandoned: false,
        })
    }

    /// True while this subscription is active (neither detached nor abandoned).
    pub fn is_active(&self) -> bool {
        !self.detached_or_abandoned && self.subscription_active.load(Ordering::Acquire)
    }

    /// Number of TextEdit change-type handlers currently registered on this subscription.
    pub fn subscribed_handler_count(&self) -> usize {
        self.registered_handlers.len()
    }

    /// Total TextEdit events dropped due to bounded channel backpressure since attach.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    /// Read and reset the count of TextEdit events dropped due to bounded channel backpressure.
    pub fn take_dropped_count(&self) -> u64 {
        self.dropped_count.swap(0, Ordering::AcqRel)
    }

    /// Finish the subscription using the selected [`SubscriptionTeardown`] policy.
    pub fn finish(self, teardown: SubscriptionTeardown) {
        match teardown {
            SubscriptionTeardown::Detach => self.detach(),
            SubscriptionTeardown::AbandonForProcessExit => self.abandon_for_process_exit(),
        }
    }

    /// Unsubscribe cleanly by calling `RemoveTextEditTextChangedEventHandler` for all registered
    /// handlers using the default bounded 40ms per-call COM timeout.
    pub fn detach(mut self) {
        self.detach_in_place_with_timeout(40);
    }

    /// Unsubscribe cleanly using an explicit bounded per-call COM timeout (`1..=40` ms).
    pub fn detach_with_timeout(mut self, timeout_ms: u32) {
        self.detach_in_place_with_timeout(timeout_ms.clamp(1, 40));
    }

    /// Silence callbacks and skip remote `RemoveTextEditTextChangedEventHandler` calls on
    /// process-exit retirement to prevent COM teardown deadlocks against hung UI threads.
    pub fn abandon_for_process_exit(mut self) {
        self.detached_or_abandoned = true;
        self.subscription_active.store(false, Ordering::Release);
        self.registered_handlers.clear();
    }

    fn detach_in_place_with_timeout(&mut self, timeout_ms: u32) {
        if self.detached_or_abandoned {
            return;
        }
        self.detached_or_abandoned = true;
        self.subscription_active.store(false, Ordering::Release);
        let bounded_ms = timeout_ms.clamp(1, 40);
        // Clamp IUIAutomation2 timeouts right before remote RemoveTextEditTextChangedEventHandler
        // calls so detaching from a busy/unresponsive target window never stalls past budget.
        if let Ok(uia2) = self.automation.cast::<IUIAutomation2>() {
            // SAFETY: Bounded non-zero timeout values in milliseconds.
            unsafe {
                let _ = uia2.SetConnectionTimeout(bounded_ms);
                let _ = uia2.SetTransactionTimeout(bounded_ms);
            }
        }
        for handler in self.registered_handlers.drain(..).rev() {
            // SAFETY: Balanced with `AddTextEditTextChangedEventHandler` using the exact same
            // `root` and `handler` inside MTA COM.
            unsafe {
                let _ = self
                    .automation3
                    .RemoveTextEditTextChangedEventHandler(&self.root, &handler);
            }
        }
    }
}

impl Drop for UiaTextEditEventSubscription {
    fn drop(&mut self) {
        if !self.detached_or_abandoned {
            self.detach_in_place_with_timeout(40);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HWND, LPARAM, S_FALSE, S_OK, WPARAM};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    };
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::Accessibility::{
        CUIAutomation, CUIAutomation8, UIA_StructureChangedEventId,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, DispatchMessageW, GetMessageW, PeekMessageW,
        PostThreadMessageW, TranslateMessage, MSG, PM_NOREMOVE, WINDOW_EX_STYLE, WM_QUIT,
        WS_OVERLAPPEDWINDOW,
    };

    struct TestMtaGuard {
        should_uninit: bool,
        _uia_lock: std::sync::MutexGuard<'static, ()>,
    }

    impl TestMtaGuard {
        fn init() -> Self {
            let uia_lock = crate::uia_com::acquire_test_mta_uia_lock();
            // SAFETY: Standard MTA COM init on this test thread.
            let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            assert!(
                hr == S_OK || hr == S_FALSE,
                "CoInitializeEx(COINIT_MULTITHREADED) failed: {hr:?}"
            );
            Self {
                should_uninit: true,
                _uia_lock: uia_lock,
            }
        }
    }

    impl Drop for TestMtaGuard {
        fn drop(&mut self) {
            if self.should_uninit {
                // SAFETY: Balanced with `CoInitializeEx` in `TestMtaGuard::init`.
                unsafe {
                    CoUninitialize();
                }
            }
        }
    }

    fn create_test_automation() -> IUIAutomation {
        // SAFETY: Caller holds `TestMtaGuard` (COINIT_MULTITHREADED).
        unsafe {
            CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER)
                .or_else(|_| CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER))
                .expect("CoCreateInstance(CUIAutomation8 / CUIAutomation)")
        }
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Hidden synthetic Win32 window pumped on its own UI thread so MTA UIA calls from the test
    /// thread (`ElementFromHandle`, `AddAutomationEventHandler`, `RemoveAutomationEventHandler`)
    /// never block on an unpumped owning thread.
    struct HiddenSyntheticWindow {
        hwnd: HWND,
        thread_id: u32,
        handle: Option<JoinHandle<()>>,
    }

    impl HiddenSyntheticWindow {
        fn spawn(title: &str) -> Self {
            let title_owned = title.to_string();
            let (tx, rx) = mpsc::sync_channel::<(isize, u32)>(1);
            let handle = thread::spawn(move || {
                let class_wide = to_wide("#32770");
                let title_wide = to_wide(&title_owned);
                // SAFETY: Hidden synthetic "#32770" window owned and pumped by this thread.
                unsafe {
                    let mut init_msg = MSG::default();
                    let _ = PeekMessageW(&mut init_msg, None, 0, 0, PM_NOREMOVE);
                    let hwnd = CreateWindowExW(
                        WINDOW_EX_STYLE(0),
                        PCWSTR(class_wide.as_ptr()),
                        PCWSTR(title_wide.as_ptr()),
                        WS_OVERLAPPEDWINDOW,
                        0,
                        0,
                        240,
                        160,
                        None,
                        None,
                        None,
                        None,
                    )
                    .expect("CreateWindowExW hidden synthetic window");
                    let tid = GetCurrentThreadId();
                    let _ = tx.send((hwnd.0 as isize, tid));

                    let mut msg = MSG::default();
                    while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                    let _ = DestroyWindow(hwnd);
                }
            });
            let (raw_hwnd, thread_id) = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("hidden synthetic window startup");
            Self {
                hwnd: HWND(raw_hwnd as *mut core::ffi::c_void),
                thread_id,
                handle: Some(handle),
            }
        }
    }

    impl Drop for HiddenSyntheticWindow {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                if self.thread_id != 0 {
                    // SAFETY: Terminates the synthetic window's GetMessageW loop cleanly.
                    unsafe {
                        let _ = PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
                    }
                }
                let _ = handle.join();
            }
        }
    }

    #[test]
    fn menu_event_kind_round_trips_subscribed_ids_and_rejects_others() {
        assert_eq!(
            UiaMenuEventKind::from_event_id(UIA_MenuOpenedEventId),
            Some(UiaMenuEventKind::MenuOpened)
        );
        assert_eq!(
            UiaMenuEventKind::from_event_id(UIA_MenuClosedEventId),
            Some(UiaMenuEventKind::MenuClosed)
        );
        assert_eq!(
            UiaMenuEventKind::from_event_id(UIA_Invoke_InvokedEventId),
            Some(UiaMenuEventKind::Invoked)
        );
        assert_eq!(
            UiaMenuEventKind::from_event_id(UIA_StructureChangedEventId),
            None
        );

        for kind in [
            UiaMenuEventKind::MenuOpened,
            UiaMenuEventKind::MenuClosed,
            UiaMenuEventKind::Invoked,
        ] {
            assert_eq!(UiaMenuEventKind::from_event_id(kind.as_event_id()), Some(kind));
        }
    }

    #[test]
    fn handler_enqueues_non_blocking_respects_active_flag_and_bounds_backpressure() {
        let (tx, rx) = create_menu_event_channel();
        let active = Arc::new(AtomicBool::new(true));
        let dropped = Arc::new(AtomicU64::new(0));
        let handler: IUIAutomationEventHandler =
            UiaMenuEventHandler::new(tx, Arc::clone(&active), Arc::clone(&dropped)).into();

        // Fill all 32 slots plus 3 overflow events with null sender (valid for MenuClosed).
        for i in 0..(UIA_MENU_EVENT_CHANNEL_CAPACITY + 3) {
            let event_id = MENU_SUBSCRIBED_EVENT_IDS[i % MENU_SUBSCRIBED_EVENT_IDS.len()];
            // SAFETY: Direct COM vtable invocation on local `IUIAutomationEventHandler`.
            let res = unsafe {
                handler.HandleAutomationEvent(Option::<&IUIAutomationElement>::None, event_id)
            };
            assert!(res.is_ok(), "HandleAutomationEvent must never fail or block");
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 3);

        let mut received = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            assert!(ev.sender.is_none());
            assert!(ev.observed_unix_ms > 0);
            assert!(ev.kind().is_some());
            received.push(ev);
        }
        assert_eq!(received.len(), UIA_MENU_EVENT_CHANNEL_CAPACITY);

        // Once deactivated (detach / abandon), callbacks return Ok(()) without enqueueing.
        active.store(false, Ordering::Release);
        // SAFETY: Direct COM vtable invocation on local `IUIAutomationEventHandler`.
        let res = unsafe {
            handler.HandleAutomationEvent(
                Option::<&IUIAutomationElement>::None,
                UIA_MenuOpenedEventId,
            )
        };
        assert!(res.is_ok());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn handler_com_identity_supports_iunknown_event_handler_agile_and_marshal() {
        let _com = TestMtaGuard::init();
        let (tx, _rx) = create_menu_event_channel();
        let handler: IUIAutomationEventHandler = UiaMenuEventHandler::new(
            tx,
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicU64::new(0)),
        )
        .into();

        // Standard COM identity & MTA agility casts must succeed.
        assert!(handler.cast::<IUnknown>().is_ok());
        assert!(handler.cast::<IUIAutomationEventHandler>().is_ok());
        assert!(handler.cast::<IAgileObject>().is_ok());
        assert!(handler.cast::<IMarshal>().is_ok());
        // Unrelated interface must return E_NOINTERFACE.
        assert!(handler.cast::<IUIAutomation>().is_err());

        drop(handler);
    }

    #[test]
    fn live_mta_attach_detach_and_abandon_for_process_exit_without_deadlock() {
        let _com = TestMtaGuard::init();
        let automation = create_test_automation();
        let window = HiddenSyntheticWindow::spawn("p5a-uia-events-hidden-test");

        // SAFETY: Valid live hidden HWND pumped on dedicated UI thread; caller holds MTA COM.
        let root = unsafe { automation.ElementFromHandle(window.hwnd) }
            .expect("ElementFromHandle on hidden synthetic window");

        // 1. Attach -> explicit detach() without deadlock.
        let (tx1, _rx1) = create_menu_event_channel();
        let start_detach = Instant::now();
        let sub1 = UiaMenuEventSubscription::attach(&automation, &root, tx1)
            .expect("UiaMenuEventSubscription::attach #1");
        assert!(sub1.is_active());
        assert_eq!(sub1.subscribed_event_count(), 3);
        assert_eq!(sub1.dropped_count(), 0);
        sub1.detach();
        assert!(
            start_detach.elapsed() < Duration::from_secs(5),
            "attach+detach exceeded 5s"
        );

        // 2. Attach -> Drop-driven detach without deadlock.
        let (tx2, _rx2) = create_menu_event_channel();
        {
            let sub2 = UiaMenuEventSubscription::attach(&automation, &root, tx2)
                .expect("UiaMenuEventSubscription::attach #2");
            assert!(sub2.is_active());
            assert_eq!(sub2.subscribed_event_count(), 3);
        }

        // 3. Attach -> abandon_for_process_exit() skips remote RemoveAutomationEventHandler cleanly.
        let (tx3, rx3) = create_menu_event_channel();
        let start_abandon = Instant::now();
        let sub3 = UiaMenuEventSubscription::attach(&automation, &root, tx3)
            .expect("UiaMenuEventSubscription::attach #3");
        let handler_ref = sub3.handler.clone();
        assert!(sub3.is_active());
        sub3.abandon_for_process_exit();
        assert!(
            start_abandon.elapsed() < Duration::from_secs(5),
            "attach+abandon_for_process_exit exceeded 5s"
        );

        // Verify late callback after abandonment is silently suppressed.
        // SAFETY: Direct COM vtable invocation on local `IUIAutomationEventHandler`.
        let late_res = unsafe {
            handler_ref.HandleAutomationEvent(
                Option::<&IUIAutomationElement>::None,
                UIA_Invoke_InvokedEventId,
            )
        };
        assert!(late_res.is_ok());
        assert!(rx3.try_recv().is_err());

        // 4. Verify non-null `sender` (`IUIAutomationElement`) round-trips cleanly across MTA
        // threads via `MtaElement` with zero UIA calls inside `HandleAutomationEvent`.
        let (tx4, rx4) = create_menu_event_channel();
        let handler4: IUIAutomationEventHandler = UiaMenuEventHandler::new(
            tx4,
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicU64::new(0)),
        )
        .into();
        // SAFETY: Direct COM vtable invocation passing live MTA `root` element.
        unsafe {
            handler4
                .HandleAutomationEvent(&root, UIA_MenuOpenedEventId)
                .expect("HandleAutomationEvent with live sender");
        }
        let received = rx4.try_recv().expect("RawUiaMenuEvent with live sender");
        assert_eq!(received.kind(), Some(UiaMenuEventKind::MenuOpened));
        let mta_sender = received.sender.expect("non-null MtaElement sender");
        // Now on the worker main MTA thread, reading a property from the element succeeds.
        // SAFETY: Caller holds MTA COM (`_com`) and `window` is alive and pumping.
        let pid = unsafe { mta_sender.as_element().CurrentProcessId() }
            .expect("CurrentProcessId on received MtaElement");
        assert_eq!(pid as u32, std::process::id());
        let inner = mta_sender.into_inner();

        // Compile-time thread-safety trait assertions.
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<MtaElement>();
        assert_send::<RawUiaMenuEvent>();
        assert_send::<UiaMenuEventHandler>();
        assert_sync::<UiaMenuEventHandler>();

        // Drop COM objects strictly before `_com` (`CoUninitialize`).
        drop(inner);
        drop(handler4);
        drop(handler_ref);
        drop(root);
        drop(automation);
    }

    struct OwnedTestSafeArray(*mut SAFEARRAY);

    impl Drop for OwnedTestSafeArray {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: Owned SAFEARRAY created in unit tests via `SafeArrayCreate`.
                unsafe {
                    let _ = windows::Win32::System::Ole::SafeArrayDestroy(self.0);
                }
            }
        }
    }

    fn make_bstr_safearray(entries: &[Option<&[u16]>]) -> OwnedTestSafeArray {
        use windows::Win32::Foundation::SysAllocStringLen;
        use windows::Win32::System::Com::SAFEARRAYBOUND;
        use windows::Win32::System::Ole::{SafeArrayCreate, SafeArrayPutElement};

        let bound = SAFEARRAYBOUND {
            cElements: entries.len() as u32,
            lLbound: 0,
        };
        // SAFETY: Valid 1-D VT_BSTR SAFEARRAY creation and element population.
        unsafe {
            let psa = SafeArrayCreate(VT_BSTR, 1, &bound);
            assert!(!psa.is_null(), "SafeArrayCreate(VT_BSTR, 1) must succeed");
            for (idx, entry) in entries.iter().enumerate() {
                if let Some(wide) = entry {
                    // Always allocate a genuine OLE BSTR (including for 0-length `&[]`) and pass
                    // its raw BSTR pointer (NEVER `Deref<[u16]>::as_ptr()`, which returns a static
                    // sentinel without a BSTR length prefix for empty `BSTR::new()`).
                    let bstr = SysAllocStringLen(Some(wide));
                    let raw_ptr = bstr.into_raw();
                    let i = idx as i32;
                    let put_res = SafeArrayPutElement(psa, &i, raw_ptr as *const c_void);
                    // `SafeArrayPutElement` copies VT_BSTR; reclaim and free our local BSTR.
                    let _reclaim = BSTR::from_raw(raw_ptr);
                    put_res.expect("SafeArrayPutElement(VT_BSTR)");
                }
            }
            OwnedTestSafeArray(psa)
        }
    }

    fn make_test_text_edit_gates(bound_hwnd: isize) -> TextEditHookGates {
        TextEditHookGates {
            active: Arc::new(AtomicBool::new(true)),
            retiring: Arc::new(AtomicBool::new(false)),
            secure_input_blocked: Arc::new(AtomicBool::new(false)),
            context_ready: Arc::new(AtomicBool::new(true)),
            bound_hwnd: Arc::new(AtomicIsize::new(bound_hwnd)),
            focus_epoch: Arc::new(AtomicU64::new(1)),
            expected_focus_epoch: Arc::new(AtomicU64::new(1)),
        }
    }

    #[test]
    fn sensitive_text_zeroizes_utf8_buffer_redacts_debug_and_preserves_into_inner() {
        // 1. Verify in-place zeroization helper zeroes ASCII & multi-byte UTF-8 bytes in place.
        let mut buf = "密码secret中文".to_string();
        let original_ptr = buf.as_ptr();
        let original_len = buf.len();
        zeroize_string_in_place(&mut buf);
        assert_eq!(buf.as_ptr(), original_ptr);
        assert_eq!(buf.len(), original_len);
        assert!(buf.as_bytes().iter().all(|&b| b == 0));

        // 2. Verify `SensitiveText` accessors, redacted Debug, and `into_inner()` transfer.
        let s = SensitiveText::new("你好世界".to_string());
        assert_eq!(s.as_str(), "你好世界");
        assert!(!s.is_empty());
        assert_eq!(s.len(), "你好世界".len());
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("你好"), "Debug must redact sensitive text: {dbg}");
        assert!(dbg.contains("redacted"));

        let extracted = s.into_inner();
        assert_eq!(extracted, "你好世界");

        // 3. Empty & direct drop complete cleanly.
        let empty = SensitiveText::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.as_str(), "");
        drop(empty);

        let dropped = SensitiveText::new("ephemeral-secret".to_string());
        drop(dropped);
    }

    #[test]
    fn bstr_safearray_extracts_valid_and_cjk_saturates_over_2048_and_rejects_malformed() {
        use windows::Win32::System::Com::{ADVANCED_FEATURE_FLAGS, FADF_BSTR, SAFEARRAYBOUND};
        use windows::Win32::System::Ole::SafeArrayCreate;
        use windows::Win32::System::Variant::{VT_I2, VT_I8};

        // 1. Valid 1-D BSTR array with NULL slot + ASCII + CJK + supplementary emoji (UTF-16 pair).
        let w1: Vec<u16> = "你好".encode_utf16().collect();
        let w2: Vec<u16> = "世界🚀".encode_utf16().collect();
        let sa_cjk = make_bstr_safearray(&[None, Some(&w1), Some(&[]), Some(&w2)]);
        // SAFETY: Valid test SAFEARRAY owned by `sa_cjk`.
        let parsed = unsafe { read_bstr_safearray_bounded(sa_cjk.0) };
        assert_eq!(
            parsed,
            Some(ExtractedTextEditStrings::Text(SensitiveText::new(
                "你好世界🚀".to_string()
            )))
        );

        // 2. Exact 2048 UTF-16 code units succeeds (`saturated = false`).
        let exact_units = vec![b'a' as u16; TEXT_EDIT_MAX_CODE_UNITS];
        let sa_exact = make_bstr_safearray(&[Some(&exact_units)]);
        // SAFETY: Valid test SAFEARRAY owned by `sa_exact`.
        let parsed_exact = unsafe { read_bstr_safearray_bounded(sa_exact.0) };
        match parsed_exact {
            Some(ExtractedTextEditStrings::Text(t)) => {
                assert_eq!(t.as_str().len(), TEXT_EDIT_MAX_CODE_UNITS);
            }
            other => panic!("expected exact 2048 text, got {other:?}"),
        }

        // 2b. Multi-element array (16 segments totaling 1024 units) concatenates in a single
        // pre-sized allocation without reallocation.
        let seg: Vec<u16> = "中文テスト123".encode_utf16().collect(); // 8 units * 16 = 128 units
        let multi_entries: Vec<Option<&[u16]>> = (0..16).map(|_| Some(seg.as_slice())).collect();
        let sa_multi = make_bstr_safearray(&multi_entries);
        // SAFETY: Valid test SAFEARRAY owned by `sa_multi`.
        assert_eq!(
            unsafe { read_bstr_safearray_bounded(sa_multi.0) },
            Some(ExtractedTextEditStrings::Text(SensitiveText::new(
                "中文テスト123".repeat(16)
            )))
        );

        // 3. Over 2048 UTF-16 code units (split across 2 BSTRs) returns `Saturated`.
        let part1 = vec![0x4E2Du16; 1_500]; // '中'
        let part2 = vec![0x6587u16; 549]; // '文' -> 2049 total units
        let sa_over = make_bstr_safearray(&[Some(&part1), Some(&part2)]);
        // SAFETY: Valid test SAFEARRAY owned by `sa_over`.
        assert_eq!(
            unsafe { read_bstr_safearray_bounded(sa_over.0) },
            Some(ExtractedTextEditStrings::Saturated)
        );

        // 4. Invalid UTF-16 (unpaired surrogate) is dropped (`None`).
        let bad_utf16 = [0xD800u16, b'x' as u16];
        let sa_bad_utf16 = make_bstr_safearray(&[Some(&bad_utf16)]);
        // SAFETY: Valid test SAFEARRAY owned by `sa_bad_utf16`.
        assert_eq!(unsafe { read_bstr_safearray_bounded(sa_bad_utf16.0) }, None);

        // 5. Well-formed empty array or all-null entries returns `Empty` (distinguished from
        // malformed `None` so cancelled IME compositions reset `ime_state` cleanly).
        let sa_empty = make_bstr_safearray(&[]);
        let sa_nulls = make_bstr_safearray(&[None, None]);
        assert_eq!(
            unsafe { read_bstr_safearray_bounded(sa_empty.0) },
            Some(ExtractedTextEditStrings::Empty)
        );
        assert_eq!(
            unsafe { read_bstr_safearray_bounded(sa_nulls.0) },
            Some(ExtractedTextEditStrings::Empty)
        );

        // 6. Null pointer rejected.
        assert_eq!(unsafe { read_bstr_safearray_bounded(core::ptr::null()) }, None);

        // 7. 2-D VT_BSTR SAFEARRAY rejected (`cDims != 1`).
        let bounds_2d = [
            SAFEARRAYBOUND {
                cElements: 1,
                lLbound: 0,
            },
            SAFEARRAYBOUND {
                cElements: 1,
                lLbound: 0,
            },
        ];
        // SAFETY: Valid 2-D SAFEARRAY owned by `sa_2d`.
        let sa_2d = OwnedTestSafeArray(unsafe { SafeArrayCreate(VT_BSTR, 2, bounds_2d.as_ptr()) });
        assert!(!sa_2d.0.is_null());
        assert_eq!(unsafe { read_bstr_safearray_bounded(sa_2d.0) }, None);

        // 8. Wrong `cbElements` (`VT_I2`, 2 bytes) rejected.
        let bound_i2 = SAFEARRAYBOUND {
            cElements: 1,
            lLbound: 0,
        };
        let sa_i2 = OwnedTestSafeArray(unsafe { SafeArrayCreate(VT_I2, 1, &bound_i2) });
        assert!(!sa_i2.0.is_null());
        assert_eq!(unsafe { read_bstr_safearray_bounded(sa_i2.0) }, None);

        // 9. Wrong vartype even with pointer-width `cbElements` (`VT_I8`, 8 bytes on 64-bit) rejected!
        let bound_i8 = SAFEARRAYBOUND {
            cElements: 1,
            lLbound: 0,
        };
        let sa_i8 = OwnedTestSafeArray(unsafe { SafeArrayCreate(VT_I8, 1, &bound_i8) });
        assert!(!sa_i8.0.is_null());
        assert_eq!(unsafe { read_bstr_safearray_bounded(sa_i8.0) }, None);

        // 10. Count > 64 rejected.
        let bound_65 = SAFEARRAYBOUND {
            cElements: 65,
            lLbound: 0,
        };
        let sa_65 = OwnedTestSafeArray(unsafe { SafeArrayCreate(VT_BSTR, 1, &bound_65) });
        assert!(!sa_65.0.is_null());
        assert_eq!(unsafe { read_bstr_safearray_bounded(sa_65.0) }, None);

        // 11. Extreme i32 bounds overflow rejected cleanly via i64 arithmetic.
        let fake = SAFEARRAY {
            cDims: 1,
            fFeatures: ADVANCED_FEATURE_FLAGS(FADF_BSTR.0),
            cbElements: std::mem::size_of::<*mut u16>() as u32,
            cLocks: 0,
            pvData: core::ptr::null_mut(),
            rgsabound: [SAFEARRAYBOUND {
                cElements: u32::MAX,
                lLbound: i32::MIN,
            }],
        };
        assert_eq!(
            unsafe { read_bstr_safearray_bounded(&fake as *const SAFEARRAY) },
            None
        );
    }

    #[test]
    fn text_edit_handler_enforces_pre_gates_hwnd_match_backpressure_and_com_identity() {
        use windows::Win32::UI::Accessibility::{
            TextEditChangeType_AutoComplete, TextEditChangeType_AutoCorrect,
            TextEditChangeType_None,
        };

        let _com = TestMtaGuard::init();
        let (tx, rx) = create_text_edit_event_channel();
        let gates = make_test_text_edit_gates(0x2222);
        let sub_active = Arc::new(AtomicBool::new(true));
        let dropped = Arc::new(AtomicU64::new(0));

        let handler = UiaTextEditEventHandler::new(
            tx,
            gates.clone(),
            Arc::clone(&sub_active),
            Arc::clone(&dropped),
        );

        let cjk: Vec<u16> = "中文提交".encode_utf16().collect();
        let sa_cjk = make_bstr_safearray(&[Some(&cjk)]);

        // 1. Composition MUST NEVER inspect `event_strings` (even a deliberately bogus non-null
        // sentinel pointer or null pointer must not be dereferenced).
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_Composition,
            0x10usize as *const SAFEARRAY,
            Some(0x2222),
        );
        let ev1 = rx.try_recv().expect("Composition event");
        assert_eq!(ev1.kind, UiaTextEditEventKind::Composition);
        assert!(ev1.sender.is_none());
        assert!(ev1.observed_unix_ms > 0);

        // 2. CompositionFinalized extracts valid CJK text cleanly.
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_CompositionFinalized,
            sa_cjk.0,
            Some(0x2222),
        );
        let ev2 = rx.try_recv().expect("CompositionFinalized event");
        assert_eq!(
            ev2.kind,
            UiaTextEditEventKind::CompositionFinalized {
                text: SensitiveText::new("中文提交".to_string()),
                saturated: false,
            }
        );

        // 3. CompositionFinalized over 2048 code units emits saturated=true with empty text.
        let big = vec![0x4E2Du16; TEXT_EDIT_MAX_CODE_UNITS + 1];
        let sa_big = make_bstr_safearray(&[Some(&big)]);
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_CompositionFinalized,
            sa_big.0,
            Some(0x2222),
        );
        let ev3 = rx.try_recv().expect("Saturated CompositionFinalized");
        assert_eq!(
            ev3.kind,
            UiaTextEditEventKind::CompositionFinalized {
                text: SensitiveText::empty(),
                saturated: true,
            }
        );

        // 3b. Empty valid SAFEARRAY emits `CompositionCleared` (resets IME state without stall).
        let sa_empty = make_bstr_safearray(&[]);
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_CompositionFinalized,
            sa_empty.0,
            Some(0x2222),
        );
        assert_eq!(
            rx.try_recv().expect("CompositionCleared").kind,
            UiaTextEditEventKind::CompositionCleared
        );

        // 4. Other TextEditChangeType variants are ignored without touching `event_strings`.
        for ignored in [
            TextEditChangeType_None,
            TextEditChangeType_AutoCorrect,
            TextEditChangeType_AutoComplete,
        ] {
            handler.handle_event_with_fg(
                None,
                ignored,
                0x10usize as *const SAFEARRAY,
                Some(0x2222),
            );
        }
        assert!(rx.try_recv().is_err());

        // 5. Fast HWND mismatch / zero bound HWND blocks BEFORE touching `event_strings`.
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_CompositionFinalized,
            0x10usize as *const SAFEARRAY,
            Some(0x9999),
        );
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_CompositionFinalized,
            0x10usize as *const SAFEARRAY,
            Some(0),
        );
        gates.bound_hwnd.store(0, Ordering::Release);
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_CompositionFinalized,
            0x10usize as *const SAFEARRAY,
            Some(0x2222),
        );
        gates.bound_hwnd.store(0x2222, Ordering::Release);
        assert!(rx.try_recv().is_err());

        // 6. All atomic pre-gates block BEFORE touching `event_strings`.
        gates.secure_input_blocked.store(true, Ordering::Release);
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_CompositionFinalized,
            0x10usize as *const SAFEARRAY,
            Some(0x2222),
        );
        gates.secure_input_blocked.store(false, Ordering::Release);

        gates.retiring.store(true, Ordering::Release);
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_CompositionFinalized,
            0x10usize as *const SAFEARRAY,
            Some(0x2222),
        );
        gates.retiring.store(false, Ordering::Release);

        gates.context_ready.store(false, Ordering::Release);
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_CompositionFinalized,
            0x10usize as *const SAFEARRAY,
            Some(0x2222),
        );
        gates.context_ready.store(true, Ordering::Release);

        gates.active.store(false, Ordering::Release);
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_CompositionFinalized,
            0x10usize as *const SAFEARRAY,
            Some(0x2222),
        );
        gates.active.store(true, Ordering::Release);

        sub_active.store(false, Ordering::Release);
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_CompositionFinalized,
            0x10usize as *const SAFEARRAY,
            Some(0x2222),
        );
        sub_active.store(true, Ordering::Release);

        // 6b. `expected_focus_epoch` mismatch or zero blocks BEFORE touching `event_strings`.
        gates.focus_epoch.store(99, Ordering::Release);
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_CompositionFinalized,
            0x10usize as *const SAFEARRAY,
            Some(0x2222),
        );
        gates.focus_epoch.store(1, Ordering::Release);
        gates.expected_focus_epoch.store(0, Ordering::Release);
        handler.handle_event_with_fg(
            None,
            TextEditChangeType_CompositionFinalized,
            0x10usize as *const SAFEARRAY,
            Some(0x2222),
        );
        gates.expected_focus_epoch.store(1, Ordering::Release);
        assert!(rx.try_recv().is_err());

        // 7. Backpressure increments `dropped_count` non-blockingly.
        for _ in 0..(TEXT_EDIT_EVENT_CHANNEL_CAPACITY + 4) {
            handler.handle_event_with_fg(
                None,
                TextEditChangeType_Composition,
                core::ptr::null(),
                Some(0x2222),
            );
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 4);
        let mut drained = 0;
        while rx.try_recv().is_ok() {
            drained += 1;
        }
        assert_eq!(drained, TEXT_EDIT_EVENT_CHANNEL_CAPACITY);

        // 8. Agile MTA COM identity checks on `IUIAutomationTextEditTextChangedEventHandler`.
        let com_handler: IUIAutomationTextEditTextChangedEventHandler = handler.into();
        assert!(com_handler.cast::<IUnknown>().is_ok());
        assert!(com_handler
            .cast::<IUIAutomationTextEditTextChangedEventHandler>()
            .is_ok());
        assert!(com_handler.cast::<IAgileObject>().is_ok());
        assert!(com_handler.cast::<IMarshal>().is_ok());
        assert!(com_handler.cast::<IUIAutomation>().is_err());
        drop(com_handler);
    }

    #[test]
    fn live_mta_text_edit_attach_detach_with_timeout_and_abandon_without_deadlock() {
        let _com = TestMtaGuard::init();
        let automation = create_test_automation();
        let automation3 = automation
            .cast::<IUIAutomation3>()
            .expect("Windows 8.1+ CUIAutomation8 must support IUIAutomation3");
        let window = HiddenSyntheticWindow::spawn("p5b-uia-text-edit-hidden-test");

        // SAFETY: Valid live hidden HWND pumped on dedicated UI thread; caller holds MTA COM.
        let root = unsafe { automation.ElementFromHandle(window.hwnd) }
            .expect("ElementFromHandle on hidden synthetic window");
        let gates = make_test_text_edit_gates(window.hwnd.0 as isize);

        // 1. Attach -> explicit `detach_with_timeout` completes well under 3s with zero deadlock.
        let (tx1, _rx1) = create_text_edit_event_channel();
        let start_detach = Instant::now();
        let sub1 = UiaTextEditEventSubscription::attach(
            &automation,
            &automation3,
            &root,
            gates.clone(),
            tx1,
        )
        .expect("UiaTextEditEventSubscription::attach #1");
        assert!(sub1.is_active());
        assert_eq!(sub1.subscribed_handler_count(), 2);
        assert_eq!(sub1.dropped_count(), 0);
        sub1.detach_with_timeout(25);
        assert!(
            start_detach.elapsed() < Duration::from_secs(3),
            "TextEdit attach+detach_with_timeout exceeded 3s"
        );
        // Detaching MUST NOT clobber caller's shared `gates.active`.
        assert!(gates.active.load(Ordering::Acquire));

        // 2. Attach -> Drop-driven detach completes cleanly under 3s.
        let (tx2, _rx2) = create_text_edit_event_channel();
        let start_drop = Instant::now();
        {
            let sub2 = UiaTextEditEventSubscription::attach(
                &automation,
                &automation3,
                &root,
                gates.clone(),
                tx2,
            )
            .expect("UiaTextEditEventSubscription::attach #2");
            assert!(sub2.is_active());
            assert_eq!(sub2.subscribed_handler_count(), 2);
        }
        assert!(
            start_drop.elapsed() < Duration::from_secs(3),
            "TextEdit attach+Drop exceeded 3s"
        );

        // 3. Attach -> `abandon_for_process_exit()` skips remote COM removal and silences callbacks.
        let (tx3, rx3) = create_text_edit_event_channel();
        let start_abandon = Instant::now();
        let sub3 = UiaTextEditEventSubscription::attach(
            &automation,
            &automation3,
            &root,
            gates.clone(),
            tx3,
        )
        .expect("UiaTextEditEventSubscription::attach #3");
        let handler_ref = sub3.registered_handlers[0].clone();
        assert!(sub3.is_active());
        sub3.finish(SubscriptionTeardown::AbandonForProcessExit);
        assert!(
            start_abandon.elapsed() < Duration::from_secs(3),
            "TextEdit attach+abandon_for_process_exit exceeded 3s"
        );

        // Verify late COM callback after abandonment returns Ok(()) and enqueues nothing.
        // SAFETY: Direct COM vtable invocation on local `IUIAutomationTextEditTextChangedEventHandler`.
        let late_res = unsafe {
            handler_ref.HandleTextEditTextChangedEvent(
                &root,
                TextEditChangeType_Composition,
                core::ptr::null(),
            )
        };
        assert!(late_res.is_ok());
        assert!(rx3.try_recv().is_err());

        // Compile-time thread-safety trait assertions.
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<SensitiveText>();
        assert_send::<UiaTextEditEventKind>();
        assert_send::<RawUiaTextEditEvent>();
        assert_send::<TextEditHookGates>();
        assert_sync::<TextEditHookGates>();
        assert_send::<UiaTextEditEventHandler>();
        assert_sync::<UiaTextEditEventHandler>();

        // Drop COM objects strictly before `_com` (`CoUninitialize`).
        drop(handler_ref);
        drop(root);
        drop(automation3);
        drop(automation);
    }
}

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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, TrySendError};
use std::sync::Arc;

use windows::core::{
    imp::{self, IAgileObject, IMarshal, WeakRefCount},
    ComObject, ComObjectInner, ComObjectInterface, IUnknown, IUnknownImpl, Interface, InterfaceRef,
    Ref, GUID, HRESULT,
};
use windows::Win32::UI::Accessibility::{
    IUIAutomation, IUIAutomation2, IUIAutomationCacheRequest, IUIAutomationElement,
    IUIAutomationEventHandler, IUIAutomationEventHandler_Impl, IUIAutomationEventHandler_Vtbl,
    TreeScope_Subtree, UIA_Invoke_InvokedEventId, UIA_MenuClosedEventId, UIA_MenuOpenedEventId,
    UIA_EVENT_ID,
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

    /// Unsubscribe cleanly by calling `RemoveAutomationEventHandler` for all 3 event IDs.
    /// Appropriate for normal target window rebind or channel disable.
    pub fn detach(mut self) {
        self.detach_in_place();
    }

    /// Silence callbacks and skip remote `RemoveAutomationEventHandler` calls on process-exit
    /// retirement, matching macOS `ObserverTeardown` and preventing COM teardown deadlocks.
    pub fn abandon_for_process_exit(mut self) {
        self.detached_or_abandoned = true;
        self.active.store(false, Ordering::Release);
        self.registered_events.clear();
    }

    fn detach_in_place(&mut self) {
        if self.detached_or_abandoned {
            return;
        }
        self.detached_or_abandoned = true;
        self.active.store(false, Ordering::Release);
        // Clamp IUIAutomation2 timeouts to 40ms right before remote RemoveAutomationEventHandler
        // calls so detaching from a busy/unresponsive target window never stalls for seconds.
        if let Ok(uia2) = self.automation.cast::<IUIAutomation2>() {
            // SAFETY: Bounded non-zero timeout values in milliseconds.
            unsafe {
                let _ = uia2.SetConnectionTimeout(40);
                let _ = uia2.SetTransactionTimeout(40);
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
            self.detach_in_place();
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
}

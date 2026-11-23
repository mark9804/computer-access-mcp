use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use access_contract::utf16_len;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, SetHandleInformation, FILETIME, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    WAIT_EVENT, WAIT_FAILED, WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileAttributesW, GetFileInformationByHandle, LockFileEx, UnlockFileEx,
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, INVALID_FILE_ATTRIBUTES,
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, OPEN_ALWAYS,
};
use windows::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, CONSOLE_MODE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::IO::OVERLAPPED;
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, GetProcessId, GetProcessTimes,
    OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

use crate::protocol_model::generate_uuid_v4;

const STILL_ACTIVE_CODE: u32 = 259;
const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;

pub const VALID_FIXTURE_SCENARIOS: &[&str] = &[
    "allowed",
    "activity",
    "locked",
    "unknown",
    "workerhang",
    "empty",
    "partial",
    "value",
    "focus-loss",
    "sensitive",
    "browser",
    "readerror",
];

/// Returns true if the given Windows standard handle refers to an interactive console/TTY.
pub fn is_console_handle(std_handle: STD_HANDLE) -> bool {
    // SAFETY: Standard Win32 console probe.
    unsafe {
        let Ok(handle) = GetStdHandle(std_handle) else {
            return false;
        };
        if handle.is_invalid() || handle.0.is_null() {
            return false;
        }
        let mut mode = CONSOLE_MODE(0);
        GetConsoleMode(handle, &mut mode).is_ok()
    }
}

/// Current WTS session ID for this process.
pub fn current_wts_session_id() -> Option<u32> {
    let mut sid: u32 = u32::MAX;
    // SAFETY: Valid output pointer and current PID.
    let ok = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut sid).is_ok() };
    if ok && sid != u32::MAX {
        Some(sid)
    } else {
        None
    }
}

/// Canonical Windows `osSessionId` (`wts-<sessionId>`).
pub fn os_session_id() -> Option<String> {
    current_wts_session_id().map(|id| format!("wts-{id}"))
}

/// Canonical Windows `desktopId` (`winsta0-default-wts-<sessionId>`).
pub fn desktop_id() -> Option<String> {
    os_session_id().map(|sid| format!("winsta0-default-{sid}"))
}

/// Look up the parent process ID of the current process via ToolHelp32 snapshot.
pub fn parent_pid() -> Option<u32> {
    // SAFETY: Standard Win32 ToolHelp32 process snapshot, handle closed before return.
    unsafe {
        let current = GetCurrentProcessId();
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = None;
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == current {
                    if entry.th32ParentProcessID > 1 {
                        found = Some(entry.th32ParentProcessID);
                    }
                    break;
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
        found
    }
}

/// Returns true iff `pid > 1` refers to a currently running process.
pub fn is_pid_alive(pid: u32) -> bool {
    if pid <= 1 {
        return false;
    }
    // SAFETY: OpenProcess handle is closed before returning.
    unsafe {
        if let Ok(handle) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) {
            let alive = WaitForSingleObject(handle, 0) == WAIT_TIMEOUT;
            let _ = CloseHandle(handle);
            return alive;
        }
        if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            let mut code: u32 = 0;
            let alive = GetExitCodeProcess(handle, &mut code).is_ok() && code == STILL_ACTIVE_CODE;
            let _ = CloseHandle(handle);
            return alive;
        }
        false
    }
}

/// Returns `true` iff a `WaitForSingleObject(..., 0)` status confirms a process is still running.
/// Strictly treats `WAIT_OBJECT_0`, `WAIT_FAILED`, and any other status as exited/not-alive.
pub fn is_wait_status_alive(wait_status: WAIT_EVENT) -> bool {
    wait_status == WAIT_TIMEOUT
}

/// Returns `true` iff `parent_creation_100ns` is non-zero and not newer than `self_creation_100ns`,
/// rejecting recycled PIDs spawned after the current process started.
pub fn is_valid_parent_creation_time(parent_creation_100ns: u64, self_creation_100ns: u64) -> bool {
    parent_creation_100ns > 0
        && self_creation_100ns > 0
        && parent_creation_100ns <= self_creation_100ns
}

fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

fn query_process_creation_time_100ns(handle: HANDLE) -> Option<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: Valid process handle and output FILETIME pointers.
    let ok = unsafe {
        GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok()
    };
    if !ok {
        return None;
    }
    let raw = filetime_to_u64(creation);
    (raw > 0).then_some(raw)
}

/// Stable kernel handle to the owning parent process (prevents PID-reuse races).
/// Never falls back to polling static `th32ParentProcessID`.
pub struct ParentProcessHandle {
    pid: u32,
    handle: HANDLE,
}

// SAFETY: Win32 process HANDLEs are process-wide kernel objects safe to wait on from any thread.
unsafe impl Send for ParentProcessHandle {}
unsafe impl Sync for ParentProcessHandle {}

impl ParentProcessHandle {
    /// Open and verify a kernel handle to `pid` requiring BOTH `SYNCHRONIZE` and
    /// `PROCESS_QUERY_LIMITED_INFORMATION`, confirming `parent_creation_time <= self_creation_time`
    /// and `WaitForSingleObject(handle, 0) == WAIT_TIMEOUT`. Fails closed (`None`) on any error,
    /// PID reuse, or `WAIT_FAILED`.
    pub fn open(pid: u32) -> Option<Self> {
        if pid <= 1 {
            return None;
        }
        // SAFETY: OpenProcess returns an owned kernel handle closed on error or Drop.
        let handle = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid,
            )
            .ok()?
        };
        let parent_creation = query_process_creation_time_100ns(handle);
        // SAFETY: GetCurrentProcess returns the current-process pseudo-handle.
        let self_creation = query_process_creation_time_100ns(unsafe { GetCurrentProcess() });
        let valid_creation = matches!(
            (parent_creation, self_creation),
            (Some(parent_ct), Some(self_ct)) if is_valid_parent_creation_time(parent_ct, self_ct)
        );
        // SAFETY: Valid SYNCHRONIZE handle.
        let alive = valid_creation && is_wait_status_alive(unsafe { WaitForSingleObject(handle, 0) });
        if !alive {
            unsafe {
                let _ = CloseHandle(handle);
            }
            return None;
        }
        Some(Self { pid, handle })
    }

    /// Adopt and validate an inherited duplicated parent process handle (`SYNCHRONIZE |
    /// PROCESS_QUERY_LIMITED_INFORMATION`), clearing `HANDLE_FLAG_INHERIT` and confirming
    /// `parent_creation_time <= self_creation_time` and `WaitForSingleObject(handle, 0) == WAIT_TIMEOUT`.
    pub fn from_inherited_handle(raw_handle: isize) -> Option<Self> {
        if raw_handle == 0 || raw_handle == INVALID_HANDLE_VALUE.0 as isize {
            return None;
        }
        let handle = HANDLE(raw_handle as *mut core::ffi::c_void);
        // SAFETY: Probe handle validity and liveness before taking ownership.
        let wait_status = unsafe { WaitForSingleObject(handle, 0) };
        if wait_status == WAIT_FAILED {
            return None;
        }
        if !is_wait_status_alive(wait_status) {
            unsafe {
                let _ = CloseHandle(handle);
            }
            return None;
        }
        // Clear inherit flag so grandchild processes cannot inherit the parent handle.
        // SAFETY: Valid kernel handle.
        unsafe {
            let _ = SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, Default::default());
        }
        // SAFETY: Valid kernel handle; returns 0 if not a process handle or lacks query access.
        let pid = unsafe { GetProcessId(handle) };
        let parent_creation = query_process_creation_time_100ns(handle);
        // SAFETY: GetCurrentProcess returns the current-process pseudo-handle.
        let self_creation = query_process_creation_time_100ns(unsafe { GetCurrentProcess() });
        let valid_process = pid > 1
            && matches!(
                (parent_creation, self_creation),
                (Some(parent_ct), Some(self_ct)) if is_valid_parent_creation_time(parent_ct, self_ct)
            );
        if !valid_process || !is_wait_status_alive(unsafe { WaitForSingleObject(handle, 0) }) {
            unsafe {
                let _ = CloseHandle(handle);
            }
            return None;
        }
        Some(Self { pid, handle })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn is_alive(&self) -> bool {
        // SAFETY: Handle stays valid until Drop; treats WAIT_OBJECT_0 and WAIT_FAILED as dead.
        is_wait_status_alive(unsafe { WaitForSingleObject(self.handle, 0) })
    }
}

impl Drop for ParentProcessHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() && !self.handle.0.is_null() {
            // SAFETY: Owned handle opened in `open` or adopted in `from_inherited_handle`.
            unsafe {
                let _ = CloseHandle(self.handle);
            }
            self.handle = HANDLE::default();
        }
    }
}

/// Format a process's creation time from `GetProcessTimes` as `unix-ms:<int>.<3digits>`.
pub fn process_start_time_for_pid(pid: u32) -> Option<String> {
    if pid <= 1 {
        return None;
    }
    // SAFETY: OpenProcess handle closed before returning.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let ok = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok();
        let _ = CloseHandle(handle);
        if !ok {
            return None;
        }
        filetime_to_process_start_time(creation)
    }
}

pub fn filetime_to_process_start_time(ft: FILETIME) -> Option<String> {
    let raw_100ns = ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64);
    if raw_100ns <= WINDOWS_TO_UNIX_EPOCH_100NS {
        return None;
    }
    let unix_100ns = raw_100ns - WINDOWS_TO_UNIX_EPOCH_100NS;
    let whole_ms = unix_100ns / 10_000;
    let frac_thousandths = (unix_100ns % 10_000) / 10;
    if whole_ms == 0 && frac_thousandths == 0 {
        return None;
    }
    Some(format!("unix-ms:{whole_ms}.{frac_thousandths:03}"))
}

fn to_wide_null(path: &Path) -> Vec<u16> {
    OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn is_reparse_point(path: &Path) -> bool {
    let wide = to_wide_null(path);
    // SAFETY: Null-terminated UTF-16 path.
    let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerLockError {
    Session,
    Path,
    Busy,
}

/// Exclusive per-session OS lock preventing concurrent collector instances.
/// Uses Win32 `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY)` without unlinking on release.
pub struct OwnerLock {
    handle: HANDLE,
    pub session_id: String,
    pub lock_path: PathBuf,
}

// SAFETY: Win32 file HANDLE owned exclusively by OwnerLock.
unsafe impl Send for OwnerLock {}

impl OwnerLock {
    pub fn acquire(fixture: bool, fixture_lock_id: Option<&str>) -> Result<Self, OwnerLockError> {
        let (session_id, dir, file_name) = if fixture {
            let lock_id = fixture_lock_id
                .map(ToString::to_string)
                .unwrap_or_else(generate_uuid_v4);
            let session = format!("fixture-{lock_id}");
            let temp_dir = env::temp_dir();
            (
                session,
                temp_dir,
                format!("dsh-computer-access-fixture-{lock_id}.lock"),
            )
        } else {
            let sid = current_wts_session_id().ok_or(OwnerLockError::Session)?;
            let session = format!("wts-{sid}");
            let base = env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .ok_or(OwnerLockError::Path)?;
            let dir = base.join("computer-access-mcp");
            (session, dir, format!("collector-wts-{sid}.lock"))
        };

        if !dir.exists() {
            fs::create_dir_all(&dir).map_err(|_| OwnerLockError::Path)?;
        }
        if is_reparse_point(&dir) {
            return Err(OwnerLockError::Path);
        }

        let lock_path = dir.join(file_name);
        if is_reparse_point(&lock_path) {
            return Err(OwnerLockError::Path);
        }

        let wide = to_wide_null(&lock_path);
        // SAFETY: Null-terminated UTF-16 path; handle checked and closed on error/Drop.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
            .map_err(|_| OwnerLockError::Path)?
        };
        if handle == INVALID_HANDLE_VALUE || handle.0.is_null() {
            return Err(OwnerLockError::Path);
        }

        // Verify handle is a regular non-reparse file with single link.
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: Valid file handle and output struct.
        let info_ok = unsafe { GetFileInformationByHandle(handle, &mut info).is_ok() };
        if !info_ok
            || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0
            || info.nNumberOfLinks > 1
        {
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Err(OwnerLockError::Path);
        }

        let mut overlapped = OVERLAPPED::default();
        // SAFETY: Valid file handle and zeroed OVERLAPPED for non-blocking exclusive byte-0 lock.
        let locked = unsafe {
            LockFileEx(
                handle,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                Some(0),
                1,
                0,
                &mut overlapped,
            )
            .is_ok()
        };
        if !locked {
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Err(OwnerLockError::Busy);
        }

        Ok(Self {
            handle,
            session_id,
            lock_path,
        })
    }
}

impl Drop for OwnerLock {
    fn drop(&mut self) {
        let mut overlapped = OVERLAPPED::default();
        // SAFETY: Unlock and close owned file handle without unlinking lock file.
        unsafe {
            let _ = UnlockFileEx(self.handle, Some(0), 1, 0, &mut overlapped);
            let _ = CloseHandle(self.handle);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliOptions {
    pub fixture: bool,
    pub worker: bool,
    pub session_worker: bool,
    pub owner: String,
    pub instance: String,
    pub device: String,
    pub scenario: String,
    pub fixture_lock: Option<String>,
    pub worker_parent_pid: Option<u32>,
    pub worker_token: Option<String>,
}

impl CliOptions {
    pub fn valid_id(id: &str) -> bool {
        !id.is_empty()
            && utf16_len(id) <= 96
            && !id.chars().any(|c| (c as u32) < 0x20)
    }

    pub fn valid_fixture_lock_id(lock: &str) -> bool {
        !lock.is_empty()
            && lock.len() <= 64
            && lock
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }

    pub fn parse(args: &[String]) -> Option<Self> {
        Self::parse_with_context(
            args,
            parent_pid(),
            env::var("DSH_COLLECTOR_WORKER_TOKEN").ok().as_deref(),
            !is_console_handle(STD_INPUT_HANDLE) && !is_console_handle(STD_OUTPUT_HANDLE),
        )
    }

    pub fn parse_with_context(
        args: &[String],
        actual_parent_pid: Option<u32>,
        env_worker_token: Option<&str>,
        stdio_non_tty: bool,
    ) -> Option<Self> {
        let mode = args.first()?.as_str();
        if !matches!(mode, "--serve" | "--fixture" | "--ax-worker") {
            return None;
        }
        let worker = mode == "--ax-worker";
        let mut values = std::collections::HashMap::<&str, &str>::new();
        let mut index = 1;
        while index < args.len() {
            let key = args[index].as_str();
            if !matches!(
                key,
                "--owner-id"
                    | "--instance-id"
                    | "--device-id"
                    | "--fixture-scenario"
                    | "--fixture-lock-id"
                    | "--parent-pid"
                    | "--worker-token"
                    | "--synthetic"
                    | "--session-worker"
            ) || index + 1 >= args.len()
                || values.contains_key(key)
            {
                return None;
            }
            values.insert(key, args[index + 1].as_str());
            index += 2;
        }

        if worker {
            let expected_parent: u32 = values.get("--parent-pid")?.parse().ok()?;
            if expected_parent <= 1 || actual_parent_pid != Some(expected_parent) {
                return None;
            }
            let token = *values.get("--worker-token")?;
            if token.len() != 36 || env_worker_token != Some(token) || !stdio_non_tty {
                return None;
            }
            if values.contains_key("--owner-id")
                || values.contains_key("--instance-id")
                || values.contains_key("--device-id")
                || values.contains_key("--fixture-lock-id")
            {
                return None;
            }
            let synthetic = match values.get("--synthetic").copied() {
                None => false,
                Some("yes") => true,
                Some(_) => return None,
            };
            let session_worker = match values.get("--session-worker").copied() {
                None => false,
                Some("yes") => true,
                Some(_) => return None,
            };
            if synthetic && session_worker {
                return None;
            }
            let scenario = values.get("--fixture-scenario").copied().unwrap_or("allowed");
            if !VALID_FIXTURE_SCENARIOS.contains(&scenario) {
                return None;
            }
            return Some(Self {
                fixture: synthetic,
                worker: true,
                session_worker,
                owner: String::new(),
                instance: String::new(),
                device: String::new(),
                scenario: scenario.to_string(),
                fixture_lock: None,
                worker_parent_pid: Some(expected_parent),
                worker_token: Some(token.to_string()),
            });
        }

        let owner = *values.get("--owner-id")?;
        let instance = *values.get("--instance-id")?;
        let device = *values.get("--device-id")?;
        if !Self::valid_id(owner)
            || !Self::valid_id(instance)
            || !Self::valid_id(device)
            || values.contains_key("--parent-pid")
            || values.contains_key("--worker-token")
            || values.contains_key("--synthetic")
            || values.contains_key("--session-worker")
        {
            return None;
        }
        let fixture = mode == "--fixture";
        let scenario = values.get("--fixture-scenario").copied().unwrap_or("allowed");
        if !VALID_FIXTURE_SCENARIOS.contains(&scenario) {
            return None;
        }
        if !fixture
            && (values.contains_key("--fixture-scenario")
                || values.contains_key("--fixture-lock-id"))
        {
            return None;
        }
        let fixture_lock = match values.get("--fixture-lock-id").copied() {
            None => None,
            Some(lock) => {
                if !Self::valid_fixture_lock_id(lock) {
                    return None;
                }
                Some(lock.to_string())
            }
        };

        Some(Self {
            fixture,
            worker: false,
            session_worker: false,
            owner: owner.to_string(),
            instance: instance.to_string(),
            device: device.to_string(),
            scenario: scenario.to_string(),
            fixture_lock,
            worker_parent_pid: None,
            worker_token: None,
        })
    }
}

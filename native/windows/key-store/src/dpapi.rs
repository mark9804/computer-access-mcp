use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};

use windows::core::{Error as WinError, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, E_ACCESSDENIED, ERROR_ACCESS_DENIED,
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER,
    ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION, FALSE, HANDLE, HLOCAL, NTE_BAD_KEY_STATE,
    WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, CryptProtectData, CryptUnprotectData, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileDispositionInfo, FlushFileBuffers,
    GetFileInformationByHandle, GetFinalPathNameByHandleW, MoveFileExW,
    SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, CREATE_NEW, DELETE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GETFINALPATHNAMEBYHANDLE_FLAGS, MOVE_FILE_FLAGS, OPEN_EXISTING, VOLUME_NAME_DOS,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::request::{Command, KeyStoreRequest};
use crate::response::KeyStoreResponse;
use crate::zeroize::{zeroize_slice, ZeroizingKey};

pub const DPAPI_KEY_FILENAME: &str = "master.key.dpapi";
pub const MAX_DPAPI_BLOB_BYTES: usize = 8192;
const MAX_FINAL_PATH_UTF16_UNITS: u32 = 32_768;

struct HandleGuard(HANDLE);

impl HandleGuard {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: `self.0` is an owned Win32 HANDLE opened by CreateFileW or OpenProcessToken.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

struct LocalMemGuard {
    ptr: *mut u8,
    len: usize,
    zero_on_drop: bool,
}

impl Drop for LocalMemGuard {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            if self.zero_on_drop && self.len > 0 {
                // SAFETY: `ptr` points to `len` valid writable bytes allocated by CryptUnprotectData.
                let slice = unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) };
                zeroize_slice(slice);
            }
            // SAFETY: `ptr` was allocated by Win32 with LocalAlloc and must be freed via LocalFree.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.ptr.cast()))) };
        }
    }
}

struct LocalWideStringGuard(PWSTR);

impl Drop for LocalWideStringGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by ConvertSidToStringSidW and must be freed via LocalFree.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0 .0.cast()))) };
        }
    }
}

struct RestrictedSecurityDescriptor {
    sd: PSECURITY_DESCRIPTOR,
}

impl RestrictedSecurityDescriptor {
    /// Builds a protected DACL granting full control only to the current process user SID,
    /// `SYSTEM` (`SY`), and `BUILTIN\Administrators` (`BA`), blocking inherited ACEs (`D:P`).
    fn for_current_user(phase: &'static str) -> Result<Self, KeyStoreResponse> {
        let user_sid = current_process_user_sid_string(phase)?;
        if !is_safe_sddl_sid(&user_sid) {
            return Err(KeyStoreResponse::error(Some(phase), None));
        }

        let mut sddl = format!("D:P(A;OICI;FA;;;{user_sid})");
        if !user_sid.eq_ignore_ascii_case("S-1-5-18") {
            sddl.push_str("(A;OICI;FA;;;SY)");
        }
        if !user_sid.eq_ignore_ascii_case("S-1-5-32-544") {
            sddl.push_str("(A;OICI;FA;;;BA)");
        }

        let mut wide: Vec<u16> = sddl.encode_utf16().collect();
        wide.push(0);

        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated UTF-16 SDDL; on success `sd` is allocated with LocalAlloc
        // and immediately owned by `RestrictedSecurityDescriptor` which frees it with LocalFree on Drop.
        if let Err(err) = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
        } {
            return Err(map_win_error(&err, phase));
        }
        if sd.0.is_null() {
            return Err(KeyStoreResponse::error(Some(phase), None));
        }
        Ok(Self { sd })
    }

    fn as_security_attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.sd.0,
            bInheritHandle: FALSE,
        }
    }
}

impl Drop for RestrictedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.sd.0.is_null() {
            // SAFETY: `self.sd` was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.sd.0))) };
        }
    }
}

struct VerifiedDataRoot {
    /// Holds `data_root` open without `FILE_SHARE_DELETE` so neither `data_root`
    /// nor any ancestor directory can be renamed or swapped while the request runs.
    _dir_handle: HandleGuard,
    /// Normalized canonical path (`\\?\C:\...`, no trailing backslash) returned by
    /// `GetFinalPathNameByHandleW(..., FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)`.
    canonical_path: String,
    volume_serial: u32,
    file_index_high: u32,
    file_index_low: u32,
}

struct TempFileGuard {
    canonical_data_root: String,
    temp_name: String,
    armed: bool,
}

impl TempFileGuard {
    fn new(canonical_data_root: String, temp_name: String) -> Self {
        Self {
            canonical_data_root,
            temp_name,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = delete_verified_file(&self.canonical_data_root, &self.temp_name, "add", "add");
        }
    }
}

fn to_wide_null(path: &Path) -> Vec<u16> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    wide
}

fn to_wide_null_str(s: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = s.encode_utf16().collect();
    wide.push(0);
    wide
}

fn is_safe_sddl_sid(sid: &str) -> bool {
    sid.starts_with("S-")
        && sid.len() >= 5
        && sid.len() <= 256
        && sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
}

fn current_process_user_sid_string(phase: &'static str) -> Result<String, KeyStoreResponse> {
    let mut token_raw = HANDLE::default();
    // SAFETY: `GetCurrentProcess()` returns a pseudo-handle valid for the current process;
    // on success `token_raw` is immediately wrapped in `HandleGuard`.
    if let Err(err) = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_raw) }
    {
        return Err(map_win_error(&err, phase));
    }
    let token = HandleGuard(token_raw);

    let mut needed = 0u32;
    // SAFETY: querying required buffer size with None buffer.
    let first = unsafe { GetTokenInformation(token.raw(), TokenUser, None, 0, &mut needed) };
    if let Err(err) = first {
        if WIN32_ERROR::from_error(&err) != Some(ERROR_INSUFFICIENT_BUFFER) {
            return Err(map_win_error(&err, phase));
        }
    }
    if (needed as usize) < std::mem::size_of::<TOKEN_USER>() || needed > 65_536 {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

    // Allocate pointer-aligned storage for TOKEN_USER and trailing SID bytes.
    let word_count = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut storage = vec![0usize; word_count];
    let mut returned = 0u32;
    // SAFETY: `storage` is properly aligned for `TOKEN_USER` and at least `needed` bytes long.
    if let Err(err) = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            Some(storage.as_mut_ptr().cast::<c_void>()),
            needed,
            &mut returned,
        )
    } {
        return Err(map_win_error(&err, phase));
    }
    if (returned as usize) < std::mem::size_of::<TOKEN_USER>() {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

    // SAFETY: `storage` was initialized by `GetTokenInformation(TokenUser)` and is properly aligned.
    let token_user = unsafe { &*(storage.as_ptr().cast::<TOKEN_USER>()) };
    let mut sid_pwstr = PWSTR::null();
    // SAFETY: `token_user.User.Sid` points into `storage` which lives for the duration of this call;
    // on success `sid_pwstr` is owned by `LocalWideStringGuard` and freed via `LocalFree`.
    if let Err(err) = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_pwstr) } {
        return Err(map_win_error(&err, phase));
    }
    let _sid_guard = LocalWideStringGuard(sid_pwstr);
    if sid_pwstr.is_null() {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

    // SAFETY: `sid_pwstr` is a valid NUL-terminated UTF-16 string allocated by ConvertSidToStringSidW.
    unsafe { sid_pwstr.to_string() }.map_err(|_| KeyStoreResponse::error(Some(phase), None))
}

fn extract_os_status(err: &WinError) -> i32 {
    if let Some(win32) = WIN32_ERROR::from_error(err) {
        win32.0 as i32
    } else {
        err.code().0
    }
}

fn is_not_found_win32(err: WIN32_ERROR) -> bool {
    err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND
}

fn is_not_found_error(err: &WinError) -> bool {
    matches!(WIN32_ERROR::from_error(err), Some(w) if is_not_found_win32(w))
}

fn is_already_exists_error(err: &WinError) -> bool {
    matches!(
        WIN32_ERROR::from_error(err),
        Some(w) if w == ERROR_ALREADY_EXISTS || w == ERROR_FILE_EXISTS
    )
}

fn is_sharing_violation_error(err: &WinError) -> bool {
    WIN32_ERROR::from_error(err) == Some(ERROR_SHARING_VIOLATION)
}

fn is_denied_error(err: &WinError) -> bool {
    if let Some(w) = WIN32_ERROR::from_error(err) {
        if w == ERROR_ACCESS_DENIED {
            return true;
        }
    }
    err.code() == NTE_BAD_KEY_STATE || err.code() == E_ACCESSDENIED
}

fn map_win_error(err: &WinError, phase: &'static str) -> KeyStoreResponse {
    let code = extract_os_status(err);
    if is_denied_error(err) {
        KeyStoreResponse::denied(phase, Some(code))
    } else {
        KeyStoreResponse::error(Some(phase), Some(code))
    }
}

fn map_win32_error(err: WIN32_ERROR, phase: &'static str) -> KeyStoreResponse {
    let code = err.0 as i32;
    if err == ERROR_ACCESS_DENIED {
        KeyStoreResponse::denied(phase, Some(code))
    } else {
        KeyStoreResponse::error(Some(phase), Some(code))
    }
}

fn map_io_error(err: &std::io::Error, phase: &'static str) -> KeyStoreResponse {
    let code = err.raw_os_error();
    if code == Some(ERROR_ACCESS_DENIED.0 as i32) {
        KeyStoreResponse::denied(phase, code)
    } else {
        KeyStoreResponse::error(Some(phase), code)
    }
}

fn normalize_final_path(mut path: String) -> String {
    while path.len() > 7 && path.ends_with('\\') {
        path.pop();
    }
    path
}

fn paths_equal_ci(a: &str, b: &str) -> bool {
    a == b || a.to_lowercase() == b.to_lowercase()
}

fn split_parent_and_leaf(final_path: &str) -> Option<(&str, &str)> {
    let idx = final_path.rfind('\\')?;
    let parent = &final_path[..idx];
    let leaf = &final_path[idx + 1..];
    if parent.is_empty() || leaf.is_empty() {
        return None;
    }
    Some((parent, leaf))
}

fn canonical_drive_prefix(data_root: &Path) -> Option<String> {
    match data_root.components().next()? {
        Component::Prefix(p) => match p.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => {
                let letter = (drive as char).to_ascii_uppercase();
                if letter.is_ascii_alphabetic() {
                    Some(format!("\\\\?\\{letter}:"))
                } else {
                    None
                }
            }
            _ => None,
        },
        _ => None,
    }
}

/// Enumerates every directory component from the first segment under the drive root
/// down to `data_root` itself (inclusive), in top-down order.
fn ancestor_chain(data_root: &Path) -> Vec<PathBuf> {
    let mut chain = Vec::new();
    let mut current = PathBuf::new();
    for comp in data_root.components() {
        match comp {
            Component::Prefix(p) => current.push(p.as_os_str()),
            Component::RootDir => current.push(Component::RootDir.as_os_str()),
            Component::Normal(seg) => {
                current.push(seg);
                chain.push(current.clone());
            }
            Component::CurDir | Component::ParentDir => {}
        }
    }
    chain
}

fn get_final_path_name(handle: HANDLE, phase: &'static str) -> Result<String, KeyStoreResponse> {
    let flags = GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0);
    // SAFETY: `handle` is a valid open Win32 handle; querying required UTF-16 buffer size.
    let required = unsafe { GetFinalPathNameByHandleW(handle, &mut [], flags) };
    if required == 0 {
        // SAFETY: immediately reading thread-local Win32 error after GetFinalPathNameByHandleW failure.
        let err = unsafe { GetLastError() };
        return Err(map_win32_error(err, phase));
    }
    if required > MAX_FINAL_PATH_UTF16_UNITS {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

    let mut buf = vec![0u16; required as usize];
    // SAFETY: `buf` has space for `required` UTF-16 code units.
    let written = unsafe { GetFinalPathNameByHandleW(handle, &mut buf, flags) };
    if written == 0 {
        // SAFETY: immediately reading thread-local Win32 error after GetFinalPathNameByHandleW failure.
        let err = unsafe { GetLastError() };
        return Err(map_win32_error(err, phase));
    }
    if written >= required {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

    let raw = String::from_utf16(&buf[..written as usize])
        .map_err(|_| KeyStoreResponse::error(Some(phase), None))?;
    Ok(normalize_final_path(raw))
}

/// Verifies an already-opened regular file handle is NOT a reparse point or directory,
/// and that its canonical `GetFinalPathNameByHandleW` parent directory exactly matches
/// `canonical_data_root` (case-insensitive) with leaf filename equal to `expected_filename`.
fn verify_handle_under_canonical_dir(
    handle: HANDLE,
    canonical_data_root: &str,
    expected_filename: &str,
    phase: &'static str,
) -> Result<BY_HANDLE_FILE_INFORMATION, KeyStoreResponse> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is a valid open file handle and `info` is valid writable memory.
    if let Err(err) = unsafe { GetFileInformationByHandle(handle, &mut info) } {
        return Err(map_win_error(&err, phase));
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0
    {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

    let final_path = get_final_path_name(handle, phase)?;
    let Some((parent, leaf)) = split_parent_and_leaf(&final_path) else {
        return Err(KeyStoreResponse::error(Some(phase), None));
    };
    if !paths_equal_ci(parent, canonical_data_root) || !paths_equal_ci(leaf, expected_filename) {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

    Ok(info)
}

fn open_dir_handle_no_reparse(
    dir_path: &Path,
    share_mode: FILE_SHARE_MODE,
    phase: &'static str,
) -> Result<Option<HandleGuard>, KeyStoreResponse> {
    let wide = to_wide_null(dir_path);
    // SAFETY: `wide` is a NUL-terminated UTF-16 path; on success handle is immediately wrapped in `HandleGuard`.
    match unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            share_mode,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(h) => Ok(Some(HandleGuard(h))),
        Err(err) if is_not_found_error(&err) => Ok(None),
        Err(err) => Err(map_win_error(&err, phase)),
    }
}

fn inspect_and_verify_dir_handle(
    handle: HANDLE,
    expected_parent: &str,
    phase: &'static str,
) -> Result<(String, BY_HANDLE_FILE_INFORMATION), KeyStoreResponse> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is a valid open directory handle and `info` is valid writable memory.
    if let Err(err) = unsafe { GetFileInformationByHandle(handle, &mut info) } {
        return Err(map_win_error(&err, phase));
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0) == 0
    {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

    let final_path = get_final_path_name(handle, phase)?;
    let Some((parent, _leaf)) = split_parent_and_leaf(&final_path) else {
        return Err(KeyStoreResponse::error(Some(phase), None));
    };
    if !paths_equal_ci(parent, expected_parent) {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

    Ok((final_path, info))
}

/// Walks every existing ancestor of `data_root` and `data_root` itself top-down via open
/// directory handles (`FILE_FLAG_OPEN_REPARSE_POINT`), rejecting any reparse point, non-directory,
/// or ancestor redirection. Returns `Ok(None)` if an ancestor or `data_root` is missing (with all
/// existing higher ancestors verified safe), or `Ok(Some(VerifiedDataRoot))` keeping `data_root`
/// open without `FILE_SHARE_DELETE`.
fn open_verified_existing_data_root(
    data_root: &Path,
    phase: &'static str,
) -> Result<Option<VerifiedDataRoot>, KeyStoreResponse> {
    let Some(mut expected_parent) = canonical_drive_prefix(data_root) else {
        return Err(KeyStoreResponse::error(Some(phase), None));
    };
    let chain = ancestor_chain(data_root);
    if chain.is_empty() {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

    let last_idx = chain.len() - 1;
    for (idx, dir) in chain.iter().enumerate() {
        let is_leaf = idx == last_idx;
        let share_mode = if is_leaf {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        } else {
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        };
        let Some(guard) = open_dir_handle_no_reparse(dir, share_mode, phase)? else {
            return Ok(None);
        };
        let (final_path, info) =
            inspect_and_verify_dir_handle(guard.raw(), &expected_parent, phase)?;
        expected_parent = final_path;

        if is_leaf {
            return Ok(Some(VerifiedDataRoot {
                _dir_handle: guard,
                canonical_path: expected_parent,
                volume_serial: info.dwVolumeSerialNumber,
                file_index_high: info.nFileIndexHigh,
                file_index_low: info.nFileIndexLow,
            }));
        }
    }

    Err(KeyStoreResponse::error(Some(phase), None))
}

/// Creates `data_root` recursively top-down using `sd` on every newly created directory,
/// while verifying each ancestor handle against reparse points and redirection, and returns
/// a pinned `VerifiedDataRoot`.
fn ensure_data_root(
    data_root: &Path,
    sd: &RestrictedSecurityDescriptor,
) -> Result<VerifiedDataRoot, KeyStoreResponse> {
    let Some(mut expected_parent) = canonical_drive_prefix(data_root) else {
        return Err(KeyStoreResponse::error(Some("add"), None));
    };
    let chain = ancestor_chain(data_root);
    if chain.is_empty() {
        return Err(KeyStoreResponse::error(Some("add"), None));
    }

    let sa = sd.as_security_attributes();
    let last_idx = chain.len() - 1;

    for (idx, dir) in chain.iter().enumerate() {
        let is_leaf = idx == last_idx;
        let share_mode = if is_leaf {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        } else {
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        };

        let guard = match open_dir_handle_no_reparse(dir, share_mode, "add")? {
            Some(existing) => existing,
            None => {
                let Some(seg) = dir.file_name().and_then(|s| s.to_str()) else {
                    return Err(KeyStoreResponse::error(Some("add"), None));
                };
                let create_target = format!("{expected_parent}\\{seg}");
                let create_wide = to_wide_null_str(&create_target);
                // SAFETY: `create_wide` is NUL-terminated UTF-16 under the verified canonical parent;
                // `sa` points to a valid restricted protected SECURITY_DESCRIPTOR.
                if let Err(create_err) =
                    unsafe { CreateDirectoryW(PCWSTR(create_wide.as_ptr()), Some(&sa)) }
                {
                    if !is_already_exists_error(&create_err) {
                        return Err(map_win_error(&create_err, "add"));
                    }
                }
                open_dir_handle_no_reparse(Path::new(&create_target), share_mode, "add")?
                    .ok_or_else(|| KeyStoreResponse::error(Some("add"), None))?
            }
        };

        let (final_path, info) =
            inspect_and_verify_dir_handle(guard.raw(), &expected_parent, "add")?;
        expected_parent = final_path;

        if is_leaf {
            return Ok(VerifiedDataRoot {
                _dir_handle: guard,
                canonical_path: expected_parent,
                volume_serial: info.dwVolumeSerialNumber,
                file_index_high: info.nFileIndexHigh,
                file_index_low: info.nFileIndexLow,
            });
        }
    }

    Err(KeyStoreResponse::error(Some("add"), None))
}

/// Re-walks `data_root` from the drive root and confirms it still resolves to the exact same
/// canonical path and NTFS volume/file-ID as `expected`.
fn verify_dir_still_canonical(
    data_root: &Path,
    expected: &VerifiedDataRoot,
    phase: &'static str,
) -> Result<(), KeyStoreResponse> {
    let Some(fresh) = open_verified_existing_data_root(data_root, phase)? else {
        return Err(KeyStoreResponse::error(Some(phase), None));
    };
    if !paths_equal_ci(&fresh.canonical_path, &expected.canonical_path)
        || fresh.volume_serial != expected.volume_serial
        || fresh.file_index_high != expected.file_index_high
        || fresh.file_index_low != expected.file_index_low
    {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }
    Ok(())
}

fn fill_random(buf: &mut [u8]) -> Result<(), KeyStoreResponse> {
    // SAFETY: `buf` is a valid mutable byte slice; `BCRYPT_USE_SYSTEM_PREFERRED_RNG` requires hAlgorithm == None.
    let status = unsafe { BCryptGenRandom(None, buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status.is_err() {
        return Err(KeyStoreResponse::error(Some("random"), Some(status.0)));
    }
    Ok(())
}

fn read_dpapi_file(
    verified_root: &VerifiedDataRoot,
    phase: &'static str,
) -> Result<Option<Vec<u8>>, KeyStoreResponse> {
    let key_path = format!("{}\\{DPAPI_KEY_FILENAME}", verified_root.canonical_path);
    let wide = to_wide_null_str(&key_path);

    // Open with FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS so we never follow
    // a symlink or junction leaf and can inspect attributes directly on the opened handle.
    // Bounded retry on ERROR_SHARING_VIOLATION handles the brief kernel window where a concurrent
    // MoveFileExW has committed the rename to `master.key.dpapi` but not yet closed its internal
    // DELETE-access handle, while preserving strict FILE_SHARE_READ (no WRITE/DELETE sharing).
    let mut file = {
        const MAX_OPEN_ATTEMPTS: usize = 6;
        let mut opened = None;
        for attempt in 0..MAX_OPEN_ATTEMPTS {
            // SAFETY: `wide` is a NUL-terminated UTF-16 path; on success ownership transfers to `File`.
            match unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    FILE_GENERIC_READ.0,
                    FILE_SHARE_READ,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                    None,
                )
            } {
                Ok(h) => {
                    opened = Some(unsafe { File::from_raw_handle(h.0) });
                    break;
                }
                Err(err) if is_not_found_error(&err) => return Ok(None),
                Err(err) if is_sharing_violation_error(&err) && attempt + 1 < MAX_OPEN_ATTEMPTS => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(err) => return Err(map_win_error(&err, phase)),
            }
        }
        match opened {
            Some(f) => f,
            None => return Err(map_win32_error(ERROR_SHARING_VIOLATION, phase)),
        }
    };

    let raw_handle = HANDLE(file.as_raw_handle());
    let info = verify_handle_under_canonical_dir(
        raw_handle,
        &verified_root.canonical_path,
        DPAPI_KEY_FILENAME,
        phase,
    )?;

    let file_size = ((info.nFileSizeHigh as u64) << 32) | (info.nFileSizeLow as u64);
    if file_size < 1 || file_size > MAX_DPAPI_BLOB_BYTES as u64 {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

    let mut data = Vec::with_capacity(file_size as usize);
    let mut chunk = [0u8; 2048];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if data.len().saturating_add(n) > MAX_DPAPI_BLOB_BYTES {
                    return Err(KeyStoreResponse::error(Some(phase), None));
                }
                data.extend_from_slice(&chunk[..n]);
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(map_io_error(&err, phase)),
        }
    }

    if data.is_empty() || data.len() > MAX_DPAPI_BLOB_BYTES {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

    Ok(Some(data))
}

fn dpapi_unprotect(encrypted: &[u8], phase: &'static str) -> Result<ZeroizingKey, KeyStoreResponse> {
    let cb_data = u32::try_from(encrypted.len())
        .map_err(|_| KeyStoreResponse::error(Some(phase), None))?;
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: cb_data,
        pbData: encrypted.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB::default();

    // SAFETY: `in_blob` points to valid `encrypted` bytes for the duration of the call;
    // `out_blob` is immediately wrapped in `LocalMemGuard` on success to zeroize & LocalFree.
    if let Err(err) = unsafe {
        CryptUnprotectData(
            &in_blob,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    } {
        return Err(map_win_error(&err, phase));
    }

    let guard = LocalMemGuard {
        ptr: out_blob.pbData,
        len: out_blob.cbData as usize,
        zero_on_drop: true,
    };

    if guard.ptr.is_null() || guard.len != 32 {
        return Err(KeyStoreResponse::error(Some("response-validation"), None));
    }

    // SAFETY: `guard.ptr` is non-null and valid for `guard.len == 32` bytes.
    let plaintext = unsafe { std::slice::from_raw_parts(guard.ptr, guard.len) };
    let key = ZeroizingKey::from_slice(plaintext)
        .ok_or_else(|| KeyStoreResponse::error(Some("response-validation"), None))?;
    drop(guard);
    Ok(key)
}

fn dpapi_protect(key: &ZeroizingKey) -> Result<Vec<u8>, KeyStoreResponse> {
    let bytes = key.as_bytes();
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB::default();

    // SAFETY: `in_blob` points to the 32-byte plaintext key for the duration of the call.
    // Flags = CRYPTPROTECT_UI_FORBIDDEN only (CurrentUser scope, NULL entropy, NULL prompt)
    // for 100% byte-compatibility with .NET ProtectedData.Protect($raw, $null, CurrentUser).
    if let Err(err) = unsafe {
        CryptProtectData(
            &in_blob,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    } {
        return Err(map_win_error(&err, "dpapi-protect"));
    }

    let guard = LocalMemGuard {
        ptr: out_blob.pbData,
        len: out_blob.cbData as usize,
        zero_on_drop: false,
    };

    if guard.ptr.is_null() || guard.len == 0 || guard.len > MAX_DPAPI_BLOB_BYTES {
        return Err(KeyStoreResponse::error(Some("dpapi-protect"), None));
    }

    // SAFETY: `guard.ptr` is non-null and valid for `guard.len` bytes.
    let ciphertext = unsafe { std::slice::from_raw_parts(guard.ptr, guard.len) }.to_vec();
    drop(guard);
    Ok(ciphertext)
}

fn load_key_verified(
    verified_root: &VerifiedDataRoot,
    lookup_phase: &'static str,
    unprotect_phase: &'static str,
) -> Result<Option<ZeroizingKey>, KeyStoreResponse> {
    let Some(encrypted) = read_dpapi_file(verified_root, lookup_phase)? else {
        return Ok(None);
    };
    dpapi_unprotect(&encrypted, unprotect_phase).map(Some)
}

fn load_key(
    data_root: &Path,
    lookup_phase: &'static str,
    unprotect_phase: &'static str,
) -> Result<Option<ZeroizingKey>, KeyStoreResponse> {
    let Some(verified_root) = open_verified_existing_data_root(data_root, lookup_phase)? else {
        return Ok(None);
    };
    load_key_verified(&verified_root, lookup_phase, unprotect_phase)
}

fn write_all_and_flush(
    verified_root: &VerifiedDataRoot,
    temp_name: &str,
    bytes: &[u8],
    sd: &RestrictedSecurityDescriptor,
) -> Result<(), KeyStoreResponse> {
    let temp_path = format!("{}\\{temp_name}", verified_root.canonical_path);
    let temp_wide = to_wide_null_str(&temp_path);
    let sa = sd.as_security_attributes();

    // SAFETY: `temp_wide` is a NUL-terminated UTF-16 path; CREATE_NEW prevents overwriting or
    // following existing links; `sa` applies the restricted protected DACL.
    // On success, HANDLE ownership transfers immediately to `File`.
    let mut file = match unsafe {
        CreateFileW(
            PCWSTR(temp_wide.as_ptr()),
            FILE_GENERIC_WRITE.0 | FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_MODE(0),
            Some(&sa),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(h) => unsafe { File::from_raw_handle(h.0) },
        Err(err) => return Err(map_win_error(&err, "add")),
    };

    let raw_handle = HANDLE(file.as_raw_handle());
    verify_handle_under_canonical_dir(raw_handle, &verified_root.canonical_path, temp_name, "add")?;

    if let Err(err) = file.write_all(bytes) {
        return Err(map_io_error(&err, "add"));
    }

    // SAFETY: `raw_handle` is a valid open writable file handle.
    if let Err(err) = unsafe { FlushFileBuffers(raw_handle) } {
        return Err(map_win_error(&err, "add"));
    }

    // Explicitly close handle before MoveFileExW.
    drop(file);
    Ok(())
}

/// Deletes a regular file strictly inside `canonical_data_root` via handle-based
/// `SetFileInformationByHandle(..., FileDispositionInfo, ...)` after verifying non-reparse
/// attributes and exact `GetFinalPathNameByHandleW` parent + filename match.
/// Returns `Ok(true)` if the file was deleted, `Ok(false)` if it did not exist.
fn delete_verified_file(
    canonical_data_root: &str,
    filename: &str,
    open_phase: &'static str,
    delete_phase: &'static str,
) -> Result<bool, KeyStoreResponse> {
    let target_path = format!("{canonical_data_root}\\{filename}");
    let wide = to_wide_null_str(&target_path);

    // Open with DELETE | FILE_READ_ATTRIBUTES, no share flags (blocks concurrent tampering),
    // and FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS so symlinks/junctions
    // are opened directly for inspection and rejected before deletion.
    // SAFETY: `wide` is a NUL-terminated UTF-16 path; on success handle is wrapped in `HandleGuard`.
    let handle = match unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            DELETE.0 | FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    } {
        Ok(h) => HandleGuard(h),
        Err(err) if is_not_found_error(&err) => return Ok(false),
        Err(err) => return Err(map_win_error(&err, delete_phase)),
    };

    verify_handle_under_canonical_dir(handle.raw(), canonical_data_root, filename, open_phase)?;

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `handle` is an exclusively opened verified regular file handle with DELETE access;
    // `disposition` is valid for `size_of::<FILE_DISPOSITION_INFO>()` bytes.
    if let Err(err) = unsafe {
        SetFileInformationByHandle(
            handle.raw(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast::<c_void>(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } {
        if is_not_found_error(&err) {
            return Ok(false);
        }
        return Err(map_win_error(&err, delete_phase));
    }

    drop(handle);
    Ok(true)
}

fn verify_committed_file(
    verified_root: &VerifiedDataRoot,
    filename: &str,
    phase: &'static str,
) -> Result<(), KeyStoreResponse> {
    let dst_path = format!("{}\\{filename}", verified_root.canonical_path);
    let wide = to_wide_null_str(&dst_path);
    // SAFETY: `wide` is a NUL-terminated UTF-16 path; handle is wrapped in `HandleGuard`.
    let handle = match unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    } {
        Ok(h) => HandleGuard(h),
        Err(err) => return Err(map_win_error(&err, phase)),
    };

    verify_handle_under_canonical_dir(
        handle.raw(),
        &verified_root.canonical_path,
        filename,
        phase,
    )?;
    Ok(())
}

fn format_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

fn execute_get(data_root: &Path) -> KeyStoreResponse {
    match load_key(data_root, "lookup", "dpapi-unprotect") {
        Ok(Some(key)) => KeyStoreResponse::ok_key(key),
        Ok(None) => KeyStoreResponse::missing("lookup"),
        Err(resp) => resp,
    }
}

fn execute_create(data_root: &Path) -> KeyStoreResponse {
    let sd = match RestrictedSecurityDescriptor::for_current_user("add") {
        Ok(sd) => sd,
        Err(resp) => return resp,
    };

    let verified_root = match ensure_data_root(data_root, &sd) {
        Ok(root) => root,
        Err(resp) => return resp,
    };

    // Idempotent: return existing key if already present.
    match load_key_verified(&verified_root, "lookup", "dpapi-unprotect") {
        Ok(Some(existing)) => return KeyStoreResponse::ok_key(existing),
        Ok(None) => {}
        Err(resp) => return resp,
    }

    let mut generated = ZeroizingKey::zeroed();
    if let Err(resp) = fill_random(generated.as_bytes_mut()) {
        return resp;
    }

    let ciphertext = match dpapi_protect(&generated) {
        Ok(blob) => blob,
        Err(resp) => return resp,
    };

    let mut suffix_bytes = [0u8; 8];
    if let Err(resp) = fill_random(&mut suffix_bytes) {
        return resp;
    }
    let temp_name = format!(
        "{DPAPI_KEY_FILENAME}.tmp.{}.{}",
        std::process::id(),
        format_hex(&suffix_bytes)
    );

    let mut temp_guard = TempFileGuard::new(verified_root.canonical_path.clone(), temp_name.clone());
    if let Err(resp) = write_all_and_flush(&verified_root, &temp_name, &ciphertext, &sd) {
        return resp;
    }

    // Re-verify `data_root` has not been swapped before committing via MoveFileExW.
    if let Err(resp) = verify_dir_still_canonical(data_root, &verified_root, "add") {
        return resp;
    }

    let temp_wide = to_wide_null_str(&format!("{}\\{temp_name}", verified_root.canonical_path));
    let dst_wide = to_wide_null_str(&format!(
        "{}\\{DPAPI_KEY_FILENAME}",
        verified_root.canonical_path
    ));

    // Place atomically WITHOUT MOVEFILE_REPLACE_EXISTING so concurrent creators cannot overwrite a winner.
    // SAFETY: `temp_wide` and `dst_wide` are NUL-terminated UTF-16 canonical paths under the pinned root.
    match unsafe {
        MoveFileExW(
            PCWSTR(temp_wide.as_ptr()),
            PCWSTR(dst_wide.as_ptr()),
            MOVE_FILE_FLAGS(0),
        )
    } {
        Ok(()) => {
            temp_guard.disarm();
            if let Err(resp) = verify_dir_still_canonical(data_root, &verified_root, "add") {
                return resp;
            }
            if let Err(resp) = verify_committed_file(&verified_root, DPAPI_KEY_FILENAME, "add") {
                return resp;
            }
            KeyStoreResponse::ok_key(generated)
        }
        Err(err) if is_already_exists_error(&err) => {
            // Remove temp file and zero our losing key before reloading the winner.
            drop(temp_guard);
            drop(generated);
            if let Err(resp) = verify_dir_still_canonical(data_root, &verified_root, "race-reload")
            {
                return resp;
            }
            match load_key_verified(&verified_root, "race-reload", "race-reload") {
                Ok(Some(winner)) => KeyStoreResponse::ok_key(winner),
                Ok(None) => KeyStoreResponse::missing("race-reload"),
                Err(resp) => resp,
            }
        }
        Err(err) => {
            drop(temp_guard);
            drop(generated);
            map_win_error(&err, "add")
        }
    }
}

fn execute_delete(data_root: &Path) -> KeyStoreResponse {
    let verified_root = match open_verified_existing_data_root(data_root, "lookup") {
        Ok(Some(root)) => root,
        Ok(None) => return KeyStoreResponse::ok_empty(),
        Err(resp) => return resp,
    };

    match delete_verified_file(
        &verified_root.canonical_path,
        DPAPI_KEY_FILENAME,
        "lookup",
        "delete",
    ) {
        Ok(_) => KeyStoreResponse::ok_empty(),
        Err(resp) => resp,
    }
}

pub fn execute_request(req: &KeyStoreRequest) -> KeyStoreResponse {
    match req.command {
        Command::Get => execute_get(&req.data_root),
        Command::Create => execute_create(&req.data_root),
        Command::Delete => execute_delete(&req.data_root),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command as ProcessCommand;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::response::ResponseStatus;
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        AclSizeInformation, CreateWellKnownSid, EqualSid, GetAce, GetAclInformation,
        GetSecurityDescriptorControl, WinAuthenticatedUserSid, WinBuiltinAdministratorsSid,
        WinBuiltinUsersSid, WinLocalSystemSid, WinWorldSid, ACCESS_ALLOWED_ACE, ACL,
        ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED,
        WELL_KNOWN_SID_TYPE,
    };
    use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "chmcp-dpapi-unit-{label}-{}-{id}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("create test temp dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Vec<u8> {
        let mut size = 68u32;
        let mut buf = vec![0u8; size as usize];
        unsafe {
            CreateWellKnownSid(kind, None, Some(PSID(buf.as_mut_ptr().cast())), &mut size)
                .expect("CreateWellKnownSid");
        }
        buf.truncate(size as usize);
        buf
    }

    fn current_user_sid_bytes() -> Vec<u8> {
        let mut token_raw = HANDLE::default();
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_raw)
                .expect("OpenProcessToken");
        }
        let token = HandleGuard(token_raw);
        let mut needed = 0u32;
        let _ = unsafe { GetTokenInformation(token.raw(), TokenUser, None, 0, &mut needed) };
        let mut storage = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        let mut returned = 0u32;
        unsafe {
            GetTokenInformation(
                token.raw(),
                TokenUser,
                Some(storage.as_mut_ptr().cast()),
                needed,
                &mut returned,
            )
            .expect("GetTokenInformation");
        }
        let user = unsafe { &*(storage.as_ptr().cast::<TOKEN_USER>()) };
        // Copy raw SID bytes out by querying its exact length via EqualSid-compatible buffer.
        // Windows SID structure: [Revision(1), SubAuthorityCount(1), IdentifierAuthority(6), SubAuthority[count](4*count)].
        let raw_ptr = user.User.Sid.0 as *const u8;
        let sub_count = unsafe { *raw_ptr.add(1) } as usize;
        let sid_len = 8 + 4 * sub_count;
        unsafe { std::slice::from_raw_parts(raw_ptr, sid_len) }.to_vec()
    }

    fn sid_equals(a: PSID, b: &[u8]) -> bool {
        unsafe { EqualSid(a, PSID(b.as_ptr() as *mut c_void)).is_ok() }
    }

    fn assert_restricted_protected_dacl(path: &Path) {
        let wide = to_wide_null(path);
        let mut dacl_ptr: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            let status = GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl_ptr),
                None,
                &mut sd,
            );
            assert!(status.is_ok(), "GetNamedSecurityInfoW failed for {:?}: {status:?}", path);
        }
        let _sd_guard = RestrictedSecurityDescriptor { sd };
        assert!(!dacl_ptr.is_null(), "DACL must be present on {:?}", path);

        let mut control = 0u16;
        let mut revision = 0u32;
        unsafe {
            GetSecurityDescriptorControl(sd, &mut control, &mut revision)
                .expect("GetSecurityDescriptorControl");
        }
        assert_ne!(
            control & SE_DACL_PROTECTED.0,
            0,
            "DACL must be protected (SE_DACL_PROTECTED) on {:?}",
            path
        );

        let mut acl_size = ACL_SIZE_INFORMATION::default();
        unsafe {
            GetAclInformation(
                dacl_ptr,
                (&mut acl_size as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
            .expect("GetAclInformation");
        }
        assert!(acl_size.AceCount >= 2 && acl_size.AceCount <= 3);

        let user_sid = current_user_sid_bytes();
        let system_sid = well_known_sid(WinLocalSystemSid);
        let admins_sid = well_known_sid(WinBuiltinAdministratorsSid);
        let auth_users_sid = well_known_sid(WinAuthenticatedUserSid);
        let users_sid = well_known_sid(WinBuiltinUsersSid);
        let world_sid = well_known_sid(WinWorldSid);

        let mut has_user = false;
        let mut has_system = false;
        let mut has_admins = false;

        for idx in 0..acl_size.AceCount {
            let mut ace_ptr: *mut c_void = std::ptr::null_mut();
            unsafe {
                GetAce(dacl_ptr, idx, &mut ace_ptr).expect("GetAce");
            }
            let ace = unsafe { &*(ace_ptr.cast::<ACCESS_ALLOWED_ACE>()) };
            assert_eq!(ace.Header.AceType, 0, "expected ACCESS_ALLOWED_ACE");
            assert_eq!(
                ace.Mask, FILE_ALL_ACCESS.0,
                "expected FILE_ALL_ACCESS (FA) on {:?}",
                path
            );

            let ace_sid = PSID((&ace.SidStart as *const u32) as *mut c_void);
            assert!(
                !sid_equals(ace_sid, &auth_users_sid),
                "Authenticated Users must not have an ACE on {:?}",
                path
            );
            assert!(
                !sid_equals(ace_sid, &users_sid),
                "BUILTIN\\Users must not have an ACE on {:?}",
                path
            );
            assert!(
                !sid_equals(ace_sid, &world_sid),
                "Everyone must not have an ACE on {:?}",
                path
            );

            let mut matched = false;
            if sid_equals(ace_sid, &user_sid) {
                has_user = true;
                matched = true;
            }
            if sid_equals(ace_sid, &system_sid) {
                has_system = true;
                matched = true;
            }
            if sid_equals(ace_sid, &admins_sid) {
                has_admins = true;
                matched = true;
            }
            assert!(
                matched,
                "unexpected trustee ACE found in restricted DACL on {:?}",
                path
            );
        }

        assert!(has_user, "current user ACE missing on {:?}", path);
        assert!(has_system, "SYSTEM ACE missing on {:?}", path);
        assert!(has_admins, "BUILTIN\\Administrators ACE missing on {:?}", path);
    }

    #[test]
    fn canonical_handle_verification_accepts_in_root_and_rejects_wrong_dir_or_name() {
        let dir_a = TestDir::new("canon-a");
        let dir_b = TestDir::new("canon-b");

        let verified_a = match open_verified_existing_data_root(dir_a.path(), "lookup") {
            Ok(Some(v)) => v,
            Ok(None) => panic!("dir_a must exist"),
            Err(resp) => panic!("verify dir_a failed: status={:?} phase={:?}", resp.status, resp.phase),
        };

        let file_a = dir_a.path().join(DPAPI_KEY_FILENAME);
        let file_b = dir_b.path().join(DPAPI_KEY_FILENAME);
        fs::write(&file_a, b"payload-a").expect("write file_a");
        fs::write(&file_b, b"payload-b").expect("write file_b");

        // Handle inside dir_a passes with matching filename, fails with wrong filename.
        let handle_a = File::open(&file_a).expect("open file_a");
        let raw_a = HANDLE(handle_a.as_raw_handle());
        assert!(verify_handle_under_canonical_dir(
            raw_a,
            &verified_a.canonical_path,
            DPAPI_KEY_FILENAME,
            "lookup"
        )
        .is_ok());
        let wrong_name = verify_handle_under_canonical_dir(
            raw_a,
            &verified_a.canonical_path,
            "other.key.dpapi",
            "lookup",
        )
        .expect_err("wrong filename must fail");
        assert_eq!(wrong_name.status, ResponseStatus::Error);
        assert_eq!(wrong_name.phase, Some("lookup"));

        // Handle inside dir_b must fail when verified against dir_a's canonical path.
        let handle_b = File::open(&file_b).expect("open file_b");
        let raw_b = HANDLE(handle_b.as_raw_handle());
        let wrong_dir = verify_handle_under_canonical_dir(
            raw_b,
            &verified_a.canonical_path,
            DPAPI_KEY_FILENAME,
            "lookup",
        )
        .expect_err("file outside canonical data_root must fail");
        assert_eq!(wrong_dir.status, ResponseStatus::Error);
        assert_eq!(wrong_dir.phase, Some("lookup"));
    }

    #[test]
    fn handle_based_delete_handles_missing_existing_and_reparse_leaf() {
        let temp = TestDir::new("handle-delete");
        let data_root = temp.path().join("store");
        fs::create_dir_all(&data_root).expect("create store dir");
        let verified = match open_verified_existing_data_root(&data_root, "lookup") {
            Ok(Some(v)) => v,
            Ok(None) => panic!("store must exist"),
            Err(resp) => panic!("verify store failed: status={:?} phase={:?}", resp.status, resp.phase),
        };

        // 1. Missing file -> deleted == false
        let missing = match delete_verified_file(
            &verified.canonical_path,
            DPAPI_KEY_FILENAME,
            "lookup",
            "delete",
        ) {
            Ok(deleted) => deleted,
            Err(resp) => panic!("missing delete failed: status={:?} phase={:?}", resp.status, resp.phase),
        };
        assert!(!missing);

        // 2. Existing regular file -> deleted == true and file is removed
        let key_file = data_root.join(DPAPI_KEY_FILENAME);
        fs::write(&key_file, b"synthetic-dpapi-bytes").expect("write key file");
        assert!(key_file.exists());
        let deleted = match delete_verified_file(
            &verified.canonical_path,
            DPAPI_KEY_FILENAME,
            "lookup",
            "delete",
        ) {
            Ok(deleted) => deleted,
            Err(resp) => panic!("existing delete failed: status={:?} phase={:?}", resp.status, resp.phase),
        };
        assert!(deleted);
        assert!(!key_file.exists());

        // 3. Reparse point leaf (NTFS junction at master.key.dpapi) -> rejected and target preserved
        let target_dir = temp.path().join("target-dir");
        fs::create_dir_all(&target_dir).expect("create target_dir");
        let sentinel = target_dir.join("keep.txt");
        fs::write(&sentinel, b"do-not-touch").expect("write sentinel");

        let mklink = ProcessCommand::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                key_file.to_str().unwrap(),
                target_dir.to_str().unwrap(),
            ])
            .output()
            .expect("run mklink /J");
        assert!(mklink.status.success(), "mklink /J failed");

        let err = delete_verified_file(
            &verified.canonical_path,
            DPAPI_KEY_FILENAME,
            "lookup",
            "delete",
        )
        .expect_err("reparse leaf must be rejected");
        assert_eq!(err.status, ResponseStatus::Error);
        assert_eq!(err.phase, Some("lookup"));
        assert!(sentinel.exists(), "junction target contents must remain untouched");

        let _ = fs::remove_dir(&key_file);

        // 4. If file symlinks are permitted in this environment, verify file symlink leaf is rejected too.
        let target_file = temp.path().join("real-target.bin");
        fs::write(&target_file, b"keep-file").expect("write target_file");
        if std::os::windows::fs::symlink_file(&target_file, &key_file).is_ok() {
            let sym_err = delete_verified_file(
                &verified.canonical_path,
                DPAPI_KEY_FILENAME,
                "lookup",
                "delete",
            )
            .expect_err("file symlink leaf must be rejected");
            assert_eq!(sym_err.status, ResponseStatus::Error);
            assert_eq!(sym_err.phase, Some("lookup"));
            assert!(target_file.exists(), "symlink target file must remain untouched");
            let _ = fs::remove_file(&key_file);
        }
    }

    #[test]
    fn newly_created_data_root_and_key_file_have_restricted_protected_dacl() {
        let temp = TestDir::new("dacl");
        let custom_parent = temp.path().join("custom-root");
        let data_root = custom_parent.join("nested");

        let req = KeyStoreRequest {
            command: Command::Create,
            data_root: data_root.clone(),
            service: None,
            account: None,
        };
        let resp = execute_request(&req);
        assert_eq!(resp.status, ResponseStatus::Ok);
        assert!(resp.key.is_some());

        assert_restricted_protected_dacl(&custom_parent);
        assert_restricted_protected_dacl(&data_root);
        assert_restricted_protected_dacl(&data_root.join(DPAPI_KEY_FILENAME));

        // Even when data_root already exists with inherited ACLs, newly created master.key.dpapi
        // must still receive the explicit restricted protected DACL.
        let preexisting_root = temp.path().join("preexisting");
        fs::create_dir_all(&preexisting_root).expect("create preexisting dir");
        let resp2 = execute_request(&KeyStoreRequest {
            command: Command::Create,
            data_root: preexisting_root.clone(),
            service: None,
            account: None,
        });
        assert_eq!(resp2.status, ResponseStatus::Ok);
        assert!(resp2.key.is_some());
        assert_restricted_protected_dacl(&preexisting_root.join(DPAPI_KEY_FILENAME));
    }
}

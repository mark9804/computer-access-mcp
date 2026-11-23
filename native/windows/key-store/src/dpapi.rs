use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf};

use windows::core::{Error as WinError, PCWSTR};
use windows::Win32::Foundation::{
    GetLastError, LocalFree, E_ACCESSDENIED, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS,
    ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, HANDLE, HLOCAL,
    NTE_BAD_KEY_STATE, WIN32_ERROR,
};
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, CryptProtectData, CryptUnprotectData, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, DeleteFileW, FlushFileBuffers, GetFileAttributesW,
    GetFileInformationByHandle, MoveFileExW, BY_HANDLE_FILE_INFORMATION, CREATE_NEW,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE,
    FILE_SHARE_READ, INVALID_FILE_ATTRIBUTES, MOVE_FILE_FLAGS, OPEN_EXISTING,
};

use crate::request::{Command, KeyStoreRequest};
use crate::response::KeyStoreResponse;
use crate::zeroize::{zeroize_slice, ZeroizingKey};

pub const DPAPI_KEY_FILENAME: &str = "master.key.dpapi";
pub const MAX_DPAPI_BLOB_BYTES: usize = 8192;

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
            // SAFETY: `ptr` was allocated by DPAPI with LocalAlloc and must be freed via LocalFree.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.ptr.cast()))) };
        }
    }
}

struct TempFileGuard {
    wide_path: Vec<u16>,
    armed: bool,
}

impl TempFileGuard {
    fn new(wide_path: Vec<u16>) -> Self {
        Self {
            wide_path,
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
            // SAFETY: `self.wide_path` is a NUL-terminated UTF-16 path.
            let _ = unsafe { DeleteFileW(PCWSTR(self.wide_path.as_ptr())) };
        }
    }
}

fn to_wide_null(path: &Path) -> Vec<u16> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    wide
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

/// Walks every existing ancestor of `data_root` and `data_root` itself top-down,
/// rejecting any symlink/junction (`FILE_ATTRIBUTE_REPARSE_POINT`) or non-directory.
/// Returns `Ok(true)` if `data_root` exists and is safe, `Ok(false)` if an ancestor or
/// `data_root` is missing (with all existing higher ancestors verified safe).
fn verify_existing_dir_chain(data_root: &Path, phase: &'static str) -> Result<bool, KeyStoreResponse> {
    let chain = ancestor_chain(data_root);
    if chain.is_empty() {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }
    for dir in chain {
        let wide = to_wide_null(&dir);
        // SAFETY: `wide` is a NUL-terminated UTF-16 string.
        let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            // SAFETY: immediately reading thread-local Win32 error after GetFileAttributesW failure.
            let err = unsafe { GetLastError() };
            if is_not_found_win32(err) {
                return Ok(false);
            }
            return Err(map_win32_error(err, phase));
        }
        if (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0 {
            return Err(KeyStoreResponse::error(Some(phase), None));
        }
        if (attrs & FILE_ATTRIBUTE_DIRECTORY.0) == 0 {
            return Err(KeyStoreResponse::error(Some(phase), None));
        }
    }
    Ok(true)
}

/// Creates `data_root` recursively top-down while rejecting any symlink/junction
/// (`FILE_ATTRIBUTE_REPARSE_POINT`) or non-directory at every ancestor component.
fn ensure_data_root(data_root: &Path) -> Result<(), KeyStoreResponse> {
    let chain = ancestor_chain(data_root);
    if chain.is_empty() {
        return Err(KeyStoreResponse::error(Some("add"), None));
    }

    for dir in chain {
        let wide = to_wide_null(&dir);
        // SAFETY: `wide` is a NUL-terminated UTF-16 path.
        let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
        if attrs != INVALID_FILE_ATTRIBUTES {
            if (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0
                || (attrs & FILE_ATTRIBUTE_DIRECTORY.0) == 0
            {
                return Err(KeyStoreResponse::error(Some("add"), None));
            }
            continue;
        }

        // SAFETY: immediately reading thread-local Win32 error after GetFileAttributesW failure.
        let err = unsafe { GetLastError() };
        if !is_not_found_win32(err) {
            return Err(map_win32_error(err, "add"));
        }

        // SAFETY: `wide` is NUL-terminated UTF-16; default security descriptor inherits user profile ACLs.
        if let Err(create_err) = unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), None) } {
            if !is_already_exists_error(&create_err) {
                return Err(map_win_error(&create_err, "add"));
            }
        }

        // Re-verify attributes immediately after creation or race.
        // SAFETY: `wide` is a NUL-terminated UTF-16 path.
        let verified = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
        if verified == INVALID_FILE_ATTRIBUTES {
            // SAFETY: immediately reading thread-local Win32 error.
            let verify_err = unsafe { GetLastError() };
            return Err(map_win32_error(verify_err, "add"));
        }
        if (verified & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0
            || (verified & FILE_ATTRIBUTE_DIRECTORY.0) == 0
        {
            return Err(KeyStoreResponse::error(Some("add"), None));
        }
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

fn read_dpapi_file(key_path: &Path, phase: &'static str) -> Result<Option<Vec<u8>>, KeyStoreResponse> {
    let wide = to_wide_null(key_path);
    // SAFETY: `wide` is a NUL-terminated UTF-16 path.
    let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        // SAFETY: reading thread-local Win32 error after GetFileAttributesW failure.
        let err = unsafe { GetLastError() };
        if is_not_found_win32(err) {
            return Ok(None);
        }
        return Err(map_win32_error(err, phase));
    }
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0 || (attrs & FILE_ATTRIBUTE_DIRECTORY.0) != 0 {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

    // Open with FILE_FLAG_OPEN_REPARSE_POINT so we never follow a symlink swapped in after GetFileAttributesW.
    // SAFETY: `wide` is a NUL-terminated UTF-16 path; on success ownership transfers to `File`.
    let mut file = match unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(h) => unsafe { File::from_raw_handle(h.0) },
        Err(err) => {
            if is_not_found_error(&err) {
                return Ok(None);
            }
            return Err(map_win_error(&err, phase));
        }
    };

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let raw_handle = HANDLE(file.as_raw_handle());
    // SAFETY: `raw_handle` is a valid open file handle and `info` is valid writable memory.
    if let Err(err) = unsafe { GetFileInformationByHandle(raw_handle, &mut info) } {
        return Err(map_win_error(&err, phase));
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0
    {
        return Err(KeyStoreResponse::error(Some(phase), None));
    }

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

fn load_key(
    data_root: &Path,
    lookup_phase: &'static str,
    unprotect_phase: &'static str,
) -> Result<Option<ZeroizingKey>, KeyStoreResponse> {
    if !verify_existing_dir_chain(data_root, lookup_phase)? {
        return Ok(None);
    }
    let key_path = data_root.join(DPAPI_KEY_FILENAME);
    let Some(encrypted) = read_dpapi_file(&key_path, lookup_phase)? else {
        return Ok(None);
    };
    dpapi_unprotect(&encrypted, unprotect_phase).map(Some)
}

fn write_all_and_flush(temp_wide: &[u16], bytes: &[u8]) -> Result<(), KeyStoreResponse> {
    // SAFETY: `temp_wide` is a NUL-terminated UTF-16 path; CREATE_NEW prevents overwriting or following existing links.
    // On success, HANDLE ownership transfers immediately to `File`.
    let mut file = match unsafe {
        CreateFileW(
            PCWSTR(temp_wide.as_ptr()),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(h) => unsafe { File::from_raw_handle(h.0) },
        Err(err) => return Err(map_win_error(&err, "add")),
    };

    if let Err(err) = file.write_all(bytes) {
        return Err(map_io_error(&err, "add"));
    }

    let raw_handle = HANDLE(file.as_raw_handle());
    // SAFETY: `raw_handle` is a valid open writable file handle.
    if let Err(err) = unsafe { FlushFileBuffers(raw_handle) } {
        return Err(map_win_error(&err, "add"));
    }

    // Explicitly close handle before MoveFileExW.
    drop(file);
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
    if let Err(resp) = ensure_data_root(data_root) {
        return resp;
    }

    // Idempotent: return existing key if already present.
    match load_key(data_root, "lookup", "dpapi-unprotect") {
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
    let temp_path = data_root.join(temp_name);
    let dst_path = data_root.join(DPAPI_KEY_FILENAME);

    let temp_wide = to_wide_null(&temp_path);
    let dst_wide = to_wide_null(&dst_path);

    let mut temp_guard = TempFileGuard::new(temp_wide.clone());
    if let Err(resp) = write_all_and_flush(&temp_wide, &ciphertext) {
        return resp;
    }

    // Place atomically WITHOUT MOVEFILE_REPLACE_EXISTING so concurrent creators cannot overwrite a winner.
    // SAFETY: `temp_wide` and `dst_wide` are NUL-terminated UTF-16 paths.
    match unsafe {
        MoveFileExW(
            PCWSTR(temp_wide.as_ptr()),
            PCWSTR(dst_wide.as_ptr()),
            MOVE_FILE_FLAGS(0),
        )
    } {
        Ok(()) => {
            temp_guard.disarm();
            KeyStoreResponse::ok_key(generated)
        }
        Err(err) if is_already_exists_error(&err) => {
            // Remove temp file and zero our losing key before reloading the winner.
            drop(temp_guard);
            drop(generated);
            match load_key(data_root, "race-reload", "race-reload") {
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
    match verify_existing_dir_chain(data_root, "lookup") {
        Ok(false) => return KeyStoreResponse::ok_empty(),
        Ok(true) => {}
        Err(resp) => return resp,
    }

    let key_path = data_root.join(DPAPI_KEY_FILENAME);
    let wide = to_wide_null(&key_path);
    // SAFETY: `wide` is a NUL-terminated UTF-16 path.
    let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        // SAFETY: reading thread-local Win32 error after GetFileAttributesW failure.
        let err = unsafe { GetLastError() };
        if is_not_found_win32(err) {
            return KeyStoreResponse::ok_empty();
        }
        return map_win32_error(err, "lookup");
    }
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0 || (attrs & FILE_ATTRIBUTE_DIRECTORY.0) != 0 {
        return KeyStoreResponse::error(Some("lookup"), None);
    }

    // SAFETY: `wide` is a NUL-terminated UTF-16 path pointing to a verified non-reparse regular file.
    match unsafe { DeleteFileW(PCWSTR(wide.as_ptr())) } {
        Ok(()) => KeyStoreResponse::ok_empty(),
        Err(err) if is_not_found_error(&err) => KeyStoreResponse::ok_empty(),
        Err(err) => map_win_error(&err, "delete"),
    }
}

pub fn execute_request(req: &KeyStoreRequest) -> KeyStoreResponse {
    match req.command {
        Command::Get => execute_get(&req.data_root),
        Command::Create => execute_create(&req.data_root),
        Command::Delete => execute_delete(&req.data_root),
    }
}

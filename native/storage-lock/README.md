# Cross-Platform Storage Lock (`native/storage-lock`)

Synchronous Node-API 8 C addon providing non-blocking exclusive file descriptor locking across macOS, Windows, and Linux.

## Exported API

- `tryLock(fd: number): boolean` — Acquires an exclusive non-blocking lock on an open nonnegative int32 file descriptor. Returns `true` when acquired, `false` when held by another open file description/handle, and throws (`INVALID_FD`, `EBADF`, `LOCK_FAILED`) on invalid arguments or system errors.
- `unlock(fd: number): void` — Releases an acquired lock on `fd` before closing the handle (`flock(fd, LOCK_UN)` on POSIX, `UnlockFileEx` on Windows). Kernel locks are also released automatically by the OS if the owning process crashes or terminates.

## Platform Primitives

- **POSIX (macOS / Linux)**: `flock(fd, LOCK_EX | LOCK_NB)` and `flock(fd, LOCK_UN)`.
- **Windows**: Dynamically resolves `uv_get_osfhandle` from the host `node.exe` process via `GetModuleHandleW(NULL)` + `GetProcAddress` (avoiding CRT mismatch crashes from calling the addon's own `_get_osfhandle` against Node.js's statically linked `/MT` CRT), then calls `LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov)` and `UnlockFileEx(h, 0, 1, 0, &ov)`.

The caller owns the `FileHandle` for `store.lock` and must never `unlink` `store.lock`.

## Build

```sh
pnpm build:storage-lock
# equivalent to:
node scripts/build-storage-lock.mjs
```

Outputs `native-bin/computer-history-storage-lock.node` and `native-bin/storage-lock.manifest.json`.

- **macOS**: Compiles with `xcrun clang` against the vendored Node-API v8 headers.
- **Windows**: Works completely offline without `node-gyp` or network downloads. Requires Visual Studio 2022/2026 Build Tools (Desktop development with C++ workload + Windows 11 SDK). `scripts/build-storage-lock.mjs` discovers MSVC via `vswhere.exe` + `vcvarsall.bat`, generates a local N-API import library (`node.lib`) using `lib.exe` when `NODE_LIB` or an adjacent `node.lib` is not present, and compiles with `cl.exe` (falling back to `clang-cl` if MSVC is absent). Live lock contention, unlock, and crash-release semantics are verified on Windows in `tests/integration/native-storage-lock.test.ts`.
- **Linux**: Compiles with `$CC` (default `cc`).

## Vendored Node-API Headers & License

The `vendor/node-v24.22.1` directory contains four unmodified Node-API headers from Node.js v24.22.1 covered by [LICENSE.node](./LICENSE.node) (MIT):

| File | SHA-256 |
| --- | --- |
| `node_api.h` | `2d4560831e525b47b060ec8a0864ab73993df9e20215ce9f0fe7b24cd31af32a` |
| `node_api_types.h` | `a25356630d3058f0a0c8937d9f297e9471e037fda58c2696d8a505c2bd99cb00` |
| `js_native_api.h` | `82d3708ce120f8000ec34d72e1aa70b0d7d8a43027986293681374a71b2cb840` |
| `js_native_api_types.h` | `4f19cb90d240765cc0961d92a1ee20f65fdc50db7de1ab0a5cb6bc227224e1a0` |

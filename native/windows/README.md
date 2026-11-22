# Windows Native Collector & Key Store (`native/windows/`)

This directory is the home for the planned **Rust (`windows-rs`)** native Windows packages speaking the shared NDJSON wire protocol v1 defined in `src/shared/protocol/`.

## Current Status: Phase 0 + Phase 1 Shipped (PR 1)

The cross-platform foundation, storage layer, wire protocol, and Node.js Host layer already support Windows (`win32`):

- **Dev & Build Baseline**: Node.js `>= 24.12.0`, pnpm, Visual Studio 2022/2026 Build Tools (C++ workload + Windows 11 SDK), LF-normalized repository (`.gitattributes`, `tsconfig.build.json` `"newLine": "lf"`).
- **Native Storage Lock (`native/storage-lock/`)**: `LockFileEx`/`UnlockFileEx` via `uv_get_osfhandle` (resolved dynamically from `node.exe` to avoid static `/MT` CRT mismatch crashes), compiled offline by `scripts/build-storage-lock.mjs` using `vswhere` + MSVC `cl.exe`/`lib.exe`, verified live on Windows (`tests/integration/native-storage-lock.test.ts`).
- **Master Key Protection (`src/storage/key-provider.ts`)**: Hardened `WindowsDpapiKeyProvider` encrypting `<dataRoot>/master.key.dpapi` via Windows DPAPI (`CryptProtectData`, `CurrentUser` scope), live-verified on Windows.
- **CLI Supervisor Clean Shutdown (`src/server/cli.ts`)**: Supervisor <-> worker IPC `'shutdown'` channel with bounded fallback termination for clean `SIGINT`/`SIGTERM` handling on Windows.
- **Wire Protocol v1 Windows Sources**: `uia.tree`, `uia.text` (supporting `rangeBasis: 'visible'` and `selection.snapshot`), `uia.value`, `uia.menu`, `win32.listen-only`, and `win32.unicode`, synchronized across TypeScript (`src/shared/protocol/validate.ts`) and macOS Swift (`native/macos/contract/`).
- **Host & Policy Windows Adaptation**:
  - Windows password managers in `MANDATORY_EXCLUDED_APPLICATION_IDS`, Windows shell/auth overlays in `SYSTEM_UI_SKIP_APPLICATION_IDS`, Windows browsers in `BROWSER_APPLICATION_FAMILIES`, and Windows IDs across `BUILT_IN_ADAPTERS` (`src/shared/app-policy.ts`).
  - `minimalChildEnv` (`src/shared/child-env.ts`) restricting Windows child processes to 11 essential OS environment variables.
  - `win32` support in `CollectorSupervisor` (with bounded graceful stop wait), fail-closed `wts-session` / `win32-desktop` permission validation (`'not-applicable'` grants for `accessibility`/`inputMonitoring`) in `permissions.ts`, `wts-*` / `winsta0-default-wts-*` identity validation in `source-navigation.ts`, and `.exe` default binary resolution / live `checkPermissions` / `openSource` in `history-service.ts`.

## Locked Windows Design Conventions

All planned `native/windows/` crates must conform to these locked contracts:

1. **NDJSON Wire Transport**: LF-terminated canonical JSON frames (`<= 65,536` bytes) over `stdio`.
2. **UIA -> `AX*` Role Mapping**: Map UIA `ControlType` values to canonical `AX*` role names in `SurfaceNode.axRole`. Unmapped controls omit `axRole` and fall back to the generic `SurfaceNode.role` category (`text`, `editable`, `container`, `terminal`, `other`), preserving zero-change compatibility with downstream MCP consumers and `layout-guides/`.
3. **Windows `applicationId` Convention**:
   - Win32 / Electron / Qt apps emit lowercase `.exe` basenames (e.g., `code.exe`, `msedge.exe`, `1password.exe`).
   - UWP / MSIX apps (including windows hosted by `ApplicationFrameHost.exe`) resolve the inner application process and emit the lowercase Package Name without `_<publisherId>!Entry` (e.g., `microsoft.windowsterminal`), matching the canonical `^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$` rule.
   - **PR #2 Normalization & Verification Note**: Strip/normalize whitespace and disallowed characters in Win32 `.exe` basenames (e.g., `Proton Pass.exe` -> `protonpass.exe`) before matching against `MANDATORY_EXCLUDED_APPLICATION_IDS` or emitting wire frames, and verify exact installed `.exe` names for desktop apps (such as Antigravity) against `src/shared/app-policy.ts`.
4. **Session & Desktop Identifiers**: `osSessionId: "wts-<sessionId>"` and `desktopId: "winsta0-default-wts-<sessionId>"`.

## Planned Native Architecture (Rust / `windows-rs`)

The chosen Windows native toolchain is **Rust (`windows-rs`, `stable-x86_64-pc-windows-msvc`)**, structured as a Cargo workspace mirroring `native/macos/`:

```text
native/windows/
  Cargo.toml
  contract/    # Wire v1 schema & canonical NDJSON validator (matching TS & Swift)
  key-store/   # computer-access-key-store.exe (native Win32 DPAPI CryptProtectData/CryptUnprotectData)
  collector/   # computer-access-collector.exe (CollectorEngine + isolated MTA COM UIA worker)
```

### PR 2 — Phase 2 + Phase 3 (Core Native Runtime & UIA Collector)

- **Native DPAPI Key Store (`computer-access-key-store.exe`)**: Direct Win32 `CryptProtectData` / `CryptUnprotectData` binary compatible with `<dataRoot>/master.key.dpapi`, replacing the Phase 0/1 PowerShell subprocess overhead.
- **Control Process (`CollectorEngine`)**: Speaks NDJSON (`<= 65,536` bytes) over `stdio`, enforces lease heartbeats and epoch fencing, passes the 12 deterministic fixture scenarios, and implements `--permissions` (`wts-session`/`win32-desktop`) and `--navigate-source`.
- **Isolated MTA COM UIA Worker**: Out-of-process worker contained in a Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) with a shared-memory progress fence so hung COM/UIA calls are terminated cleanly. Enforces WTS/Secure Desktop lock detection, mandatory exclusions, `UIA_IsPasswordPropertyId` pre-read privacy gates, `ReadBudget` (`deadlineMs`, `maxCalls`, `maxTextUnits`), and focused text, selection, and surface snapshot capture.

### PR 3+ — Phase 4 + Phase 5 (App Adapters & Input/Menu Channels)

- **Per-App Windows `AppAdapter` Tuning**: Windows implementations across the 10 built-in adapters (`generic`, `vscode-family`, `browser-family`, `terminal-family`, `qq`, `feishu`, `wechat`, `slack`, `typora`, `figma`) plus Windows updates to `layout-guides/`.
- **Optional Input & Menu Channels**: `input.activity` (`win32.listen-only`), `input.text` (`win32.unicode` with IME composition handling), and `menu.action` (`uia.menu`).

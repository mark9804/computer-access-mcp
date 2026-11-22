# Roadmap

## Shipped

### macOS Local Service & MCP (v0.2)

- **Standalone Daemon & Web Control Panel**: `computer-access-mcp serve` hosting the React 18 + Base UI panel (`Overview & Permissions`, `Capture Scope & Adapters`, `MCP Access`, `History & Forget`) with Admin Token authentication.
- **Standard MCP Server**: Streamable HTTP (`POST /mcp`) and `computer-access-mcp stdio` proxy supporting `history_status`, `history_search`, `history_read`, `history_layout`, `history_layout_guide`, optional `history_pause`, and opt-in `history_reload` under scoped, revocable `ClientLease` tokens, plus `computer-access://layout-guides/{id}` MCP resources.
- **Cross-Platform AEAD Segment Store**: Append-only 4 MiB AES-256-GCM segments (`seg-*.cah`), `store.lock` (`flock` / `LockFileEx`), cold/hot tiered LRU segment indexing, 14-day TTL and 16 GiB budget eviction of closed segments, and EOF torn-frame self-healing.
- **macOS Collector & AppAdapter Framework**:
  - Process-isolated control loop + ephemeral AX/input workers with atomic deadline fencing.
  - Pre-read privacy gates (mandatory excluded app families, System UI skip, private browser blocking, lock screen, Secure Input, password/protected fields).
  - Focused text, `AXTextMarker` ranges, selections, committed keyboard `input.text`, 1-second coarse `input.activity`, `menu.action`, and window-relative `surface.snapshot` geometry.
  - Ten built-in adapters (`generic`, `vscode-family`, `browser-family`, `terminal-family`, `qq`, `feishu`, `wechat`, `slack`, `typora`, `figma`) and declarative `layout-guides/`.

### Windows Phase 0 + Phase 1 Foundation (PR 1)

- **Windows Dev & Build Baseline**: Node.js `>= 24.12.0`, pnpm, Visual Studio 2022/2026 Build Tools (C++ workload + Windows 11 SDK), LF `.gitattributes`, and `tsconfig.build.json` `"newLine": "lf"`.
- **Native Storage Lock (`native/storage-lock/`)**: `LockFileEx`/`UnlockFileEx` via `uv_get_osfhandle` (avoiding Node static CRT `/MT` crashes), compiled offline by `scripts/build-storage-lock.mjs` via `vswhere` + MSVC `cl.exe`/`lib.exe`, and verified live on Windows (`tests/integration/native-storage-lock.test.ts`).
- **Hardened DPAPI & Clean CLI Shutdown**: `WindowsDpapiKeyProvider` hardened and live-tested on Windows (`<dataRoot>/master.key.dpapi`), plus supervisor <-> worker IPC `'shutdown'` handling in `src/server/cli.ts`.
- **Wire Protocol v1 Windows Sources & Locked Conventions**: Added `uia.tree`, `uia.text` (supporting `rangeBasis: 'visible'` and `selection.snapshot`), `uia.menu`, `win32.listen-only`, and `win32.unicode` across TypeScript (`validate.ts`) and macOS Swift (`ContractValidator.swift`). Locked UIA `ControlType` -> canonical `AX*` `SurfaceNode.axRole` mapping and Windows `applicationId` conventions (lowercase `.exe` basenames + inner-process UWP/MSIX Package Names).
- **Host & Policy Windows Adaptation**: Added Windows password managers, shell/auth System UI overlays, browsers, and built-in adapter IDs to `src/shared/app-policy.ts`; introduced `minimalChildEnv` (11 essential Windows env vars); enabled `win32` in `CollectorSupervisor` (with bounded graceful stop wait), `permissions.ts` (`wts-session`/`win32-desktop` fail-closed validation + `'not-applicable'` grants), `source-navigation.ts` (`wts-*`/`winsta0-default-wts-*`), and `history-service.ts` (`.exe` defaults, live `checkPermissions`, `openSource`).

## Planned Next Milestones

### 1. Windows Native Collector & Key Store — PR 2 (Phase 2 + Phase 3, `native/windows/`)
- **Toolchain & Workspace**: **Rust (`windows-rs`, `stable-x86_64-pc-windows-msvc`)** structured as a Cargo workspace mirroring `native/macos/` (`contract`, `key-store`, `collector`).
- **Native DPAPI Key Store**: `computer-access-key-store.exe` calling Win32 `CryptProtectData`/`CryptUnprotectData` directly against the identical `master.key.dpapi` format, eliminating Phase 0/1 PowerShell subprocess overhead.
- **Core UIA Collector**: `CollectorEngine` + 12 deterministic fixture scenarios, isolated out-of-process MTA COM UIA worker under a Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) with a shared-memory progress fence, WTS/Secure Desktop lock detection, `UIA_IsPasswordPropertyId` pre-read privacy gates, focused text/selection/surface capture, `--permissions`, and `--navigate-source`.

### 2. Windows AppAdapter Tuning & Input/Menu Channels — PR 3+ (Phase 4 + Phase 5)
- Per-app Windows `AppAdapter` tuning across the 10 built-in adapters plus Windows updates to `layout-guides/`.
- Optional Windows input and menu channels (`input.activity`, `input.text` with IME composition handling, and `menu.action`).

### 3. Companion Semantic Bridges (`companions/`)
- Optional authenticated local bridges for browsers and IDEs to supply exact tab URLs, incognito/private window flags, and workspace file paths that OS accessibility trees omit or obscure.

### 4. Scoped Computer Use Execution (`ActionRequest` / `ActionReceipt`)
- Implement opt-in action drivers (`text.set`, `pointer.click`, `key.chord`, `view.zoom`) verified against fresh `TargetIdentity`, `Stamp`, and `snapshotId` leases, paired with explicit action-scoped grants separate from read-only History leases.

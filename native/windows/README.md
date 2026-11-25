# Windows Native Collector & Key Store (`native/windows/`)

This directory contains the **Rust (`windows-rs`, `stable-x86_64-pc-windows-msvc`)** native Windows Cargo workspace speaking the shared NDJSON wire protocol v1 defined in `src/shared/protocol/`.

## Current Status: Phases 0–4 + Phase 5A Shipped

### Phase 0 + Phase 1 Foundation

- **Dev & Build Baseline**: Node.js `>= 24.12.0`, pnpm, Visual Studio 2022/2026 Build Tools (C++ workload + Windows 11 SDK), LF-normalized repository (`.gitattributes`, `tsconfig.build.json` `"newLine": "lf"`).
- **Native Storage Lock (`native/storage-lock/`)**: `LockFileEx`/`UnlockFileEx` via `uv_get_osfhandle` (resolved dynamically from `node.exe` to avoid static `/MT` CRT mismatch crashes), compiled offline by `scripts/build-storage-lock.mjs` using `vswhere` + MSVC `cl.exe`/`lib.exe`, verified live on Windows (`tests/integration/native-storage-lock.test.ts`).
- **Master Key Protection (`src/storage/key-provider.ts`)**: Hardened `WindowsDpapiKeyProvider` encrypting `<dataRoot>/master.key.dpapi` via Windows DPAPI (`CryptProtectData`, `CurrentUser` scope), automatically using native `computer-history-key-store.exe` when present and falling back to PowerShell DPAPI only when absent.
- **CLI Supervisor Clean Shutdown (`src/server/cli.ts`)**: Supervisor <-> worker IPC `'shutdown'` channel with bounded fallback termination for clean `SIGINT`/`SIGTERM` handling on Windows.
- **Wire Protocol v1 Windows Sources**: `uia.tree`, `uia.text` (supporting `rangeBasis: 'visible'` and `selection.snapshot`), `uia.value`, `uia.menu`, `win32.listen-only`, and `win32.unicode`, synchronized across TypeScript (`src/shared/protocol/validate.ts`), macOS Swift (`native/macos/contract/`), and Windows Rust (`native/windows/contract/`).
- **Host & Policy Windows Adaptation**:
  - Windows password managers in `MANDATORY_EXCLUDED_APPLICATION_IDS`, Windows shell/auth overlays in `SYSTEM_UI_SKIP_APPLICATION_IDS`, Windows browsers in `BROWSER_APPLICATION_FAMILIES`, and Windows IDs across `BUILT_IN_ADAPTERS` (`src/shared/app-policy.ts`).
  - `minimalChildEnv` (`src/shared/child-env.ts`) restricting Windows child processes to 11 essential OS environment variables.
  - `win32` support in `CollectorSupervisor` (with bounded graceful stop wait), fail-closed `wts-session` / `win32-desktop` permission validation (`'not-applicable'` grants for `accessibility`/`inputMonitoring`) in `permissions.ts`, `wts-*` / `winsta0-default-wts-*` identity validation in `source-navigation.ts`, `.exe` default binary resolution / live `checkPermissions` / `openSource` in `history-service.ts`, and honest Windows default capture start options (`defaultCaptureStartOptions('win32')` enables `inputActivity` and `menuActions` while defaulting `inputText` and macOS-only `textMarkers` to `false`, preserving explicit `true` for fail-closed capability checks).

### Phase 2 + Phase 3 Native Runtime & UIA Core Collector

```text
native/windows/
  Cargo.toml     # Unified Cargo workspace (resolver = "2")
  contract/      # history-contract lib + contract-check.exe (wire v1 canonical validator)
  key-store/     # computer-history-key-store.exe (native Win32 DPAPI CryptProtectData/CryptUnprotectData)
  collector/     # computer-history-collector.exe (CollectorEngine + isolated MTA COM UIA worker)
```

- **Wire Contract Crate (`native/windows/contract/`)**: Independent Rust validator (`history-contract`) and `contract-check.exe` CLI verified against shared TypeScript fixtures via `pnpm test:cross` (`scripts/test-cross-language.mjs`).
- **Native DPAPI Key Store (`computer-history-key-store.exe`)**: Direct Win32 `CryptProtectData` / `CryptUnprotectData` binary compatible with `<dataRoot>/master.key.dpapi`, eliminating the Phase 0/1 PowerShell subprocess overhead when built into `native-bin/`.
- **Control Process (`CollectorEngine`)**: Speaks NDJSON (`<= 65,536` bytes) over `stdio`, enforces lease heartbeats and epoch fencing, passes all 12 deterministic `--fixture-scenario` modes, reports honest `--serve` capabilities, and implements live `--permissions` (`wts-session`/`win32-desktop` via WTS + `OpenInputDesktop`) and live `--navigate-source` (`SetForegroundWindow` with strict identity/session/non-browser gating).
- **Isolated MTA COM UIA Worker**: Out-of-process worker contained in a Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) with a shared-memory progress fence so hung COM/UIA calls are killed and reaped cleanly. Enforces WTS active-session & `OpenInputDesktop` (`"Default"`) lock detection, mandatory exclusions (with Win32 `.exe` basename whitespace normalization and UWP/MSIX `GetPackageFamilyName` / `ApplicationFrameHost.exe` inner-process resolution), in-memory private/incognito browser title blocking, `UIA_IsPasswordPropertyId` pre-read privacy gates and sibling pruning, `ReadBudget` (`deadlineMs`, `maxCalls`, `maxTextUnits`), Per-Monitor V2 DPI-normalized `SurfaceGeometry`, weighted traversal + `SurfaceBaseline` full/diff updates, `WinEventWatcher`, and focused text (`uia.text` / `uia.value`), selection (`uia.text`), and surface (`uia.tree`) capture.
- **Build & Test Integration**: `pnpm build:native` (`scripts/build.mjs --native`) builds release `.exe` binaries and writes `native-bin/manifest.json` (`platform: 'win32'`); `node scripts/test-native-p1.mjs` runs `cargo test`, builds release `computer-history-collector.exe`, and executes `tests/integration/native-p1.test.ts`; `tests/integration/native-windows.test.ts` exercises the built Windows binaries end-to-end.

### Phase 4 Per-App Adapters & Cross-Platform Layout Guides

- **Two-Tier `AppAdapter` Dispatch & `SafeSurfaceContext`**: Added kernel-guarded `SafeSurfaceContext` / `KernelSurfaceContext` dispatch under `native/windows/collector/src/adapters/` (`mod.rs`, `kernel.rs`, `declarative.rs`, `wechat.rs`, `figma.rs`) across all 10 built-in adapters (`generic`, `vscode-family`, `browser-family`, `terminal-family`, `qq`, `feishu`, `wechat`, `slack`, `typora`, `figma`), enforcing `ReadBudget`, fail-closed `UIA_IsPasswordPropertyId` / `TextSecurityGate` rejection, PID checks, head/tail child paging, PUA Codicon filtering, and cached-name `AXStaticText` fast paths.
- **Canonical UIA Role, Subrole & URL Enrichment**: Cached `UIA_LandmarkTypePropertyId`, `UIA_HelpTextPropertyId`, `UIA_FullDescriptionPropertyId`, and `UIA_AriaPropertiesPropertyId` (suppressed on password fields), mapped UIA `LandmarkType`/`AriaRole`/`HeadingLevel`/`StatusBar`/`AutomationId` to `AXLandmarkMain`, `AXApplicationGroup`, `AXApplicationStatus`, and `AXHeading`, and enabled post-security-gate `ValuePattern` URL lookup for `AXWebArea` and `AXLink`.
- **Custom Windows `WeChatAdapter` & `FigmaAdapter`**: Shipped custom `extract_surface` implementations for Windows WeChat Qt 4.x (`weixin.exe` / `wechat.exe` dotted `AutomationId` matching, tail-first `chat_message_list` extraction, `virtual_cell` / zero-size filtering) and Windows Figma Desktop (`figma.exe` four-zone Design & Slides layout, titlebar chrome pruning, offscreen Left Sidebar clipping), with automatic fallback to declarative traversal.
- **Cross-Platform `layout-guides/`**: Upgraded all seven built-in `layout-guides/*.md` to `platform: all` with Windows `.exe` / MSIX (`91750d7e.slack`) `bundleIds` and Windows layout guidance.

### Phase 5A Input Activity & Top Menu Bar Actions

- **Modular UIA Worker Layout (`native/windows/collector/src/uia_worker/`)**: Split the MTA COM UIA worker into focused modules (`mod.rs`, `session.rs`, `read_pipeline.rs`, `surface_backend.rs`, `target_verify.rs`, `text_read.rs`, `uia_events.rs`, `input_hook.rs`, and `menu_action/{mod,state,walker,privacy}.rs`).
- **Coarse `input.activity` (`win32.listen-only`)**: Implemented Win32 Raw Input (`RIDEV_INPUTSINK`) monitoring in `input_activity_win32.rs` emitting 1-second aggregate counts (`pointerReleases`, `dragSamples`, `scrollSamples`, `shortcutPresses`) with zero keycodes or coordinates, gated by WTS/`OpenInputDesktop` lock checks, mandatory exclusions, private browser title gating, and epoch/policy fencing.
- **Foreground Top Menu Bar `menu.action` (`uia.menu`)**: Implemented pure `MenuActionCore` (`menu_action_core.rs`) + UIA menu session tracking (`uia_worker/menu_action/`) capturing committed top menu bar paths under pre-read privacy gates.
- **Pure `InputTextCore` Foundation**: Shipped `input_text_core.rs` (buffer, debounce/flush, IME composition, causal read barrier) ready for the Phase 5B live driver.

## Build & Test Commands (Windows)

Requires Rust (`stable-x86_64-pc-windows-msvc`), Node.js `>= 24.12.0`, pnpm, and Visual Studio 2022/2026 Build Tools (Desktop development with C++ + Windows 11 SDK).

```powershell
pnpm build:native
pnpm test:cross
node scripts/test-native-p1.mjs
cargo test --manifest-path native/windows/Cargo.toml --workspace
cargo clippy --manifest-path native/windows/Cargo.toml --workspace --all-targets -- -D warnings
```

## Locked Windows Design Conventions

All `native/windows/` crates enforce these locked contracts:

1. **NDJSON Wire Transport**: LF-terminated canonical JSON frames (`<= 65,536` bytes) over `stdio`.
2. **UIA -> `AX*` Role Mapping**: Map UIA `ControlType` values to canonical `AX*` role names in `SurfaceNode.axRole`. Unmapped controls omit `axRole` and fall back to the generic `SurfaceNode.role` category (`text`, `editable`, `container`, `terminal`, `other`), preserving zero-change compatibility with downstream MCP consumers and `layout-guides/`.
3. **Windows `applicationId` Convention**:
   - Win32 / Electron / Qt apps emit lowercase `.exe` basenames (e.g., `code.exe`, `msedge.exe`, `1password.exe`), with ASCII whitespace stripped and disallowed characters normalized (e.g., `Proton Pass.exe` -> `protonpass.exe`) before mandatory-exclusion checks or wire emission.
   - UWP / MSIX apps (including windows hosted by `ApplicationFrameHost.exe`) resolve the inner application process and emit the lowercase Package Name without `_<publisherId>!Entry` (e.g., `microsoft.windowsterminal`), matching the canonical `^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$` rule.
4. **Session & Desktop Identifiers**: `osSessionId: "wts-<sessionId>"` and `desktopId: "winsta0-default-wts-<sessionId>"`.

## Remaining Planned Milestones (Phase 5B)

- **Phase 5B — Live Input Text (`win32.unicode`)**: Wire the live Windows keyboard/IME capture driver (with IME composition handling and causal read barriers) into `input_text_core.rs` and enable `input.text` capability in `--serve` mode. (`text.marker` remains macOS-only and is reported as `not-applicable-windows`.)

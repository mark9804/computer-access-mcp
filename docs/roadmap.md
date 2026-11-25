# Roadmap

## Shipped

### macOS Local Service & MCP (v0.2)

- **Standalone Daemon & Web Control Panel**: `computer-history-mcp serve` hosting the React 18 + Base UI panel (`Overview & Permissions`, `Capture Scope & Adapters`, `MCP Access`, `History & Forget`) with Admin Token authentication.
- **Standard MCP Server**: Streamable HTTP (`POST /mcp`) and `computer-history-mcp stdio` proxy supporting `history_status`, `history_search`, `history_read`, `history_layout`, `history_layout_guide`, optional `history_pause`, and opt-in `history_reload` under scoped, revocable `ClientLease` tokens, plus `computer-history://layout-guides/{id}` MCP resources.
- **Cross-Platform AEAD Segment Store**: Append-only 4 MiB AES-256-GCM segments (`seg-*.cah`), `store.lock` (`flock` / `LockFileEx`), cold/hot tiered LRU segment indexing, 14-day TTL and 16 GiB budget eviction of closed segments, and EOF torn-frame self-healing.
- **macOS Collector & AppAdapter Framework**:
  - Process-isolated control loop + ephemeral AX/input workers with atomic deadline fencing.
  - Pre-read privacy gates (mandatory excluded app families, System UI skip, private browser blocking, lock screen, Secure Input, password/protected fields).
  - Focused text, `AXTextMarker` ranges, selections, committed keyboard `input.text`, 1-second coarse `input.activity`, `menu.action`, and window-relative `surface.snapshot` geometry.
  - Ten built-in adapters (`generic`, `vscode-family`, `browser-family`, `terminal-family`, `qq`, `feishu`, `wechat`, `slack`, `typora`, `figma`) and declarative `layout-guides/`.

### Windows Phase 0 + Phase 1 Foundation

- **Windows Dev & Build Baseline**: Node.js `>= 24.12.0`, pnpm, Visual Studio 2022/2026 Build Tools (C++ workload + Windows 11 SDK), LF `.gitattributes`, and `tsconfig.build.json` `"newLine": "lf"`.
- **Native Storage Lock (`native/storage-lock/`)**: `LockFileEx`/`UnlockFileEx` via `uv_get_osfhandle` (avoiding Node static CRT `/MT` crashes), compiled offline by `scripts/build-storage-lock.mjs` via `vswhere` + MSVC `cl.exe`/`lib.exe`, and verified live on Windows (`tests/integration/native-storage-lock.test.ts`).
- **Hardened DPAPI & Clean CLI Shutdown**: `WindowsDpapiKeyProvider` hardened and live-tested on Windows (`<dataRoot>/master.key.dpapi`), plus supervisor <-> worker IPC `'shutdown'` handling in `src/server/cli.ts`.
- **Wire Protocol v1 Windows Sources & Locked Conventions**: Added `uia.tree`, `uia.text` (supporting `rangeBasis: 'visible'` and `selection.snapshot`), `uia.menu`, `win32.listen-only`, and `win32.unicode` across TypeScript (`validate.ts`) and macOS Swift (`ContractValidator.swift`). Locked UIA `ControlType` -> canonical `AX*` `SurfaceNode.axRole` mapping and Windows `applicationId` conventions (lowercase `.exe` basenames + inner-process UWP/MSIX Package Names).
- **Host & Policy Windows Adaptation**: Added Windows password managers, shell/auth System UI overlays, browsers, and built-in adapter IDs to `src/shared/app-policy.ts`; introduced `minimalChildEnv` (11 essential Windows env vars); enabled `win32` in `CollectorSupervisor` (with bounded graceful stop wait), `permissions.ts` (`wts-session`/`win32-desktop` fail-closed validation + `'not-applicable'` grants), `source-navigation.ts` (`wts-*`/`winsta0-default-wts-*`), and `history-service.ts` (`.exe` defaults, live `checkPermissions`, `openSource`).

### Windows Native Collector & Key Store — Phase 2 + Phase 3 (`native/windows/`)

- **Unified Rust (`windows-rs`) Cargo Workspace**: `native/windows/Cargo.toml` unifying `contract` (`history-contract` + `contract-check.exe`), `key-store` (`computer-history-key-store.exe`), and `collector` (`computer-history-collector.exe`), built into `native-bin/` by `pnpm build:native` with `native-bin/manifest.json` (`platform: 'win32'`) and tested cross-language via `pnpm test:cross` and `node scripts/test-native-p1.mjs`.
- **Native DPAPI Key Store**: `computer-history-key-store.exe` calling Win32 `CryptProtectData`/`CryptUnprotectData` (`CurrentUser` scope) directly against `<dataRoot>/master.key.dpapi`, automatically preferred by `WindowsDpapiKeyProvider` (retaining PowerShell DPAPI only as fallback when the native binary is absent).
- **Core UIA Collector & Process Isolation**: `CollectorEngine` + all 12 deterministic fixture scenarios, isolated out-of-process MTA COM UIA worker under a Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) with a shared-memory progress fence, WTS active-session + `OpenInputDesktop` (`"Default"`) lock detection, mandatory exclusion / incognito title / `UIA_IsPasswordPropertyId` pre-read privacy gates, focused text (`uia.text`/`uia.value`), selection (`uia.text`), and DPI-normalized surface (`uia.tree`) capture with `SurfaceBaseline` full/diff updates, live `--permissions`, and live `--navigate-source`.

### Windows Per-App Adapters & Cross-Platform Layout Guides — Phase 4

- **Windows Two-Tier `AppAdapter` & Kernel Semantics**: Added `SafeSurfaceContext` / `KernelSurfaceContext` dispatch in `native/windows/collector/src/adapters/`, UIA `LandmarkType` / `AriaRole` / `HeadingLevel` / `StatusBar` mapping to canonical `AXLandmarkMain`, `AXApplicationGroup`, `AXApplicationStatus`, and `AXHeading`, post-gate `AXWebArea` / `AXLink` `ValuePattern` URLs, cached-name `AXStaticText` fast path, and per-app tuning across all 10 built-in adapters (`generic`, `vscode-family`, `browser-family`, `terminal-family`, `qq`, `feishu`, `wechat`, `slack`, `typora`, `figma`).
- **Custom Windows `WeChatAdapter` & `FigmaAdapter`**: Shipped custom `extract_surface` implementations for Windows WeChat Qt 4.x (`weixin.exe` / `wechat.exe` dotted `AutomationId` matching, tail-first `chat_message_list` paging, `virtual_cell` / zero-size filtering) and Windows Figma Desktop (`figma.exe` four-zone Design & Slides extraction, titlebar chrome pruning, and offscreen Left Sidebar clipping), with automatic fallback to declarative traversal.
- **Cross-Platform `layout-guides/`**: Updated all seven built-in `layout-guides/*.md` (`_generic`, `feishu`, `figma`, `qq`, `slack`, `vscode-family`, `wechat`) to `platform: all` with synchronized Windows `.exe` / MSIX `bundleIds` and Windows layout guidance.

### Windows Input Activity & Top Menu Bar Actions — Phase 5A

- **Coarse `input.activity` (`win32.listen-only`)**: Added a Win32 Raw Input (`RIDEV_INPUTSINK`) listener in `native/windows/collector/src/input_activity_win32.rs` emitting 1-second aggregate counts (`pointerReleases`, `dragSamples`, `scrollSamples`, `shortcutPresses`) with zero keycodes or coordinates, gated by WTS/`OpenInputDesktop` lock checks, mandatory exclusions, private browser title gating, and epoch/policy fencing.
- **Foreground Top Menu Bar `menu.action` (`uia.menu`)**: Added pure `MenuActionCore` (`menu_action_core.rs`) and modular UIA worker session/walker/privacy modules (`uia_worker/menu_action/{mod,state,walker,privacy}.rs`, `uia_worker/uia_events.rs`, `uia_worker/input_hook.rs`) capturing committed top menu bar paths under full pre-read privacy gates.
- **Pure `InputTextCore` & Honest Defaults**: Shipped the platform-neutral `InputTextCore` state machine (`input_text_core.rs`) ready for Phase 5B, enabled `inputActivity` and `menuActions` by default in `defaultCaptureStartOptions('win32')`, and kept `inputText` (`not-implemented-phase5b`) and macOS-only `textMarkers` (`not-applicable-windows`) disabled by default with fail-closed capability checks.

## Planned Next Milestones

### 1. Windows Live Input Text Channel — Phase 5B
- Wire the live Windows keyboard/IME driver (`win32.unicode`, including IME composition handling and causal read barriers) into the already-shipped `InputTextCore` (`native/windows/collector/src/input_text_core.rs`) and flip `input.text` capability to `supported` on Windows.

### 2. Companion Semantic Bridges (`companions/`)
- Optional authenticated local bridges for browsers and IDEs to supply exact tab URLs, incognito/private window flags, and workspace file paths that OS accessibility trees omit or obscure.

# Windows Native Collector & Key Store (`native/windows/`)

This directory contains the **Rust (`windows-rs`, `stable-x86_64-pc-windows-msvc`)** native Windows Cargo workspace speaking the shared NDJSON wire protocol v1 defined in `src/shared/protocol/`.

## Current Status: Phases 0–5 Shipped

### Phase 0 + Phase 1 Foundation

- **Dev & Build Baseline**: Node.js `>= 24.12.0`, pnpm, Visual Studio 2022/2026 Build Tools (C++ workload + Windows 11 SDK), LF-normalized repository (`.gitattributes`, `tsconfig.build.json` `"newLine": "lf"`).
- **Native Storage Lock (`native/storage-lock/`)**: `LockFileEx`/`UnlockFileEx` via `uv_get_osfhandle` (resolved dynamically from `node.exe` to avoid static `/MT` CRT mismatch crashes), compiled offline by `scripts/build-storage-lock.mjs` using `vswhere` + MSVC `cl.exe`/`lib.exe`, verified live on Windows (`tests/integration/native-storage-lock.test.ts`).
- **Master Key Protection (`src/storage/key-provider.ts`)**: Hardened `WindowsDpapiKeyProvider` encrypting `<dataRoot>/master.key.dpapi` via Windows DPAPI (`CryptProtectData`, `CurrentUser` scope), automatically using native `computer-history-key-store.exe` when present and falling back to PowerShell DPAPI only when absent.
- **CLI Supervisor Clean Shutdown (`src/server/cli.ts`)**: Supervisor <-> worker IPC `'shutdown'` channel with bounded fallback termination for clean `SIGINT`/`SIGTERM` handling on Windows.
- **Wire Protocol v1 Windows Sources**: `uia.tree`, `uia.text` (supporting `rangeBasis: 'visible'` and `selection.snapshot`), `uia.value`, `uia.menu`, `win32.listen-only`, and `win32.unicode`, synchronized across TypeScript (`src/shared/protocol/validate.ts`), macOS Swift (`native/macos/contract/`), and Windows Rust (`native/windows/contract/`).
- **Host & Policy Windows Adaptation**:
  - Windows password managers in `MANDATORY_EXCLUDED_APPLICATION_IDS`, Windows shell/auth overlays in `SYSTEM_UI_SKIP_APPLICATION_IDS`, Windows browsers in `BROWSER_APPLICATION_FAMILIES`, and Windows IDs across `BUILT_IN_ADAPTERS` (`src/shared/app-policy.ts`).
  - `minimalChildEnv` (`src/shared/child-env.ts`) restricting Windows child processes to 11 essential OS environment variables.
  - `win32` support in `CollectorSupervisor` (with bounded graceful stop wait), fail-closed `wts-session` / `win32-desktop` permission validation (`'not-applicable'` grants for `accessibility`/`inputMonitoring`) in `permissions.ts`, `wts-*` / `winsta0-default-wts-*` identity validation in `source-navigation.ts`, `.exe` default binary resolution / live `checkPermissions` / `openSource` in `history-service.ts`, and platform capture start options (`defaultCaptureStartOptions('win32')` enables all Windows channels by default — `inputText: true`, `inputActivity: true`, `menuActions: true`, `selectionCapture: true`, `captureScope: 'window'` — while defaulting only macOS-specific `textMarkers` to `false` and preserving explicit `true` for fail-closed `not-applicable-windows` capability checks).

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
- **Pure `InputTextCore` Foundation**: Shipped `input_text_core.rs` (buffer, debounce/flush, IME composition, causal read barrier), wired live in Phase 5B.

### Phase 5B Live Input Text, Hybrid CJK IME & Timeout Recovery

- **Isolated Session Worker & Shared `"input-hook"` Thread (`uia_worker/input_hook.rs`, `uia_worker/session.rs`)**: Live `input.text` (`source: "win32.unicode"`) runs inside the isolated `--ax-worker --session-worker yes` child process, sharing a single dedicated `"input-hook"` OS thread (`WH_KEYBOARD_LL` + conditional `WH_MOUSE_LL`, `<10µs` callback, `HeldKeyBitset` autorepeat tracking, zero COM/UIA/`ToUnicodeEx` inside hook callbacks) with `MenuActionSession`.
- **Non-Mutating Key Translation & `VK_PACKET` (`uia_worker/input_text/translate.rs`)**: Translates printable keys via non-mutating `ToUnicodeEx(..., wFlags = 0x0004)` using a minimal Shift/CapsLock/(AltGr) key-state table and immediate stack buffer zeroization (zero dead-key corruption), plus `VK_PACKET` UTF-16 surrogate-pair assembly.
- **Hybrid TSF + Bounded IMM32 CJK IME Handling (`uia_worker/uia_events.rs`, `uia_worker/input_text/`)**: On modern TSF/UIA controls, uses agile MTA COM `IUIAutomation3::AddTextEditTextChangedEventHandler` (`TextEditChangeType_Composition` prefix purge + `VK_RETURN` suppression, and gated `TextEditChangeType_CompositionFinalized` committed Unicode text capture). On legacy non-TSF IMM32 controls where UIA `TextEdit` events are unavailable, runs a bounded `<= 25ms` `SendMessageTimeoutW` (`SMTO_ABORTIFHUNG`) `IMC_GETOPENSTATUS`/`IMC_GETCONVERSIONMODE` (`IME_CMODE_NATIVE`) probe to suppress raw pinyin/Return leakage while final committed text is captured via `text.snapshot` (never calling blocking `SendMessageW`).
- **Pre-Gate -> Translate -> Post-Gate Privacy Pipeline (`uia_worker/input_text/safety.rs`, `uia_worker/input_text/mod.rs`)**: Enforces `focus_epoch` sub-10ms flicker guarding, `ES_PASSWORD` (`GetGUIThreadInfo` + `GWL_STYLE`), `GUI_INMENUMODE`, UIA `UIA_IsPasswordPropertyId` / `is_sensitive()`, editable-only roles (`AXTextField`/`AXTextArea`, never `AXStaticText`), dual-ID application policy + `PrivateChromeVerdict::VerifiedNormal`, and buffer zeroization on every boundary.
- **Causal Read Ordering & Shared Budget (`uia_worker/read_pipeline.rs`, `engine.rs`, `worker_ipc.rs`)**: Emits `input.text` strictly before `text.snapshot`/`surface.snapshot`/`selection.snapshot` inside `ReadResult` (for `EvidenceCorrelator` `temporal-same-surface` linking), with a 2,048 UTF-16 code-unit reservation inside the 8,192 shared read budget.
- **`ReadRecovery` Timeout Recovery & Full Defaults (`engine.rs`, `src/shared/app-policy.ts`)**: Recovers `inputText: true` read timeouts across up to 3 attempts in a 60s sliding window via Job Object termination + shared-memory progress fence check (`paused/read-timeout-recovering` -> `running/read-timeout-recovered`, exhausting to `read-timeout-exhausted` / `read-timeout-unrecoverable` / `worker-exit-unconfirmed`), enables `input.text` capability in `--serve` mode, and defaults all Windows channels to enabled in `defaultCaptureStartOptions('win32')`.

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

## Platform-Specific Boundaries

- **`text.marker` (`textMarkers: false`)**: macOS `AXTextMarker` range extraction has no Windows UIA equivalent; `defaultCaptureStartOptions('win32')` leaves `textMarkers: false`, and `--serve` reports `not-applicable-windows` (failing closed with `content-capability-unavailable` if explicitly enabled). All other capture channels (`inputText`, `inputActivity`, `menuActions`, `selectionCapture`, and `captureScope: 'window'`) are supported and enabled by default on Windows.

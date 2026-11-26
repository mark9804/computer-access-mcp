# System Architecture

`computer-history-mcp` is a host-agnostic local service structured around strict fault boundaries and explicit data ownership.

## Process Topology

```text
+-------------------------------------------------------------------------+
| Node.js Daemon (`computer-history-mcp serve` on 127.0.0.1:43180)        |
|                                                                         |
|  +----------------------+   +----------------------+   +--------------+ |
|  | Web Static & /api/*  |   | MCP HTTP POST /mcp   |   | AuthStore    | |
|  | (Admin Token + Host/ |   | (Scoped ClientLease  |   | admin.token  | |
|  |  Origin checks)      |   |  read / pause tools) |   | leases.json  | |
|  +----------+-----------+   +----------+-----------+   +--------------+ |
|             |                          |                                |
|             +------------+-------------+                                |
|                          v                                              |
|             +--------------------------+                                |
|             | HistoryService           |                                |
|             | - CollectorSupervisor    | ---> Native Keychain / DPAPI   |
|             | - EvidenceCorrelator     |                                |
|             | - SegmentStore (AEAD)    | ---> `store.lock` + `seg-*.cah`|
|             +------------+-------------+                                |
+--------------------------|----------------------------------------------+
                           | NDJSON (LF-terminated canonical JSON frames,
                           | <= 65,536 bytes) over stdio + lease
                           v
+-------------------------------------------------------------------------+
| Native Collector Control Process (`computer-history-collector`)         |
|  - Enforces lease heartbeats, policy revisions, and epoch fencing       |
|  - Supervises isolated desktop AX/input worker subprocesses             |
+--------------------------|----------------------------------------------+
                           | Bounded read rounds + shared atomic deadline
                           v
+-------------------------------------------------------------------------+
| Ephemeral Desktop Worker                                                |
|  - Pre-read privacy gates (denylist, lock state, Secure Input, fields)  |
|  - `SafeAXContext` + `ReadBudget` + `AppAdapter` traversal              |
+-------------------------------------------------------------------------+
```

## Core Subsystems

### 1. Local Daemon & Control Plane (`src/server/`, `src/web/`)
- Binds exclusively to `127.0.0.1` (default port `43180`) and validates `Host` and `Origin` headers to prevent DNS rebinding and cross-site requests.
- Serves the static React 18 + Base UI Web Control Panel (`dist/web/`) at `/` and exposes `/api/*` exclusively to holders of the local `Admin Token`.
- Exposes `POST /mcp` (MCP JSON-RPC 2.0 Streamable HTTP) exclusively to holders of scoped `ClientLease` tokens, plus `computer-history-mcp stdio` as a stateless `stdin`/`stdout` bridge for stdio-only MCP hosts.
- Runs `serve` under a lightweight supervisor <-> worker loop (`src/server/cli.ts`); on Windows, shutdown signals (`SIGINT`/`SIGTERM`) are delivered over a Node IPC `'shutdown'` channel with a bounded fallback kill timer so the worker flushes and closes `SegmentStore` cleanly.

### 2. Host Coordinator & Storage (`src/host/`, `src/storage/`)
- **`CollectorSupervisor`**: Supports both `darwin` and `win32`. Manages the native Collector lifecycle (`start`, `pause`, `resume`, `stop` with a bounded graceful stop wait on Windows), spawns helpers with `minimalChildEnv` (only 11 essential OS environment variables on Windows), sends periodic lease heartbeats, validates incoming NDJSON wire frames, and fences stale `captureEpoch` or `policyRevision` observations before persistence.
- **`HistoryService`, `permissions.ts`, and `source-navigation.ts`**: Resolves platform default binaries (`.exe` suffix on Windows), applies platform capture start defaults (`defaultCaptureStartOptions`: on `win32`, all Windows channels default to enabled — `inputText: true`, `inputActivity: true`, `menuActions: true`, `selectionCapture: true`, `captureScope: 'window'` — while only macOS-specific `textMarkers` defaults to `false` and preserves explicit `true` for fail-closed `not-applicable-windows` capability checks), runs live `--permissions check` with fail-closed validation for macOS (`cg-session`/`io-session`/`io-console-compat`) and Windows (`wts-session`/`win32-desktop`, with `accessibility`/`inputMonitoring` reported as `'not-applicable'`), and validates `--navigate-source` session/desktop identities (`audit-*`/`console-audit-*` on macOS, `wts-*`/`winsta0-default-wts-*` on Windows).
- **`EvidenceCorrelator`**: Links short-window keyboard `input.text` events to concurrent `surface.snapshot` observations on the same target identity (`temporal-same-surface`) without caching plaintext across target changes.
- **`SegmentStore`**: Appends AES-256-GCM encrypted frames into 4 MiB rolling segment files (`seg-NNNNNNNN.cah`) protected by a native OS file lock (`native/storage-lock/`: `flock` on POSIX, `LockFileEx`/`UnlockFileEx` via `uv_get_osfhandle` on Windows) and platform master key protection (`MacKeychainKeyProvider` / `WindowsDpapiKeyProvider`).

### 3. Native Collectors & Two-Tier Adapters (`native/macos/`, `native/windows/`)
- **macOS (`native/macos/collector/`)**: Separates the state machine (`CollectorEngine`) from blocking Accessibility IPC (`AXWorker`). If a target application hangs an AX call past the hard round deadline, the control process terminates and reaps the worker cleanly. Centralizes all privacy checks and `ReadBudget` accounting (`deadlineMs`, `maxCalls`, `maxTextUnits`) inside `SafeAXContext` so application adapters only declare traversal policy or bounded extraction logic.
- **Windows (`native/windows/`)**: Unified **Rust (`windows-rs`, `stable-x86_64-pc-windows-msvc`)** Cargo workspace (`contract`, `key-store`, `collector`) mirroring `native/macos/`:
  - `contract` (`history-contract` + `contract-check.exe`): Independent wire v1 canonical validator cross-tested against TypeScript fixtures via `pnpm test:cross`.
  - `key-store` (`computer-history-key-store.exe`): Direct Win32 `CryptProtectData` / `CryptUnprotectData` DPAPI helper reading/writing `<dataRoot>/master.key.dpapi` (automatically preferred by `WindowsDpapiKeyProvider`, falling back to PowerShell DPAPI only when absent).
  - `collector` (`computer-history-collector.exe`): Runs `CollectorEngine` (all 12 fixture scenarios, `--serve` capability reporting, live `--permissions`, live `--navigate-source`, and `ReadRecovery` for `inputText: true` read timeouts — 3 attempts / 60s sliding window via Job Object termination + shared-memory progress fence check, transitioning `paused/read-timeout-recovering` -> `running/read-timeout-recovered` and exhausting to `read-timeout-exhausted` / `read-timeout-unrecoverable` / `worker-exit-unconfirmed`) supervising an isolated out-of-process MTA COM UIA worker (`--ax-worker --session-worker yes`, `uia_worker/`) inside a Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) with a shared-memory progress fence. Enforces WTS active-session & `OpenInputDesktop` (`"Default"`) lock detection, mandatory exclusions, in-memory private browser title gating (`PrivateChromeVerdict::VerifiedNormal`), `ES_PASSWORD` / `UIA_IsPasswordPropertyId` pre-read gates, Per-Monitor V2 DPI-normalized `SurfaceGeometry`, two-tier `AppAdapter` dispatch (`adapters/` with `SafeSurfaceContext` / `KernelSurfaceContext`, custom `WeChatAdapter` & `FigmaAdapter`, UIA `LandmarkType`/`AriaRole`/`HeadingLevel`/`StatusBar` canonical mapping, and post-gate `AXWebArea`/`AXLink` URLs), weighted traversal + `SurfaceBaseline` full/diff updates, `WinEventWatcher`, `uia.text` / `uia.value` / `uia.tree` capture, Win32 Raw Input coarse `input.activity` (`win32.listen-only` in `input_activity_win32.rs`), foreground top menu bar `menu.action` (`uia.menu` via `MenuActionCore` + `uia_worker/menu_action/`), and live `input.text` (`win32.unicode` via `InputTextCore` + `uia_worker/input_text/{translate,safety,mod}.rs`). Live `input.text` and `menu.action` share a single dedicated `"input-hook"` OS thread (`WH_KEYBOARD_LL` + conditional `WH_MOUSE_LL`, `<10µs` callback, `HeldKeyBitset` autorepeat tracking, zero COM/UIA/`ToUnicodeEx` in hook callbacks), use non-mutating `ToUnicodeEx(..., wFlags = 0x0004)` + `VK_PACKET` UTF-16 surrogate-pair assembly and hybrid TSF (`IUIAutomation3::AddTextEditTextChangedEventHandler`) + bounded 25ms `SendMessageTimeoutW` (`SMTO_ABORTIFHUNG`) IMM32 CJK IME capture, and causally emit `input.text` strictly before `text.snapshot`/`surface.snapshot`/`selection.snapshot` inside `ReadResult` (reserving 2,048 UTF-16 code units within the 8,192 shared read budget).

## Extension Boundaries

### Windows Collector Status (`native/windows/`)
- **Shipped (Phases 0–5)**: Shared wire v1 schema, `SegmentStore` + `native/storage-lock/` (`LockFileEx` via `uv_get_osfhandle`), unified Rust Cargo workspace (`contract`, native Win32 DPAPI `key-store`, `collector` with out-of-process MTA COM UIA worker + Job Object isolation + `ReadRecovery`), all 10 built-in Windows `AppAdapter` implementations (including custom `WeChatAdapter` & `FigmaAdapter`) plus cross-platform `layout-guides/*.md`, Win32 Raw Input `input.activity` (`win32.listen-only`), UIA foreground top menu bar `menu.action` (`uia.menu`), live `input.text` (`win32.unicode`) with hybrid TSF/IMM32 CJK IME capture and causal read ordering, full default Windows capture options (`defaultCaptureStartOptions('win32')`), and `pnpm build:native` / `pnpm test:cross` / `scripts/test-native-p1.mjs`.
- **Platform Boundary**: Only macOS-specific `text.marker` (`textMarkers: false`) remains disabled on Windows and is reported as `not-applicable-windows`. See [native/windows/README.md](../native/windows/README.md).

### Reserved Wire Slots (`ActionRequest` / `ActionReceipt`)
- `computer-history-mcp` focuses exclusively on desktop history capture and read-only MCP retrieval. Wire protocol v1 retains orthogonal `ActionRequest` / `ActionReceipt` message definitions bound to `TargetIdentity`, `Stamp`, and `snapshotId` for schema stability without coupling action execution into this repository.

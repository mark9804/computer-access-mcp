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
- **`HistoryService`, `permissions.ts`, and `source-navigation.ts`**: Resolves platform default binaries (`.exe` suffix on Windows), applies honest platform capture start defaults (`defaultCaptureStartOptions`: on `win32`, `textMarkers`/`inputText`/`inputActivity`/`menuActions` default to `false` while preserving explicit `true` for fail-closed capability checks), runs live `--permissions check` with fail-closed validation for macOS (`cg-session`/`io-session`/`io-console-compat`) and Windows (`wts-session`/`win32-desktop`, with `accessibility`/`inputMonitoring` reported as `'not-applicable'`), and validates `--navigate-source` session/desktop identities (`audit-*`/`console-audit-*` on macOS, `wts-*`/`winsta0-default-wts-*` on Windows).
- **`EvidenceCorrelator`**: Links short-window keyboard `input.text` events to concurrent `surface.snapshot` observations on the same target identity without caching plaintext across target changes.
- **`SegmentStore`**: Appends AES-256-GCM encrypted frames into 4 MiB rolling segment files (`seg-NNNNNNNN.cah`) protected by a native OS file lock (`native/storage-lock/`: `flock` on POSIX, `LockFileEx`/`UnlockFileEx` via `uv_get_osfhandle` on Windows) and platform master key protection (`MacKeychainKeyProvider` / `WindowsDpapiKeyProvider`).

### 3. Native Collectors & Two-Tier Adapters (`native/macos/`, `native/windows/`)
- **macOS (`native/macos/collector/`)**: Separates the state machine (`CollectorEngine`) from blocking Accessibility IPC (`AXWorker`). If a target application hangs an AX call past the hard round deadline, the control process terminates and reaps the worker cleanly. Centralizes all privacy checks and `ReadBudget` accounting (`deadlineMs`, `maxCalls`, `maxTextUnits`) inside `SafeAXContext` so application adapters only declare traversal policy or bounded extraction logic.
- **Windows (`native/windows/`)**: Unified **Rust (`windows-rs`, `stable-x86_64-pc-windows-msvc`)** Cargo workspace (`contract`, `key-store`, `collector`) mirroring `native/macos/`:
  - `contract` (`access-contract` + `contract-check.exe`): Independent wire v1 canonical validator cross-tested against TypeScript fixtures via `pnpm test:cross`.
  - `key-store` (`computer-history-key-store.exe`): Direct Win32 `CryptProtectData` / `CryptUnprotectData` DPAPI helper reading/writing `<dataRoot>/master.key.dpapi` (automatically preferred by `WindowsDpapiKeyProvider`, falling back to PowerShell DPAPI only when absent).
  - `collector` (`computer-history-collector.exe`): Runs `CollectorEngine` (all 12 fixture scenarios, honest `--serve` capability reporting, live `--permissions`, live `--navigate-source`) supervising an isolated out-of-process MTA COM UIA worker inside a Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) with a shared-memory progress fence. Enforces WTS active-session & `OpenInputDesktop` (`"Default"`) lock detection, mandatory exclusions, in-memory private browser title gating, `UIA_IsPasswordPropertyId` pre-read gates, Per-Monitor V2 DPI-normalized `SurfaceGeometry`, two-tier `AppAdapter` dispatch (`SafeSurfaceContext` / `KernelSurfaceContext` with custom `WeChatAdapter` & `FigmaAdapter`, UIA `LandmarkType`/`AriaRole`/`HeadingLevel`/`StatusBar` canonical mapping, and post-gate `AXWebArea`/`AXLink` URLs), weighted traversal + `SurfaceBaseline` full/diff updates, `WinEventWatcher`, and `uia.text` / `uia.value` / `uia.tree` capture.

## Extension Boundaries

### Windows Collector Remaining Milestones (`native/windows/`, PR 4)
- **Shipped (Phases 0–4 — PR 1 + PR 2 + PR 3)**: Shared wire v1 schema, `SegmentStore` + `native/storage-lock/` (`LockFileEx` via `uv_get_osfhandle`), unified Rust Cargo workspace (`contract`, native Win32 DPAPI `key-store`, `collector` with out-of-process MTA COM UIA worker + Job Object isolation), all 10 built-in Windows `AppAdapter` implementations (including custom `WeChatAdapter` & `FigmaAdapter`) plus cross-platform `layout-guides/*.md`, `pnpm build:native` / `pnpm test:cross` / `scripts/test-native-p1.mjs`, and honest Windows default start options.
- **Planned (PR 4 — Phase 5)**: Optional input and menu channels (`input.activity` via `win32.listen-only`, `input.text` via `win32.unicode` with IME handling, and `menu.action` via `uia.menu`). See [native/windows/README.md](../native/windows/README.md).

### Computer Use Slot (`ActionRequest` / `ActionReceipt`)
- The wire protocol reserves orthogonal `ActionRequest` (`text.set`, `pointer.click`, `key.chord`, `view.zoom`) and `ActionReceipt` messages bound to `TargetIdentity`, `Stamp`, and `snapshotId` so future desktop action drivers verify target freshness against the same identity model without coupling to History storage.

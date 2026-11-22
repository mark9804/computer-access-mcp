# System Architecture

`computer-access-mcp` is a host-agnostic local service structured around strict fault boundaries and explicit data ownership.

## Process Topology

```text
+-------------------------------------------------------------------------+
| Node.js Daemon (`computer-access-mcp serve` on 127.0.0.1:43180)         |
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
| Native Collector Control Process (`computer-access-collector`)          |
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
- Exposes `POST /mcp` (MCP JSON-RPC 2.0 Streamable HTTP) exclusively to holders of scoped `ClientLease` tokens, plus `computer-access-mcp stdio` as a stateless `stdin`/`stdout` bridge for stdio-only MCP hosts.
- Runs `serve` under a lightweight supervisor <-> worker loop (`src/server/cli.ts`); on Windows, shutdown signals (`SIGINT`/`SIGTERM`) are delivered over a Node IPC `'shutdown'` channel with a bounded fallback kill timer so the worker flushes and closes `SegmentStore` cleanly.

### 2. Host Coordinator & Storage (`src/host/`, `src/storage/`)
- **`CollectorSupervisor`**: Supports both `darwin` and `win32`. Manages the native Collector lifecycle (`start`, `pause`, `resume`, `stop` with a bounded graceful stop wait on Windows), spawns helpers with `minimalChildEnv` (only 11 essential OS environment variables on Windows), sends periodic lease heartbeats, validates incoming NDJSON wire frames, and fences stale `captureEpoch` or `policyRevision` observations before persistence.
- **`HistoryService`, `permissions.ts`, and `source-navigation.ts`**: Resolves platform default binaries (`.exe` suffix on Windows), runs live `--permissions check` with fail-closed validation for macOS (`cg-session`/`io-session`/`io-console-compat`) and Windows (`wts-session`/`win32-desktop`, with `accessibility`/`inputMonitoring` reported as `'not-applicable'`), and validates `--navigate-source` session/desktop identities (`audit-*`/`console-audit-*` on macOS, `wts-*`/`winsta0-default-wts-*` on Windows).
- **`EvidenceCorrelator`**: Links short-window keyboard `input.text` events to concurrent `surface.snapshot` observations on the same target identity without caching plaintext across target changes.
- **`SegmentStore`**: Appends AES-256-GCM encrypted frames into 4 MiB rolling segment files (`seg-NNNNNNNN.cah`) protected by a native OS file lock (`native/storage-lock/`: `flock` on POSIX, `LockFileEx`/`UnlockFileEx` via `uv_get_osfhandle` on Windows) and platform master key protection (`MacKeychainKeyProvider` / `WindowsDpapiKeyProvider`).

### 3. Native Collector & Two-Tier Adapters (`native/macos/collector/`)
- Separates the state machine (`CollectorEngine`) from blocking Accessibility IPC (`AXWorker`). If a target application hangs an AX call past the hard round deadline, the control process terminates and reaps the worker cleanly.
- Centralizes all privacy checks and `ReadBudget` accounting (`deadlineMs`, `maxCalls`, `maxTextUnits`) inside `SafeAXContext` so application adapters only declare traversal policy or bounded extraction logic.

## Extension Boundaries

### Windows Collector & Key Store (`native/windows/`)
- **Implemented (Phase 0 + Phase 1)**: Shares the identical `src/shared/protocol` wire v1 schema (including Windows sources `uia.tree`, `uia.text`, `uia.value`, `uia.menu`, `win32.listen-only`, `win32.unicode`), `SegmentStore` format, `native/storage-lock/` (`LockFileEx` via `uv_get_osfhandle`, built offline with MSVC), hardened `WindowsDpapiKeyProvider` (`CryptProtectData`, `CurrentUser` scope, live-tested on Windows), Windows `app-policy.ts` lists, `minimalChildEnv`, and `win32` Host/daemon integration.
- **Planned (PR 2 — Phase 2 + Phase 3)**: Native **Rust (`windows-rs`, `stable-x86_64-pc-windows-msvc`)** Cargo workspace mirroring `native/macos/` (`contract`, `key-store`, `collector`). Ships native DPAPI `computer-access-key-store.exe` (compatible with `master.key.dpapi`, replacing PowerShell subprocess overhead), `CollectorEngine` + 12 fixture scenarios, an isolated out-of-process MTA COM UIA worker managed under a Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) with a shared-memory progress fence, WTS/Secure Desktop lock detection, `UIA_IsPasswordPropertyId` pre-read privacy gates, focused text/selection/surface capture, `--permissions`, and `--navigate-source`.
- **Planned (PR 3+ — Phase 4 + Phase 5)**: Per-app Windows `AppAdapter` tuning across the 10 built-in adapters (`layout-guides/` Windows updates) and optional input/menu channels (`input.activity`, `input.text` with IME handling, `menu.action`). See [native/windows/README.md](../native/windows/README.md).

### Computer Use Slot (`ActionRequest` / `ActionReceipt`)
- The wire protocol reserves orthogonal `ActionRequest` (`text.set`, `pointer.click`, `key.chord`, `view.zoom`) and `ActionReceipt` messages bound to `TargetIdentity`, `Stamp`, and `snapshotId` so future desktop action drivers verify target freshness against the same identity model without coupling to History storage.

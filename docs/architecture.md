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
                           | Length-prefixed JSON frames (stdio) + lease
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

### 2. Host Coordinator & Storage (`src/host/`, `src/storage/`)
- **`CollectorSupervisor`**: Manages the native Collector lifecycle (`start`, `pause`, `resume`, `stop`), sends periodic lease heartbeats, validates incoming wire frames, and fences stale `captureEpoch` or `policyRevision` observations before persistence.
- **`EvidenceCorrelator`**: Links short-window keyboard `input.text` events to concurrent `surface.snapshot` observations on the same target identity without caching plaintext across target changes.
- **`SegmentStore`**: Appends AES-256-GCM encrypted frames into 4 MiB rolling segment files (`seg-NNNNNNNN.cah`) protected by a native OS file lock (`native/storage-lock/`).

### 3. Native Collector & Two-Tier Adapters (`native/macos/collector/`)
- Separates the state machine (`CollectorEngine`) from blocking Accessibility IPC (`AXWorker`). If a target application hangs an AX call past the hard round deadline, the control process terminates and reaps the worker cleanly.
- Centralizes all privacy checks and `ReadBudget` accounting (`deadlineMs`, `maxCalls`, `maxTextUnits`) inside `SafeAXContext` so application adapters only declare traversal policy or bounded extraction logic.

## Extension Boundaries

### Windows Collector (`native/windows/`)
- Shares the identical `src/shared/protocol` wire schema, `SegmentStore` format, and `KeyProvider` contract (`WindowsDpapiKeyProvider` using `CryptProtectData` in `CurrentUser` scope).
- Planned native implementation isolates a Win32 event broker from an out-of-process MTA UI Automation (`UIAutomationCore`) worker.

### Computer Use Slot (`ActionRequest` / `ActionReceipt`)
- The wire protocol reserves orthogonal `ActionRequest` (`text.set`, `pointer.click`, `key.chord`, `view.zoom`) and `ActionReceipt` messages bound to `TargetIdentity`, `Stamp`, and `snapshotId` so future desktop action drivers verify target freshness against the same identity model without coupling to History storage.

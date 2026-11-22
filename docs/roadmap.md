# Roadmap

## Shipped (macOS Local Service & MCP v0.2)

- **Standalone Daemon & Web Control Panel**: `computer-access-mcp serve` hosting the React 18 + Base UI panel (`Overview & Permissions`, `Capture Scope & Adapters`, `MCP Access`, `History & Forget`) with Admin Token authentication.
- **Standard MCP Server**: Streamable HTTP (`POST /mcp`) and `computer-access-mcp stdio` proxy supporting `history_status`, `history_search`, `history_read`, `history_layout`, and optional `history_pause` under scoped, revocable `ClientLease` tokens.
- **Cross-Platform AEAD Segment Store**: Append-only 4 MiB AES-256-GCM segments (`seg-*.cah`), `store.lock` (`flock` / `LockFileEx`), cold/hot tiered LRU segment indexing, 14-day TTL and 16 GiB budget eviction of closed segments, and EOF torn-frame self-healing.
- **macOS Collector & AppAdapter Framework**:
  - Process-isolated control loop + ephemeral AX/input workers with atomic deadline fencing.
  - Pre-read privacy gates (mandatory excluded app families, lock screen, Secure Input, password/protected fields).
  - Focused text, `AXTextMarker` ranges, selections, committed keyboard `input.text`, 1-second coarse `input.activity`, and window-relative `surface.snapshot` geometry.
  - Built-in declarative adapters: `generic`, `vscode-family` (Antigravity IDE, VSCode, Cursor, Windsurf), `qq`, and `feishu`.

## Planned Next Milestones

### 1. Windows Native Collector (`native/windows/`)
- Implement out-of-process Windows Collector speaking the shared `src/shared/protocol` stdio frame contract.
- Isolate Win32 foreground/focus event monitoring from an MTA UI Automation (`UIAutomationCore`) worker with equivalent `ReadBudget` and password/protected-control (`IsPassword`) pre-read gates.
- Wire end-to-end validation on Windows NTFS with `WindowsDpapiKeyProvider` and `LockFileEx`.

### 2. Companion Semantic Bridges (`companions/`)
- Optional authenticated local bridges for browsers and IDEs to supply exact tab URLs, incognito/private window flags, and workspace file paths that OS accessibility trees omit or obscure.

### 3. Scoped Computer Use Execution (`ActionRequest` / `ActionReceipt`)
- Implement opt-in action drivers (`text.set`, `pointer.click`, `key.chord`, `view.zoom`) verified against fresh `TargetIdentity`, `Stamp`, and `snapshotId` leases, paired with explicit action-scoped grants separate from read-only History leases.

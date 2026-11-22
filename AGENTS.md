# AGENTS.md

## Mission

`computer-access-mcp` is a host-agnostic local desktop context daemon. It captures user-authorized desktop text and window layout snapshots into a cross-platform AEAD segment store, serves a Web Control Panel for human control, and exposes a scoped MCP endpoint for AI agents (Antigravity, Claude Code, Cursor).

## Directory Map

- `src/shared/` — Canonical wire protocol (`Observation`, `ActionRequest`), REST DTOs, and app policy constants.
- `src/storage/` — Cross-platform AEAD `SegmentStore` (`seg-*.cah`), `StorageLock`, and `KeyProvider` (Keychain / DPAPI).
- `src/host/` — `CollectorSupervisor`, `EvidenceCorrelator`, and `HistoryService`.
- `src/server/` — `127.0.0.1` HTTP server, Admin/Client auth store, `/mcp` handler, and `stdio` proxy CLI.
- `src/web/` — React 18 + Base UI control panel built into `dist/web/`.
- `layout-guides/` — Declarative per-app Markdown guides (`SKILL.md`-style frontmatter) served over MCP (`history_layout_guide` and `computer-access://layout-guides/{id}`) with user override support in `<dataDir>/layout-guides/`.
- `locale/` — Paired `zh.json` and `en.json` UI dictionaries.
- `native/storage-lock/` — C Node-API exclusive file lock (`flock` on POSIX; `LockFileEx`/`UnlockFileEx` via `uv_get_osfhandle` on Windows, compiled offline with clang or MSVC).
- `native/macos/` — `contract` validator, `key-store` helper, and `collector` (thin AX kernel + `AppAdapter` framework).
- `native/windows/` — Planned Rust (`windows-rs`) Cargo workspace mirroring `native/macos/` (`contract`, `key-store`, `collector`); Phase 0/1 Windows baseline (`storage-lock.node`, DPAPI `KeyProvider`, wire v1 Windows sources, and Host/policy adaptation) is shipped.
- `docs/` — Architecture, data model, adapter guide, security model, and roadmap.
- `tests/` — Contract, storage, server/MCP, and integration tests.

## Four Non-Negotiable Invariants

1. **Process Isolation**: Node daemon, native Collector control loop, and AX/UIA read workers run in separate fault boundaries; hung workers are killed and reaped without wedging the daemon (with Windows Job Object isolation planned in `native/windows/`).
2. **Pre-Read Privacy Gates & Epoch Fencing**: Mandatory excluded families (macOS: 1Password, Apple Passwords, Keychain Access, Bitwarden, Dashlane, LastPass, NordPass, Proton Pass, Safari; Windows: `1password.exe`, `bitwarden.exe`, `keepass.exe`, `keepassxc.exe`, `dashlane.exe`, `lastpass.exe`, `nordpass.exe`, `protonpass.exe`), silent System UI skips (macOS and Windows shell/auth overlays), private browser windows, locked screens, Secure Input, and protected fields (`AXSecureTextField`, `containsProtectedContent`, and Windows `UIA_IsPasswordPropertyId`) block reads before text extraction. Stale `Stamp` epochs drop on pause, stop, or policy change.
3. **Cross-Platform AEAD Segment Integrity**: `store.lock` holds an OS lock (`flock` / `LockFileEx`) without unlinking the file. Frames in `seg-NNNNNNNN.cah` use AES-256-GCM with AAD `${storeId}:${segmentSeq}:${frameIndex}`; segments close at 4 MiB so 14-day TTL and 16 GiB eviction only unlink closed files (APFS & NTFS safe), with cold/hot tiered indexing keeping RAM bounded.
4. **Admin vs MCP Client Separation**: Only `admin.token` initializes keys, starts/resumes capture, edits policy, runs Forget, or issues tokens. External agents receive hashed `ClientLease` tokens restricted to `read`, optional `pause`, and opt-in `reload` (never starts stopped/paused capture or widens scope).

## Build & Test Commands

Source files and TypeScript build output use LF line endings (enforced via `.gitattributes` and `tsconfig.build.json` `"newLine": "lf"`).

```bash
# Cross-platform (macOS & Windows; Windows requires VS 2022/2026 C++ Build Tools + Windows 11 SDK for build:storage-lock)
pnpm build:storage-lock
pnpm schema:check
pnpm typecheck
pnpm build
pnpm test

# macOS native packages & cross-language contract tests
pnpm build:native
pnpm test:cross
swift test --package-path native/macos/contract
swift test --package-path native/macos/collector
swift test --package-path native/macos/key-store
```

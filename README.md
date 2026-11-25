# computer-history-mcp

Host-agnostic local desktop history daemon, Web Control Panel, and scoped Model Context Protocol (MCP) server.

`computer-history-mcp` captures user-authorized desktop text, selections, input text, and window layout geometry into a local AES-256-GCM segment store. Humans manage permissions, capture scope, retention, and token leases through a local Web UI; AI agents (Antigravity, Claude Code, Cursor, etc.) query retained context through a least-privilege MCP interface.

## Architecture

```text
+---------------------------+        Admin Bearer Token        +-------------------------------+
|  Browser Control Panel    | <------------------------------> |  computer-history-mcp serve   |
|  http://127.0.0.1:43180/  |        REST /api/* + Static      |  (Node HTTP Daemon, 127.0.0.1)|
+---------------------------+                                  +---------------+---------------+
                                                                               |
+---------------------------+     Scoped Client Lease Token                    |
|  AI Agents (Antigravity,  |     POST /mcp (Streamable HTTP)                  |
|  Claude Code, Cursor)     | <------------------------------------------------+
|  or `stdio` proxy CLI     |     Tools: status/search/read/layout/pause       |
+---------------------------+                                                  |
                                                   +---------------------------+---------------------------+
                                                   |                                                       |
                                                   v                                                       v
                                    +------------------------------+                        +------------------------------+
                                    |  SegmentStore (AEAD Log)     |                        |  Native Collector Supervisor |
                                    |  - store.lock (flock/Win32)  |                        |  - macOS AX / Windows UIA    |
                                    |  - store.meta + seg-*.cah    |                        |  - AppAdapter Meta-Framework |
                                    |  - Keychain / DPAPI 32B Key  |                        |  - Pre-read Privacy Gates    |
                                    +------------------------------+                        +------------------------------+
```

## Quickstart

### macOS (Full Local Daemon + Native AX Collector)

Requirements: Node.js `>= 24.12.0`, pnpm, and Xcode Command Line Tools (`swift` / `clang`).

```bash
pnpm install
pnpm build:storage-lock
pnpm build:native
pnpm build
pnpm serve
```

### Windows (Local Daemon + Native Rust UIA Collector & DPAPI Key Store)

Requirements: Node.js `>= 24.12.0`, pnpm, Visual Studio 2022/2026 Build Tools (Desktop development with C++ workload + Windows 11 SDK), and Rust (`stable-x86_64-pc-windows-msvc`).

```powershell
pnpm install
pnpm build:native
pnpm test
pnpm serve
```

> **Windows Collector Status**: Phases 0–4 and Phase 5A are shipped in the unified Rust (`windows-rs`) workspace (`native/windows/` -> `contract`, native Win32 DPAPI `computer-history-key-store.exe`, and `computer-history-collector.exe`), including the out-of-process MTA COM UIA worker with Job Object isolation and shared-memory progress fence, WTS/`OpenInputDesktop` lock detection, `UIA_IsPasswordPropertyId`/incognito/policy pre-read privacy gates, focused text (`uia.text`/`uia.value`), selection (`uia.text`), window surface (`uia.tree`), coarse `input.activity` (`win32.listen-only` via Win32 Raw Input), foreground top menu bar `menu.action` (`uia.menu`), `--permissions`, `--navigate-source`, per-app tuning across all 10 built-in Windows adapters (including custom `WeChatAdapter` & `FigmaAdapter`, UIA `LandmarkType`/`AriaRole`/`StatusBar` canonical mapping, and cross-platform `layout-guides/*.md`), and honest Windows default capture options (`inputActivity` and `menuActions` enabled by default; `inputText` and macOS-only `textMarkers` disabled by default). Only live Windows `input.text` (`win32.unicode`, Phase 5B — wiring the Win32 keyboard/IME driver into the already-shipped `InputTextCore`) remains planned—see [native/windows/README.md](native/windows/README.md) and [docs/roadmap.md](docs/roadmap.md).

When `computer-history-mcp serve` starts, it listens on `127.0.0.1:43180` and prints a local login URL:

```text
Web UI:   http://127.0.0.1:43180/#token=<admin-token>
MCP HTTP: http://127.0.0.1:43180/mcp
```

1. Open the printed `Web UI` link in your browser (the `#token=...` fragment is stored in `sessionStorage` and immediately cleared from the URL bar).
2. Click **Initialize Encryption Key** on the **Overview & Permissions** tab, grant macOS **Accessibility** (and optional **Input Monitoring**) on macOS (Windows UIA requires no separate TCC grant), and click **Start Capture**.
3. Open **MCP Access (Client Tokens)** to generate a scoped token (`chmcp_...`) for your AI client.

## Connecting Antigravity / Claude / Cursor via MCP

After creating a Client Token in the Web Control Panel, click **Copy HTTP MCP Config JSON** or **Copy stdio MCP Config JSON**.

### Option A: Streamable HTTP (Direct)

```json
{
  "mcpServers": {
    "computer-history": {
      "url": "http://127.0.0.1:43180/mcp",
      "headers": {
        "Authorization": "Bearer chmcp_<your_client_token>"
      }
    }
  }
}
```

### Option B: `stdio` Proxy (Recommended for Local Source Checkout)

Use the full `node` and `dist/server/cli.js` paths (the Web Control Panel's **Copy stdio MCP Config JSON** button fills both paths automatically for your machine):

```json
{
  "mcpServers": {
    "computer-history": {
      "command": "/full/path/to/node",
      "args": ["/full/path/to/repo/dist/server/cli.js", "stdio"],
      "env": {
        "COMPUTER_HISTORY_TOKEN": "chmcp_<your_client_token>",
        "COMPUTER_HISTORY_URL": "http://127.0.0.1:43180/mcp"
      }
    }
  }
}
```

### Exposed MCP Tools

| Tool | Required Scope | Purpose |
|---|---|---|
| `history_status` | `read` | Service state, active capture scope, and retained time range |
| `history_search` | `read` | Search retained observations by keyword, bundle ID, kind, and time window |
| `history_read` | `read` | Read the full observation record by `eventId` or `snapshotId` |
| `history_layout` | `read` | Read window-relative node bounds and text from a surface snapshot |
| `history_layout_guide` | `read` | Read cross-platform per-app layout guides (or list available guides) for interpreting `history_layout` responses |
| `history_pause` | `pause` | Pause active capture immediately (cannot start or resume capture) |
| `history_reload` | `reload` (opt-in) | Hot-reload the native Collector (`collector`) or restart the local daemon (`server`); preserves an already-running scope only, never auto-starts |

## Built-In Application Adapters

Both the macOS Swift Collector (`native/macos/`) and Windows Rust Collector (`native/windows/`) pair a thin accessibility security kernel with ten built-in adapters (`generic` fallback, seven declarative adapters, and two custom `extractSurface` adapters): `vscode-family` (Antigravity, VSCode, VSCode Insiders, Cursor, Windsurf), `browser-family` (Chrome, Chromium, Brave, Edge, Arc, Dia, Vivaldi, Opera, Firefox, Zen, Floorp, Comet, Atlas, Helium), `terminal-family` (Terminal, iTerm2, Ghostty, Warp, Kitty, WezTerm, Rio, Wave, Windows Terminal, Alacritty, ConHost, Mintty), `qq`, `feishu`, `wechat` (WeChat Qt 4.x custom `extractSurface` with `AXIdentifier` / Windows dotted `AutomationId` matching), `slack` (including Windows MSIX `91750d7e.slack`), `typora`, and `figma` (Figma Design & Slides custom four-zone `extractSurface`). Paired cross-platform `layout-guides/*.md` (`platform: all`) document app-specific coordinate semantics for MCP clients. See [docs/adapters.md](docs/adapters.md).

## Security Model Summary

- **Pre-Read Blocking**: Password managers (1Password, Apple Passwords, Keychain Access, Bitwarden, KeePass, KeePassXC, Dashlane, LastPass, NordPass, Proton Pass), `com.apple.safari*`, private/incognito browser windows, macOS and Windows System UI overlays, locked screens, active Secure Input, and password/protected UI fields are blocked before text extraction.
- **Encrypted at Rest**: Observations are encrypted frame-by-frame using AES-256-GCM in 4 MiB append-only segments (`seg-*.cah`), keyed by a 32-byte master key in macOS Keychain (or Windows DPAPI) and guarded by an OS file lock (`flock` on POSIX, `LockFileEx` via `uv_get_osfhandle` on Windows).
- **Two-Tier Credentials**: Full control requires the local `admin.token` (protected by `Host`/`Origin` validation against DNS rebinding and cross-site requests). Agent tokens store only SHA-256 digests on disk, carry explicit expiration/revocation, and never receive lifecycle start, policy edit, or Forget permissions.

## Uninstall

### macOS / Linux (and Git Bash on Windows)

Run the bundled [uninstall.sh](uninstall.sh) script from the repository root to stop running processes, revoke all keys, delete both current (`computer-history-mcp`) and legacy (`computer-access-mcp`) encrypted stores, and uninstall global CLI links plus local build artifacts:

```bash
# Preview every action without modifying anything
./uninstall.sh --dry-run

# Interactive uninstall (prompts before deletion)
./uninstall.sh

# Non-interactive uninstall (also supports repeatable --data-dir <path> and --keep-build)
./uninstall.sh --yes
```

What `uninstall.sh` removes:
1. **Processes**: Stops running `computer-history-mcp` / `computer-access-mcp` daemons, `stdio` proxies, collectors, and key-store helpers.
2. **All Keys & Credentials**:
   - Deletes all macOS Login Keychain master key entries under `com.computer-history.mcp` and legacy `com.computer-access.mcp` (all accounts, including `master-key` and `history.<deviceId>`).
   - Revokes `admin.token`, `auth-leases.json` (invalidating all issued `chmcp_*` and legacy `camcp_*` MCP client tokens), `restart-resume.json`, and Windows `master.key.dpapi` inside each data directory.
3. **Current & Legacy Data Stores**: Deletes `~/Library/Application Support/computer-history-mcp` and `~/Library/Application Support/computer-access-mcp` on macOS (or `$XDG_DATA_HOME` / `~/.local/share` on Linux, `%LOCALAPPDATA%` under Git Bash, plus `$COMPUTER_HISTORY_DATA_DIR`, `$COMPUTER_ACCESS_DATA_DIR`, and any `--data-dir` path), along with macOS runtime lock directories in `/private/tmp/dsh-computer-{history,access}-<uid>`.
4. **Installed CLI & Build Outputs**: Uninstalls global `pnpm` / `npm` links for `computer-history-mcp` / `computer-access-mcp` if present, and removes local `dist/`, `native-bin/`, and native build directories (unless `--keep-build` is passed).

### Windows (PowerShell)

Run the bundled [uninstall.ps1](uninstall.ps1) script from the repository root to stop running processes (and any matching scheduled tasks), zeroize and revoke DPAPI master keys, admin tokens, and MCP client leases, delete both current (`%LOCALAPPDATA%\computer-history-mcp`) and legacy (`%LOCALAPPDATA%\computer-access-mcp`) encrypted stores plus temporary fixture locks, and uninstall global CLI links and local build outputs:

```powershell
# Preview every action without modifying anything
.\uninstall.ps1 -DryRun

# Interactive uninstall (prompts before deletion)
.\uninstall.ps1

# Non-interactive uninstall (also supports -DataDir <path[]> and -KeepBuild)
.\uninstall.ps1 -Yes
```

If PowerShell script execution is restricted in your shell, run `powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -DryRun` (or `-Yes`).

### Manual Cleanup (All Platforms)

- Remove `"computer-history"` / `"computer-access"` entries from your MCP client configuration (Antigravity, Claude Code, Cursor).
- On macOS, optionally revoke **Accessibility** and **Input Monitoring** permissions for your terminal/host app in **System Settings -> Privacy & Security**.
- Delete the cloned repository directory if you no longer need the source checkout.

## Documentation

See [docs/README.md](docs/README.md) for the full design documentation index.

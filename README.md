# computer-access-mcp

Host-agnostic local desktop history daemon, Web Control Panel, and scoped Model Context Protocol (MCP) server.

`computer-access-mcp` captures user-authorized desktop text, selections, input text, and window layout geometry into a local AES-256-GCM segment store. Humans manage permissions, capture scope, retention, and token leases through a local Web UI; AI agents (Antigravity, Claude Code, Cursor, etc.) query retained context through a least-privilege MCP interface.

## Architecture

```text
+---------------------------+        Admin Bearer Token        +-------------------------------+
|  Browser Control Panel    | <------------------------------> |  computer-access-mcp serve    |
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
                                    |  - store.lock (flock/Win32)  |                        |  - macOS AX Collector/Worker |
                                    |  - store.meta + seg-*.cah    |                        |  - AppAdapter Meta-Framework |
                                    |  - Keychain / DPAPI 32B Key  |                        |  - Pre-read Privacy Gates    |
                                    +------------------------------+                        +------------------------------+
```

## Quickstart

Requirements: Node.js `>= 24.12.0`, pnpm, and Xcode Command Line Tools (`swift` / `clang` on macOS).

```bash
pnpm install
pnpm build:storage-lock
pnpm build:native
pnpm build
pnpm serve
```

When `computer-access-mcp serve` starts, it listens on `127.0.0.1:43180` and prints a local login URL:

```text
Web UI:   http://127.0.0.1:43180/#token=<admin-token>
MCP HTTP: http://127.0.0.1:43180/mcp
```

1. Open the printed `Web UI` link in your browser (the `#token=...` fragment is stored in `sessionStorage` and immediately cleared from the URL bar).
2. Click **Initialize Encryption Key** on the **Overview & Permissions** tab, grant macOS **Accessibility** (and optional **Input Monitoring**), and click **Start Capture**.
3. Open **MCP Access (Client Tokens)** to generate a scoped token (`camcp_...`) for your AI client.

## Connecting Antigravity / Claude / Cursor via MCP

After creating a Client Token in the Web Control Panel, click **Copy HTTP MCP Config JSON** or **Copy stdio MCP Config JSON**.

### Option A: Streamable HTTP (Direct)

```json
{
  "mcpServers": {
    "computer-access": {
      "url": "http://127.0.0.1:43180/mcp",
      "headers": {
        "Authorization": "Bearer camcp_<your_client_token>"
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
    "computer-access": {
      "command": "/full/path/to/node",
      "args": ["/full/path/to/repo/dist/server/cli.js", "stdio"],
      "env": {
        "COMPUTER_ACCESS_TOKEN": "camcp_<your_client_token>",
        "COMPUTER_ACCESS_URL": "http://127.0.0.1:43180/mcp"
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
| `history_pause` | `pause` | Pause active capture immediately (cannot start or resume capture) |
| `history_reload` | `reload` (opt-in) | Hot-reload the native Collector (`collector`) or restart the local daemon (`server`); preserves an already-running scope only, never auto-starts |

## Built-In Application Adapters

The macOS Collector pairs a thin AX security kernel with eight built-in adapters (`generic` fallback, six declarative adapters, and the custom `wechat` adapter): `vscode-family` (Antigravity, VSCode, Cursor, Windsurf), `browser-family` (Chrome, Chromium, Brave, Edge, Arc, Dia, Vivaldi, Opera, Firefox, Zen, Floorp, Comet, Atlas, Helium), `terminal-family` (Terminal, iTerm2, Ghostty, Warp, Kitty, WezTerm, Rio, Wave), `qq`, `feishu`, `wechat` (WeChat 4.x Qt custom `extractSurface` + `AXParent` ownership proof), and `slack` (Slack). Surface reads batch `AXPosition`/`AXSize`/`AXIdentifier` in metadata queries, fetch `AXStaticText` bounded ranges in a single shot (with `safeTitle`/`AXValue` fallback on verified non-sensitive leaves), and trigger a serial `Return` fast focused read followed by a 200 ms full surface refresh. See [docs/adapters.md](docs/adapters.md).

## Security Model Summary

- **Pre-Read Blocking**: Password managers (1Password, Apple Passwords, Keychain Access, Bitwarden, Dashlane, LastPass, NordPass, Proton Pass), `com.apple.safari*`, private/incognito browser windows, System UI overlays, locked screens, active Secure Input, and password/protected UI fields are blocked before text extraction.
- **Encrypted at Rest**: Observations are encrypted frame-by-frame using AES-256-GCM in 4 MiB append-only segments (`seg-*.cah`), keyed by a 32-byte master key in macOS Keychain (or Windows DPAPI).
- **Two-Tier Credentials**: Full control requires the local `admin.token` (protected by `Host`/`Origin` validation against DNS rebinding and cross-site requests). Agent tokens store only SHA-256 digests on disk, carry explicit expiration/revocation, and never receive lifecycle start, policy edit, or Forget permissions.

## Documentation

See [docs/README.md](docs/README.md) for the full design documentation index.

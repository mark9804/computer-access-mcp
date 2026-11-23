# Privacy & Security Model

`computer-access-mcp` enforces privacy before reading desktop content, encrypts all retained observations at rest, and strictly separates human administration from external AI agent access.

## 1. Pre-Read Privacy Gates

Sensitive contexts are blocked in the native Collector before any text or surface query runs:

- **Mandatory Excluded Application Families**: Case-insensitive exact or dotted-prefix matches enforced unconditionally in both Host policy validation (`src/shared/app-policy.ts`) and the native Collector kernel:
  - **macOS**: `com.1password`, `com.agilebits.onepassword`, `com.agilebits.onepassword7`, `com.agilebits.onepassword-osx`, `com.apple.safari`, `com.apple.passwords`, `com.apple.keychainaccess`, `com.bitwarden.desktop`, `com.dashlane.dashlanephonefinal`, `com.lastpass.lastpass`, `com.nordsec.nordpass`, and `me.proton.pass`.
  - **Windows**: `1password.exe`, `bitwarden.exe`, `keepass.exe`, `keepassxc.exe`, `dashlane.exe`, `lastpass.exe`, `nordpass.exe`, and `protonpass.exe`.
- **System UI Silent Skipping**: OS shell and authentication overlays are skipped silently without emitting gap records and rejected by Host policy admission:
  - **macOS**: `com.apple.windowmanager`, `com.apple.controlcenter`, `com.apple.notificationcenterui`, `com.apple.securityagent`, `com.apple.localauthentication.uiagent`, `com.apple.localauthenticationremoteservice`, `com.apple.loginwindow`, `com.apple.usernotificationcenter`.
  - **Windows**: `lockapp.exe`, `logonui.exe`, `credentialuibroker.exe`, `consent.exe`, `shellexperiencehost.exe`, `startmenuexperiencehost.exe`, `searchhost.exe`, `searchapp.exe`, `textinputhost.exe`, `pickerhost.exe`.
- **Private / Incognito Browser Window Blocking**: `BROWSER_APPLICATION_FAMILIES` covers both macOS bundle families and Windows browser executables (`chrome.exe`, `chromium.exe`, `msedge.exe`, `brave.exe`, `firefox.exe`, `vivaldi.exe`, `opera.exe`, `arc.exe`, `zen.exe`, `floorp.exe`, `waterfox.exe`, `librewolf.exe`, `tor.exe`, `comet.exe`, `dia.exe`). Before traversing a browser window, the Collector inspects the root window title in memory for private browsing markers (`(incognito)`, `(private)`, `inprivate`, `private browsing`, `(privat)`, `(privato)`, `无痕`, `隐私浏览`, `私人浏览`, case-insensitive). Matching windows abort immediately with `surface-security-excluded`, reading zero content and omitting the window title.
- **User Application Filter**: Supports `denylist` (capture all non-excluded apps) and `allowlist` (capture only explicitly listed application IDs, with browser capture disabled).
- **Desktop Session & Secure Input**: Locked screens (`desktop-unavailable`) and active macOS Secure Event Input suppress text and keyboard capture immediately and wipe any in-flight input buffer. On Windows, `permissions.ts` enforces fail-closed validation on `wts-session` and `win32-desktop` lock reports (with `accessibility` and `inputMonitoring` reported as `'not-applicable'`), and `native/windows/collector/` enforces dual-sampled WTS active-session (`WTSActive` + `WTS_SESSIONSTATE_UNLOCK`) and `OpenInputDesktop` (`"Default"` desktop, rejecting `"Winlogon"` / UAC Secure Desktop / `"Screen-saver"`) checks before any UIA read.
- **Password & Protected Fields**: Controls reporting `AXSecureTextField`, password subroles, or `containsProtectedContent == true` (on macOS) and `UIA_IsPasswordPropertyId` (in the Windows UIA worker) are rejected with a `secure-field` gap diagnostic, strip batched metadata (`Name`/`AutomationId` cleared immediately, sibling password nodes pruned with `tree-security-pruned`), and read zero text (`AXValue` / UIA `Value`/`Text` patterns are never included in the pre-classification metadata batch).
- **Foreground Top Menu Bar Actions (`menu.action`)**: Captures only committed top menu bar paths for the active allowed application (strictly excluding the macOS Apple menu, hover-only highlights, screen coordinates, and arbitrary keycodes). Enforces the same pre-read privacy gates (mandatory exclusions, System UI skip, private/incognito browser blocking, locked screen, Secure Input, `ContentGate`, and epoch/application-identity fencing) and degrades gracefully in AX-only mode when Input Monitoring is absent. (On Windows, `menu.action`, `input.text`, `input.activity`, and `text.marker` are reported as `unsupported` until Phase 5 and default to `false` in start options, failing closed with `content-capability-unavailable` if explicitly enabled.)

## 2. Encryption & Key Management (`KeyProvider`)

- **32-Byte AES-256 Master Key**:
  - **macOS (`MacKeychainKeyProvider`)**: Stored in the user login Keychain (`service: com.computer-access.mcp`) via the native `computer-access-key-store` helper. Keys are created only on explicit `Initialize Encryption Key` action.
  - **Windows (`WindowsDpapiKeyProvider`)**: Stored in `<dataRoot>/master.key.dpapi` encrypted with Windows DPAPI (`CryptProtectData`, `CurrentUser` scope), verified live on Windows with randomized temp-file atomic writes and a minimal 11-variable child environment. Automatically invokes the native Rust `computer-access-key-store.exe` (`native/windows/key-store/`) calling Win32 `CryptProtectData`/`CryptUnprotectData` directly when present in `native-bin/`, falling back to the PowerShell DPAPI wrapper only when the native binary is absent.
  - **Tests (`MemoryKeyProvider`)**: Ephemeral in-memory 32-byte key for isolated automated tests.
- **Directory Hygiene & Subprocess Environment Minimization**: `prepareDataDirectory` rejects symlinks and reparse points (`lstat`) and enforces `0700` directory / `0600` file permissions on POSIX. On Windows, `minimalChildEnv` (`src/shared/child-env.ts`) passes only 11 essential OS environment variables (`SystemRoot`, `WINDIR`, `SystemDrive`, `ComSpec`, `PATH`, `TEMP`, `TMP`, `USERPROFILE`, `LOCALAPPDATA`, `APPDATA`, `PATHEXT`) to spawned helper/collector processes so host secrets never leak.

## 3. Two-Tier Authentication & Local Network Hardening

The HTTP server binds to `127.0.0.1` by default and verifies `Host` (`127.0.0.1` / `localhost` / `[::1]`) on every request, plus same-origin `Origin` checks on `/api/*` to block DNS rebinding and cross-origin browser requests.

| Credential | Storage | Allowed Endpoints & Capabilities |
|---|---|---|
| **Admin Token** | `<dataRoot>/admin.token` (`0600`), passed via `#token=...` into `sessionStorage` and sent as `Authorization: Bearer` | Full `/api/*` control: initialize key, check/request OS permissions, Start / Pause / Resume / Stop capture, hot-reload collector or restart daemon (`POST /api/service/reload`), browse history, execute Forget, and issue or revoke Client Leases. |
| **Client Lease Token** (`camcp_...`) | Only SHA-256 hash stored in `auth-leases.json`; raw token displayed once at creation | `POST /mcp` only: `read` scope enables `history_status`, `history_search`, `history_read`, and `history_layout`; optional `pause` scope enables `history_pause`; opt-in `reload` scope (default OFF) enables `history_reload` (preserves an already-running `activeScope` only, never starts stopped/paused/uninitialized capture, and never widens scope). Never grants `start`, `resume`, policy mutation, or `forget`. |

Server self-restart (`mode: "server"`) uses a short-lived (30 s TTL) `0600` one-shot handoff file `<dataRoot>/restart-resume.json` written ONLY when capture is actively `running`. On worker boot, `restart-resume.json` is symlink-checked (`lstat` + `O_NOFOLLOW`), read, and immediately unlinked so it never persists as auto-start across reboots.

Every MCP read response is capped at `64 KiB` (`65536` UTF-8 bytes) and tagged as untrusted desktop text so consuming agents treat captured screen content as data rather than executable instructions.

## 4. Forget Semantics

- **Time-Window Forget (`beforeMs`)**: Updates `forgetBeforeMs` in `store.meta`, bumps store `generation` (invalidating outstanding pagination cursors), immediately hides older records from all queries, and unlinks sealed segments whose records fall entirely before `forgetBeforeMs`.
- **Forget All (`all: true`)**: Closes the active segment, unlinks all `.cah` segment files on disk, increments `generation`, and starts a fresh empty segment.
- **External Recall Boundary**: Deleting local history permanently removes encrypted segments on disk; text previously fetched by an external AI model cannot be recalled from that model's context.

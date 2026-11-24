# Application Adapter Guide

Desktop applications expose Accessibility (AX) trees with very different quirks: Electron editors require explicit AX activation, IM clients often report zero-length `AXStaticText` while holding text in bounded ranges, and complex apps bury primary content inside deep container chains.

`computer-access-mcp` handles these differences with a **thin security kernel + two-tier `AppAdapter` meta-framework** in `native/macos/collector/Sources/CollectorCore/` (macOS Swift) and `native/windows/collector/src/` (Windows Rust).

## Kernel Guarantees (Never Re-Implemented in Adapters)

Every adapter runs inside `SafeAXContext`. Privacy checks, metadata sanitization, and budget accounting are enforced automatically by the kernel on every AX query:

1. **Application & Desktop Gates**: Mandatory excluded families (1Password, Apple Passwords, Keychain Access, Bitwarden, Dashlane, LastPass, NordPass, Proton Pass, and Safari), silent System UI skips, user allowlist/denylist, unlocked desktop state, and inactive Secure Input.
2. **Private Window Blocking**: When `blockPrivateWindows` is enabled (default for `browser-family` and known browsers), the kernel checks the root window `AXTitle` in memory for private/incognito indicators before traversal and aborts with `.securityExcluded` without reading content or recording the blocked title.
3. **Protected Field Rejection & Batched Metadata**: `AXMetadataBatch` fetches 10 attributes (`AXRole`, `AXSubrole`, `containsProtectedContent`, `AXEnabled`, `AXTitle`, `AXDescription`, `AXURL`, `AXPosition`, `AXSize`, and `AXIdentifier`) in one public `AXUIElementCopyMultipleAttributeValues` call (never `AXValue`), caching node geometry and identifiers with zero extra IPCs. Whenever `AXSecureTextField`, a sensitive subrole, or `containsProtectedContent == true` is detected, field extraction aborts and `safeIdentifier`/`safeRect`/`safeTitle`/`safeDescription`/`safeURL` return `nil`.
4. **Display Text Extraction, `AXStaticText` Fast Path & Pruning**: Non-sensitive display roles (`AXHeading`, `AXLink`, `AXButton`, `AXTabButton`, `AXRadioButton`, `AXCell`, `AXWebArea`) reuse bounded `safeTitle` / `safeDescription` / `safeURL` directly from the metadata batch with zero extra IPC calls; empty disabled leaves (`enabled == false`, `childCount == 0`) are pruned. For `AXStaticText` nodes under `.boundedRangeProbe` whose `AXNumberOfCharacters` is missing or zero (common in QQ Electron and WeChat Qt), the kernel first reuses batched `safeTitle`/`safeDescription` (zero extra IPCs) or performs one safety-verified bounded `AXValue` read under the text budget, falling back to `AXStringForRange` binary probing (`maximumAttempts = 9` over `[1..256]`) only when `AXValue` is unavailable.
5. **Safe `AXParent` Chain Window Ownership Proof**: When an element's `AXWindow` and `AXTopLevelUIElement` both return absent (`attributeUnsupported` / `noValue`) and the adapter allows top-level fallback (`.allowTopLevelFallback` or `.allowUnfocusedWindow`), `WindowOwnership` walks `AXParent` up to 16 hops with cycle detection and per-hop PID verification to prove the focused element belongs to `AXFocusedWindow`.
6. **Unified `ReadBudget`**: Hard round `deadlineMs` (with final validation reserve), `maxCalls`, and `maxTextUnits` are metered directly on each underlying AX query.
7. **Low-Latency Fast Paths & Causal Ordering**:
   - **Single-Shot `StaticText` Fast Path**: `AXStaticText` leaves without reported lengths resolve in 0–1 IPC via `StaticTextFallback` (`safeTitle`/`safeDescription` -> bounded `AXValue`), with 9-attempt binary-search `StaticTextRangeProbe` fallback covering every length in `1...256`.
   - **`Return`-Triggered Fast Focused Read**: Pressing `Return` seals the input buffer immediately and signals a serial `.focusedFast` read (focused field + drained input only, skipping selection and surface tree traversal), then schedules a 200 ms `.full` surface refresh to capture the rendered update.
   - **Causal Input Drain Barrier**: Every verified `Session.read()` drain seals buffered `input.text` for the same verified context ahead of the enclosing `text.snapshot` / `surface.snapshot` via `InputTextReadGate.drainAtBarrier`, eliminating cross-read debounce timestamp inversions.
   - **Geometry-Guided Pane Header Preservation**: When a focused tall content pane (`height >= 200`) sits `24–120 pt` below its split parent container, `WeightedSurfaceTraversal` runs a tightly bounded head-first lane (`<= 12` probes, `<= 2` title hits, skipping `AXToolbar`) to retain the active chat/pane header title ahead of deep message lists without app-specific DOM selectors.

## Built-In Adapters

Ten built-in adapters ship under `native/macos/collector/Sources/CollectorCore/Adapters/` (macOS Swift: `DeclarativeAdapters.swift`, `WeChatAdapter.swift`, `FigmaAdapter.swift`, registered in `BuiltInAdapters.swift`) and `native/windows/collector/src/adapters/` (Windows Rust: `declarative.rs`, `wechat.rs`, `figma.rs`, kernel in `kernel.rs`, registered in `mod.rs`), mirroring 1:1 in `BUILT_IN_ADAPTERS` (`src/shared/app-policy.ts`) across both macOS bundle IDs and Windows application IDs (`.exe` basenames and UWP/MSIX Package Names):

| ID | Display Name | Mode | Target App Families (macOS & Windows) / Key Settings |
|---|---|---|---|
| `generic` | Generic Desktop Adapter | `fallback` | Fallback for unmatched apps (`pageSize: 8`) |
| `vscode-family` | VSCode & Electron Editors | `declarative` | macOS: `com.google.antigravity`, `com.google.antigravity-ide`, VSCode, VSCode Insiders, Cursor, Windsurf; Windows: `antigravity.exe`, `code.exe`, `code-insiders.exe`, `cursor.exe`, `windsurf.exe` (`.manualAccessibility`, `.allowUnfocusedWindow`, `.boundedRangeProbe(maxUnits: 256)`, `ignoredSubroles: ["AXApplicationStatus"]`, `collapseEmptyContainers: true`, PUA Codicon glyph filtering, `pageSize: 16`) |
| `browser-family` | Web Browsers (Chromium & Firefox) | `declarative` | macOS: Chrome, Chrome Canary, Chromium, Brave, Edge, Arc, Dia, Vivaldi, Opera, Firefox, Nightly, Zen, Floorp, Comet, Atlas, Helium; Windows: `chrome.exe`, `chromium.exe`, `msedge.exe`, `brave.exe`, `vivaldi.exe`, `opera.exe`, `firefox.exe`, `zen.exe`, `floorp.exe`, `arc.exe`, `dia.exe`, `comet.exe` (`.manualAccessibility`, `.allowUnfocusedWindow`, `blockPrivateWindows: true`) |
| `terminal-family` | Terminals & CLI | `declarative` | macOS: Terminal, iTerm2, Ghostty, Warp, Kitty, WezTerm, Rio, Wave; Windows: `windowsterminal.exe`, `microsoft.windowsterminal`, `wt.exe`, `wezterm-gui.exe`, `alacritty.exe`, `warp.exe`, `waveterm.exe`, `rio.exe`, `conhost.exe`, `mintty.exe` (`.none`, `.allowTopLevelFallback`, `maxNodeTextUnits: 1024`) |
| `qq` | Tencent QQ | `declarative` | `com.tencent.qq`, `qq.exe` (`.allowUnfocusedWindow`, `.boundedRangeProbe(maxUnits: 256)`) |
| `feishu` | Feishu / Lark | `declarative` | `com.electron.lark`, `com.bytedance.feishu`, `feishu.exe`, `lark.exe` (`.manualAccessibility`, `.allowUnfocusedWindow`, `.boundedRangeProbe(maxUnits: 256)`) |
| `wechat` | WeChat | `custom` | `com.tencent.xinWeChat`, `wechat.exe`, `weixin.exe` (`.none`, `.allowUnfocusedWindow`, custom `extractSurface` matching Qt 4.x `AXIdentifier` / Windows dotted `AutomationId` with tail-first `chat_message_list` and declarative fallback) |
| `slack` | Slack | `declarative` | `com.tinyspeck.slackmacgap`, `slack.exe`, `91750d7e.slack` (`.manualAccessibility`, `.allowUnfocusedWindow`, `.boundedRangeProbe(maxUnits: 256)`) |
| `typora` | Typora | `declarative` | `abnerworks.Typora`, `typora.exe` (`.enhancedUI`, `.allowUnfocusedWindow`, `pageSize: 16`, `maxNodeTextUnits: 512`) |
| `figma` | Figma | `custom` | `com.figma.Desktop`, `figma.exe` (`.enhancedUI`, `.allowUnfocusedWindow`, `.boundedRangeProbe(maxUnits: 256)`, custom `extractSurface` prioritizing Tab Bar, `AXLandmarkMain` canvas selection, Right Inspector, and clipped Left Sidebar with declarative fallback on Home/File Browser) |

---

## Tier 1: Adding a Declarative Adapter in ~20 Lines of Swift

Over 80% of application differences only require declaring an `AppAdapterSpec` in `Adapters/DeclarativeAdapters.swift` and registering it in `Adapters/BuiltInAdapters.swift`.

### Example: Adding a Notion / Linear Adapter

```swift
// In native/macos/collector/Sources/CollectorCore/Adapters/DeclarativeAdapters.swift

public struct LinearAdapter: AppAdapter {
    public let spec = AppAdapterSpec(
        id: "linear",
        displayName: "Linear Desktop",
        matchBundleIds: ["com.linear"],
        activation: .manualAccessibility,              // Wake Chromium/Electron AX tree
        windowAnchor: .allowTopLevelFallback,          // Keep window surface if focus transiently clears
        staticTextProbe: .standard,                    // Use .boundedRangeProbe(maxUnits: 256) if AXNumberOfCharacters lies
        preferredRoles: ["AXWebArea", "AXTextArea", "AXStaticText"],
        ignoredRoles: ["AXMenuBar", "AXToolbar"],
        pageSize: 16,
        maxNodeTextUnits: 512
    )

    public init() {}
}
```

Then register `LinearAdapter()` in `BuiltInAdapters.specialized` (`Adapters/BuiltInAdapters.swift`) and add its metadata summary to `BUILT_IN_ADAPTERS` in `src/shared/app-policy.ts` so it appears in the Web Control Panel.

### `AppAdapterSpec` Fields Reference

| Field | Options | When to Use |
|---|---|---|
| `activation` | `.none`, `.manualAccessibility`, `.enhancedUI` | Use `.manualAccessibility` for Electron / Chromium / VSCode forks whose AX trees stay dormant until requested. |
| `windowAnchor` | `.focusedOnly`, `.allowTopLevelFallback`, `.allowUnfocusedWindow` | Use `.allowTopLevelFallback` or `.allowUnfocusedWindow` when clicking message panes or WebAreas leaves `AXFocusedUIElement` unset (also enables safe `AXFocusedWindow` -> `AXMainWindow` fallback). |
| `staticTextProbe` | `.standard`, `.boundedRangeProbe(maxUnits: Int)` | Use `.boundedRangeProbe` when an app (such as QQ, Feishu, WeChat, or Slack) reports `AXNumberOfCharacters == 0` on non-empty `AXStaticText` nodes; reads up to `maxUnits` in a single shot with binary-search shrink fallback. |
| `preferredRoles` | `Set<String>` | Boost priority of document/chat roles during weighted traversal so deep content is reached before sidebars. |
| `ignoredRoles` | `Set<String>` | Prune noisy chrome (`AXMenuBar`, `AXToolbar`, scroll bars) without wasting AX IPC calls. |
| `ignoredSubroles` | `Set<String>` (default `[]`) | Prune noisy subrole subtrees such as VSCode's bottom extension status bar (`AXApplicationStatus`) without wasting AX IPC calls. |
| `collapseEmptyContainers` | `Bool` (default `false`) | Collapse empty, unfocused wrapper containers (`AXGroup`, `AXScrollArea`, `AXSplitGroup`, `AXLayoutArea`) in output and re-parent retained descendants to the nearest retained ancestor (used by `vscode-family`). |
| `pageSize` | `Int` | Child pagination batch size per container query (typically `8`–`24`). |
| `maxNodeTextUnits` | `Int` | Per-node UTF-16 truncation limit for value text and batched `AXTitle`/`AXDescription`/`AXURL` display text. |
| `blockPrivateWindows` | `Bool` (default `false`) | Set `true` for browsers (also enforced automatically for known browser bundle families) to refuse private/incognito window titles before traversal. |

---

## Tier 2: Custom `extractSurface` Hook

Implement `extractSurface(context:)` on `AppAdapter` only when declarative weighted traversal cannot express an application's structure (for example, Qt split panes where recent messages sit at the tail of a virtualized `AXList` identified by `AXIdentifier`).

### Example: Built-In `WeChatAdapter` (Qt 4.x)

`WeChatAdapter` uses `AXNodeInfo.identifier` (populated directly from `AXMetadataBatch` with zero extra IPCs) to skip the left navigation bar and `session_list`, extract the active chat header (`current_chat_name_label`), read the tail of `chat_message_list` (filtering out zero-size `virtual_cell` placeholders), and read `chat_input_field`:

```swift
public struct WeChatAdapter: AppAdapter {
    public let spec = AppAdapterSpec(
        id: "wechat",
        displayName: "WeChat",
        matchBundleIds: ["com.tencent.xinWeChat"],
        activation: .none,
        windowAnchor: .allowUnfocusedWindow,
        staticTextProbe: .boundedRangeProbe(maxUnits: 256),
        preferredRoles: ["AXList", "AXTable", "AXRow", "AXScrollArea", "AXStaticText", "AXTextArea", "AXTextField"],
        ignoredRoles: ["AXMenuBar", "AXMenu", "AXScrollBar"],
        pageSize: 16,
        maxNodeTextUnits: 256
    )

    public func extractSurface(context: SafeAXContext) -> CustomSurfaceResult? {
        // 1. Walk shallowly from `context.root`, pruning `session_list` and left-nav buttons.
        // 2. Locate `current_chat_name_label` (chat header), `chat_message_list` (read tail
        //    children via `children(of:offset:limit:)`, skipping `virtual_cell`), and
        //    `chat_input_field` (marking `isFocused` when matching `context.focus`).
        // 3. Return `nil` if neither `chat_message_list` nor `chat_input_field` is found so
        //    `SurfaceCaptureRunner` automatically falls back to standard declarative traversal.
        ...
    }
}
```

## Testing Your Adapter

Add a unit test in `native/macos/collector/Tests/CollectorCoreTests/AppAdapterTests.swift` verifying:
1. `AppAdapterRegistry` resolves your target bundle ID to your adapter's `id`.
2. Synthetic AX trees exercise your `windowAnchor`, `staticTextProbe`, or custom `extractSurface` path while respecting `ReadBudget` and protected-field rejection.

Run:

```bash
swift test --package-path native/macos/collector
```

## Per-App Layout Guides (`layout-guides/`)

Collector adapters capture raw evidence only; they do not inject semantic guesses (such as speaker identity or chat type) into stored records. When an application has useful spatial layout semantics or AX/UIA virtualization boundaries (such as QQ's two-column bubble alignment, Feishu/WeChat's single-column/full-width constraints, Figma's four-zone selection hierarchy in `figma.md`, or VSCode/Antigravity's multi-pane workbench and pruned status bar in `vscode-family.md`), document them in a plain Markdown guide under `layout-guides/<id>.md` with YAML frontmatter (`id`, `name`, `bundleIds`, `platform`, `summary`). All seven built-in guides (`_generic.md`, `feishu.md`, `figma.md`, `qq.md`, `slack.md`, `vscode-family.md`, and `wechat.md`) ship with `platform: all` and cover both macOS bundle IDs and Windows executable / MSIX package IDs. Users can also hot-drop overrides or custom app guides into `<dataDir>/layout-guides/*.md`.

The MCP server exposes these guides without bloating `history_layout` responses:
- `initialize` advertises `capabilities.resources` and concise `instructions`.
- `history_layout` appends a lightweight `layoutGuide` pointer (`{ available, id, uri }` or `_generic` fallback).
- `history_layout_guide` (tool, `read` scope) lists available guides or returns the matched guide alongside `_generic`.
- `resources/list` and `resources/read` (`read` scope) expose each guide as `computer-access://layout-guides/{id}` (`text/markdown`).

## Windows Adapter Architecture & Conventions (`native/windows/`)

Phases 0–4 ship full 10-adapter parity under `native/windows/collector/src/adapters/` (`mod.rs`, `kernel.rs`, `declarative.rs`, `wechat.rs`, `figma.rs`, Rust `windows-rs`), enforcing the same security kernel invariants and cross-platform wire conventions as macOS:

1. **`SafeSurfaceContext`, `KernelSurfaceContext`, & Unified `SurfaceCaptureRunner::run`**: All live Windows surface captures — both custom extractors (`adapters/wechat.rs`, `adapters/figma.rs`) and declarative weighted traversals — execute through the unified `SurfaceCaptureRunner::run` + `KernelSurfaceContext` pipeline in `adapters/kernel.rs` (backed by `LiveUiaSurfaceBackend` in `uia_worker/surface_backend.rs` and `MockSurfaceBackend` in `tests/common/mod.rs`, tested across `tests/adapter_kernel.rs`, `tests/adapter_wechat.rs`, `tests/adapter_figma.rs`, and `tests/uia_live.rs`), with all internal security and budget state kept module-private inside `kernel.rs` and guaranteeing fail-closed `UIA_IsPasswordPropertyId` / `TextSecurityGate` rejection, PID ownership checks, `ReadBudget` accounting, lazy head/tail child paging, cached-name `AXStaticText` fast paths, PUA Codicon filtering, and post-gate `AXWebArea` / `AXLink` `ValuePattern` URL extraction.
2. **UIA -> Canonical `AX*` Role & Subrole Mapping**: The Windows Collector maps UIA `ControlType` values to canonical `AX*` `SurfaceNode.axRole` names and enriches container semantics from UIA `LandmarkType`, `AriaRole`, `HeadingLevel`, and `AutomationId`:
   - `UIA_MainLandmarkTypeId` / `AriaRole="main"` -> `AXLandmarkMain` (Figma canvas selection).
   - `AriaRole="group"` / `"region"` / `"application"` -> `AXApplicationGroup` (Figma selection layers).
   - `UIA_StatusBarControlTypeId` / `AriaRole="status"` / `AutomationId="workbench.parts.statusbar"` -> `AXApplicationStatus` (pruned by `vscode-family`).
   - `HeadingLevel > None` / `AriaRole="heading"` on `Text`, `Group`, and `Custom` controls -> `AXHeading`.
   - Unmapped controls omit `axRole` and fall back to the generic `SurfaceNode.role` category (`text`, `editable`, `container`, `terminal`, `other`), preserving zero-change compatibility with downstream MCP consumers and `layout-guides/`.
3. **Custom Windows `WeChatAdapter` & `FigmaAdapter`**:
   - **`WeChatAdapter` (`wechat.exe`, `weixin.exe`)**: Matches Qt 4.x dotted `AutomationId` suffixes (`current_chat_name_label`, `chat_message_list`, `chat_input_field`), prunes `session_list`, reads `chat_message_list` tail-first, drops `virtual_cell` / zero-size placeholders while keeping partially scrolled rows (`y < 0 && height > 0`), and falls back automatically to declarative traversal when the chat view is absent.
   - **`FigmaAdapter` (`figma.exe`)**: Extracts the four-zone Design & Slides editor layout (Top File Tab Bar with Windows titlebar controls `Close`/`Maximize`/`Minimize`/`Menu` pruned, `AXLandmarkMain` canvas/slide selection with `AXApplicationGroup` layers, Right Inspector, and Left Sidebar with offscreen rows `y < 0`, `height <= 1`, or `y >= windowSize.height` clipped), falling back automatically on Home / File Browser views.
4. **Windows `applicationId` Convention**: Win32 / Electron / Qt apps emit lowercase `.exe` basenames (`code.exe`, `msedge.exe`, `1password.exe`). UWP / MSIX apps (including `ApplicationFrameHost.exe`-hosted windows) resolve the inner application process and emit the lowercase Package Name without `_<publisherId>!Entry` (e.g., `microsoft.windowsterminal`, `91750d7e.slack`).
5. **Delivery Status**:
   - **Shipped (PR 1–PR 3 — Phases 0–4)**: Storage lock, native DPAPI key store, isolated MTA COM UIA worker + Job Object, core UIA capture, all 10 built-in Windows `AppAdapter` implementations (including custom `WeChatAdapter` & `FigmaAdapter`), and cross-platform `layout-guides/*.md`.
   - **Planned (PR 4 — Phase 5)**: Optional Windows input and menu channels (`input.activity`, `input.text`, `menu.action`).

# Application Adapter Guide

Desktop applications expose Accessibility (AX) trees with very different quirks: Electron editors require explicit AX activation, IM clients often report zero-length `AXStaticText` while holding text in bounded ranges, and complex apps bury primary content inside deep container chains.

`computer-access-mcp` handles these differences with a **thin security kernel + two-tier `AppAdapter` meta-framework** in `native/macos/collector/Sources/CollectorCore/`.

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

Eight built-in adapters ship in `BuiltInAdapters.swift` and mirror 1:1 in `BUILT_IN_ADAPTERS` (`src/shared/app-policy.ts`):

| ID | Display Name | Mode | Target Bundle Families / Key Settings |
|---|---|---|---|
| `generic` | Generic Desktop Adapter | `fallback` | Fallback for unmatched apps (`pageSize: 8`) |
| `vscode-family` | VSCode & Electron Editors | `declarative` | `com.google.antigravity`, `com.google.antigravity-ide`, VSCode, VSCode Insiders, Cursor, Windsurf (`.manualAccessibility`, `.allowUnfocusedWindow`, `pageSize: 16`) |
| `browser-family` | Web Browsers (Chromium & Firefox) | `declarative` | Chrome, Chrome Canary, Chromium, Brave, Edge, Arc, Dia, Vivaldi, Opera, Firefox, Nightly, Zen, Floorp, Comet, Atlas, Helium (`.manualAccessibility`, `.allowUnfocusedWindow`, `blockPrivateWindows: true`) |
| `terminal-family` | Terminals & CLI | `declarative` | Terminal, iTerm2, Ghostty, Warp, Kitty, WezTerm, Rio, Wave (`.none`, `.allowTopLevelFallback`, `maxNodeTextUnits: 1024`) |
| `qq` | Tencent QQ | `declarative` | `com.tencent.qq` (`.allowUnfocusedWindow`, `.boundedRangeProbe(maxUnits: 256)`) |
| `feishu` | Feishu / Lark | `declarative` | `com.electron.lark`, `com.bytedance.feishu` (`.manualAccessibility`, `.allowUnfocusedWindow`, `.boundedRangeProbe(maxUnits: 256)`) |
| `wechat` | WeChat | `custom` | `com.tencent.xinWeChat` (`.none`, `.allowUnfocusedWindow` + `AXParent` ownership proof, custom `extractSurface` using `AXIdentifier` for Qt 4.x with declarative fallback) |
| `slack` | Slack | `declarative` | `com.tinyspeck.slackmacgap` (`.manualAccessibility`, `.allowUnfocusedWindow`, `.boundedRangeProbe(maxUnits: 256)`) |

---

## Tier 1: Adding a Declarative Adapter in ~20 Lines of Swift

Over 80% of application differences only require declaring an `AppAdapterSpec` and registering it in `BuiltInAdapters.swift`.

### Example: Adding a Notion / Linear Adapter

```swift
// In native/macos/collector/Sources/CollectorCore/BuiltInAdapters.swift

public static let linear = DeclarativeAppAdapter(
    spec: AppAdapterSpec(
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
)
```

Then register `linear` in `BuiltInAdapters.all` and add its metadata summary to `BUILT_IN_ADAPTERS` in `src/shared/app-policy.ts` so it appears in the Web Control Panel.

### `AppAdapterSpec` Fields Reference

| Field | Options | When to Use |
|---|---|---|
| `activation` | `.none`, `.manualAccessibility`, `.enhancedUI` | Use `.manualAccessibility` for Electron / Chromium / VSCode forks whose AX trees stay dormant until requested. |
| `windowAnchor` | `.focusedOnly`, `.allowTopLevelFallback`, `.allowUnfocusedWindow` | Use `.allowTopLevelFallback` or `.allowUnfocusedWindow` when clicking message panes or WebAreas leaves `AXFocusedUIElement` unset (also enables safe `AXFocusedWindow` -> `AXMainWindow` fallback). |
| `staticTextProbe` | `.standard`, `.boundedRangeProbe(maxUnits: Int)` | Use `.boundedRangeProbe` when an app (such as QQ, Feishu, WeChat, or Slack) reports `AXNumberOfCharacters == 0` on non-empty `AXStaticText` nodes; reads up to `maxUnits` in a single shot with binary-search shrink fallback. |
| `preferredRoles` | `Set<String>` | Boost priority of document/chat roles during weighted traversal so deep content is reached before sidebars. |
| `ignoredRoles` | `Set<String>` | Prune noisy chrome (`AXMenuBar`, status bars) without wasting AX IPC calls. |
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

Collector adapters capture raw evidence only; they do not inject semantic guesses (such as speaker identity or chat type) into stored records. When an application has useful spatial layout semantics (such as QQ's two-column bubble alignment or Feishu/WeChat's single-column/full-width constraints), document them in a plain Markdown guide under `layout-guides/<id>.md` with YAML frontmatter (`id`, `name`, `bundleIds`, `platform`, `summary`). Users can also hot-drop overrides or custom app guides into `<dataDir>/layout-guides/*.md`.

The MCP server exposes these guides without bloating `history_layout` responses:
- `initialize` advertises `capabilities.resources` and concise `instructions`.
- `history_layout` appends a lightweight `layoutGuide` pointer (`{ available, id, uri }` or `_generic` fallback).
- `history_layout_guide` (tool, `read` scope) lists available guides or returns the matched guide alongside `_generic`.
- `resources/list` and `resources/read` (`read` scope) expose each guide as `computer-access://layout-guides/{id}` (`text/markdown`).

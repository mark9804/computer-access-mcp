---
id: _generic
name: Generic Desktop Layout Guide
bundleIds: []
platform: all
summary: Universal coordinate rules, virtual-list clipping artifacts, and speaker-inference strategy for interpreting history_layout responses.
---

## Coordinate Space

- `windowSize` is `{ width, height }` in window logical points (`window-top-left-point` coordinates on both macOS AX and Windows Per-Monitor V2 DPI-normalized UIA `uia.tree` snapshots, where `x = 0, y = 0` is the window top-left corner); every node `bounds` is `[x, y, width, height]`.
- Always prefer **relative proportions and edge alignment** (`x / windowSize.width`, `(x + width) / windowSize.width`, alignment against the focused pane) rather than fixed pixel thresholds, because users resize windows freely.

## Snapshot Semantics

- Both macOS Accessibility (`ax.tree`) and Windows UI Automation (`uia.tree`) snapshots map controls to canonical `AX*` `axRole` names where available and fall back to generic `role` categories (`text`, `editable`, `container`, `terminal`, `other`).
- `consistency: "non-atomic"` means node text and geometry were sampled sequentially over tens of milliseconds; check individual `observedAtMs` / `boundsObservedAtMs` if timing matters.
- `snapshotFocusedNodeId` (and `focused: true`) identifies the active input or focused container and anchors which pane the user was interacting with.
- `default-node-filter` omits empty unfocused containers by default (`projection.totalNodes` vs `returnedNodes`).

## Virtualized Lists and Clipped Nodes

- Electron / Chromium apps often keep scrolled-out history items in the AX/UIA tree pinned to the top edge of the scroll viewport with **`height <= 1`** (typically `1 pt`). Treat `height <= 1` nodes stacked at a shared top `y` as off-screen history, not currently visible screen content.
- Native/Qt scroll views may report a negative `y` with a normal positive `height` for a top item partially scrolled above the clip edge; that item is partially visible at the top of the viewport.

## Pane Headers and Speaker Inference

- When a tall content pane (`height >= 200`) sits directly below a 24–120 pt header band, the top-of-pane text in that band usually names the active chat, channel, or document.
- **Why horizontal alignment is app-dependent**: only apps that physically place incoming and outgoing bubbles on opposite edges (such as QQ) expose speaker identity through `bounds.x` / `x + width`. Many desktop apps render all messages in a single left-aligned feed or as full-width list rows where `bounds.x` and `bounds.width` are identical regardless of who spoke.
- **General speaker-inference fallback order** (when geometry carries no left/right signal):
  1. Check explicit author `AXStaticText` / `AXButton` labels immediately above or left of each message block.
  2. Cross-reference `history_search(kind: "text")` (and `history_search(kind: "input")` where enabled, as `input.text` is optional and platform-dependent) around the snapshot timestamp: text typed into the focused composer immediately before a bubble appears is authored by the local user.
  3. Read inline attribution cues (quoted-reply headers, first-person system notices, self-chat composer placeholders).
  4. If none of the above signals distinguish speakers for an older historical message, report the speaker as uncertain rather than guessing from coordinates.

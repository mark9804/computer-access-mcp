---
id: wechat
name: WeChat
bundleIds:
  - com.tencent.xinWeChat
platform: darwin
summary: Full-width Qt message rows (x/width carry no speaker signal; infer speaker from input.text correlation, quotes, and system notices) with pruned session list.
---

## Active Session Title

- Located as the top `AXStaticText` in the right chat pane (`y` roughly 15–25 pt, horizontally right of the left sidebar). It contains the active contact remark or group name.
- Because the built-in `WeChatAdapter` prunes the left session list, captured nodes belong exclusively to the active chat header, visible message list, and bottom `AXTextArea` composer.

## How to Infer Speaker Identity

- **Why `bounds.x` and `bounds.width` cannot separate speakers**: macOS WeChat (Qt) wraps every message bubble inside a full-width list row cell (`bounds.x` anchored at the chat pane's left edge, `bounds.width` spanning ~68–72% of `windowSize.width`). Even though bubbles visually render left or right inside that cell, the AX tree only exposes the outer row rectangle, so incoming and outgoing messages have identical `x` and `width`.
- **How to infer speakers instead** (in priority order):
  1. **Correlate composer captures (`input.text` / `text.snapshot`)**: query `history_search(applicationId: "com.tencent.xinWeChat", kind: "input")` or `kind: "text"` near the message's appearance time. Any text captured in the focused bottom `AXTextArea` right before a new row appears in `surface.snapshot` was sent by the local user.
  2. **Read quoted-reply attribution**: quoted replies embed the original author directly inside the row text as `"<回复内容>\n引用 <昵称> 的消息 : <被引用内容>"`, which anchors who wrote the quoted message and reveals the local user's own nickname when they are quoted.
  3. **Use first-person system notices**: rows like `"你撤回了一条消息"` or `"你拍了拍..."` explicitly mark actions by the local user (`"你"`).
  4. **Historical messages without composer/quote evidence**: if a user merely opened an existing 1-on-1 chat without typing, use conversational context carefully (matching against known nicknames from earlier sessions) and mark unverified turns as uncertain rather than guessing from coordinates.

## Layout Pitfalls

- Standalone short rows such as `"00:13"` are time dividers, carrying the same full-width row `bounds` as message rows.
- The topmost message row may report a negative `y` with normal positive `height` when partially scrolled above the top clip boundary; treat it as a real partially visible message rather than a 1px virtualized placeholder.

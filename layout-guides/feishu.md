---
id: feishu
name: Feishu / Lark
bundleIds:
  - com.electron.lark
  - com.bytedance.feishu
  - feishu.exe
  - lark.exe
platform: all
summary: Single-column left-aligned chat feed (infer speaker from author labels, reply headers, and composer text/input correlation), top header title band, and localized composer target placeholders on macOS and Windows.
---

## Active Session Title

- Located in the top header band (`y` roughly 15–30 pt) inside the `messenger-chat` `AXWebArea` (the right pane):
  - The leftmost header `AXStaticText` is the active chat or group title (e.g. `"Engineering Team"` or a contact name).
  - In group chats, adjacent header controls immediately to the right report member count (`AXButton`), bot count (`AXButton`), and external badge (`AXStaticText` `"外部"`).
- The focused composer `AXTextArea` placeholder also identifies the target when empty: `"发送给 <群名或联系人>"` or `"Message <group>"` for normal chats, and `"可以向自己发送文件或转发消息"` for self-chat.

## How to Infer Speaker Identity

- **Why `bounds.x` cannot separate speakers**: Feishu renders both outgoing and incoming messages in a **single-column left-aligned** feed (`webArea.x + 70..80 pt`), so local user and other participants share the exact same horizontal coordinate.
- **How to infer speakers instead** (in priority order):
  1. **Read the author header above each message group**: an explicit sender `AXStaticText` (optionally alongside a signature/profile `AXLink`) sits directly above the message block, indented ~10–15 pt left of the message body (`webArea.x + 60..65 pt`).
  2. **Read quoted reply headers**: replies include `"回复 <昵称>"` or `"Reply to <name>"` on the line above the reply body, identifying the target author.
  3. **Check self-chat placeholder and composer captures**: `"可以向自己发送文件或转发消息"` confirms a solo self-chat; for messages sent during capture, correlate timestamps with `history_search(applicationId: "com.electron.lark", kind: "text")` / `kind: "input"` (on Windows, `applicationId: "feishu.exe"` or `"lark.exe"` with `kind: "text"`) from the focused `AXTextArea` to identify the local user's nickname and turns.

## Layout Pitfalls

- An empty focused `AXTextArea` often contains placeholder text plus zero-width space characters (`\u200b`); verify actual user typing via `text.changed` / `text.snapshot` (and `input.text` where enabled).
- Bottom-right text `"Shift + Enter 换行"` or `"Shift + Enter to add a new line"` is static composer chrome.
- On Windows (`feishu.exe` / `lark.exe`), snapshots may include an optional left navigation rail (`AXTabGroup`) and top-right Electron window controls (`Minimize`, `Maximize`, `Close` near `y ~ 1`); ignore these as outer window chrome rather than chat header controls.
- `height <= 1` nodes stacked along the message list top edge (`y` around 70–80 pt) are scrolled-out virtualized history items, not visible messages.

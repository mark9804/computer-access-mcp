---
id: qq
name: Tencent QQ
bundleIds:
  - com.tencent.qq
  - qq.exe
platform: all
summary: Two-column chat bubbles (left=other, right-aligned=self), top header band for session title, and composer width ratio for group sidebar detection.
---

## Active Session Title

- Located in the top header band of the right chat pane (`y` roughly 50–65 pt below window top, immediately to the right of the left conversation list).
- **Group chats** emit an `AXButton` and child `AXStaticText` containing the group name, followed by a sibling `AXStaticText` member count such as `"(3)"` or `"(86)"`.
- **1-on-1 DMs** emit an `AXButton` with the contact remark/nickname and an adjacent status button (e.g. `"在线状态 ..."`).

## 1-on-1 vs. Group Chat Structure

- Compare the focused composer `AXTextArea` width (`bounds[2]`) against `windowSize.width`:
  - Roughly **50–56%** of `windowSize.width` indicates the right group-member sidebar is open (group chat).
  - Roughly **68–75%** of `windowSize.width` indicates no right sidebar (1-on-1 DM or collapsed group sidebar).

## Speaker Inference (Two-Column Alignment Supported)

- QQ renders messages in two horizontal columns inside the chat pane (`paneLeft = composer.x`, `paneRight = composer.x + composer.width`):
  - **Other speaker**: left-aligned near `paneLeft + 60..75 pt` (avatar sits to the left). In group chats, the sender nickname / role badge (e.g. `"群主"`, `"管理员"`) sits slightly left of the body text, and quoted-reply previews indent ~10–15 pt right of body text.
  - **Self (local user)**: right-aligned so the bubble's right edge (`x + width`) consistently lines up near `paneRight - 65..75 pt`, with own nickname/badge right-aligned above the bubble in group chats.
  - Centered short strings near `(paneLeft + paneRight) / 2` (e.g. `"00:27"`, `"昨天 23:41"`) are conversation timestamps, not messages.

## Special Windows and Pitfalls

- **Windows QQ NT (`qq.exe`)**: Windows QQ NT uses the same Electron/Chromium multi-pane structure and two-column bubble alignment as macOS `com.tencent.qq`; the Windows Collector maps UIA controls to canonical `AX*` roles and normalizes coordinates to `window-top-left-point`, so relative edge ratios apply identically (ignore top-right Windows minimize/maximize/close chrome).
- **Merged-forward history popups** open in a separate `AXWebArea` (distinct `webcontentsid`, `focused: true` on `AXWebArea` with no `AXTextArea` composer); entries appear vertically with author headings and `"<昵称>: ..."` previews.
- **Multi-select forward dialogs** show a focused search input with controls like `"发送给:"`, `"取消"`, `"确定"`, `"[合并转发] 群聊的聊天记录"`, and `"留言"`.
- Nodes with `height <= 1` stacked at the top edge of the message viewport (`y` around 90–95 pt) are off-screen scrolled-out history.

---
id: slack
name: Slack
bundleIds:
  - com.tinyspeck.slackmacgap
platform: darwin
summary: Session/channel and workspace in root AXWebArea title, single-column left-aligned feed (infer speaker from author button/label and archive link), and action-button chrome.
---

## Active Session and Workspace

- The root `AXWebArea` (`bounds: [0, 0, windowSize.width, windowSize.height]`) directly embeds the active channel or DM name, workspace name, and Slack URL in its `text` field, e.g. `"<Channel or Person>（DM/チャンネル） - <Workspace> - Slack (https://app.slack.com/client/...)"` (localized according to the user's Slack UI language).

## How to Infer Speaker Identity

- **Why `bounds.x` cannot separate speakers**: Slack uses a **single-column left-aligned** timeline where every participant's messages align to the same left column inside the conversation pane, so horizontal coordinates carry no speaker signal.
- **How to infer speakers instead** (in priority order):
  1. **Read the author control preceding each message block**: Slack emits an `AXButton` or `AXStaticText` with the sender's display name (e.g. `"Alice"`, `"Bob"`) directly above the message lines, paired with a timestamp `AXLink` whose URL contains the archive channel/DM ID and message timestamp.
  2. **Check self-indicators in DM/sidebar previews**: Slack labels local-user messages with localized markers such as `"あなた :"` / `"You:"` or `"（自分）"` / `"(you)"` in previews, and for live sends correlate with `history_search(applicationId: "com.tinyspeck.slackmacgap", kind: "input")`.

## Layout Pitfalls

- When the user browses messages without focusing the bottom message input (`snapshotFocusedNodeId: null`), captured nodes include header tab `AXRadioButton` controls (`y` around 85–100 pt, e.g. `"メッセージ"` / `"Messages"`, `"ファイルとリンク"`, `"ピン"`) and per-message action/attachment `AXButton` controls (e.g. `"リアクションを追加する..."`, `"スレッドに返信する"`, `"メッセージを転送..."`, `"ファイルの詳細を表示"` / localized equivalents). Filter these controls out as UI chrome rather than message prose.
- Nodes with `height <= 1` stacked at a shared top `y` (typically ~115–125 pt) are scrolled-out virtualized history messages above the visible viewport.

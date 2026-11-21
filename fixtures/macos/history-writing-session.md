# Synthetic writing-session fixture

This document is entirely invented. It contains no real paper, unpublished result,
account, credential, file path or private conversation. Opening it in an editor is
an explicit user action; this file and the test scripts do not open any application.

## 1 · Baseline

HISTORY-WRITING-BASELINE-20261114

We study a fictional model that classifies imaginary shapes. The purpose of this
paragraph is to test a bounded, focused text provider — not to evaluate a real paper.

中文合成段落：我们只验证文本是否被正确记录，不推断输入来源或论文贡献。
Unicode sample: 🧪 👩🏽‍💻 é かな 한글.

## 2 · Editing scenarios

- Replace this sentence with `HISTORY-WRITING-REPLACED-20261114`.
- Undo the replacement and check whether a later sampled snapshot reflects it.
- Delete this paragraph temporarily to test an empty focused editor.
- Paste `HISTORY-WRITING-PASTED-20261114` while the synthetic file is focused.
- Scroll this file yourself to the last section when testing visible-range mode.

These actions are performed only by the person testing the editor. A collector
must never press keys, focus, scroll or read a file behind the scenes to make the
capture succeed. Failure to expose a range is a reported coverage limitation.

## 3 · Independent activity

If separately enabled by the user, coarse activity may count mouse releases,
scroll samples and Command/Control shortcuts. These counts do not show exact keys,
coordinates, user intent or successful business effects. They do not prove that
an observation was caused by the user rather than an application update.

## 4 · Other editor surfaces

Switching to another document, a terminal or an agent chat panel may expose a
different Accessibility role or no text capability. Record that as partial or
unsupported instead of claiming the whole editor is covered. Use synthetic text
for any such test, never environment variables, tokens or private shell output.

## 5 · Tail

HISTORY-WRITING-VISIBLE-TAIL-20261114

可见尾部合成标记：如果只采到这里，起点应是真实 UTF-16 位置；没有读到的
前文不应凭空补全，也不应被标为全文完整。模型共享默认关闭。

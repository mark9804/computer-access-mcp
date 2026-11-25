---
id: vscode-family
name: VSCode & Electron IDEs
bundleIds:
  - com.google.antigravity
  - com.google.antigravity-ide
  - com.microsoft.VSCode
  - com.microsoft.VSCodeInsiders
  - com.todesktop.230313mzl4w4u92
  - com.exafunction.windsurf
  - antigravity.exe
  - antigravityide.exe
  - code.exe
  - code-insiders.exe
  - cursor.exe
  - windsurf.exe
platform: all
summary: Multi-pane IDE layout (title bar and editor tabs, left Explorer sidebar, virtualized center Monaco editor, bottom panel/terminal, right nested Agent/Chat AXWebArea), pruned status bar and PUA glyphs, and virtual viewport boundaries.
---

## Multi-Pane Workbench Regions

VSCode and Electron-based IDE forks (Antigravity, VSCode Insiders, Cursor, Windsurf) share the Chromium workbench layout across macOS and Windows. Combine relative window coordinates with `focused: true` / `snapshotFocusedNodeId` to anchor which pane the user is interacting with.

1. **Top Title Bar and Editor Tabs (`y < 85`)**:
   - The window title typically uses `"<workspace> — <file>"` (or `"<file> — <workspace>"` depending on title-bar preferences).
   - Editor tab strips (`AXTabGroup`, `AXTabButton`, `AXRadioButton`) list open file tabs and identify the active editor tab.
2. **Left Explorer / Sidebar (`x < 300`)**:
   - Hosts File Explorer trees, Search, Source Control, or Extensions when expanded.
   - Tree rows expose only visible, expanded entries currently rendered in the virtualized viewport.
3. **Center Monaco Code Editor (primary central region)**:
   - Exposed through an `AXTextArea` (alongside editor `AXWebArea`, `AXScrollArea`, breadcrumb, or diagnostic `AXStaticText` nodes).
   - Represents the visible viewport of the active editor (or split editor groups), not the full file on disk.
4. **Bottom Panel / Terminal (`y > windowSize.height * 0.65`)**:
   - Contains the Integrated Terminal, Problems, Output, or Debug Console when expanded.
5. **Right Agent / Chat Panel (`x > windowSize.width - 420`)**:
   - Often rendered inside a nested `AXWebArea` (for example, `Antigravity` or `Agent` assistant sidebars in Antigravity, Cursor, or Windsurf).
   - Distinguish assistant prose and chat inputs inside the right-edge nested `AXWebArea` from source code in the center Monaco `AXTextArea` using `bounds.x` and focus markers.

## Intentionally Pruned Chrome

- **Bottom status bar pruned**: `workbench.parts.statusbar` (`AXApplicationStatus`) often holds 20–30+ extension buttons that would exhaust shallow traversal budget. On Windows, the UIA Collector maps `StatusBar`, `AriaRole="status"`, and `AutomationId="workbench.parts.statusbar"` to `AXApplicationStatus` so the built-in `vscode-family` adapter prunes `AXApplicationStatus` subtrees (`ignoredSubroles: ["AXApplicationStatus"]`) identically across macOS and Windows to preserve node budget for code, tabs, Explorer, and Agent/Chat panes.
- **Codicon PUA icon glyphs filtered**: Private Use Area icon-font glyphs (`U+E000`–`U+F8FF` and supplementary PUA planes) exposed as pure-icon `AXStaticText` leaves are skipped so decorative icons never waste output slots.
- **Do not infer missing state from pruned chrome**: Never assume extensions are missing, Git branch or dirty status is absent, remote hosts are disconnected, or linters/formatters are disabled because status bar controls do not appear in the snapshot.

## Virtual Viewport and Focus Warnings

- **Virtualized editors and trees are partial views**: Monaco editor `AXTextArea` and virtualized Explorer, Output, or Terminal lists expose only visible or nearby lines and rows (further bounded by `maxTextCodeUnits` and `maxNodeTextUnits`), never entire repositories or multi-thousand-line files. Do not treat captured editor text as the complete file unless context confirms it fits within the viewport and text budget.
- **Clipped virtual rows**: Scrolled-out Chromium rows or chat items may appear pinned at a shared top `y` with `height <= 1`; treat them as off-screen history rather than visible screen content.
- **Confirm focus target before attributing typing**: Check `snapshotFocusedNodeId` / `focused: true` to verify whether input targeted the center Monaco editor, Quick Open / Command Palette (`AXTextField`), bottom terminal, or right Agent/Chat composer.

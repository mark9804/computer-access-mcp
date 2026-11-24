---
id: figma
name: Figma Desktop
bundleIds:
  - com.figma.Desktop
  - figma.exe
platform: all
summary: Four-zone Figma Design and Figma Slides (Deck) layout (top file tab bar, virtualized canvas/slide selection in AXLandmarkMain, right Design/Prototype/Animate inspector, clipped left sidebar), Cmd+\ / Ctrl+\ sidebar hiding, and WebGL canvas boundaries.
---

## Four-Zone Editor Layout (Design & Slides / Deck)

Figma Desktop wraps two Electron `AXWebArea` surfaces (the top file tab bar and the main document) inside outer window chrome. This structure applies to both **Figma Design** (`https://www.figma.com/design/...`) and **Figma Slides / Deck** (`https://www.figma.com/slides/...`). Combine relative edge regions with the typical point thresholds below.

1. **Top File Tab Bar (`y < 40`)**:
   - Lists open Figma design and slide files as `AXRadioButton` / `AXTabButton` controls (tab chrome such as `"Close tab"`, `"New file"`, and `"Open tabs and recently closed items"` is pruned).
   - The main document `AXWebArea` directly below carries the active file name and its `https://www.figma.com/design/...` or `https://www.figma.com/slides/...` URL.
2. **Center Canvas or Slide Selection (`AXLandmarkMain`, e.g. `"Figma Design, N item(s) selected"` or `"Figma Slides, N item(s) selected"`)**:
   - Figma virtualizes its canvas AX/UIA tree to the active selection and its immediate parent/child chain.
   - In **Design** mode, `AXApplicationGroup` labels carry `"<LayerName>, <NodeType>"` (such as `"card-header, Design frame"` or `"button/primary, Component instance"`), paired with dimension `AXStaticText` values like `"176 Fill × 32 Hug"`.
   - In **Slides (Deck)** mode, the hierarchy typically flows `Section` -> `Slide N` -> selected frame/object and slide headings (`AXHeading`, e.g. `"技术路线"`).
   - Use `focused: true` / `snapshotFocusedNodeId` to identify which selected layer, slide element, or inline text edit holds active focus.
3. **Right Inspector (`x > windowSize.width - 300`, when sidebars are visible)**:
   - In **Design** mode, reports active mode (`Design` / `Prototype`), canvas zoom percentage (e.g. `"73%"`), selected component name and source (`"From this file"`), variant properties (`AXComboBox`, `AXCheckBox`, `AXTextField`, `AXTextArea`, `AXStaticText`, `AXHeading`), and color design tokens (`AXButton` labels such as `"Color Variable text/1 with value #1D2129 · 100%"`).
   - In **Slides (Deck)** mode, reports `Design` / `Animate`, zoom percentage, active slide heading (`"Slide 6"`), and `Template style` (`AXComboBox` such as `"Style: 亮色模板, Fonts: HarmonyOS Sans SC"`).
   - Inspector action chrome (alignment buttons, `"Apply variable..."`, `"Add fill/stroke/effect/layout guide/export settings"`, `"Toggle visibility"`, `"Prototype view"`, `"Ignore auto layout"`, `"Edit template style"`, `"Adjust tone"`, `"Present"`, `"Share"`, `"Help"`, `"Multiplayer tools"`), `AXToolbar`, and `AXSlider` controls are pruned by `FigmaAdapter`.
4. **Left Sidebar (`x < 300`, when sidebars are visible)**:
   - Displays the active file header and visible in-viewport `Pages` and `Layers` rows (`bounds.y >= 0` and `bounds.height > 1`).
   - Off-screen virtualized rows (`y < 0`, `height <= 1`, or `y >= windowSize.height`) and sidebar toolbar chrome (`"Minimize UI"`, `"Collapse layers"`, `"Find"`, `"Add new page"`, and `AXToolbar` controls) are clipped or pruned.

## Windows Electron Notes (`figma.exe`)

- On Windows, the built-in Rust `FigmaAdapter` maps UIA `LandmarkType` / `AriaRole` metadata directly to canonical `AXLandmarkMain` and `AXApplicationGroup` subroles so snapshots share the same four-zone structure as macOS.
- Windows `FigmaAdapter` prunes Windows Electron titlebar controls (`Close`, `Maximize`, `Minimize`, `Menu`) from the top tab bar `AXWebArea` and clips offscreen sidebar rows (`y < 0`, `height <= 1`, or `y >= windowSize.height`).

## Sidebar Toggle (`Cmd + \` / `Ctrl + \`)

- In both Figma Design and Figma Slides, users frequently toggle UI panels with `Cmd + \` (macOS) or `Ctrl + \` (Windows). When sidebars are hidden, `Right sidebar` and `Left sidebar` omit cleanly from the AX/UIA tree and the snapshot shrinks to a compact set (~8–15 nodes) containing only the top file tabs and active `AXLandmarkMain` canvas/slide selection. Treat a sidebar-less snapshot as normal hidden-UI mode, not a truncated or failed read.

## Explicit Boundaries (Do Not Assume)

- **Why the full artboard is absent**: Figma renders the design/slide canvas in WebGL/WASM and only materializes an Accessibility subtree inside `AXLandmarkMain` for the active selection hierarchy. Unselected canvas geometry, sibling artboards/slides, vector paths, and collapsed or off-screen layers do not exist in AX/UIA snapshots.
- **Treat canvas nodes as active selection context, not the complete artboard**: Never assume a frame, slide, layer, text label, or component is missing simply because it is absent from `AXLandmarkMain` or the clipped Left Sidebar.
- **Pruned toolbars are not disabled features**: Bottom toolbelt tools (`Move`, `Frame`, `Rectangle`, `Pen`, `Text`, `Code`, `Comment`), help/zoom toolbars, and inspector action buttons are intentionally omitted to keep node budget focused on selection hierarchy, variants, templates, and design tokens.

## Home and File Browser Fallback

- On the Figma Home, Recents, or File Browser screen, there is no `AXLandmarkMain` design or slide canvas. `FigmaAdapter` returns `nil` / `None` and capture automatically falls back to generic bounded traversal; do not expect the four-zone editor layout on non-editor views.

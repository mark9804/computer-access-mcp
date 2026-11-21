# Synthetic AppKit fixture

This package owns only fixed synthetic controls. Building and the structure-only
mode do not open an application window, create an AX client, ask for TCC, install
an input tap, or access History. GUI execution requires a separate explicit test
authorization; the commands below are documentation, not an instruction to launch.

## Build and structure-only checks

```bash
swift build --package-path fixtures/macos/app
swift test --package-path fixtures/macos/app
node scripts/build-fixture-app.mjs --describe-visible-tree
```

The test target imports only the Foundation-based
[fixture model](<Sources/VisibleTreeFixtureModel/VisibleTreeFixture.swift>), not the
executable or AppKit. The last command builds as needed and executes only the
`--describe-visible-tree` branch, which exits before `NSApplication.shared` or any
AppKit object construction. It prints structure without row text and does not
write the `.app` bundle. Compilation and these pure checks are **not remote AX
acceptance**.

The default build script still packages the executable with the existing bundle
ID when called without arguments. See the [build script](<../../../scripts/build-fixture-app.mjs>).

## Opt-in visible-tree window

The existing `--synthetic-fixture` mode and its editor, secure field, visible-range,
async, protected/unmarked and slow-tree preparations are unchanged. The new GUI
requires **both** `--synthetic-fixture` and `--visible-tree-fixture`. Calling only
`--visible-tree-fixture` still refuses to launch.

[The new provider](<Sources/FixtureApp/VisibleTreeFixtureWindow.swift>) implements
public `NSAccessibility` properties, not a private AX hierarchy API:

- One synthetic `NSWindow` with an initially focused synthetic input and an
  `AXList`.
- The list has **1,000 stable sibling `AXRow` objects** via `AXChildren`. Each row
  owns one `AXStaticText` child with fixed `SYNTHETIC ROW` text.
- `AXVisibleChildren` returns the **same 24 row objects at indexes 480...503**.
  They are exactly the rows drawn in the fixed 480-point viewport; rows outside
  this middle slice are not drawn. There is no scrolling or reveal action.
- Parent, window and top-level ownership are explicit for custom nodes, as are
  ordinary roles/subroles and `protectedContent=false`. The AppKit input fixture
  explicitly declares itself as an `AXTextField`; it is not a password field.
  No user/other-application text supplies the rows.
- Static text exposes a known UTF-16 character count and a public, bounds-checked
  `accessibilityString(for:)` implementation for range readers.

Expected sampling distinction: ordinary child head/tail pages sample rows near
0 and 999, **not** the visible middle. A future visible-subset-first traversal
can reach 480...503 without enumerating the other 976 rows. A visible subset is
not evidence that the complete child tree was read or that pixels are unobscured.
This package does not modify the production traversal, quotas, diagnostics, or
History behavior. The public provider declarations and successful compilation
alone do not prove cross-process child counts/pagination, focus metadata, range
reads, or collector output; those remain a separately authorized real-AX test.

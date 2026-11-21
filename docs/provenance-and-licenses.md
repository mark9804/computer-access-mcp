# Provenance & Third-Party Licenses

## Bundled & Vendored Components

1. **Node-API C Headers (`native/storage-lock/`)**
   - `native/storage-lock/` vendors unmodified Node.js v24.22.1 Node-API C headers to compile `computer-access-storage-lock.node` offline without `node-gyp` or network downloads.
   - Covered by the Node.js MIT license in [native/storage-lock/LICENSE.node](../native/storage-lock/LICENSE.node) and documented in [native/storage-lock/README.md](../native/storage-lock/README.md).

2. **Web Control Panel UI (`src/web/`, `dist/web/`)**
   - Uses `@base-ui/react` (MIT), `react` / `react-dom` (MIT), and component compositions adapted from `shadcn/ui` (Copyright (c) 2023 shadcn, MIT).
   - Attribution and license texts are retained in [src/web/NOTICE.md](../src/web/NOTICE.md) and [src/web/SHADCN_LICENSE.txt](../src/web/SHADCN_LICENSE.txt). `scripts/build-client.mjs` collects all bundled package licenses into `dist/web/THIRD_PARTY_NOTICES.txt`.

3. **Core Daemon & Native macOS Packages (`src/`, `native/macos/`)**
   - Implemented directly against Node.js built-in modules (`node:crypto`, `node:http`, `node:fs`) and macOS system frameworks (`ApplicationServices`, `AppKit`, `CoreGraphics`, `Security`, `IOKit`) with zero external npm runtime dependencies.

## Reference Submodules

Any external repositories under `reference/` (if present in a developer checkout) are read-only research material and are never imported, bundled, or distributed with `computer-access-mcp`.

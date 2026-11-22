# Documentation Index

| Document | Scope |
|---|---|
| [architecture.md](architecture.md) | Daemon, Web Control Panel, MCP Server, native Collector/Worker isolation, and extension boundaries |
| [adapters.md](adapters.md) | Adding declarative `AppAdapterSpec` definitions (~20 lines of Swift), custom `extractSurface` hooks, and Windows UIA role/`applicationId` conventions |
| [data-model.md](data-model.md) | Wire `Observation` types, macOS & Windows sources/conventions, deduplication, and cross-platform AEAD `SegmentStore` layout |
| [privacy-and-security.md](privacy-and-security.md) | Pre-read gates, mandatory macOS/Windows exclusions, Keychain/DPAPI encryption, Admin vs MCP Client leases, and Forget |
| [roadmap.md](roadmap.md) | Shipped macOS capabilities, Windows Phase 0/1 baseline, planned Rust (`windows-rs`) Collector milestones, and Computer Use integration |
| [provenance-and-licenses.md](provenance-and-licenses.md) | Bundled third-party licenses, vendored headers, and reference material boundaries |

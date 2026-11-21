# TypeScript Source (`src/`)

- `shared/` — Canonical wire protocol (`protocol/generated.ts`, `protocol/validate.ts`), REST & service contracts (`api-types.ts`), layout projection types (`history-layout.ts`), and application policy constants (`app-policy.ts`).
- `storage/` — Cross-platform encrypted `SegmentStore` (`segment-store.ts`), OS exclusive lock wrapper (`storage-lock.ts`), path hygiene (`platform-paths.ts`), and `KeyProvider` implementations (`key-provider.ts`).
- `host/` — Subprocess runner (`managed-runner.ts`), `CollectorSupervisor`, `EvidenceCorrelator`, permissions/navigation helpers, and `HistoryService`.
- `server/` — Local `127.0.0.1` HTTP server (`http-server.ts`), Admin Token & `ClientLease` credential store (`auth-store.ts`), MCP Streamable HTTP handler (`mcp-handler.ts`), `stdio` proxy (`stdio-proxy.ts`), and CLI entrypoint (`cli.ts`).
- `web/` — Standalone React 18 + `@base-ui/react` Web Control Panel bundled by `scripts/build-client.mjs` into `dist/web/`.

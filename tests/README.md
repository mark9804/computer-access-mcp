# Test Suite (`tests/`)

## Suites

- `tests/contract/` — Wire protocol schema validation, framing, application policy rules, and cross-field invariants.
- `tests/privacy/` — `SegmentStore` AEAD encryption, 4 MiB segment rolling, 14-day TTL and 16 GiB eviction, EOF torn-frame crash recovery, AAD tamper detection, `StorageLock` contention, and `KeyProvider` behavior.
- `tests/storage/` — Gap disposition classification, menu action persistence, segment-scoped v2 text-delta compression, and cold/hot tiered LRU segment caching.
- `tests/server/` — Admin Token authentication, `Host`/`Origin` hardening, `ClientLease` creation/hashing/expiry/revocation, MCP JSON-RPC (`initialize`, `tools/list`, `tools/call`, 64 KiB cap), and `stdio-proxy` round-trips.
- `tests/integration/` — `CollectorSupervisor`, `EvidenceCorrelator`, `HistoryService`, layout pagination, source navigation, and end-to-end HTTP + MCP server flows.

## Running Tests

```bash
# Node test suites
pnpm test

# Cross-language TypeScript <-> Swift wire contract parity
pnpm test:cross

# Native Swift package tests
pnpm test:swift
swift test --package-path native/macos
```

Standard test commands run entirely offline against temporary directories, synthetic inputs, and `MemoryKeyProvider` without touching your real Keychain, desktop session, or retained history.

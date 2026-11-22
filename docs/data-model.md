# Data Model & Encrypted Segment Store

`src/shared/protocol/schema-source.mjs` defines the single wire schema shared between TypeScript (`src/shared/protocol/generated.ts`) and Swift (`native/macos/contract/`).

## Observation Envelope

Every captured event is persisted as an `Observation`:

- **Identity (`TargetRef`)**:
  - `resolved`: `{ deviceId, osSessionId, desktopId, processId, processStartTime, applicationId, windowId, windowGeneration }`
  - `application`: process-level identity when no specific window applies (`input.activity`, `menu.action`)
  - `unresolved`: `{ reason: 'not-observed' | 'focus-unavailable' | 'policy-boundary' | 'desktop-unavailable' }`
- **Epoch Fencing (`Stamp`)**: `{ captureEpoch, foregroundGeneration, focusGeneration, policyRevision }`. Host admission drops any observation from an outdated epoch or policy revision.
- **Payloads (`Observation['payload']`)**:
  1. `text.snapshot` — Full bounded UTF-16 text read (`prefix` or `visible` range) from the focused control, carrying a `ContentGate`.
  2. `text.changed` — Delta update referencing `baseSnapshotId` on the same `editSessionId` and target identity.
  3. `surface.snapshot` — Bounded tree of `SurfaceNode` entries (`full` or `diff` mode against `baseRevision`), optional window-relative `SurfaceGeometry` (`window-top-left-point`), and per-node `[x, y, width, height]` bounds.
  4. `selection.snapshot` — Highlighted text selection range and string within the active surface.
  5. `input.text` — Committed keyboard Unicode text chunk (`text`, `return`, `shortcut`) correlated temporally (`<= 1500 ms`) with the active surface.
  6. `input.activity` — Coarse 1-second aggregate counts (`pointerReleases`, `dragSamples`, `scrollSamples`, `shortcutPresses`) with zero keycodes or coordinates.
  7. `menu.action` — Selected foreground application top menu bar command path (`path: string[]`, 2–8 sanitized segments, max 128 UTF-16 code units per segment and 512 total, excluding the Apple menu), carrying `ContentGate`, `secureInput: "inactive"`, `effect: "unverified"`, and `coverage` (`menu-bar-only`, `effect-unverified`, plus `menu-title-truncated` when clipped). Searchable by `kind: "menu"` and substring matching against `path.join(' > ')`.
  8. `context.changed` — Foreground application, window, or focus transition marker.
  9. `gap` — Explicit record of omitted capture (`policy-boundary`, `stale`, `timeout`, `read-error`, `budget`, `backpressure`, `desktop-unavailable`) with structured `GapDiagnostic` codes.

## Deduplication & Delta Materialization

- The Collector suppresses identical consecutive `text.snapshot` and `surface.snapshot` reads on unchanged targets and emits `text.changed` or `surface.snapshot (mode: "diff")` when a valid baseline exists in the current epoch.
- `SegmentStore` indexes observations in memory on startup and materializes full text or surface state when serving `search`, `read`, and `layout` queries.

## Cross-Platform AEAD Segment Store (`src/storage/segment-store.ts`)

All persistent state lives in a user-private directory (`~/Library/Application Support/computer-access-mcp` on macOS, `%LOCALAPPDATA%\computer-access-mcp` on Windows, `$XDG_DATA_HOME/computer-access-mcp` on Linux). File names use pure ASCII without colons for full APFS and NTFS compatibility.

### Disk Layout

```text
<dataRoot>/
  store.lock          # Empty lock file held via OS-level exclusive lock (never unlinked)
  store.meta          # Atomic AEAD JSON: { version: 1, storeId, createdAtMs, forgetBeforeMs }
  seg-00000001.cah    # Sealed 4 MiB AEAD segment
  seg-00000002.cah    # Active append-only AEAD segment
```

### Segment Binary Format (`seg-NNNNNNNN.cah`)

- **32-Byte Header**:
  - `0..5`: Magic bytes `CAHS\x01`
  - `5..8`: Reserved flags (`0x000000`)
  - `8..16`: `segmentSeq` (`uint64BE`)
  - `16..24`: `createdAtMs` (`uint64BE`)
  - `24..32`: Reserved (`0`)
- **Appended Encrypted Frames**:
  - `frameBodyLen` (`uint32BE`)
  - `nonce` (`12` random bytes)
  - `ciphertext + authTag` (AES-256-GCM ciphertext followed by `16`-byte authentication tag)
- **Associated Authenticated Data (AAD)**:
  - UTF-8 string `${storeId}:${segmentSeq}:${frameIndex}`.
  - Cryptographically binds every frame to its store, segment sequence, and exact position, preventing cross-store replay, frame deletion, or reordering.

### Rolling, Retention & Crash Self-Healing

1. **NTFS-Safe Segment Rolling**: Only the active segment holds an open `FileHandle`. Once the active segment reaches `4 MiB`, the store calls `datasync()`, closes the handle, and opens `seg-(N+1).cah`.
2. **TTL & Byte Budget Eviction**: Defaults enforce a `14-day` retention window and `16 GiB` total disk budget. Eviction only `unlink`s closed, sealed segment files—guaranteeing clean deletion on both POSIX and Windows NTFS (which forbids deleting open handles).
3. **Cold/Hot Tiered Memory Index**: To support multi-gigabyte retention without bloating Node.js heap, `SegmentStore` retains only compact per-segment summaries (`SegmentInfo` counts, time bounds, application sets, per-instance sequence ranges, and a 4 KiB snapshot Bloom filter) plus a bounded LRU hot cache (default `32 MiB` / `16` segments, pinning the active segment). `status()` runs in `O(segments)` and `search()` streams only matching segments with early termination, without creating any plaintext sidecar files on disk.
4. **Power-Loss Self-Healing**: On `open()`, segments are scanned sequentially. If the final frame of the last segment was torn at EOF during a crash or power loss, `SegmentStore` truncates the file back to the last valid authenticated frame offset. Authentication failure anywhere in the middle of a segment or in an earlier sealed segment fails closed with `invalid-store`.

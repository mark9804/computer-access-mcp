# macOS Native Packages (`native/macos/`)

- `contract/` (`AccessContract`) — Foundation-only wire protocol validator and JSON framing library shared across Swift executables and cross-language contract tests.
- `key-store/` (`computer-access-key-store`) — Command-driven macOS Keychain helper managing the 32-byte AES-256 master key (`service: com.computer-access.mcp`) over `stdin`/`stdout` without interactive prompts during background reads.
- `collector/` (`computer-access-collector`) — Process-isolated Collector control loop, ephemeral AX/input workers, `SafeAXContext` pre-read privacy gates, unified `ReadBudget`, and the `AppAdapter` meta-framework (`GenericAdapter`, `VSCodeFamilyAdapter`, `QQAdapter`, `FeishuAdapter`).

Cross-platform file locking lives one level up in [native/storage-lock/](../storage-lock/README.md).

## Building & Testing

```bash
swift test --package-path native/macos/contract
swift test --package-path native/macos/key-store
swift test --package-path native/macos/collector

# Build release binaries into native-bin/
pnpm build:native
```

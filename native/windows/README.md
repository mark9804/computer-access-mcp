# Windows Native Collector Slot (`native/windows/`)

Reserved for the Windows UI Automation (`UIAutomationCore`) Collector binary speaking the shared stdio wire protocol defined in `src/shared/protocol/`.

Storage and key management on Windows are already supported in `src/storage/` via `WindowsDpapiKeyProvider` (`CryptProtectData` in `CurrentUser` scope) and `LockFileEx` in `native/storage-lock/storage-lock.c`.

## Planned Collector Architecture

- **Control Process**: Speaks length-prefixed JSON wire frames over `stdio`, enforces lease heartbeats and epoch fencing, and supervises worker processes in the interactive user session.
- **MTA UIA Worker**: Executes bounded `IUIAutomation` queries under `ReadBudget` (`deadlineMs`, `maxCalls`, `maxTextUnits`) after verifying unlocked desktop state, excluded application rules, and `UIA_IsPasswordPropertyId` pre-read gates.

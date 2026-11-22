export {
  HistoryStoreError,
  KEY_ERROR_CODES,
  KEY_PHASES,
  KeyProviderError,
  rejectStorage,
  safeKeyDiagnostic,
  StorageError,
  toStorageError,
} from './errors.ts';
export type {
  HistoryStoreErrorCode,
  KeyDiagnostic,
  KeyProviderErrorCode,
  StorageErrorCode,
} from './errors.ts';
export {
  assertSafeDirectoryStat,
  assertSafeFileStat,
  defaultDataRoot,
  isPosixPlatform,
  prepareDataDirectory,
} from './platform-paths.ts';
export type { PrepareDirectoryOptions } from './platform-paths.ts';
export { acquireStorageLock, loadNativeStorageLock } from './storage-lock.ts';
export type { NativeStorageLock, StorageLock } from './storage-lock.ts';
export {
  createPlatformKeyProvider,
  DEFAULT_KEYCHAIN_ACCOUNT,
  DEFAULT_KEYCHAIN_SERVICE,
  DPAPI_KEY_FILENAME,
  MacKeychainKeyProvider,
  MemoryKeyProvider,
  WindowsDpapiKeyProvider,
} from './key-provider.ts';
export type {
  KeyProvider,
  MacKeychainKeyProviderOptions,
  WindowsDpapiKeyProviderOptions,
} from './key-provider.ts';
export {
  HISTORY_MAX_BYTES,
  HISTORY_RETENTION_MS,
  SEGMENT_HEADER_BYTES,
  SEGMENT_MAX_BYTES,
  SegmentStore,
} from './segment-store.ts';
export type { SegmentAppendOptions, SegmentStoreOptions } from './segment-store.ts';
export {
  applySingleSpanPatch,
  computeSingleSpanPatch,
  DEFAULT_MAX_TEXT_DELTA_CHAIN_DEPTH,
  MIN_TEXT_DELTA_BYTES,
  shouldStoreTextPatch,
} from './text-delta.ts';
export type { TextSpanPatch } from './text-delta.ts';

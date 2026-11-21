export type StorageErrorCode =
  | 'invalid-input'
  | 'invalid-store'
  | 'authentication-failed'
  | 'key-unavailable'
  | 'budget-exceeded'
  | 'unsafe-path'
  | 'unsafe-permissions'
  | 'already-owned'
  | 'io-failure'
  | 'closed'
  | 'failed'
  | 'stale-generation'
  | 'duplicate-conflict'
  | 'out-of-order'
  | 'baseline-unavailable'
  | 'invalid-cursor'
  | 'cursor-expired'
  | 'invalid-layout-query'
  | 'invalid-layout-position'
  | 'layout-budget-too-small'
  | 'snapshot-ambiguous'
  | 'native-lock-unavailable';

export class StorageError extends Error {
  readonly code: StorageErrorCode;

  constructor(code: StorageErrorCode) {
    super(`Storage error: ${code}`);
    this.name = 'StorageError';
    this.code = code;
  }
}

export type HistoryStoreErrorCode = StorageErrorCode;
export const HistoryStoreError = StorageError;

export function rejectStorage(code: StorageErrorCode): never {
  throw new StorageError(code);
}

export function toStorageError(error: unknown): StorageError {
  return error instanceof StorageError ? error : new StorageError('io-failure');
}

export const KEY_ERROR_CODES = [
  'invalid-input',
  'key-missing',
  'key-denied',
  'key-unavailable',
  'key-helper-spawn-failed',
  'key-helper-input-failed',
  'key-helper-timeout',
  'key-helper-output-limit',
  'key-helper-exit-failed',
  'key-helper-response-invalid',
  'keychain-parameter-error',
  'keychain-not-available',
  'keychain-missing-entitlement',
  'keychain-ui-required',
  'keychain-operation-failed',
  'dpapi-operation-failed',
] as const;

export type KeyProviderErrorCode = (typeof KEY_ERROR_CODES)[number];

export const KEY_PHASES = [
  'ui-policy',
  'lookup',
  'random',
  'add',
  'race-reload',
  'response-validation',
  'dpapi-protect',
  'dpapi-unprotect',
] as const;

export interface KeyDiagnostic {
  phase?: (typeof KEY_PHASES)[number];
  osStatus?: number;
  exitCode?: number;
}

export function safeKeyDiagnostic(value: unknown): KeyDiagnostic | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const record = value as Record<string, unknown>;
  const result: KeyDiagnostic = {};
  if (typeof record.phase === 'string' && (KEY_PHASES as readonly string[]).includes(record.phase)) {
    result.phase = record.phase as NonNullable<KeyDiagnostic['phase']>;
  }
  if (
    typeof record.osStatus === 'number' &&
    Number.isSafeInteger(record.osStatus) &&
    record.osStatus >= -2147483648 &&
    record.osStatus <= 2147483647
  ) {
    result.osStatus = record.osStatus;
  }
  if (
    typeof record.exitCode === 'number' &&
    Number.isSafeInteger(record.exitCode) &&
    record.exitCode >= -1 &&
    record.exitCode <= 255
  ) {
    result.exitCode = record.exitCode;
  }
  return Object.keys(result).length > 0 ? result : undefined;
}

export class KeyProviderError extends Error {
  readonly code: KeyProviderErrorCode;
  readonly diagnostic: KeyDiagnostic | undefined;

  constructor(code: KeyProviderErrorCode, diagnostic?: KeyDiagnostic) {
    super(`Key provider error: ${code}`);
    this.name = 'KeyProviderError';
    this.code = code;
    this.diagnostic = safeKeyDiagnostic(diagnostic);
  }
}

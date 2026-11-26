import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readFile, rename, unlink } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { dirname, isAbsolute, join } from 'node:path';
import { createManagedRunner, ManagedRunnerError } from '../host/managed-runner.ts';
import type { SubprocessRunner } from '../host/managed-runner.ts';
import type { SpawnManaged } from '../host/collectors/process.ts';
import { minimalChildEnv } from '../shared/child-env.ts';
import { KeyProviderError, safeKeyDiagnostic } from './errors.ts';
import type { KeyProviderErrorCode } from './errors.ts';
import { assertSafeFileStat, prepareDataDirectory } from './platform-paths.ts';

export { KeyProviderError } from './errors.ts';
export type { KeyDiagnostic, KeyProviderErrorCode } from './errors.ts';

export const DEFAULT_KEYCHAIN_SERVICE = 'com.computer-history.mcp';
export const DEFAULT_KEYCHAIN_ACCOUNT = 'master-key';
export const DPAPI_KEY_FILENAME = 'master.key.dpapi';

export interface KeyProvider {
  readKey(): Promise<Buffer | null>;
  getOrCreateKey(): Promise<Buffer>;
  deleteKey(): Promise<void>;
}

function mapRunnerError(error: unknown): KeyProviderError {
  if (error instanceof KeyProviderError) return error;
  if (error instanceof ManagedRunnerError) {
    switch (error.code) {
      case 'spawn-failed':
      case 'busy':
      case 'closed':
        return new KeyProviderError('key-helper-spawn-failed');
      case 'input-failed':
      case 'cancelled':
      case 'cancelled-after-dispatch':
        return new KeyProviderError('key-helper-input-failed');
      case 'timeout':
        return new KeyProviderError('key-helper-timeout');
      case 'output-limit':
        return new KeyProviderError('key-helper-output-limit');
      case 'response-invalid':
        return new KeyProviderError('key-helper-response-invalid');
      case 'exit-failed':
      case 'exit-unconfirmed':
        return new KeyProviderError('key-helper-exit-failed');
    }
  }
  return new KeyProviderError('key-unavailable');
}

function decodeStrictKeyBase64(encoded: string): Buffer {
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(encoded)) {
    throw new KeyProviderError('key-helper-response-invalid');
  }
  const key = Buffer.from(encoded, 'base64');
  if (key.length !== 32 || key.toString('base64') !== encoded) {
    key.fill(0);
    throw new KeyProviderError('key-helper-response-invalid');
  }
  return key;
}

export class MemoryKeyProvider implements KeyProvider {
  #key: Buffer | null;

  constructor(initialKey?: Uint8Array | null) {
    if (initialKey !== undefined && initialKey !== null) {
      if (!(initialKey instanceof Uint8Array) || initialKey.byteLength !== 32) {
        throw new KeyProviderError('invalid-input');
      }
      this.#key = Buffer.from(initialKey);
    } else {
      this.#key = null;
    }
  }

  async readKey(): Promise<Buffer | null> {
    return this.#key ? Buffer.from(this.#key) : null;
  }

  async getOrCreateKey(): Promise<Buffer> {
    if (!this.#key) {
      this.#key = randomBytes(32);
    }
    return Buffer.from(this.#key);
  }

  async deleteKey(): Promise<void> {
    if (this.#key) {
      this.#key.fill(0);
      this.#key = null;
    }
  }
}

export interface MacKeychainKeyProviderOptions {
  executable: string;
  service?: string;
  account?: string;
  runner?: SubprocessRunner;
  spawn?: SpawnManaged;
  timeoutMs?: number;
}

export class MacKeychainKeyProvider implements KeyProvider {
  readonly #executable: string;
  readonly #service: string;
  readonly #account: string;
  readonly #runner: SubprocessRunner;
  readonly #timeoutMs: number;

  constructor(options: MacKeychainKeyProviderOptions) {
    const service = options.service ?? DEFAULT_KEYCHAIN_SERVICE;
    const account = options.account ?? DEFAULT_KEYCHAIN_ACCOUNT;
    const timeoutMs = options.timeoutMs ?? 5_000;

    if (
      !isAbsolute(options.executable) ||
      !/^[A-Za-z0-9._-]{1,128}$/.test(service) ||
      !/^[A-Za-z0-9._-]{1,128}$/.test(account) ||
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 1 ||
      timeoutMs > 30_000
    ) {
      throw new KeyProviderError('invalid-input');
    }

    this.#executable = options.executable;
    this.#service = service;
    this.#account = account;
    this.#timeoutMs = timeoutMs;
    this.#runner =
      options.runner ??
      createManagedRunner({
        ...(options.spawn ? { spawn: options.spawn } : {}),
        cwd: dirname(options.executable),
      }).run;
  }

  async readKey(): Promise<Buffer | null> {
    return this.#invoke('get');
  }

  async getOrCreateKey(): Promise<Buffer> {
    const key = await this.#invoke('create');
    if (!key) {
      throw new KeyProviderError('key-missing');
    }
    return key;
  }

  async deleteKey(): Promise<void> {
    await this.#invoke('delete');
  }

  async #invoke(command: 'get' | 'create' | 'delete'): Promise<Buffer | null> {
    let output: Buffer | undefined;
    try {
      const response = await this.#runner({
        executable: this.#executable,
        args: ['--command', command],
        stdin:
          JSON.stringify({
            version: 1,
            command,
            service: this.#service,
            account: this.#account,
          }) + '\n',
        timeoutMs: this.#timeoutMs,
        maxOutputBytes: 1024,
      });

      output = response.stdout;
      if (output.byteLength > 1024) {
        throw new KeyProviderError('key-helper-output-limit');
      }
      if (response.exitCode !== 0) {
        throw new KeyProviderError('key-helper-exit-failed', { exitCode: response.exitCode });
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(output));
      } catch {
        throw new KeyProviderError('key-helper-response-invalid');
      }

      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new KeyProviderError('key-helper-response-invalid');
      }
      const object = parsed as Record<string, unknown>;
      const allowedKeys = ['version', 'status', 'key', 'phase', 'osStatus'];
      if (object.version !== 1 || Object.keys(object).some((k) => !allowedKeys.includes(k))) {
        throw new KeyProviderError('key-helper-response-invalid');
      }

      const diagnostic = safeKeyDiagnostic(object);
      if (
        ('phase' in object && diagnostic?.phase !== object.phase) ||
        ('osStatus' in object && diagnostic?.osStatus !== object.osStatus)
      ) {
        throw new KeyProviderError('key-helper-response-invalid');
      }

      if (object.status !== 'ok' && 'key' in object) {
        throw new KeyProviderError('key-helper-response-invalid');
      }

      if (object.status === 'missing') {
        if (command === 'get' || command === 'delete') return null;
        throw new KeyProviderError('key-missing', diagnostic);
      }

      if (object.status === 'denied') {
        const code: KeyProviderErrorCode = object.osStatus === -25308 ? 'keychain-ui-required' : 'key-denied';
        throw new KeyProviderError(code, diagnostic);
      }

      if (object.status === 'error') {
        const code: KeyProviderErrorCode =
          object.osStatus === -50
            ? 'keychain-parameter-error'
            : object.osStatus === -25291
              ? 'keychain-not-available'
              : object.osStatus === -34018
                ? 'keychain-missing-entitlement'
                : 'keychain-operation-failed';
        throw new KeyProviderError(code, diagnostic);
      }

      if (command === 'delete') {
        if (object.status !== 'ok' || 'key' in object) {
          throw new KeyProviderError('key-helper-response-invalid');
        }
        return null;
      }

      if (object.status !== 'ok' || typeof object.key !== 'string') {
        throw new KeyProviderError('key-helper-response-invalid');
      }
      return decodeStrictKeyBase64(object.key);
    } catch (error) {
      throw mapRunnerError(error);
    } finally {
      output?.fill(0);
    }
  }
}

const PS_PROTECT_SCRIPT =
  'Add-Type -AssemblyName System.Security; ' +
  '$in = [Console]::In.ReadToEnd().Trim(); ' +
  '$raw = [Convert]::FromBase64String($in); ' +
  '$enc = [System.Security.Cryptography.ProtectedData]::Protect($raw, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); ' +
  '[Array]::Clear($raw, 0, $raw.Length); ' +
  '[Console]::Out.Write([Convert]::ToBase64String($enc))';

const PS_UNPROTECT_SCRIPT =
  'Add-Type -AssemblyName System.Security; ' +
  '$in = [Console]::In.ReadToEnd().Trim(); ' +
  '$enc = [Convert]::FromBase64String($in); ' +
  '$raw = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); ' +
  '[Console]::Out.Write([Convert]::ToBase64String($raw)); ' +
  '[Array]::Clear($raw, 0, $raw.Length)';

export interface WindowsDpapiKeyProviderOptions {
  dataRoot: string;
  executable?: string;
  powershellExecutable?: string;
  runner?: SubprocessRunner;
  spawn?: SpawnManaged;
  timeoutMs?: number;
  platform?: NodeJS.Platform;
}

export class WindowsDpapiKeyProvider implements KeyProvider {
  readonly #dataRoot: string;
  readonly #keyFilePath: string;
  readonly #executable: string | undefined;
  readonly #powershell: string;
  readonly #runner: SubprocessRunner;
  readonly #timeoutMs: number;
  readonly #platform: NodeJS.Platform;

  constructor(options: WindowsDpapiKeyProviderOptions) {
    const timeoutMs = options.timeoutMs ?? 10_000;
    if (
      typeof options.dataRoot !== 'string' ||
      !isAbsolute(options.dataRoot) ||
      (options.executable !== undefined && (typeof options.executable !== 'string' || !isAbsolute(options.executable))) ||
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 1 ||
      timeoutMs > 90_000
    ) {
      throw new KeyProviderError('invalid-input');
    }
    this.#dataRoot = options.dataRoot;
    this.#keyFilePath = join(options.dataRoot, DPAPI_KEY_FILENAME);
    this.#executable = options.executable;
    this.#powershell = options.powershellExecutable ?? 'powershell.exe';
    this.#timeoutMs = timeoutMs;
    this.#platform = options.platform ?? 'win32';
    this.#runner =
      options.runner ??
      createManagedRunner({
        ...(options.spawn ? { spawn: options.spawn } : {}),
        cwd: options.executable ? dirname(options.executable) : options.dataRoot,
      }).run;
  }

  async readKey(): Promise<Buffer | null> {
    if (this.#executable) {
      return this.#invokeNative('get');
    }
    let stat;
    try {
      stat = await lstat(this.#keyFilePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return null;
      }
      throw new KeyProviderError('key-unavailable');
    }

    try {
      assertSafeFileStat(stat, this.#platform);
    } catch {
      throw new KeyProviderError('invalid-input');
    }
    if (stat.size < 1 || stat.size > 8192) {
      throw new KeyProviderError('key-helper-response-invalid');
    }

    let encryptedBytes: Buffer | undefined;
    let stdout: Buffer | undefined;
    try {
      encryptedBytes = await readFile(this.#keyFilePath);
      const res = await this.#runner({
        executable: this.#powershell,
        args: ['-NoProfile', '-NonInteractive', '-Command', PS_UNPROTECT_SCRIPT],
        cwd: this.#dataRoot,
        stdin: encryptedBytes.toString('base64') + '\n',
        timeoutMs: this.#timeoutMs,
        maxOutputBytes: 4096,
        env: this.#windowsEnv(),
      });
      stdout = res.stdout;
      if (res.exitCode !== 0) {
        throw new KeyProviderError('dpapi-operation-failed', {
          phase: 'dpapi-unprotect',
          exitCode: res.exitCode,
        });
      }
      const trimmed = new TextDecoder('utf-8', { fatal: true }).decode(stdout).trim();
      return decodeStrictKeyBase64(trimmed);
    } catch (error) {
      throw mapRunnerError(error);
    } finally {
      encryptedBytes?.fill(0);
      stdout?.fill(0);
    }
  }

  async getOrCreateKey(): Promise<Buffer> {
    if (this.#executable) {
      const key = await this.#invokeNative('create');
      if (!key) {
        throw new KeyProviderError('key-missing');
      }
      return key;
    }
    try {
      await prepareDataDirectory(this.#dataRoot, { platform: this.#platform });
    } catch {
      throw new KeyProviderError('invalid-input');
    }

    const existing = await this.readKey();
    if (existing !== null) {
      return existing;
    }

    const rawKey = randomBytes(32);
    let stdout: Buffer | undefined;
    let tempHandle: FileHandle | undefined;
    const tempPath = `${this.#keyFilePath}.tmp.${process.pid}.${randomBytes(4).toString('hex')}`;

    try {
      const res = await this.#runner({
        executable: this.#powershell,
        args: ['-NoProfile', '-NonInteractive', '-Command', PS_PROTECT_SCRIPT],
        cwd: this.#dataRoot,
        stdin: rawKey.toString('base64') + '\n',
        timeoutMs: this.#timeoutMs,
        maxOutputBytes: 8192,
        env: this.#windowsEnv(),
      });
      stdout = res.stdout;
      if (res.exitCode !== 0) {
        rawKey.fill(0);
        throw new KeyProviderError('dpapi-operation-failed', {
          phase: 'dpapi-protect',
          exitCode: res.exitCode,
        });
      }

      const encodedBlob = new TextDecoder('utf-8', { fatal: true }).decode(stdout).trim();
      if (!encodedBlob || !/^[A-Za-z0-9+/=]+$/.test(encodedBlob)) {
        rawKey.fill(0);
        throw new KeyProviderError('key-helper-response-invalid');
      }
      const dpapiBlob = Buffer.from(encodedBlob, 'base64');
      if (dpapiBlob.length === 0) {
        rawKey.fill(0);
        throw new KeyProviderError('key-helper-response-invalid');
      }

      tempHandle = await open(tempPath, constants.O_CREAT | constants.O_TRUNC | constants.O_WRONLY, 0o600);
      await tempHandle.writeFile(dpapiBlob);
      await tempHandle.datasync();
      await tempHandle.close();
      tempHandle = undefined;

      // Avoid overwriting a concurrently created key.
      try {
        await lstat(this.#keyFilePath);
        await unlink(tempPath).catch(() => {});
        rawKey.fill(0);
        const raced = await this.readKey();
        if (!raced) throw new KeyProviderError('key-unavailable');
        return raced;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
          rawKey.fill(0);
          throw err;
        }
      }

      await rename(tempPath, this.#keyFilePath);
      return rawKey;
    } catch (error) {
      rawKey.fill(0);
      if (tempHandle) {
        await tempHandle.close().catch(() => {});
      }
      await unlink(tempPath).catch(() => {});
      throw mapRunnerError(error);
    } finally {
      stdout?.fill(0);
    }
  }

  async deleteKey(): Promise<void> {
    if (this.#executable) {
      await this.#invokeNative('delete');
      return;
    }
    try {
      await unlink(this.#keyFilePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw new KeyProviderError('key-unavailable');
    }
  }

  async #invokeNative(command: 'get' | 'create' | 'delete'): Promise<Buffer | null> {
    const executable = this.#executable;
    if (!executable) {
      throw new KeyProviderError('invalid-input');
    }
    let output: Buffer | undefined;
    try {
      const response = await this.#runner({
        executable,
        args: ['--command', command],
        cwd: dirname(executable),
        stdin:
          JSON.stringify({
            version: 1,
            command,
            dataRoot: this.#dataRoot,
          }) + '\n',
        timeoutMs: this.#timeoutMs,
        maxOutputBytes: 1024,
        env: this.#windowsEnv(),
      });

      output = response.stdout;
      if (output.byteLength > 1024) {
        throw new KeyProviderError('key-helper-output-limit');
      }
      if (response.exitCode !== 0) {
        throw new KeyProviderError('key-helper-exit-failed', { exitCode: response.exitCode });
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(output));
      } catch {
        throw new KeyProviderError('key-helper-response-invalid');
      }

      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new KeyProviderError('key-helper-response-invalid');
      }
      const object = parsed as Record<string, unknown>;
      const allowedKeys = ['version', 'status', 'key', 'phase', 'osStatus'];
      if (object.version !== 1 || Object.keys(object).some((k) => !allowedKeys.includes(k))) {
        throw new KeyProviderError('key-helper-response-invalid');
      }

      const diagnostic = safeKeyDiagnostic(object);
      if (
        ('phase' in object && diagnostic?.phase !== object.phase) ||
        ('osStatus' in object && diagnostic?.osStatus !== object.osStatus)
      ) {
        throw new KeyProviderError('key-helper-response-invalid');
      }

      if (object.status !== 'ok' && 'key' in object) {
        throw new KeyProviderError('key-helper-response-invalid');
      }
      if (command === 'delete' && 'key' in object) {
        throw new KeyProviderError('key-helper-response-invalid');
      }

      if (object.status === 'missing') {
        if (command === 'get') return null;
        throw new KeyProviderError('key-missing', diagnostic);
      }

      if (object.status === 'denied') {
        throw new KeyProviderError('key-denied', diagnostic);
      }

      if (object.status === 'error') {
        throw new KeyProviderError('dpapi-operation-failed', diagnostic);
      }

      if (object.status !== 'ok') {
        throw new KeyProviderError('key-helper-response-invalid');
      }

      if (command === 'delete') {
        return null;
      }

      if (typeof object.key !== 'string') {
        throw new KeyProviderError('key-helper-response-invalid');
      }
      return decodeStrictKeyBase64(object.key);
    } catch (error) {
      throw mapRunnerError(error);
    } finally {
      output?.fill(0);
    }
  }

  #windowsEnv(): NodeJS.ProcessEnv {
    return minimalChildEnv({}, 'win32');
  }
}

export function createPlatformKeyProvider(options: {
  platform?: NodeJS.Platform;
  dataRoot: string;
  keyHelperPath?: string;
  deviceId?: string;
  spawn?: SpawnManaged;
  runner?: SubprocessRunner;
}): KeyProvider {
  const platform = options.platform ?? process.platform;
  if (platform === 'darwin') {
    if (!options.keyHelperPath) {
      throw new KeyProviderError('invalid-input');
    }
    return new MacKeychainKeyProvider({
      executable: options.keyHelperPath,
      service: DEFAULT_KEYCHAIN_SERVICE,
      account: options.deviceId ? `history.${options.deviceId}` : DEFAULT_KEYCHAIN_ACCOUNT,
      ...(options.spawn ? { spawn: options.spawn } : {}),
      ...(options.runner ? { runner: options.runner } : {}),
    });
  }
  if (platform === 'win32') {
    return new WindowsDpapiKeyProvider({
      dataRoot: options.dataRoot,
      ...(options.keyHelperPath !== undefined ? { executable: options.keyHelperPath } : {}),
      ...(options.spawn ? { spawn: options.spawn } : {}),
      ...(options.runner ? { runner: options.runner } : {}),
    });
  }
  throw new KeyProviderError('key-unavailable');
}

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { PassThrough, Writable } from 'node:stream';
import { lstat, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import type { TestContext } from 'node:test';
import { createManagedRunner } from '../../src/host/managed-runner.ts';
import type { SubprocessRunRequest } from '../../src/host/managed-runner.ts';
import type { ManagedProcess, SpawnManaged } from '../../src/host/collectors/process.ts';
import { createHistoryService, HistoryOperationError } from '../../src/host/service/history-service.ts';
import {
  createPlatformKeyProvider,
  DEFAULT_KEYCHAIN_SERVICE,
  DPAPI_KEY_FILENAME,
  KeyProviderError,
  MacKeychainKeyProvider,
  MemoryKeyProvider,
  WindowsDpapiKeyProvider,
} from '../../src/storage/key-provider.ts';

const SECRET = 'SYNTHETIC-SECRET-DO-NOT-LEAK-9941';
const FAKE_KEY_HELPER = '/synthetic/never-executed/computer-history-key-store';
const FAKE_WIN_KEY_HELPER =
  process.platform === 'win32'
    ? 'C:\\synthetic\\never-executed\\computer-history-key-store.exe'
    : '/synthetic/never-executed/computer-history-key-store.exe';
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

function findBuiltWindowsKeyStoreExe(): string | null {
  const candidates = [
    join(REPO_ROOT, 'native-bin', 'computer-history-key-store.exe'),
    join(REPO_ROOT, 'native', 'windows', 'target', 'release', 'computer-history-key-store.exe'),
    join(REPO_ROOT, 'native', 'windows', 'target', 'debug', 'computer-history-key-store.exe'),
    join(REPO_ROOT, 'native', 'windows', 'key-store', 'target', 'release', 'computer-history-key-store.exe'),
    join(REPO_ROOT, 'native', 'windows', 'key-store', 'target', 'debug', 'computer-history-key-store.exe'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

async function makeTempDir(t: TestContext): Promise<string> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'chmcp-key-')));
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  return dir;
}

function expectKeyError(expectedCode: string) {
  return (error: unknown): boolean => {
    assert.ok(error instanceof KeyProviderError);
    assert.equal(error.code, expectedCode);
    assert.equal(error.message.includes(SECRET), false);
    return true;
  };
}

function helperJson(status: string, key?: string, extra: Record<string, unknown> = {}): Buffer {
  return Buffer.from(JSON.stringify({ version: 1, status, ...(key ? { key } : {}), ...extra }), 'utf8');
}

test('MemoryKeyProvider returns defensive 32-byte copies and wipes on deleteKey', async () => {
  const provider = new MemoryKeyProvider();
  assert.equal(await provider.readKey(), null);

  const created = await provider.getOrCreateKey();
  assert.equal(created.length, 32);
  const originalHex = created.toString('hex');

  // Mutating returned buffer must not corrupt stored key.
  created.fill(0);
  const reread = await provider.readKey();
  assert.ok(reread);
  assert.equal(reread.toString('hex'), originalHex);

  await provider.deleteKey();
  assert.equal(await provider.readKey(), null);

  assert.throws(() => new MemoryKeyProvider(Buffer.alloc(16)), expectKeyError('invalid-input'));
});

test('MacKeychainKeyProvider uses com.computer-history.mcp service, returns null on missing, and creates only on getOrCreateKey', async () => {
  const calls: SubprocessRunRequest[] = [];
  const keyBytes = Buffer.alloc(32, 0x42);

  const provider = new MacKeychainKeyProvider({
    executable: FAKE_KEY_HELPER,
    account: 'history.test-device',
    async runner(req) {
      calls.push(req);
      if (req.executable === '/usr/bin/security') {
        return { stdout: Buffer.alloc(0), exitCode: 44 };
      }
      const parsed = JSON.parse(String(req.stdin)) as { command: string; service: string; account: string };
      if (parsed.command === 'get' && calls.length === 1) {
        return { stdout: helperJson('missing'), exitCode: 0 };
      }
      return { stdout: helperJson('ok', keyBytes.toString('base64')), exitCode: 0 };
    },
  });

  assert.equal(calls.length, 0);
  assert.equal(await provider.readKey(), null);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0]!.args, ['--command', 'get']);
  assert.deepEqual(JSON.parse(String(calls[0]!.stdin)), {
    version: 1,
    command: 'get',
    service: DEFAULT_KEYCHAIN_SERVICE,
    account: 'history.test-device',
  });

  const created = await provider.getOrCreateKey();
  assert.deepEqual(created, keyBytes);
  assert.deepEqual(calls[1]!.args, ['--command', 'create']);

  for (const call of calls) {
    assert.equal(JSON.stringify(call.args).includes(keyBytes.toString('base64')), false);
  }

  await provider.deleteKey();
  assert.equal(calls[2]!.executable, '/usr/bin/security');
});

test('MacKeychainKeyProvider fails closed on denied, malformed, oversized, and failed helper responses', async () => {
  const badCases: Array<{ stdout: Buffer; exitCode: number; code: string }> = [
    { stdout: helperJson('denied'), exitCode: 0, code: 'key-denied' },
    { stdout: helperJson('denied', undefined, { phase: 'lookup', osStatus: -25308 }), exitCode: 0, code: 'keychain-ui-required' },
    { stdout: helperJson('error', undefined, { phase: 'lookup', osStatus: -25291 }), exitCode: 0, code: 'keychain-not-available' },
    { stdout: Buffer.from(SECRET, 'utf8'), exitCode: 0, code: 'key-helper-response-invalid' },
    { stdout: helperJson('ok', Buffer.alloc(31).toString('base64')), exitCode: 0, code: 'key-helper-response-invalid' },
    { stdout: Buffer.alloc(1025, 0x41), exitCode: 0, code: 'key-helper-output-limit' },
    { stdout: helperJson('ok', Buffer.alloc(32).toString('base64')), exitCode: 2, code: 'key-helper-exit-failed' },
  ];

  for (const tc of badCases) {
    const provider = new MacKeychainKeyProvider({
      executable: FAKE_KEY_HELPER,
      async runner() {
        return { stdout: tc.stdout, exitCode: tc.exitCode };
      },
    });
    await assert.rejects(provider.readKey(), expectKeyError(tc.code));
  }
});

test('WindowsDpapiKeyProvider protects and unprotects 32-byte key via PowerShell stdin/stdout without argv leakage', async (t) => {
  const root = await makeTempDir(t);
  const dpapiMask = Buffer.alloc(32, 0xa5);
  const calls: SubprocessRunRequest[] = [];

  const provider = new WindowsDpapiKeyProvider({
    dataRoot: join(root, 'win-data'),
    platform: 'win32',
    async runner(req) {
      calls.push(req);
      const script = req.args[3] ?? '';
      const inputB64 = String(req.stdin).trim();
      const inputBuf = Buffer.from(inputB64, 'base64');
      assert.equal(req.executable, 'powershell.exe');
      assert.deepEqual(req.args.slice(0, 3), ['-NoProfile', '-NonInteractive', '-Command']);
      assert.equal(JSON.stringify(req.args).includes(inputB64), false);

      if (script.includes('::Protect(')) {
        assert.equal(inputBuf.length, 32);
        const masked = Buffer.from(inputBuf.map((b, i) => b ^ dpapiMask[i]!));
        const blob = Buffer.concat([Buffer.from('DPAPI01:'), masked]);
        return { stdout: Buffer.from(blob.toString('base64'), 'utf8'), exitCode: 0 };
      }
      if (script.includes('::Unprotect(')) {
        assert.equal(inputBuf.subarray(0, 8).toString('utf8'), 'DPAPI01:');
        const masked = inputBuf.subarray(8);
        const raw = Buffer.from(masked.map((b, i) => b ^ dpapiMask[i]!));
        return { stdout: Buffer.from(raw.toString('base64'), 'utf8'), exitCode: 0 };
      }
      throw new Error('unexpected powershell command');
    },
  });

  assert.equal(await provider.readKey(), null);
  assert.equal(calls.length, 0);

  const generated = await provider.getOrCreateKey();
  assert.equal(generated.length, 32);
  assert.equal(calls.length, 1);

  const dpapiFile = join(root, 'win-data', DPAPI_KEY_FILENAME);
  const onDisk = await readFile(dpapiFile);
  assert.equal(onDisk.includes(generated), false);

  const loaded = await provider.readKey();
  assert.deepEqual(loaded, generated);

  const idempotent = await provider.getOrCreateKey();
  assert.deepEqual(idempotent, generated);

  await provider.deleteKey();
  await assert.rejects(lstat(dpapiFile), { code: 'ENOENT' });
  assert.equal(await provider.readKey(), null);
});

test('WindowsDpapiKeyProvider native executable mode invokes --command get|create|delete via stdin and zeroes stdout buffers', async (t) => {
  const root = await makeTempDir(t);
  const dataRoot = join(root, 'native-win-data');
  const calls: SubprocessRunRequest[] = [];
  const returnedBuffers: Buffer[] = [];
  const keyBytes = Buffer.alloc(32, 0x7a);

  assert.throws(
    () => new WindowsDpapiKeyProvider({ dataRoot, executable: 'relative/computer-history-key-store.exe' }),
    expectKeyError('invalid-input'),
  );

  const provider = new WindowsDpapiKeyProvider({
    dataRoot,
    executable: FAKE_WIN_KEY_HELPER,
    platform: 'win32',
    async runner(req) {
      calls.push(req);
      const parsed = JSON.parse(String(req.stdin)) as { version: number; command: string; dataRoot: string };
      assert.equal(req.executable, FAKE_WIN_KEY_HELPER);
      assert.deepEqual(req.args, ['--command', parsed.command]);
      assert.equal(req.maxOutputBytes, 1024);
      assert.equal(parsed.version, 1);
      assert.equal(parsed.dataRoot, dataRoot);
      assert.equal(JSON.stringify(req.args).includes(dataRoot), false);
      assert.equal(JSON.stringify(req.args).includes(keyBytes.toString('base64')), false);
      assert.equal(req.env?.ANTHROPIC_API_KEY, undefined);

      let stdout: Buffer;
      if (parsed.command === 'get' && calls.length === 1) {
        stdout = Buffer.from(JSON.stringify({ version: 1, status: 'missing', phase: 'lookup' }) + '\n', 'utf8');
      } else if (parsed.command === 'delete') {
        stdout = Buffer.from(JSON.stringify({ version: 1, status: 'ok' }) + '\n', 'utf8');
      } else {
        stdout = Buffer.from(
          JSON.stringify({ version: 1, status: 'ok', key: keyBytes.toString('base64') }) + '\n',
          'utf8',
        );
      }
      returnedBuffers.push(stdout);
      return { stdout, exitCode: 0 };
    },
  });

  assert.equal(await provider.readKey(), null);
  const created = await provider.getOrCreateKey();
  assert.deepEqual(created, keyBytes);
  const loaded = await provider.readKey();
  assert.deepEqual(loaded, keyBytes);
  await provider.deleteKey();

  assert.equal(calls.length, 4);
  assert.deepEqual(
    calls.map((c) => c.args[1]),
    ['get', 'create', 'get', 'delete'],
  );
  // Every stdout buffer returned from the helper must be zeroed in finally.
  for (const buf of returnedBuffers) {
    assert.equal(
      buf.every((byte) => byte === 0),
      true,
    );
  }
});

test('WindowsDpapiKeyProvider native executable mode fails closed on denied, error, malformed, oversized, and exit 64 responses', async (t) => {
  const root = await makeTempDir(t);
  const dataRoot = join(root, 'native-fail-closed');

  const getCases: Array<{
    stdout: Buffer;
    exitCode: number;
    code: string;
    diagnostic?: Record<string, unknown>;
  }> = [
    {
      stdout: helperJson('denied', undefined, { phase: 'dpapi-unprotect', osStatus: -2146893813 }),
      exitCode: 0,
      code: 'key-denied',
      diagnostic: { phase: 'dpapi-unprotect', osStatus: -2146893813 },
    },
    {
      stdout: helperJson('error', undefined, { phase: 'dpapi-protect', osStatus: 5 }),
      exitCode: 0,
      code: 'dpapi-operation-failed',
      diagnostic: { phase: 'dpapi-protect', osStatus: 5 },
    },
    {
      stdout: Buffer.from(SECRET, 'utf8'),
      exitCode: 0,
      code: 'key-helper-response-invalid',
    },
    {
      stdout: helperJson('ok', Buffer.alloc(31).toString('base64')),
      exitCode: 0,
      code: 'key-helper-response-invalid',
    },
    {
      stdout: helperJson('ok', Buffer.alloc(32).toString('base64'), { extra: true }),
      exitCode: 0,
      code: 'key-helper-response-invalid',
    },
    {
      stdout: Buffer.from(JSON.stringify({ version: 2, status: 'ok', key: Buffer.alloc(32).toString('base64') })),
      exitCode: 0,
      code: 'key-helper-response-invalid',
    },
    {
      stdout: helperJson('error', Buffer.alloc(32).toString('base64')),
      exitCode: 0,
      code: 'key-helper-response-invalid',
    },
    {
      stdout: helperJson('error', undefined, { phase: 'bogus' }),
      exitCode: 0,
      code: 'key-helper-response-invalid',
    },
    {
      stdout: Buffer.alloc(1025, 0x41),
      exitCode: 0,
      code: 'key-helper-output-limit',
    },
    {
      stdout: helperJson('error'),
      exitCode: 64,
      code: 'key-helper-exit-failed',
      diagnostic: { exitCode: 64 },
    },
  ];

  for (const tc of getCases) {
    const stdoutCopy = Buffer.from(tc.stdout);
    const provider = new WindowsDpapiKeyProvider({
      dataRoot,
      executable: FAKE_WIN_KEY_HELPER,
      platform: 'win32',
      async runner() {
        return { stdout: stdoutCopy, exitCode: tc.exitCode };
      },
    });
    await assert.rejects(provider.readKey(), (error: unknown) => {
      assert.ok(error instanceof KeyProviderError);
      assert.equal(error.code, tc.code);
      assert.equal(error.message.includes(SECRET), false);
      if (tc.diagnostic) {
        assert.deepEqual(error.diagnostic, tc.diagnostic);
      }
      return true;
    });
    assert.equal(
      stdoutCopy.every((byte) => byte === 0),
      true,
    );
  }

  // create must reject status: 'missing' with key-missing
  const missingOnCreate = new WindowsDpapiKeyProvider({
    dataRoot,
    executable: FAKE_WIN_KEY_HELPER,
    platform: 'win32',
    async runner() {
      return { stdout: helperJson('missing', undefined, { phase: 'race-reload' }), exitCode: 0 };
    },
  });
  await assert.rejects(missingOnCreate.getOrCreateKey(), expectKeyError('key-missing'));

  // delete must reject unexpected key field and map delete denied/error cleanly
  const keyOnDelete = new WindowsDpapiKeyProvider({
    dataRoot,
    executable: FAKE_WIN_KEY_HELPER,
    platform: 'win32',
    async runner() {
      return { stdout: helperJson('ok', Buffer.alloc(32).toString('base64')), exitCode: 0 };
    },
  });
  await assert.rejects(keyOnDelete.deleteKey(), expectKeyError('key-helper-response-invalid'));

  const deniedOnDelete = new WindowsDpapiKeyProvider({
    dataRoot,
    executable: FAKE_WIN_KEY_HELPER,
    platform: 'win32',
    async runner() {
      return { stdout: helperJson('denied', undefined, { phase: 'delete', osStatus: 5 }), exitCode: 0 };
    },
  });
  await assert.rejects(deniedOnDelete.deleteKey(), (error: unknown) => {
    assert.ok(error instanceof KeyProviderError);
    assert.equal(error.code, 'key-denied');
    assert.deepEqual(error.diagnostic, { phase: 'delete', osStatus: 5 });
    return true;
  });

  const errorOnDelete = new WindowsDpapiKeyProvider({
    dataRoot,
    executable: FAKE_WIN_KEY_HELPER,
    platform: 'win32',
    async runner() {
      return { stdout: helperJson('error', undefined, { phase: 'delete', osStatus: 32 }), exitCode: 0 };
    },
  });
  await assert.rejects(errorOnDelete.deleteKey(), (error: unknown) => {
    assert.ok(error instanceof KeyProviderError);
    assert.equal(error.code, 'dpapi-operation-failed');
    assert.deepEqual(error.diagnostic, { phase: 'delete', osStatus: 32 });
    return true;
  });
});

test('createPlatformKeyProvider on win32 selects native executable when keyHelperPath is provided and PowerShell fallback when omitted', async (t) => {
  const root = await makeTempDir(t);
  const dataRoot = join(root, 'platform-select');
  const seen: string[] = [];

  const nativeProvider = createPlatformKeyProvider({
    platform: 'win32',
    dataRoot,
    keyHelperPath: FAKE_WIN_KEY_HELPER,
    async runner(req) {
      seen.push(req.executable);
      return { stdout: helperJson('missing', undefined, { phase: 'lookup' }), exitCode: 0 };
    },
  });
  assert.equal(await nativeProvider.readKey(), null);
  assert.deepEqual(seen, [FAKE_WIN_KEY_HELPER]);

  const psProvider = createPlatformKeyProvider({
    platform: 'win32',
    dataRoot,
    async runner(req) {
      seen.push(req.executable);
      throw new Error('PowerShell should not spawn when master.key.dpapi is absent');
    },
  });
  assert.equal(await psProvider.readKey(), null);
  assert.deepEqual(seen, [FAKE_WIN_KEY_HELPER]);
});

test(
  'HistoryService on win32 verifies explicit keyHelperPath manifest and fails closed on tampering',
  { skip: process.platform !== 'win32', timeout: 10_000 },
  async (t) => {
    const dir = await makeTempDir(t);
    const keyHelperPath = join(dir, 'computer-history-key-store.exe');
    const binaryBytes = 'Synthetic Windows key-store binary';
    await writeFile(keyHelperPath, binaryBytes);
    const sha256 = createHash('sha256').update(binaryBytes).digest('hex');
    await writeFile(
      join(dir, 'manifest.json'),
      JSON.stringify({
        version: 1,
        platform: 'win32',
        arch: process.arch,
        files: { 'computer-history-key-store.exe': { sha256 } },
      }),
    );

    const invoked: string[][] = [];
    const keyBytes = Buffer.alloc(32, 0x33);
    const spawn: SpawnManaged = (spec) => {
      invoked.push([...spec.argv]);
      const stdout = new PassThrough();
      const stderr = new PassThrough();
      let end!: (v: { exitCode: number | null; signal: NodeJS.Signals | null }) => void;
      const done = new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>((resolveDone) => {
        end = resolveDone;
      });
      const stdin = new Writable({
        write(_c, _e, cb) {
          cb();
        },
        final(cb) {
          stdout.end(JSON.stringify({ version: 1, status: 'ok', key: keyBytes.toString('base64') }) + '\n');
          stderr.end();
          end({ exitCode: 0, signal: null });
          cb();
        },
      });
      const handle: ManagedProcess = {
        stdin,
        stdout,
        stderr,
        done,
        terminate() {
          end({ exitCode: 0, signal: null });
        },
        async waitForExit() {
          await done;
          return true;
        },
      };
      return handle;
    };

    const service = createHistoryService({
      dataRoot: join(dir, 'data-ok'),
      platform: 'win32',
      keyHelperPath,
      deviceId: 'win-ks-verify',
      spawn,
    });
    t.after(() => service.close());

    const status = await service.initializeKey();
    assert.equal(status.state, 'stopped');
    assert.ok(invoked.length >= 1);
    assert.deepEqual(invoked[0], [keyHelperPath, '--command', 'create']);

    // Tampering with the key helper binary must fail closed before spawning.
    await writeFile(keyHelperPath, 'tampered-key-store-bytes');
    const tamperedInvokedCount = invoked.length;
    const tamperedService = createHistoryService({
      dataRoot: join(dir, 'data-tampered'),
      platform: 'win32',
      keyHelperPath,
      deviceId: 'win-ks-tampered',
      spawn,
    });
    t.after(() => tamperedService.close());

    await assert.rejects(tamperedService.initializeKey(), (error: unknown) => {
      assert.ok(error instanceof HistoryOperationError);
      assert.equal(error.code, 'native-hash-mismatch');
      return true;
    });
    assert.equal(invoked.length, tamperedInvokedCount);
  },
);

test(
  'WindowsDpapiKeyProvider native computer-history-key-store.exe round-trips live DPAPI and is byte-for-byte compatible with PowerShell DPAPI',
  { skip: process.platform !== 'win32', timeout: 240_000 },
  async (t) => {
    const exePath = findBuiltWindowsKeyStoreExe();
    if (!exePath) {
      t.skip('computer-history-key-store.exe is not built yet');
      return;
    }

    const root = await makeTempDir(t);
    const dataRoot = join(root, 'live-native-cross-compat');
    const nativeProvider = new WindowsDpapiKeyProvider({
      dataRoot,
      executable: exePath,
      platform: 'win32',
      timeoutMs: 10_000,
    });
    const psProvider = new WindowsDpapiKeyProvider({
      dataRoot,
      platform: 'win32',
      timeoutMs: 90_000,
    });

    // 1. Native Rust round-trip
    assert.equal(await nativeProvider.readKey(), null);
    const rustKey = await nativeProvider.getOrCreateKey();
    assert.equal(rustKey.length, 32);

    const dpapiFile = join(dataRoot, DPAPI_KEY_FILENAME);
    const rustOnDisk = await readFile(dpapiFile);
    assert.ok(rustOnDisk.length > 0 && rustOnDisk.length <= 8192);
    assert.equal(rustOnDisk.includes(rustKey), false);

    assert.deepEqual(await nativeProvider.readKey(), rustKey);
    assert.deepEqual(await nativeProvider.getOrCreateKey(), rustKey);

    // 2. Cross-compat: PowerShell DPAPI decrypts Rust-created master.key.dpapi byte-for-byte
    const psReadFromRust = await psProvider.readKey();
    assert.ok(psReadFromRust);
    assert.deepEqual(psReadFromRust, rustKey);

    // 3. Delete via native Rust helper
    await nativeProvider.deleteKey();
    await assert.rejects(lstat(dpapiFile), { code: 'ENOENT' });
    assert.equal(await nativeProvider.readKey(), null);
    assert.equal(await psProvider.readKey(), null);

    // 4. Cross-compat: Rust computer-history-key-store.exe decrypts PowerShell-created master.key.dpapi byte-for-byte
    const psKey = await psProvider.getOrCreateKey();
    assert.equal(psKey.length, 32);
    const rustReadFromPs = await nativeProvider.readKey();
    assert.ok(rustReadFromPs);
    assert.deepEqual(rustReadFromPs, psKey);
    assert.deepEqual(await nativeProvider.getOrCreateKey(), psKey);

    await nativeProvider.deleteKey();
    await assert.rejects(lstat(dpapiFile), { code: 'ENOENT' });
  },
);

test(
  'WindowsDpapiKeyProvider protects and unprotects live 32-byte key via DPAPI on Windows',
  { skip: process.platform !== 'win32', timeout: 240_000 },
  async (t) => {
    const root = await makeTempDir(t);
    const dataRoot = join(root, 'live-dpapi');
    // PowerShell 5.1 + .NET DPAPI cold starts can exceed 45s under parallel test load on Windows CI runners.
    const provider = new WindowsDpapiKeyProvider({ dataRoot, platform: 'win32', timeoutMs: 90_000 });

    assert.equal(await provider.readKey(), null);

    const created = await provider.getOrCreateKey();
    assert.ok(Buffer.isBuffer(created));
    assert.equal(created.length, 32);

    const dpapiFile = join(dataRoot, DPAPI_KEY_FILENAME);
    const onDisk = await readFile(dpapiFile);
    assert.ok(onDisk.length > 0);
    assert.equal(onDisk.includes(created), false);

    const reread = await provider.readKey();
    assert.ok(Buffer.isBuffer(reread));
    assert.equal(reread.length, 32);
    assert.deepEqual(reread, created);

    await provider.deleteKey();
    await assert.rejects(lstat(dpapiFile), { code: 'ENOENT' });
    assert.equal(await provider.readKey(), null);
  },
);

test('unified createManagedRunner enforces timeouts, output limits, and poisons on unconfirmed exit', async (t) => {
  const dir = await makeTempDir(t);
  const hangScript = join(dir, 'hang.mjs');
  await writeFile(hangScript, 'setInterval(() => {}, 10000);', { mode: 0o600 });

  const localRunner = createManagedRunner({ cwd: dir });
  await assert.rejects(
    localRunner.run({
      executable: process.execPath,
      args: [hangScript],
      timeoutMs: 40,
      maxOutputBytes: 1024,
    }),
    { code: 'timeout' },
  );

  let spawns = 0;
  const unconfirmedSpawn: SpawnManaged = () => {
    spawns++;
    return {
      stdin: new Writable({
        write(_c, _e, cb) {
          cb();
        },
      }),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      done: new Promise(() => {}),
      terminate() {},
      waitForExit() {
        return Promise.resolve(false);
      },
    };
  };
  const poisonedRunner = createManagedRunner({ spawn: unconfirmedSpawn, cwd: dir });
  await assert.rejects(
    poisonedRunner.run({
      executable: FAKE_KEY_HELPER,
      args: [],
      timeoutMs: 20,
    }),
    { code: 'exit-unconfirmed' },
  );
  assert.equal(poisonedRunner.poisoned, true);
  await assert.rejects(
    poisonedRunner.run({
      executable: FAKE_KEY_HELPER,
      args: [],
      timeoutMs: 20,
    }),
    { code: 'exit-unconfirmed' },
  );
  assert.equal(spawns, 1);
});

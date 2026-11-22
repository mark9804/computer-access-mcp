import assert from 'node:assert/strict';
import { PassThrough, Writable } from 'node:stream';
import { lstat, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import type { TestContext } from 'node:test';
import { createManagedRunner } from '../../src/host/managed-runner.ts';
import type { SubprocessRunRequest } from '../../src/host/managed-runner.ts';
import type { SpawnManaged } from '../../src/host/collectors/process.ts';
import {
  DEFAULT_KEYCHAIN_SERVICE,
  DPAPI_KEY_FILENAME,
  KeyProviderError,
  MacKeychainKeyProvider,
  MemoryKeyProvider,
  WindowsDpapiKeyProvider,
} from '../../src/storage/key-provider.ts';

const SECRET = 'SYNTHETIC-SECRET-DO-NOT-LEAK-9941';
const FAKE_KEY_HELPER = '/synthetic/never-executed/computer-access-key-store';

async function makeTempDir(t: TestContext): Promise<string> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'camcp-key-')));
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

test('MacKeychainKeyProvider uses com.computer-access.mcp service, returns null on missing, and creates only on getOrCreateKey', async () => {
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

test(
  'WindowsDpapiKeyProvider protects and unprotects live 32-byte key via DPAPI on Windows',
  { skip: process.platform !== 'win32', timeout: 15000 },
  async (t) => {
    const root = await makeTempDir(t);
    const dataRoot = join(root, 'live-dpapi');
    const provider = new WindowsDpapiKeyProvider({ dataRoot, platform: 'win32' });

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

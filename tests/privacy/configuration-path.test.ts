import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { chmod, lstat, mkdir, mkdtemp, realpath, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import test from 'node:test';
import type { TestContext } from 'node:test';
import { StorageError } from '../../src/storage/errors.ts';
import { defaultDataRoot, prepareDataDirectory } from '../../src/storage/platform-paths.ts';
import { acquireStorageLock } from '../../src/storage/storage-lock.ts';

async function makeTempDir(t: TestContext): Promise<string> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'camcp-paths-')));
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  return dir;
}

function expectStorageCode(code: StorageError['code']) {
  return (err: unknown): boolean => {
    assert.ok(err instanceof StorageError);
    assert.equal(err.code, code);
    return true;
  };
}

test('defaultDataRoot resolves platform-specific directories cleanly', () => {
  assert.equal(
    defaultDataRoot('darwin', {}, '/Users/alice'),
    '/Users/alice/Library/Application Support/computer-access-mcp',
  );
  assert.equal(
    defaultDataRoot('win32', { LOCALAPPDATA: 'C:\\Users\\alice\\AppData\\Local' }, 'C:\\Users\\alice'),
    'C:\\Users\\alice\\AppData\\Local\\computer-access-mcp',
  );
  assert.equal(
    defaultDataRoot('win32', {}, 'C:\\Users\\alice'),
    'C:\\Users\\alice\\AppData\\Local\\computer-access-mcp',
  );
  assert.equal(
    defaultDataRoot('linux', { XDG_DATA_HOME: '/home/alice/.xdg-data' }, '/home/alice'),
    '/home/alice/.xdg-data/computer-access-mcp',
  );
  assert.equal(
    defaultDataRoot('linux', {}, '/home/alice'),
    '/home/alice/.local/share/computer-access-mcp',
  );
});

test('prepareDataDirectory enforces 0o700 on POSIX, allows mode bits on win32, and rejects symlinks', async (t) => {
  const base = await makeTempDir(t);

  const created = join(base, 'fresh-data');
  if (process.platform !== 'win32') {
    const resolved = await prepareDataDirectory(created, { platform: 'darwin' });
    assert.equal(resolved, created);
    assert.equal((await lstat(created)).mode & 0o777, 0o700);
  } else {
    const resolved = await prepareDataDirectory(created, { platform: 'win32' });
    assert.equal(resolved, created);
  }

  const looseDir = join(base, 'loose-dir');
  await mkdir(looseDir);
  if (process.platform !== 'win32') {
    await chmod(looseDir, 0o755);
    await assert.rejects(
      prepareDataDirectory(looseDir, { platform: 'darwin' }),
      expectStorageCode('unsafe-permissions'),
    );
  }
  // Simulated win32 platform does not fail on POSIX mode bits.
  assert.equal(await prepareDataDirectory(looseDir, { platform: 'win32' }), looseDir);

  const realTarget = join(base, 'real-target');
  await mkdir(realTarget, { mode: 0o700 });
  const linkDir = join(base, 'symlink-dir');
  await symlink(realTarget, linkDir, process.platform === 'win32' ? 'junction' : undefined);

  await assert.rejects(
    prepareDataDirectory(linkDir, { platform: 'darwin' }),
    expectStorageCode('unsafe-path'),
  );
  await assert.rejects(
    prepareDataDirectory(linkDir, { platform: 'win32' }),
    expectStorageCode('unsafe-path'),
  );
  await assert.rejects(
    prepareDataDirectory(join(linkDir, 'nested'), { platform: 'darwin' }),
    expectStorageCode('unsafe-path'),
  );
  await assert.rejects(
    prepareDataDirectory('relative/path', { platform: 'darwin' }),
    expectStorageCode('unsafe-path'),
  );
  await assert.rejects(
    prepareDataDirectory('/', { platform: 'darwin' }),
    expectStorageCode('unsafe-path'),
  );
});

test('acquireStorageLock enforces exclusive contention in-process and across child crash without unlinking store.lock', async (t) => {
  const base = await makeTempDir(t);
  const lockPath = join(base, 'store.lock');

  const first = await acquireStorageLock(lockPath);
  await assert.rejects(acquireStorageLock(lockPath), expectStorageCode('already-owned'));
  await first.release();
  // Lock file remains on disk after release.
  assert.equal((await lstat(lockPath)).isFile(), true);

  // Spawn a separate process holding the lock, verify contention, then SIGKILL it and verify immediate OS release.
  const lockModuleUrl = new URL('../../src/storage/storage-lock.ts', import.meta.url).href;
  const childScript = `
    import { acquireStorageLock } from ${JSON.stringify(lockModuleUrl)};
    const lock = await acquireStorageLock(${JSON.stringify(lockPath)});
    process.stdout.write('locked\\n');
    setInterval(() => {}, 10000);
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', childScript], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const closed = once(child, 'close');
  const rl = createInterface({ input: child.stdout });

  try {
    const [line] = await once(rl, 'line');
    assert.equal(line, 'locked');
    await assert.rejects(acquireStorageLock(lockPath), expectStorageCode('already-owned'));

    child.kill('SIGKILL');
    await closed;

    const recovered = await acquireStorageLock(lockPath);
    await recovered.release();
    assert.equal((await lstat(lockPath)).isFile(), true);
  } finally {
    rl.close();
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await closed;
    }
  }
});

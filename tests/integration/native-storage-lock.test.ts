import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import type { Socket } from 'node:net';
import { copyFile, lstat, mkdir, mkdtemp, open, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';
import type { TestContext } from 'node:test';
import { loadNativeStorageLock } from '../../src/storage/storage-lock.ts';

const root = fileURLToPath(new URL('../../', import.meta.url));
const modulePath = join(root, 'src/storage/storage-lock.ts');
const nativeDirectory = join(root, 'native-bin');
const filename = 'computer-access-storage-lock.node';
const manifestName = 'storage-lock.manifest.json';
const supportedOs = { skip: process.platform !== 'darwin' && process.platform !== 'win32' };
const env = { ...process.env };

async function temporary(t: TestContext): Promise<string> {
  const base = await realpath(tmpdir());
  const directory = await mkdtemp(join(base, 'camcp-native-lock-synthetic-'));
  const identity = await lstat(directory);
  t.after(async () => {
    const current = await lstat(directory);
    assert.equal(resolve(directory), directory);
    assert.equal(dirname(directory), base);
    assert.ok(directory.startsWith(join(base, 'camcp-native-lock-synthetic-')));
    assert.equal(await realpath(directory), directory);
    assert.equal(current.dev, identity.dev);
    assert.equal(current.ino, identity.ino);
    await rm(directory, { recursive: true, force: false });
  });
  return directory;
}

function childCode(lockFile: string, hold = false): string {
  return `import {open} from 'node:fs/promises';
    import {loadNativeStorageLock} from ${JSON.stringify(pathToFileURL(modulePath).href)};
    const handle=await open(${JSON.stringify(lockFile)}, 'r+');
    const lock=await loadNativeStorageLock();
    const acquired=lock.tryLock(handle.fd);
    console.log(JSON.stringify({acquired}));
    ${hold ? 'setTimeout(async()=>{await handle.close();process.exit(0)},5000);' : 'await handle.close();'}`;
}

function probe(lockFile: string): boolean {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', childCode(lockFile)], {
    encoding: 'utf8',
    env,
    timeout: 2000,
    maxBuffer: 16384,
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  return (JSON.parse(result.stdout) as { acquired: boolean }).acquired;
}

function ready(child: ChildProcess): Promise<{ acquired: boolean }> {
  return new Promise((resolveReady, reject) => {
    let buffer = '';
    const timer = setTimeout(() => reject(new Error('synthetic-child-ready-timeout')), 2000);
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.stdout!.on('data', (bytes: Buffer) => {
      buffer += bytes.toString();
      if (buffer.includes('\n')) {
        clearTimeout(timer);
        try {
          resolveReady(JSON.parse(buffer.split('\n')[0]!) as { acquired: boolean });
        } catch (error) {
          reject(error);
        }
      }
    });
  });
}

test('Node-owned fd flock rejects competing writers and survives unrelated helper death', supportedOs, async (t) => {
  const directory = await temporary(t);
  const file = join(directory, 'synthetic-writer');
  const handle = await open(file, 'wx+', 0o600);
  const lock = await loadNativeStorageLock();
  assert.equal(await loadNativeStorageLock(), lock);
  try {
    assert.equal(lock.tryLock(handle.fd), true);
    // POSIX flock is idempotent on the same fd; Windows LockFileEx rejects re-locking an already-held byte range.
    assert.equal(lock.tryLock(handle.fd), process.platform === 'win32' ? false : true);
    assert.equal(probe(file), false);
    const independent = await open(file, 'r+');
    try {
      assert.equal(lock.tryLock(independent.fd), false);
    } finally {
      await independent.close();
    }
    assert.equal(probe(file), false, 'closing separately opened fd must not release owner lock');
    const helper = spawnSync(process.execPath, ['-e', 'process.kill(process.pid,"SIGKILL")'], { env, timeout: 2000 });
    assert.equal(process.platform === 'win32' ? helper.status !== 0 : helper.signal === 'SIGKILL', true);
    assert.equal(probe(file), false, 'helper lifetime cannot release Node owner lock');
  } finally {
    await handle.close();
  }
  assert.equal(probe(file), true);
  assert.equal((await lstat(file)).isFile(), true);
});

test('SIGKILL of writer releases OS flock without removing persistent sentinel', supportedOs, async (t) => {
  const directory = await temporary(t);
  const file = join(directory, 'synthetic-writer');
  await writeFile(file, 'SYNTHETIC-NOT-A-HISTORY-STORE\n', { mode: 0o600, flag: 'wx' });
  const child = spawn(process.execPath, ['--input-type=module', '-e', childCode(file, true)], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolveExit) =>
    child.once('exit', (code, signal) => resolveExit({ code, signal })),
  );
  try {
    assert.equal((await ready(child)).acquired, true);
    assert.equal(probe(file), false);
    assert.equal(child.kill('SIGKILL'), true);
    const exit = await exited;
    assert.equal(
      process.platform === 'win32' ? exit.signal === 'SIGKILL' || (exit.code !== null && exit.code !== 0) : exit.signal === 'SIGKILL',
      true,
    );
    assert.equal(probe(file), true);
    assert.equal(await readFile(file, 'utf8'), 'SYNTHETIC-NOT-A-HISTORY-STORE\n');
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited;
  }
});

test('default spawned child cannot retain owner flock after owner SIGKILL', supportedOs, async (t) => {
  const directory = await temporary(t);
  const file = join(directory, 'synthetic-writer');
  const token = randomBytes(24).toString('hex');
  const socketPath =
    process.platform === 'win32' ? `\\\\.\\pipe\\camcp-lock-${token.slice(0, 16)}` : join(directory, 's');
  if (process.platform !== 'win32') {
    assert.ok(Buffer.byteLength(socketPath) < 104, 'Darwin Unix socket path is bounded');
  }
  await writeFile(file, 'SYNTHETIC-CLOEXEC-ONLY\n', { mode: 0o600, flag: 'wx' });
  const sockets = new Set<Socket>();
  const server = createServer();
  const connected = new Promise<Socket>((resolveSocket) => server.once('connection', resolveSocket));
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  await new Promise<void>((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(socketPath, resolveListen);
  });
  const within = <T>(promise: Promise<T>): Promise<T> =>
    new Promise((resolveWithin, reject) => {
      const timer = setTimeout(() => reject(new Error('synthetic-descendant-timeout')), 2500);
      promise.then(
        (value) => {
          clearTimeout(timer);
          resolveWithin(value);
        },
        (error: unknown) => {
          clearTimeout(timer);
          reject(error);
        },
      );
    });
  const descendantCode = `const net=require('node:net');
    const token=${JSON.stringify(token)};
    const socket=net.createConnection(${JSON.stringify(socketPath)});
    const stop=()=>${process.platform === 'win32' ? 'process.exit(1)' : "process.kill(process.pid,'SIGKILL')"};
    setTimeout(stop,6000).unref();
    socket.on('error',()=>process.exit(2)); socket.on('end',()=>process.exit(0));
    socket.on('connect',()=>socket.write(JSON.stringify({token,pid:process.pid,kind:'hello'})+'\\n'));
    let text=''; socket.on('data',chunk=>{ text+=chunk; let index;
      while((index=text.indexOf('\\n'))!==-1){const line=text.slice(0,index);text=text.slice(index+1);
        const msg=JSON.parse(line);if(msg.token!==token)process.exit(3);
        if(msg.kind==='stop')stop();
        if(msg.kind==='ping')socket.write(JSON.stringify({token,pid:process.pid,kind:'pong'})+'\\n');
      }
    });`;
  const ownerCode = `import {open} from 'node:fs/promises'; import {spawn} from 'node:child_process';
    import {loadNativeStorageLock} from ${JSON.stringify(pathToFileURL(modulePath).href)};
    const handle=await open(${JSON.stringify(file)},'r+');
    const acquired=(await loadNativeStorageLock()).tryLock(handle.fd);
    if(!acquired)throw new Error('synthetic-owner-contended');
    // On Windows, libuv binds non-detached children to a kill-on-close Job Object; detach so the grandchild survives owner termination while still using piped stdio (bInheritHandles=TRUE).
    const child=spawn(process.execPath,['-e',${JSON.stringify(descendantCode)}],${
      process.platform === 'win32' ? '{env:process.env,detached:true,windowsHide:true}' : '{env:process.env}'
    });
    console.log(JSON.stringify({acquired,grandchildPid:child.pid}));
    setTimeout(()=>process.exit(0),6500);`;
  const owner = spawn(process.execPath, ['--input-type=module', '-e', ownerCode], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolveExit) =>
    owner.once('exit', (code, signal) => resolveExit({ code, signal })),
  );
  let control: Socket | undefined;
  let authenticated = false;
  let controlClosed: Promise<void> | undefined;
  try {
    const info = (await ready(owner)) as { acquired: boolean; grandchildPid: number };
    assert.equal(info.acquired, true);
    assert.ok(
      Number.isInteger(info.grandchildPid) &&
        info.grandchildPid > 0 &&
        info.grandchildPid !== process.pid &&
        info.grandchildPid !== owner.pid,
    );
    control = await within(connected);
    controlClosed = new Promise<void>((resolveClose) => control!.once('close', () => resolveClose()));
    let text = '';
    const messages: Array<{ token: string; pid: number; kind: string }> = [];
    let receiver: ((value: { token: string; pid: number; kind: string }) => void) | undefined;
    control.on('data', (chunk: Buffer) => {
      text += chunk.toString();
      let index: number;
      while ((index = text.indexOf('\n')) !== -1) {
        const message = JSON.parse(text.slice(0, index)) as { token: string; pid: number; kind: string };
        text = text.slice(index + 1);
        if (receiver) {
          const resolveMessage = receiver;
          receiver = undefined;
          resolveMessage(message);
        } else messages.push(message);
      }
    });
    const next = () =>
      within(
        messages.length
          ? Promise.resolve(messages.shift()!)
          : new Promise<{ token: string; pid: number; kind: string }>((resolveMessage) => {
              receiver = resolveMessage;
            }),
      );
    assert.deepEqual(await next(), { token, pid: info.grandchildPid, kind: 'hello' });
    authenticated = true;
    assert.equal(probe(file), false, 'live owner must exclude contenders');
    assert.equal(owner.kill('SIGKILL'), true);
    const ownerExit = await within(exited);
    assert.equal(
      process.platform === 'win32'
        ? ownerExit.signal === 'SIGKILL' || (ownerExit.code !== null && ownerExit.code !== 0)
        : ownerExit.signal === 'SIGKILL',
      true,
    );
    assert.equal(probe(file), true, 'still-living spawned child must not retain owner lock');
    control.write(JSON.stringify({ token, kind: 'ping' }) + '\n');
    assert.deepEqual(
      await next(),
      { token, pid: info.grandchildPid, kind: 'pong' },
      'descendant remains alive after owner death and reacquisition',
    );
  } finally {
    if (owner.exitCode === null && owner.signalCode === null) owner.kill('SIGKILL');
    await within(exited);
    if (control && authenticated && !control.destroyed) {
      control.write(JSON.stringify({ token, kind: 'stop' }) + '\n');
      try {
        await within(controlClosed!);
      } finally {
        control.destroy();
      }
    }
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolveClose, reject) => server.close((error) => (error ? reject(error) : resolveClose())));
  }
});

test('fd-only native API rejects coercion and exposes only tryLock and unlock', supportedOs, async (t) => {
  const lock = await loadNativeStorageLock();
  const raw = createRequire(import.meta.url)(join(nativeDirectory, filename)) as {
    tryLock: (...args: unknown[]) => boolean;
    unlock: (...args: unknown[]) => void;
  };
  assert.deepEqual(Object.keys(raw).sort(), ['tryLock', 'unlock']);
  for (const value of [-1, 1.1, NaN, Infinity, 0x80000000, '4', null, {}]) {
    assert.throws(() => raw.tryLock(value), { code: 'INVALID_FD' });
    assert.throws(() => raw.unlock(value), { code: 'INVALID_FD' });
    assert.throws(() => lock.tryLock(value as number), { code: 'native-lock-unavailable' });
    assert.throws(() => lock.unlock(value as number), { code: 'native-lock-unavailable' });
  }
  assert.throws(() => raw.tryLock(), { code: 'INVALID_FD' });
  assert.throws(() => raw.tryLock(1, 2), { code: 'INVALID_FD' });
  const directory = await temporary(t);
  const handle = await open(join(directory, 'synthetic-writer'), 'wx+', 0o600);
  const fd = handle.fd;
  await handle.close();
  assert.throws(() => raw.tryLock(fd), { code: 'EBADF' });
  assert.throws(() => lock.tryLock(fd), { code: 'native-lock-unavailable' });
});

async function isolatedPackage(
  t: TestContext,
): Promise<{ directory: string; addon: string; manifest: string; loader: string }> {
  const directory = await temporary(t);
  const storage = join(directory, 'src/storage');
  const binaries = join(directory, 'native-bin');
  await mkdir(storage, { recursive: true });
  await mkdir(binaries, { mode: 0o700 });
  await writeFile(join(directory, 'package.json'), '{"type":"module"}\n');
  await copyFile(modulePath, join(storage, 'storage-lock.ts'));
  await copyFile(join(root, 'src/storage/errors.ts'), join(storage, 'errors.ts'));
  await copyFile(join(root, 'src/storage/platform-paths.ts'), join(storage, 'platform-paths.ts'));
  await copyFile(join(nativeDirectory, filename), join(binaries, filename));
  await copyFile(join(nativeDirectory, manifestName), join(binaries, manifestName));
  return {
    directory,
    addon: join(binaries, filename),
    manifest: join(binaries, manifestName),
    loader: join(storage, 'storage-lock.ts'),
  };
}

function checkIsolated(loader: string, expected: string, importOnly = false): void {
  const code = `const {loadNativeStorageLock}=await import(${JSON.stringify(pathToFileURL(loader).href)});
    ${
      importOnly
        ? 'console.log("inert")'
        : `try {await loadNativeStorageLock(); console.log('loaded')} catch(error) {console.log(error.code); if(error.cause!==undefined || error.message!=='Storage error: native-lock-unavailable')process.exitCode=1}`
    }`;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', code], {
    encoding: 'utf8',
    env,
    timeout: 3000,
    maxBuffer: 16384,
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  assert.equal(result.stdout.trim(), expected);
}

test('loader import stays inert and missing artifacts fail closed on explicit load', supportedOs, async (t) => {
  const fixture = await isolatedPackage(t);
  assert.equal(dirname(fixture.addon), join(fixture.directory, 'native-bin'));
  assert.equal(await realpath(fixture.addon), fixture.addon);
  await rm(fixture.addon);
  checkIsolated(fixture.loader, 'inert', true);
  checkIsolated(fixture.loader, 'native-lock-unavailable');
});

test('loader rejects corrupt hash, symlink, oversized and mismatched manifests', supportedOs, async (t) => {
  for (const variant of ['hash', 'symlink', 'oversized', 'platform', 'arch', 'filename', 'version']) {
    await t.test(variant, async (sub) => {
      const fixture = await isolatedPackage(sub);
      if (variant === 'hash') await writeFile(fixture.addon, 'SYNTHETIC-BAD-ADDON');
      else if (variant === 'symlink') {
        assert.equal(dirname(fixture.addon), join(fixture.directory, 'native-bin'));
        assert.equal(await realpath(fixture.addon), fixture.addon);
        await rm(fixture.addon);
        try {
          await symlink(join(nativeDirectory, filename), fixture.addon);
        } catch (err) {
          const code = (err as NodeJS.ErrnoException).code;
          if (process.platform === 'win32' && (code === 'EPERM' || code === 'EACCES')) {
            sub.skip('Windows file symlink requires Developer Mode or elevation');
            return;
          }
          throw err;
        }
      } else if (variant === 'oversized') await writeFile(fixture.manifest, ' '.repeat(16385));
      else {
        const manifest = JSON.parse(await readFile(fixture.manifest, 'utf8')) as Record<string, unknown>;
        manifest[variant] = variant === 'version' ? 99 : 'synthetic-invalid';
        await writeFile(fixture.manifest, JSON.stringify(manifest));
      }
      checkIsolated(fixture.loader, 'native-lock-unavailable');
    });
  }
});

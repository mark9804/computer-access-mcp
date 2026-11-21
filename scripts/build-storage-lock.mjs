import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, open, readFile, realpath, rename, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const sourceDir = join(root, 'native/storage-lock');
const headerDirectory = join(sourceDir, 'vendor/node-v24.22.1');
const output = join(root, 'native-bin');
const filename = 'computer-access-storage-lock.node';
const manifestName = 'storage-lock.manifest.json';
const isWindows = process.platform === 'win32';

const headerHashes = {
  'node_api.h': '2d4560831e525b47b060ec8a0864ab73993df9e20215ce9f0fe7b24cd31af32a',
  'node_api_types.h': 'a25356630d3058f0a0c8937d9f297e9471e037fda58c2696d8a505c2bd99cb00',
  'js_native_api.h': '82d3708ce120f8000ec34d72e1aa70b0d7d8a43027986293681374a71b2cb840',
  'js_native_api_types.h': '4f19cb90d240765cc0961d92a1ee20f65fdc50db7de1ab0a5cb6bc227224e1a0',
};

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function verifyFile(path, maxBytes) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes) {
    throw new Error(`unsafe-storage-lock-file: ${path}`);
  }
  if (!isWindows && (stat.mode & 0o022) !== 0) {
    throw new Error(`unsafe-storage-lock-permissions: ${path}`);
  }
  return stat;
}

function compileAddon(cSource, binaryPath) {
  if (process.platform === 'darwin') {
    const archFlag = process.arch === 'arm64' ? 'arm64' : 'x86_64';
    return spawnSync(
      'xcrun',
      [
        'clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-DNAPI_VERSION=8', '-fvisibility=hidden', '-mmacosx-version-min=13.0',
        '-arch', archFlag, '-bundle', '-undefined', 'dynamic_lookup',
        '-I', headerDirectory, cSource, '-o', binaryPath,
      ],
      { cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024 },
    );
  }
  if (isWindows) {
    const nodeLib = process.env.NODE_LIB || join(dirname(process.execPath), 'node.lib');
    const extraLibs = existsSync(nodeLib) ? [nodeLib] : [];
    for (const compiler of ['clang-cl', 'cl']) {
      const check = spawnSync('where', [compiler], { encoding: 'utf8' });
      if (check.status !== 0) continue;
      return spawnSync(
        compiler,
        ['/O2', '/W4', '/DNAPI_VERSION=8', `/I${headerDirectory}`, cSource, '/LD', `/Fe:${binaryPath}`, ...extraLibs],
        { cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024 },
      );
    }
    throw new Error('storage-lock-compile-failed: neither clang-cl nor cl found in PATH');
  }
  return spawnSync(
    process.env.CC || 'cc',
    [
      '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      '-DNAPI_VERSION=8', '-fPIC', '-fvisibility=hidden', '-shared',
      '-I', headerDirectory, cSource, '-o', binaryPath,
    ],
    { cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024 },
  );
}

for (const [name, expected] of Object.entries(headerHashes)) {
  const path = join(headerDirectory, name);
  await verifyFile(path, 65536);
  if (sha256(await readFile(path)) !== expected) {
    throw new Error(`storage-lock-header-integrity-failed: ${name}`);
  }
}

const cSource = join(sourceDir, 'storage-lock.c');
await verifyFile(cSource, 65536);

await mkdir(output, { recursive: true, mode: 0o700 });
const outputStat = await lstat(output);
if (!outputStat.isDirectory() || outputStat.isSymbolicLink() || await realpath(output) !== output) {
  throw new Error('unsafe-native-output');
}

const scratch = await mkdtemp(join(output, '.storage-lock-build-'));
try {
  const binary = join(scratch, filename);
  const compile = compileAddon(cSource, binary);
  if (compile.status !== 0) {
    throw new Error(`storage-lock-compile-failed: ${compile.stderr || compile.stdout || compile.error?.message || compile.status}`);
  }
  if (!isWindows) await chmod(binary, 0o600);
  await verifyFile(binary, 2 * 1024 * 1024);

  const binaryBytes = await readFile(binary);
  const manifest = {
    version: 1,
    platform: process.platform,
    arch: process.arch,
    napiVersion: 8,
    filename,
    sha256: sha256(binaryBytes),
    sourceSha256: sha256(await readFile(cSource)),
    headers: { version: 'node-v24.22.1', sha256: headerHashes },
  };
  const manifestTemp = join(scratch, manifestName);
  const manifestHandle = await open(manifestTemp, 'wx', 0o600);
  try {
    await manifestHandle.writeFile(JSON.stringify(manifest, null, 2) + '\n');
    await manifestHandle.datasync();
  } finally {
    await manifestHandle.close();
  }

  await rename(binary, join(output, filename));
  await rename(manifestTemp, join(output, manifestName));
  console.log(`Built native-bin/${filename} (${process.platform}-${process.arch})`);
} finally {
  await rm(scratch, { recursive: true, force: true });
}

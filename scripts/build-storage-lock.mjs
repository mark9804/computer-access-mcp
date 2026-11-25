import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, open, readFile, realpath, rename, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const sourceDir = join(root, 'native/storage-lock');
const headerDirectory = join(sourceDir, 'vendor/node-v24.22.1');
const output = join(root, 'native-bin');
const filename = 'computer-history-storage-lock.node';
const manifestName = 'storage-lock.manifest.json';
const isWindows = process.platform === 'win32';

const headerHashes = {
  'node_api.h': '2d4560831e525b47b060ec8a0864ab73993df9e20215ce9f0fe7b24cd31af32a',
  'node_api_types.h': 'a25356630d3058f0a0c8937d9f297e9471e037fda58c2696d8a505c2bd99cb00',
  'js_native_api.h': '82d3708ce120f8000ec34d72e1aa70b0d7d8a43027986293681374a71b2cb840',
  'js_native_api_types.h': '4f19cb90d240765cc0961d92a1ee20f65fdc50db7de1ab0a5cb6bc227224e1a0',
};

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function samePath(a, b) {
  return isWindows
    ? resolve(a).toLowerCase() === resolve(b).toLowerCase()
    : resolve(a) === resolve(b);
}

function hasCommand(command, env = process.env) {
  return spawnSync('where', [command], { encoding: 'utf8', env }).status === 0;
}

function resolveWindowsMsvcEnv() {
  if (hasCommand('cl') && hasCommand('lib')) {
    return process.env;
  }
  const programFilesX86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
  const vswhere = join(programFilesX86, 'Microsoft Visual Studio', 'Installer', 'vswhere.exe');
  if (!existsSync(vswhere)) {
    return null;
  }
  const vcComponent =
    process.arch === 'arm64'
      ? 'Microsoft.VisualStudio.Component.VC.Tools.ARM64'
      : 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64';
  const query = spawnSync(
    vswhere,
    [
      '-all',
      '-products',
      '*',
      '-latest',
      '-requires',
      vcComponent,
      '-property',
      'installationPath',
    ],
    { encoding: 'utf8', maxBuffer: 1024 * 1024 },
  );
  if (query.status !== 0) {
    return null;
  }
  const installPath = (query.stdout || '').split(/\r?\n/).find(Boolean)?.trim();
  if (!installPath || /["\r\n]/.test(installPath)) {
    return null;
  }
  const vcvarsall = join(installPath, 'VC', 'Auxiliary', 'Build', 'vcvarsall.bat');
  if (!existsSync(vcvarsall)) {
    return null;
  }
  const vcvarsArch = process.arch === 'arm64' ? 'arm64' : 'x64';
  const probe = spawnSync(
    'cmd.exe',
    ['/d', '/s', '/c', `""${vcvarsall}" ${vcvarsArch} >nul && set"`],
    { encoding: 'utf8', windowsVerbatimArguments: true, maxBuffer: 4 * 1024 * 1024 },
  );
  if (probe.status !== 0) {
    return null;
  }
  const env = {};
  for (const line of (probe.stdout || '').split(/\r?\n/)) {
    const idx = line.indexOf('=');
    if (idx > 0) {
      env[line.slice(0, idx)] = line.slice(idx + 1);
    }
  }
  if (!hasCommand('cl', env) || !hasCommand('lib', env)) {
    return null;
  }
  return env;
}

function resolveWindowsNodeLib(scratch, env) {
  if (process.env.NODE_LIB && existsSync(process.env.NODE_LIB)) {
    return process.env.NODE_LIB;
  }
  const adjacentNodeLib = join(dirname(process.execPath), 'node.lib');
  if (existsSync(adjacentNodeLib)) {
    return adjacentNodeLib;
  }
  const defPath = join(scratch, 'napi.def');
  const libPath = join(scratch, 'node.lib');
  const defContents = [
    'LIBRARY node.exe',
    'EXPORTS',
    '  napi_module_register',
    '  napi_throw_error',
    '  napi_throw_type_error',
    '  napi_get_cb_info',
    '  napi_typeof',
    '  napi_get_value_double',
    '  napi_get_boolean',
    '  napi_get_undefined',
    '  napi_create_function',
    '  napi_set_named_property',
    '',
  ].join('\n');
  writeFileSync(defPath, defContents, 'utf8');
  const machine = process.arch === 'arm64' ? 'ARM64' : 'X64';
  const libResult = spawnSync(
    'lib.exe',
    ['/NOLOGO', `/DEF:${defPath}`, `/OUT:${libPath}`, `/MACHINE:${machine}`],
    { cwd: scratch, env, encoding: 'utf8', maxBuffer: 1024 * 1024 },
  );
  if (libResult.status !== 0 || !existsSync(libPath)) {
    throw new Error(
      `storage-lock-import-lib-failed: ${libResult.stderr || libResult.stdout || libResult.error?.message || libResult.status}`,
    );
  }
  return libPath;
}

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

function compileAddon(cSource, binaryPath, scratch) {
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
    const msvcEnv = resolveWindowsMsvcEnv();
    if (msvcEnv) {
      const nodeLib = resolveWindowsNodeLib(scratch, msvcEnv);
      return spawnSync(
        'cl.exe',
        [
          '/nologo',
          '/O2',
          '/W4',
          '/DNAPI_VERSION=8',
          `/I${headerDirectory}`,
          cSource,
          `/Fo:${join(scratch, 'storage-lock.obj')}`,
          '/LD',
          `/Fe:${binaryPath}`,
          nodeLib,
        ],
        { cwd: scratch, env: msvcEnv, encoding: 'utf8', maxBuffer: 1024 * 1024 },
      );
    }
    if (hasCommand('clang-cl')) {
      const candidateNodeLib = process.env.NODE_LIB || join(dirname(process.execPath), 'node.lib');
      const extraLibs = existsSync(candidateNodeLib) ? [candidateNodeLib] : [];
      return spawnSync(
        'clang-cl',
        [
          '/O2',
          '/W4',
          '/DNAPI_VERSION=8',
          `/I${headerDirectory}`,
          cSource,
          `/Fo:${join(scratch, 'storage-lock.obj')}`,
          '/LD',
          `/Fe:${binaryPath}`,
          ...extraLibs,
        ],
        { cwd: scratch, encoding: 'utf8', maxBuffer: 1024 * 1024 },
      );
    }
    throw new Error('storage-lock-compile-failed: neither MSVC cl.exe nor clang-cl found');
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
if (!outputStat.isDirectory() || outputStat.isSymbolicLink() || !samePath(await realpath(output), output)) {
  throw new Error('unsafe-native-output');
}

const scratch = await mkdtemp(join(output, '.storage-lock-build-'));
try {
  const binary = join(scratch, filename);
  const compile = compileAddon(cSource, binary, scratch);
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

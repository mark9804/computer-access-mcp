import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

function prependPath(env, dir) {
  const next = { ...env };
  const pathKey = Object.keys(next).find((k) => k.toLowerCase() === 'path') || 'PATH';
  const current = next[pathKey] || '';
  next[pathKey] = current ? `${dir};${current}` : dir;
  return next;
}

function resolveCargo() {
  if (process.platform === 'win32') {
    const check = spawnSync('where', ['cargo'], { encoding: 'utf8' });
    if (check.status !== 0) {
      const cargoHome =
        process.env.CARGO_HOME || (process.env.USERPROFILE ? join(process.env.USERPROFILE, '.cargo') : '');
      const candidate = cargoHome ? join(cargoHome, 'bin', 'cargo.exe') : '';
      if (candidate && existsSync(candidate)) {
        return {
          command: candidate,
          env: prependPath(process.env, dirname(candidate)),
        };
      }
    }
  }
  return { command: 'cargo', env: process.env };
}

function runInherit(command, args, env) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', ...(env ? { env } : {}) });
  if (result.error) {
    process.stderr.write(`${command} failed: ${result.error.message}\n`);
    process.exit(1);
  }
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const storageLockBuild = spawnSync(process.execPath, ['scripts/build-storage-lock.mjs'], { stdio: 'inherit' });
if (storageLockBuild.status !== 0) process.exit(storageLockBuild.status ?? 1);

if (process.platform === 'darwin') {
  runInherit('swift', ['test', '--package-path', 'native/macos']);
  runInherit('swift', ['test', '--package-path', 'fixtures/macos/app']);
  const build = spawnSync('swift', ['build', '--package-path', 'native/macos', '--show-bin-path'], { encoding: 'utf8' });
  if (build.status !== 0) { process.stderr.write(build.stderr); process.exit(build.status ?? 1); }
  const helper = join(build.stdout.trim(), 'computer-history-collector');
  const navigation = spawnSync('python3', ['scripts/test-source-navigation-negative.py', '--binary', helper], { stdio: 'inherit' });
  if (navigation.status !== 0) process.exit(navigation.status ?? 1);
  const processes = spawnSync('python3', ['native/macos/Tests/fixture_process.py', helper], { stdio: 'inherit' });
  if (processes.status !== 0) process.exit(processes.status ?? 1);
  const result = spawnSync(process.execPath, ['--test', 'tests/integration/native-p1.test.ts'], { stdio: 'inherit', env: { ...process.env, DSH_TEST_FIXTURE_HELPER: helper } });
  process.exit(result.status ?? 1);
} else if (process.platform === 'win32') {
  const cargo = resolveCargo();
  const workspaceManifest = 'native/windows/Cargo.toml';
  let collectorManifest;

  if (existsSync(join(root, workspaceManifest))) {
    collectorManifest = workspaceManifest;
    runInherit(cargo.command, ['test', '--workspace', '--manifest-path', workspaceManifest], cargo.env);
  } else {
    for (const directory of ['contract', 'key-store', 'collector']) {
      runInherit(cargo.command, ['test', '--manifest-path', `native/windows/${directory}/Cargo.toml`], cargo.env);
    }
    collectorManifest = 'native/windows/collector/Cargo.toml';
  }

  runInherit(
    cargo.command,
    ['build', '--release', '--manifest-path', collectorManifest, '--bin', 'computer-history-collector'],
    cargo.env,
  );

  const meta = spawnSync(
    cargo.command,
    ['metadata', '--no-deps', '--format-version', '1', '--manifest-path', collectorManifest],
    { cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, env: cargo.env },
  );
  if (meta.error) {
    process.stderr.write(`cargo metadata failed: ${meta.error.message}\n`);
    process.exit(1);
  }
  if (meta.status !== 0) {
    process.stderr.write(meta.stderr || meta.stdout || '');
    process.exit(meta.status ?? 1);
  }
  const metadata = JSON.parse(meta.stdout.trim());
  const helper = join(metadata.target_directory, 'release', 'computer-history-collector.exe');
  if (!existsSync(helper)) {
    process.stderr.write(`collector binary not found at: ${helper}\n`);
    process.exit(1);
  }

  const result = spawnSync(process.execPath, ['--test', 'tests/integration/native-p1.test.ts'], {
    cwd: root,
    stdio: 'inherit',
    env: { ...cargo.env, DSH_TEST_FIXTURE_HELPER: helper },
  });
  process.exit(result.status ?? 1);
} else {
  process.stderr.write(`Unsupported platform for native P1 tests: ${process.platform}\n`);
  process.exit(1);
}

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, cp, lstat, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

function run(file, args) {
  const result = spawnSync(file, args, { cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout);
    throw new Error(`build-failed: ${file} ${args.join(' ')} (${result.status})`);
  }
  return result.stdout.trim();
}

run(process.execPath, ['scripts/generate-protocol.mjs', '--check']);
run(process.execPath, ['scripts/sync-client-locales.mjs', '--check']);
run(process.execPath, ['scripts/build-storage-lock.mjs']);

await rm(join(root, 'dist'), { recursive: true, force: true });

run(process.execPath, ['node_modules/typescript/bin/tsc', '-p', 'tsconfig.build.json']);
run(process.execPath, ['node_modules/typescript/bin/tsc', '-p', 'tsconfig.client.json', '--noEmit']);
run(process.execPath, ['scripts/build-client.mjs']);

await cp(join(root, 'src/shared/protocol/wire.schema.json'), join(root, 'dist/shared/protocol/wire.schema.json'));
await cp(join(root, 'src/shared/protocol/schema-source.mjs'), join(root, 'dist/shared/protocol/schema-source.mjs'));
run(process.execPath, ['scripts/prepare-type-exports.mjs']);

if (process.platform !== 'win32') {
  await chmod(join(root, 'dist/server/cli.js'), 0o755);
}

run(process.execPath, ['--check', 'dist/server/cli.js']);
run(process.execPath, ['--check', 'dist/host/service/history-service.js']);
run(process.execPath, ['--check', 'dist/storage/segment-store.js']);

if (process.argv.includes('--native')) {
  if (process.platform !== 'darwin') {
    throw new Error('macos-native-build-required');
  }
  const output = join(root, 'native-bin');
  await mkdir(output, { recursive: true, mode: 0o700 });
  if ((await realpath(output)) !== resolve(output) || !(await lstat(output)).isDirectory()) {
    throw new Error('unsafe-native-output');
  }

  const files = {};
  for (const [directory, name] of [
    ['collector', 'computer-access-collector'],
    ['key-store', 'computer-access-key-store'],
  ]) {
    const packagePath = `native/macos/${directory}`;
    run('swift', ['build', '--package-path', packagePath, '-c', 'release', '--product', name]);
    const binDir = run('swift', ['build', '--package-path', packagePath, '-c', 'release', '--show-bin-path']);
    const bin = join(binDir, name);
    const destination = join(output, name);
    try {
      const existing = await lstat(destination);
      if (!existing.isFile() || existing.isSymbolicLink()) {
        throw new Error('unsafe-native-destination');
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await cp(bin, destination);
    await chmod(destination, 0o755);
    files[name] = { sha256: createHash('sha256').update(await readFile(destination)).digest('hex') };

    if (directory === 'collector') {
      const resourceName = 'AccessContract_AccessContract.bundle';
      const resourceSource = join(binDir, resourceName);
      const resourceDestination = join(output, resourceName);
      try {
        const existing = await lstat(resourceDestination);
        if (!existing.isDirectory() || existing.isSymbolicLink()) {
          throw new Error('unsafe-resource-destination');
        }
        await rm(resourceDestination, { recursive: true, force: false });
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      await cp(resourceSource, resourceDestination, { recursive: true, dereference: false });
      const resource = `${resourceName}/Contents/Resources/wire.schema.json`;
      const resourceFile = join(output, resource);
      await chmod(resourceFile, 0o644);
      files[resource] = { sha256: createHash('sha256').update(await readFile(resourceFile)).digest('hex') };
    }
  }

  const manifestPath = join(output, 'manifest.json');
  try {
    const existing = await lstat(manifestPath);
    if (!existing.isFile() || existing.isSymbolicLink()) {
      throw new Error('unsafe-native-manifest');
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  await writeFile(
    manifestPath,
    JSON.stringify(
      {
        version: 1,
        platform: 'darwin',
        arch: process.arch,
        protocolVersion: 1,
        signing: 'local-development-unverified',
        files,
      },
      null,
      2,
    ) + '\n',
    { mode: 0o600 },
  );
  await chmod(manifestPath, 0o600);
}

run(process.execPath, ['scripts/check-bundle.mjs']);
console.log('Build complete.');

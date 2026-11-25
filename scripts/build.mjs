import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { chmod, cp, lstat, mkdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const isWindows = process.platform === 'win32';

function samePath(a, b) {
  return isWindows
    ? resolve(a).toLowerCase() === resolve(b).toLowerCase()
    : resolve(a) === resolve(b);
}

function prependPath(env, dir) {
  const next = { ...env };
  const pathKey = Object.keys(next).find((k) => k.toLowerCase() === 'path') || 'PATH';
  const current = next[pathKey] || '';
  next[pathKey] = current ? `${dir};${current}` : dir;
  return next;
}

function resolveCargo() {
  if (isWindows) {
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

function run(file, args, env) {
  const result = spawnSync(file, args, {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    ...(env ? { env } : {}),
  });
  if (result.error) {
    throw new Error(`build-failed: ${file} ${args.join(' ')} (${result.error.message})`);
  }
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout || '');
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
  if (process.platform === 'darwin') {
    const output = join(root, 'native-bin');
    await mkdir(output, { recursive: true, mode: 0o700 });
    if ((await realpath(output)) !== resolve(output) || !(await lstat(output)).isDirectory()) {
      throw new Error('unsafe-native-output');
    }

    const files = {};
    for (const [directory, name] of [
      ['collector', 'computer-history-collector'],
      ['key-store', 'computer-history-key-store'],
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
        // SwiftPM produces either a deep macOS bundle (swiftbuild) or a flat bundle (llbuild).
        const candidateResources = [
          `${resourceName}/Contents/Resources/wire.schema.json`,
          `${resourceName}/wire.schema.json`,
        ];
        const existingResources = [];
        for (const candidate of candidateResources) {
          try {
            const stat = await lstat(join(output, candidate));
            if (!stat.isFile() || stat.isSymbolicLink()) {
              throw new Error('unsafe-native-resource');
            }
            existingResources.push(candidate);
          } catch (error) {
            if (error.code !== 'ENOENT') throw error;
          }
        }
        if (existingResources.length !== 1) {
          throw new Error('missing-native-schema-resource');
        }
        const resource = existingResources[0];
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
  } else if (process.platform === 'win32') {
    const output = join(root, 'native-bin');
    await mkdir(output, { recursive: true, mode: 0o700 });
    const outputStat = await lstat(output);
    if (!outputStat.isDirectory() || outputStat.isSymbolicLink() || !samePath(await realpath(output), output)) {
      throw new Error('unsafe-native-output');
    }

    const cargo = resolveCargo();
    const binaries = [
      ['collector', 'computer-history-collector'],
      ['key-store', 'computer-history-key-store'],
    ];
    const workspaceManifest = 'native/windows/Cargo.toml';
    const builtBinaries = [];

    if (existsSync(join(root, workspaceManifest))) {
      run(
        cargo.command,
        [
          'build',
          '--release',
          '--manifest-path',
          workspaceManifest,
          '--bin',
          'computer-history-collector',
          '--bin',
          'computer-history-key-store',
        ],
        cargo.env,
      );
      const metadata = JSON.parse(
        run(cargo.command, ['metadata', '--no-deps', '--format-version', '1', '--manifest-path', workspaceManifest], cargo.env),
      );
      if (!metadata || typeof metadata.target_directory !== 'string' || !metadata.target_directory) {
        throw new Error(`cargo-metadata-missing-target-directory: ${workspaceManifest}`);
      }
      for (const [, name] of binaries) {
        const exeName = `${name}.exe`;
        builtBinaries.push([exeName, join(metadata.target_directory, 'release', exeName)]);
      }
    } else {
      for (const [directory, name] of binaries) {
        const crateManifest = `native/windows/${directory}/Cargo.toml`;
        run(cargo.command, ['build', '--release', '--manifest-path', crateManifest, '--bin', name], cargo.env);
        const metadata = JSON.parse(
          run(cargo.command, ['metadata', '--no-deps', '--format-version', '1', '--manifest-path', crateManifest], cargo.env),
        );
        if (!metadata || typeof metadata.target_directory !== 'string' || !metadata.target_directory) {
          throw new Error(`cargo-metadata-missing-target-directory: ${crateManifest}`);
        }
        const exeName = `${name}.exe`;
        builtBinaries.push([exeName, join(metadata.target_directory, 'release', exeName)]);
      }
    }

    const files = {};
    for (const [exeName, bin] of builtBinaries) {
      const sourceStat = await lstat(bin);
      if (!sourceStat.isFile() || sourceStat.isSymbolicLink()) {
        throw new Error(`unsafe-native-source: ${bin}`);
      }
      const destination = join(output, exeName);
      try {
        const existing = await lstat(destination);
        if (!existing.isFile() || existing.isSymbolicLink()) {
          throw new Error('unsafe-native-destination');
        }
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      await cp(bin, destination);
      files[exeName] = { sha256: createHash('sha256').update(await readFile(destination)).digest('hex') };
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
          platform: 'win32',
          arch: process.arch,
          protocolVersion: 1,
          signing: 'local-development-unverified',
          files,
        },
        null,
        2,
      ) + '\n',
    );
  } else {
    throw new Error(`unsupported-native-build-platform: ${process.platform}`);
  }
}

run(process.execPath, ['scripts/check-bundle.mjs']);
console.log('Build complete.');

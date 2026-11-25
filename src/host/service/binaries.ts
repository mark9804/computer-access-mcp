import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { dirname, isAbsolute, join } from 'node:path';
import { isPosixPlatform } from '../../storage/platform-paths.ts';

const COLLECTOR_SCHEMA_RESOURCES = [
  'HistoryContract_HistoryContract.bundle/Contents/Resources/wire.schema.json',
  'HistoryContract_HistoryContract.bundle/wire.schema.json',
] as const;

export interface BinaryFacts {
  path: string;
  sha256: string;
}

export async function verifyNativeBinary(
  path: string,
  name: 'computer-history-collector' | 'computer-history-key-store',
): Promise<BinaryFacts> {
  if (!isAbsolute(path)) {
    throw new Error('native-path-must-be-absolute');
  }

  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 128 * 1024 * 1024) {
    throw new Error('unsafe-native-file');
  }
  if (isPosixPlatform() && ((metadata.mode & 0o022) !== 0 || (metadata.mode & 0o111) === 0)) {
    throw new Error('unsafe-native-file');
  }

  const dirStat = await lstat(dirname(path));
  if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
    throw new Error('unsafe-native-file');
  }

  const manifestPath = join(dirname(path), 'manifest.json');
  const manifestStat = await lstat(manifestPath);
  if (!manifestStat.isFile() || manifestStat.isSymbolicLink() || manifestStat.size > 16384) {
    throw new Error('unsafe-native-manifest');
  }
  if (isPosixPlatform() && (manifestStat.mode & 0o022) !== 0) {
    throw new Error('unsafe-native-manifest');
  }

  const parsed: unknown = JSON.parse(await readFile(manifestPath, 'utf8'));
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    !('version' in parsed) ||
    parsed.version !== 1 ||
    !('platform' in parsed) ||
    parsed.platform !== process.platform ||
    !('arch' in parsed) ||
    parsed.arch !== process.arch ||
    !('files' in parsed) ||
    !parsed.files ||
    typeof parsed.files !== 'object'
  ) {
    throw new Error('native-manifest-mismatch');
  }

  const files = parsed.files as Record<string, unknown>;
  const record = files[name] ?? (process.platform === 'win32' ? files[`${name}.exe`] : undefined);
  if (
    !record ||
    typeof record !== 'object' ||
    !('sha256' in record) ||
    typeof record.sha256 !== 'string' ||
    !/^[a-f0-9]{64}$/.test(record.sha256)
  ) {
    throw new Error('native-manifest-entry-missing');
  }

  const hash = createHash('sha256').update(await readFile(path)).digest('hex');
  if (record.sha256 !== hash) {
    throw new Error('native-hash-mismatch');
  }

  if (name === 'computer-history-collector' && process.platform === 'darwin') {
    const matchedResources = COLLECTOR_SCHEMA_RESOURCES.filter((candidate) =>
      Object.prototype.hasOwnProperty.call(files, candidate),
    );
    if (matchedResources.length !== 1) {
      throw new Error('native-resource-manifest-missing');
    }
    const resourceName = matchedResources[0]!;
    const resourcePath = join(dirname(path), resourceName);
    const resource = files[resourceName];
    if (
      !resource ||
      typeof resource !== 'object' ||
      !('sha256' in resource) ||
      typeof resource.sha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(resource.sha256)
    ) {
      throw new Error('native-resource-manifest-missing');
    }
    const stat = await lstat(resourcePath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 131072) {
      throw new Error('unsafe-native-resource');
    }
    if (isPosixPlatform() && (stat.mode & 0o022) !== 0) {
      throw new Error('unsafe-native-resource');
    }
    if (createHash('sha256').update(await readFile(resourcePath)).digest('hex') !== resource.sha256) {
      throw new Error('native-resource-mismatch');
    }
  }

  return { path, sha256: hash };
}

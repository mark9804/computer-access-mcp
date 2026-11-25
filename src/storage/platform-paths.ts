import type { BigIntStats, Stats } from 'node:fs';
import { chmod, lstat, mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve, win32, posix } from 'node:path';
import { rejectStorage, StorageError } from './errors.ts';

const APP_DIR_NAME = 'computer-history-mcp';

export function isPosixPlatform(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== 'win32';
}

export function defaultDataRoot(
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
  home: string = homedir(),
): string {
  if (platform === 'darwin') {
    return posix.join(home, 'Library', 'Application Support', APP_DIR_NAME);
  }
  if (platform === 'win32') {
    const localAppData = env.LOCALAPPDATA?.trim();
    if (localAppData && win32.isAbsolute(localAppData)) {
      return win32.join(localAppData, APP_DIR_NAME);
    }
    return win32.join(home, 'AppData', 'Local', APP_DIR_NAME);
  }
  const xdgDataHome = env.XDG_DATA_HOME?.trim();
  if (xdgDataHome && posix.isAbsolute(xdgDataHome)) {
    return posix.join(xdgDataHome, APP_DIR_NAME);
  }
  return posix.join(home, '.local', 'share', APP_DIR_NAME);
}

export interface PrepareDirectoryOptions {
  platform?: NodeJS.Platform;
  enforceAutoChmod?: boolean;
}

function validatePathString(dir: string): string {
  if (
    typeof dir !== 'string' ||
    dir.length === 0 ||
    dir.length > 4096 ||
    !dir.isWellFormed() ||
    /[\u0000-\u001f\u007f]/.test(dir) ||
    !isAbsolute(dir)
  ) {
    rejectStorage('unsafe-path');
  }
  const normalized = resolve(dir);
  if (normalized === dirname(normalized)) {
    rejectStorage('unsafe-path');
  }
  return normalized;
}

async function verifyNoSymlinkChain(targetDir: string): Promise<void> {
  // Check targetDir and any non-system ancestor components created within the user/temp tree.
  // Stop before root-level OS firmlinks such as /var -> private/var on macOS.
  const chain: string[] = [];
  let current = targetDir;
  while (true) {
    const parent = dirname(current);
    if (parent === current || parent === '/' || /^[A-Za-z]:\\?$/.test(parent)) {
      break;
    }
    chain.push(current);
    current = parent;
  }

  for (const candidate of chain) {
    try {
      const stat = await lstat(candidate);
      if (stat.isSymbolicLink()) {
        rejectStorage('unsafe-path');
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        continue;
      }
      throw error;
    }
  }
}

export function assertSafeDirectoryStat(
  stat: Stats | BigIntStats,
  platform: NodeJS.Platform = process.platform,
): void {
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    rejectStorage('unsafe-path');
  }
  if (!isPosixPlatform(platform)) {
    return;
  }
  const mode = Number(stat.mode) & 0o777;
  if (process.getuid !== undefined && Number(stat.uid) !== process.getuid()) {
    rejectStorage('unsafe-permissions');
  }
  if ((mode & 0o077) !== 0) {
    rejectStorage('unsafe-permissions');
  }
}

export function assertSafeFileStat(
  stat: Stats | BigIntStats,
  platform: NodeJS.Platform = process.platform,
): void {
  if (stat.isSymbolicLink() || !stat.isFile()) {
    rejectStorage('unsafe-path');
  }
  if (!isPosixPlatform(platform)) {
    return;
  }
  if (Number(stat.nlink) > 1) {
    rejectStorage('unsafe-path');
  }
  if (process.getuid !== undefined && Number(stat.uid) !== process.getuid()) {
    rejectStorage('unsafe-permissions');
  }
  const mode = Number(stat.mode) & 0o777;
  if ((mode & 0o077) !== 0) {
    rejectStorage('unsafe-permissions');
  }
}

export async function prepareDataDirectory(
  dir: string,
  options: PrepareDirectoryOptions = {},
): Promise<string> {
  const platform = options.platform ?? process.platform;
  const normalized = validatePathString(dir);

  try {
    await verifyNoSymlinkChain(normalized);

    let created = false;
    try {
      await lstat(normalized);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw error;
      }
      await mkdir(normalized, { recursive: true, mode: 0o700 });
      created = true;
    }

    const stat = await lstat(normalized);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      rejectStorage('unsafe-path');
    }

    if (isPosixPlatform(platform)) {
      if (created && (stat.mode & 0o077) !== 0) {
        await chmod(normalized, 0o700);
      }
      const verified = created ? await lstat(normalized) : stat;
      assertSafeDirectoryStat(verified, platform);
    }

    return normalized;
  } catch (error) {
    if (error instanceof StorageError) throw error;
    rejectStorage('io-failure');
  }
}

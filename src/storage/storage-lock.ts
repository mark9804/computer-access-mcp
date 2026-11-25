import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, open, readFile } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { rejectStorage, StorageError, toStorageError } from './errors.ts';
import { assertSafeFileStat, isPosixPlatform } from './platform-paths.ts';

export interface NativeStorageLock {
  tryLock(fd: number): boolean;
  unlock(fd: number): void;
}

export interface StorageLock {
  readonly lockFilePath: string;
  release(): Promise<void>;
}

const ADDON_FILENAME = 'computer-history-storage-lock.node';
const DEFAULT_ADDON_PATH = fileURLToPath(new URL(`../../native-bin/${ADDON_FILENAME}`, import.meta.url));
const requireAddon = createRequire(import.meta.url);

let cachedAddonPromise: Promise<NativeStorageLock> | undefined;

async function verifyAndLoadAddon(addonPath: string): Promise<NativeStorageLock> {
  try {
    const addonStat = await lstat(addonPath);
    if (addonStat.isSymbolicLink() || !addonStat.isFile() || addonStat.size === 0 || addonStat.size > 4 * 1024 * 1024) {
      rejectStorage('native-lock-unavailable');
    }

    const manifestPath = join(dirname(addonPath), 'storage-lock.manifest.json');
    const manifestStat = await lstat(manifestPath);
    if (manifestStat.isSymbolicLink() || !manifestStat.isFile() || manifestStat.size > 16384) {
      rejectStorage('native-lock-unavailable');
    }

    const manifestRaw: unknown = JSON.parse(await readFile(manifestPath, 'utf8'));
    if (!manifestRaw || typeof manifestRaw !== 'object') {
      rejectStorage('native-lock-unavailable');
    }
    const manifest = manifestRaw as Record<string, unknown>;
    if (
      manifest.version !== 1 ||
      manifest.platform !== process.platform ||
      manifest.arch !== process.arch ||
      manifest.filename !== ADDON_FILENAME ||
      typeof manifest.sha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(manifest.sha256)
    ) {
      rejectStorage('native-lock-unavailable');
    }

    const addonBytes = await readFile(addonPath);
    const actualHash = createHash('sha256').update(addonBytes).digest('hex');
    if (actualHash !== manifest.sha256) {
      rejectStorage('native-lock-unavailable');
    }

    const rawLoaded: unknown = requireAddon(addonPath);
    if (
      !rawLoaded ||
      typeof rawLoaded !== 'object' ||
      !('tryLock' in rawLoaded) ||
      typeof rawLoaded.tryLock !== 'function' ||
      !('unlock' in rawLoaded) ||
      typeof rawLoaded.unlock !== 'function'
    ) {
      rejectStorage('native-lock-unavailable');
    }

    const nativeTryLock = rawLoaded.tryLock as (fd: number) => unknown;
    const nativeUnlock = rawLoaded.unlock as (fd: number) => unknown;

    return Object.freeze({
      tryLock(fd: number): boolean {
        if (!Number.isInteger(fd) || fd < 0 || fd > 0x7fffffff) {
          rejectStorage('native-lock-unavailable');
        }
        let ok: unknown;
        try {
          ok = nativeTryLock(fd);
        } catch {
          rejectStorage('native-lock-unavailable');
        }
        if (typeof ok !== 'boolean') {
          rejectStorage('native-lock-unavailable');
        }
        return ok;
      },
      unlock(fd: number): void {
        if (!Number.isInteger(fd) || fd < 0 || fd > 0x7fffffff) {
          rejectStorage('native-lock-unavailable');
        }
        try {
          nativeUnlock(fd);
        } catch {
          rejectStorage('native-lock-unavailable');
        }
      },
    });
  } catch (error) {
    if (error instanceof StorageError) throw error;
    rejectStorage('native-lock-unavailable');
  }
}

export function loadNativeStorageLock(): Promise<NativeStorageLock> {
  return (cachedAddonPromise ??= verifyAndLoadAddon(DEFAULT_ADDON_PATH));
}

export async function acquireStorageLock(
  lockFilePath: string,
  options: { platform?: NodeJS.Platform; nativeLock?: NativeStorageLock } = {},
): Promise<StorageLock> {
  const platform = options.platform ?? process.platform;
  if (typeof lockFilePath !== 'string' || !isAbsolute(lockFilePath)) {
    rejectStorage('unsafe-path');
  }

  const native = options.nativeLock ?? (await loadNativeStorageLock());
  let handle: FileHandle | undefined;

  try {
    try {
      const existing = await lstat(lockFilePath);
      assertSafeFileStat(existing, platform);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw error;
      }
    }

    const flags = constants.O_CREAT | constants.O_RDWR | (constants.O_NOFOLLOW ?? 0);
    handle = await open(lockFilePath, flags, 0o600);

    let openedStat = await handle.stat();
    if (isPosixPlatform(platform) && (openedStat.mode & 0o077) !== 0) {
      await chmod(lockFilePath, 0o600);
      openedStat = await handle.stat();
    }
    assertSafeFileStat(openedStat, platform);

    const postPathStat = await lstat(lockFilePath);
    assertSafeFileStat(postPathStat, platform);
    if (isPosixPlatform(platform) && (postPathStat.dev !== openedStat.dev || postPathStat.ino !== openedStat.ino)) {
      rejectStorage('unsafe-path');
    }

    if (!native.tryLock(handle.fd)) {
      rejectStorage('already-owned');
    }

    const lockedHandle = handle;
    let released = false;

    return {
      lockFilePath,
      async release(): Promise<void> {
        if (released) return;
        released = true;
        let unlockErr: unknown;
        try {
          native.unlock(lockedHandle.fd);
        } catch (err) {
          unlockErr = err;
        } finally {
          await lockedHandle.close();
        }
        if (unlockErr) {
          throw toStorageError(unlockErr);
        }
      },
    };
  } catch (error) {
    if (handle) {
      await handle.close().catch(() => {});
    }
    if (error instanceof StorageError) throw error;
    throw toStorageError(error);
  }
}

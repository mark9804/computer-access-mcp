import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { AuthStore, AuthValidationError } from '../../src/server/auth-store.ts';

async function withTempDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), 'camcp-auth-test-'));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('AuthStore generates persistent 32-byte admin token with 0600 permissions and constant-time check', async () => {
  await withTempDir(async (dir) => {
    const store1 = await AuthStore.open({ dataDir: dir });
    const adminToken = store1.getAdminToken();
    assert.match(adminToken, /^[0-9a-f]{64}$/);
    assert.equal(store1.verifyAdminToken(adminToken), true);
    assert.equal(store1.verifyAdminToken(''), false);
    assert.equal(store1.verifyAdminToken(adminToken.slice(0, -1) + (adminToken.endsWith('0') ? '1' : '0')), false);
    assert.equal(store1.verifyAdminToken('short'), false);

    if (process.platform !== 'win32') {
      const adminStat = await stat(join(dir, 'admin.token'));
      assert.equal(adminStat.mode & 0o777, 0o600);
      const leasesStat = await stat(join(dir, 'auth-leases.json'));
      assert.equal(leasesStat.mode & 0o777, 0o600);
    }
    await store1.close();

    const store2 = await AuthStore.open({ dataDir: dir });
    assert.equal(store2.getAdminToken(), adminToken);
    assert.equal(store2.verifyAdminToken(adminToken), true);

    const rotated = await store2.rotateAdminToken();
    assert.match(rotated, /^[0-9a-f]{64}$/);
    assert.notEqual(rotated, adminToken);
    assert.equal(store2.verifyAdminToken(adminToken), false);
    assert.equal(store2.verifyAdminToken(rotated), true);
    await store2.close();
  });
});

test('AuthStore stores only SHA-256 hashes on disk and enforces lease scopes, expiry, and revocation', async () => {
  await withTempDir(async (dir) => {
    let nowMs = 1_700_000_000_000;
    const store = await AuthStore.open({
      dataDir: dir,
      now: () => nowMs,
      lastUsedFlushDelayMs: 5000,
    });

    const created = await store.createLease({
      label: 'antigravity-ide',
      scopes: ['read'],
      ttlMs: 60_000,
    });

    assert.match(created.token, /^camcp_[0-9a-f]{64}$/);
    assert.equal(created.lease.label, 'antigravity-ide');
    assert.deepEqual(created.lease.scopes, ['read']);
    assert.equal(created.lease.createdAtMs, 1_700_000_000_000);
    assert.equal(created.lease.expiresAtMs, 1_700_000_060_000);
    assert.equal(created.lease.revokedAtMs, null);
    assert.equal(created.lease.lastUsedAtMs, null);
    assert.equal('tokenSha256' in created.lease, false);

    // Disk must never contain the plaintext camcp_ token.
    const rawDisk = await readFile(join(dir, 'auth-leases.json'), 'utf8');
    assert.equal(rawDisk.includes(created.token), false);
    const expectedSha = createHash('sha256').update(created.token, 'utf8').digest('hex');
    assert.equal(rawDisk.includes(expectedSha), true);

    // Scope enforcement and lastUsedAtMs tracking.
    nowMs += 5_000;
    const verifiedRead = store.verifyClientToken(created.token, 'read');
    assert.ok(verifiedRead);
    assert.equal(verifiedRead.lastUsedAtMs, 1_700_000_005_000);
    assert.equal(store.verifyClientToken(created.token, 'pause'), null);
    assert.equal(store.verifyClientToken(created.token, 'reload'), null);

    // Advance past expiresAtMs -> rejected immediately.
    nowMs = 1_700_000_060_000;
    assert.equal(store.verifyClientToken(created.token, 'read'), null);

    // Non-expiring read+pause lease + revocation (still never grants reload).
    const endless = await store.createLease({
      label: 'claude-desktop',
      scopes: ['pause', 'read'],
      ttlMs: null,
    });
    assert.deepEqual(endless.lease.scopes, ['read', 'pause']);
    assert.ok(store.verifyClientToken(endless.token, 'read'));
    assert.ok(store.verifyClientToken(endless.token, 'pause'));
    assert.equal(store.verifyClientToken(endless.token, 'reload'), null);

    // Opt-in reload scope persists cleanly across reload and enforces scope isolation.
    const reloadLease = await store.createLease({
      label: 'dev-reloader',
      scopes: ['reload', 'read'],
      ttlMs: null,
    });
    assert.deepEqual(reloadLease.lease.scopes, ['read', 'reload']);
    assert.ok(store.verifyClientToken(reloadLease.token, 'read'));
    assert.ok(store.verifyClientToken(reloadLease.token, 'reload'));
    assert.equal(store.verifyClientToken(reloadLease.token, 'pause'), null);

    nowMs += 1_000;
    const revoked = await store.revokeLease(endless.lease.id);
    assert.ok(revoked);
    assert.equal(revoked.revokedAtMs, nowMs);
    assert.equal(store.verifyClientToken(endless.token), null);
    assert.equal(store.verifyClientToken(endless.token, 'read'), null);

    await store.close();

    // Reload from disk verifies revoked state, reload scope, and lastUsedAtMs persisted cleanly.
    const reloaded = await AuthStore.open({ dataDir: dir, now: () => nowMs });
    assert.equal(reloaded.verifyClientToken(endless.token), null);
    assert.ok(reloaded.verifyClientToken(reloadLease.token, 'reload'));
    const listed = reloaded.listLeases();
    assert.equal(listed.length, 3);
    assert.equal(listed.find((l) => l.id === created.lease.id)?.lastUsedAtMs, 1_700_000_005_000);
    assert.deepEqual(listed.find((l) => l.id === reloadLease.lease.id)?.scopes, ['read', 'reload']);
    await reloaded.close();
  });
});

test('AuthStore rejects invalid lease inputs and symlinked auth files', async () => {
  await withTempDir(async (dir) => {
    const store = await AuthStore.open({ dataDir: dir });

    await assert.rejects(
      () => store.createLease({ label: '   ', scopes: ['read'], ttlMs: null }),
      (err: unknown) => err instanceof AuthValidationError && err.code === 'invalid-lease-label',
    );
    await assert.rejects(
      () => store.createLease({ label: 'bad-scope', scopes: ['admin' as 'read'], ttlMs: null }),
      (err: unknown) => err instanceof AuthValidationError && err.code === 'invalid-lease-scopes',
    );
    await assert.rejects(
      () => store.createLease({ label: 'empty-scope', scopes: [], ttlMs: null }),
      (err: unknown) => err instanceof AuthValidationError && err.code === 'invalid-lease-scopes',
    );
    await assert.rejects(
      () => store.createLease({ label: 'bad-ttl', scopes: ['read'], ttlMs: -10 }),
      (err: unknown) => err instanceof AuthValidationError && err.code === 'invalid-lease-ttl',
    );

    await store.close();

    // Replace admin.token with a symlink -> AuthStore.open must refuse.
    const outsideTarget = join(dir, 'outside-secret.txt');
    await writeFile(outsideTarget, 'a'.repeat(64), 'utf8');
    await rm(join(dir, 'admin.token'));
    let createdFileSymlink = true;
    try {
      await symlink(outsideTarget, join(dir, 'admin.token'));
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (process.platform === 'win32' && (code === 'EPERM' || code === 'EACCES')) {
        createdFileSymlink = false;
      } else {
        throw err;
      }
    }

    if (createdFileSymlink) {
      await assert.rejects(() => AuthStore.open({ dataDir: dir }), /unsafe-auth-file/);
    }
  });
});

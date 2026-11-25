import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmod, lstat, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import type {
  ClientLease,
  ClientScope,
  CreateLeaseRequest,
  CreateLeaseResponse,
  StoredClientLease,
} from '../shared/api-types.ts';

const ADMIN_TOKEN_FILENAME = 'admin.token';
const LEASES_FILENAME = 'auth-leases.json';
const VALID_SCOPES: readonly ClientScope[] = ['read', 'pause', 'reload'];
const VALID_SCOPE_SET = new Set<string>(VALID_SCOPES);
const CLIENT_TOKEN_PREFIX = 'chmcp_';
// Also accept legacy camcp_ leases migrated from pre-rename auth-leases.json stores.
const ACCEPTED_CLIENT_TOKEN_PREFIXES = [CLIENT_TOKEN_PREFIX, 'camcp_'] as const;
const LAST_USED_FLUSH_DELAY_MS = 1000;

interface LeasesDiskPayload {
  version: 1;
  leases: StoredClientLease[];
}

export class AuthValidationError extends Error {
  readonly code: string;

  constructor(code: string, message?: string) {
    super(message ?? code);
    this.name = 'AuthValidationError';
    this.code = code;
  }
}

export interface AuthStoreOptions {
  dataDir: string;
  now?: () => number;
  lastUsedFlushDelayMs?: number;
}

function sha256Buffer(input: string): Buffer {
  return createHash('sha256').update(input, 'utf8').digest();
}

function sha256Hex(input: string): string {
  return sha256Buffer(input).toString('hex');
}

function toPublicLease(stored: StoredClientLease): ClientLease {
  return {
    id: stored.id,
    label: stored.label,
    scopes: [...stored.scopes],
    createdAtMs: stored.createdAtMs,
    expiresAtMs: stored.expiresAtMs,
    revokedAtMs: stored.revokedAtMs,
    lastUsedAtMs: stored.lastUsedAtMs,
  };
}

function isLeaseActive(lease: StoredClientLease, nowMs: number): boolean {
  return (
    lease.scopes.length > 0 &&
    lease.revokedAtMs === null &&
    (lease.expiresAtMs === null || nowMs < lease.expiresAtMs)
  );
}

function normalizeScopes(raw: unknown): ClientScope[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new AuthValidationError('invalid-lease-scopes', 'At least one valid client scope is required.');
  }
  const requested = new Set<ClientScope>();
  for (const item of raw) {
    if (typeof item !== 'string' || !VALID_SCOPE_SET.has(item)) {
      throw new AuthValidationError('invalid-lease-scopes', `Unsupported client scope: ${String(item)}`);
    }
    requested.add(item as ClientScope);
  }
  return VALID_SCOPES.filter((scope) => requested.has(scope));
}

function normalizeLabel(raw: unknown): string {
  if (typeof raw !== 'string') {
    throw new AuthValidationError('invalid-lease-label', 'Lease label must be a non-empty string.');
  }
  const trimmed = raw.trim();
  if (trimmed.length < 1 || trimmed.length > 128) {
    throw new AuthValidationError('invalid-lease-label', 'Lease label must be between 1 and 128 characters.');
  }
  return trimmed;
}

function normalizeTtlMs(raw: unknown): number | null {
  if (raw === null || raw === undefined) {
    return null;
  }
  if (typeof raw !== 'number' || !Number.isFinite(raw) || raw <= 0 || raw > 3650 * 24 * 60 * 60 * 1000) {
    throw new AuthValidationError('invalid-lease-ttl', 'ttlMs must be null or a positive duration in milliseconds.');
  }
  return Math.floor(raw);
}

function isValidStoredLease(item: unknown): item is StoredClientLease {
  if (item === null || typeof item !== 'object' || Array.isArray(item)) return false;
  const rec = item as Record<string, unknown>;
  if (typeof rec.id !== 'string' || rec.id.length < 1 || rec.id.length > 128) return false;
  if (typeof rec.label !== 'string' || rec.label.length < 1 || rec.label.length > 128) return false;
  if (typeof rec.tokenSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(rec.tokenSha256)) return false;
  if (
    !Array.isArray(rec.scopes) ||
    rec.scopes.some((s) => typeof s !== 'string' || !VALID_SCOPE_SET.has(s))
  ) {
    return false;
  }
  if (typeof rec.createdAtMs !== 'number' || !Number.isFinite(rec.createdAtMs)) return false;
  if (rec.expiresAtMs !== null && (typeof rec.expiresAtMs !== 'number' || !Number.isFinite(rec.expiresAtMs))) {
    return false;
  }
  if (rec.revokedAtMs !== null && (typeof rec.revokedAtMs !== 'number' || !Number.isFinite(rec.revokedAtMs))) {
    return false;
  }
  if (rec.lastUsedAtMs !== null && (typeof rec.lastUsedAtMs !== 'number' || !Number.isFinite(rec.lastUsedAtMs))) {
    return false;
  }
  return true;
}

async function ensurePrivateDirectory(dir: string): Promise<void> {
  try {
    const info = await lstat(dir);
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new Error('unsafe-auth-directory');
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw err;
    }
    await mkdir(dir, { recursive: true, mode: 0o700 });
  }
  if (process.platform !== 'win32') {
    await chmod(dir, 0o700);
  }
}

async function assertSafeExistingFile(filePath: string): Promise<boolean> {
  try {
    const info = await lstat(filePath);
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new Error('unsafe-auth-file');
    }
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return false;
    }
    throw err;
  }
}

let tempCounter = 0;

async function writePrivateFileAtomic(targetPath: string, content: string): Promise<void> {
  await assertSafeExistingFile(targetPath);
  tempCounter += 1;
  const tmpPath = `${targetPath}.tmp.${process.pid}.${tempCounter}.${randomBytes(4).toString('hex')}`;
  try {
    await writeFile(tmpPath, content, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    if (process.platform !== 'win32') {
      await chmod(tmpPath, 0o600);
    }
    await rename(tmpPath, targetPath);
    if (process.platform !== 'win32') {
      await chmod(targetPath, 0o600);
    }
  } catch (err) {
    await rm(tmpPath, { force: true }).catch(() => {});
    throw err;
  }
}

// Two-tier local credential store: persistent Admin Token + SHA-256 hashed MCP Client Leases.
export class AuthStore {
  readonly dataDir: string;
  private readonly adminTokenPath: string;
  private readonly leasesPath: string;
  private readonly now: () => number;
  private readonly flushDelayMs: number;

  private adminToken = '';
  private adminTokenDigest: Buffer = Buffer.alloc(32);
  private readonly leases = new Map<string, StoredClientLease>();
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private dirtyLastUsed = false;
  private writeChain: Promise<void> = Promise.resolve();
  private initialized = false;

  constructor(options: AuthStoreOptions) {
    this.dataDir = resolve(options.dataDir);
    this.adminTokenPath = join(this.dataDir, ADMIN_TOKEN_FILENAME);
    this.leasesPath = join(this.dataDir, LEASES_FILENAME);
    this.now = options.now ?? (() => Date.now());
    this.flushDelayMs = options.lastUsedFlushDelayMs ?? LAST_USED_FLUSH_DELAY_MS;
  }

  static async open(options: AuthStoreOptions): Promise<AuthStore> {
    const store = new AuthStore(options);
    await store.init();
    return store;
  }

  async init(): Promise<void> {
    if (this.initialized) return;
    await ensurePrivateDirectory(this.dataDir);
    await this.loadOrCreateAdminToken();
    await this.loadLeases();
    this.initialized = true;
  }

  getAdminToken(): string {
    this.assertInitialized();
    return this.adminToken;
  }

  verifyAdminToken(candidate: string): boolean {
    this.assertInitialized();
    if (typeof candidate !== 'string' || candidate.length === 0 || candidate.length > 512) {
      return false;
    }
    const candidateDigest = sha256Buffer(candidate);
    return timingSafeEqual(candidateDigest, this.adminTokenDigest) && candidate.length === this.adminToken.length;
  }

  async rotateAdminToken(): Promise<string> {
    this.assertInitialized();
    const nextToken = randomBytes(32).toString('hex');
    await this.enqueueWrite(async () => {
      await writePrivateFileAtomic(this.adminTokenPath, `${nextToken}\n`);
      this.setAdminTokenInMemory(nextToken);
    });
    return nextToken;
  }

  listLeases(): ClientLease[] {
    this.assertInitialized();
    return Array.from(this.leases.values(), toPublicLease);
  }

  async createLease(request: CreateLeaseRequest): Promise<CreateLeaseResponse> {
    this.assertInitialized();
    if (request === null || typeof request !== 'object' || Array.isArray(request)) {
      throw new AuthValidationError('invalid-lease-request', 'Lease request must be a JSON object.');
    }
    const label = normalizeLabel(request.label);
    const scopes = normalizeScopes(request.scopes);
    const ttlMs = normalizeTtlMs(request.ttlMs);

    const createdAtMs = this.now();
    const id = `lease_${randomBytes(8).toString('hex')}`;
    const token = `${CLIENT_TOKEN_PREFIX}${randomBytes(32).toString('hex')}`;
    const stored: StoredClientLease = {
      id,
      label,
      tokenSha256: sha256Hex(token),
      scopes,
      createdAtMs,
      expiresAtMs: ttlMs === null ? null : createdAtMs + ttlMs,
      revokedAtMs: null,
      lastUsedAtMs: null,
    };

    this.leases.set(id, stored);
    await this.persistLeasesNow();

    return {
      lease: toPublicLease(stored),
      token,
    };
  }

  async revokeLease(id: string): Promise<ClientLease | null> {
    this.assertInitialized();
    if (typeof id !== 'string' || id.length === 0) {
      return null;
    }
    const stored = this.leases.get(id);
    if (!stored) {
      return null;
    }
    if (stored.revokedAtMs === null) {
      stored.revokedAtMs = this.now();
      await this.persistLeasesNow();
    }
    return toPublicLease(stored);
  }

  verifyClientToken(bearerToken: string, requiredScope?: ClientScope): ClientLease | null {
    this.assertInitialized();
    if (typeof bearerToken !== 'string' || bearerToken.length > 256) {
      return null;
    }
    const matchedPrefix = ACCEPTED_CLIENT_TOKEN_PREFIXES.find((prefix) => bearerToken.startsWith(prefix));
    if (!matchedPrefix || bearerToken.length <= matchedPrefix.length) {
      return null;
    }

    const candidateDigest = sha256Buffer(bearerToken);
    const nowMs = this.now();
    let matched: StoredClientLease | undefined;

    for (const lease of this.leases.values()) {
      const storedDigest = Buffer.from(lease.tokenSha256, 'hex');
      if (storedDigest.byteLength === candidateDigest.byteLength && timingSafeEqual(storedDigest, candidateDigest)) {
        matched = lease;
      }
    }

    if (!matched || !isLeaseActive(matched, nowMs)) {
      return null;
    }
    if (requiredScope !== undefined && !matched.scopes.includes(requiredScope)) {
      return null;
    }

    matched.lastUsedAtMs = nowMs;
    this.scheduleLastUsedFlush();
    return toPublicLease(matched);
  }

  async flush(): Promise<void> {
    if (!this.initialized) return;
    if (this.flushTimer !== null) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    if (this.dirtyLastUsed) {
      await this.persistLeasesNow();
    } else {
      await this.writeChain;
    }
  }

  async close(): Promise<void> {
    await this.flush();
  }

  private assertInitialized(): void {
    if (!this.initialized) {
      throw new Error('auth-store-not-initialized');
    }
  }

  private setAdminTokenInMemory(token: string): void {
    this.adminToken = token;
    this.adminTokenDigest = sha256Buffer(token);
  }

  private async loadOrCreateAdminToken(): Promise<void> {
    const exists = await assertSafeExistingFile(this.adminTokenPath);
    if (exists) {
      const raw = (await readFile(this.adminTokenPath, 'utf8')).trim();
      if (raw.length >= 32 && raw.length <= 256 && /^[\x21-\x7e]+$/.test(raw)) {
        if (process.platform !== 'win32') {
          await chmod(this.adminTokenPath, 0o600);
        }
        this.setAdminTokenInMemory(raw);
        return;
      }
      throw new Error('invalid-admin-token-file');
    }

    const generated = randomBytes(32).toString('hex');
    await writePrivateFileAtomic(this.adminTokenPath, `${generated}\n`);
    this.setAdminTokenInMemory(generated);
  }

  private async loadLeases(): Promise<void> {
    const exists = await assertSafeExistingFile(this.leasesPath);
    if (!exists) {
      await writePrivateFileAtomic(this.leasesPath, `${JSON.stringify({ version: 1, leases: [] }, null, 2)}\n`);
      return;
    }

    if (process.platform !== 'win32') {
      await chmod(this.leasesPath, 0o600);
    }

    const raw = await readFile(this.leasesPath, 'utf8');
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error('invalid-auth-leases-file');
    }

    if (
      parsed === null ||
      typeof parsed !== 'object' ||
      Array.isArray(parsed) ||
      (parsed as Record<string, unknown>).version !== 1 ||
      !Array.isArray((parsed as Record<string, unknown>).leases)
    ) {
      throw new Error('invalid-auth-leases-file');
    }

    this.leases.clear();
    for (const item of (parsed as LeasesDiskPayload).leases) {
      if (!isValidStoredLease(item)) {
        throw new Error('invalid-auth-leases-entry');
      }
      this.leases.set(item.id, {
        ...item,
        scopes: [...item.scopes],
      });
    }
  }

  private scheduleLastUsedFlush(): void {
    this.dirtyLastUsed = true;
    if (this.flushTimer !== null) {
      return;
    }
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      if (this.dirtyLastUsed) {
        void this.persistLeasesNow().catch(() => {});
      }
    }, this.flushDelayMs);
    this.flushTimer.unref();
  }

  private persistLeasesNow(): Promise<void> {
    if (this.flushTimer !== null) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    return this.enqueueWrite(async () => {
      this.dirtyLastUsed = false;
      const payload: LeasesDiskPayload = {
        version: 1,
        leases: Array.from(this.leases.values()),
      };
      await writePrivateFileAtomic(this.leasesPath, `${JSON.stringify(payload, null, 2)}\n`);
    });
  }

  private enqueueWrite(task: () => Promise<void>): Promise<void> {
    const next = this.writeChain.then(task);
    this.writeChain = next.catch(() => {});
    return next;
  }
}

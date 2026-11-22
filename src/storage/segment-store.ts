import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, open, readdir, readFile, rename, truncate, unlink } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { join } from 'node:path';
import { HISTORY_QUERY_KINDS } from '../shared/api-types.ts';
import type {
  HistoryForgetRequest,
  HistoryForgetResult,
  HistoryQuery,
  HistoryQueryKind,
  HistoryQueryResult,
  HistoryTextDelta,
  StorageRecordCounts,
  StorageStatusSummary,
} from '../shared/api-types.ts';
import { classifyGap } from '../shared/gap-classification.ts';
import type {
  HistoryLayoutPosition,
  HistoryLayoutRequest,
  HistoryLayoutResult,
  NormalizedHistoryLayoutRequest,
} from '../shared/history-layout.ts';
import { LIMITS } from '../shared/protocol/generated.ts';
import type {
  ApplicationTargetIdentity,
  Coverage,
  Observation,
  TextSnapshot,
} from '../shared/protocol/generated.ts';
import { validateMessage } from '../shared/protocol/validate.ts';
import { canRelateEvidence, evidenceMetadata } from '../host/collectors/evidence-correlator.ts';
import {
  createHistoryLayoutUnavailable,
  HistoryLayoutError,
  normalizeHistoryLayoutRequest,
  projectHistoryLayout,
} from '../host/service/history-layout.ts';
import { KeyProviderError, rejectStorage, StorageError, toStorageError } from './errors.ts';
import type { StorageErrorCode } from './errors.ts';
import type { KeyProvider } from './key-provider.ts';
import { assertSafeFileStat, isPosixPlatform, prepareDataDirectory } from './platform-paths.ts';
import { acquireStorageLock } from './storage-lock.ts';
import type { NativeStorageLock, StorageLock } from './storage-lock.ts';
import {
  applySingleSpanPatch,
  computeSingleSpanPatch,
  shouldStoreTextPatch,
} from './text-delta.ts';
import type { TextSpanPatch } from './text-delta.ts';

export { StorageError, HistoryStoreError } from './errors.ts';
export type { StorageErrorCode, HistoryStoreErrorCode } from './errors.ts';

export const SEGMENT_MAX_BYTES = 4 * 1024 * 1024;
export const HISTORY_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
export const HISTORY_MAX_BYTES = 128 * 1024 * 1024;
export const SEGMENT_HEADER_BYTES = 32;

const META_MAGIC = Buffer.from('CAHM\x01', 'binary');
const META_AAD = Buffer.from('computer-access-mcp:store.meta:v1', 'utf8');
const SEGMENT_MAGIC = Buffer.from('CAHS\x01', 'binary');
const LOCK_FILENAME = 'store.lock';
const META_FILENAME = 'store.meta';
const SEGMENT_NAME_RE = /^seg-([0-9]{8,16})\.cah$/;

const GCM_NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;
const MIN_FRAME_BODY_BYTES = GCM_NONCE_BYTES + 2 + GCM_TAG_BYTES;
const MAX_FRAME_BODY_BYTES = LIMITS.maxFrameBytes + 4096;

const MAX_CURSORS = 256;
const CURSOR_TTL_MS = 5 * 60 * 1000;
const CURSOR_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const CURSOR_PLACEHOLDER = '0'.repeat(43);
const MAX_PENDING = 64;
const MAX_PENDING_BYTES = 4 * 1024 * 1024;
const MAX_QUERY_BYTES = 256 * 1024;

const VALID_QUERY_KINDS = new Set<HistoryQueryKind>(HISTORY_QUERY_KINDS);

const FATAL_CODES: ReadonlySet<StorageErrorCode> = new Set([
  'invalid-store',
  'authentication-failed',
  'unsafe-path',
  'unsafe-permissions',
  'io-failure',
]);

interface StoreMeta {
  version: 1;
  storeId: string;
  createdAtMs: number;
  forgetBeforeMs: number;
  generation: number;
}

interface StoredFullFramePayload {
  version: 1;
  inputHash: string;
  receivedAtMs: number;
  record: Observation;
  materializedBase?: string;
}

type StoredTextDeltaRecord = Omit<Observation, 'payload'> & {
  payload: Omit<TextSnapshot, 'text'>;
};

interface StoredTextDeltaFramePayload {
  version: 2;
  encoding: 'text-patch-v1';
  inputHash: string;
  receivedAtMs: number;
  baseEventId: string;
  patch: TextSpanPatch;
  record: StoredTextDeltaRecord;
  materializedBase?: string;
}

interface TextDeltaBaseline {
  readonly eventId: string;
  readonly text: string;
  readonly chainDepth: number;
}

interface MemoryEntry {
  readonly segmentSeq: number;
  readonly order: number;
  readonly inputHash: string;
  readonly receivedAtMs: number;
  readonly record: Observation;
  readonly textDelta?: HistoryTextDelta;
}

interface SegmentInfo {
  readonly seq: number;
  readonly filename: string;
  readonly filePath: string;
  readonly createdAtMs: number;
  bytes: number;
  frameCount: number;
  liveRecords: number;
  handle: FileHandle | null;
}

interface QueryCursor {
  readonly fingerprint: string;
  readonly generation: number;
  readonly highWater: number;
  readonly order: 'asc' | 'desc';
  readonly afterTimeMs: number;
  readonly afterOrder: number;
  readonly expiresAtMs: number;
}

interface LayoutCursor {
  readonly fingerprint: string;
  readonly generation: number;
  readonly entryOrder: number;
  readonly position: HistoryLayoutPosition;
  readonly expiresAtMs: number;
}

export interface SegmentStoreOptions {
  root: string;
  keyProvider: KeyProvider;
  retentionMs?: number;
  maxBytes?: number;
  maxSegmentBytes?: number;
  clock?: () => number;
  platform?: NodeJS.Platform;
  nativeLock?: NativeStorageLock;
}

export interface SegmentAppendOptions {
  generation?: number;
  isCurrent?: () => boolean;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const obj = value as Record<string, unknown>;
  return (
    '{' +
    Object.keys(obj)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k]))
      .join(',') +
    '}'
  );
}

function sha256Hex(input: Uint8Array | string): string {
  return createHash('sha256').update(input).digest('hex');
}

function isSafeInt(value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
}

function formatSegmentFilename(seq: number): string {
  return `seg-${String(seq).padStart(8, '0')}.cah`;
}

function encodeSegmentHeader(segmentSeq: number, createdAtMs: number): Buffer {
  const header = Buffer.alloc(SEGMENT_HEADER_BYTES, 0);
  SEGMENT_MAGIC.copy(header, 0);
  // Bytes 5..7 are flags 0x00, 0x00, 0x00; bytes 24..31 are reserved 0x00.
  header.writeBigUInt64BE(BigInt(segmentSeq), 8);
  header.writeBigUInt64BE(BigInt(createdAtMs), 16);
  return header;
}

function parseSegmentHeader(buf: Buffer, expectedSeq: number): { createdAtMs: number } {
  if (buf.length < SEGMENT_HEADER_BYTES) rejectStorage('invalid-store');
  if (!buf.subarray(0, 5).equals(SEGMENT_MAGIC)) rejectStorage('invalid-store');
  if (buf[5] !== 0 || buf[6] !== 0 || buf[7] !== 0) rejectStorage('invalid-store');
  for (let i = 24; i < 32; i++) {
    if (buf[i] !== 0) rejectStorage('invalid-store');
  }
  const seq = buf.readBigUInt64BE(8);
  const createdAt = buf.readBigUInt64BE(16);
  if (seq !== BigInt(expectedSeq) || createdAt > BigInt(Number.MAX_SAFE_INTEGER)) {
    rejectStorage('invalid-store');
  }
  return { createdAtMs: Number(createdAt) };
}

function frameAad(storeId: string, segmentSeq: number, frameIndex: number): Buffer {
  return Buffer.from(`${storeId}:${segmentSeq}:${frameIndex}`, 'utf8');
}

function encryptFrame(plain: Uint8Array, key: Buffer, storeId: string, segmentSeq: number, frameIndex: number): Buffer {
  const nonce = randomBytes(GCM_NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(frameAad(storeId, segmentSeq, frameIndex));
  const c1 = cipher.update(plain);
  const c2 = cipher.final();
  const tag = cipher.getAuthTag();
  const bodyLen = GCM_NONCE_BYTES + c1.length + c2.length + GCM_TAG_BYTES;
  const lenHeader = Buffer.allocUnsafe(4);
  lenHeader.writeUInt32BE(bodyLen, 0);
  return Buffer.concat([lenHeader, nonce, c1, c2, tag], 4 + bodyLen);
}

function decryptFrameBody(
  body: Uint8Array,
  key: Buffer,
  storeId: string,
  segmentSeq: number,
  frameIndex: number,
): Buffer | null {
  if (body.byteLength < MIN_FRAME_BODY_BYTES) return null;
  try {
    const buf = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
    const nonce = buf.subarray(0, GCM_NONCE_BYTES);
    const ciphertext = buf.subarray(GCM_NONCE_BYTES, buf.length - GCM_TAG_BYTES);
    const tag = buf.subarray(buf.length - GCM_TAG_BYTES);
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(frameAad(storeId, segmentSeq, frameIndex));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    return null;
  }
}

function encryptMeta(meta: StoreMeta, key: Buffer): Buffer {
  const plain = Buffer.from(canonicalJson(meta), 'utf8');
  const nonce = randomBytes(GCM_NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(META_AAD);
  const sealed = Buffer.concat([META_MAGIC, nonce, cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  plain.fill(0);
  return sealed;
}

function decryptMeta(bytes: Buffer, key: Buffer): StoreMeta {
  const minBytes = META_MAGIC.length + GCM_NONCE_BYTES + 2 + GCM_TAG_BYTES;
  if (bytes.length < minBytes || !bytes.subarray(0, META_MAGIC.length).equals(META_MAGIC)) {
    rejectStorage('invalid-store');
  }
  let plain: Buffer;
  try {
    const nonceStart = META_MAGIC.length;
    const nonce = bytes.subarray(nonceStart, nonceStart + GCM_NONCE_BYTES);
    const ciphertext = bytes.subarray(nonceStart + GCM_NONCE_BYTES, bytes.length - GCM_TAG_BYTES);
    const tag = bytes.subarray(bytes.length - GCM_TAG_BYTES);
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(META_AAD);
    decipher.setAuthTag(tag);
    plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    rejectStorage('authentication-failed');
  }

  try {
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      rejectStorage('invalid-store');
    }
    const obj = parsed as Record<string, unknown>;
    if (
      obj.version !== 1 ||
      typeof obj.storeId !== 'string' ||
      obj.storeId.length < 8 ||
      obj.storeId.length > 128 ||
      !isSafeInt(obj.createdAtMs) ||
      !isSafeInt(obj.forgetBeforeMs) ||
      !isSafeInt(obj.generation ?? 0)
    ) {
      rejectStorage('invalid-store');
    }
    return {
      version: 1,
      storeId: obj.storeId,
      createdAtMs: obj.createdAtMs,
      forgetBeforeMs: obj.forgetBeforeMs,
      generation: typeof obj.generation === 'number' ? obj.generation : 0,
    };
  } catch (error) {
    if (error instanceof StorageError) throw error;
    rejectStorage('invalid-store');
  } finally {
    plain.fill(0);
  }
}

async function writeFullAt(handle: FileHandle, data: Buffer, position: number): Promise<void> {
  let written = 0;
  while (written < data.length) {
    const res = await handle.write(data, written, data.length - written, position + written);
    if (res.bytesWritten <= 0) rejectStorage('io-failure');
    written += res.bytesWritten;
  }
}

function extractTextSnapshot(record: Observation): TextSnapshot | undefined {
  if (record.payload.kind === 'text.snapshot') return record.payload;
  if (record.payload.kind === 'text.changed') return record.payload.after;
  return undefined;
}

function extractSnapshotId(record: Observation): string | undefined {
  const payload = record.payload;
  if (payload.kind === 'text.snapshot') return payload.snapshotId;
  if (payload.kind === 'text.changed') return payload.after.snapshotId;
  if (payload.kind === 'surface.snapshot') return payload.snapshotId;
  if (payload.kind === 'selection.snapshot') return payload.snapshotId;
  return undefined;
}

function extractCoverage(record: Observation): Coverage | undefined {
  const payload = record.payload.kind === 'text.changed' ? record.payload.after : record.payload;
  return 'coverage' in payload ? payload.coverage : undefined;
}

function matchesSearchText(record: Observation, needle: string): boolean {
  const payload = record.payload.kind === 'text.changed' ? record.payload.after : record.payload;
  if (payload.kind === 'surface.snapshot') {
    return payload.nodes.some((n) => n.text?.includes(needle) === true);
  }
  if (payload.kind === 'menu.action') {
    return payload.path.join(' > ').includes(needle);
  }
  if (
    payload.kind === 'text.snapshot' ||
    payload.kind === 'selection.snapshot' ||
    payload.kind === 'input.text'
  ) {
    return payload.text?.includes(needle) === true;
  }
  return false;
}

function matchesKind(record: Observation, kind: HistoryQueryKind): boolean {
  if (kind === 'all') return true;
  const payload = record.payload;
  switch (kind) {
    case 'text':
      return payload.kind === 'text.snapshot' || payload.kind === 'text.changed';
    case 'surface':
      return payload.kind === 'surface.snapshot';
    case 'selection':
      return payload.kind === 'selection.snapshot';
    case 'input':
      return payload.kind === 'input.text';
    case 'activity':
      return payload.kind === 'input.activity';
    case 'menu':
      return payload.kind === 'menu.action';
    case 'context':
      return payload.kind === 'context.changed';
    case 'gap':
      return payload.kind === 'gap';
    case 'exception':
      return payload.kind === 'gap' && classifyGap(payload) === 'exception';
    case 'discarded':
      return payload.kind === 'gap' && classifyGap(payload) === 'discarded';
  }
}

function textDeltaTargetKey(record: Observation, snap: TextSnapshot): string | null {
  if (record.target.kind !== 'resolved') return null;
  const id = record.target.identity;
  return canonicalJson([
    id.deviceId,
    id.applicationId,
    id.processId,
    id.processStartTime,
    id.windowId,
    id.windowGeneration,
    snap.nodeId,
    snap.scope,
    snap.rangeBasis ?? 'prefix',
  ]);
}

function omitTextFromObservation(record: Observation): StoredTextDeltaRecord {
  if (record.payload.kind !== 'text.snapshot') {
    rejectStorage('invalid-input');
  }
  const { text: _omitted, ...payloadWithoutText } = record.payload;
  return {
    ...record,
    payload: payloadWithoutText,
  };
}

function parseStoredTextPatch(raw: unknown): TextSpanPatch {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    rejectStorage('invalid-store');
  }
  const obj = raw as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (
    keys.length !== 3 ||
    !isSafeInt(obj.start) ||
    !isSafeInt(obj.deleteCount) ||
    typeof obj.insert !== 'string' ||
    !obj.insert.isWellFormed()
  ) {
    rejectStorage('invalid-store');
  }
  return {
    start: obj.start,
    deleteCount: obj.deleteCount,
    insert: obj.insert,
  };
}

function validateObservationInput(input: unknown): Observation {
  try {
    const validated = validateMessage(input);
    if (validated.type !== 'observation') rejectStorage('invalid-input');
    if (validated.eventId !== `${validated.instanceId}:${validated.seq}`) rejectStorage('invalid-input');
    if (Buffer.byteLength(canonicalJson(validated), 'utf8') + 1 > LIMITS.maxFrameBytes) {
      rejectStorage('budget-exceeded');
    }
    return validated;
  } catch (error) {
    if (error instanceof StorageError) throw error;
    rejectStorage('invalid-input');
  }
}

function buildQueryResult(
  records: Observation[],
  recordJsonBytes: number,
  truncated: boolean,
  nextCursor?: string,
  textDeltas?: Record<string, HistoryTextDelta>,
): HistoryQueryResult {
  const hasDeltas = textDeltas !== undefined && Object.keys(textDeltas).length > 0;
  const result: HistoryQueryResult = {
    records: [],
    truncated,
    bytes: 0,
    hasMore: nextCursor !== undefined,
    ...(nextCursor !== undefined ? { nextCursor } : {}),
    ...(hasDeltas ? { textDeltas } : {}),
  };
  let computed = Buffer.byteLength(JSON.stringify(result), 'utf8') + recordJsonBytes;
  while (computed !== result.bytes) {
    result.bytes = computed;
    computed = Buffer.byteLength(JSON.stringify(result), 'utf8') + recordJsonBytes;
  }
  result.records = records;
  return result;
}

export class SegmentStore {
  readonly #root: string;
  readonly #lock: StorageLock;
  readonly #key: Buffer;
  readonly #retentionMs: number;
  readonly #maxBytes: number;
  readonly #maxSegmentBytes: number;
  readonly #clock: () => number;
  readonly #platform: NodeJS.Platform;
  readonly #cursorKey = randomBytes(32);

  #meta: StoreMeta = {
    version: 1,
    storeId: '',
    createdAtMs: 0,
    forgetBeforeMs: 0,
    generation: 0,
  };
  #metaBytes = 0;
  #generation = 0;
  #nextOrder = 0;
  #nextSegmentSeq = 1;

  #segments: SegmentInfo[] = [];
  #activeSegment: SegmentInfo | null = null;
  #activeSegmentBaselineSeq = 0;
  #activeSegmentBaselines = new Map<string, TextDeltaBaseline>();

  #entries: MemoryEntry[] = [];
  #byId = new Map<string, MemoryEntry>();
  #byTextSnapshot = new Map<string, MemoryEntry>();
  #bySnapshotId = new Map<string, MemoryEntry[]>();
  #lastSeq = new Map<string, number>();

  #cursors = new Map<string, QueryCursor | null>();
  #layoutCursors = new Map<string, LayoutCursor | null>();

  #state: 'open' | 'closed' | 'failed' = 'open';
  #closing = false;
  #tail: Promise<void> = Promise.resolve();
  #pending = 0;
  #pendingBytes = 0;

  private constructor(
    root: string,
    lock: StorageLock,
    key: Buffer,
    options: {
      retentionMs: number;
      maxBytes: number;
      maxSegmentBytes: number;
      clock: () => number;
      platform: NodeJS.Platform;
    },
  ) {
    this.#root = root;
    this.#lock = lock;
    this.#key = key;
    this.#retentionMs = options.retentionMs;
    this.#maxBytes = options.maxBytes;
    this.#maxSegmentBytes = options.maxSegmentBytes;
    this.#clock = options.clock;
    this.#platform = options.platform;
  }

  static async open(options: SegmentStoreOptions): Promise<SegmentStore> {
    const retentionMs = options.retentionMs ?? HISTORY_RETENTION_MS;
    const maxBytes = options.maxBytes ?? HISTORY_MAX_BYTES;
    const maxSegmentBytes = options.maxSegmentBytes ?? SEGMENT_MAX_BYTES;
    const platform = options.platform ?? process.platform;
    const clock = options.clock ?? Date.now;

    if (
      typeof options.root !== 'string' ||
      !isSafeInt(retentionMs, 1) ||
      !isSafeInt(maxBytes, 1024, HISTORY_MAX_BYTES * 8) ||
      !isSafeInt(maxSegmentBytes, 512, HISTORY_MAX_BYTES * 8) ||
      typeof clock !== 'function'
    ) {
      rejectStorage('invalid-input');
    }

    let key: Buffer;
    try {
      const supplied = await options.keyProvider.readKey();
      if (!(supplied instanceof Uint8Array) || supplied.byteLength !== 32) {
        rejectStorage('key-unavailable');
      }
      key = Buffer.from(supplied);
    } catch (error) {
      if (error instanceof KeyProviderError || error instanceof StorageError) {
        throw error;
      }
      rejectStorage('key-unavailable');
    }

    let lock: StorageLock | undefined;
    let store: SegmentStore | undefined;
    try {
      const preparedRoot = await prepareDataDirectory(options.root, { platform });
      lock = await acquireStorageLock(join(preparedRoot, LOCK_FILENAME), {
        platform,
        ...(options.nativeLock ? { nativeLock: options.nativeLock } : {}),
      });
      store = new SegmentStore(preparedRoot, lock, key, {
        retentionMs,
        maxBytes,
        maxSegmentBytes,
        clock,
        platform,
      });
      await store.#load();
      await store.#evictExpired(store.#now());
      await store.#evictOverBudget(0);
      return store;
    } catch (error) {
      key.fill(0);
      if (store) {
        await store.#closeActiveSegment().catch(() => {});
        store.#clearMemory();
        store.#cursorKey.fill(0);
      }
      await lock?.release().catch(() => {});
      if (error instanceof StorageError || error instanceof KeyProviderError) throw error;
      throw toStorageError(error);
    }
  }

  get generation(): number {
    return this.#generation;
  }

  get storeId(): string {
    return this.#meta.storeId;
  }

  get root(): string {
    return this.#root;
  }

  isOpenForRead(): boolean {
    return this.#state === 'open' && !this.#closing;
  }

  status(): StorageStatusSummary {
    const counts: StorageRecordCounts = {
      text: 0,
      surface: 0,
      selection: 0,
      inputText: 0,
      activity: 0,
      menu: 0,
      context: 0,
      gap: 0,
      gapDiscarded: 0,
      gapException: 0,
    };
    let fromTimeMs = Infinity;
    let toTimeMs = -Infinity;

    for (const entry of this.#entries) {
      const t = entry.record.eventTimeMs;
      if (t < fromTimeMs) fromTimeMs = t;
      if (t > toTimeMs) toTimeMs = t;
      switch (entry.record.payload.kind) {
        case 'text.snapshot':
        case 'text.changed':
          counts.text++;
          break;
        case 'surface.snapshot':
          counts.surface++;
          break;
        case 'selection.snapshot':
          counts.selection++;
          break;
        case 'input.text':
          counts.inputText++;
          break;
        case 'input.activity':
          counts.activity++;
          break;
        case 'menu.action':
          counts.menu++;
          break;
        case 'context.changed':
          counts.context++;
          break;
        case 'gap':
          counts.gap++;
          if (classifyGap(entry.record.payload) === 'exception') {
            counts.gapException++;
          } else {
            counts.gapDiscarded++;
          }
          break;
      }
    }

    return {
      state: this.#state,
      storeId: this.#meta.storeId,
      generation: this.#generation,
      segments: this.#segments.length,
      records: this.#entries.length,
      bytes: this.#totalDiskBytes(),
      retentionMs: this.#retentionMs,
      maxBytes: this.#maxBytes,
      forgetBeforeMs: this.#meta.forgetBeforeMs,
      retainedTimeRange: this.#entries.length > 0 ? { fromTimeMs, toTimeMs } : null,
      counts,
    };
  }

  append(input: Observation, options: SegmentAppendOptions = {}): Promise<void> {
    let validated: Observation;
    let inputHash: string;
    let encodedSize: number;
    let fence: { generation: number; isCurrent?: () => boolean };

    try {
      const expectedGen = options.generation ?? this.#generation;
      if (options.isCurrent !== undefined && typeof options.isCurrent !== 'function') {
        rejectStorage('invalid-input');
      }
      fence = {
        generation: expectedGen,
        ...(options.isCurrent ? { isCurrent: options.isCurrent } : {}),
      };
      this.#gate(fence);
      const checked = validateObservationInput(input);
      const encoded = canonicalJson(checked);
      encodedSize = Buffer.byteLength(encoded, 'utf8');
      inputHash = sha256Hex(encoded);
      validated = JSON.parse(encoded) as Observation;
    } catch (error) {
      return Promise.reject(toStorageError(error));
    }

    return this.#enqueue(async () => {
      this.#gate(fence);
      await this.#verifyDirectory();
      const now = this.#now();
      await this.#evictExpired(now);
      this.#gate(fence);

      if (
        validated.eventTimeMs < this.#meta.forgetBeforeMs ||
        validated.eventTimeMs <= now - this.#retentionMs
      ) {
        rejectStorage('stale-generation');
      }

      const existingById = this.#byId.get(validated.eventId);
      if (existingById) {
        if (existingById.inputHash !== inputHash) {
          rejectStorage('duplicate-conflict');
        }
        return;
      }

      if ((this.#lastSeq.get(validated.instanceId) ?? -1) >= validated.seq) {
        rejectStorage('out-of-order');
      }

      const textSnap = extractTextSnapshot(validated);
      if (textSnap && this.#byTextSnapshot.has(textSnap.snapshotId)) {
        rejectStorage('duplicate-conflict');
      }

      this.#admitRelation(validated);

      let materializedBase: string | undefined;
      let storedRecord: Observation = validated;

      if (validated.payload.kind === 'text.changed') {
        const baseId = validated.payload.baseSnapshotId;
        const baseEntry = this.#byTextSnapshot.get(baseId);
        const baseRecord = baseEntry?.record;
        const baseSnap = baseRecord ? extractTextSnapshot(baseRecord) : undefined;
        const after = validated.payload.after;

        if (
          !baseRecord ||
          !baseSnap ||
          baseSnap.valueState !== 'read' ||
          after.valueState !== 'read' ||
          baseSnap.coverage.status !== 'complete' ||
          after.coverage.status !== 'complete' ||
          canonicalJson(baseRecord.target) !== canonicalJson(validated.target) ||
          canonicalJson(baseRecord.stamp) !== canonicalJson(validated.stamp) ||
          baseRecord.instanceId !== validated.instanceId ||
          baseSnap.nodeId !== after.nodeId ||
          baseSnap.editSessionId !== after.editSessionId ||
          baseSnap.source !== after.source ||
          baseSnap.scope !== after.scope
        ) {
          rejectStorage('baseline-unavailable');
        }
        materializedBase = baseId;
        storedRecord = { ...validated, payload: after };
      }

      const buildFullPayload = (): StoredFullFramePayload => ({
        version: 1,
        inputHash,
        receivedAtMs: now,
        record: storedRecord,
        ...(materializedBase !== undefined ? { materializedBase } : {}),
      });

      const textSnapForDelta =
        storedRecord.payload.kind === 'text.snapshot' &&
        storedRecord.payload.valueState === 'read' &&
        typeof storedRecord.payload.text === 'string'
          ? storedRecord.payload
          : undefined;
      const deltaTargetKey =
        textSnapForDelta !== undefined ? textDeltaTargetKey(storedRecord, textSnapForDelta) : null;

      let deltaCandidate:
        | {
            segmentSeq: number;
            payload: StoredTextDeltaFramePayload;
            textDelta: HistoryTextDelta;
            nextChainDepth: number;
          }
        | undefined;

      if (textSnapForDelta && deltaTargetKey !== null && textSnapForDelta.text !== undefined) {
        const tail = this.#activeSegment ?? this.#segments[this.#segments.length - 1];
        if (tail && tail.bytes < this.#maxSegmentBytes && this.#activeSegmentBaselineSeq === tail.seq) {
          const baseline = this.#activeSegmentBaselines.get(deltaTargetKey);
          const baseEntry = baseline ? this.#byId.get(baseline.eventId) : undefined;
          if (baseline && baseEntry && baseEntry.segmentSeq === tail.seq) {
            const patch = computeSingleSpanPatch(baseline.text, textSnapForDelta.text);
            if (shouldStoreTextPatch(textSnapForDelta.text, patch, baseline.chainDepth)) {
              deltaCandidate = {
                segmentSeq: tail.seq,
                payload: {
                  version: 2,
                  encoding: 'text-patch-v1',
                  inputHash,
                  receivedAtMs: now,
                  baseEventId: baseline.eventId,
                  patch,
                  record: omitTextFromObservation(storedRecord),
                  ...(materializedBase !== undefined ? { materializedBase } : {}),
                },
                textDelta: {
                  baseEventId: baseline.eventId,
                  start: patch.start,
                  deleteCount: patch.deleteCount,
                  insert: patch.insert,
                  totalLength: textSnapForDelta.text.length,
                },
                nextChainDepth: baseline.chainDepth + 1,
              };
            }
          }
        }
      }

      let plainBytes = Buffer.from(
        canonicalJson(deltaCandidate ? deltaCandidate.payload : buildFullPayload()),
        'utf8',
      );

      try {
        const frameBodyLen = GCM_NONCE_BYTES + plainBytes.length + GCM_TAG_BYTES;
        const totalFrameBytes = 4 + frameBodyLen;

        if (
          frameBodyLen > MAX_FRAME_BODY_BYTES ||
          this.#metaBytes + SEGMENT_HEADER_BYTES + totalFrameBytes > this.#maxBytes
        ) {
          rejectStorage('budget-exceeded');
        }

        await this.#evictOverBudget(totalFrameBytes);
        this.#gate(fence);

        let active = await this.#ensureActiveSegment(now);

        // Hard invariant: delta frames must live in the exact same segment as baseEventId.
        // If budget eviction or segment rollover switched segments, fall back to a full v1 keyframe.
        if (
          deltaCandidate &&
          (active.seq !== deltaCandidate.segmentSeq ||
            this.#byId.get(deltaCandidate.payload.baseEventId)?.segmentSeq !== active.seq)
        ) {
          plainBytes.fill(0);
          deltaCandidate = undefined;
          plainBytes = Buffer.from(canonicalJson(buildFullPayload()), 'utf8');
          const fullBodyLen = GCM_NONCE_BYTES + plainBytes.length + GCM_TAG_BYTES;
          const fullTotalBytes = 4 + fullBodyLen;
          if (
            fullBodyLen > MAX_FRAME_BODY_BYTES ||
            this.#metaBytes + SEGMENT_HEADER_BYTES + fullTotalBytes > this.#maxBytes
          ) {
            rejectStorage('budget-exceeded');
          }
          await this.#evictOverBudget(fullTotalBytes);
          this.#gate(fence);
          active = await this.#ensureActiveSegment(now);
        }

        const frameIndex = active.frameCount;
        const encryptedFrame = encryptFrame(plainBytes, this.#key, this.#meta.storeId, active.seq, frameIndex);

        if (!active.handle) rejectStorage('io-failure');
        await writeFullAt(active.handle, encryptedFrame, active.bytes);

        active.bytes += encryptedFrame.length;
        active.frameCount += 1;
        active.liveRecords += 1;

        const memEntry: MemoryEntry = {
          segmentSeq: active.seq,
          order: this.#nextOrder++,
          inputHash,
          receivedAtMs: now,
          record: storedRecord,
          ...(deltaCandidate ? { textDelta: deltaCandidate.textDelta } : {}),
        };
        this.#entries.push(memEntry);
        this.#indexEntry(memEntry);

        if (textSnapForDelta && deltaTargetKey !== null && textSnapForDelta.text !== undefined) {
          if (this.#activeSegmentBaselineSeq !== active.seq) {
            this.#activeSegmentBaselineSeq = active.seq;
            this.#activeSegmentBaselines.clear();
          }
          this.#activeSegmentBaselines.set(deltaTargetKey, {
            eventId: storedRecord.eventId,
            text: textSnapForDelta.text,
            chainDepth: deltaCandidate ? deltaCandidate.nextChainDepth : 0,
          });
        }

        if (active.bytes >= this.#maxSegmentBytes) {
          await this.#rollActiveSegment(now);
        }
      } finally {
        plainBytes.fill(0);
      }
    }, encodedSize);
  }

  search(query: HistoryQuery = {}, cursorScope?: string): Promise<HistoryQueryResult> {
    let normalized: HistoryQuery;
    let fingerprint: string;

    try {
      normalized = this.#validateSearchQuery(query);
      fingerprint = this.#computeSearchFingerprint(normalized, cursorScope);
      if (normalized.cursor !== undefined) {
        this.#verifySearchCursor(normalized.cursor, fingerprint);
      }
    } catch (error) {
      return Promise.reject(toStorageError(error));
    }

    const generation = this.#generation;
    return this.#enqueue(async () => {
      await this.#verifyDirectory();
      const now = this.#now();
      await this.#evictExpired(now);

      const cursor =
        normalized.cursor === undefined
          ? undefined
          : this.#verifySearchCursor(normalized.cursor, fingerprint);
      if (generation !== this.#generation || this.#closing) {
        rejectStorage(cursor ? 'cursor-expired' : 'stale-generation');
      }

      const highWater = cursor?.highWater ?? this.#nextOrder;
      const order = cursor?.order ?? normalized.order ?? 'asc';

      const inScope = (entry: MemoryEntry): boolean => {
        const rec = entry.record;
        return (
          entry.order < highWater &&
          (normalized.fromTimeMs === undefined || rec.eventTimeMs >= normalized.fromTimeMs) &&
          (normalized.toTimeMs === undefined || rec.eventTimeMs <= normalized.toTimeMs) &&
          (normalized.applicationId === undefined ||
            (rec.target.kind !== 'unresolved' &&
              rec.target.identity.applicationId === normalized.applicationId))
        );
      };

      const matches = (entry: MemoryEntry): boolean =>
        inScope(entry) &&
        (normalized.kind === undefined || matchesKind(entry.record, normalized.kind)) &&
        (normalized.text === undefined || matchesSearchText(entry.record, normalized.text));

      const matched: MemoryEntry[] = [];
      for (const entry of this.#entries) {
        if (!matches(entry)) continue;
        if (cursor) {
          const cmp = entry.record.eventTimeMs - cursor.afterTimeMs || entry.order - cursor.afterOrder;
          if (order === 'asc' ? cmp <= 0 : cmp >= 0) continue;
        }
        matched.push(entry);
      }

      matched.sort(
        (a, b) =>
          (order === 'asc' ? 1 : -1) *
          (a.record.eventTimeMs - b.record.eventTimeMs || a.order - b.order),
      );

      const limit = normalized.limit ?? 100;
      const byteBudget = normalized.maxBytes ?? 64 * 1024;
      const textView = normalized.textView ?? 'full';
      const pageRecords: Observation[] = [];
      const pageTextDeltas: Record<string, HistoryTextDelta> = {};
      let recordJsonBytes = 0;
      let truncated = false;

      for (const entry of matched) {
        if (pageRecords.length >= limit) break;
        const projected = this.#projectRecord(entry.record, matches);
        let entryDelta: HistoryTextDelta | undefined;
        if (
          textView === 'delta' &&
          entry.textDelta !== undefined &&
          this.#byId.has(entry.textDelta.baseEventId) &&
          projected.payload.kind === 'text.snapshot'
        ) {
          delete projected.payload.text;
          entryDelta = { ...entry.textDelta };
        }
        const cov = extractCoverage(projected);
        const more = pageRecords.length + 1 < matched.length;
        const candidateJsonBytes =
          recordJsonBytes + Buffer.byteLength(JSON.stringify(projected), 'utf8') + (pageRecords.length > 0 ? 1 : 0);
        const candidateTruncated: boolean = truncated || cov?.truncated === true;
        const candidateDeltas =
          entryDelta !== undefined
            ? { ...pageTextDeltas, [entry.record.eventId]: entryDelta }
            : pageTextDeltas;
        const candidatePage = buildQueryResult(
          [],
          candidateJsonBytes,
          candidateTruncated || more,
          more ? CURSOR_PLACEHOLDER : undefined,
          candidateDeltas,
        );
        if (candidatePage.bytes > byteBudget) break;

        pageRecords.push(projected);
        if (entryDelta !== undefined) {
          pageTextDeltas[entry.record.eventId] = entryDelta;
        }
        recordJsonBytes = candidateJsonBytes;
        truncated = candidateTruncated;
      }

      const hasRemaining = pageRecords.length < matched.length;
      if (hasRemaining) {
        truncated = true;
      }
      const canContinue = hasRemaining && pageRecords.length > 0;
      const result = buildQueryResult(
        pageRecords,
        recordJsonBytes,
        truncated,
        canContinue ? CURSOR_PLACEHOLDER : undefined,
        pageTextDeltas,
      );
      if (result.bytes > byteBudget) {
        rejectStorage('budget-exceeded');
      }

      if (canContinue) {
        const last = matched[pageRecords.length - 1]!;
        result.nextCursor = this.#mintSearchCursor(
          {
            fingerprint,
            generation,
            highWater,
            order,
            afterTimeMs: last.record.eventTimeMs,
            afterOrder: last.order,
            expiresAtMs: cursor?.expiresAtMs ?? now + CURSOR_TTL_MS,
          },
          now,
        );
      }
      return result;
    });
  }

  // Alias for callers using query()
  query(query: HistoryQuery = {}, cursorScope?: string): Promise<HistoryQueryResult> {
    return this.search(query, cursorScope);
  }

  read(id: string): Promise<Observation | null> {
    if (typeof id !== 'string' || id.length === 0 || id.length > 256 || !id.isWellFormed()) {
      return Promise.reject(new StorageError('invalid-input'));
    }
    const generation = this.#generation;
    return this.#enqueue(async () => {
      await this.#verifyDirectory();
      await this.#evictExpired(this.#now());
      if (generation !== this.#generation) {
        rejectStorage('stale-generation');
      }

      const byEvent = this.#byId.get(id);
      if (byEvent) {
        return this.#projectRecord(byEvent.record);
      }

      const bySnap = this.#bySnapshotId.get(id);
      if (!bySnap || bySnap.length === 0) {
        return null;
      }
      if (bySnap.length > 1) {
        rejectStorage('snapshot-ambiguous');
      }
      return this.#projectRecord(bySnap[0]!.record);
    });
  }

  latestApplicationTarget(applicationId: string): Promise<ApplicationTargetIdentity | null> {
    if (typeof applicationId !== 'string' || applicationId.length === 0 || applicationId.length > 256) {
      return Promise.reject(new StorageError('invalid-input'));
    }
    return this.#enqueue(async () => {
      await this.#verifyDirectory();
      await this.#evictExpired(this.#now());
      for (let i = this.#entries.length - 1; i >= 0; i--) {
        const rec = this.#entries[i]!.record;
        if (rec.target.kind !== 'unresolved' && rec.target.identity.applicationId === applicationId) {
          return structuredClone(rec.target.identity);
        }
      }
      return null;
    });
  }

  layout(input: HistoryLayoutRequest, cursorScope?: string): Promise<HistoryLayoutResult> {
    let options: NormalizedHistoryLayoutRequest;
    let fingerprint: string;

    try {
      options = normalizeHistoryLayoutRequest(input);
      const { cursor: _cursor, ...filters } = options;
      fingerprint = createHmac('sha256', this.#cursorKey)
        .update(canonicalJson(['layout', cursorScope ?? null, filters]))
        .digest('hex');
      if (options.cursor !== undefined) {
        this.#verifyLayoutCursor(options.cursor, fingerprint);
      }
    } catch (error) {
      if (error instanceof HistoryLayoutError) {
        const mapped: StorageErrorCode =
          error.code === 'invalid-layout-record' || error.code === 'invalid-layout-result'
            ? 'invalid-store'
            : error.code;
        return Promise.reject(new StorageError(mapped));
      }
      return Promise.reject(toStorageError(error));
    }

    const generation = this.#generation;
    return this.#enqueue(async () => {
      await this.#verifyDirectory();
      const now = this.#now();
      await this.#evictExpired(now);

      const cursor =
        options.cursor === undefined ? undefined : this.#verifyLayoutCursor(options.cursor, fingerprint);
      if (generation !== this.#generation || this.#closing) {
        rejectStorage(cursor ? 'cursor-expired' : 'stale-generation');
      }

      const matchesApp = (candidate: MemoryEntry): boolean =>
        options.applicationId === undefined ||
        (candidate.record.target.kind !== 'unresolved' &&
          candidate.record.target.identity.applicationId === options.applicationId);

      let entry: MemoryEntry | undefined;
      if (options.eventId !== undefined) {
        const found = this.#byId.get(options.eventId);
        if (found && matchesApp(found)) entry = found;
      } else if (options.snapshotId !== undefined) {
        const candidates = (this.#bySnapshotId.get(options.snapshotId) ?? []).filter(
          (c) => c.record.payload.kind === 'surface.snapshot' && matchesApp(c),
        );
        if (candidates.length > 1) rejectStorage('snapshot-ambiguous');
        entry = candidates[0];
      }

      if (!entry) {
        if (cursor) rejectStorage('cursor-expired');
        return createHistoryLayoutUnavailable('not-found-or-forgotten');
      }
      if (cursor && cursor.entryOrder !== entry.order) {
        rejectStorage('cursor-expired');
      }
      if (entry.record.payload.kind !== 'surface.snapshot') {
        return createHistoryLayoutUnavailable('not-a-surface-snapshot');
      }

      try {
        const { page, nextPosition } = projectHistoryLayout(entry.record, options, cursor?.position, {
          maxBytes: 60_000,
        });
        if (nextPosition) {
          page.nextCursor = this.#mintLayoutCursor(
            {
              fingerprint,
              generation,
              entryOrder: entry.order,
              position: nextPosition,
              expiresAtMs: cursor?.expiresAtMs ?? now + CURSOR_TTL_MS,
            },
            now,
          );
        } else {
          delete page.nextCursor;
        }
        return page;
      } catch (error) {
        if (error instanceof HistoryLayoutError) {
          const mapped: StorageErrorCode =
            error.code === 'invalid-layout-record' || error.code === 'invalid-layout-result'
              ? 'invalid-store'
              : error.code;
          throw new StorageError(mapped);
        }
        throw error;
      }
    });
  }

  forget(request: HistoryForgetRequest): Promise<HistoryForgetResult> {
    try {
      if (!request || typeof request !== 'object' || Array.isArray(request)) {
        rejectStorage('invalid-input');
      }
      const keys = Object.keys(request);
      if (keys.some((k) => k !== 'beforeMs' && k !== 'all')) {
        rejectStorage('invalid-input');
      }
      const isAll = request.all === true;
      if (request.all !== undefined && typeof request.all !== 'boolean') {
        rejectStorage('invalid-input');
      }
      if (!isAll && request.beforeMs === undefined) {
        rejectStorage('invalid-input');
      }
      if (isAll && request.beforeMs !== undefined) {
        rejectStorage('invalid-input');
      }
      if (request.beforeMs !== undefined && !isSafeInt(request.beforeMs)) {
        rejectStorage('invalid-input');
      }
      if (this.#state !== 'open' || this.#closing) {
        rejectStorage(this.#state === 'failed' ? 'failed' : 'closed');
      }
    } catch (error) {
      return Promise.reject(toStorageError(error));
    }

    const generation = ++this.#generation;
    this.#invalidateCursors();
    const isAll = request.all === true;
    const beforeMs = request.beforeMs;

    return this.#enqueue(async () => {
      await this.#verifyDirectory();
      const now = this.#now();

      if (isAll) {
        await this.#closeActiveSegment();
        let deletedSegments = 0;
        for (const seg of this.#segments) {
          await unlink(seg.filePath);
          deletedSegments++;
        }
        this.#segments = [];
        this.#nextSegmentSeq = 1;
        this.#clearMemory();
        this.#meta = {
          version: 1,
          storeId: randomUUID(),
          createdAtMs: now,
          forgetBeforeMs: 0,
          generation,
        };
        await this.#writeMetaAtomically(this.#meta);
        return {
          deletedSegments,
          remainingRecords: 0,
          remainingBytes: this.#totalDiskBytes(),
          forgetBeforeMs: 0,
          generation,
        };
      }

      const nextForgetBeforeMs = Math.max(this.#meta.forgetBeforeMs, beforeMs!);
      this.#meta = {
        ...this.#meta,
        forgetBeforeMs: nextForgetBeforeMs,
        generation,
      };
      await this.#writeMetaAtomically(this.#meta);

      const deletedSegments = await this.#pruneRecordsAndSegments(
        (entry) => entry.record.eventTimeMs < nextForgetBeforeMs,
      );

      return {
        deletedSegments,
        remainingRecords: this.#entries.length,
        remainingBytes: this.#totalDiskBytes(),
        forgetBeforeMs: this.#meta.forgetBeforeMs,
        generation,
      };
    });
  }

  pruneExpired(): Promise<number> {
    return this.#enqueue(async () => {
      await this.#verifyDirectory();
      const before = this.#entries.length;
      await this.#evictExpired(this.#now());
      return before - this.#entries.length;
    });
  }

  barrier(): Promise<void> {
    return this.#enqueue(async () => {
      await this.#verifyDirectory();
      if (this.#activeSegment?.handle) {
        await this.#activeSegment.handle.datasync();
      }
    });
  }

  async close(): Promise<void> {
    if (this.#state === 'closed') return;
    this.#closing = true;
    this.#invalidateCursors();
    await this.#tail;
    let closeError: unknown;
    try {
      await this.#closeActiveSegment();
    } catch (err) {
      closeError = err;
    }
    this.#clearMemory();
    this.#cursorKey.fill(0);
    this.#key.fill(0);
    try {
      await this.#lock.release();
    } catch (err) {
      closeError ??= err;
    } finally {
      this.#state = 'closed';
    }
    if (closeError) {
      throw toStorageError(closeError);
    }
  }

  #now(): number {
    const t = this.#clock();
    if (!isSafeInt(t)) rejectStorage('invalid-input');
    return t;
  }

  #totalDiskBytes(): number {
    let segBytes = 0;
    for (const seg of this.#segments) {
      segBytes += seg.bytes;
    }
    return this.#metaBytes + segBytes;
  }

  async #verifyDirectory(): Promise<void> {
    const stat = await lstat(this.#root);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      rejectStorage('unsafe-path');
    }
    if (isPosixPlatform(this.#platform)) {
      if (process.getuid !== undefined && stat.uid !== process.getuid()) {
        rejectStorage('unsafe-permissions');
      }
      if ((stat.mode & 0o077) !== 0) {
        rejectStorage('unsafe-permissions');
      }
    }
  }

  #gate(fence: { generation: number; isCurrent?: () => boolean }): void {
    let current = true;
    try {
      current = fence.isCurrent?.() ?? true;
    } catch {
      current = false;
    }
    if (!isSafeInt(fence.generation) || fence.generation !== this.#generation || !current || this.#closing) {
      rejectStorage('stale-generation');
    }
  }

  #enqueue<T>(work: () => Promise<T>, bytes = 0): Promise<T> {
    if (this.#closing || this.#state === 'closed') {
      return Promise.reject(new StorageError('closed'));
    }
    if (this.#state === 'failed') {
      return Promise.reject(new StorageError('failed'));
    }
    if (this.#pending >= MAX_PENDING || this.#pendingBytes + bytes > MAX_PENDING_BYTES) {
      return Promise.reject(new StorageError('budget-exceeded'));
    }

    this.#pending++;
    this.#pendingBytes += bytes;

    const result = this.#tail.then(async () => {
      try {
        if (this.#state !== 'open') {
          rejectStorage(this.#state === 'failed' ? 'failed' : 'closed');
        }
        return await work();
      } catch (error) {
        const safe = toStorageError(error);
        if (FATAL_CODES.has(safe.code)) {
          this.#state = 'failed';
          await this.#closeActiveSegment().catch(() => {});
          this.#clearMemory();
          this.#cursors.clear();
          this.#layoutCursors.clear();
          this.#cursorKey.fill(0);
          this.#key.fill(0);
        }
        throw safe;
      } finally {
        this.#pending--;
        this.#pendingBytes -= bytes;
      }
    });

    this.#tail = result.then(
      () => {},
      () => {},
    );
    return result;
  }

  async #writeMetaAtomically(meta: StoreMeta): Promise<void> {
    const sealed = encryptMeta(meta, this.#key);
    const metaPath = join(this.#root, META_FILENAME);
    const tempPath = join(this.#root, `${META_FILENAME}.tmp`);
    let handle: FileHandle | undefined;
    try {
      handle = await open(
        tempPath,
        constants.O_CREAT | constants.O_TRUNC | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0),
        0o600,
      );
      if (isPosixPlatform(this.#platform)) {
        const st = await handle.stat();
        if ((st.mode & 0o077) !== 0) {
          await chmod(tempPath, 0o600);
        }
      }
      await handle.writeFile(sealed);
      await handle.datasync();
      await handle.close();
      handle = undefined;

      await rename(tempPath, metaPath);
      this.#metaBytes = sealed.length;
    } catch (error) {
      if (handle) await handle.close().catch(() => {});
      await unlink(tempPath).catch(() => {});
      if (error instanceof StorageError) throw error;
      rejectStorage('io-failure');
    }
  }

  async #load(): Promise<void> {
    const names = await readdir(this.#root);
    const hasMeta = names.includes(META_FILENAME);

    if (names.includes(`${META_FILENAME}.tmp`)) {
      await unlink(join(this.#root, `${META_FILENAME}.tmp`)).catch(() => {});
    }

    const segmentCandidates: Array<{ seq: number; filename: string; filePath: string }> = [];
    const seenSeqs = new Set<number>();

    for (const name of names) {
      if (name === LOCK_FILENAME || name === META_FILENAME || name === `${META_FILENAME}.tmp`) {
        continue;
      }
      if (name.endsWith('.cah') || name.startsWith('seg-')) {
        const match = SEGMENT_NAME_RE.exec(name);
        if (!match) rejectStorage('invalid-store');
        const seq = Number(match[1]);
        if (!isSafeInt(seq, 1) || seenSeqs.has(seq)) {
          rejectStorage('invalid-store');
        }
        seenSeqs.add(seq);
        segmentCandidates.push({
          seq,
          filename: name,
          filePath: join(this.#root, name),
        });
      }
    }

    if (!hasMeta) {
      if (segmentCandidates.length > 0) {
        rejectStorage('invalid-store');
      }
      const now = this.#now();
      this.#meta = {
        version: 1,
        storeId: randomUUID(),
        createdAtMs: now,
        forgetBeforeMs: 0,
        generation: 0,
      };
      this.#generation = 0;
      await this.#writeMetaAtomically(this.#meta);
      return;
    }

    const metaPath = join(this.#root, META_FILENAME);
    const metaStat = await lstat(metaPath);
    assertSafeFileStat(metaStat, this.#platform);
    if (metaStat.size > 65536) rejectStorage('invalid-store');

    const metaRaw = await readFile(metaPath);
    this.#metaBytes = metaRaw.length;
    this.#meta = decryptMeta(metaRaw, this.#key);
    this.#generation = this.#meta.generation;

    segmentCandidates.sort((a, b) => a.seq - b.seq);
    this.#nextSegmentSeq =
      segmentCandidates.length > 0 ? segmentCandidates[segmentCandidates.length - 1]!.seq + 1 : 1;
    this.#activeSegmentBaselineSeq = 0;
    this.#activeSegmentBaselines.clear();

    for (let idx = 0; idx < segmentCandidates.length; idx++) {
      const candidate = segmentCandidates[idx]!;
      const isLast = idx === segmentCandidates.length - 1;
      const stat = await lstat(candidate.filePath);
      assertSafeFileStat(stat, this.#platform);

      const bytes = await readFile(candidate.filePath);
      if (bytes.length < SEGMENT_HEADER_BYTES) {
        if (isLast) {
          await unlink(candidate.filePath);
          this.#nextSegmentSeq = candidate.seq;
          continue;
        }
        rejectStorage('invalid-store');
      }

      const header = parseSegmentHeader(bytes, candidate.seq);
      let offset = SEGMENT_HEADER_BYTES;
      let frameIndex = 0;
      let liveRecords = 0;
      let truncatedAt: number | undefined;
      // Strictly segment-scoped text map: cleared at the end of every segment so delta chains never cross files.
      const segmentTexts = new Map<string, { text: string; depth: number }>();
      const tailBaselines = isLast ? new Map<string, TextDeltaBaseline>() : undefined;

      while (offset < bytes.length) {
        if (offset + 4 > bytes.length) {
          if (isLast) {
            truncatedAt = offset;
            break;
          }
          rejectStorage('invalid-store');
        }

        const bodyLen = bytes.readUInt32BE(offset);
        if (bodyLen === 0 && isLast && bytes.subarray(offset).every((b) => b === 0)) {
          truncatedAt = offset;
          break;
        }
        if (bodyLen < MIN_FRAME_BODY_BYTES || bodyLen > MAX_FRAME_BODY_BYTES) {
          rejectStorage('invalid-store');
        }

        const frameEnd = offset + 4 + bodyLen;
        if (frameEnd > bytes.length) {
          if (isLast) {
            truncatedAt = offset;
            break;
          }
          rejectStorage('invalid-store');
        }

        const isFinalFrameAtEof = frameEnd === bytes.length;
        const plain = decryptFrameBody(
          bytes.subarray(offset + 4, frameEnd),
          this.#key,
          this.#meta.storeId,
          candidate.seq,
          frameIndex,
        );

        if (plain === null) {
          if (isLast && isFinalFrameAtEof) {
            truncatedAt = offset;
            break;
          }
          rejectStorage('invalid-store');
        }

        try {
          const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain));
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            rejectStorage('invalid-store');
          }
          const obj = parsed as Record<string, unknown>;
          if (
            !isSafeInt(obj.receivedAtMs) ||
            typeof obj.inputHash !== 'string' ||
            !/^[a-f0-9]{64}$/.test(obj.inputHash) ||
            (obj.materializedBase !== undefined &&
              (typeof obj.materializedBase !== 'string' || obj.materializedBase.length > 128))
          ) {
            rejectStorage('invalid-store');
          }

          let record: Observation;
          let textDelta: HistoryTextDelta | undefined;
          let chainDepth = 0;

          if (obj.version === 1) {
            record = validateObservationInput(obj.record);
            if (record.payload.kind === 'text.changed') {
              rejectStorage('invalid-store');
            }
          } else if (obj.version === 2) {
            if (
              obj.encoding !== 'text-patch-v1' ||
              typeof obj.baseEventId !== 'string' ||
              obj.baseEventId.length === 0 ||
              obj.baseEventId.length > 256 ||
              !obj.record ||
              typeof obj.record !== 'object' ||
              Array.isArray(obj.record)
            ) {
              rejectStorage('invalid-store');
            }
            const patch = parseStoredTextPatch(obj.patch);
            const base = segmentTexts.get(obj.baseEventId);
            if (!base) {
              rejectStorage('invalid-store');
            }
            const rawRecord = obj.record as Record<string, unknown>;
            if (
              !rawRecord.payload ||
              typeof rawRecord.payload !== 'object' ||
              Array.isArray(rawRecord.payload)
            ) {
              rejectStorage('invalid-store');
            }
            const rawPayload = rawRecord.payload as Record<string, unknown>;
            if (
              rawPayload.kind !== 'text.snapshot' ||
              rawPayload.valueState !== 'read' ||
              rawPayload.text !== undefined
            ) {
              rejectStorage('invalid-store');
            }
            const materializedText = applySingleSpanPatch(base.text, patch);
            if (materializedText === null) {
              rejectStorage('invalid-store');
            }
            record = validateObservationInput({
              ...rawRecord,
              payload: {
                ...rawPayload,
                text: materializedText,
              },
            });
            if (record.payload.kind !== 'text.snapshot' || record.payload.valueState !== 'read') {
              rejectStorage('invalid-store');
            }
            chainDepth = base.depth + 1;
            textDelta = {
              baseEventId: obj.baseEventId,
              start: patch.start,
              deleteCount: patch.deleteCount,
              insert: patch.insert,
              totalLength: materializedText.length,
            };
          } else {
            rejectStorage('invalid-store');
          }

          if (this.#byId.has(record.eventId) || segmentTexts.has(record.eventId)) {
            rejectStorage('invalid-store');
          }

          if (
            record.payload.kind === 'text.snapshot' &&
            record.payload.valueState === 'read' &&
            typeof record.payload.text === 'string'
          ) {
            segmentTexts.set(record.eventId, { text: record.payload.text, depth: chainDepth });
          }

          this.#lastSeq.set(
            record.instanceId,
            Math.max(this.#lastSeq.get(record.instanceId) ?? -1, record.seq),
          );

          if (record.eventTimeMs >= this.#meta.forgetBeforeMs) {
            const textSnap = extractTextSnapshot(record);
            if (textSnap && this.#byTextSnapshot.has(textSnap.snapshotId)) {
              rejectStorage('invalid-store');
            }
            const memEntry: MemoryEntry = {
              segmentSeq: candidate.seq,
              order: this.#nextOrder++,
              inputHash: obj.inputHash,
              receivedAtMs: obj.receivedAtMs,
              record,
              ...(textDelta ? { textDelta } : {}),
            };
            this.#entries.push(memEntry);
            this.#indexEntry(memEntry);
            liveRecords++;

            if (
              tailBaselines &&
              record.payload.kind === 'text.snapshot' &&
              record.payload.valueState === 'read' &&
              typeof record.payload.text === 'string'
            ) {
              const targetKey = textDeltaTargetKey(record, record.payload);
              if (targetKey !== null) {
                tailBaselines.set(targetKey, {
                  eventId: record.eventId,
                  text: record.payload.text,
                  chainDepth,
                });
              }
            }
          }
        } catch (error) {
          if (
            error instanceof StorageError &&
            (error.code === 'invalid-input' || error.code === 'budget-exceeded')
          ) {
            rejectStorage('invalid-store');
          }
          if (error instanceof StorageError) throw error;
          rejectStorage('invalid-store');
        } finally {
          plain.fill(0);
        }

        offset = frameEnd;
        frameIndex++;
      }

      segmentTexts.clear();

      let finalBytes = bytes.length;
      if (truncatedAt !== undefined) {
        await truncate(candidate.filePath, truncatedAt);
        finalBytes = truncatedAt;
      }

      this.#segments.push({
        seq: candidate.seq,
        filename: candidate.filename,
        filePath: candidate.filePath,
        createdAtMs: header.createdAtMs,
        bytes: finalBytes,
        frameCount: frameIndex,
        liveRecords,
        handle: null,
      });

      if (isLast && tailBaselines && finalBytes < this.#maxSegmentBytes) {
        this.#activeSegmentBaselineSeq = candidate.seq;
        this.#activeSegmentBaselines = tailBaselines;
      }
    }
  }

  async #ensureActiveSegment(now: number): Promise<SegmentInfo> {
    if (this.#activeSegment && this.#activeSegment.handle) {
      return this.#activeSegment;
    }

    const tail = this.#segments[this.#segments.length - 1];
    if (tail && tail.bytes < this.#maxSegmentBytes) {
      const stat = await lstat(tail.filePath);
      assertSafeFileStat(stat, this.#platform);
      const handle = await open(
        tail.filePath,
        constants.O_RDWR | (constants.O_NOFOLLOW ?? 0),
        0o600,
      );
      tail.handle = handle;
      this.#activeSegment = tail;
      return tail;
    }

    return this.#createNewActiveSegment(now);
  }

  async #createNewActiveSegment(now: number): Promise<SegmentInfo> {
    const seq = this.#nextSegmentSeq++;
    const filename = formatSegmentFilename(seq);
    const filePath = join(this.#root, filename);
    const header = encodeSegmentHeader(seq, now);

    const handle = await open(
      filePath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    try {
      if (isPosixPlatform(this.#platform)) {
        const st = await handle.stat();
        if ((st.mode & 0o077) !== 0) {
          await chmod(filePath, 0o600);
        }
      }
      await writeFullAt(handle, header, 0);
    } catch (error) {
      await handle.close().catch(() => {});
      await unlink(filePath).catch(() => {});
      if (error instanceof StorageError) throw error;
      rejectStorage('io-failure');
    }

    const seg: SegmentInfo = {
      seq,
      filename,
      filePath,
      createdAtMs: now,
      bytes: SEGMENT_HEADER_BYTES,
      frameCount: 0,
      liveRecords: 0,
      handle,
    };
    this.#segments.push(seg);
    this.#activeSegment = seg;
    this.#activeSegmentBaselineSeq = seg.seq;
    this.#activeSegmentBaselines.clear();
    return seg;
  }

  async #closeActiveSegment(): Promise<void> {
    const active = this.#activeSegment;
    if (!active) return;
    this.#activeSegment = null;
    if (this.#activeSegmentBaselineSeq === active.seq) {
      this.#activeSegmentBaselineSeq = 0;
      this.#activeSegmentBaselines.clear();
    }
    const handle = active.handle;
    active.handle = null;
    if (handle) {
      try {
        await handle.datasync();
      } finally {
        await handle.close();
      }
    }
  }

  async #rollActiveSegment(now: number): Promise<void> {
    await this.#closeActiveSegment();
    if (this.#totalDiskBytes() + SEGMENT_HEADER_BYTES <= this.#maxBytes) {
      await this.#createNewActiveSegment(now);
    }
  }

  async #evictExpired(now: number): Promise<void> {
    this.#expireCursors(now);
    const cutoff = now - this.#retentionMs;
    const hasExpired = this.#entries.some(
      (e) =>
        e.record.eventTimeMs < this.#meta.forgetBeforeMs ||
        Math.min(e.record.eventTimeMs, e.receivedAtMs) <= cutoff,
    );
    if (!hasExpired && !this.#segments.some((s) => s.liveRecords === 0 && s.frameCount > 0)) {
      return;
    }
    await this.#pruneRecordsAndSegments(
      (entry) =>
        entry.record.eventTimeMs < this.#meta.forgetBeforeMs ||
        Math.min(entry.record.eventTimeMs, entry.receivedAtMs) <= cutoff,
    );
  }

  async #pruneRecordsAndSegments(shouldRemove: (entry: MemoryEntry) => boolean): Promise<number> {
    const kept: MemoryEntry[] = [];
    let removedAny = false;

    for (const seg of this.#segments) {
      seg.liveRecords = 0;
    }

    for (const entry of this.#entries) {
      if (shouldRemove(entry)) {
        removedAny = true;
      } else {
        kept.push(entry);
      }
    }

    if (removedAny) {
      this.#invalidateCursors();
      this.#entries = kept;
      this.#rebuildIndexes();
    } else {
      for (const entry of this.#entries) {
        const seg = this.#segments.find((s) => s.seq === entry.segmentSeq);
        if (seg) seg.liveRecords++;
      }
    }

    // Close active segment if all its written frames expired, or if the entire store is now empty.
    if (
      this.#activeSegment &&
      this.#activeSegment.liveRecords === 0 &&
      (this.#activeSegment.frameCount > 0 || this.#entries.length === 0)
    ) {
      await this.#closeActiveSegment();
    }

    let deletedSegments = 0;
    const remainingSegments: SegmentInfo[] = [];
    for (const seg of this.#segments) {
      if (
        seg.handle === null &&
        seg.liveRecords === 0 &&
        (seg.frameCount > 0 || this.#entries.length === 0)
      ) {
        await unlink(seg.filePath);
        deletedSegments++;
      } else {
        remainingSegments.push(seg);
      }
    }
    this.#segments = remainingSegments;
    return deletedSegments;
  }

  async #evictOverBudget(incomingFrameBytes: number): Promise<void> {
    const projectedNeed = (): number => {
      const base = this.#totalDiskBytes();
      if (incomingFrameBytes === 0) return base;
      const tail = this.#activeSegment ?? this.#segments[this.#segments.length - 1];
      const needsNewHeader = !tail || tail.bytes >= this.#maxSegmentBytes;
      return base + (needsNewHeader ? SEGMENT_HEADER_BYTES : 0) + incomingFrameBytes;
    };

    while (projectedNeed() > this.#maxBytes) {
      const oldestClosedIdx = this.#segments.findIndex((s) => s.handle === null);
      if (oldestClosedIdx >= 0) {
        const victim = this.#segments[oldestClosedIdx]!;
        await unlink(victim.filePath);
        this.#segments.splice(oldestClosedIdx, 1);
        const beforeLen = this.#entries.length;
        this.#entries = this.#entries.filter((e) => e.segmentSeq !== victim.seq);
        if (this.#entries.length !== beforeLen) {
          this.#invalidateCursors();
          this.#rebuildIndexes();
        }
        continue;
      }

      if (this.#activeSegment && this.#activeSegment.frameCount > 0) {
        await this.#closeActiveSegment();
        continue;
      }

      rejectStorage('budget-exceeded');
    }
  }

  #clearMemory(): void {
    this.#entries = [];
    this.#byId.clear();
    this.#byTextSnapshot.clear();
    this.#bySnapshotId.clear();
    this.#lastSeq.clear();
    this.#activeSegmentBaselineSeq = 0;
    this.#activeSegmentBaselines.clear();
  }

  #rebuildIndexes(): void {
    this.#byId.clear();
    this.#byTextSnapshot.clear();
    this.#bySnapshotId.clear();
    for (const seg of this.#segments) {
      seg.liveRecords = 0;
    }
    const segBySeq = new Map(this.#segments.map((s) => [s.seq, s]));
    for (const entry of this.#entries) {
      this.#indexEntry(entry);
      const seg = segBySeq.get(entry.segmentSeq);
      if (seg) seg.liveRecords++;
    }
    if (this.#activeSegmentBaselineSeq !== 0) {
      if (!segBySeq.has(this.#activeSegmentBaselineSeq)) {
        this.#activeSegmentBaselineSeq = 0;
        this.#activeSegmentBaselines.clear();
      } else {
        for (const [key, baseline] of this.#activeSegmentBaselines) {
          const entry = this.#byId.get(baseline.eventId);
          if (!entry || entry.segmentSeq !== this.#activeSegmentBaselineSeq) {
            this.#activeSegmentBaselines.delete(key);
          }
        }
      }
    }
  }

  #indexEntry(entry: MemoryEntry): void {
    const record = entry.record;
    this.#byId.set(record.eventId, entry);
    const textSnap = extractTextSnapshot(record);
    if (textSnap) {
      this.#byTextSnapshot.set(textSnap.snapshotId, entry);
    }
    const snapId = extractSnapshotId(record);
    if (snapId !== undefined) {
      const list = this.#bySnapshotId.get(snapId);
      if (list) list.push(entry);
      else this.#bySnapshotId.set(snapId, [entry]);
    }
    this.#lastSeq.set(
      record.instanceId,
      Math.max(this.#lastSeq.get(record.instanceId) ?? -1, record.seq),
    );
  }

  #admitRelation(record: Observation): void {
    if (!record.relation) return;
    const current = evidenceMetadata(record);
    if (!current) rejectStorage('invalid-input');
    const evidenceIds: string[] = [];
    for (const id of record.relation.evidenceIds) {
      if (id === record.eventId || evidenceIds.includes(id)) {
        rejectStorage('invalid-input');
      }
      const prior = this.#byId.get(id);
      if (!prior) continue;
      const earlier = evidenceMetadata(prior.record);
      if (!earlier || !canRelateEvidence(earlier, current)) {
        rejectStorage('invalid-input');
      }
      evidenceIds.push(id);
    }
    if (evidenceIds.length > 0) {
      record.relation = { ...record.relation, evidenceIds };
    } else {
      delete record.relation;
    }
  }

  #projectRecord(record: Observation, inScope: (entry: MemoryEntry) => boolean = () => true): Observation {
    const cloned = structuredClone(record);
    if (!cloned.relation) return cloned;
    const current = evidenceMetadata(record);
    const validIds = cloned.relation.evidenceIds.filter((id) => {
      const entry = this.#byId.get(id);
      const earlier = entry && evidenceMetadata(entry.record);
      return (
        current !== undefined &&
        earlier !== undefined &&
        entry !== undefined &&
        inScope(entry) &&
        canRelateEvidence(earlier, current)
      );
    });
    if (validIds.length > 0) {
      cloned.relation = { ...cloned.relation, evidenceIds: validIds };
    } else {
      delete cloned.relation;
    }
    return cloned;
  }

  #validateSearchQuery(input: unknown): HistoryQuery {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      rejectStorage('invalid-input');
    }
    const allowed = [
      'fromTimeMs',
      'toTimeMs',
      'applicationId',
      'text',
      'kind',
      'textView',
      'limit',
      'maxBytes',
      'order',
      'cursor',
    ];
    const obj = input as Record<string, unknown>;
    for (const key of Object.keys(obj)) {
      if (!allowed.includes(key)) rejectStorage('invalid-input');
    }
    if (obj.fromTimeMs !== undefined && !isSafeInt(obj.fromTimeMs)) rejectStorage('invalid-input');
    if (obj.toTimeMs !== undefined && !isSafeInt(obj.toTimeMs)) rejectStorage('invalid-input');
    if (
      obj.fromTimeMs !== undefined &&
      obj.toTimeMs !== undefined &&
      (obj.fromTimeMs as number) > (obj.toTimeMs as number)
    ) {
      rejectStorage('invalid-input');
    }
    for (const field of ['applicationId', 'text'] as const) {
      if (
        obj[field] !== undefined &&
        (typeof obj[field] !== 'string' || obj[field].length > 1024 || !obj[field].isWellFormed())
      ) {
        rejectStorage('invalid-input');
      }
    }
    if (obj.limit !== undefined && !isSafeInt(obj.limit, 0, 1000)) rejectStorage('invalid-input');
    if (obj.maxBytes !== undefined && !isSafeInt(obj.maxBytes, 256, MAX_QUERY_BYTES)) {
      rejectStorage('invalid-input');
    }
    if (
      obj.kind !== undefined &&
      (typeof obj.kind !== 'string' || !VALID_QUERY_KINDS.has(obj.kind as HistoryQueryKind))
    ) {
      rejectStorage('invalid-input');
    }
    if (obj.textView !== undefined && obj.textView !== 'full' && obj.textView !== 'delta') {
      rejectStorage('invalid-input');
    }
    if (obj.order !== undefined && obj.order !== 'asc' && obj.order !== 'desc') {
      rejectStorage('invalid-input');
    }
    if (obj.cursor !== undefined && (typeof obj.cursor !== 'string' || !CURSOR_PATTERN.test(obj.cursor))) {
      rejectStorage('invalid-cursor');
    }
    return { ...(obj as HistoryQuery) };
  }

  #computeSearchFingerprint(options: HistoryQuery, cursorScope?: string): string {
    return createHmac('sha256', this.#cursorKey)
      .update(
        canonicalJson([
          'search',
          cursorScope ?? null,
          options.fromTimeMs ?? null,
          options.toTimeMs ?? null,
          options.applicationId ?? null,
          options.text ?? null,
          options.limit ?? 100,
          options.maxBytes ?? 64 * 1024,
          options.kind ?? 'all',
          options.textView ?? 'full',
          options.order ?? 'asc',
        ]),
      )
      .digest('hex');
  }

  #createSignedToken(fingerprint: string): string {
    const nonce = randomBytes(16);
    const mac = createHmac('sha256', this.#cursorKey)
      .update(nonce)
      .update(fingerprint, 'hex')
      .digest()
      .subarray(0, 16);
    return Buffer.concat([nonce, mac], 32).toString('base64url');
  }

  #verifySignedToken(token: string, fingerprint: string): boolean {
    if (!CURSOR_PATTERN.test(token)) return false;
    const raw = Buffer.from(token, 'base64url');
    if (raw.length !== 32) return false;
    const nonce = raw.subarray(0, 16);
    const mac = raw.subarray(16, 32);
    const expected = createHmac('sha256', this.#cursorKey)
      .update(nonce)
      .update(fingerprint, 'hex')
      .digest()
      .subarray(0, 16);
    return timingSafeEqual(mac, expected);
  }

  #invalidateCursors(): void {
    for (const token of this.#cursors.keys()) this.#cursors.set(token, null);
    for (const token of this.#layoutCursors.keys()) this.#layoutCursors.set(token, null);
  }

  #expireCursors(now: number): void {
    for (const [token, c] of this.#cursors) {
      if (c !== null && now >= c.expiresAtMs) this.#cursors.set(token, null);
    }
    for (const [token, c] of this.#layoutCursors) {
      if (c !== null && now >= c.expiresAtMs) this.#layoutCursors.set(token, null);
    }
  }

  #verifySearchCursor(token: string, fingerprint: string): QueryCursor {
    if (!this.#verifySignedToken(token, fingerprint)) {
      rejectStorage('invalid-cursor');
    }
    const cursor = this.#cursors.get(token);
    if (cursor === undefined) rejectStorage('invalid-cursor');
    if (cursor === null) rejectStorage('cursor-expired');
    if (
      cursor.generation !== this.#generation ||
      this.#now() >= cursor.expiresAtMs ||
      this.#closing ||
      this.#state !== 'open'
    ) {
      this.#cursors.set(token, null);
      rejectStorage('cursor-expired');
    }
    if (cursor.fingerprint !== fingerprint) {
      rejectStorage('invalid-cursor');
    }
    return cursor;
  }

  #mintSearchCursor(cursor: QueryCursor, now: number): string {
    for (const [t, c] of this.#cursors) {
      if (c === null || now >= c.expiresAtMs) this.#cursors.delete(t);
    }
    while (this.#cursors.size >= MAX_CURSORS) {
      const oldest = this.#cursors.keys().next().value;
      if (oldest === undefined) break;
      this.#cursors.delete(oldest);
    }
    let token: string;
    do {
      token = this.#createSignedToken(cursor.fingerprint);
    } while (this.#cursors.has(token) || this.#layoutCursors.has(token));
    this.#cursors.set(token, cursor);
    return token;
  }

  #verifyLayoutCursor(token: string, fingerprint: string): LayoutCursor {
    if (!this.#verifySignedToken(token, fingerprint)) {
      rejectStorage('invalid-cursor');
    }
    const cursor = this.#layoutCursors.get(token);
    if (cursor === undefined) rejectStorage('invalid-cursor');
    if (cursor === null) rejectStorage('cursor-expired');
    if (
      cursor.generation !== this.#generation ||
      this.#now() >= cursor.expiresAtMs ||
      this.#closing ||
      this.#state !== 'open'
    ) {
      this.#layoutCursors.set(token, null);
      rejectStorage('cursor-expired');
    }
    if (cursor.fingerprint !== fingerprint) {
      rejectStorage('invalid-cursor');
    }
    return cursor;
  }

  #mintLayoutCursor(cursor: LayoutCursor, now: number): string {
    for (const [t, c] of this.#layoutCursors) {
      if (c === null || now >= c.expiresAtMs) this.#layoutCursors.delete(t);
    }
    while (this.#layoutCursors.size >= MAX_CURSORS) {
      const oldest = this.#layoutCursors.keys().next().value;
      if (oldest === undefined) break;
      this.#layoutCursors.delete(oldest);
    }
    let token: string;
    do {
      token = this.#createSignedToken(cursor.fingerprint);
    } while (this.#layoutCursors.has(token) || this.#cursors.has(token));
    this.#layoutCursors.set(token, cursor);
    return token;
  }
}

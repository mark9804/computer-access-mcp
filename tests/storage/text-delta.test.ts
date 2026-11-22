import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { lstat, readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import { createHistoryService } from '../../src/host/service/history-service.ts';
import { startHttpServer } from '../../src/server/http-server.ts';
import type { HistoryQueryResult, HistoryTextDelta } from '../../src/shared/api-types.ts';
import type { Observation, TextSnapshot } from '../../src/shared/protocol/generated.ts';
import {
  applySingleSpanPatch,
  computeSingleSpanPatch,
  DEFAULT_MAX_TEXT_DELTA_CHAIN_DEPTH,
  HISTORY_RETENTION_MS,
  SEGMENT_HEADER_BYTES,
  SegmentStore,
  shouldStoreTextPatch,
  StorageError,
} from '../../src/storage/index.ts';
import { NOW, observation, temporary } from '../integration/history-store-fixtures.ts';

const SEGMENT_MAGIC = Buffer.from('CAHS\x01', 'binary');
const GCM_NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;

function expectStorageCode(code: StorageError['code']): (err: unknown) => boolean {
  return (err: unknown) => err instanceof StorageError && err.code === code;
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
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

function encodeSegmentHeader(segmentSeq: number, createdAtMs: number): Buffer {
  const header = Buffer.alloc(SEGMENT_HEADER_BYTES, 0);
  SEGMENT_MAGIC.copy(header, 0);
  header.writeBigUInt64BE(BigInt(segmentSeq), 8);
  header.writeBigUInt64BE(BigInt(createdAtMs), 16);
  return header;
}

function encryptRawFrame(
  payload: unknown,
  key: Buffer,
  storeId: string,
  segmentSeq: number,
  frameIndex: number,
): Buffer {
  const plain = Buffer.from(canonicalJson(payload), 'utf8');
  const nonce = randomBytes(GCM_NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(`${storeId}:${segmentSeq}:${frameIndex}`, 'utf8'));
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  const bodyLen = GCM_NONCE_BYTES + encrypted.length + GCM_TAG_BYTES;
  const lenBuf = Buffer.allocUnsafe(4);
  lenBuf.writeUInt32BE(bodyLen, 0);
  return Buffer.concat([lenBuf, nonce, encrypted, tag]);
}

async function decryptSegmentFrames(
  filePath: string,
  key: Buffer,
  storeId: string,
  segmentSeq: number,
): Promise<Array<Record<string, unknown>>> {
  const raw = await readFile(filePath);
  let offset = SEGMENT_HEADER_BYTES;
  let frameIndex = 0;
  const frames: Array<Record<string, unknown>> = [];
  while (offset < raw.length) {
    const bodyLen = raw.readUInt32BE(offset);
    const body = raw.subarray(offset + 4, offset + 4 + bodyLen);
    const nonce = body.subarray(0, GCM_NONCE_BYTES);
    const ciphertext = body.subarray(GCM_NONCE_BYTES, body.length - GCM_TAG_BYTES);
    const tag = body.subarray(body.length - GCM_TAG_BYTES);
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(Buffer.from(`${storeId}:${segmentSeq}:${frameIndex}`, 'utf8'));
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    frames.push(JSON.parse(plain.toString('utf8')) as Record<string, unknown>);
    offset += 4 + bodyLen;
    frameIndex += 1;
  }
  return frames;
}

function makeEditorObservation(
  seq: number,
  text: string,
  eventTimeMs = NOW + seq * 1000,
  nodeId = 'editor-main',
): Observation {
  const obs = observation(seq, text, eventTimeMs);
  if (obs.payload.kind === 'text.snapshot') {
    obs.payload.nodeId = nodeId;
  }
  return obs;
}

test('computeSingleSpanPatch & applySingleSpanPatch handle prefix/suffix/middle/insert/delete/IME and UTF-16 surrogates safely', () => {
  const pairs: Array<[string, string, string]> = [
    ['identical', 'unchanged text block', 'unchanged text block'],
    ['prefix edit', 'hello world', 'HERO world'],
    ['suffix edit', 'hello world', 'hello earth!'],
    ['middle edit', 'the quick brown fox', 'the slow silver fox'],
    ['pure insert', 'abcdef', 'abcXYZdef'],
    ['pure delete', 'abcXYZdef', 'abcdef'],
    ['empty to text', '', 'fresh content'],
    ['text to empty', 'to be cleared', ''],
    ['IME pinyin commit', "Draft: ni'hao shijie", 'Draft: 你好世界'],
    ['IME Japanese commit', 'メモ: にほんご入力', 'メモ: 日本語入力'],
    ['astral surrogate same high', 'prefix \u{1F600} suffix', 'prefix \u{1F601} suffix'],
    ['astral surrogate same low', 'prefix \uD83D\uDE00 suffix', 'prefix \uD83E\uDE00 suffix'],
    ['CJK extension B surrogate', 'doc 𠮷野家 menu', 'doc 𠮸野家 menu'],
    ['insert adjacent astral', 'a\u{1F600}c', 'a\u{1F600}\u{1F600}c'],
    ['delete adjacent astral', 'a\u{1F600}\u{1F600}c', 'a\u{1F600}c'],
    ['ZWJ sequence edit', 'team: \u{1F468}\u200D\u{1F469}\u200D\u{1F467} ready', 'team: \u{1F468}\u200D\u{1F469}\u200D\u{1F466} ready'],
  ];

  for (const [label, before, after] of pairs) {
    const patch = computeSingleSpanPatch(before, after);
    assert.equal(patch.insert.isWellFormed(), true, `${label}: patch.insert must be well-formed UTF-16`);
    const reconstructed = applySingleSpanPatch(before, patch);
    assert.equal(reconstructed, after, `${label}: patch roundtrip mismatch`);
  }

  // Strict bounds & surrogate-split rejection in applySingleSpanPatch.
  assert.equal(applySingleSpanPatch('hello', { start: -1, deleteCount: 0, insert: '' }), null);
  assert.equal(applySingleSpanPatch('hello', { start: 0, deleteCount: -1, insert: '' }), null);
  assert.equal(applySingleSpanPatch('hello', { start: 6, deleteCount: 0, insert: '' }), null);
  assert.equal(applySingleSpanPatch('hello', { start: 3, deleteCount: 3, insert: '' }), null);
  assert.equal(applySingleSpanPatch('hello', { start: 1.5, deleteCount: 0, insert: '' }), null);
  assert.equal(applySingleSpanPatch('hello', { start: 0, deleteCount: 0, insert: '\uD83D' }), null);
  // Attempting to split a surrogate pair in `before` must return null.
  assert.equal(applySingleSpanPatch('a\u{1F600}b', { start: 2, deleteCount: 1, insert: 'x' }), null);
  assert.equal(applySingleSpanPatch('a\u{1F600}b', { start: 1, deleteCount: 1, insert: 'x' }), null);
});

test('shouldStoreTextPatch enforces 64-byte minimum, <60% ratio fallback, and chainDepth=32 keyframe reset', () => {
  assert.equal(DEFAULT_MAX_TEXT_DELTA_CHAIN_DEPTH, 32);

  // < 64 UTF-8 bytes always returns false.
  const shortText = 'a'.repeat(63);
  assert.equal(shouldStoreTextPatch(shortText, { start: 0, deleteCount: 0, insert: '' }, 0), false);

  // >= 64 UTF-8 bytes with small patch returns true up to depth 31, false at depth 32.
  const baseText = 'x'.repeat(200);
  const smallPatch = { start: 200, deleteCount: 0, insert: '!' };
  assert.equal(shouldStoreTextPatch(baseText, smallPatch, 0), true);
  assert.equal(shouldStoreTextPatch(baseText, smallPatch, 31), true);
  assert.equal(shouldStoreTextPatch(baseText, smallPatch, 32), false);
  assert.equal(shouldStoreTextPatch(baseText, smallPatch, 5, 5), false);
  assert.equal(shouldStoreTextPatch(baseText, smallPatch, -1), false);

  // Ratio boundary: exact 60% (patchBytes === 60 for 100-byte fullText) must fall back to keyframe (false).
  // {"start":0,"deleteCount":0,"insert":""} is 39 UTF-8 bytes.
  const hundredBytes = 'a'.repeat(100);
  const patch59 = { start: 0, deleteCount: 0, insert: 'b'.repeat(20) }; // 39 + 20 = 59 bytes (< 60%)
  const patch60 = { start: 0, deleteCount: 0, insert: 'b'.repeat(21) }; // 39 + 21 = 60 bytes (=== 60%)
  assert.equal(Buffer.byteLength(JSON.stringify(patch59), 'utf8'), 59);
  assert.equal(Buffer.byteLength(JSON.stringify(patch60), 'utf8'), 60);
  assert.equal(shouldStoreTextPatch(hundredBytes, patch59, 0), true);
  assert.equal(shouldStoreTextPatch(hundredBytes, patch60, 0), false);
});

test('SegmentStore stores v2 text-patch-v1 frames, resets keyframe at chainDepth=32 and >=60% rewrite, and achieves strong 1000-char compression', async () => {
  const temp = await temporary();
  let now = NOW;
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => now });
  const expectedTexts = new Map<string, string>();
  const rawFullFrameBaselineBytes: number[] = [];

  try {
    let doc = 'L'.repeat(1000);
    // Append 35 sequential edits:
    // seq 1: keyframe (depth 0)
    // seq 2..33: 32 delta frames (depth 1..32)
    // seq 34: chainDepth=32 reached -> keyframe reset (depth 0)
    // seq 35: delta referencing seq 34 (depth 1)
    for (let seq = 1; seq <= 35; seq++) {
      now += 100;
      if (seq > 1) {
        doc += ` e${seq}`;
      }
      const obs = makeEditorObservation(seq, doc, now);
      expectedTexts.set(obs.eventId, doc);
      rawFullFrameBaselineBytes.push(
        4 +
          GCM_NONCE_BYTES +
          Buffer.byteLength(
            canonicalJson({ version: 1, inputHash: sha256Hex(canonicalJson(obs)), receivedAtMs: now, record: obs }),
            'utf8',
          ) +
          GCM_TAG_BYTES,
      );
      await store.append(obs);
    }

    const compressed35Bytes = store.status().bytes - (await lstat(join(temp.root, 'store.meta'))).size;

    // seq 36: >=60% rewrite must fall back to v1 keyframe and reset chain depth to 0.
    now += 100;
    const rewritten = 'R'.repeat(1100);
    const obs36 = makeEditorObservation(36, rewritten, now);
    expectedTexts.set(obs36.eventId, rewritten);
    await store.append(obs36);

    // seq 37: small edit after rewrite is delta against seq 36.
    now += 100;
    const obs37Text = rewritten + ' tail';
    const obs37 = makeEditorObservation(37, obs37Text, now);
    expectedTexts.set(obs37.eventId, obs37Text);
    await store.append(obs37);

    // Idempotent duplicate append on a delta-stored record must succeed silently; conflicting content rejects.
    const dup37 = makeEditorObservation(37, obs37Text, now);
    await store.append(dup37);
    const conflict37 = makeEditorObservation(37, obs37Text + '!', now);
    await assert.rejects(store.append(conflict37), expectStorageCode('duplicate-conflict'));

    const storeId = store.storeId;
    const segPath = join(temp.root, 'seg-00000001.cah');
    await store.close();

    // Inspect decrypted frames on disk to verify exact on-disk layout.
    const frames = await decryptSegmentFrames(segPath, temp.key, storeId, 1);
    assert.equal(frames.length, 37);

    assert.equal(frames[0]!.version, 1);
    for (let i = 1; i <= 32; i++) {
      assert.equal(frames[i]!.version, 2, `frame ${i} should be v2 delta`);
      assert.equal(frames[i]!.encoding, 'text-patch-v1');
      assert.equal(frames[i]!.baseEventId, `synthetic-instance:${i}`);
      assert.equal(((frames[i]!.record as Record<string, unknown>).payload as Record<string, unknown>).text, undefined);
    }
    // Frame index 33 (seq 34) MUST reset to v1 keyframe due to chainDepth=32!
    assert.equal(frames[33]!.version, 1);
    // Frame index 34 (seq 35) is v2 delta against seq 34.
    assert.equal(frames[34]!.version, 2);
    assert.equal(frames[34]!.baseEventId, 'synthetic-instance:34');
    // Frame index 35 (seq 36) >=60% rewrite MUST be v1 keyframe.
    assert.equal(frames[35]!.version, 1);
    // Frame index 36 (seq 37) is v2 delta against seq 36.
    assert.equal(frames[36]!.version, 2);
    assert.equal(frames[36]!.baseEventId, 'synthetic-instance:36');

    // Measure exact apples-to-apples compression savings on the 35 incremental 1000-char edits.
    const uncompressed35Bytes = SEGMENT_HEADER_BYTES + rawFullFrameBaselineBytes.reduce((a, b) => a + b, 0);
    const savedRatio = 1 - compressed35Bytes / uncompressed35Bytes;
    assert.ok(
      savedRatio > 0.35,
      `Expected >35% total encrypted segment byte savings on 1000-char edits: compressed=${compressed35Bytes} vs uncompressed=${uncompressed35Bytes} (${(savedRatio * 100).toFixed(1)}%)`,
    );

    // Reopen and verify every single record materializes bit-identically.
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => now });
    assert.equal(store.status().records, 37);
    for (const [eventId, expectedText] of expectedTexts) {
      const rec = await store.read(eventId);
      assert.ok(rec, `missing ${eventId}`);
      assert.equal(rec.payload.kind, 'text.snapshot');
      assert.equal(rec.payload.text, expectedText, `text mismatch for ${eventId}`);
    }

    // Idempotent dedup and conflict rejection for a v2 delta frame must hold AFTER reopen().
    await store.append(makeEditorObservation(37, obs37Text, now));
    assert.equal(store.status().records, 37);
    await assert.rejects(
      store.append(makeEditorObservation(37, obs37Text + '?', now)),
      expectStorageCode('duplicate-conflict'),
    );

    // Appending after reopen into the half-full active segment resumes delta compression cleanly.
    now += 100;
    const obs38Text = obs37Text + ' reopened';
    await store.append(makeEditorObservation(38, obs38Text, now));
    await store.close();
    const framesAfterReopen = await decryptSegmentFrames(segPath, temp.key, storeId, 1);
    assert.equal(framesAfterReopen.length, 38);
    assert.equal(framesAfterReopen[37]!.version, 2);
    assert.equal(framesAfterReopen[37]!.baseEventId, 'synthetic-instance:37');

    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => now });
    const rec38 = await store.read('synthetic-instance:38');
    assert.equal(rec38?.payload.kind, 'text.snapshot');
    assert.equal((rec38?.payload as TextSnapshot).text, obs38Text);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('SegmentStore rollover forces keyframe in new segment and eviction of old segment leaves new segment 100% readable', async () => {
  const temp = await temporary();
  let now = NOW;
  let store = await SegmentStore.open({
    root: temp.root,
    keyProvider: temp.provider,
    clock: () => now,
    maxSegmentBytes: 4600,
  });

  try {
    let doc = 'S'.repeat(900);
    const texts = new Map<string, string>();
    let seq = 0;

    // Append edits until seg-00000001.cah rolls and seg-00000002.cah receives multiple frames.
    while (store.status().segments < 2) {
      seq += 1;
      now += 100;
      doc += `-${seq}`;
      const obs = makeEditorObservation(seq, doc, now);
      texts.set(obs.eventId, doc);
      await store.append(obs);
    }
    const seg1LastSeq = seq;

    // Advance 6 days so seg-00000002.cah frames survive when seg-00000001.cah expires via 7-day TTL.
    now = NOW + 6 * 24 * 60 * 60 * 1000;
    for (let k = 0; k < 3; k++) {
      seq += 1;
      now += 100;
      doc += `+${seq}`;
      const obs = makeEditorObservation(seq, doc, now);
      texts.set(obs.eventId, doc);
      await store.append(obs);
    }

    const storeId = store.storeId;
    await store.close();

    // First frame of seg-00000002.cah MUST be a full v1 keyframe (never referencing seg-00000001.cah).
    const seg2Frames = await decryptSegmentFrames(join(temp.root, 'seg-00000002.cah'), temp.key, storeId, 2);
    assert.equal(seg2Frames.length, 3);
    assert.equal(seg2Frames[0]!.version, 1);
    assert.equal(seg2Frames[1]!.version, 2);
    assert.equal(seg2Frames[1]!.baseEventId, `synthetic-instance:${seg1LastSeq + 1}`);
    assert.equal(seg2Frames[2]!.version, 2);
    assert.equal(seg2Frames[2]!.baseEventId, `synthetic-instance:${seg1LastSeq + 2}`);

    // Reopen past 7 days from seg-00000001.cah: seg-00000001.cah is unlinked during TTL eviction.
    now = NOW + HISTORY_RETENTION_MS + 60_000;
    store = await SegmentStore.open({
      root: temp.root,
      keyProvider: temp.provider,
      clock: () => now,
      maxSegmentBytes: 4600,
    });
    assert.equal((await readdir(temp.root)).includes('seg-00000001.cah'), false);
    assert.equal((await readdir(temp.root)).includes('seg-00000002.cah'), true);
    assert.equal(store.status().records, 3);

    for (let s = seg1LastSeq + 1; s <= seq; s++) {
      const id = `synthetic-instance:${s}`;
      const rec = await store.read(id);
      assert.ok(rec);
      assert.equal(rec.payload.kind, 'text.snapshot');
      assert.equal(rec.payload.text, texts.get(id));
    }

    // Reopen a second time after seg-00000001.cah is gone from disk to confirm 100% standalone readability.
    await store.close();
    store = await SegmentStore.open({
      root: temp.root,
      keyProvider: temp.provider,
      clock: () => now,
      maxSegmentBytes: 4600,
    });
    assert.equal(store.status().records, 3);
    const lastRec = await store.read(`synthetic-instance:${seq}`);
    assert.equal((lastRec?.payload as TextSnapshot).text, texts.get(`synthetic-instance:${seq}`));
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('SegmentStore falls back to full keyframe if maxBytes eviction closes the only active segment before write', async () => {
  const temp = await temporary();
  let now = NOW;
  // Tight maxBytes so writing a second/third edit triggers eviction of seg-00000001.cah.
  let store = await SegmentStore.open({
    root: temp.root,
    keyProvider: temp.provider,
    clock: () => now,
    maxSegmentBytes: 4096,
    maxBytes: 2600,
  });

  try {
    let doc = 'M'.repeat(900);
    const texts = new Map<string, string>();
    for (let seq = 1; seq <= 8; seq++) {
      now += 100;
      doc += `_${seq}`;
      texts.set(`synthetic-instance:${seq}`, doc);
      await store.append(makeEditorObservation(seq, doc, now));
      assert.ok(store.status().bytes <= 2600);
    }

    await store.close();
    // Reopening after tight budget evictions must succeed cleanly with zero dangling delta references.
    store = await SegmentStore.open({
      root: temp.root,
      keyProvider: temp.provider,
      clock: () => now,
      maxSegmentBytes: 4096,
      maxBytes: 2600,
    });
    const latest = await store.read('synthetic-instance:8');
    assert.ok(latest);
    assert.equal(latest.payload.kind, 'text.snapshot');
    assert.equal(latest.payload.text, texts.get('synthetic-instance:8'));
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('SegmentStore handles partial forget inside a delta chain cleanly across reopen without exposing dangling delta refs', async () => {
  const temp = await temporary();
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });

  try {
    const t1 = 'F'.repeat(300);
    const t2 = t1 + ' edited-2';
    const t3 = t2 + ' edited-3';
    // 3-frame chain in seg-00000001.cah: e1 (v1 keyframe) -> e2 (v2 delta -> e1) -> e3 (v2 delta -> e2).
    await store.append(makeEditorObservation(1, t1, NOW));
    await store.append(makeEditorObservation(2, t2, NOW + 5000));
    await store.append(makeEditorObservation(3, t3, NOW + 10_000));

    // Forget e1 (keyframe) while keeping e2 and e3 in seg-00000001.cah.
    await store.forget({ beforeMs: NOW + 2500 });

    const assertDeltaChainAfterPartialForget = async () => {
      assert.equal(await store.read('synthetic-instance:1'), null);
      assert.equal(((await store.read('synthetic-instance:2'))?.payload as TextSnapshot).text, t2);
      assert.equal(((await store.read('synthetic-instance:3'))?.payload as TextSnapshot).text, t3);

      // e2's baseEventId (e1) is forgotten -> e2 falls back to full text with no dangling delta entry.
      // e3's baseEventId (e2) is still live -> e3 stays a compact delta referencing e2.
      const deltaRes = await store.search({ kind: 'text', textView: 'delta' });
      assert.deepEqual(
        deltaRes.records.map((r) => r.eventId),
        ['synthetic-instance:2', 'synthetic-instance:3'],
      );
      assert.equal((deltaRes.records[0]!.payload as TextSnapshot).text, t2);
      assert.equal((deltaRes.records[1]!.payload as TextSnapshot).text, undefined);
      assert.ok(deltaRes.textDeltas);
      assert.deepEqual(Object.keys(deltaRes.textDeltas), ['synthetic-instance:3']);
      const e3Delta = deltaRes.textDeltas['synthetic-instance:3']!;
      assert.equal(e3Delta.baseEventId, 'synthetic-instance:2');
      assert.equal(applySingleSpanPatch(t2, e3Delta), t3);
      assert.equal(e3Delta.totalLength, t3.length);
    };

    await assertDeltaChainAfterPartialForget();

    // Reopen must materialize e2 and e3 from seg-00000001.cah cleanly and preserve exact textView='delta' behavior.
    await store.close();
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 12_000 });
    await assertDeltaChainAfterPartialForget();
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('SegmentStore fails closed with invalid-store on missing base, cross-segment base, out-of-bounds patch, dual-text v2, or invalid materialized observation', async () => {
  const cases: Array<{
    name: string;
    corrupt: (root: string, key: Buffer, storeId: string) => Promise<void>;
  }> = [
    {
      name: 'missing baseEventId in same segment',
      corrupt: async (root, key, storeId) => {
        const obs = makeEditorObservation(1, 'A'.repeat(200), NOW);
        const { text: _omitted, ...payloadNoText } = obs.payload as TextSnapshot;
        const frame = encryptRawFrame(
          {
            version: 2,
            encoding: 'text-patch-v1',
            inputHash: sha256Hex(canonicalJson(obs)),
            receivedAtMs: NOW,
            baseEventId: 'synthetic-instance:999',
            patch: { start: 0, deleteCount: 0, insert: '' },
            record: { ...obs, payload: payloadNoText },
          },
          key,
          storeId,
          1,
          0,
        );
        await writeFile(join(root, 'seg-00000001.cah'), Buffer.concat([encodeSegmentHeader(1, NOW), frame]), {
          mode: 0o600,
        });
      },
    },
    {
      name: 'cross-segment baseEventId (seg-2 referencing seg-1)',
      corrupt: async (root, key, storeId) => {
        const obs2 = makeEditorObservation(2, 'A'.repeat(200) + 'x', NOW + 100);
        const { text: _omitted, ...payloadNoText } = obs2.payload as TextSnapshot;
        const frame = encryptRawFrame(
          {
            version: 2,
            encoding: 'text-patch-v1',
            inputHash: sha256Hex(canonicalJson(obs2)),
            receivedAtMs: NOW + 100,
            baseEventId: 'synthetic-instance:1',
            patch: { start: 200, deleteCount: 0, insert: 'x' },
            record: { ...obs2, payload: payloadNoText },
          },
          key,
          storeId,
          2,
          0,
        );
        await writeFile(join(root, 'seg-00000002.cah'), Buffer.concat([encodeSegmentHeader(2, NOW + 100), frame]), {
          mode: 0o600,
        });
      },
    },
    {
      name: 'out-of-bounds patch',
      corrupt: async (root, key, storeId) => {
        const obs1 = makeEditorObservation(1, 'A'.repeat(200), NOW);
        const obs2 = makeEditorObservation(2, 'A'.repeat(200) + 'x', NOW + 100);
        const { text: _omitted, ...payloadNoText } = obs2.payload as TextSnapshot;
        const f0 = encryptRawFrame(
          { version: 1, inputHash: sha256Hex(canonicalJson(obs1)), receivedAtMs: NOW, record: obs1 },
          key,
          storeId,
          1,
          0,
        );
        const f1 = encryptRawFrame(
          {
            version: 2,
            encoding: 'text-patch-v1',
            inputHash: sha256Hex(canonicalJson(obs2)),
            receivedAtMs: NOW + 100,
            baseEventId: 'synthetic-instance:1',
            patch: { start: 5000, deleteCount: 0, insert: 'x' },
            record: { ...obs2, payload: payloadNoText },
          },
          key,
          storeId,
          1,
          1,
        );
        await writeFile(join(root, 'seg-00000001.cah'), Buffer.concat([encodeSegmentHeader(1, NOW), f0, f1]), {
          mode: 0o600,
        });
      },
    },
    {
      name: 'materialized observation fails protocol validation (range mismatch)',
      corrupt: async (root, key, storeId) => {
        const obs1 = makeEditorObservation(1, 'A'.repeat(200), NOW);
        const obs2 = makeEditorObservation(2, 'A'.repeat(200) + 'x', NOW + 100);
        const { text: _omitted, ...payloadNoText } = obs2.payload as TextSnapshot;
        // Patch yields 205 chars while obs2.payload.range.length is 201 -> validateMessage rejects!
        const f0 = encryptRawFrame(
          { version: 1, inputHash: sha256Hex(canonicalJson(obs1)), receivedAtMs: NOW, record: obs1 },
          key,
          storeId,
          1,
          0,
        );
        const f1 = encryptRawFrame(
          {
            version: 2,
            encoding: 'text-patch-v1',
            inputHash: sha256Hex(canonicalJson(obs2)),
            receivedAtMs: NOW + 100,
            baseEventId: 'synthetic-instance:1',
            patch: { start: 200, deleteCount: 0, insert: 'xxxxx' },
            record: { ...obs2, payload: payloadNoText },
          },
          key,
          storeId,
          1,
          1,
        );
        await writeFile(join(root, 'seg-00000001.cah'), Buffer.concat([encodeSegmentHeader(1, NOW), f0, f1]), {
          mode: 0o600,
        });
      },
    },
    {
      name: 'v2 frame illegally includes payload.text on disk',
      corrupt: async (root, key, storeId) => {
        const obs1 = makeEditorObservation(1, 'A'.repeat(200), NOW);
        const obs2 = makeEditorObservation(2, 'A'.repeat(200) + 'x', NOW + 100);
        const f0 = encryptRawFrame(
          { version: 1, inputHash: sha256Hex(canonicalJson(obs1)), receivedAtMs: NOW, record: obs1 },
          key,
          storeId,
          1,
          0,
        );
        const f1 = encryptRawFrame(
          {
            version: 2,
            encoding: 'text-patch-v1',
            inputHash: sha256Hex(canonicalJson(obs2)),
            receivedAtMs: NOW + 100,
            baseEventId: 'synthetic-instance:1',
            patch: { start: 200, deleteCount: 0, insert: 'x' },
            record: obs2,
          },
          key,
          storeId,
          1,
          1,
        );
        await writeFile(join(root, 'seg-00000001.cah'), Buffer.concat([encodeSegmentHeader(1, NOW), f0, f1]), {
          mode: 0o600,
        });
      },
    },
  ];

  for (const tc of cases) {
    const temp = await temporary();
    try {
      const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
      await store.append(makeEditorObservation(1, 'A'.repeat(200), NOW));
      const storeId = store.storeId;
      await store.close();

      await tc.corrupt(temp.root, temp.key, storeId);

      await assert.rejects(
        SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 200 }),
        expectStorageCode('invalid-store'),
        `expected invalid-store for case: ${tc.name}`,
      );
    } finally {
      await temp.cleanup();
    }
  }
});

test('SegmentStore stays backward compatible with legacy v1-only full frames on disk', async () => {
  const temp = await temporary();
  try {
    let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
    const storeId = store.storeId;
    await store.close();

    // Write two pure v1 full frames directly (simulating pre-delta segment files on disk).
    const obs1 = makeEditorObservation(1, 'V'.repeat(200), NOW);
    const obs2 = makeEditorObservation(2, 'V'.repeat(200) + ' v1-edit', NOW + 100);
    const f0 = encryptRawFrame(
      { version: 1, inputHash: sha256Hex(canonicalJson(obs1)), receivedAtMs: NOW, record: obs1 },
      temp.key,
      storeId,
      1,
      0,
    );
    const f1 = encryptRawFrame(
      { version: 1, inputHash: sha256Hex(canonicalJson(obs2)), receivedAtMs: NOW + 100, record: obs2 },
      temp.key,
      storeId,
      1,
      1,
    );
    await writeFile(join(temp.root, 'seg-00000001.cah'), Buffer.concat([encodeSegmentHeader(1, NOW), f0, f1]), {
      mode: 0o600,
    });

    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 200 });
    try {
      assert.equal(store.status().records, 2);
      const res = await store.search({ kind: 'text', textView: 'delta' });
      assert.equal(res.records.length, 2);
      assert.equal((res.records[0]!.payload as TextSnapshot).text, 'V'.repeat(200));
      assert.equal((res.records[1]!.payload as TextSnapshot).text, 'V'.repeat(200) + ' v1-edit');
      assert.equal(res.textDeltas, undefined);
    } finally {
      await store.close();
    }
  } finally {
    await temp.cleanup();
  }
});

test('textView full (default) vs delta, cursor isolation, and full assembly over MCP and REST APIs', async () => {
  const temp = await temporary();
  let now = NOW;

  // Seed real SegmentStore with 1 keyframe + 12 incremental 1000-char edits + 1 exception gap + 1 discarded gap.
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => now });
  const expectedByEventId = new Map<string, string>();
  let doc = 'PREFIX-ANCHOR-' + 'D'.repeat(986);
  try {
    for (let seq = 1; seq <= 13; seq++) {
      now += 100;
      if (seq > 1) doc += seq === 7 ? ' PATCH-NEEDLE-7' : ` edit-${seq}`;
      const obs = makeEditorObservation(seq, doc, now);
      expectedByEventId.set(obs.eventId, doc);
      await store.append(obs);
    }
    const excGap = observation(14, '', now + 100);
    excGap.target = { kind: 'unresolved', reason: 'policy-boundary' };
    excGap.payload = { kind: 'gap', reason: 'timeout', count: 1, diagnostic: { code: 'read-deadline' } };
    await store.append(excGap);

    const discGap = observation(15, '', now + 200);
    discGap.target = { kind: 'unresolved', reason: 'policy-boundary' };
    discGap.payload = { kind: 'gap', reason: 'stale', count: 1, diagnostic: { code: 'focus-changed' } };
    await store.append(discGap);

    // Direct SegmentStore textView behavior + cursor fingerprint isolation.
    const fullRes = await store.search({ kind: 'text', limit: 20 });
    assert.equal(fullRes.records.length, 13);
    assert.equal(fullRes.textDeltas, undefined);
    for (const rec of fullRes.records) {
      assert.equal((rec.payload as TextSnapshot).text, expectedByEventId.get(rec.eventId));
    }

    const deltaRes = await store.search({ kind: 'text', textView: 'delta', limit: 20 });
    assert.equal(deltaRes.records.length, 13);
    assert.ok(deltaRes.textDeltas);
    assert.equal(Object.keys(deltaRes.textDeltas).length, 12);
    assert.ok(
      deltaRes.bytes < fullRes.bytes * 0.65,
      `delta bytes ${deltaRes.bytes} should save >35% over full ${fullRes.bytes}`,
    );

    // Under a tight byte budget (16 KB), textView='delta' returns all 13 edits while textView='full' truncates.
    const tightFull = await store.search({ kind: 'text', textView: 'full', limit: 20, maxBytes: 16 * 1024 });
    const tightDelta = await store.search({ kind: 'text', textView: 'delta', limit: 20, maxBytes: 16 * 1024 });
    assert.ok(tightFull.records.length < 13 && tightFull.hasMore);
    assert.equal(tightDelta.records.length, 13);
    assert.equal(tightDelta.hasMore, false);

    // Keyframe retains full text; patched records elide payload.text and reconstruct identically via textDeltas.
    const assembled = new Map<string, string>();
    for (const rec of deltaRes.records) {
      const snap = rec.payload as TextSnapshot;
      const patchMeta: HistoryTextDelta | undefined = deltaRes.textDeltas[rec.eventId];
      if (!patchMeta) {
        assert.equal(typeof snap.text, 'string');
        assembled.set(rec.eventId, snap.text!);
      } else {
        assert.equal(snap.text, undefined);
        const baseText = assembled.get(patchMeta.baseEventId);
        assert.equal(typeof baseText, 'string');
        const nextText = applySingleSpanPatch(baseText!, patchMeta);
        assert.equal(nextText, expectedByEventId.get(rec.eventId));
        assert.equal(nextText!.length, patchMeta.totalLength);
        assembled.set(rec.eventId, nextText!);
      }
    }

    // Cursor minted under textView='full' cannot be reused with textView='delta' (and vice versa).
    const fullPage1 = await store.search({ kind: 'text', textView: 'full', limit: 5 });
    const deltaPage1 = await store.search({ kind: 'text', textView: 'delta', limit: 5 });
    assert.ok(fullPage1.nextCursor);
    assert.ok(deltaPage1.nextCursor);
    await assert.rejects(
      store.search({ kind: 'text', textView: 'delta', limit: 5, cursor: fullPage1.nextCursor }),
      expectStorageCode('invalid-cursor'),
    );
    await assert.rejects(
      store.search({ kind: 'text', textView: 'full', limit: 5, cursor: deltaPage1.nextCursor }),
      expectStorageCode('invalid-cursor'),
    );
    const deltaPage2 = await store.search({ kind: 'text', textView: 'delta', limit: 5, cursor: deltaPage1.nextCursor });
    assert.equal(deltaPage2.records.length, 5);
    assert.ok(deltaPage2.textDeltas && Object.keys(deltaPage2.textDeltas).length === 5);

    // Substring search paired with textView='delta' must match full materialized text:
    // (a) substring only in unchanged prefix (absent from every patch.insert) matches all 13 records.
    const prefixSearch = await store.search({ text: 'PREFIX-ANCHOR', kind: 'text', textView: 'delta', limit: 20 });
    assert.equal(prefixSearch.records.length, 13);
    assert.ok(prefixSearch.textDeltas);
    assert.equal(Object.keys(prefixSearch.textDeltas).length, 12);
    assert.equal((prefixSearch.records[0]!.payload as TextSnapshot).text, expectedByEventId.get('synthetic-instance:1'));
    for (const rec of prefixSearch.records.slice(1)) {
      assert.equal((rec.payload as TextSnapshot).text, undefined);
      assert.equal(prefixSearch.textDeltas[rec.eventId]!.insert.includes('PREFIX-ANCHOR'), false);
    }
    // (b) substring introduced in patch.insert of seq 7 matches seq 7..13, eliding payload.text on all patched hits.
    const patchSearch = await store.search({ text: 'PATCH-NEEDLE-7', kind: 'text', textView: 'delta', limit: 20 });
    assert.deepEqual(
      patchSearch.records.map((r) => r.eventId),
      [
        'synthetic-instance:7',
        'synthetic-instance:8',
        'synthetic-instance:9',
        'synthetic-instance:10',
        'synthetic-instance:11',
        'synthetic-instance:12',
        'synthetic-instance:13',
      ],
    );
    assert.ok(patchSearch.textDeltas);
    assert.equal(Object.keys(patchSearch.textDeltas).length, 7);
    assert.equal(patchSearch.textDeltas['synthetic-instance:7']!.insert, ' PATCH-NEEDLE-7');
    for (const rec of patchSearch.records) {
      assert.equal((rec.payload as TextSnapshot).text, undefined);
    }

    // store.read(id) ALWAYS returns full assembled text even for patched records.
    const readPatched = await store.read('synthetic-instance:13');
    assert.equal((readPatched?.payload as TextSnapshot).text, expectedByEventId.get('synthetic-instance:13'));
  } finally {
    await store.close();
  }

  // Now mount the exact same encrypted store via HistoryService + HTTP/MCP server.
  const service = createHistoryService({
    dataRoot: temp.root,
    keyProvider: temp.provider,
    retentionMs: 365 * 24 * 60 * 60 * 1000 * 100, // Keep synthetic NOW timestamp active under real clock.
  });
  const srv = await startHttpServer({ dataDir: temp.root, port: 0, service });

  try {
    const { token } = await srv.authStore.createLease({ label: 'delta-reader', scopes: ['read'], ttlMs: null });
    const mcpCall = async (name: string, args: Record<string, unknown>) => {
      const res = await fetch(srv.mcpUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: `${name}-${Math.random()}`,
          method: 'tools/call',
          params: { name, arguments: args },
        }),
      });
      assert.equal(res.status, 200);
      const body = (await res.json()) as {
        result?: { content?: Array<{ text: string }>; isError?: boolean };
        error?: { code: number; message: string };
      };
      return body;
    };

    // 1. MCP history_search default textView='full' returns complete text on all records.
    const mcpFull = await mcpCall('history_search', { kind: 'text', limit: 20 });
    const mcpFullData = JSON.parse(mcpFull.result!.content![0]!.text) as HistoryQueryResult;
    assert.equal(mcpFullData.records.length, 13);
    assert.equal(mcpFullData.textDeltas, undefined);
    assert.equal((mcpFullData.records[12]!.payload as TextSnapshot).text, expectedByEventId.get('synthetic-instance:13'));

    // 2. MCP history_search with textView='delta' returns compact textDeltas with payload.text elided.
    const mcpDelta = await mcpCall('history_search', { kind: 'text', textView: 'delta', limit: 20 });
    const mcpDeltaData = JSON.parse(mcpDelta.result!.content![0]!.text) as HistoryQueryResult;
    assert.equal(mcpDeltaData.records.length, 13);
    assert.ok(mcpDeltaData.textDeltas);
    assert.equal(Object.keys(mcpDeltaData.textDeltas).length, 12);
    assert.equal((mcpDeltaData.records[0]!.payload as TextSnapshot).text, expectedByEventId.get('synthetic-instance:1'));
    assert.equal((mcpDeltaData.records[12]!.payload as TextSnapshot).text, undefined);
    assert.ok(mcpDeltaData.bytes < mcpFullData.bytes * 0.65);

    // 3. MCP history_read ALWAYS returns full backend-assembled text.
    const mcpRead = await mcpCall('history_read', { id: 'synthetic-instance:13' });
    const mcpReadData = JSON.parse(mcpRead.result!.content![0]!.text) as { found: boolean; record: Observation };
    assert.equal(mcpReadData.found, true);
    assert.equal((mcpReadData.record.payload as TextSnapshot).text, expectedByEventId.get('synthetic-instance:13'));

    // 4. MCP history_search rejects invalid textView with JSON-RPC -32602.
    const mcpBadView = await mcpCall('history_search', { kind: 'text', textView: 'compact' });
    assert.equal(mcpBadView.error?.code, -32602);

    // 5. MCP history_search supports kind='exception' and kind='discarded'.
    const mcpExc = await mcpCall('history_search', { kind: 'exception' });
    const mcpExcData = JSON.parse(mcpExc.result!.content![0]!.text) as HistoryQueryResult;
    assert.deepEqual(
      mcpExcData.records.map((r) => r.eventId),
      ['synthetic-instance:14'],
    );
    const mcpDisc = await mcpCall('history_search', { kind: 'discarded' });
    const mcpDiscData = JSON.parse(mcpDisc.result!.content![0]!.text) as HistoryQueryResult;
    assert.deepEqual(
      mcpDiscData.records.map((r) => r.eventId),
      ['synthetic-instance:15'],
    );

    // 6. REST POST /api/history/search supports textView and kind='exception' | 'discarded', rejects invalid textView.
    const restHeaders = {
      Authorization: `Bearer ${srv.adminToken}`,
      'Content-Type': 'application/json',
    };
    const restDelta = (await (
      await fetch(`${srv.baseUrl}/api/history/search`, {
        method: 'POST',
        headers: restHeaders,
        body: JSON.stringify({ kind: 'text', textView: 'delta', limit: 20 }),
      })
    ).json()) as HistoryQueryResult;
    assert.equal(Object.keys(restDelta.textDeltas ?? {}).length, 12);

    const restExc = (await (
      await fetch(`${srv.baseUrl}/api/history/search`, {
        method: 'POST',
        headers: restHeaders,
        body: JSON.stringify({ kind: 'exception' }),
      })
    ).json()) as HistoryQueryResult;
    assert.deepEqual(
      restExc.records.map((r) => r.eventId),
      ['synthetic-instance:14'],
    );

    const restBadView = await fetch(`${srv.baseUrl}/api/history/search`, {
      method: 'POST',
      headers: restHeaders,
      body: JSON.stringify({ kind: 'text', textView: 'invalid' }),
    });
    assert.equal(restBadView.status, 400);
  } finally {
    await srv.close();
    await temp.cleanup();
  }
});

test('SegmentStore isolates interleaved multi-target delta chains and compresses text.changed observations', async () => {
  const temp = await temporary();
  let now = NOW;
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => now });

  try {
    const docA1 = 'A'.repeat(400);
    const docB1 = 'B'.repeat(400);
    const docA2 = docA1 + ' alpha-edit';
    const docB2 = docB1 + ' beta-edit';

    await store.append(makeEditorObservation(1, docA1, now + 10, 'node-A'));
    await store.append(makeEditorObservation(2, docB1, now + 20, 'node-B'));
    // Interleaved text.changed on node-A referencing snap-1.
    const changedA2: Observation = {
      ...makeEditorObservation(3, docA2, now + 30, 'node-A'),
      payload: {
        kind: 'text.changed',
        baseSnapshotId: 'synthetic-snapshot-1',
        after: {
          ...(makeEditorObservation(3, docA2, now + 30, 'node-A').payload as TextSnapshot),
        },
      },
    };
    await store.append(changedA2);
    await store.append(makeEditorObservation(4, docB2, now + 40, 'node-B'));

    const storeId = store.storeId;
    await store.close();

    const frames = await decryptSegmentFrames(join(temp.root, 'seg-00000001.cah'), temp.key, storeId, 1);
    assert.equal(frames.length, 4);
    assert.equal(frames[0]!.version, 1);
    assert.equal(frames[1]!.version, 1);
    assert.equal(frames[2]!.version, 2);
    assert.equal(frames[2]!.baseEventId, 'synthetic-instance:1');
    assert.equal(frames[2]!.materializedBase, 'synthetic-snapshot-1');
    assert.equal(frames[3]!.version, 2);
    assert.equal(frames[3]!.baseEventId, 'synthetic-instance:2');

    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => now + 50 });
    assert.equal(((await store.read('synthetic-instance:3'))?.payload as TextSnapshot).text, docA2);
    assert.equal(((await store.read('synthetic-instance:4'))?.payload as TextSnapshot).text, docB2);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

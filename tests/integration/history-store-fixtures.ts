import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import type { Observation } from '../../src/shared/protocol/generated.ts';
import { MemoryKeyProvider } from '../../src/storage/key-provider.ts';
import type { KeyProvider } from '../../src/storage/key-provider.ts';

export const SECRET = 'SYNTHETIC-ONLY-中文正文-秘密-𠮷-c8f71';
export const APP = 'synthetic.private.application';
export const NOW = 1_700_000_100_000;

export function observation(seq = 1, text = SECRET, eventTimeMs = NOW): Observation {
  return {
    protocolVersion: 1,
    type: 'observation',
    eventId: `synthetic-instance:${seq}`,
    instanceId: 'synthetic-instance',
    seq,
    eventTimeMs,
    monotonicMs: seq,
    target: {
      kind: 'resolved',
      identity: {
        deviceId: 'synthetic-device',
        osSessionId: 'synthetic-session',
        desktopId: 'synthetic-desktop',
        processId: 123,
        processStartTime: 'synthetic-start',
        applicationId: APP,
        windowId: 'synthetic-private-window',
        windowGeneration: 1,
      },
    },
    stamp: { captureEpoch: 1, focusGeneration: 1, foregroundGeneration: 1, policyRevision: 1 },
    actor: 'unknown',
    relatedActionIds: [],
    payload: {
      kind: 'text.snapshot',
      snapshotId: `synthetic-snapshot-${seq}`,
      editSessionId: 'synthetic-edit',
      nodeId: 'synthetic-node',
      source: 'fixture',
      scope: 'field',
      valueState: 'read',
      text,
      range: { unit: 'utf16', start: 0, length: text.length },
      totalLength: text.length,
      composition: 'unknown',
      captureStartMs: eventTimeMs,
      captureEndMs: eventTimeMs,
      coverage: { status: 'complete', truncated: false, missingReasons: [] },
    },
  };
}

export async function temporary(): Promise<{
  parent: string;
  root: string;
  provider: KeyProvider;
  key: Buffer;
  cleanup(): Promise<void>;
}> {
  const base = await realpath(tmpdir());
  const parent = await mkdtemp(join(base, 'camcp-history-synthetic-'));
  const root = join(parent, 'data');
  const key = randomBytes(32);
  const provider = new MemoryKeyProvider(key);
  return {
    parent,
    root,
    key,
    provider,
    async cleanup() {
      assert.equal(resolve(parent), parent);
      assert.equal(dirname(parent), base);
      assert.ok(parent.startsWith(join(base, 'camcp-history-synthetic-')));
      assert.equal(await realpath(parent), parent);
      await provider.deleteKey();
      await rm(parent, { recursive: true, force: false });
      key.fill(0);
    },
  };
}

export function code(expected: string): (error: unknown) => boolean {
  return (error) => {
    assert.ok(error instanceof Error);
    assert.equal((error as Error & { code?: string }).code, expected);
    assert.equal(error.cause, undefined);
    assert.ok(!error.message.includes(SECRET));
    return true;
  };
}

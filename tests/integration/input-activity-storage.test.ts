import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { SegmentStore } from '../../src/storage/segment-store.ts';
import { activityObservation, activityIdentity } from './input-activity-fixtures.ts';
import { NOW, temporary, observation } from './history-store-fixtures.ts';

test('application counts persist encrypted, query by category and application, reopen and Forget without text index confusion', async () => {
  const temp = await temporary();
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 2000 });
  try {
    const app = 'synthetic.activity.only';
    const activity = activityObservation(1, undefined, 'synthetic-activity', NOW);
    activity.target = { kind: 'application', identity: activityIdentity({ applicationId: app }) };
    await store.append(activity, { generation: store.generation });
    await store.append(observation(1, '普通文本', NOW + 1500), { generation: store.generation });
    assert.equal(store.status().counts.activity, 1);
    assert.equal(store.status().counts.text, 1);
    assert.equal(store.status().records, 2);
    const page = await store.search({ kind: 'activity', applicationId: app });
    assert.equal(page.records.length, 1);
    assert.equal(page.bytes, Buffer.byteLength(JSON.stringify(page)));
    assert.deepEqual((await store.search({ kind: 'text', applicationId: app })).records, []);
    assert.deepEqual((await store.search({ kind: 'activity', text: 'pointerReleases' })).records, []);
    for (const name of await readdir(temp.root)) {
      const bytes = await readFile(join(temp.root, name));
      for (const plaintext of [app, 'pointerReleases', 'event-target-pid']) {
        assert.equal(bytes.includes(Buffer.from(plaintext)), false);
      }
    }
    await store.close();
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 2000 });
    assert.deepEqual((await store.search({ kind: 'activity' })).records, [activity]);
    await store.forget({ all: true });
    assert.equal(store.status().counts.activity, 0);
    assert.equal((await store.search({ kind: 'activity' })).records.length, 0);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

test('capped activity coverage stays truncated across bounded pagination', async () => {
  const temp = await temporary();
  const store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW + 3000 });
  try {
    const first = activityObservation(1, undefined, 'synthetic-activity', NOW);
    const second = activityObservation(2, undefined, 'synthetic-activity', NOW + 1000);
    if (first.payload.kind !== 'input.activity') throw Error('fixture');
    first.payload.coverage.truncated = true;
    first.payload.coverage.missingReasons.push('input-events-capped');
    await store.append(first, { generation: store.generation });
    await store.append(second, { generation: store.generation });
    const page = await store.search({ kind: 'activity', limit: 1 });
    assert.equal(page.truncated, true);
    assert.ok(page.nextCursor);
    const rest = await store.search({ kind: 'activity', limit: 1, cursor: page.nextCursor! });
    assert.deepEqual(rest.records, [second]);
    assert.equal(rest.hasMore, false);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

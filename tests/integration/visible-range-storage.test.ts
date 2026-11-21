import test from 'node:test';
import assert from 'node:assert/strict';
import { SegmentStore } from '../../src/storage/segment-store.ts';
import { NOW, temporary, observation } from './history-store-fixtures.ts';

test('visible range absolute UTF16 offsets and partial coverage survive encrypted reopen and Forget', async () => {
  const temp = await temporary();
  let store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
  try {
    const event = observation();
    if (event.payload.kind !== 'text.snapshot') throw Error('fixture');
    event.payload = {
      ...event.payload,
      rangeBasis: 'visible',
      text: '尾部𠮷',
      range: { unit: 'utf16', start: 1234, length: 4 },
      selection: { unit: 'utf16', start: 1236, length: 2 },
      totalLength: 2000,
      scope: 'accessible-range',
      source: 'fixture',
      coverage: { status: 'partial', truncated: false, missingReasons: ['visible-range-only'] },
    };
    await store.append(event, { generation: store.generation });
    await store.close();
    store = await SegmentStore.open({ root: temp.root, keyProvider: temp.provider, clock: () => NOW });
    const result = await store.search({ text: '尾部', kind: 'text' });
    assert.deepEqual(result.records, [event]);
    assert.equal(result.truncated, false);
    assert.deepEqual(await store.read(event.eventId), event);
    await store.forget({ all: true });
    assert.deepEqual((await store.search()).records, []);
  } finally {
    await store.close();
    await temp.cleanup();
  }
});

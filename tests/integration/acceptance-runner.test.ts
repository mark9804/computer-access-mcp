import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../../scripts/test-acceptance.mjs', import.meta.url));

test('acceptance runner refuses unknown or duplicated flags without starting work', () => {
  for (const args of [['--all'], ['--plan', '--plan']]) {
    const result = spawnSync(process.execPath, [script, ...args], {
      encoding: 'utf8', env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, timeout: 3000,
    });
    assert.equal(result.status, 64);
    assert.equal(result.stdout, '');
  }
});

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const locales = await Promise.all(
  ['en', 'zh'].map(
    async (language) =>
      JSON.parse(await readFile(new URL(`../locale/${language}.json`, import.meta.url), 'utf8')).ui,
  ),
);
assert.deepEqual(Object.keys(locales[0]).sort(), Object.keys(locales[1]).sort(), 'locale-key-parity');
for (const locale of locales) {
  for (const [key, value] of Object.entries(locale)) {
    assert.ok(typeof value === 'string' && value.length > 0, `invalid-locale-message:${key}`);
  }
}
const moduleSource = await readFile(new URL('../src/web/i18n.ts', import.meta.url), 'utf8');
for (const language of ['en', 'zh']) {
  assert.ok(moduleSource.includes(`../../locale/${language}.json`), 'canonical-locale-import-required');
}
console.log(`Web locale resources checked (${Object.keys(locales[0]).length} keys).`);

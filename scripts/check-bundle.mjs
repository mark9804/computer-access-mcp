import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
assert.equal(manifest.name, 'computer-access-mcp');
assert.equal(manifest.bin?.['computer-access-mcp'], './dist/server/cli.js');
assert.equal(manifest.dsh, undefined);
assert.equal(manifest.scripts.install, undefined);
assert.equal(manifest.scripts.postinstall, undefined);

for (const [subpath, target] of Object.entries(manifest.exports)) {
  assert.equal(typeof target?.types, 'string', `missing types export for ${subpath}`);
  assert.equal(typeof target?.default, 'string', `missing default export for ${subpath}`);
  for (const rel of [target.types, target.default]) {
    const stat = await lstat(join(root, rel));
    assert.ok(stat.isFile() && !stat.isSymbolicLink(), `invalid export target: ${rel}`);
  }
}

const requiredFiles = [
  'dist/server/cli.js',
  'dist/server/http-server.js',
  'dist/server/layout-guides.js',
  'dist/server/mcp-handler.js',
  'dist/server/stdio-proxy.js',
  'dist/server/auth-store.js',
  'layout-guides/_generic.md',
  'layout-guides/qq.md',
  'layout-guides/feishu.md',
  'layout-guides/wechat.md',
  'layout-guides/slack.md',
  'dist/host/service/history-service.js',
  'dist/storage/segment-store.js',
  'dist/storage/storage-lock.js',
  'dist/shared/api-types.d.ts',
  'dist/shared/protocol/generated.d.ts',
  'dist/shared/protocol/wire.schema.json',
  'dist/web/index.html',
  'dist/web/app.js',
  'dist/web/styles.css',
  'dist/web/icon.svg',
  'dist/web/bundle.meta.json',
  'dist/web/THIRD_PARTY_NOTICES.txt',
  'src/web/NOTICE.md',
  'src/web/SHADCN_LICENSE.txt',
  'locale/en.json',
  'locale/zh.json',
  'icon.svg',
];

for (const rel of requiredFiles) {
  const stat = await lstat(join(root, rel));
  assert.ok(stat.isFile() && !stat.isSymbolicLink(), `missing or unsafe bundle file: ${rel}`);
}

const cliPath = join(root, 'dist/server/cli.js');
const cliText = await readFile(cliPath, 'utf8');
assert.ok(cliText.startsWith('#!/usr/bin/env node\n'), 'cli.js must start with node shebang');
if (process.platform !== 'win32') {
  const cliStat = await lstat(cliPath);
  assert.notEqual(cliStat.mode & 0o111, 0, 'dist/server/cli.js must be executable');
}

for (const language of ['en', 'zh']) {
  const locale = JSON.parse(await readFile(join(root, `locale/${language}.json`), 'utf8'));
  assert.equal(typeof locale.meta?.title, 'string');
  assert.equal(typeof locale.ui?.appTitle, 'string');
  assert.ok(locale.ui.appTitle.length > 0);
}

const icon = await readFile(join(root, 'icon.svg'), 'utf8');
assert.ok(Buffer.byteLength(icon) <= 256 * 1024);
assert.match(icon, /<svg\b/);
assert.doesNotMatch(icon, /<(?:script|foreignObject|image|style|text)\b|on\w+\s*=/i);

for (const rel of ['dist/server/cli.js', 'dist/web/app.js']) {
  const result = spawnSync(process.execPath, ['--check', join(root, rel)], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
}

const addonRel = 'native-bin/computer-access-storage-lock.node';
const addonStat = await lstat(join(root, addonRel));
assert.ok(addonStat.isFile() && !addonStat.isSymbolicLink() && addonStat.nlink === 1 && addonStat.size <= 2 * 1024 * 1024);
assert.ok(manifest.files.includes('native-bin'));
for (const notice of ['native/storage-lock/LICENSE.node', 'native/storage-lock/README.md']) {
  assert.ok(manifest.files.includes(notice));
  assert.ok((await lstat(join(root, notice))).isFile());
}

const lockModule = await import(pathToFileURL(join(root, 'dist/storage/storage-lock.js')).href);
const nativeLock = await lockModule.loadNativeStorageLock();
assert.equal(typeof nativeLock.tryLock, 'function');
assert.equal(typeof nativeLock.unlock, 'function');

const appJs = await readFile(join(root, 'dist/web/app.js'));
const stylesCss = await readFile(join(root, 'dist/web/styles.css'));
const thirdPartyNotices = await readFile(join(root, 'dist/web/THIRD_PARTY_NOTICES.txt'), 'utf8');
const webMeta = JSON.parse(await readFile(join(root, 'dist/web/bundle.meta.json'), 'utf8'));

assert.equal(webMeta.appJsSha256, sha256(appJs));
assert.equal(webMeta.stylesCssSha256, sha256(stylesCss));
assert.equal(webMeta.noticesSha256, sha256(thirdPartyNotices));
assert.ok(webMeta.packages.some((item) => item.name === '@base-ui/react' && item.version === '1.9.0'));

console.log('PASS: package exports, CLI executable, web bundle metadata, locales, SVG, JS syntax, and native storage lock verified.');

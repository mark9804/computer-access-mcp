import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const outputDirectory = resolve(root, 'dist/web');
const hash = (value) => createHash('sha256').update(value).digest('hex');
const portable = (value) => value.split(sep).join('/');

const jsResult = await build({
  absWorkingDir: root,
  entryPoints: ['src/web/main.tsx'],
  outfile: resolve(outputDirectory, 'app.js'),
  tsconfig: resolve(root, 'tsconfig.client.json'),
  bundle: true,
  write: false,
  platform: 'browser',
  target: ['es2022'],
  format: 'iife',
  jsx: 'automatic',
  define: { 'process.env.NODE_ENV': '"production"' },
  minify: true,
  legalComments: 'eof',
  metafile: true,
});

const cssResult = await build({
  absWorkingDir: root,
  entryPoints: ['src/web/styles.css'],
  outfile: resolve(outputDirectory, 'styles.css'),
  bundle: true,
  write: false,
  minify: true,
});

assert.equal(jsResult.outputFiles.length, 1, 'expected-single-js-bundle');
assert.equal(cssResult.outputFiles.length, 1, 'expected-single-css-bundle');

for (const input of Object.keys(jsResult.metafile.inputs)) {
  assert.ok(!input.includes('wire.schema.json'), `forbidden-schema-import:${input}`);
  assert.ok(!input.includes('@deepseek-ai/'), `forbidden-dsh-import:${input}`);
}

const packages = new Map();
for (const input of Object.keys(jsResult.metafile.inputs)) {
  const parts = portable(input).split('/');
  const index = parts.lastIndexOf('node_modules');
  if (index < 0) continue;
  const name = parts[index + 1]?.startsWith('@')
    ? `${parts[index + 1]}/${parts[index + 2]}`
    : parts[index + 1];
  assert.ok(name && name !== '.pnpm', `unexpected-node-modules-entry:${input}`);
  let directory = dirname(await realpath(resolve(root, input)));
  for (;;) {
    let metadata;
    try {
      metadata = JSON.parse(await readFile(resolve(directory, 'package.json'), 'utf8'));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (typeof metadata?.name === 'string') {
      assert.equal(metadata.name, name);
      const location = portable(relative(root, directory));
      if (!packages.has(location)) {
        packages.set(location, {
          root: location,
          name,
          version: metadata.version,
          license: metadata.license,
          inputs: [],
        });
      }
      packages.get(location).inputs.push(input);
      break;
    }
    const parent = dirname(directory);
    assert.notEqual(parent, directory, 'dependency-manifest-missing');
    directory = parent;
  }
}

assert.ok(
  [...packages.values()].some((item) => item.name === '@base-ui/react'),
  'base-ui-package-expected',
);

let notices = 'Computer Access MCP Web Control Panel Third-Party Notices\n\n';
const licenses = [];
const addNotice = (origin, text) => {
  assert.ok(text.trim(), `empty-license:${origin}`);
  notices += `=== ${origin} ===\n${text}\n\n`;
  return { origin, sha256: hash(text) };
};

for (const file of ['src/web/NOTICE.md', 'src/web/SHADCN_LICENSE.txt']) {
  licenses.push(addNotice(file, await readFile(resolve(root, file), 'utf8')));
}

for (const item of [...packages.values()].sort((a, b) => a.name.localeCompare(b.name))) {
  const directory = resolve(root, item.root);
  const files = (await readdir(directory, { withFileTypes: true }))
    .filter((file) => file.isFile() && /^(?:licen[cs]e|copying|notice)(?:$|[._-])/i.test(file.name))
    .map((file) => file.name)
    .sort();
  assert.ok(files.length > 0, `missing-license:${item.name}`);
  for (const file of files) {
    licenses.push(
      addNotice(`${item.name}@${item.version}/${file}`, await readFile(resolve(directory, file), 'utf8')),
    );
  }
}

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

const jsBytes = jsResult.outputFiles[0].contents;
const cssBytes = cssResult.outputFiles[0].contents;
const htmlText = await readFile(resolve(root, 'src/web/index.html'), 'utf8');

await writeFile(resolve(outputDirectory, 'app.js'), jsBytes);
await writeFile(resolve(outputDirectory, 'styles.css'), cssBytes);
await writeFile(resolve(outputDirectory, 'index.html'), htmlText);
await cp(resolve(root, 'icon.svg'), resolve(outputDirectory, 'icon.svg'));
await writeFile(resolve(outputDirectory, 'THIRD_PARTY_NOTICES.txt'), notices);
await writeFile(
  resolve(outputDirectory, 'bundle.meta.json'),
  JSON.stringify(
    {
      version: 1,
      outputDir: 'dist/web',
      appJsSha256: hash(jsBytes),
      stylesCssSha256: hash(cssBytes),
      noticesSha256: hash(notices),
      packages: [...packages.values()],
      licenses,
    },
    null,
    2,
  ) + '\n',
);

console.log(
  `Web bundle built -> dist/web/ (app.js: ${jsBytes.byteLength} B, styles.css: ${cssBytes.byteLength} B).`,
);

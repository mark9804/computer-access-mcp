import { readdir, readFile, writeFile, lstat } from 'node:fs/promises';
import { dirname, join, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

// TypeScript rewrites runtime .ts specifiers, but keeps them in declarations.
// Publish declarations against emitted .js/.d.ts files, never workspace .ts files.
const output = resolve(dirname(fileURLToPath(import.meta.url)), '../dist');
let count = 0;
async function prepare(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) throw new Error('type-output-symlink');
    if (entry.isDirectory()) { await prepare(path); continue; }
    if (!entry.isFile() || !entry.name.endsWith('.d.ts')) continue;
    const text = await readFile(path, 'utf8');
    const updated = text.replace(/((?:from\s*|import\s*\(\s*)["'])(\.{1,2}\/[^"']+?)(\.tsx?)(["'])/g, (_match, prefix, target, _extension, suffix) => `${prefix}${target}.js${suffix}`);
    for (const match of updated.matchAll(/(?:from\s*|import\s*\(\s*)["'](\.{1,2}\/[^"']+\.js)["']/g)) {
      const target = resolve(dirname(path), match[1]);
      const inOutput = relative(output, target);
      if (inOutput.startsWith('..') || inOutput.startsWith('/')) throw new Error('type-reference-outside-dist');
      const declaration = target.slice(0, -3) + '.d.ts';
      const stat = await lstat(declaration).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
      if (!stat?.isFile() || stat.isSymbolicLink()) throw new Error(`missing-type-dependency:${inOutput}`);
    }
    if (updated !== text) await writeFile(path, updated);
    count++;
  }
}
await prepare(output);
console.log(`Prepared ${count} generated declaration files for package consumers.`);

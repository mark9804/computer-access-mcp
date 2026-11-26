import { spawnSync } from 'node:child_process';
import { cp, mkdir, lstat, writeFile, realpath } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
if (args.some((arg) => arg !== '--describe-visible-tree')) throw new Error('unknown-fixture-build-argument');
function swift(args) { const result = spawnSync('swift', args, { cwd: root, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }); if (result.status !== 0) { process.stderr.write(result.stderr); throw new Error('fixture-build-failed'); } return result.stdout.trim(); }
swift(['build', '--package-path', 'fixtures/macos/app']);
const source = join(swift(['build', '--package-path', 'fixtures/macos/app', '--show-bin-path']), 'computer-history-fixture');
if (args.includes('--describe-visible-tree')) {
  // Only the pre-NSApplication description branch runs; no .app is written/opened.
  const result = spawnSync(source, ['--describe-visible-tree'], { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 });
  if (result.status !== 0) { process.stderr.write(result.stderr); throw new Error('fixture-description-failed'); }
  process.stdout.write(result.stdout);
} else {
const app = join(root, 'native-bin', 'Computer History Fixture.app');
const executable = join(app, 'Contents', 'MacOS');
try { const stat = await lstat(app); if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('unsafe-fixture-bundle'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
await mkdir(executable, { recursive: true, mode: 0o700 });
if (await realpath(executable) !== executable) throw new Error('unsafe-fixture-bundle-ancestor');
const target = join(executable, 'computer-history-fixture');
try { const stat = await lstat(target); if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('unsafe-fixture-executable'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
await cp(source, target);
const plist = join(app, 'Contents', 'Info.plist');
try { const stat = await lstat(plist); if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('unsafe-fixture-plist'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
await writeFile(plist, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.dsh.computer-history.fixture</string>
<key>CFBundleName</key><string>Computer History Fixture</string>
<key>CFBundleExecutable</key><string>computer-history-fixture</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>15.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
`, { mode: 0o600 });
console.log('Built synthetic .app with explicit bundle ID. Not launched, signed, trusted or added to any allowlist.');
console.log('Optional visible-tree GUI: --synthetic-fixture --visible-tree-fixture (separate explicit GUI authorization required).');
console.log('Structure only: node scripts/build-fixture-app.mjs --describe-visible-tree (no NSApplication/AX client).');
}

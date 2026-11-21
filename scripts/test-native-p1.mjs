import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

const storageLockBuild = spawnSync(process.execPath, ['scripts/build-storage-lock.mjs'], { stdio: 'inherit' });
if (storageLockBuild.status !== 0) process.exit(storageLockBuild.status ?? 1);
for (const directory of ['collector', 'key-store']) {
  const result = spawnSync('swift', ['test', '--package-path', `native/macos/${directory}`], { stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
const build = spawnSync('swift', ['build', '--package-path', 'native/macos/collector', '--show-bin-path'], { encoding: 'utf8' });
if (build.status !== 0) { process.stderr.write(build.stderr); process.exit(build.status ?? 1); }
const helper = join(build.stdout.trim(), 'computer-access-collector');
const navigation = spawnSync('python3', ['scripts/test-source-navigation-negative.py', '--binary', helper], { stdio: 'inherit' });
if (navigation.status !== 0) process.exit(navigation.status ?? 1);
const processes = spawnSync('python3', ['native/macos/collector/Tests/fixture_process.py', helper], { stdio: 'inherit' });
if (processes.status !== 0) process.exit(processes.status ?? 1);
const result = spawnSync(process.execPath, ['--test', 'tests/integration/native-p1.test.ts'], { stdio: 'inherit', env: { ...process.env, DSH_TEST_FIXTURE_HELPER: helper } });
process.exit(result.status ?? 1);

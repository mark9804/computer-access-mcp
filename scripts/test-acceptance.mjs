import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Developer acceptance runner. Default runs offline contracts, storage, server, and native --fixture tests.
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const allowed = new Set([
  '--authorized-synthetic-ax',
  '--authorized-synthetic-multisource',
  '--authorized-synthetic-field-policy',
  '--authorized-synthetic-layout',
  '--plan',
  '--help',
]);
if (new Set(args).size !== args.length || args.some((arg) => !allowed.has(arg))) {
  console.error(
    'Usage: node scripts/test-acceptance.mjs [--plan] [--authorized-synthetic-ax] [--authorized-synthetic-multisource] [--authorized-synthetic-field-policy] [--authorized-synthetic-layout]',
  );
  process.exit(64);
}
if (args.includes('--help')) {
  console.log('Default: build and run offline contract, storage, server, supervisor, and native --fixture tests.');
  console.log('--authorized-synthetic-ax: run plain, empty, visible, async, and secure against the open synthetic fixture app.');
  console.log('--authorized-synthetic-multisource: run region/window, selection, synthetic input, and exclusion against the open fixture app.');
  console.log('--authorized-synthetic-field-policy: verify synthetic AXTextArea under strict/denylist and protected-content modes.');
  console.log('--authorized-synthetic-layout: verify real AX -> temporary SegmentStore -> layout projection against the open fixture app.');
  console.log('--plan: print stage names without executing.');
  process.exit(0);
}

const testFiles = ['contract', 'privacy', 'server', 'integration'].flatMap((dir) =>
  readdirSync(join(root, 'tests', dir))
    .filter((name) => name.endsWith('.test.ts'))
    .sort()
    .map((name) => `tests/${dir}/${name}`),
);

const stages = [
  ['protocol-resources', process.execPath, ['scripts/generate-protocol.mjs', '--check']],
  ['policy-resources', process.execPath, ['scripts/generate-policy.mjs', '--check']],
  ['locale-resources', process.execPath, ['scripts/sync-client-locales.mjs', '--check']],
  ['storage-lock-build', process.execPath, ['scripts/build-storage-lock.mjs']],
  ['typescript', process.execPath, ['node_modules/typescript/bin/tsc', '--noEmit']],
  ['client-typescript', process.execPath, ['node_modules/typescript/bin/tsc', '-p', 'tsconfig.client.json', '--noEmit']],
  ['client-bundle', process.execPath, ['scripts/build-client.mjs']],
  ['node-regression', process.execPath, ['--test', ...testFiles]],
  ['swift-package', 'swift', ['test', '--package-path', 'native/macos']],
  ['cross-language', process.execPath, ['scripts/test-cross-language.mjs']],
  ['fixture-package-tests', 'swift', ['test', '--package-path', 'fixtures/macos/app']],
  ['native-process-fixture', process.execPath, ['scripts/test-native-p1.mjs', '--skip-unit-tests']],
  ['release-bundle', process.execPath, ['scripts/build.mjs', '--native']],
  ['bundle-integrity', process.execPath, ['scripts/check-bundle.mjs']],
  [
    'release-native-fixture',
    process.execPath,
    ['--test', 'tests/integration/native-p1.test.ts'],
    { DSH_TEST_FIXTURE_HELPER: join(root, 'native-bin/computer-history-collector') },
  ],
];

if (args.includes('--authorized-synthetic-multisource')) {
  for (const mode of ['surface', 'diff', 'selection', 'input', 'combined', 'excluded']) {
    stages.push([
      `authorized-multisource-${mode}`,
      process.execPath,
      ['scripts/test-multisource-ax-smoke.mjs', '--authorized-synthetic-ax', mode],
    ]);
  }
}
if (args.includes('--authorized-synthetic-field-policy')) {
  for (const mode of ['field-strict', 'field-denylist', 'field-protected']) {
    stages.push([
      `authorized-${mode}`,
      process.execPath,
      ['scripts/test-multisource-ax-smoke.mjs', '--authorized-synthetic-ax', mode],
    ]);
  }
}
if (args.includes('--authorized-synthetic-layout')) {
  for (const mode of ['surface', 'protected', 'excluded']) {
    stages.push([
      `authorized-layout-${mode}`,
      process.execPath,
      ['scripts/test-layout-ax-smoke.mjs', '--authorized-synthetic-layout', mode],
    ]);
  }
}
if (args.includes('--authorized-synthetic-ax')) {
  for (const mode of ['plain', 'empty', 'visible', 'async', 'secure']) {
    stages.push([
      `authorized-fixture-ax-${mode}`,
      process.execPath,
      ['scripts/test-fixture-ax-smoke.mjs', '--authorized-synthetic-ax', mode],
    ]);
  }
}

if (args.includes('--plan')) {
  console.log(
    JSON.stringify(
      {
        mode: args.includes('--authorized-synthetic-layout')
          ? 'authorized-synthetic-layout'
          : args.includes('--authorized-synthetic-field-policy')
            ? 'authorized-field-policy'
            : args.includes('--authorized-synthetic-multisource')
              ? 'authorized-fixture-multisource'
              : args.includes('--authorized-synthetic-ax')
                ? 'authorized-fixture-ax'
                : 'offline',
        stages: stages.map(([name]) => name),
        realHistory: false,
        keychain: false,
        permissionPrompts: false,
      },
      null,
      2,
    ),
  );
  process.exit(0);
}

if (process.platform !== 'darwin') {
  console.error('macos-acceptance-required');
  process.exit(64);
}

const completed = [];
for (const [name, executable, argv, extraEnv] of stages) {
  console.log(`\n=== ${name} ===`);
  const started = performance.now();
  const result = spawnSync(executable, argv, {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, ...extraEnv },
    timeout: 300_000,
    killSignal: 'SIGTERM',
  });
  if (result.status !== 0) {
    console.error(
      JSON.stringify({
        ok: false,
        failedStage: name,
        exitCode: result.status,
        signal: result.signal,
        completed,
      }),
    );
    process.exit(result.status ?? 1);
  }
  completed.push({ name, elapsedMs: Math.round(performance.now() - started) });
}
console.log(JSON.stringify({ ok: true, completed, realHistory: false, keychain: false }, null, 2));

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  BROWSER_APPLICATION_FAMILIES,
  BUILT_IN_ADAPTERS,
  DEFAULT_EXCLUDED_APPLICATION_IDS,
  MANDATORY_EXCLUDED_APPLICATION_IDS,
  PRIVATE_CHROME_EXACT_LABELS,
  PRIVATE_CHROME_INDICATORS,
  PRIVATE_WINDOW_INDICATORS,
  SYSTEM_UI_SKIP_APPLICATION_IDS,
} from '../../src/shared/app-policy.ts';

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));

test('policy-catalog.json stays in lockstep with generated TypeScript and macOS Swift policy catalogs', () => {
  const catalog = JSON.parse(
    readFileSync(join(ROOT, 'src/shared/policy/policy-catalog.json'), 'utf8'),
  ) as {
    version: number;
    mandatoryExcludedFamilies: { macos: string[]; windows: string[] };
    systemUIFamilies: { macos: string[]; windows: string[] };
    defaultExcludedApplicationIds: string[];
    browserFamilies: { macos: string[]; windows: string[] };
    privateWindowIndicators: string[];
    privateChromeIndicators: string[];
    privateChromeExactLabels: string[];
    builtInAdapters: Array<{
      id: string;
      name: string;
      mode: string;
      macosBundleIds: string[];
      windowsProcessNames: string[];
    }>;
  };

  assert.equal(catalog.version, 1);
  assert.deepEqual(MANDATORY_EXCLUDED_APPLICATION_IDS, [
    ...catalog.mandatoryExcludedFamilies.macos,
    ...catalog.mandatoryExcludedFamilies.windows,
  ]);
  assert.deepEqual(SYSTEM_UI_SKIP_APPLICATION_IDS, [
    ...catalog.systemUIFamilies.macos,
    ...catalog.systemUIFamilies.windows,
  ]);
  assert.deepEqual(DEFAULT_EXCLUDED_APPLICATION_IDS, catalog.defaultExcludedApplicationIds);
  assert.deepEqual(BROWSER_APPLICATION_FAMILIES, [
    ...catalog.browserFamilies.macos,
    ...catalog.browserFamilies.windows,
  ]);
  assert.deepEqual(PRIVATE_WINDOW_INDICATORS, catalog.privateWindowIndicators);
  assert.deepEqual(PRIVATE_CHROME_INDICATORS, catalog.privateChromeIndicators);
  assert.deepEqual(PRIVATE_CHROME_EXACT_LABELS, catalog.privateChromeExactLabels);
  assert.deepEqual(
    BUILT_IN_ADAPTERS.map((adapter) => adapter.id),
    catalog.builtInAdapters.map((adapter) => adapter.id),
  );

  // Verify generated Swift catalog contains every macOS policy family and adapter id.
  const swiftCatalog = readFileSync(
    join(ROOT, 'native/macos/Sources/CollectorCore/Policy/GeneratedPolicyCatalog.swift'),
    'utf8',
  );
  for (const id of [
    ...catalog.mandatoryExcludedFamilies.macos,
    ...catalog.systemUIFamilies.macos,
    ...catalog.browserFamilies.macos,
    ...catalog.privateWindowIndicators,
    ...catalog.privateChromeIndicators,
    ...catalog.privateChromeExactLabels,
  ]) {
    assert.ok(swiftCatalog.includes(JSON.stringify(id)), `missing policy item in Swift catalog: ${id}`);
  }
  for (const adapter of catalog.builtInAdapters) {
    assert.ok(swiftCatalog.includes(`id: ${JSON.stringify(adapter.id)}`), `missing adapter in Swift catalog: ${adapter.id}`);
  }
});

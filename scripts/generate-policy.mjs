import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const check = process.argv.includes('--check');

const catalogPath = fileURLToPath(new URL('src/shared/policy/policy-catalog.json', root));
const catalog = JSON.parse(readFileSync(catalogPath, 'utf8'));

const APP_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/;

function assertStringArray(
  value,
  label,
  { allowEmpty = false, requireLowercase = false, requireAppId = false, uniqueCaseInsensitive = false } = {},
) {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    throw new Error(`Invalid policy catalog array: ${label}`);
  }
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== 'string' || item.length === 0) {
      throw new Error(`Invalid string entry in policy catalog: ${label}`);
    }
    if (requireLowercase && item !== item.toLowerCase()) {
      throw new Error(`Policy catalog entry must be lowercase in ${label}: ${item}`);
    }
    if (requireAppId && !APP_ID_PATTERN.test(item)) {
      throw new Error(`Invalid application ID in policy catalog ${label}: ${item}`);
    }
    if (uniqueCaseInsensitive) {
      const key = item.toLowerCase();
      if (seen.has(key)) {
        throw new Error(`Duplicate entry in policy catalog ${label}: ${item}`);
      }
      seen.add(key);
    }
  }
}

if (catalog.version !== 1) {
  throw new Error(`Unsupported policy catalog version: ${catalog.version}`);
}
assertStringArray(catalog.mandatoryExcludedFamilies?.macos, 'mandatoryExcludedFamilies.macos', {
  requireLowercase: true,
  requireAppId: true,
  uniqueCaseInsensitive: true,
});
assertStringArray(catalog.mandatoryExcludedFamilies?.windows, 'mandatoryExcludedFamilies.windows', {
  requireLowercase: true,
  requireAppId: true,
  uniqueCaseInsensitive: true,
});
assertStringArray(catalog.systemUIFamilies?.macos, 'systemUIFamilies.macos', {
  requireLowercase: true,
  requireAppId: true,
  uniqueCaseInsensitive: true,
});
assertStringArray(catalog.systemUIFamilies?.windows, 'systemUIFamilies.windows', {
  requireLowercase: true,
  requireAppId: true,
  uniqueCaseInsensitive: true,
});
assertStringArray(catalog.defaultExcludedApplicationIds, 'defaultExcludedApplicationIds', {
  requireAppId: true,
  uniqueCaseInsensitive: true,
});
assertStringArray(catalog.browserFamilies?.macos, 'browserFamilies.macos', {
  requireLowercase: true,
  requireAppId: true,
  uniqueCaseInsensitive: true,
});
assertStringArray(catalog.browserFamilies?.windows, 'browserFamilies.windows', {
  requireLowercase: true,
  requireAppId: true,
  uniqueCaseInsensitive: true,
});
assertStringArray(catalog.privateWindowIndicators, 'privateWindowIndicators', {
  requireLowercase: true,
  uniqueCaseInsensitive: true,
});
assertStringArray(catalog.privateChromeIndicators, 'privateChromeIndicators', {
  requireLowercase: true,
  uniqueCaseInsensitive: true,
});
assertStringArray(catalog.privateChromeExactLabels, 'privateChromeExactLabels', {
  requireLowercase: true,
  uniqueCaseInsensitive: true,
});
if (!Array.isArray(catalog.builtInAdapters) || catalog.builtInAdapters.length === 0) {
  throw new Error('Invalid policy catalog array: builtInAdapters');
}
const seenAdapterIds = new Set();
for (const adapter of catalog.builtInAdapters) {
  if (
    typeof adapter?.id !== 'string' ||
    adapter.id.length === 0 ||
    typeof adapter?.name !== 'string' ||
    adapter.name.length === 0 ||
    !['fallback', 'declarative', 'custom'].includes(adapter?.mode)
  ) {
    throw new Error(`Invalid adapter entry in policy catalog: ${JSON.stringify(adapter)}`);
  }
  if (seenAdapterIds.has(adapter.id)) {
    throw new Error(`Duplicate adapter id in policy catalog: ${adapter.id}`);
  }
  seenAdapterIds.add(adapter.id);
  assertStringArray(adapter.macosBundleIds, `builtInAdapters.${adapter.id}.macosBundleIds`, {
    allowEmpty: true,
    requireAppId: true,
  });
  assertStringArray(adapter.windowsProcessNames, `builtInAdapters.${adapter.id}.windowsProcessNames`, {
    allowEmpty: true,
    requireLowercase: true,
    requireAppId: true,
    uniqueCaseInsensitive: true,
  });
}

function tsString(value) {
  return `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

function tsStringArray(items) {
  return items.map((item) => `  ${tsString(item)},`).join('\n');
}

function swiftString(value) {
  return JSON.stringify(value);
}

function swiftStringArray(items, indent = '        ') {
  return items.map((item) => `${indent}${swiftString(item)},`).join('\n');
}

const mandatoryAll = [
  ...catalog.mandatoryExcludedFamilies.macos,
  ...catalog.mandatoryExcludedFamilies.windows,
];
const systemUiAll = [
  ...catalog.systemUIFamilies.macos,
  ...catalog.systemUIFamilies.windows,
];
const browserAll = [
  ...catalog.browserFamilies.macos,
  ...catalog.browserFamilies.windows,
];

const tsAdapters = catalog.builtInAdapters
  .map((adapter) => {
    const bundleIds = [...adapter.macosBundleIds, ...adapter.windowsProcessNames];
    const idsLiteral =
      bundleIds.length === 0
        ? '[]'
        : `[\n${bundleIds.map((id) => `      ${tsString(id)},`).join('\n')}\n    ]`;
    return [
      '  {',
      `    id: ${tsString(adapter.id)},`,
      `    name: ${tsString(adapter.name)},`,
      `    bundleIds: ${idsLiteral},`,
      `    mode: ${tsString(adapter.mode)},`,
      '  },',
    ].join('\n');
  })
  .join('\n');

const tsOutput = [
  '// Generated by scripts/generate-policy.mjs; edit src/shared/policy/policy-catalog.json instead.',
  "import type { AdapterSummary } from '../api-types.ts';",
  '',
  'export const MANDATORY_EXCLUDED_APPLICATION_IDS: readonly string[] = Object.freeze([',
  tsStringArray(mandatoryAll),
  ']);',
  '',
  'export const SYSTEM_UI_SKIP_APPLICATION_IDS: readonly string[] = Object.freeze([',
  tsStringArray(systemUiAll),
  ']);',
  '',
  'export const DEFAULT_EXCLUDED_APPLICATION_IDS: readonly string[] = Object.freeze([',
  tsStringArray(catalog.defaultExcludedApplicationIds),
  ']);',
  '',
  'export const BROWSER_APPLICATION_FAMILIES: readonly string[] = Object.freeze([',
  tsStringArray(browserAll),
  ']);',
  '',
  'export const PRIVATE_WINDOW_INDICATORS: readonly string[] = Object.freeze([',
  tsStringArray(catalog.privateWindowIndicators),
  ']);',
  '',
  'export const PRIVATE_CHROME_INDICATORS: readonly string[] = Object.freeze([',
  tsStringArray(catalog.privateChromeIndicators),
  ']);',
  '',
  'export const PRIVATE_CHROME_EXACT_LABELS: readonly string[] = Object.freeze([',
  tsStringArray(catalog.privateChromeExactLabels),
  ']);',
  '',
  'export const BUILT_IN_ADAPTERS: readonly AdapterSummary[] = Object.freeze([',
  tsAdapters,
  ']);',
  '',
].join('\n');

const swiftAdapters = catalog.builtInAdapters
  .map((adapter) => {
    const ids =
      adapter.macosBundleIds.length === 0
        ? '[]'
        : `[\n${swiftStringArray(adapter.macosBundleIds, '                ')}\n            ]`;
    return [
      '        BuiltInAdapterCatalogEntry(',
      `            id: ${swiftString(adapter.id)},`,
      `            displayName: ${swiftString(adapter.name)},`,
      `            mode: ${swiftString(adapter.mode)},`,
      `            bundleIds: ${ids}`,
      '        ),',
    ].join('\n');
  })
  .join('\n');

const swiftOutput = [
  '// Generated by scripts/generate-policy.mjs; edit src/shared/policy/policy-catalog.json instead.',
  'import Foundation',
  '',
  'public struct BuiltInAdapterCatalogEntry: Equatable, Sendable {',
  '    public let id: String',
  '    public let displayName: String',
  '    public let mode: String',
  '    public let bundleIds: [String]',
  '',
  '    public init(id: String, displayName: String, mode: String, bundleIds: [String]) {',
  '        self.id = id',
  '        self.displayName = displayName',
  '        self.mode = mode',
  '        self.bundleIds = bundleIds',
  '    }',
  '}',
  '',
  '/// Generated macOS policy and adapter metadata shared with Host TypeScript.',
  'public enum GeneratedPolicyCatalog {',
  '    public static let mandatoryExcludedFamilies: [String] = [',
  swiftStringArray(catalog.mandatoryExcludedFamilies.macos),
  '    ]',
  '',
  '    public static let systemUIFamilies: [String] = [',
  swiftStringArray(catalog.systemUIFamilies.macos),
  '    ]',
  '',
  '    public static let browserFamilies: [String] = [',
  swiftStringArray(catalog.browserFamilies.macos),
  '    ]',
  '',
  '    public static let privateWindowIndicators: [String] = [',
  swiftStringArray(catalog.privateWindowIndicators),
  '    ]',
  '',
  '    public static let privateChromeIndicators: [String] = [',
  swiftStringArray(catalog.privateChromeIndicators),
  '    ]',
  '',
  '    public static let privateChromeExactLabels: [String] = [',
  swiftStringArray(catalog.privateChromeExactLabels),
  '    ]',
  '',
  '    public static let builtInAdapters: [BuiltInAdapterCatalogEntry] = [',
  swiftAdapters,
  '    ]',
  '}',
  '',
].join('\n');

const outputs = [
  ['src/shared/policy/generated-policy.ts', tsOutput],
  ['native/macos/Sources/CollectorCore/Policy/GeneratedPolicyCatalog.swift', swiftOutput],
];

let changed = false;
for (const [relative, content] of outputs) {
  const path = fileURLToPath(new URL(relative, root));
  const current = existsSync(path) ? readFileSync(path, 'utf8') : undefined;
  if (current === content) continue;
  if (check) {
    console.error(`Generated policy artifact out of date: ${relative}`);
    changed = true;
    continue;
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, { mode: 0o644 });
  console.log(`Generated ${relative}`);
}

if (changed) {
  process.exitCode = 1;
} else {
  console.log(check ? 'Generated policy artifacts are current.' : 'Policy generation complete.');
}

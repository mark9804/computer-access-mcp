import type { AdapterSummary, CaptureStartOptions, NormalizedCaptureStartOptions } from './api-types.ts';
import type { CapturePolicy } from './protocol/generated.ts';

// Hard-excluded application bundle families enforced across Host and Collector.
export const MANDATORY_EXCLUDED_APPLICATION_IDS: readonly string[] = Object.freeze([
  'com.1password',
  'com.agilebits.onepassword',
  'com.agilebits.onepassword7',
  'com.agilebits.onepassword-osx',
  'com.apple.safari',
  'com.apple.passwords',
  'com.apple.keychainaccess',
  'com.bitwarden.desktop',
  'com.dashlane.dashlanephonefinal',
  'com.lastpass.lastpass',
  'com.nordsec.nordpass',
  'me.proton.pass',
]);

// System UI and authentication overlays silently skipped without emitting gap records.
export const SYSTEM_UI_SKIP_APPLICATION_IDS: readonly string[] = Object.freeze([
  'com.apple.windowmanager',
  'com.apple.controlcenter',
  'com.apple.notificationcenterui',
  'com.apple.securityagent',
  'com.apple.localauthentication.uiagent',
  'com.apple.localauthenticationremoteservice',
  'com.apple.loginwindow',
  'com.apple.usernotificationcenter',
]);

export const DEFAULT_EXCLUDED_APPLICATION_IDS: readonly string[] = Object.freeze([
  'com.1password.1password',
  'com.1password.safari',
  'com.apple.Safari',
]);

export const BROWSER_APPLICATION_FAMILIES: readonly string[] = Object.freeze([
  'com.apple.safari',
  'com.google.chrome',
  'org.chromium',
  'org.chromium.chromium',
  'com.brave.browser',
  'com.microsoft.edgemac',
  'company.thebrowser.browser',
  'company.thebrowser.dia',
  'com.vivaldi.vivaldi',
  'com.operasoftware.opera',
  'org.mozilla.firefox',
  'org.mozilla.nightly',
  'app.zen-browser.zen',
  'app.floorp.floorp',
  'ai.perplexity.comet',
  'com.openai.atlas',
  'net.imput.helium',
  'com.kagi.kagimacos',
  'org.torproject.torbrowser',
  'net.waterfox',
  'org.mozilla.librewolf',
  'io.gitlab.librewolf-community.librewolf',
  'net.librewolf.librewolf',
]);

export const BUILT_IN_ADAPTERS: readonly AdapterSummary[] = Object.freeze([
  {
    id: 'generic',
    name: 'Generic Desktop Adapter',
    bundleIds: [],
    mode: 'fallback',
  },
  {
    id: 'vscode-family',
    name: 'VSCode & Electron Editors',
    bundleIds: [
      'com.google.antigravity',
      'com.google.antigravity-ide',
      'com.microsoft.VSCode',
      'com.microsoft.VSCodeInsiders',
      'com.todesktop.230313mzl4w4u92',
      'com.exafunction.windsurf',
    ],
    mode: 'declarative',
  },
  {
    id: 'browser-family',
    name: 'Web Browsers (Chromium & Firefox)',
    bundleIds: [
      'com.google.Chrome',
      'com.google.Chrome.canary',
      'org.chromium.Chromium',
      'com.brave.Browser',
      'com.microsoft.edgemac',
      'company.thebrowser.Browser',
      'company.thebrowser.browser',
      'company.thebrowser.dia',
      'com.vivaldi.Vivaldi',
      'com.operasoftware.Opera',
      'org.mozilla.firefox',
      'org.mozilla.nightly',
      'app.zen-browser.zen',
      'app.floorp.Floorp',
      'ai.perplexity.comet',
      'com.openai.atlas',
      'net.imput.helium',
    ],
    mode: 'declarative',
  },
  {
    id: 'terminal-family',
    name: 'Terminals & CLI',
    bundleIds: [
      'com.apple.Terminal',
      'com.googlecode.iterm2',
      'com.mitchellh.ghostty',
      'dev.warp.Warp-Stable',
      'net.kovidgoyal.kitty',
      'com.github.wez.wezterm',
      'com.raphaelamorim.rio',
      'dev.commandline.waveterm',
    ],
    mode: 'declarative',
  },
  {
    id: 'qq',
    name: 'Tencent QQ',
    bundleIds: ['com.tencent.qq'],
    mode: 'declarative',
  },
  {
    id: 'feishu',
    name: 'Feishu / Lark',
    bundleIds: ['com.electron.lark', 'com.bytedance.feishu'],
    mode: 'declarative',
  },
  {
    id: 'wechat',
    name: 'WeChat',
    bundleIds: ['com.tencent.xinWeChat'],
    mode: 'custom',
  },
  {
    id: 'slack',
    name: 'Slack',
    bundleIds: ['com.tinyspeck.slackmacgap'],
    mode: 'declarative',
  },
  {
    id: 'typora',
    name: 'Typora',
    bundleIds: ['abnerworks.Typora'],
    mode: 'declarative',
  },
]);

export const DEFAULT_CAPTURE_START_OPTIONS: Readonly<NormalizedCaptureStartOptions> = Object.freeze({
  applicationScope: 'denylist',
  allowedApplicationIds: [],
  excludedApplicationIds: [...DEFAULT_EXCLUDED_APPLICATION_IDS],
  allowBrowserContent: true,
  fieldSecurity: 'denylist',
  axCompatibility: true,
  textMarkers: true,
  captureScope: 'window',
  maxTreeNodes: 48,
  inputText: true,
  selectionCapture: true,
  inputActivity: true,
  menuActions: true,
  textRange: 'prefix',
  maxTextCodeUnits: 4096,
  sampleIntervalMs: 1000,
});

export function validApplicationId(id: unknown): id is string {
  return typeof id === 'string' && id.length >= 1 && id.length <= 256 && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(id);
}

export function applicationFamilyMatches(id: string, family: string): boolean {
  const value = id.toLowerCase();
  const prefix = family.toLowerCase();
  return value === prefix || value.startsWith(prefix + '.');
}

export function mandatoryApplicationDenied(id: string): boolean {
  return MANDATORY_EXCLUDED_APPLICATION_IDS.some((family) => applicationFamilyMatches(id, family));
}

export function isSystemUiApplicationId(id: string): boolean {
  return SYSTEM_UI_SKIP_APPLICATION_IDS.some((family) => applicationFamilyMatches(id, family));
}

export function isBrowserApplicationId(id: string): boolean {
  return BROWSER_APPLICATION_FAMILIES.some((family) => applicationFamilyMatches(id, family));
}

export const knownBrowser = isBrowserApplicationId;

export function applicationAllowed(
  policy: Pick<
    CapturePolicy,
    'enabled' | 'allowedApplicationIds' | 'applicationScope' | 'excludedApplicationIds' | 'allowBrowserContent'
  >,
  id: string,
): boolean {
  if (!policy.enabled || !validApplicationId(id) || mandatoryApplicationDenied(id) || isSystemUiApplicationId(id)) {
    return false;
  }
  if (policy.excludedApplicationIds?.some((family) => applicationFamilyMatches(id, family))) return false;
  if (isBrowserApplicationId(id) && !(policy.applicationScope === 'denylist' && policy.allowBrowserContent === true)) {
    return false;
  }
  if (policy.applicationScope === 'denylist') return true;
  if (policy.applicationScope !== undefined && policy.applicationScope !== 'allowlist') return false;
  return policy.allowedApplicationIds.some((allowed) => allowed.toLowerCase() === id.toLowerCase());
}

export function validApplicationPolicy(
  policy: Pick<
    CapturePolicy,
    'allowedApplicationIds' | 'applicationScope' | 'excludedApplicationIds' | 'allowBrowserContent'
  >,
): boolean {
  const mode = policy.applicationScope ?? 'allowlist';
  if (mode !== 'allowlist' && mode !== 'denylist') return false;
  if (policy.excludedApplicationIds !== undefined && !Array.isArray(policy.excludedApplicationIds)) return false;
  for (const list of [policy.allowedApplicationIds, policy.excludedApplicationIds ?? []]) {
    if (
      !Array.isArray(list) ||
      list.length > 64 ||
      list.some((id) => !validApplicationId(id)) ||
      new Set(list.map((id) => id.toLowerCase())).size !== list.length
    ) {
      return false;
    }
  }
  if (mode === 'allowlist' && policy.allowedApplicationIds.length === 0) return false;
  return (
    policy.allowBrowserContent === undefined ||
    (typeof policy.allowBrowserContent === 'boolean' && (!policy.allowBrowserContent || mode === 'denylist'))
  );
}

function normalizeAppIdList(raw: unknown, fieldName: string): string[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw) || raw.length > 64) {
    throw new Error(`invalid-${fieldName}`);
  }
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of raw) {
    if (!validApplicationId(item)) {
      throw new Error(`invalid-${fieldName}`);
    }
    const lower = item.toLowerCase();
    if (!seen.has(lower)) {
      seen.add(lower);
      out.push(item);
    }
  }
  return out;
}

function normalizeBoolean(raw: unknown, fallback: boolean): boolean {
  if (raw === undefined) return fallback;
  if (typeof raw !== 'boolean') throw new Error('invalid-capture-options');
  return raw;
}

function normalizeInt(raw: unknown, fallback: number, min: number, max: number, errorCode: string): number {
  if (raw === undefined) return fallback;
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw < min || raw > max) {
    throw new Error(errorCode);
  }
  return raw;
}

export function validateCaptureStartOptions(input: unknown): NormalizedCaptureStartOptions {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('invalid-capture-options');
  }
  const raw = input as CaptureStartOptions & Record<string, unknown>;

  const allowedApplicationIds = normalizeAppIdList(raw.allowedApplicationIds, 'allowed-application-ids');
  const excludedApplicationIds = normalizeAppIdList(
    raw.excludedApplicationIds === undefined ? DEFAULT_EXCLUDED_APPLICATION_IDS : raw.excludedApplicationIds,
    'excluded-application-ids',
  );

  const defaultScope = allowedApplicationIds.length > 0 ? 'allowlist' : 'denylist';
  const applicationScope = raw.applicationScope === undefined ? defaultScope : raw.applicationScope;
  if (applicationScope !== 'allowlist' && applicationScope !== 'denylist') {
    throw new Error('application-allowlist-invalid');
  }
  if (applicationScope === 'allowlist' && allowedApplicationIds.length === 0) {
    throw new Error('application-allowlist-invalid');
  }

  const allowBrowserContent = normalizeBoolean(
    raw.allowBrowserContent,
    applicationScope === 'denylist' ? DEFAULT_CAPTURE_START_OPTIONS.allowBrowserContent : false,
  );
  if (allowBrowserContent && applicationScope !== 'denylist') {
    throw new Error('application-allowlist-invalid');
  }

  const fieldSecurity = raw.fieldSecurity === undefined ? DEFAULT_CAPTURE_START_OPTIONS.fieldSecurity : raw.fieldSecurity;
  if (fieldSecurity !== 'strict' && fieldSecurity !== 'denylist') {
    throw new Error('invalid-capture-options');
  }

  const captureScope = raw.captureScope === undefined ? DEFAULT_CAPTURE_START_OPTIONS.captureScope : raw.captureScope;
  if (captureScope !== 'focused' && captureScope !== 'region' && captureScope !== 'window') {
    throw new Error('invalid-capture-options');
  }

  const textRange = raw.textRange === undefined ? DEFAULT_CAPTURE_START_OPTIONS.textRange : raw.textRange;
  if (textRange !== 'prefix' && textRange !== 'visible') {
    throw new Error('text-range-policy-invalid');
  }

  return {
    applicationScope,
    allowedApplicationIds,
    excludedApplicationIds,
    allowBrowserContent,
    fieldSecurity,
    axCompatibility: normalizeBoolean(raw.axCompatibility, DEFAULT_CAPTURE_START_OPTIONS.axCompatibility),
    textMarkers: normalizeBoolean(raw.textMarkers, DEFAULT_CAPTURE_START_OPTIONS.textMarkers),
    captureScope,
    maxTreeNodes: normalizeInt(raw.maxTreeNodes, DEFAULT_CAPTURE_START_OPTIONS.maxTreeNodes, 1, 96, 'invalid-capture-options'),
    inputText: normalizeBoolean(raw.inputText, DEFAULT_CAPTURE_START_OPTIONS.inputText),
    selectionCapture: normalizeBoolean(raw.selectionCapture, DEFAULT_CAPTURE_START_OPTIONS.selectionCapture),
    inputActivity: normalizeBoolean(raw.inputActivity, DEFAULT_CAPTURE_START_OPTIONS.inputActivity),
    menuActions: normalizeBoolean(raw.menuActions, DEFAULT_CAPTURE_START_OPTIONS.menuActions),
    textRange,
    maxTextCodeUnits: normalizeInt(raw.maxTextCodeUnits, DEFAULT_CAPTURE_START_OPTIONS.maxTextCodeUnits, 1, 8192, 'text-budget-invalid'),
    sampleIntervalMs: normalizeInt(raw.sampleIntervalMs, DEFAULT_CAPTURE_START_OPTIONS.sampleIntervalMs, 1000, 30000, 'sample-interval-invalid'),
  };
}

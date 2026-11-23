import assert from 'node:assert/strict';
import test from 'node:test';
import {
  applicationAllowed,
  applicationFamilyMatches,
  BROWSER_APPLICATION_FAMILIES,
  BUILT_IN_ADAPTERS,
  DEFAULT_CAPTURE_START_OPTIONS,
  defaultCaptureStartOptions,
  isBrowserApplicationId,
  isSystemUiApplicationId,
  MANDATORY_EXCLUDED_APPLICATION_IDS,
  mandatoryApplicationDenied,
  SYSTEM_UI_SKIP_APPLICATION_IDS,
  validApplicationId,
  validateCaptureStartOptions,
  validApplicationPolicy,
} from '../../src/shared/app-policy.ts';
import type { CapturePolicy } from '../../src/shared/protocol/generated.ts';

const base: CapturePolicy = {
  enabled: true,
  allowedApplicationIds: ['test.editor'],
  maxTextCodeUnits: 128,
  maxPending: 4,
  debounceMs: 0,
  maxWaitMs: 10,
  readTimeoutMs: 50,
};

test('personal denylist allows other apps only after explicit policy selection', () => {
  assert.equal(applicationAllowed(base, 'test.other'), false);
  const policy = {
    ...base,
    applicationScope: 'denylist' as const,
    allowedApplicationIds: [],
    excludedApplicationIds: ['test.excluded'],
  };
  assert.equal(validApplicationPolicy(policy), true);
  assert.equal(applicationAllowed(policy, 'test.other'), true);
  assert.equal(applicationAllowed(policy, 'test.excluded.extension'), false);
  assert.equal(applicationAllowed({ ...policy, enabled: false }, 'test.other'), false);
  assert.equal(applicationAllowed({ ...policy, applicationScope: 'unknown' as any }, 'test.other'), false);
});

test('password manager families and Safari remain excluded despite allowlist or browser opt-in', () => {
  assert.deepEqual(MANDATORY_EXCLUDED_APPLICATION_IDS, [
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
    '1password.exe',
    'bitwarden.exe',
    'keepass.exe',
    'keepassxc.exe',
    'dashlane.exe',
    'lastpass.exe',
    'nordpass.exe',
    'protonpass.exe',
  ]);
  for (const id of [
    'com.1password.1password',
    'com.1password.1password.autofill-extension',
    'com.1password.safari',
    'com.1password.safari.extension',
    'COM.1PASSWORD.SAFARI.extension',
    'com.agilebits.onepassword',
    'com.agilebits.onepassword7',
    'com.agilebits.onepassword-osx',
    'com.apple.Safari',
    'com.apple.Safari.WebContent',
    'com.apple.Passwords',
    'com.apple.keychainaccess',
    'com.bitwarden.desktop',
    'com.bitwarden.desktop.helper',
    'com.dashlane.DashlanePhoneFinal',
    'com.lastpass.LastPass',
    'com.nordsec.nordpass',
    'me.proton.pass',
    'me.proton.pass.electron',
    '1password.exe',
    '1Password.EXE',
    '1password.exe.helper',
    'bitwarden.exe',
    'Bitwarden.exe',
    'keepass.exe',
    'keepassxc.exe',
    'KeePassXC.exe',
    'dashlane.exe',
    'lastpass.exe',
    'nordpass.exe',
    'protonpass.exe',
  ]) {
    assert.equal(mandatoryApplicationDenied(id), true, id);
    assert.equal(applicationAllowed({ ...base, allowedApplicationIds: [id] }, id), false, id);
    assert.equal(applicationAllowed({ ...base, applicationScope: 'denylist', allowBrowserContent: true }, id), false, id);
  }
  assert.equal(applicationFamilyMatches('com.1passwordevil.app', 'com.1password'), false);
  assert.equal(applicationFamilyMatches('example.com.1password', 'com.1password'), false);
  assert.equal(mandatoryApplicationDenied('com.bitwarden.desktopevil'), false);
  assert.equal(applicationFamilyMatches('1password.exeevil', '1password.exe'), false);
  assert.equal(applicationFamilyMatches('evil.1password.exe', '1password.exe'), false);
  assert.equal(mandatoryApplicationDenied('keepassxc.exeevil'), false);
});

test('System UI processes are matched by isSystemUiApplicationId and never admitted', () => {
  assert.deepEqual(SYSTEM_UI_SKIP_APPLICATION_IDS, [
    'com.apple.windowmanager',
    'com.apple.controlcenter',
    'com.apple.notificationcenterui',
    'com.apple.securityagent',
    'com.apple.localauthentication.uiagent',
    'com.apple.localauthenticationremoteservice',
    'com.apple.loginwindow',
    'com.apple.usernotificationcenter',
    'lockapp.exe',
    'logonui.exe',
    'credentialuibroker.exe',
    'consent.exe',
    'shellexperiencehost.exe',
    'startmenuexperiencehost.exe',
    'searchhost.exe',
    'searchapp.exe',
    'textinputhost.exe',
    'pickerhost.exe',
  ]);
  for (const id of [
    ...SYSTEM_UI_SKIP_APPLICATION_IDS,
    'com.apple.ControlCenter',
    'com.apple.SecurityAgent.helper',
    'com.apple.LocalAuthentication.UIAgent',
    'LockApp.exe',
    'LogonUI.EXE',
    'CredentialUIBroker.exe',
    'ShellExperienceHost.exe',
    'StartMenuExperienceHost.exe',
    'TextInputHost.exe',
  ]) {
    assert.equal(isSystemUiApplicationId(id), true, id);
    assert.equal(mandatoryApplicationDenied(id), false, id);
    assert.equal(applicationAllowed({ ...base, allowedApplicationIds: [id] }, id), false, id);
    assert.equal(applicationAllowed({ ...base, applicationScope: 'denylist', allowBrowserContent: true }, id), false, id);
  }
  assert.equal(isSystemUiApplicationId('com.apple.Terminal'), false);
  assert.equal(isSystemUiApplicationId('com.apple.controlcenterevil'), false);
  assert.equal(isSystemUiApplicationId('lockapp.exeevil'), false);
  assert.equal(isSystemUiApplicationId('evil.lockapp.exe'), false);
  assert.equal(isSystemUiApplicationId('notepad.exe'), false);
});

test('browser permission is explicit and never overrides exclusions', () => {
  for (const family of [
    'com.google.chrome',
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
    'com.apple.safari',
    'net.waterfox',
    'io.gitlab.librewolf-community.librewolf',
    'net.librewolf.librewolf',
    'chrome.exe',
    'chromium.exe',
    'msedge.exe',
    'brave.exe',
    'firefox.exe',
    'vivaldi.exe',
    'opera.exe',
    'arc.exe',
    'zen.exe',
    'floorp.exe',
    'waterfox.exe',
    'librewolf.exe',
    'tor.exe',
    'comet.exe',
    'dia.exe',
  ]) {
    assert.equal(BROWSER_APPLICATION_FAMILIES.includes(family), true, family);
    assert.equal(isBrowserApplicationId(family), true, family);
  }
  assert.equal(isBrowserApplicationId('com.google.Chrome'), true);
  assert.equal(isBrowserApplicationId('net.waterfox.waterfox'), true);
  assert.equal(isBrowserApplicationId('MSEdge.exe'), true);
  assert.equal(isBrowserApplicationId('CHROME.EXE'), true);
  assert.equal(isBrowserApplicationId('com.google.antigravity'), false);
  assert.equal(isBrowserApplicationId('com.google.antigravity-ide'), false);
  assert.equal(isBrowserApplicationId('antigravity.exe'), false);
  assert.equal(isBrowserApplicationId('code.exe'), false);
  assert.equal(isBrowserApplicationId('msedge.exeevil'), false);
  assert.equal(isBrowserApplicationId('evil.msedge.exe'), false);
  assert.equal(applicationAllowed({ ...base, applicationScope: 'denylist' }, 'com.google.Chrome'), false);
  assert.equal(applicationAllowed({ ...base, applicationScope: 'denylist', allowBrowserContent: true }, 'com.google.Chrome'), true);
  assert.equal(applicationAllowed({ ...base, applicationScope: 'denylist' }, 'MSEdge.exe'), false);
  assert.equal(applicationAllowed({ ...base, applicationScope: 'denylist', allowBrowserContent: true }, 'MSEdge.exe'), true);
  assert.equal(
    applicationAllowed(
      { ...base, applicationScope: 'denylist', allowBrowserContent: true, excludedApplicationIds: ['com.google.chrome'] },
      'com.google.Chrome.canary',
    ),
    false,
  );
  assert.equal(
    applicationAllowed(
      { ...base, applicationScope: 'denylist', allowBrowserContent: true, excludedApplicationIds: ['msedge.exe'] },
      'MSEdge.exe',
    ),
    false,
  );
  assert.equal(validApplicationPolicy({ ...base, allowBrowserContent: true }), false);
});

test('built-in adapter summaries stay synced with collector adapters', () => {
  assert.equal(BUILT_IN_ADAPTERS.length, 10);
  assert.deepEqual(
    BUILT_IN_ADAPTERS.map((adapter) => ({ id: adapter.id, name: adapter.name, mode: adapter.mode })),
    [
      { id: 'generic', name: 'Generic Desktop Adapter', mode: 'fallback' },
      { id: 'vscode-family', name: 'VSCode & Electron Editors', mode: 'declarative' },
      { id: 'browser-family', name: 'Web Browsers (Chromium & Firefox)', mode: 'declarative' },
      { id: 'terminal-family', name: 'Terminals & CLI', mode: 'declarative' },
      { id: 'qq', name: 'Tencent QQ', mode: 'declarative' },
      { id: 'feishu', name: 'Feishu / Lark', mode: 'declarative' },
      { id: 'wechat', name: 'WeChat', mode: 'custom' },
      { id: 'slack', name: 'Slack', mode: 'declarative' },
      { id: 'typora', name: 'Typora', mode: 'declarative' },
      { id: 'figma', name: 'Figma', mode: 'custom' },
    ],
  );

  const byId = new Map(BUILT_IN_ADAPTERS.map((adapter) => [adapter.id, adapter]));
  assert.deepEqual(byId.get('generic')?.bundleIds, []);
  assert.deepEqual(byId.get('vscode-family')?.bundleIds, [
    'com.google.antigravity',
    'com.google.antigravity-ide',
    'com.microsoft.VSCode',
    'com.microsoft.VSCodeInsiders',
    'com.todesktop.230313mzl4w4u92',
    'com.exafunction.windsurf',
    'antigravity.exe',
    'code.exe',
    'code-insiders.exe',
    'cursor.exe',
    'windsurf.exe',
  ]);
  assert.deepEqual(byId.get('browser-family')?.bundleIds, [
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
    'chrome.exe',
    'chromium.exe',
    'msedge.exe',
    'brave.exe',
    'vivaldi.exe',
    'opera.exe',
    'firefox.exe',
    'zen.exe',
    'floorp.exe',
    'arc.exe',
    'dia.exe',
    'comet.exe',
  ]);
  for (const browserBundleId of byId.get('browser-family')!.bundleIds) {
    assert.equal(isBrowserApplicationId(browserBundleId), true, browserBundleId);
  }
  assert.deepEqual(byId.get('terminal-family')?.bundleIds, [
    'com.apple.Terminal',
    'com.googlecode.iterm2',
    'com.mitchellh.ghostty',
    'dev.warp.Warp-Stable',
    'net.kovidgoyal.kitty',
    'com.github.wez.wezterm',
    'com.raphaelamorim.rio',
    'dev.commandline.waveterm',
    'windowsterminal.exe',
    'microsoft.windowsterminal',
    'wt.exe',
    'wezterm-gui.exe',
    'alacritty.exe',
    'warp.exe',
    'waveterm.exe',
    'rio.exe',
    'conhost.exe',
    'mintty.exe',
  ]);
  assert.deepEqual(byId.get('qq')?.bundleIds, ['com.tencent.qq', 'qq.exe']);
  assert.deepEqual(byId.get('feishu')?.bundleIds, ['com.electron.lark', 'com.bytedance.feishu', 'feishu.exe', 'lark.exe']);
  assert.deepEqual(byId.get('wechat')?.bundleIds, ['com.tencent.xinWeChat', 'wechat.exe', 'weixin.exe']);
  assert.deepEqual(byId.get('slack')?.bundleIds, ['com.tinyspeck.slackmacgap', 'slack.exe', '91750d7e.slack']);
  assert.deepEqual(byId.get('typora')?.bundleIds, ['abnerworks.Typora', 'typora.exe']);
  assert.deepEqual(byId.get('figma')?.bundleIds, ['com.figma.Desktop', 'figma.exe']);

  for (const adapter of BUILT_IN_ADAPTERS) {
    for (const bundleId of adapter.bundleIds) {
      assert.equal(validApplicationId(bundleId), true, `${adapter.id}: ${bundleId}`);
    }
  }
});

test('Windows application IDs work with allowlist, denylist, case-insensitivity, and non-prefix collisions', () => {
  for (const id of ['code.exe', 'microsoft.windowsterminal', 'wechat.exe', 'weixin.exe', 'qq.exe', 'feishu.exe']) {
    assert.equal(validApplicationId(id), true, id);
    assert.equal(applicationAllowed({ ...base, applicationScope: 'denylist' }, id), true, id);
  }
  assert.equal(applicationAllowed({ ...base, allowedApplicationIds: ['code.exe'] }, 'Code.EXE'), true);
  assert.equal(applicationAllowed({ ...base, allowedApplicationIds: ['microsoft.windowsterminal'] }, 'Microsoft.WindowsTerminal'), true);
  assert.equal(applicationAllowed({ ...base, allowedApplicationIds: ['code.exe'] }, 'code.exeevil'), false);
  assert.equal(
    applicationAllowed({ ...base, applicationScope: 'denylist', excludedApplicationIds: ['wechat.exe'] }, 'WeChat.exe'),
    false,
  );
  assert.equal(
    applicationAllowed({ ...base, applicationScope: 'denylist', excludedApplicationIds: ['wechat.exe'] }, 'wechat.exeevil'),
    true,
  );
  assert.equal(validApplicationPolicy({ ...base, allowedApplicationIds: ['code.exe', 'CODE.EXE'] }), false);
});

test('application policy rejects malformed or duplicated scopes and normalizes start options', () => {
  for (const data of [
    { ...base, allowedApplicationIds: [] },
    { ...base, allowedApplicationIds: ['test.app', 'TEST.APP'] },
    { ...base, excludedApplicationIds: ['test.app', 'TEST.APP'] },
    { ...base, allowedApplicationIds: ['*'] },
    { ...base, applicationScope: 'everything' },
    { ...base, allowBrowserContent: 'true' },
    { ...base, excludedApplicationIds: null },
  ]) {
    assert.equal(validApplicationPolicy(data as any), false);
  }
  assert.equal(validApplicationPolicy({ ...base, excludedApplicationIds: ['test.editor'] }), true);
  assert.equal(applicationAllowed({ ...base, excludedApplicationIds: ['test.editor'] }, 'test.editor'), false);

  const normalized = validateCaptureStartOptions({}, 'darwin');
  assert.equal(normalized.applicationScope, 'denylist');
  assert.equal(normalized.captureScope, 'window');
  assert.equal(normalized.menuActions, true);
  assert.equal(normalized.textMarkers, true);
  assert.equal(normalized.inputText, true);
  assert.equal(normalized.inputActivity, true);
  assert.equal(validateCaptureStartOptions({ menuActions: false }, 'darwin').menuActions, false);
  assert.throws(() => validateCaptureStartOptions({ menuActions: 'true' as unknown as boolean }));
  assert.throws(() => validateCaptureStartOptions({ applicationScope: 'allowlist', allowedApplicationIds: [] }));
  assert.throws(() => validateCaptureStartOptions({ applicationScope: 'allowlist', allowedApplicationIds: ['test.app'], allowBrowserContent: true }));
});

test('Windows default capture options disable unimplemented channels by default while preserving explicit true', () => {
  assert.equal(DEFAULT_CAPTURE_START_OPTIONS.textMarkers, true);
  assert.equal(DEFAULT_CAPTURE_START_OPTIONS.inputText, true);
  assert.equal(DEFAULT_CAPTURE_START_OPTIONS.inputActivity, true);
  assert.equal(DEFAULT_CAPTURE_START_OPTIONS.menuActions, true);

  const darwinDefaults = defaultCaptureStartOptions('darwin');
  assert.deepEqual(darwinDefaults, DEFAULT_CAPTURE_START_OPTIONS);

  const winDefaults = defaultCaptureStartOptions('win32');
  assert.equal(winDefaults.applicationScope, 'denylist');
  assert.equal(winDefaults.allowBrowserContent, true);
  assert.equal(winDefaults.fieldSecurity, 'denylist');
  assert.equal(winDefaults.axCompatibility, true);
  assert.equal(winDefaults.captureScope, 'window');
  assert.equal(winDefaults.selectionCapture, true);
  assert.equal(winDefaults.textMarkers, false);
  assert.equal(winDefaults.inputText, false);
  assert.equal(winDefaults.inputActivity, false);
  assert.equal(winDefaults.menuActions, false);

  const winNormalized = validateCaptureStartOptions({}, 'win32');
  assert.deepEqual(winNormalized, winDefaults);

  const winExplicit = validateCaptureStartOptions(
    {
      textMarkers: true,
      inputText: true,
      inputActivity: true,
      menuActions: true,
    },
    'win32',
  );
  assert.equal(winExplicit.textMarkers, true);
  assert.equal(winExplicit.inputText, true);
  assert.equal(winExplicit.inputActivity, true);
  assert.equal(winExplicit.menuActions, true);
  assert.equal(winExplicit.selectionCapture, true);
  assert.equal(winExplicit.captureScope, 'window');

  assert.throws(() => validateCaptureStartOptions({ inputText: 'true' as unknown as boolean }, 'win32'));
  assert.deepEqual(validateCaptureStartOptions({}), defaultCaptureStartOptions(process.platform));
});

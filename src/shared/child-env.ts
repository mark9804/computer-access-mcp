const WINDOWS_ESSENTIAL_ENV_KEYS = [
  'SystemRoot',
  'WINDIR',
  'SystemDrive',
  'ComSpec',
  'PATH',
  'TEMP',
  'TMP',
  'USERPROFILE',
  'LOCALAPPDATA',
  'APPDATA',
  'PATHEXT',
] as const;

const WINDOWS_ALLOWED_KEY_MAP = new Map<string, string>(
  WINDOWS_ESSENTIAL_ENV_KEYS.map((key) => [key.toLowerCase(), key]),
);

export function minimalChildEnv(
  extra: NodeJS.ProcessEnv = {},
  platform: NodeJS.Platform = process.platform,
  sourceEnv: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  if (platform !== 'win32') {
    return { ...extra };
  }

  const env: NodeJS.ProcessEnv = {};
  for (const [actualKey, value] of Object.entries(sourceEnv)) {
    if (value === undefined) continue;
    const canonical = WINDOWS_ALLOWED_KEY_MAP.get(actualKey.toLowerCase());
    if (canonical && (env[canonical] === undefined || actualKey === canonical)) {
      env[canonical] = value;
    }
  }

  for (const [key, value] of Object.entries(extra)) {
    const canonical = WINDOWS_ALLOWED_KEY_MAP.get(key.toLowerCase());
    if (canonical && canonical !== key && canonical in env) {
      delete env[canonical];
    }
    if (value !== undefined) {
      env[key] = value;
    }
  }

  return env;
}

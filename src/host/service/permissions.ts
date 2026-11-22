import { dirname } from 'node:path';
import type { PermissionStatus } from '../../shared/api-types.ts';
import type { SpawnManaged } from '../collectors/process.ts';
import { createManagedRunner, ManagedRunnerError } from '../managed-runner.ts';
import { verifyNativeBinary } from './binaries.ts';

export type PermissionAction =
  | 'check'
  | 'request-accessibility'
  | 'open-accessibility-settings'
  | 'request-input-monitoring'
  | 'open-input-monitoring-settings';

export class PermissionActionError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = 'PermissionActionError';
    this.code = code;
  }
}

const refuse = (code: string): never => {
  throw new PermissionActionError(code);
};

const ACTIONS: readonly PermissionAction[] = [
  'check',
  'request-accessibility',
  'open-accessibility-settings',
  'request-input-monitoring',
  'open-input-monitoring-settings',
];

const REASONS = new Set([
  'ready',
  'ready-console-compat',
  'session-unavailable',
  'console-unavailable',
  'login-incomplete',
  'lock-state-unavailable',
  'screen-locked',
  'desktop-signal-invalid',
  'desktop-session-changed',
  'desktop-session-mismatch',
  'desktop-lock-transition',
  'secure-input-indicated',
]);

export interface PermissionReport {
  version: 1;
  action: PermissionAction;
  accessibility: 'granted' | 'not-granted' | 'not-applicable';
  desktop: {
    status: 'unlocked' | 'locked' | 'unknown';
    reason: string;
    sessionAvailable: boolean;
    onConsole?: boolean;
    loginDone?: boolean;
    screenLocked?: boolean;
    consoleLocked?: boolean;
    registryScreenLocked?: boolean;
    registrySessionMatched?: boolean;
    sessionMatchesProcess?: boolean;
    sessionStable?: boolean;
    signalsValid?: boolean;
    lockTransition?: boolean;
    lockSource?: string;
  };
  screenRecording: 'not-required';
  promptRequested: boolean;
  settingsOpened: boolean;
  captured: false;
  inputMonitoring?: {
    state: 'granted' | 'not-granted' | 'not-applicable';
    promptRequested: boolean;
    settingsOpened: boolean;
  };
}

function checkObjectKeys(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some((k) => !keys.includes(k))) {
    refuse('permission-response-invalid');
  }
  return value as Record<string, unknown>;
}

export function parsePermissionReport(bytes: Uint8Array, action: PermissionAction): PermissionReport {
  try {
    if (!ACTIONS.includes(action) || bytes.byteLength > 4096) {
      refuse('permission-response-invalid');
    }
    const value = checkObjectKeys(
      JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)),
      [
        'version',
        'action',
        'accessibility',
        'desktop',
        'screenRecording',
        'promptRequested',
        'settingsOpened',
        'captured',
        'inputMonitoring',
      ],
    );
    if (
      value.version !== 1 ||
      value.action !== action ||
      (value.accessibility !== 'granted' &&
        value.accessibility !== 'not-granted' &&
        value.accessibility !== 'not-applicable') ||
      value.screenRecording !== 'not-required' ||
      value.captured !== false ||
      value.promptRequested !== (action === 'request-accessibility') ||
      typeof value.settingsOpened !== 'boolean' ||
      (action !== 'open-accessibility-settings' && value.settingsOpened)
    ) {
      refuse('permission-response-invalid');
    }

    if (value.inputMonitoring !== undefined) {
      const input = checkObjectKeys(value.inputMonitoring, ['state', 'promptRequested', 'settingsOpened']);
      if (
        (input.state !== 'granted' && input.state !== 'not-granted' && input.state !== 'not-applicable') ||
        input.promptRequested !== (action === 'request-input-monitoring') ||
        typeof input.settingsOpened !== 'boolean' ||
        (action !== 'open-input-monitoring-settings' && input.settingsOpened)
      ) {
        refuse('permission-response-invalid');
      }
    } else if (action === 'request-input-monitoring' || action === 'open-input-monitoring-settings') {
      refuse('permission-response-invalid');
    }

    const desktop = checkObjectKeys(value.desktop, [
      'status',
      'reason',
      'sessionAvailable',
      'onConsole',
      'loginDone',
      'screenLocked',
      'consoleLocked',
      'registryScreenLocked',
      'registrySessionMatched',
      'sessionMatchesProcess',
      'sessionStable',
      'signalsValid',
      'lockTransition',
      'lockSource',
    ]);
    if (
      (desktop.status !== 'unlocked' && desktop.status !== 'locked' && desktop.status !== 'unknown') ||
      typeof desktop.reason !== 'string' ||
      !REASONS.has(desktop.reason) ||
      typeof desktop.sessionAvailable !== 'boolean'
    ) {
      refuse('permission-response-invalid');
    }
    for (const field of [
      'onConsole',
      'loginDone',
      'screenLocked',
      'consoleLocked',
      'registryScreenLocked',
      'registrySessionMatched',
      'sessionMatchesProcess',
      'sessionStable',
      'signalsValid',
      'lockTransition',
    ]) {
      if (field in desktop && typeof desktop[field] !== 'boolean') {
        refuse('permission-response-invalid');
      }
    }
    if (
      'lockSource' in desktop &&
      (typeof desktop.lockSource !== 'string' ||
        ![
          'cg-session',
          'io-session',
          'io-console-compat',
          'locked-signal',
          'wts-session',
          'win32-desktop',
          'unknown',
        ].includes(desktop.lockSource))
    ) {
      refuse('permission-response-invalid');
    }

    if (desktop.lockSource === 'wts-session' || desktop.lockSource === 'win32-desktop') {
      const locked = desktop.screenLocked === true;
      const ready =
        !locked &&
        desktop.sessionAvailable === true &&
        desktop.sessionMatchesProcess === true &&
        desktop.sessionStable === true &&
        desktop.signalsValid === true &&
        desktop.lockTransition === false &&
        desktop.screenLocked === false;

      if (
        (desktop.status === 'unlocked') !== ready ||
        (desktop.reason === 'ready') !== ready ||
        desktop.reason === 'ready-console-compat' ||
        (desktop.status === 'locked') !== locked ||
        (locked && desktop.reason !== 'screen-locked')
      ) {
        refuse('permission-response-invalid');
      }
    } else {
      const locked =
        desktop.screenLocked === true ||
        desktop.registryScreenLocked === true ||
        desktop.consoleLocked === true;
      const base =
        desktop.sessionAvailable &&
        desktop.onConsole === true &&
        desktop.loginDone === true &&
        desktop.sessionMatchesProcess === true &&
        desktop.sessionStable === true &&
        desktop.signalsValid === true &&
        desktop.lockTransition === false;
      const explicit =
        desktop.screenLocked === false ||
        (desktop.registrySessionMatched === true && desktop.registryScreenLocked === false);
      const compatible =
        desktop.registrySessionMatched === true &&
        desktop.consoleLocked === false &&
        desktop.lockSource === 'io-console-compat';
      const ready = !locked && base && (explicit || compatible);

      if (
        (desktop.status === 'unlocked') !== ready ||
        ['ready', 'ready-console-compat'].includes(String(desktop.reason)) !== ready
      ) {
        refuse('permission-response-invalid');
      }
      if (ready && (desktop.reason === 'ready-console-compat') !== (!explicit && compatible)) {
        refuse('permission-response-invalid');
      }
      if ((desktop.status === 'locked') !== locked || (locked && desktop.reason !== 'screen-locked')) {
        refuse('permission-response-invalid');
      }
    }

    return value as unknown as PermissionReport;
  } catch (error) {
    if (error instanceof PermissionActionError) throw error;
    return refuse('permission-response-invalid');
  }
}

export function toPermissionStatus(
  report: PermissionReport & { checkedAt: number },
  platform: string = process.platform,
): PermissionStatus {
  return {
    platform,
    accessibility: report.accessibility,
    inputMonitoring: report.inputMonitoring?.state ?? 'unknown',
    desktopStatus: report.desktop.status,
    desktopReason: report.desktop.reason,
    promptRequested: report.promptRequested || report.inputMonitoring?.promptRequested === true,
    settingsOpened: report.settingsOpened || report.inputMonitoring?.settingsOpened === true,
    checkedAtMs: report.checkedAt,
  };
}

export function createPermissionActions(options: { executable: string; spawn?: SpawnManaged }) {
  const runner = createManagedRunner({
    ...(options.spawn ? { spawn: options.spawn } : {}),
    cwd: dirname(options.executable),
  });
  let closed = false;
  let busy = false;

  return {
    async perform(
      action: PermissionAction,
      signal?: AbortSignal,
    ): Promise<PermissionReport & { helperPath: string; checkedAt: number }> {
      if (closed || runner.poisoned) refuse('permission-helper-unavailable');
      if (busy) refuse('permission-action-busy');
      if (!ACTIONS.includes(action) || signal?.aborted) refuse('permission-action-cancelled');

      busy = true;
      try {
        await verifyNativeBinary(options.executable, 'computer-access-collector');
        if (closed || signal?.aborted) refuse('permission-action-cancelled');

        const result = await runner.run({
          executable: options.executable,
          args: ['--permissions', action],
          stdin: '',
          timeoutMs: 6_000,
          maxOutputBytes: 4_096,
          ...(signal ? { signal } : {}),
        });
        if (closed || signal?.aborted) refuse('permission-action-cancelled');
        if (result.exitCode !== 0) refuse('permission-helper-exit-failed');

        return {
          ...parsePermissionReport(result.stdout, action),
          helperPath: options.executable,
          checkedAt: Date.now(),
        };
      } catch (error) {
        if (error instanceof PermissionActionError) throw error;
        if (error instanceof ManagedRunnerError) {
          if (error.code === 'timeout') refuse('permission-action-timeout');
          if (error.code === 'cancelled' || error.code === 'cancelled-after-dispatch') {
            refuse('permission-action-cancelled');
          }
          if (error.code === 'exit-unconfirmed') refuse('permission-helper-exit-unconfirmed');
          if (error.code === 'busy') refuse('permission-action-busy');
        }
        return refuse('permission-helper-unavailable');
      } finally {
        busy = false;
      }
    },

    async close(): Promise<void> {
      closed = true;
      try {
        await runner.close();
      } catch {
        refuse('permission-helper-exit-unconfirmed');
      }
    },
  };
}

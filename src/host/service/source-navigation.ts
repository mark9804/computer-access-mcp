import { dirname } from 'node:path';
import type { ApplicationTargetIdentity } from '../../shared/protocol/generated.ts';
import type { SpawnManaged } from '../collectors/process.ts';
import { createManagedRunner, ManagedRunnerError } from '../managed-runner.ts';
import { verifyNativeBinary } from './binaries.ts';

export type NavigationOutcome = 'activated' | 'refused' | 'uncertain';

export interface SourceNavigationReport {
  version: 1;
  outcome: NavigationOutcome;
  reason: string;
  captured: false;
  launched: false;
}

const NATIVE_REASONS = new Set([
  'activated',
  'invalid-request',
  'input-too-large',
  'input-timeout',
  'input-unavailable',
  'parent-unavailable',
  'deadline-exceeded',
  'session-unavailable',
  'session-mismatch',
  'desktop-unavailable',
  'application-unavailable',
  'application-mismatch',
  'application-blocked',
  'activation-rejected',
  'activation-unconfirmed',
  'postcondition-changed',
  'internal-error',
]);

const UNCERTAIN_REASONS = new Set([
  'activation-rejected',
  'activation-unconfirmed',
  'postcondition-changed',
  'parent-unavailable',
  'deadline-exceeded',
]);

export const navigationReport = (
  outcome: NavigationOutcome,
  reason: string,
): SourceNavigationReport => ({
  version: 1,
  outcome,
  reason,
  captured: false,
  launched: false,
});

export function parseSourceNavigationReport(bytes: Uint8Array): SourceNavigationReport {
  try {
    if (bytes.byteLength > 1024) throw new Error();
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (
      !value ||
      typeof value !== 'object' ||
      Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'captured,launched,outcome,reason,version'
    ) {
      throw new Error();
    }
    const obj = value as Record<string, unknown>;
    if (
      obj.version !== 1 ||
      obj.captured !== false ||
      obj.launched !== false ||
      typeof obj.reason !== 'string' ||
      !NATIVE_REASONS.has(obj.reason) ||
      (obj.outcome !== 'activated' && obj.outcome !== 'refused' && obj.outcome !== 'uncertain') ||
      (obj.outcome === 'activated') !== (obj.reason === 'activated') ||
      (obj.outcome === 'uncertain' && !UNCERTAIN_REASONS.has(obj.reason)) ||
      (obj.outcome === 'refused' &&
        ['activation-rejected', 'activation-unconfirmed', 'postcondition-changed'].includes(obj.reason))
    ) {
      throw new Error();
    }
    return obj as unknown as SourceNavigationReport;
  } catch {
    throw new Error('navigation-response-invalid');
  }
}

function formatNavigationInput(target: ApplicationTargetIdentity): string {
  const validMacSession =
    /^audit-[0-9]{1,10}$/.test(target.osSessionId) && target.desktopId === `console-${target.osSessionId}`;
  const validWindowsSession =
    /^wts-[0-9]{1,10}$/.test(target.osSessionId) && target.desktopId === `winsta0-default-${target.osSessionId}`;
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/.test(target.applicationId) ||
    !Number.isSafeInteger(target.processId) ||
    target.processId < 2 ||
    target.processId > 2147483647 ||
    !/^unix-ms:[0-9]{1,16}\.[0-9]{3}$/.test(target.processStartTime) ||
    (!validMacSession && !validWindowsSession)
  ) {
    throw new Error('navigation-target-unavailable');
  }
  return (
    JSON.stringify({
      version: 1,
      applicationId: target.applicationId,
      processId: target.processId,
      processStartTime: target.processStartTime,
      osSessionId: target.osSessionId,
      desktopId: target.desktopId,
    }) + '\n'
  );
}

export function createSourceNavigation(options: { executable: string; spawn?: SpawnManaged }) {
  const runner = createManagedRunner({
    ...(options.spawn ? { spawn: options.spawn } : {}),
    cwd: dirname(options.executable),
  });
  let closed = false;
  let busy = false;

  return {
    async navigate(
      target: ApplicationTargetIdentity,
      signal?: AbortSignal,
      assertCurrent: () => void = () => {},
    ): Promise<SourceNavigationReport> {
      if (closed || runner.poisoned) return navigationReport('refused', 'navigation-unavailable');
      if (busy) return navigationReport('refused', 'navigation-busy');

      let input: string;
      try {
        input = formatNavigationInput(target);
      } catch {
        return navigationReport('refused', 'navigation-target-unavailable');
      }
      if (signal?.aborted) return navigationReport('refused', 'navigation-cancelled');

      busy = true;
      let dispatched = false;
      const checkAuthority = () => {
        try {
          assertCurrent();
        } catch {
          throw new Error('navigation-cancelled');
        }
      };
      try {
        checkAuthority();
        await verifyNativeBinary(options.executable, 'computer-access-collector');
        if (closed || signal?.aborted) return navigationReport('refused', 'navigation-cancelled');
        checkAuthority();

        const res = await runner.run({
          executable: options.executable,
          args: ['--navigate-source'],
          stdin: input,
          timeoutMs: 6_000,
          maxOutputBytes: 1_024,
          ...(signal ? { signal } : {}),
        });
        dispatched = true;

        if (closed || signal?.aborted) {
          return navigationReport('uncertain', 'navigation-cancelled-after-dispatch');
        }
        checkAuthority();

        const parsed = parseSourceNavigationReport(res.stdout);
        if (parsed.outcome === 'activated' && res.exitCode !== 0) {
          return navigationReport('uncertain', 'navigation-response-invalid');
        }
        return parsed;
      } catch (error) {
        if (error instanceof ManagedRunnerError) {
          dispatched = dispatched || error.dispatched;
          if (error.code === 'busy') return navigationReport('refused', 'navigation-busy');
          if (error.code === 'closed') return navigationReport('refused', 'navigation-unavailable');
          if (error.code === 'cancelled') return navigationReport('refused', 'navigation-cancelled');
          if (error.code === 'cancelled-after-dispatch') {
            return navigationReport('uncertain', 'navigation-cancelled-after-dispatch');
          }
          if (error.code === 'timeout') return navigationReport('uncertain', 'navigation-timeout');
          if (error.code === 'output-limit' || error.code === 'response-invalid') {
            return navigationReport('uncertain', 'navigation-response-invalid');
          }
          if (error.code === 'exit-unconfirmed') {
            return navigationReport('uncertain', 'navigation-exit-unconfirmed');
          }
          return navigationReport(dispatched ? 'uncertain' : 'refused', 'navigation-helper-unavailable');
        }
        if (error instanceof Error && error.message === 'navigation-response-invalid') {
          return navigationReport('uncertain', 'navigation-response-invalid');
        }
        if (error instanceof Error && error.message === 'navigation-cancelled') {
          return navigationReport(
            dispatched ? 'uncertain' : 'refused',
            dispatched ? 'navigation-cancelled-after-dispatch' : 'navigation-cancelled',
          );
        }
        return navigationReport(dispatched ? 'uncertain' : 'refused', 'navigation-helper-unavailable');
      } finally {
        busy = false;
      }
    },

    cancel(): void {
      runner.cancel();
    },

    async close(): Promise<void> {
      closed = true;
      try {
        await runner.close();
      } catch {
        throw new Error('shutdown-unconfirmed');
      }
    },
  };
}

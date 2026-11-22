import * as React from 'react';
import type { PermissionGrantState, PermissionStatus, ServiceLifecycleState, ServiceStatus } from '../../shared/api-types.ts';
import { formatBytes, formatDurationDays, formatTime } from '../format.ts';
import type { MessageKey, Translate } from '../i18n.ts';
import { Button } from '../ui.tsx';

type OverviewTabProps = {
  status: ServiceStatus;
  permissions: PermissionStatus;
  dataRoot: string;
  busy: boolean;
  t: Translate;
  onInitKey: () => void;
  onStart: () => void;
  onPause: () => void;
  onResume: () => void;
  onStop: () => void;
  onReloadCollector: () => void;
  onRecheckPermissions: () => void;
  onPermissionAction: (
    action: 'request-accessibility' | 'open-accessibility' | 'request-input-monitoring' | 'open-input-monitoring',
  ) => void;
};

const STATE_KEY: Record<ServiceLifecycleState, MessageKey> = {
  'not-initialized': 'state_not_initialized',
  stopped: 'state_stopped',
  starting: 'state_starting',
  running: 'state_running',
  paused: 'state_paused',
  failed: 'state_failed',
};

const STATE_TONE: Record<ServiceLifecycleState, 'ok' | 'warn' | 'danger' | 'idle'> = {
  'not-initialized': 'warn',
  stopped: 'idle',
  starting: 'warn',
  running: 'ok',
  paused: 'warn',
  failed: 'danger',
};

const PERM_KEY: Record<PermissionGrantState, MessageKey> = {
  granted: 'perm_granted',
  'not-granted': 'perm_not_granted',
  unknown: 'unknown',
  'not-applicable': 'perm_not_applicable',
};

const DESKTOP_KEY: Record<PermissionStatus['desktopStatus'], MessageKey> = {
  unlocked: 'desktop_unlocked',
  locked: 'desktop_locked',
  unknown: 'unknown',
};

export function OverviewTab({
  status,
  permissions,
  dataRoot,
  busy,
  t,
  onInitKey,
  onStart,
  onPause,
  onResume,
  onStop,
  onReloadCollector,
  onRecheckPermissions,
  onPermissionAction,
}: OverviewTabProps) {
  const storage = status.storage;
  const collector = status.collector;
  const isMac = permissions.platform === 'darwin' || status.platform === 'darwin';

  return (
    <div>
      <div className="camcp-grid-2">
        <section className="camcp-card">
          <div className="camcp-card-header">
            <div>
              <h2>{t('serviceStateTitle')}</h2>
              <p className="camcp-muted">{status.reason}</p>
            </div>
            <span className="camcp-badge">
              <span className="camcp-dot" data-tone={STATE_TONE[status.state]} />
              {t(STATE_KEY[status.state])}
            </span>
          </div>

          <dl className="camcp-stats">
            <div>
              <dt>{t('platformLabel')}</dt>
              <dd>{status.platform}</dd>
            </div>
            <div>
              <dt>{t('deviceLabel')}</dt>
              <dd className="camcp-mono">{status.deviceId}</dd>
            </div>
            <div style={{ gridColumn: '1 / -1' }}>
              <dt>{t('dataRootLabel')}</dt>
              <dd className="camcp-mono">{dataRoot || status.dataRoot}</dd>
            </div>
          </dl>

          <div className="camcp-actions">
            {status.state === 'not-initialized' ? (
              <Button variant="primary" disabled={busy} onClick={onInitKey}>
                {t('initKey')}
              </Button>
            ) : null}
            {(status.state === 'stopped' || status.state === 'failed') ? (
              <Button variant="primary" disabled={busy} onClick={onStart}>
                {t('startCapture')}
              </Button>
            ) : null}
            {status.state === 'running' ? (
              <Button disabled={busy} onClick={onPause}>
                {t('pauseCapture')}
              </Button>
            ) : null}
            {status.state === 'paused' ? (
              <Button variant="primary" disabled={busy} onClick={onResume}>
                {t('resumeCapture')}
              </Button>
            ) : null}
            {(status.state === 'running' || status.state === 'paused' || status.state === 'starting') ? (
              <Button variant="danger" disabled={busy} onClick={onStop}>
                {t('stopCapture')}
              </Button>
            ) : null}
            {status.state !== 'not-initialized' ? (
              <Button disabled={busy} onClick={onReloadCollector}>
                {t('reloadCollector')}
              </Button>
            ) : null}
          </div>
        </section>

        <section className="camcp-card">
          <div className="camcp-card-header">
            <div>
              <h2>{t('permissionsTitle')}</h2>
              <p className="camcp-muted">{t('permissionsDesc')}</p>
            </div>
            <Button disabled={busy} onClick={onRecheckPermissions}>
              {t('recheckPermissions')}
            </Button>
          </div>

          <dl className="camcp-stats">
            <div>
              <dt>{t('permAccessibility')}</dt>
              <dd>
                <span className="camcp-badge">
                  <span
                    className="camcp-dot"
                    data-tone={permissions.accessibility === 'granted' ? 'ok' : 'warn'}
                  />
                  {t(PERM_KEY[permissions.accessibility])}
                </span>
              </dd>
            </div>
            <div>
              <dt>{t('permInputMonitoring')}</dt>
              <dd>
                <span className="camcp-badge">
                  <span
                    className="camcp-dot"
                    data-tone={permissions.inputMonitoring === 'granted' ? 'ok' : 'idle'}
                  />
                  {t(PERM_KEY[permissions.inputMonitoring])}
                </span>
              </dd>
            </div>
            <div>
              <dt>{t('desktopStateLabel')}</dt>
              <dd>{t(DESKTOP_KEY[permissions.desktopStatus])}</dd>
            </div>
          </dl>

          {isMac ? (
            <div className="camcp-actions">
              <Button disabled={busy} onClick={() => onPermissionAction('request-accessibility')}>
                {t('permAccessibility')}: {t('requestPermission')}
              </Button>
              <Button disabled={busy} onClick={() => onPermissionAction('open-accessibility')}>
                {t('permAccessibility')}: {t('openSystemSettings')}
              </Button>
              <Button disabled={busy} onClick={() => onPermissionAction('request-input-monitoring')}>
                {t('permInputMonitoring')}: {t('requestPermission')}
              </Button>
              <Button disabled={busy} onClick={() => onPermissionAction('open-input-monitoring')}>
                {t('permInputMonitoring')}: {t('openSystemSettings')}
              </Button>
            </div>
          ) : null}
        </section>
      </div>

      <section className="camcp-card">
        <h2>{t('storageTitle')}</h2>
        {!storage ? (
          <p className="camcp-muted">{t('storageUninitialized')}</p>
        ) : (
          <dl className="camcp-stats">
            <div>
              <dt>{t('colStatus')}</dt>
              <dd>{storage.state}</dd>
            </div>
            <div>
              <dt>{t('segmentsLabel')}</dt>
              <dd>{storage.segments}</dd>
            </div>
            <div>
              <dt>{t('recordsLabel')}</dt>
              <dd>{storage.records}</dd>
            </div>
            <div>
              <dt>{t('sizeLabel')}</dt>
              <dd>{formatBytes(storage.bytes)}</dd>
            </div>
            <div>
              <dt>{t('retentionLabel')}</dt>
              <dd>{formatDurationDays(storage.retentionMs)}</dd>
            </div>
            <div>
              <dt>{t('budgetLabel')}</dt>
              <dd>{formatBytes(storage.maxBytes)}</dd>
            </div>
            <div>
              <dt>{t('gapCountsLabel')}</dt>
              <dd>
                exception {storage.counts.gapException} / discarded {storage.counts.gapDiscarded}
              </dd>
            </div>
            <div style={{ gridColumn: '1 / -1' }}>
              <dt>{t('timeRangeLabel')}</dt>
              <dd>
                {storage.retainedTimeRange
                  ? `${formatTime(storage.retainedTimeRange.fromTimeMs)} -> ${formatTime(storage.retainedTimeRange.toTimeMs)}`
                  : '-'}
              </dd>
            </div>
          </dl>
        )}

        {collector ? (
          <>
            <h3>{t('collectorTitle')}</h3>
            <dl className="camcp-stats">
              <div>
                <dt>{t('acceptedCountsLabel')}</dt>
                <dd>
                  text {collector.accepted.text} / surface {collector.accepted.surface} / selection{' '}
                  {collector.accepted.selection} / input {collector.accepted.inputText} / activity{' '}
                  {collector.accepted.activity} / menu {collector.accepted.menu} / exception{' '}
                  {collector.accepted.gapsException} / discarded {collector.accepted.gapsDiscarded}
                </dd>
              </div>
              <div>
                <dt>{t('lastExceptionLabel')}</dt>
                <dd className="camcp-mono">
                  {collector.lastExceptionDiagnostic?.code ?? collector.lastExceptionReason ?? '-'}
                </dd>
              </div>
            </dl>
          </>
        ) : null}
      </section>
    </div>
  );
}

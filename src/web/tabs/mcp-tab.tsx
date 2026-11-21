import * as React from 'react';
import type {
  ClientLease,
  ClientScope,
  CreateLeaseRequest,
  CreateLeaseResponse,
  StdioLauncherSpec,
} from '../../shared/api-types.ts';
import { copyTextToClipboard, formatTime } from '../format.ts';
import type { Translate } from '../i18n.ts';
import { Button, Checkbox, ChoiceCards, CollapsibleSection, Field, Input } from '../ui.tsx';

type DurationChoice = '30m' | '24h' | '7d' | '30d' | 'never';

const DURATION_MS: Record<DurationChoice, number | null> = {
  '30m': 30 * 60_000,
  '24h': 24 * 3_600_000,
  '7d': 7 * 24 * 3_600_000,
  '30d': 30 * 24 * 3_600_000,
  never: null,
};

function resolveMcpUrl(): string {
  if (typeof window !== 'undefined' && /^https?:\/\//i.test(window.location.origin)) {
    return `${window.location.origin}/mcp`;
  }
  return 'http://127.0.0.1:43180/mcp';
}

function buildHttpConfig(token: string, mcpUrl: string): string {
  return JSON.stringify(
    {
      mcpServers: {
        'computer-access': {
          url: mcpUrl,
          headers: {
            Authorization: `Bearer ${token}`,
          },
        },
      },
    },
    null,
    2,
  );
}

function buildStdioConfig(token: string, mcpUrl: string, launcher?: StdioLauncherSpec | undefined): string {
  return JSON.stringify(
    {
      mcpServers: {
        'computer-access': {
          command: launcher?.command ?? 'computer-access-mcp',
          args: launcher?.args ?? ['stdio'],
          env: {
            COMPUTER_ACCESS_TOKEN: token,
            COMPUTER_ACCESS_URL: mcpUrl,
          },
        },
      },
    },
    null,
    2,
  );
}

function leaseStatusOf(lease: ClientLease, now: number): 'active' | 'expired' | 'revoked' {
  if (lease.revokedAtMs !== null) return 'revoked';
  if (lease.expiresAtMs !== null && now >= lease.expiresAtMs) return 'expired';
  return 'active';
}

type McpTabProps = {
  leases: ClientLease[];
  createdToken: CreateLeaseResponse | null;
  stdioLauncher?: StdioLauncherSpec | undefined;
  onDismissCreated: () => void;
  onCreateLease: (req: CreateLeaseRequest) => void;
  onRevokeLease: (id: string) => void;
  onNotify: (message: string, tone?: 'info' | 'danger') => void;
  busy: boolean;
  t: Translate;
};

export function McpTab({
  leases,
  createdToken,
  stdioLauncher,
  onDismissCreated,
  onCreateLease,
  onRevokeLease,
  onNotify,
  busy,
  t,
}: McpTabProps) {
  const [label, setLabel] = React.useState('antigravity');
  const [duration, setDuration] = React.useState<DurationChoice>('7d');
  const [allowPause, setAllowPause] = React.useState(false);
  const [allowReload, setAllowReload] = React.useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanLabel = label.trim() || 'mcp-client';
    const scopes: ClientScope[] = ['read'];
    if (allowPause) scopes.push('pause');
    if (allowReload) scopes.push('reload');
    onCreateLease({
      label: cleanLabel,
      scopes,
      ttlMs: DURATION_MS[duration],
    });
  };

  const handleCopy = async (text: string) => {
    const ok = await copyTextToClipboard(text);
    onNotify(ok ? t('copied') : t('copyFailed'), ok ? 'info' : 'danger');
  };

  const mcpUrl = resolveMcpUrl();
  const now = Date.now();

  return (
    <div>
      {createdToken ? (
        <section className="camcp-card" style={{ borderColor: 'var(--camcp-brand)' }}>
          <div className="camcp-card-header">
            <div>
              <h2>{t('tokenCreatedTitle')}</h2>
              <p className="camcp-muted">{t('tokenCreatedNotice')}</p>
            </div>
            <Button variant="ghost" onClick={onDismissCreated}>
              {t('dismiss')}
            </Button>
          </div>

          <div className="camcp-field">
            <span className="camcp-label">{createdToken.lease.label}</span>
            <pre className="camcp-pre">{createdToken.token}</pre>
          </div>

          <div className="camcp-actions">
            <Button
              variant="primary"
              onClick={() => void handleCopy(buildHttpConfig(createdToken.token, mcpUrl))}
            >
              {t('copyHttpConfig')}
            </Button>
            <Button
              variant="primary"
              onClick={() => void handleCopy(buildStdioConfig(createdToken.token, mcpUrl, stdioLauncher))}
            >
              {t('copyStdioConfig')}
            </Button>
            <Button onClick={() => void handleCopy(createdToken.token)}>{t('copyRawToken')}</Button>
          </div>

          <CollapsibleSection title={t('configPreviewLabel')}>
            <div className="camcp-grid-2">
              <div>
                <div className="camcp-label">HTTP</div>
                <pre className="camcp-pre">{buildHttpConfig(createdToken.token, mcpUrl)}</pre>
              </div>
              <div>
                <div className="camcp-label">stdio</div>
                <pre className="camcp-pre">{buildStdioConfig(createdToken.token, mcpUrl, stdioLauncher)}</pre>
              </div>
            </div>
          </CollapsibleSection>
        </section>
      ) : null}

      <section className="camcp-card">
        <h2>{t('mcpCreateTitle')}</h2>
        <p className="camcp-muted">{t('mcpCreateDesc')}</p>
        <form onSubmit={handleSubmit}>
          <Field id="lease-label" label={t('leaseLabelField')}>
            <Input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="antigravity"
              maxLength={64}
            />
          </Field>

          <ChoiceCards
            id="lease-duration"
            label={t('leaseDurationField')}
            compact
            value={duration}
            onChange={setDuration}
            options={[
              { value: '30m', label: '30m' },
              { value: '24h', label: '24h' },
              { value: '7d', label: '7d' },
              { value: '30d', label: '30d' },
              { value: 'never', label: t('ttl_never') },
            ]}
          />

          <div className="camcp-field">
            <div className="camcp-label">{t('leaseScopesField')}</div>
            <Checkbox
              id="scope-read"
              label={t('scopeReadLabel')}
              checked
              disabled
              onChange={() => {}}
            />
            <Checkbox
              id="scope-pause"
              label={t('scopePauseLabel')}
              checked={allowPause}
              onChange={setAllowPause}
            />
            <Checkbox
              id="scope-reload"
              label={t('scopeReloadLabel')}
              checked={allowReload}
              onChange={setAllowReload}
            />
          </div>

          <div className="camcp-actions">
            <Button type="submit" variant="primary" disabled={busy || !label.trim()}>
              {t('createTokenBtn')}
            </Button>
          </div>
        </form>
      </section>

      <section className="camcp-card">
        <h2>{t('leasesListTitle')}</h2>
        {leases.length === 0 ? (
          <div className="camcp-empty">{t('leasesEmpty')}</div>
        ) : (
          <div className="camcp-table-wrap">
            <table className="camcp-table">
              <thead>
                <tr>
                  <th>{t('colName')}</th>
                  <th>{t('colStatus')}</th>
                  <th>{t('colScopes')}</th>
                  <th>{t('colValidity')}</th>
                  <th>{t('colLastUsed')}</th>
                  <th>{t('colAction')}</th>
                </tr>
              </thead>
              <tbody>
                {leases.map((lease) => {
                  const st = leaseStatusOf(lease, now);
                  const tone = st === 'active' ? 'ok' : st === 'expired' ? 'warn' : 'danger';
                  return (
                    <tr key={lease.id}>
                      <td>
                        <strong>{lease.label}</strong>
                      </td>
                      <td>
                        <span className="camcp-badge">
                          <span className="camcp-dot" data-tone={tone} />
                          {t(`leaseStatus_${st}`)}
                        </span>
                      </td>
                      <td className="camcp-mono">{lease.scopes.join(', ')}</td>
                      <td>
                        {formatTime(lease.createdAtMs)} {'->'}{' '}
                        {lease.expiresAtMs ? formatTime(lease.expiresAtMs) : t('never')}
                      </td>
                      <td>{lease.lastUsedAtMs ? formatTime(lease.lastUsedAtMs) : t('never')}</td>
                      <td>
                        {st === 'active' ? (
                          <Button
                            variant="danger"
                            disabled={busy}
                            onClick={() => onRevokeLease(lease.id)}
                          >
                            {t('revokeBtn')}
                          </Button>
                        ) : (
                          '-'
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

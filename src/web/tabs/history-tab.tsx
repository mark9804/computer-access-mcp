import * as React from 'react';
import type {
  HistoryLayoutResult,
  HistoryQuery,
  HistoryQueryKind,
  HistoryQueryResult,
} from '../../shared/api-types.ts';
import { classifyGap } from '../../shared/gap-classification.ts';
import type { Observation } from '../../shared/protocol/generated.ts';
import { formatTime } from '../format.ts';
import type { MessageKey, Translate } from '../i18n.ts';
import { Button, ChoiceCards, Field, Input, Select } from '../ui.tsx';

type ForgetWindow = '1h' | '24h' | '7d';
const FORGET_HOURS: Record<ForgetWindow, number> = {
  '1h': 1,
  '24h': 24,
  '7d': 168,
};

const KIND_OPTIONS: { value: HistoryQueryKind; key: MessageKey }[] = [
  { value: 'all', key: 'kind_all' },
  { value: 'text', key: 'kind_text' },
  { value: 'surface', key: 'kind_surface' },
  { value: 'selection', key: 'kind_selection' },
  { value: 'input', key: 'kind_input' },
  { value: 'activity', key: 'kind_activity' },
  { value: 'menu', key: 'kind_menu' },
  { value: 'context', key: 'kind_context' },
  { value: 'exception', key: 'kind_exception' },
  { value: 'discarded', key: 'kind_discarded' },
  { value: 'gap', key: 'kind_gap' },
];

function extractTargetLabel(obs: Observation): string {
  if (obs.target.kind === 'resolved' || obs.target.kind === 'application') {
    return obs.target.identity.applicationId;
  }
  return obs.target.reason;
}

function summarizeObservation(obs: Observation, noTextFallback: string): string {
  const p = obs.payload;
  switch (p.kind) {
    case 'text.snapshot':
      return p.text ?? `[${p.valueState}]`;
    case 'text.changed':
      return p.after.text ?? `[${p.after.valueState}]`;
    case 'selection.snapshot':
      return p.text || noTextFallback;
    case 'input.text':
      return p.text || `[${p.eventKind}]`;
    case 'surface.snapshot': {
      const texts = p.nodes
        .map((n) => n.text?.trim())
        .filter((s): s is string => Boolean(s));
      return texts.length > 0
        ? `[${p.scope} ${p.mode}, ${p.nodes.length} nodes] ${texts.slice(0, 6).join(' | ')}`
        : `[${p.scope} ${p.mode}, ${p.nodes.length} nodes]`;
    }
    case 'input.activity':
      return `clicks=${p.counts.pointerReleases} scrolls=${p.counts.scrollSamples} drags=${p.counts.dragSamples} shortcuts=${p.counts.shortcutPresses}`;
    case 'menu.action':
      return `menu: ${p.path.join(' > ')}`;
    case 'context.changed':
      return `context: ${p.reason}`;
    case 'gap': {
      const disposition = classifyGap(p);
      return `${disposition}: ${p.diagnostic?.code ?? p.reason} (x${p.count})`;
    }
  }
}

type HistoryTabProps = {
  result: HistoryQueryResult | null;
  inspectedRecord: Observation | null;
  layoutResult: HistoryLayoutResult | null;
  canPrevPage: boolean;
  busy: boolean;
  t: Translate;
  onSearch: (query: HistoryQuery, resetPagination: boolean) => void;
  onPrevPage: () => void;
  onNextPage: () => void;
  onInspect: (eventId: string) => void;
  onLoadLayout: (eventId: string) => void;
  onCloseInspector: () => void;
  onOpenSource: (eventId: string) => void;
  onForgetOlderThan: (beforeMs: number) => void;
  onForgetAll: () => void;
};

export function HistoryTab({
  result,
  inspectedRecord,
  layoutResult,
  canPrevPage,
  busy,
  t,
  onSearch,
  onPrevPage,
  onNextPage,
  onInspect,
  onLoadLayout,
  onCloseInspector,
  onOpenSource,
  onForgetOlderThan,
  onForgetAll,
}: HistoryTabProps) {
  const [keyword, setKeyword] = React.useState('');
  const [appFilter, setAppFilter] = React.useState('');
  const [kind, setKind] = React.useState<HistoryQueryKind>('all');
  const [forgetWindow, setForgetWindow] = React.useState<ForgetWindow>('24h');
  const [confirmAll, setConfirmAll] = React.useState(false);

  const buildQuery = (): HistoryQuery => {
    const q: HistoryQuery = { kind, limit: 25, order: 'desc' };
    if (keyword.trim()) q.text = keyword.trim();
    if (appFilter.trim()) q.applicationId = appFilter.trim();
    return q;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSearch(buildQuery(), true);
  };

  const handleClear = () => {
    setKeyword('');
    setAppFilter('');
    setKind('all');
    onSearch({ kind: 'all', limit: 25, order: 'desc' }, true);
  };

  return (
    <div>
      <section className="chmcp-card">
        <h2>{t('historySearchTitle')}</h2>
        <form onSubmit={handleSubmit}>
          <div className="chmcp-search-bar">
            <Field id="hist-keyword" label={t('keywordLabel')}>
              <Input
                value={keyword}
                onChange={(e) => setKeyword(e.target.value)}
                placeholder={t('keywordPlaceholder')}
              />
            </Field>
            <Field id="hist-app" label={t('appFilterLabel')}>
              <Input
                value={appFilter}
                onChange={(e) => setAppFilter(e.target.value)}
                placeholder="com.google.antigravity-ide"
              />
            </Field>
            <Field id="hist-kind" label={t('kindFilterLabel')}>
              <Select value={kind} onChange={(e) => setKind(e.target.value as HistoryQueryKind)}>
                {KIND_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {t(opt.key)}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <div className="chmcp-actions">
            <Button type="submit" variant="primary" disabled={busy}>
              {t('searchBtn')}
            </Button>
            <Button disabled={busy} onClick={handleClear}>
              {t('clearFiltersBtn')}
            </Button>
          </div>
        </form>

        {!result || result.records.length === 0 ? (
          <div className="chmcp-empty">{t('recordsEmpty')}</div>
        ) : (
          <>
            <ul className="chmcp-record-list">
              {result.records.map((rec) => {
                const isSurface = rec.payload.kind === 'surface.snapshot';
                const canOpen =
                  rec.target.kind === 'resolved' || rec.target.kind === 'application';
                return (
                  <li key={rec.eventId} className="chmcp-record-item">
                    <div className="chmcp-record-head">
                      <div>
                        <span className="chmcp-badge chmcp-mono">{rec.payload.kind}</span>{' '}
                        <code className="chmcp-mono">{extractTargetLabel(rec)}</code>{' '}
                        <span className="chmcp-muted">{formatTime(rec.eventTimeMs)}</span>
                      </div>
                      <div className="chmcp-actions" style={{ marginTop: 0 }}>
                        <Button disabled={busy} onClick={() => onInspect(rec.eventId)}>
                          {t('inspectRecord')}
                        </Button>
                        {isSurface ? (
                          <Button disabled={busy} onClick={() => onLoadLayout(rec.eventId)}>
                            {t('loadLayout')}
                          </Button>
                        ) : null}
                        {canOpen ? (
                          <Button disabled={busy} onClick={() => onOpenSource(rec.eventId)}>
                            {t('openSourceApp')}
                          </Button>
                        ) : null}
                      </div>
                    </div>
                    <pre className="chmcp-pre">
                      {summarizeObservation(rec, t('noTextBody'))}
                    </pre>
                  </li>
                );
              })}
            </ul>

            <div className="chmcp-actions" style={{ justifyContent: 'space-between' }}>
              <Button disabled={busy || !canPrevPage} onClick={onPrevPage}>
                {t('prevPage')}
              </Button>
              <Button disabled={busy || !result.hasMore} onClick={onNextPage}>
                {t('nextPage')}
              </Button>
            </div>
          </>
        )}
      </section>

      {(inspectedRecord || layoutResult) ? (
        <section className="chmcp-card">
          <div className="chmcp-card-header">
            <h2>{t('inspectorTitle')}</h2>
            <Button variant="ghost" onClick={onCloseInspector}>
              {t('dismiss')}
            </Button>
          </div>

          {inspectedRecord ? (
            <pre className="chmcp-pre">{JSON.stringify(inspectedRecord, null, 2)}</pre>
          ) : null}

          {layoutResult ? (
            layoutResult.found ? (
              <div className="chmcp-table-wrap">
                <table className="chmcp-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Role</th>
                      <th>Bounds [x, y, w, h]</th>
                      <th>Text</th>
                    </tr>
                  </thead>
                  <tbody>
                    {layoutResult.nodes.map((node) => (
                      <tr key={`${node.id}-${node.textOffset}`}>
                        <td className="chmcp-mono">
                          {node.id}
                          {node.focused ? ' *' : ''}
                        </td>
                        <td className="chmcp-mono">{node.role}</td>
                        <td className="chmcp-mono">
                          {node.bounds ? `[${node.bounds.join(', ')}]` : '-'}
                        </td>
                        <td>{node.text ?? t('noTextBody')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="chmcp-muted">
                {t('layoutUnavailable')}: <code>{layoutResult.reason}</code>
              </p>
            )
          ) : null}
        </section>
      ) : null}

      <section className="chmcp-card">
        <h2>{t('forgetTitle')}</h2>
        <p className="chmcp-muted">{t('forgetNotice')}</p>

        <ChoiceCards
          id="forget-window"
          label={t('forgetWindowField')}
          compact
          value={forgetWindow}
          onChange={(v) => {
            setForgetWindow(v);
            setConfirmAll(false);
          }}
          options={[
            { value: '1h', label: '1h' },
            { value: '24h', label: '24h' },
            { value: '7d', label: '7d' },
          ]}
        />

        <div className="chmcp-actions">
          <Button
            variant="danger"
            disabled={busy}
            onClick={() => onForgetOlderThan(Date.now() - FORGET_HOURS[forgetWindow] * 3_600_000)}
          >
            {t('forgetOlderBtn')}
          </Button>

          {!confirmAll ? (
            <Button variant="danger" disabled={busy} onClick={() => setConfirmAll(true)}>
              {t('forgetAllBtn')}
            </Button>
          ) : (
            <Button
              variant="danger"
              disabled={busy}
              onClick={() => {
                setConfirmAll(false);
                onForgetAll();
              }}
            >
              {t('forgetConfirmAll')}
            </Button>
          )}
        </div>
      </section>
    </div>
  );
}

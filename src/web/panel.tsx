import * as React from 'react';
import type {
  ClientLease,
  CreateLeaseRequest,
  CreateLeaseResponse,
  HistoryLayoutResult,
  HistoryQuery,
  HistoryQueryResult,
  NormalizedCaptureStartOptions,
  PermissionStatus,
  ServiceStatus,
  StdioLauncherSpec,
} from '../shared/api-types.ts';
import { DEFAULT_CAPTURE_START_OPTIONS } from '../shared/app-policy.ts';
import type { Observation } from '../shared/protocol/generated.ts';
import { ApiError, api, clearAdminToken, getAdminToken, setAdminToken } from './api.ts';
import { createTranslator, initialLanguage, persistLanguage, type Language } from './i18n.ts';
import { HistoryTab } from './tabs/history-tab.tsx';
import { McpTab } from './tabs/mcp-tab.tsx';
import { OverviewTab } from './tabs/overview-tab.tsx';
import { ScopeTab } from './tabs/scope-tab.tsx';
import { Button, Field, Input, Tabs } from './ui.tsx';

type TabKey = 'overview' | 'scope' | 'mcp' | 'history';
type Notice = { text: string; tone: 'info' | 'danger' | 'warn' };

function cloneDefaultScope(): NormalizedCaptureStartOptions {
  return {
    ...DEFAULT_CAPTURE_START_OPTIONS,
    allowedApplicationIds: [...DEFAULT_CAPTURE_START_OPTIONS.allowedApplicationIds],
    excludedApplicationIds: [...DEFAULT_CAPTURE_START_OPTIONS.excludedApplicationIds],
  };
}

export function App() {
  const [lang, setLang] = React.useState<Language>(initialLanguage);
  const t = React.useMemo(() => createTranslator(lang), [lang]);

  const [authenticated, setAuthenticated] = React.useState<boolean>(() => Boolean(getAdminToken()));
  const [tokenInput, setTokenInput] = React.useState('');
  const [authError, setAuthError] = React.useState<string | undefined>(undefined);

  const [tab, setTab] = React.useState<TabKey>('overview');
  const [busy, setBusy] = React.useState(false);
  const [notice, setNotice] = React.useState<Notice | null>(null);

  const [status, setStatus] = React.useState<ServiceStatus | null>(null);
  const [permissions, setPermissions] = React.useState<PermissionStatus | null>(null);
  const [dataRoot, setDataRoot] = React.useState('');
  const [stdioLauncher, setStdioLauncher] = React.useState<StdioLauncherSpec | undefined>(undefined);
  const [draftScope, setDraftScope] = React.useState<NormalizedCaptureStartOptions>(cloneDefaultScope);
  const draftTouchedRef = React.useRef(false);

  const [leases, setLeases] = React.useState<ClientLease[]>([]);
  const [createdToken, setCreatedToken] = React.useState<CreateLeaseResponse | null>(null);

  const [activeQuery, setActiveQuery] = React.useState<HistoryQuery>({
    kind: 'all',
    limit: 25,
    order: 'desc',
  });
  const [cursorStack, setCursorStack] = React.useState<(string | undefined)[]>([undefined]);
  const [historyResult, setHistoryResult] = React.useState<HistoryQueryResult | null>(null);
  const [inspectedRecord, setInspectedRecord] = React.useState<Observation | null>(null);
  const [layoutResult, setLayoutResult] = React.useState<HistoryLayoutResult | null>(null);

  const handleError = React.useCallback(
    (err: unknown, fromLogin = false) => {
      if (err instanceof ApiError && err.status === 401) {
        clearAdminToken();
        setAuthenticated(false);
        if (fromLogin) setAuthError(t('authInvalid'));
        return;
      }
      const message = err instanceof Error ? err.message : String(err);
      setNotice({ text: message, tone: 'danger' });
    },
    [t],
  );

  const refreshAll = React.useCallback(
    async (fromLogin = false) => {
      if (!getAdminToken()) {
        setAuthenticated(false);
        return;
      }
      setBusy(true);
      try {
        const [statusRes, leaseList] = await Promise.all([api.getStatus(), api.getLeases()]);
        setAuthenticated(true);
        setAuthError(undefined);
        setStatus(statusRes.status);
        setPermissions(statusRes.permissions);
        setDataRoot(statusRes.dataRoot);
        setStdioLauncher(statusRes.stdioLauncher);
        setLeases(leaseList);
        if (statusRes.status.activeScope && !draftTouchedRef.current) {
          setDraftScope({
            ...statusRes.status.activeScope,
            allowedApplicationIds: [...statusRes.status.activeScope.allowedApplicationIds],
            excludedApplicationIds: [...statusRes.status.activeScope.excludedApplicationIds],
          });
        }
      } catch (err) {
        handleError(err, fromLogin);
      } finally {
        setBusy(false);
      }
    },
    [handleError],
  );

  React.useEffect(() => {
    void refreshAll(false);
  }, [refreshAll]);

  const runAction = async (fn: () => Promise<void>) => {
    setBusy(true);
    setNotice(null);
    try {
      await fn();
    } catch (err) {
      handleError(err);
    } finally {
      setBusy(false);
    }
  };

  const executeSearch = async (query: HistoryQuery, cursor: string | undefined, nextStack: (string | undefined)[]) => {
    await runAction(async () => {
      const req: HistoryQuery = { ...query };
      if (cursor !== undefined) req.cursor = cursor;
      else delete req.cursor;
      const res = await api.searchHistory(req);
      setActiveQuery(query);
      setCursorStack(nextStack);
      setHistoryResult(res);
    });
  };

  const switchLang = (next: Language) => {
    setLang(next);
    persistLanguage(next);
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tokenInput.trim()) return;
    setAdminToken(tokenInput);
    setTokenInput('');
    await refreshAll(true);
  };

  const handleSignOut = () => {
    clearAdminToken();
    setAuthenticated(false);
    setCreatedToken(null);
  };

  return (
    <div className="camcp-shell">
      <header className="camcp-header">
        <div className="camcp-brand">
          <img src="/icon.svg" alt="" />
          <div>
            <h1>{t('appTitle')}</h1>
            <p className="camcp-subtitle">{t('appSubtitle')}</p>
          </div>
        </div>
        <div className="camcp-toolbar">
          <Button
            variant={lang === 'zh' ? 'primary' : 'default'}
            onClick={() => switchLang('zh')}
          >
            中文
          </Button>
          <Button
            variant={lang === 'en' ? 'primary' : 'default'}
            onClick={() => switchLang('en')}
          >
            EN
          </Button>
          {authenticated ? (
            <>
              <Button disabled={busy} onClick={() => void refreshAll(false)}>
                {t('refresh')}
              </Button>
              <Button variant="ghost" onClick={handleSignOut}>
                {t('signOut')}
              </Button>
            </>
          ) : null}
        </div>
      </header>

      {notice ? (
        <div className="camcp-banner" data-tone={notice.tone} role="status">
          <span>{notice.text}</span>
          <Button variant="ghost" onClick={() => setNotice(null)}>
            {t('dismiss')}
          </Button>
        </div>
      ) : null}

      {!authenticated ? (
        <section className="camcp-card" style={{ maxWidth: 520, margin: '40px auto' }}>
          <h2>{t('authTitle')}</h2>
          <p className="camcp-muted">{t('authDesc')}</p>
          <form onSubmit={(e) => void handleLogin(e)}>
            <Field id="admin-token" label={t('authTokenLabel')} error={authError}>
              <Input
                type="password"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder="admin.token"
              />
            </Field>
            <div className="camcp-actions">
              <Button type="submit" variant="primary" disabled={busy || !tokenInput.trim()}>
                {t('authSubmit')}
              </Button>
            </div>
          </form>
        </section>
      ) : !status || !permissions ? (
        <div className="camcp-card">{t('loading')}</div>
      ) : (
        <Tabs.Root
          value={tab}
          onValueChange={(next) => {
            const nextTab = next as TabKey;
            setTab(nextTab);
            if (nextTab === 'history' && historyResult === null && status.storage) {
              void executeSearch(activeQuery, undefined, [undefined]);
            }
          }}
        >
          <Tabs.List className="camcp-tablist">
            <Tabs.Tab value="overview" className="camcp-tab">
              {t('tabOverview')}
            </Tabs.Tab>
            <Tabs.Tab value="scope" className="camcp-tab">
              {t('tabScope')}
            </Tabs.Tab>
            <Tabs.Tab value="mcp" className="camcp-tab">
              {t('tabMcp')}
            </Tabs.Tab>
            <Tabs.Tab value="history" className="camcp-tab">
              {t('tabHistory')}
            </Tabs.Tab>
          </Tabs.List>

          <Tabs.Panel value="overview">
            <OverviewTab
              status={status}
              permissions={permissions}
              dataRoot={dataRoot}
              busy={busy}
              t={t}
              onInitKey={() =>
                void runAction(async () => {
                  setStatus(await api.initializeKey());
                })
              }
              onStart={() =>
                void runAction(async () => {
                  setStatus(await api.startCapture(draftScope));
                })
              }
              onPause={() =>
                void runAction(async () => {
                  setStatus(await api.pauseCapture());
                })
              }
              onResume={() =>
                void runAction(async () => {
                  setStatus(await api.resumeCapture());
                })
              }
              onStop={() =>
                void runAction(async () => {
                  setStatus(await api.stopCapture());
                })
              }
              onReloadCollector={() =>
                void runAction(async () => {
                  const res = await api.reloadService('collector');
                  if (res.status) {
                    setStatus(res.status);
                  } else {
                    const statusRes = await api.getStatus();
                    setStatus(statusRes.status);
                  }
                  setNotice({
                    text: res.resumed ? t('reloadCollectorResumed') : t('reloadCollectorDone'),
                    tone: 'info',
                  });
                })
              }
              onRecheckPermissions={() =>
                void runAction(async () => {
                  setPermissions(await api.checkPermissions());
                })
              }
              onPermissionAction={(action) =>
                void runAction(async () => {
                  setPermissions(await api.permissionAction(action));
                })
              }
            />
          </Tabs.Panel>

          <Tabs.Panel value="scope">
            <ScopeTab
              status={status}
              draft={draftScope}
              busy={busy}
              t={t}
              onChangeDraft={(next) => {
                draftTouchedRef.current = true;
                setDraftScope(next);
              }}
              onApplyStart={(next) =>
                void runAction(async () => {
                  const nextStatus = await api.startCapture(next);
                  setStatus(nextStatus);
                  setTab('overview');
                })
              }
            />
          </Tabs.Panel>

          <Tabs.Panel value="mcp">
            <McpTab
              leases={leases}
              createdToken={createdToken}
              stdioLauncher={stdioLauncher}
              busy={busy}
              t={t}
              onDismissCreated={() => setCreatedToken(null)}
              onNotify={(text, tone = 'info') => setNotice({ text, tone })}
              onCreateLease={(req: CreateLeaseRequest) =>
                void runAction(async () => {
                  const res = await api.createLease(req);
                  setCreatedToken(res);
                  setLeases(await api.getLeases());
                })
              }
              onRevokeLease={(id: string) =>
                void runAction(async () => {
                  await api.revokeLease(id);
                  setLeases(await api.getLeases());
                })
              }
            />
          </Tabs.Panel>

          <Tabs.Panel value="history">
            <HistoryTab
              result={historyResult}
              inspectedRecord={inspectedRecord}
              layoutResult={layoutResult}
              canPrevPage={cursorStack.length > 1}
              busy={busy}
              t={t}
              onSearch={(query) => void executeSearch(query, undefined, [undefined])}
              onPrevPage={() => {
                if (cursorStack.length <= 1) return;
                const nextStack = cursorStack.slice(0, -1);
                void executeSearch(activeQuery, nextStack[nextStack.length - 1], nextStack);
              }}
              onNextPage={() => {
                if (!historyResult?.nextCursor) return;
                const nextCursor = historyResult.nextCursor;
                void executeSearch(activeQuery, nextCursor, [...cursorStack, nextCursor]);
              }}
              onInspect={(eventId) =>
                void runAction(async () => {
                  const res = await api.readHistory(eventId);
                  setLayoutResult(null);
                  setInspectedRecord(res.record);
                })
              }
              onLoadLayout={(eventId) =>
                void runAction(async () => {
                  const res = await api.getHistoryLayout({ eventId });
                  setInspectedRecord(null);
                  setLayoutResult(res);
                })
              }
              onCloseInspector={() => {
                setInspectedRecord(null);
                setLayoutResult(null);
              }}
              onOpenSource={(eventId) =>
                void runAction(async () => {
                  const res = await api.openSource({ eventId });
                  setNotice({
                    text: `${res.outcome}: ${res.reason}`,
                    tone: res.outcome === 'activated' ? 'info' : 'warn',
                  });
                })
              }
              onForgetOlderThan={(beforeMs) =>
                void runAction(async () => {
                  const res = await api.forgetHistory({ beforeMs });
                  const statusRes = await api.getStatus();
                  setStatus(statusRes.status);
                  setInspectedRecord(null);
                  setLayoutResult(null);
                  setNotice({
                    text: `${t('forgetDoneSummary')}: -${res.deletedSegments} segments (${res.remainingRecords} remaining)`,
                    tone: 'info',
                  });
                  if (statusRes.status.storage) {
                    const searchRes = await api.searchHistory(activeQuery);
                    setCursorStack([undefined]);
                    setHistoryResult(searchRes);
                  } else {
                    setHistoryResult(null);
                  }
                })
              }
              onForgetAll={() =>
                void runAction(async () => {
                  const res = await api.forgetHistory({ all: true });
                  const statusRes = await api.getStatus();
                  setStatus(statusRes.status);
                  setHistoryResult(null);
                  setInspectedRecord(null);
                  setLayoutResult(null);
                  setCursorStack([undefined]);
                  setNotice({
                    text: `${t('forgetDoneSummary')}: -${res.deletedSegments} segments`,
                    tone: 'info',
                  });
                })
              }
            />
          </Tabs.Panel>
        </Tabs.Root>
      )}
    </div>
  );
}

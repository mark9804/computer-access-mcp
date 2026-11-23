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
import { defaultCaptureStartOptions } from '../shared/app-policy.ts';
import type { Observation } from '../shared/protocol/generated.ts';
import { ApiError, api, clearAdminToken, getAdminToken, setAdminToken } from './api.ts';
import {
  AUTO_REFRESH_OPTIONS,
  createAutoRefreshLoop,
  initialAutoRefreshMs,
  parseAutoRefreshMs,
  persistAutoRefreshMs,
  shouldAutoRefreshHistory,
  storageWatermarkOf,
  type AutoRefreshIntervalMs,
} from './auto-refresh.ts';
import { formatClockTime } from './format.ts';
import { createTranslator, initialLanguage, persistLanguage, type Language, type MessageKey } from './i18n.ts';
import { HistoryTab } from './tabs/history-tab.tsx';
import { McpTab } from './tabs/mcp-tab.tsx';
import { OverviewTab } from './tabs/overview-tab.tsx';
import { ScopeTab } from './tabs/scope-tab.tsx';
import { Button, Field, Input, Tabs } from './ui.tsx';

type TabKey = 'overview' | 'scope' | 'mcp' | 'history';
type Notice = { text: string; tone: 'info' | 'danger' | 'warn'; source?: 'poll' };

const AUTO_REFRESH_LABEL_KEY: Record<AutoRefreshIntervalMs, MessageKey> = {
  0: 'autoRefreshOff',
  2000: 'autoRefresh2s',
  5000: 'autoRefresh5s',
  15000: 'autoRefresh15s',
  30000: 'autoRefresh30s',
};

function cloneDefaultScope(platform?: string): NormalizedCaptureStartOptions {
  const defaults = defaultCaptureStartOptions(platform);
  return {
    ...defaults,
    allowedApplicationIds: [...defaults.allowedApplicationIds],
    excludedApplicationIds: [...defaults.excludedApplicationIds],
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
  const [autoRefreshMs, setAutoRefreshMs] = React.useState<AutoRefreshIntervalMs>(initialAutoRefreshMs);
  const [lastUpdatedAtMs, setLastUpdatedAtMs] = React.useState<number | null>(null);

  const [status, setStatus] = React.useState<ServiceStatus | null>(null);
  const [permissions, setPermissions] = React.useState<PermissionStatus | null>(null);
  const [dataRoot, setDataRoot] = React.useState('');
  const [stdioLauncher, setStdioLauncher] = React.useState<StdioLauncherSpec | undefined>(undefined);
  const [draftScope, setDraftScope] = React.useState<NormalizedCaptureStartOptions>(() => cloneDefaultScope());
  const draftTouchedRef = React.useRef(false);
  const draftPlatformRef = React.useRef<string | null>(null);

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

  // Monotonic epochs fence off stale background poll responses after logout or user actions.
  const sessionEpochRef = React.useRef(0);
  const syncEpochRef = React.useRef(0);
  const lastHistoryWatermarkRef = React.useRef<string | null>(null);
  const liveViewRef = React.useRef({
    tab,
    activeQuery,
    cursorStack,
    inspectorOpen: inspectedRecord !== null || layoutResult !== null,
    busy,
    storageWatermark: storageWatermarkOf(status?.storage),
  });
  liveViewRef.current = {
    tab,
    activeQuery,
    cursorStack,
    inspectorOpen: inspectedRecord !== null || layoutResult !== null,
    busy,
    storageWatermark: storageWatermarkOf(status?.storage),
  };

  const applyStatusResponse = React.useCallback(
    (statusRes: {
      status: ServiceStatus;
      permissions?: PermissionStatus;
      dataRoot: string;
      stdioLauncher?: StdioLauncherSpec;
    }) => {
      setStatus(statusRes.status);
      if (statusRes.permissions !== undefined) {
        setPermissions(statusRes.permissions);
      }
      setDataRoot(statusRes.dataRoot);
      setStdioLauncher(statusRes.stdioLauncher);
      setLastUpdatedAtMs(Date.now());
      if (!draftTouchedRef.current) {
        if (statusRes.status.activeScope) {
          setDraftScope({
            ...statusRes.status.activeScope,
            allowedApplicationIds: [...statusRes.status.activeScope.allowedApplicationIds],
            excludedApplicationIds: [...statusRes.status.activeScope.excludedApplicationIds],
          });
          draftPlatformRef.current = statusRes.status.platform;
        } else if (draftPlatformRef.current !== statusRes.status.platform) {
          setDraftScope(cloneDefaultScope(statusRes.status.platform));
          draftPlatformRef.current = statusRes.status.platform;
        }
      }
    },
    [],
  );

  const handleError = React.useCallback(
    (err: unknown, fromLogin = false) => {
      if (err instanceof ApiError && err.status === 401) {
        sessionEpochRef.current += 1;
        syncEpochRef.current += 1;
        clearAdminToken();
        setAuthenticated(false);
        setStatus(null);
        setPermissions(null);
        setLastUpdatedAtMs(null);
        draftTouchedRef.current = false;
        draftPlatformRef.current = null;
        lastHistoryWatermarkRef.current = null;
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
        sessionEpochRef.current += 1;
        setAuthenticated(false);
        return;
      }
      const sessionEpoch = sessionEpochRef.current;
      syncEpochRef.current += 1;
      setBusy(true);
      try {
        const [statusRes, leaseList] = await Promise.all([api.getStatus(), api.getLeases()]);
        if (sessionEpoch !== sessionEpochRef.current || !getAdminToken()) return;
        setAuthenticated(true);
        setAuthError(undefined);
        applyStatusResponse(statusRes);
        setLeases(leaseList);
        setNotice((prev) => (prev?.source === 'poll' ? null : prev));

        if (!fromLogin && liveViewRef.current.tab === 'history') {
          if (statusRes.status.storage) {
            const stack = liveViewRef.current.cursorStack;
            const currentCursor = stack[stack.length - 1];
            const req: HistoryQuery = { ...liveViewRef.current.activeQuery };
            if (currentCursor !== undefined) req.cursor = currentCursor;
            else delete req.cursor;
            const searchRes = await api.searchHistory(req);
            if (sessionEpoch !== sessionEpochRef.current || !getAdminToken()) return;
            setHistoryResult(searchRes);
            if (currentCursor === undefined) {
              lastHistoryWatermarkRef.current = storageWatermarkOf(statusRes.status.storage);
            }
          } else {
            setHistoryResult(null);
            setCursorStack([undefined]);
            lastHistoryWatermarkRef.current = 'none';
          }
        }
      } catch (err) {
        handleError(err, fromLogin);
      } finally {
        setBusy(false);
      }
    },
    [applyStatusResponse, handleError],
  );

  const pollOnce = React.useCallback(async () => {
    if (!getAdminToken() || liveViewRef.current.busy) return;
    const sessionEpoch = sessionEpochRef.current;
    const syncEpoch = syncEpochRef.current;
    const fetchLeases = liveViewRef.current.tab === 'mcp';

    try {
      const [statusRes, leaseList] = await Promise.all([
        api.getStatus({ includePermissions: false }),
        fetchLeases ? api.getLeases() : Promise.resolve(null),
      ]);
      if (sessionEpoch !== sessionEpochRef.current || syncEpoch !== syncEpochRef.current || !getAdminToken()) {
        return;
      }
      applyStatusResponse(statusRes);
      if (leaseList !== null) {
        setLeases(leaseList);
      }
      setNotice((prev) => (prev?.source === 'poll' ? null : prev));

      const nextWatermark = storageWatermarkOf(statusRes.status.storage);
      if (liveViewRef.current.tab === 'history') {
        if (!statusRes.status.storage) {
          setHistoryResult(null);
          setCursorStack([undefined]);
          lastHistoryWatermarkRef.current = 'none';
        } else if (
          shouldAutoRefreshHistory({
            tab: liveViewRef.current.tab,
            hasStorage: true,
            cursorDepth: liveViewRef.current.cursorStack.length,
            inspectorOpen: liveViewRef.current.inspectorOpen,
            currentWatermark: nextWatermark,
            lastFetchedWatermark: lastHistoryWatermarkRef.current,
          })
        ) {
          const req: HistoryQuery = { ...liveViewRef.current.activeQuery };
          delete req.cursor;
          const searchRes = await api.searchHistory(req);
          if (
            sessionEpoch !== sessionEpochRef.current ||
            syncEpoch !== syncEpochRef.current ||
            !getAdminToken()
          ) {
            return;
          }
          setHistoryResult(searchRes);
          lastHistoryWatermarkRef.current = nextWatermark;
        }
      }
    } catch (err) {
      if (sessionEpoch !== sessionEpochRef.current || !getAdminToken()) return;
      if (err instanceof ApiError && err.status === 401) {
        handleError(err, false);
        return;
      }
      setNotice((prev) =>
        prev && prev.source !== 'poll' ? prev : { text: t('autoRefreshFailed'), tone: 'warn', source: 'poll' },
      );
    }
  }, [applyStatusResponse, handleError, t]);

  React.useEffect(() => {
    void refreshAll(false);
  }, [refreshAll]);

  const readyForPolling = authenticated && status !== null && permissions !== null && autoRefreshMs > 0;
  React.useEffect(() => {
    if (!readyForPolling) return;
    const loop = createAutoRefreshLoop({
      intervalMs: autoRefreshMs,
      onTick: pollOnce,
    });
    return () => loop.stop();
  }, [readyForPolling, autoRefreshMs, pollOnce]);

  const runAction = async (fn: () => Promise<void>) => {
    syncEpochRef.current += 1;
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
      setLastUpdatedAtMs(Date.now());
      if (cursor === undefined) {
        lastHistoryWatermarkRef.current = liveViewRef.current.storageWatermark;
      }
    });
  };

  const switchLang = (next: Language) => {
    setLang(next);
    persistLanguage(next);
  };

  const handleAutoRefreshChange = (raw: string) => {
    const parsed = parseAutoRefreshMs(raw);
    if (parsed === null) return;
    setAutoRefreshMs(parsed);
    persistAutoRefreshMs(parsed);
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tokenInput.trim()) return;
    setAdminToken(tokenInput);
    setTokenInput('');
    await refreshAll(true);
  };

  const handleSignOut = () => {
    sessionEpochRef.current += 1;
    syncEpochRef.current += 1;
    clearAdminToken();
    setAuthenticated(false);
    setStatus(null);
    setPermissions(null);
    setLastUpdatedAtMs(null);
    setCreatedToken(null);
    setNotice(null);
    draftTouchedRef.current = false;
    draftPlatformRef.current = null;
    lastHistoryWatermarkRef.current = null;
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
              <div className="camcp-autorefresh">
                <span className="camcp-dot" data-tone={autoRefreshMs > 0 ? 'ok' : 'idle'} aria-hidden="true" />
                <select
                  aria-label={t('autoRefreshLabel')}
                  className="camcp-autorefresh-select"
                  value={String(autoRefreshMs)}
                  onChange={(e) => handleAutoRefreshChange(e.target.value)}
                >
                  {AUTO_REFRESH_OPTIONS.map((ms) => (
                    <option key={ms} value={String(ms)}>
                      {t(AUTO_REFRESH_LABEL_KEY[ms])}
                    </option>
                  ))}
                </select>
                {lastUpdatedAtMs !== null ? (
                  <span
                    className="camcp-updated-at"
                    title={`${t('lastUpdatedLabel')}: ${formatClockTime(lastUpdatedAtMs)}`}
                  >
                    {formatClockTime(lastUpdatedAtMs)}
                  </span>
                ) : null}
              </div>
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
            if (
              nextTab === 'history' &&
              status.storage &&
              (historyResult === null ||
                shouldAutoRefreshHistory({
                  tab: nextTab,
                  hasStorage: true,
                  cursorDepth: cursorStack.length,
                  inspectorOpen: inspectedRecord !== null || layoutResult !== null,
                  currentWatermark: storageWatermarkOf(status.storage),
                  lastFetchedWatermark: lastHistoryWatermarkRef.current,
                }))
            ) {
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
                  setLastUpdatedAtMs(Date.now());
                })
              }
              onStart={() =>
                void runAction(async () => {
                  setStatus(await api.startCapture(draftScope));
                  setLastUpdatedAtMs(Date.now());
                })
              }
              onPause={() =>
                void runAction(async () => {
                  setStatus(await api.pauseCapture());
                  setLastUpdatedAtMs(Date.now());
                })
              }
              onResume={() =>
                void runAction(async () => {
                  setStatus(await api.resumeCapture());
                  setLastUpdatedAtMs(Date.now());
                })
              }
              onStop={() =>
                void runAction(async () => {
                  setStatus(await api.stopCapture());
                  setLastUpdatedAtMs(Date.now());
                })
              }
              onReloadCollector={() =>
                void runAction(async () => {
                  const res = await api.reloadService('collector');
                  if (res.status) {
                    setStatus(res.status);
                  } else {
                    const statusRes = await api.getStatus({ includePermissions: false });
                    setStatus(statusRes.status);
                  }
                  setLastUpdatedAtMs(Date.now());
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
                  setLastUpdatedAtMs(Date.now());
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
                  const statusRes = await api.getStatus({ includePermissions: false });
                  setStatus(statusRes.status);
                  setLastUpdatedAtMs(Date.now());
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
                    lastHistoryWatermarkRef.current = storageWatermarkOf(statusRes.status.storage);
                  } else {
                    setHistoryResult(null);
                    lastHistoryWatermarkRef.current = 'none';
                  }
                })
              }
              onForgetAll={() =>
                void runAction(async () => {
                  const res = await api.forgetHistory({ all: true });
                  const statusRes = await api.getStatus({ includePermissions: false });
                  setStatus(statusRes.status);
                  setLastUpdatedAtMs(Date.now());
                  setHistoryResult(null);
                  setInspectedRecord(null);
                  setLayoutResult(null);
                  setCursorStack([undefined]);
                  lastHistoryWatermarkRef.current = storageWatermarkOf(statusRes.status.storage);
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

import * as React from 'react';
import type { AdapterMode, AdapterSummary, NormalizedCaptureStartOptions, ServiceStatus } from '../../shared/api-types.ts';
import {
  BUILT_IN_ADAPTERS,
  defaultCaptureStartOptions,
  MANDATORY_EXCLUDED_APPLICATION_IDS,
  validApplicationId,
} from '../../shared/app-policy.ts';
import type { MessageKey, Translate } from '../i18n.ts';
import { Button, ChoiceCards, CollapsibleSection, Field, Input, Textarea, Toggle } from '../ui.tsx';

type ScopeTabProps = {
  status: ServiceStatus;
  draft: NormalizedCaptureStartOptions;
  onChangeDraft: (next: NormalizedCaptureStartOptions) => void;
  onApplyStart: (next: NormalizedCaptureStartOptions) => void;
  busy: boolean;
  t: Translate;
};

const ADAPTER_MODE_KEY: Record<AdapterMode, MessageKey> = {
  declarative: 'adapterMode_declarative',
  custom: 'adapterMode_custom',
  fallback: 'adapterMode_fallback',
};

export function ScopeTab({ status, draft, onChangeDraft, onApplyStart, busy, t }: ScopeTabProps) {
  const [bundleText, setBundleText] = React.useState<string>(() =>
    (draft.applicationScope === 'allowlist' ? draft.allowedApplicationIds : draft.excludedApplicationIds).join('\n'),
  );
  const [bundleError, setBundleError] = React.useState<string | undefined>(undefined);

  const syncMode = (mode: 'denylist' | 'allowlist') => {
    const list = mode === 'allowlist' ? draft.allowedApplicationIds : draft.excludedApplicationIds;
    setBundleText(list.join('\n'));
    setBundleError(undefined);
    onChangeDraft({
      ...draft,
      applicationScope: mode,
      allowBrowserContent: mode === 'denylist' ? draft.allowBrowserContent : false,
    });
  };

  const handleBundleTextChange = (raw: string) => {
    setBundleText(raw);
    const lines = raw
      .split(/[\r\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const invalid = lines.find((id) => !validApplicationId(id));
    if (invalid) {
      setBundleError(`${t('invalidBundleIdError')}: ${invalid}`);
      return;
    }
    setBundleError(undefined);
    const deduped = [...new Map(lines.map((id) => [id.toLowerCase(), id])).values()];
    if (draft.applicationScope === 'allowlist') {
      onChangeDraft({ ...draft, allowedApplicationIds: deduped });
    } else {
      onChangeDraft({ ...draft, excludedApplicationIds: deduped });
    }
  };

  const handleReset = () => {
    const defaults = defaultCaptureStartOptions(status.platform);
    const fresh: NormalizedCaptureStartOptions = {
      ...defaults,
      allowedApplicationIds: [...defaults.allowedApplicationIds],
      excludedApplicationIds: [...defaults.excludedApplicationIds],
    };
    onChangeDraft(fresh);
    setBundleText(fresh.excludedApplicationIds.join('\n'));
    setBundleError(undefined);
  };

  const handleSubmit = () => {
    if (bundleError) return;
    if (draft.applicationScope === 'allowlist' && draft.allowedApplicationIds.length === 0) {
      setBundleError(t('allowlistEmptyError'));
      return;
    }
    onApplyStart(draft);
  };

  const mandatoryIds =
    status.mandatoryExcludedApplicationIds.length > 0
      ? status.mandatoryExcludedApplicationIds
      : MANDATORY_EXCLUDED_APPLICATION_IDS;

  const adapters: readonly AdapterSummary[] =
    status.adapters.length > 0 ? status.adapters : BUILT_IN_ADAPTERS;

  const isActive = status.state === 'running' || status.state === 'paused';

  return (
    <div>
      <section className="chmcp-card">
        <div className="chmcp-card-header">
          <div>
            <h2>{t('scopeCardTitle')}</h2>
            <p className="chmcp-muted">{t('scopeCardDesc')}</p>
          </div>
          <div className="chmcp-actions" style={{ marginTop: 0 }}>
            <Button disabled={busy} onClick={handleReset}>
              {t('resetDefaults')}
            </Button>
            <Button
              variant="primary"
              disabled={busy || status.state === 'not-initialized' || Boolean(bundleError)}
              onClick={handleSubmit}
            >
              {isActive ? t('applyRestartCapture') : t('saveStartScope')}
            </Button>
          </div>
        </div>

        <ChoiceCards
          id="capture-scope"
          label={t('captureScopeLabel')}
          value={draft.captureScope}
          onChange={(captureScope) => onChangeDraft({ ...draft, captureScope })}
          options={[
            { value: 'focused', label: t('scope_focused') },
            { value: 'region', label: t('scope_region') },
            { value: 'window', label: t('scope_window') },
          ]}
        />

        <h3>{t('channelsTitle')}</h3>
        <Toggle
          id="ch-browser"
          label={t('chBrowser')}
          checked={draft.allowBrowserContent && draft.applicationScope === 'denylist'}
          disabled={draft.applicationScope === 'allowlist'}
          onChange={(allowBrowserContent) => onChangeDraft({ ...draft, allowBrowserContent })}
        />
        <Toggle
          id="ch-ax-compat"
          label={t('chAxCompat')}
          checked={draft.axCompatibility}
          onChange={(axCompatibility) => onChangeDraft({ ...draft, axCompatibility })}
        />
        <Toggle
          id="ch-markers"
          label={t('chTextMarkers')}
          checked={draft.textMarkers}
          onChange={(textMarkers) => onChangeDraft({ ...draft, textMarkers })}
        />
        <Toggle
          id="ch-selection"
          label={t('chSelection')}
          checked={draft.selectionCapture}
          onChange={(selectionCapture) => onChangeDraft({ ...draft, selectionCapture })}
        />
        <Toggle
          id="ch-input-text"
          label={t('chInputText')}
          checked={draft.inputText}
          onChange={(inputText) => onChangeDraft({ ...draft, inputText })}
        />
        <Toggle
          id="ch-input-activity"
          label={t('chInputActivity')}
          checked={draft.inputActivity}
          onChange={(inputActivity) => onChangeDraft({ ...draft, inputActivity })}
        />
        <Toggle
          id="ch-menu-actions"
          label={t('chMenuActions')}
          checked={draft.menuActions}
          onChange={(menuActions) => onChangeDraft({ ...draft, menuActions })}
        />

        <CollapsibleSection title={t('advancedSamplingTitle')}>
          <div className="chmcp-grid-2">
            <Field id="sample-interval" label={t('sampleIntervalLabel')}>
              <Input
                type="number"
                min={1000}
                max={30000}
                step={500}
                value={draft.sampleIntervalMs}
                onChange={(e) => {
                  const n = Number(e.target.value);
                  if (Number.isInteger(n) && n >= 1000 && n <= 30000) {
                    onChangeDraft({ ...draft, sampleIntervalMs: n });
                  }
                }}
              />
            </Field>
            <Field id="max-text-units" label={t('maxTextUnitsLabel')}>
              <Input
                type="number"
                min={256}
                max={8192}
                step={256}
                value={draft.maxTextCodeUnits}
                onChange={(e) => {
                  const n = Number(e.target.value);
                  if (Number.isInteger(n) && n >= 1 && n <= 8192) {
                    onChangeDraft({ ...draft, maxTextCodeUnits: n });
                  }
                }}
              />
            </Field>
            <Field id="max-tree-nodes" label={t('maxTreeNodesLabel')}>
              <Input
                type="number"
                min={1}
                max={96}
                value={draft.maxTreeNodes}
                onChange={(e) => {
                  const n = Number(e.target.value);
                  if (Number.isInteger(n) && n >= 1 && n <= 96) {
                    onChangeDraft({ ...draft, maxTreeNodes: n });
                  }
                }}
              />
            </Field>
          </div>
          <ChoiceCards
            id="text-range"
            label={t('textRangeLabel')}
            compact
            value={draft.textRange}
            onChange={(textRange) => onChangeDraft({ ...draft, textRange })}
            options={[
              { value: 'prefix', label: t('range_prefix') },
              { value: 'visible', label: t('range_visible') },
            ]}
          />
          <ChoiceCards
            id="field-security"
            label={t('fieldSecurityLabel')}
            value={draft.fieldSecurity}
            onChange={(fieldSecurity) => onChangeDraft({ ...draft, fieldSecurity })}
            options={[
              { value: 'denylist', label: t('security_denylist') },
              { value: 'strict', label: t('security_strict') },
            ]}
          />
        </CollapsibleSection>
      </section>

      <section className="chmcp-card">
        <h2>{t('appPolicyTitle')}</h2>
        <ChoiceCards
          id="app-mode"
          label={t('appModeLabel')}
          value={draft.applicationScope}
          onChange={syncMode}
          options={[
            { value: 'denylist', label: t('mode_denylist') },
            { value: 'allowlist', label: t('mode_allowlist') },
          ]}
        />

        <Field
          id="bundle-ids"
          label={draft.applicationScope === 'allowlist' ? t('allowedAppsLabel') : t('excludedAppsLabel')}
          description="com.google.antigravity-ide, com.microsoft.VSCode, com.tencent.qq"
          error={bundleError}
        >
          <Textarea
            value={bundleText}
            onChange={(e) => handleBundleTextChange(e.target.value)}
            placeholder="com.google.antigravity-ide"
          />
        </Field>

        <h3>{t('mandatoryExclusionsTitle')}</h3>
        <p className="chmcp-muted">{t('mandatoryExclusionsDesc')}</p>
        <div className="chmcp-pill-list">
          {mandatoryIds.map((id) => (
            <code key={id} className="chmcp-badge chmcp-mono">
              {id}
            </code>
          ))}
        </div>
      </section>

      <section className="chmcp-card">
        <h2>{t('adaptersTitle')}</h2>
        <p className="chmcp-muted">{t('adaptersDesc')}</p>
        <div className="chmcp-table-wrap">
          <table className="chmcp-table">
            <thead>
              <tr>
                <th>{t('colName')}</th>
                <th>ID</th>
                <th>{t('colMode')}</th>
                <th>{t('colBundles')}</th>
              </tr>
            </thead>
            <tbody>
              {adapters.map((adapter) => (
                <tr key={adapter.id}>
                  <td>{adapter.name}</td>
                  <td>
                    <code>{adapter.id}</code>
                  </td>
                  <td>{t(ADAPTER_MODE_KEY[adapter.mode])}</td>
                  <td>
                    {adapter.bundleIds.length > 0 ? (
                      <div className="chmcp-pill-list" style={{ marginTop: 0 }}>
                        {adapter.bundleIds.map((bid) => (
                          <code key={bid} className="chmcp-badge chmcp-mono">
                            {bid}
                          </code>
                        ))}
                      </div>
                    ) : (
                      <span className="chmcp-muted">{t('adapterFallbackAll')}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

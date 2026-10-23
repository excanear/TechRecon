import { useCallback, useEffect, useState } from 'react';
import { reportFileName, toJson, toMarkdown } from '../export';
import { DEFAULT_SETTINGS, getConfirmations, getSettings, saveSettings, setConfirmation } from '../storage';
import type { Confirmations, Settings } from '../types';
import { ExportMenu, type ExportAction } from './components/ExportMenu';
import { Header, Summary, Tabs, type TabId } from './components/Header';
import { ReconPanel } from './components/ReconPanel';
import { ScanView } from './components/ScanView';
import { SettingsView } from './components/SettingsView';
import { TechList } from './components/TechList';
import { VulnList } from './components/VulnList';
import ui from './components/ui.module.css';
import styles from './App.module.css';
import { useAnalysis } from './useAnalysis';

function download(filename: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function App() {
  const { state, fatal, refresh, captureHeaders, retryCve } = useAnalysis();
  const [view, setView] = useState<'main' | 'settings' | 'scan'>('main');
  const [tab, setTab] = useState<TabId>('tech');
  const [techFilter, setTechFilter] = useState<string | null>(null);
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [confirmations, setConfirmations] = useState<Confirmations>({});
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    getSettings().then(setSettings).catch(() => undefined);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = settings.theme;
  }, [settings.theme]);

  useEffect(() => {
    if (!state?.domain) return;
    getConfirmations(state.domain).then(setConfirmations).catch(() => setConfirmations({}));
  }, [state?.domain]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 2200);
    return () => clearTimeout(t);
  }, [toast]);

  const busy = !state || state.status === 'collecting' || state.status === 'correlating';
  const ready = Boolean(state && (state.status === 'correlating' || state.status === 'done'));

  const onRefresh = useCallback(() => {
    // Keep the header probe if the previous analysis used it, so a refresh never silently loses data.
    if (state?.recon?.headerSource === 'probe') captureHeaders();
    else refresh();
  }, [state?.recon?.headerSource, captureHeaders, refresh]);

  const changeSettings = useCallback(async (patch: Partial<Settings>) => {
    setSettings(await saveSettings(patch));
  }, []);

  const toggleConfirm = useCallback(
    async (vulnId: string, techId: string, confirmed: boolean) => {
      if (!state) return;
      setConfirmations(await setConfirmation(state.domain, vulnId, techId, confirmed));
      setToast(confirmed ? `${vulnId} marcada como confirmada` : `${vulnId} voltou a potencial`);
    },
    [state],
  );

  const onExport = useCallback(
    async (action: ExportAction) => {
      if (!state) return;
      const meta = { toolVersion: chrome.runtime.getManifest().version };
      const isJson = action.endsWith('json');
      const content = isJson ? toJson(state, confirmations, meta) : toMarkdown(state, confirmations, meta);
      if (action.startsWith('copy')) {
        try {
          await navigator.clipboard.writeText(content);
          setToast(isJson ? 'JSON copiado' : 'Markdown copiado');
        } catch {
          setToast('Não foi possível acessar a área de transferência; use Baixar.');
        }
      } else {
        download(reportFileName(state, isJson ? 'json' : 'md'), content, isJson ? 'application/json' : 'text/markdown');
        setToast('Arquivo baixado');
      }
    },
    [state, confirmations],
  );

  const showVulnsFor = useCallback((techId: string) => {
    setTechFilter(techId);
    setTab('vuln');
  }, []);

  const vulnTotal = state ? Object.values(state.vulnReports).reduce((n, r) => n + r.vulns.length, 0) : 0;
  const confirmedCount = state
    ? Object.values(state.vulnReports).flatMap((r) => r.vulns).filter((v) => confirmations[v.id]).length
    : 0;

  let body: React.ReactNode;
  if (view === 'settings') {
    body = <SettingsView settings={settings} onChange={changeSettings} onBack={() => setView('main')} notify={setToast} />;
  } else if (view === 'scan') {
    body = <ScanView onBack={() => setView('main')} defaultSeed={state?.url ?? ''} />;
  } else if (fatal) {
    body = (
      <div className={ui.empty}>
        <h2>Nenhuma aba para analisar</h2>
        <p>{fatal}</p>
      </div>
    );
  } else if (!state || state.status === 'collecting') {
    body = (
      <div className={styles.loading} aria-busy="true">
        <div className={styles.scanline} />
        <p>Lendo DOM, scripts, meta tags e variáveis da página…</p>
      </div>
    );
  } else if (state.status === 'unsupported') {
    body = (
      <div className={ui.empty}>
        <h2>Esta página não pode ser analisada</h2>
        <p>{state.error}</p>
        <p>Abra um site http(s) e clique no ícone do TechRecon.</p>
      </div>
    );
  } else if (state.status === 'error') {
    body = (
      <div className={ui.empty} role="alert">
        <h2>A análise falhou</h2>
        <p>{state.error}</p>
        <button type="button" className={ui.buttonPrimary} onClick={refresh}>
          Analisar novamente
        </button>
      </div>
    );
  } else {
    const headerHint = state.recon?.headerSource !== 'probe';
    body = (
      <>
        <Summary state={state} confirmedCount={confirmedCount} />
        <Tabs
          active={tab}
          onChange={(t) => {
            setTab(t);
            if (t !== 'vuln') setTechFilter(null);
          }}
          counts={{ tech: state.technologies.length, vuln: vulnTotal, recon: null }}
        />
        <div className={styles.panel} role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
          {tab === 'tech' && (
            <TechList technologies={state.technologies} reports={state.vulnReports} onShowVulns={showVulnsFor} headerHint={headerHint} onCaptureHeaders={captureHeaders} />
          )}
          {tab === 'vuln' && (
            <VulnList
              reports={state.vulnReports}
              confirmations={confirmations}
              onToggleConfirm={toggleConfirm}
              techFilter={techFilter}
              onClearTechFilter={() => setTechFilter(null)}
              onRetry={retryCve}
              busy={busy}
              lookupEnabled={state.cveLookupEnabled}
              enrichment={state.enrichment}
            />
          )}
          {tab === 'recon' && state.recon && <ReconPanel recon={state.recon} onCaptureHeaders={captureHeaders} busy={busy} />}
        </div>
      </>
    );
  }

  return (
    <div className={styles.app}>
      <Header
        state={state}
        busy={busy && !fatal}
        onRefresh={onRefresh}
        onSettings={() => setView(view === 'settings' ? 'main' : 'settings')}
        onScan={() => setView(view === 'scan' ? 'main' : 'scan')}
        exportMenu={<ExportMenu disabled={!ready} onAction={onExport} />}
      />
      <main className={styles.main}>{body}</main>
      {toast && (
        <div className={styles.toast} role="status">
          {toast}
        </div>
      )}
    </div>
  );
}

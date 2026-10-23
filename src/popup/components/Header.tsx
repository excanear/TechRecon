import { RefreshCw, Radar, Settings as SettingsIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { SEVERITY_RANK } from '../../cve/cvss';
import type { AnalysisState, Severity } from '../../types';
import { formatTime, plural, SEVERITY_LABEL, SEVERITY_VAR } from '../format';
import { Logo } from './icons';
import styles from './Header.module.css';

interface HeaderProps {
  state: AnalysisState | null;
  busy: boolean;
  onRefresh: () => void;
  onSettings: () => void;
  onScan: () => void;
  exportMenu: ReactNode;
}

function statusText(state: AnalysisState | null): string {
  if (!state) return 'Conectando…';
  switch (state.status) {
    case 'collecting':
      return 'Coletando dados da página…';
    case 'correlating': {
      const pending = Object.values(state.vulnReports).filter((r) => r.status === 'pending').length;
      return pending ? `Consultando vulnerabilidades (${pending} pendente${pending === 1 ? '' : 's'})…` : 'Correlacionando vulnerabilidades…';
    }
    case 'done':
      return `Analisado às ${formatTime(state.finishedAt)}`;
    case 'unsupported':
      return 'Página não suportada';
    case 'error':
      return 'Falha na análise';
    default:
      return '';
  }
}

export function Header({ state, busy, onRefresh, onSettings, onScan, exportMenu }: HeaderProps) {
  return (
    <header className={styles.header}>
      <div className={styles.top}>
        <Logo />
        <div className={styles.identity}>
          <span className={styles.brand}>TechRecon</span>
          <span className={styles.domain} title={state?.url}>
            {state?.domain || '—'}
          </span>
        </div>
        <div className={styles.actions}>
          <button type="button" className={styles.iconButton} onClick={onRefresh} disabled={busy || !state} title="Analisar novamente" aria-label="Analisar novamente">
            <RefreshCw size={15} className={busy ? styles.spin : undefined} />
          </button>
          <button type="button" className={styles.iconButton} onClick={onScan} title="Varredura do site" aria-label="Varredura do site">
            <Radar size={15} />
          </button>
          {exportMenu}
          <button type="button" className={styles.iconButton} onClick={onSettings} title="Opções" aria-label="Opções">
            <SettingsIcon size={15} />
          </button>
        </div>
      </div>
      <p className={styles.status} role="status" aria-live="polite">
        <span className={styles.dot} data-state={state?.status ?? 'idle'} aria-hidden="true" />
        {statusText(state)}
        {state?.recon && (
          <span className={styles.headerSource}>{state.recon.headerSource === 'probe' ? 'headers observados' : 'análise passiva'}</span>
        )}
      </p>
    </header>
  );
}

const STRIP_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

export function Summary({ state, confirmedCount }: { state: AnalysisState; confirmedCount: number }) {
  const vulns = Object.values(state.vulnReports).flatMap((r) => r.vulns);
  const counts: Partial<Record<Severity, number>> = {};
  for (const v of vulns) {
    const key = v.severity === 'NONE' ? 'UNKNOWN' : v.severity;
    counts[key] = (counts[key] ?? 0) + 1;
  }
  const observed = state.technologies.filter((t) => !t.inferred).length;
  const highest = STRIP_ORDER.find((s) => counts[s]);
  return (
    <section className={styles.summary} aria-label="Resumo">
      <div className={styles.counter}>
        <span className={styles.count}>{state.technologies.length}</span>
        <span className={styles.countLabel}>
          tecnologias
          <small>{observed} observadas</small>
        </span>
      </div>
      <div className={styles.counter}>
        <span className={styles.count} style={highest ? { color: SEVERITY_VAR[highest] } : undefined}>
          {vulns.length}
        </span>
        <span className={styles.countLabel}>
          CVEs potenciais
          <small>{confirmedCount ? plural(confirmedCount, 'confirmada', 'confirmadas') : 'por versão'}</small>
        </span>
      </div>
      <div className={styles.strip} role="img" aria-label={vulns.length ? STRIP_ORDER.filter((s) => counts[s]).map((s) => `${counts[s]} ${SEVERITY_LABEL[s]}`).join(', ') : 'Nenhuma vulnerabilidade correlacionada'}>
        {vulns.length ? (
          STRIP_ORDER.filter((s) => counts[s])
            .sort((a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a])
            .map((s) => (
              <span key={s} className={styles.segment} style={{ flexGrow: counts[s], background: SEVERITY_VAR[s] }} title={`${counts[s]} ${SEVERITY_LABEL[s]}`}>
                {counts[s]}
              </span>
            ))
        ) : (
          <span className={styles.stripEmpty} />
        )}
      </div>
    </section>
  );
}

export type TabId = 'tech' | 'vuln' | 'recon';

export function Tabs({ active, onChange, counts }: { active: TabId; onChange: (t: TabId) => void; counts: Record<TabId, number | null> }) {
  const tabs: Array<[TabId, string]> = [
    ['tech', 'Tecnologias'],
    ['vuln', 'Vulnerabilidades'],
    ['recon', 'Recon'],
  ];
  const onKey = (e: React.KeyboardEvent, index: number) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    e.preventDefault();
    const next = tabs[(index + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length]![0];
    onChange(next);
    document.getElementById(`tab-${next}`)?.focus();
  };
  return (
    <div className={styles.tabs} role="tablist" aria-label="Seções">
      {tabs.map(([id, label], i) => (
        <button
          key={id}
          id={`tab-${id}`}
          type="button"
          role="tab"
          aria-selected={active === id}
          aria-controls={`panel-${id}`}
          tabIndex={active === id ? 0 : -1}
          className={styles.tab}
          onClick={() => onChange(id)}
          onKeyDown={(e) => onKey(e, i)}
        >
          {label}
          {counts[id] !== null && <span className={styles.tabCount}>{counts[id]}</span>}
        </button>
      ))}
    </div>
  );
}

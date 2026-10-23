import { CheckCircle2, ChevronRight, ExternalLink, RotateCw } from 'lucide-react';
import { useMemo, useState } from 'react';
import { SEVERITY_RANK } from '../../cve/cvss';
import { safeHttpUrl } from '../../shared/sanitize';
import type { Confirmations, TechVulnReport, Vulnerability } from '../../types';
import { formatDate, REPORT_STATUS_LABEL, SEVERITY_LABEL, SEVERITY_VAR } from '../format';
import styles from './VulnList.module.css';
import ui from './ui.module.css';

interface VulnListProps {
  reports: Record<string, TechVulnReport>;
  confirmations: Confirmations;
  onToggleConfirm: (vulnId: string, techId: string, confirmed: boolean) => void;
  techFilter: string | null;
  onClearTechFilter: () => void;
  onRetry: () => void;
  busy: boolean;
  lookupEnabled: boolean;
}

type SeverityFilter = 'all' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
const FILTERS: Array<[SeverityFilter, string]> = [
  ['all', 'Todas'],
  ['CRITICAL', 'Crítica'],
  ['HIGH', 'Alta'],
  ['MEDIUM', 'Média'],
  ['LOW', 'Baixa'],
];

interface Row {
  vuln: Vulnerability;
  report: TechVulnReport;
}

function ScoreBadge({ vuln }: { vuln: Vulnerability }) {
  const color = SEVERITY_VAR[vuln.severity];
  return (
    <span className={styles.score} style={{ color, borderColor: color }} title={`${SEVERITY_LABEL[vuln.severity]}${vuln.cvss ? ` · CVSS ${vuln.cvss.version}` : ''}`}>
      {vuln.cvss?.score !== null && vuln.cvss?.score !== undefined ? vuln.cvss.score.toFixed(1) : '—'}
    </span>
  );
}

function VulnDetail({ row, confirmed, onToggle }: { row: Row; confirmed: boolean; onToggle: () => void }) {
  const { vuln, report } = row;
  const source = safeHttpUrl(vuln.sourceUrl);
  return (
    <div className={ui.detail} id={`vuln-${vuln.id}`}>
      {vuln.description && <p className={styles.description}>{vuln.description}</p>}
      <dl className={ui.kv}>
        <dt>Severidade</dt>
        <dd>
          {SEVERITY_LABEL[vuln.severity]}
          {vuln.cvss && (
            <>
              {vuln.cvss.score !== null ? ` · ${vuln.cvss.score} (CVSS ${vuln.cvss.version})` : ` · CVSS ${vuln.cvss.version} sem pontuação calculada`}
              {vuln.cvss.vector && <span className={`mono ${styles.vector}`}>{vuln.cvss.vector}</span>}
            </>
          )}
        </dd>
        <dt>Detectado</dt>
        <dd>
          {report.techName} <span className="mono">{report.version}</span>
        </dd>
        <dt>Afetadas</dt>
        <dd className="mono">{vuln.affected.join('; ')}</dd>
        <dt>Corrigida em</dt>
        <dd>{vuln.fixedIn ? <span className="mono">{vuln.fixedIn}</span> : 'não informado pela fonte'}</dd>
        <dt>Base</dt>
        <dd>{vuln.matchBasis}</dd>
        {vuln.conditions && (
          <>
            <dt>Condições</dt>
            <dd>{vuln.conditions}</dd>
          </>
        )}
        {vuln.aliases.length > 0 && (
          <>
            <dt>Aliases</dt>
            <dd className="mono">{vuln.aliases.join(', ')}</dd>
          </>
        )}
        {vuln.published && (
          <>
            <dt>Publicada</dt>
            <dd>{formatDate(vuln.published)}</dd>
          </>
        )}
      </dl>
      <div className={ui.links}>
        {source && (
          <a href={source} target="_blank" rel="noreferrer noopener">
            {vuln.source === 'nvd' ? 'NVD' : 'OSV'} <ExternalLink size={11} />
          </a>
        )}
        {vuln.references.slice(0, 5).map((r) => (
          <a key={r.url} href={r.url} target="_blank" rel="noreferrer noopener" title={r.url}>
            {r.label} <ExternalLink size={11} />
          </a>
        ))}
      </div>
      <div className={styles.confirmBar}>
        <button type="button" className={confirmed ? ui.buttonPrimary : ui.button} aria-pressed={confirmed} onClick={onToggle}>
          <CheckCircle2 size={13} />
          {confirmed ? 'Confirmada pelo analista' : 'Marcar como confirmada'}
        </button>
        <span className={styles.confirmHint}>
          {confirmed ? 'Clique para voltar a potencial.' : 'Use após verificar manualmente o impacto.'}
        </span>
      </div>
    </div>
  );
}

export function VulnList({ reports, confirmations, onToggleConfirm, techFilter, onClearTechFilter, onRetry, busy, lookupEnabled }: VulnListProps) {
  const [severity, setSeverity] = useState<SeverityFilter>('all');
  const [open, setOpen] = useState<string | null>(null);

  const allReports = Object.values(reports);
  const rows = useMemo(() => {
    const list: Row[] = [];
    for (const report of allReports) {
      if (techFilter && report.techId !== techFilter) continue;
      for (const vuln of report.vulns) list.push({ vuln, report });
    }
    return list
      .filter((r) => severity === 'all' || r.vuln.severity === severity)
      .sort((a, b) => (b.vuln.cvss?.score ?? -1) - (a.vuln.cvss?.score ?? -1) || SEVERITY_RANK[b.vuln.severity] - SEVERITY_RANK[a.vuln.severity]);
  }, [allReports, techFilter, severity]);

  const errors = allReports.filter((r) => r.status === 'error' || (r.status === 'ok' && r.message));
  const pending = allReports.filter((r) => r.status === 'pending');
  const skipped = allReports.filter((r) => r.status === 'no-version' || r.status === 'version-uncertain');
  const checkedClean = allReports.filter((r) => r.status === 'ok' && r.vulns.length === 0);
  const techName = techFilter ? reports[techFilter]?.techName : null;
  const total = allReports.reduce((n, r) => n + r.vulns.length, 0);

  return (
    <>
      <div className={ui.toolbar} style={{ flexDirection: 'column', gap: 6 }}>
        <div className={ui.filters} role="group" aria-label="Filtrar por severidade">
          {FILTERS.map(([id, label]) => (
            <button key={id} type="button" className={ui.filter} aria-pressed={severity === id} onClick={() => setSeverity(id)}>
              {label}
            </button>
          ))}
          {techName && (
            <button type="button" className={ui.filter} aria-pressed="true" onClick={onClearTechFilter} title="Remover filtro de tecnologia">
              {techName} ✕
            </button>
          )}
        </div>
      </div>
      <div className={ui.scroll}>
        {!lookupEnabled && (
          <div className={ui.empty}>
            <h2>Consulta de CVEs desativada</h2>
            <p>Ative “Consultar vulnerabilidades” nas opções para correlacionar versões com o NVD e o OSV.</p>
          </div>
        )}

        {errors.length > 0 && (
          <div className={styles.errorBox} role="alert">
            <strong>Algumas consultas falharam. Nenhum resultado foi presumido.</strong>
            <ul>
              {errors.map((r) => (
                <li key={r.techId}>
                  {r.techName} {r.version}: {r.message}
                </li>
              ))}
            </ul>
            <button type="button" className={ui.button} onClick={onRetry} disabled={busy}>
              <RotateCw size={13} /> Tentar novamente
            </button>
          </div>
        )}

        {pending.length > 0 && <p className={ui.note} style={{ margin: '8px var(--pad)' }}>Consultando {pending.map((p) => p.techName).join(', ')}…</p>}

        {rows.length === 0 && lookupEnabled && pending.length === 0 && (
          <div className={ui.empty}>
            <h2>{total ? 'Nenhuma vulnerabilidade neste filtro' : 'Nenhuma vulnerabilidade correlacionada'}</h2>
            <p>
              {total
                ? 'Altere a severidade ou remova o filtro de tecnologia.'
                : 'Só são listadas vulnerabilidades cuja faixa de versões afetadas contém uma versão observada. Tecnologias sem versão não são correlacionadas por nome.'}
            </p>
          </div>
        )}

        {rows.map((row) => {
          const key = `${row.report.techId}:${row.vuln.id}`;
          const expanded = open === key;
          const confirmed = Boolean(confirmations[row.vuln.id]);
          return (
            <div key={key}>
              <button type="button" className={`${ui.row} ${styles.vulnRow}`} aria-expanded={expanded} aria-controls={`vuln-${row.vuln.id}`} onClick={() => setOpen(expanded ? null : key)}>
                <ScoreBadge vuln={row.vuln} />
                <span className={ui.rowMain}>
                  <span className={ui.rowTitle}>
                    <span className="mono">{row.vuln.id}</span>
                    <span className={ui.rowSub}>
                      {row.report.techName} {row.report.version}
                    </span>
                  </span>
                  <span className={ui.rowSub}>{row.vuln.title}</span>
                </span>
                <span className={ui.rowMeta}>
                  <span className={confirmed ? styles.confirmed : styles.potential}>{confirmed ? 'Confirmada' : 'Potencial'}</span>
                </span>
                <ChevronRight size={12} className={ui.chevron} aria-hidden="true" />
              </button>
              {expanded && <VulnDetail row={row} confirmed={confirmed} onToggle={() => onToggleConfirm(row.vuln.id, row.report.techId, !confirmed)} />}
            </div>
          );
        })}

        {(skipped.length > 0 || checkedClean.length > 0) && !techFilter && (
          <section className={styles.coverage} aria-label="Cobertura da correlação">
            <h3 className={ui.subheading}>Cobertura</h3>
            <ul>
              {checkedClean.map((r) => (
                <li key={r.techId}>
                  <span>{r.techName} <span className="mono">{r.version}</span></span>
                  <span>sem CVEs conhecidos ({r.queries.map((q) => (q.source === 'nvd' ? 'NVD' : 'OSV')).filter((s, i, a) => a.indexOf(s) === i).join(', ')}{r.queries.some((q) => q.cached) ? ', cache' : ''})</span>
                </li>
              ))}
              {skipped.map((r) => (
                <li key={r.techId}>
                  <span>{r.techName}</span>
                  <span>{REPORT_STATUS_LABEL[r.status]}</span>
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </>
  );
}


// Full-tab dashboard for one scan session: everything the popup can only summarize — the whole
// prioritized vulnerability list with filters, configuration findings, technologies, pages and
// hosts — plus the scan exports. Data comes from the same scan channel the popup uses.

import { ChevronRight, ExternalLink, FileCode2, FileJson, FileSpreadsheet, FileText, Loader2 } from 'lucide-react';
import { Fragment, useEffect, useMemo, useState } from 'react';
import { CATEGORY_LABELS } from '../fingerprinting/signature';
import { scanFileName, scanToCsv, scanToHtml, scanToJson, scanToMarkdown, type CsvTable, type ScanExportInput } from '../export/scan';
import type { ScanSession, VulnFindingRecord } from '../scan/types';
import { safeHttpUrl } from '../shared/sanitize';
import { getSettings } from '../storage';
import { EnrichmentNote, ExploitBadges, ExploitDetail, PRIORITY_HELP } from '../popup/components/Exploit';
import { formatDate, SEVERITY_LABEL, SEVERITY_VAR } from '../popup/format';
import { useScan, type Inventory } from '../popup/useScan';
import styles from './Dashboard.module.css';

type TabId = 'vulns' | 'config' | 'techs' | 'pages' | 'hosts';

const STATUS_LABEL: Record<ScanSession['status'], string> = {
  draft: 'rascunho',
  authorized: 'autorizado',
  running: 'em andamento',
  paused: 'pausado',
  done: 'concluído',
  aborted: 'interrompido',
  error: 'erro',
};

const MISCONFIG_SEVERITY = {
  high: { label: 'Alta', color: 'var(--sev-high)' },
  medium: { label: 'Média', color: 'var(--sev-medium)' },
  low: { label: 'Baixa', color: 'var(--sev-low)' },
  info: { label: 'Info', color: 'var(--muted)' },
} as const;

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

function sessionIdFromUrl(): string | null {
  return new URLSearchParams(location.search).get('session');
}

function Kpi({ value, label, tone }: { value: number | string; label: string; tone?: string }) {
  return (
    <div className={styles.kpi}>
      <b style={tone ? { color: tone } : undefined}>{value}</b>
      <span>{label}</span>
    </div>
  );
}

function VulnDetail({ finding }: { finding: VulnFindingRecord }) {
  const { vuln } = finding;
  const source = safeHttpUrl(vuln.sourceUrl);
  return (
    <div className={styles.detail}>
      {vuln.description && <p>{vuln.description}</p>}
      <dl>
        <ExploitDetail vuln={vuln} />
        <dt>Afetadas</dt>
        <dd className="mono">{vuln.affected.join('; ') || '—'}</dd>
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
      <div className={styles.links}>
        {source && (
          <a href={source} target="_blank" rel="noreferrer noopener">
            {vuln.source === 'nvd' ? 'NVD' : 'OSV'} <ExternalLink size={11} />
          </a>
        )}
        {vuln.references.slice(0, 8).map((r) => {
          const url = safeHttpUrl(r.url);
          return url ? (
            <a key={url} href={url} target="_blank" rel="noreferrer noopener" title={url}>
              {r.label} <ExternalLink size={11} />
            </a>
          ) : null;
        })}
      </div>
    </div>
  );
}

function VulnTable({ inventory, session }: { inventory: Inventory; session: ScanSession }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [tech, setTech] = useState('');
  const [open, setOpen] = useState<string | null>(null);

  const techs = useMemo(
    () => [...new Map(inventory.vulnerabilities.flatMap((f) => f.techs.map((t) => [t.id, t.name] as const))).entries()].sort((a, b) => a[1].localeCompare(b[1])),
    [inventory.vulnerabilities],
  );
  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...inventory.vulnerabilities]
      .sort((a, b) => a.rank - b.rank)
      .filter((f) => !severity || f.vuln.severity === severity)
      .filter((f) => !kevOnly || f.vuln.kev)
      .filter((f) => !tech || f.techs.some((t) => t.id === tech))
      .filter((f) => !q || [f.vuln.id, ...f.vuln.aliases, f.vuln.title].some((s) => s.toLowerCase().includes(q)));
  }, [inventory.vulnerabilities, query, severity, kevOnly, tech]);

  const failed = inventory.techCve.filter((r) => r.status === 'error' || (r.status === 'ok' && r.message));

  if (session.cve?.status === 'disabled') return <p className={styles.empty}>Correlação de CVEs desativada nas opções; o inventário não foi consultado.</p>;
  return (
    <>
      {failed.length > 0 && (
        <div className={styles.alert} role="alert">
          <strong>Consultas com falha. Nenhum resultado foi presumido.</strong>
          <ul>
            {failed.map((r) => (
              <li key={r.key}>
                {r.techName} {r.version}: {r.message}
              </li>
            ))}
          </ul>
        </div>
      )}
      <EnrichmentNote status={session.cve?.enrichment} />
      <p className={styles.hint}>{PRIORITY_HELP}</p>
      <div className={styles.toolbar}>
        <input type="search" placeholder="Buscar CVE, alias ou título" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Buscar vulnerabilidade" />
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severidade">
          <option value="">Todas as severidades</option>
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const).map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABEL[s]}
            </option>
          ))}
        </select>
        <select value={tech} onChange={(e) => setTech(e.target.value)} aria-label="Tecnologia">
          <option value="">Todas as tecnologias</option>
          {techs.map(([id, name]) => (
            <option key={id} value={id}>
              {name}
            </option>
          ))}
        </select>
        <label className={styles.check}>
          <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} /> Somente CISA KEV
        </label>
        <span className={styles.count}>
          {rows.length} de {inventory.vulnerabilities.length}
        </span>
      </div>
      <div className={styles.tableWrap}>
        <table className={styles.table} aria-label="Vulnerabilidades">
          <thead>
            <tr>
              <th>#</th>
              <th>Vulnerabilidade</th>
              <th>Severidade</th>
              <th>Exploração</th>
              <th>Tecnologias</th>
              <th>Corrigida em</th>
              <th aria-label="Detalhes" />
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => {
              const expanded = open === f.key;
              return (
                <Fragment key={f.key}>
                  <tr className={styles.clickable} onClick={() => setOpen(expanded ? null : f.key)} aria-expanded={expanded}>
                    <td className="mono">{f.rank + 1}</td>
                    <td>
                      <span className="mono">{f.vuln.id}</span>
                      <span className={styles.sub}>{f.vuln.title}</span>
                    </td>
                    <td style={{ color: SEVERITY_VAR[f.vuln.severity], whiteSpace: 'nowrap' }}>
                      {SEVERITY_LABEL[f.vuln.severity]} {f.vuln.cvss?.score != null ? f.vuln.cvss.score.toFixed(1) : ''}
                    </td>
                    <td className={styles.badges}>
                      <ExploitBadges vuln={f.vuln} />
                    </td>
                    <td>{f.techs.map((t) => `${t.name} ${t.version ?? ''}`.trim()).join(', ')}</td>
                    <td className="mono">{f.vuln.fixedIn ?? '—'}</td>
                    <td>
                      <ChevronRight size={14} className={expanded ? styles.chevronOpen : styles.chevron} aria-hidden="true" />
                    </td>
                  </tr>
                  {expanded && (
                    <tr>
                      <td colSpan={7}>
                        <VulnDetail finding={f} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
        {rows.length === 0 && <p className={styles.empty}>Nenhuma vulnerabilidade neste filtro.</p>}
      </div>
    </>
  );
}

function ConfigTable({ inventory, session }: { inventory: Inventory; session: ScanSession }) {
  const checked = session.misconfig?.checkedPages;
  if (checked === undefined) return <p className={styles.empty}>Checagens de configuração ainda não disponíveis para esta varredura.</p>;
  return (
    <>
      <p className={styles.hint}>
        {checked} página(s) HTML examinada(s) a partir das respostas já obtidas pelo crawl, sem requisições extras. Atributos de cookies não são observáveis (o navegador oculta Set-Cookie).
      </p>
      <div className={styles.tableWrap}>
        <table className={styles.table} aria-label="Achados de configuração">
          <thead>
            <tr>
              <th>Severidade</th>
              <th>Achado</th>
              <th>Páginas</th>
              <th>Evidência</th>
              <th>Exemplos</th>
            </tr>
          </thead>
          <tbody>
            {[...inventory.misconfigurations]
              .sort((a, b) => a.rank - b.rank)
              .map((f) => (
                <tr key={f.key}>
                  <td style={{ color: MISCONFIG_SEVERITY[f.severity].color }}>{MISCONFIG_SEVERITY[f.severity].label}</td>
                  <td>
                    <b>{f.title}</b>
                    <span className={styles.sub}>{f.detail}</span>
                  </td>
                  <td>
                    {f.pageCount} de {checked}
                  </td>
                  <td className="mono">{f.evidence ?? '—'}</td>
                  <td className={`mono ${styles.small}`}>{f.samplePages.join('\n')}</td>
                </tr>
              ))}
          </tbody>
        </table>
        {inventory.misconfigurations.length === 0 && <p className={styles.empty}>Nenhum problema de configuração observado.</p>}
      </div>
    </>
  );
}

function TechTable({ inventory }: { inventory: Inventory }) {
  const [query, setQuery] = useState('');
  const q = query.trim().toLowerCase();
  const rows = [...inventory.technologies]
    .sort((a, b) => Number(a.inferred) - Number(b.inferred) || b.pageCount - a.pageCount || a.name.localeCompare(b.name))
    .filter((t) => !q || t.name.toLowerCase().includes(q) || t.version?.includes(q) || t.categories.some((c) => CATEGORY_LABELS[c].toLowerCase().includes(q)));
  const cveOf = (id: string) => inventory.techCve.find((r) => r.techId === id);
  return (
    <>
      <div className={styles.toolbar}>
        <input type="search" placeholder="Buscar tecnologia, versão ou categoria" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Buscar tecnologia" />
        <span className={styles.count}>
          {rows.length} de {inventory.technologies.length}
        </span>
      </div>
      <div className={styles.tableWrap}>
        <table className={styles.table} aria-label="Tecnologias">
          <thead>
            <tr>
              <th>Tecnologia</th>
              <th>Versão</th>
              <th>Categorias</th>
              <th>Páginas</th>
              <th>Fonte</th>
              <th>CVEs</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((t) => {
              const cve = cveOf(t.id);
              return (
                <tr key={t.id}>
                  <td>
                    {t.name}
                    {t.inferred && <span className={styles.tag}>inferida</span>}
                  </td>
                  <td className="mono">
                    {t.version ?? '—'}
                    {t.version && !t.versionExact && <span className={styles.tag}>imprecisa</span>}
                  </td>
                  <td>{t.categories.map((c) => CATEGORY_LABELS[c]).join(', ')}</td>
                  <td>{t.pageCount}</td>
                  <td>{t.source === 'wappalyzer' ? <span className={styles.tag}>WA</span> : 'curada'}</td>
                  <td>{cve ? (cve.status === 'ok' ? cve.vulnIds.length : <span className={styles.muted}>{cve.message ?? cve.status}</span>) : '—'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

function PagesTable({ inventory }: { inventory: Inventory }) {
  const rows = [...inventory.pages].sort((a, b) => a.depth - b.depth || a.url.localeCompare(b.url));
  return (
    <div className={styles.tableWrap}>
      <table className={styles.table} aria-label="Páginas varridas">
        <thead>
          <tr>
            <th>Prof.</th>
            <th>Status</th>
            <th>URL</th>
            <th>Tipo</th>
            <th>Tecnologias</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((p) => (
            <tr key={p.key}>
              <td>{p.depth}</td>
              <td style={p.error || p.status >= 400 ? { color: 'var(--danger)' } : undefined}>{p.status || p.error || '—'}</td>
              <td className="mono">{p.finalUrl}</td>
              <td className={styles.small}>{p.contentType.split(';')[0]}</td>
              <td>{p.technologies.length}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HostsTable({ inventory }: { inventory: Inventory }) {
  const rows = [...inventory.assets].sort((a, b) => Number(b.thirdParty) - Number(a.thirdParty) || b.count - a.count);
  return (
    <div className={styles.tableWrap}>
      <table className={styles.table} aria-label="Hosts">
        <thead>
          <tr>
            <th>Host</th>
            <th>Origem</th>
            <th>Referências</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((a) => (
            <tr key={a.key}>
              <td className="mono">{a.host}</td>
              <td>{a.thirdParty ? 'terceiro' : 'próprio'}</td>
              <td>{a.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const CSV_TABLES: Array<[CsvTable, string]> = [
  ['vulnerabilities', 'Vulnerabilidades'],
  ['technologies', 'Tecnologias'],
  ['configuration', 'Configuração'],
  ['pages', 'Páginas'],
];

export function Dashboard() {
  const sessionId = sessionIdFromUrl();
  const { sessions, inventories, loadInventory } = useScan();
  const [tab, setTab] = useState<TabId>('vulns');
  const session = sessions.find((s) => s.id === sessionId);
  const inventory = sessionId ? inventories[sessionId] : undefined;

  useEffect(() => {
    getSettings()
      .then((s) => {
        document.documentElement.dataset.theme = s.theme;
      })
      .catch(() => undefined);
  }, []);

  // Reload the inventory when the session reaches a new stage (crawl done, CVE phase done, …).
  const stage = session ? `${session.status}|${session.cve?.status ?? ''}|${session.cve?.done ?? ''}|${session.counters.fetched}` : '';
  useEffect(() => {
    if (sessionId && session) loadInventory(sessionId);
  }, [sessionId, stage, loadInventory]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (session) document.title = `TechRecon — ${session.label}`;
  }, [session]);

  if (!sessionId) return <p className={styles.empty}>Nenhuma varredura indicada. Abra o painel a partir da lista de varreduras no popup.</p>;
  if (!session) {
    return (
      <p className={styles.empty}>
        <Loader2 size={14} className={styles.spin} /> Carregando varredura…
      </p>
    );
  }

  const exportInput = (): ScanExportInput | null =>
    inventory ? { session, inventory, toolVersion: chrome.runtime.getManifest().version } : null;
  const doExport = (kind: 'json' | 'md' | 'html' | CsvTable) => {
    const input = exportInput();
    if (!input) return;
    if (kind === 'json') download(scanFileName(session, 'json'), scanToJson(input), 'application/json');
    else if (kind === 'md') download(scanFileName(session, 'md'), scanToMarkdown(input), 'text/markdown');
    else if (kind === 'html') download(scanFileName(session, 'html'), scanToHtml(input), 'text/html');
    else download(scanFileName(session, 'csv', kind), scanToCsv(input, kind), 'text/csv');
  };

  const running = session.status === 'running';
  const exploited = inventory?.vulnerabilities.filter((f) => f.vuln.kev).length ?? 0;
  const tabs: Array<[TabId, string, number | undefined]> = [
    ['vulns', 'Vulnerabilidades', inventory?.vulnerabilities.length],
    ['config', 'Configuração', inventory?.misconfigurations.length],
    ['techs', 'Tecnologias', inventory?.technologies.length],
    ['pages', 'Páginas', inventory?.pages.length],
    ['hosts', 'Hosts', inventory?.assets.length],
  ];

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <div>
          <h1>{session.label}</h1>
          <p className={styles.meta}>
            <span className={styles.status} data-status={session.status}>
              {running && <Loader2 size={12} className={styles.spin} />}
              {running && session.cve?.status === 'running' ? `correlacionando CVEs ${session.cve.done}/${session.cve.eligible}` : STATUS_LABEL[session.status]}
            </span>
            {session.scope.seeds.join(', ')} · iniciada {session.startedAt ? new Date(session.startedAt).toLocaleString('pt-BR') : '—'}
            {session.finishedAt ? ` · terminada ${new Date(session.finishedAt).toLocaleString('pt-BR')}` : ''}
          </p>
          <p className={styles.meta}>Autorização registrada: “{session.authorization.statement}”</p>
          {session.error && (
            <p className={styles.alert} role="alert">
              {session.error}
            </p>
          )}
        </div>
        <nav className={styles.exports} aria-label="Exportar">
          <button type="button" onClick={() => doExport('html')} disabled={!inventory}>
            <FileCode2 size={14} /> Relatório HTML
          </button>
          <button type="button" onClick={() => doExport('md')} disabled={!inventory}>
            <FileText size={14} /> Markdown
          </button>
          <button type="button" onClick={() => doExport('json')} disabled={!inventory}>
            <FileJson size={14} /> JSON
          </button>
          {CSV_TABLES.map(([id, label]) => (
            <button key={id} type="button" onClick={() => doExport(id)} disabled={!inventory}>
              <FileSpreadsheet size={14} /> CSV {label}
            </button>
          ))}
        </nav>
      </header>

      <section className={styles.kpis} aria-label="Resumo">
        <Kpi value={session.counters.fetched} label="páginas" />
        <Kpi value={inventory?.technologies.filter((t) => !t.inferred).length ?? session.counters.technologies} label="tecnologias observadas" />
        <Kpi value={inventory?.vulnerabilities.length ?? session.counters.vulnerabilities} label="vulnerabilidades" />
        <Kpi value={exploited} label="no CISA KEV" tone={exploited ? 'var(--sev-critical)' : undefined} />
        <Kpi value={inventory?.misconfigurations.length ?? session.counters.misconfigurations} label="achados de configuração" />
        <Kpi value={inventory?.assets.filter((a) => a.thirdParty).length ?? 0} label="hosts de terceiros" />
      </section>

      <div className={styles.tabs} role="tablist">
        {tabs.map(([id, label, n]) => (
          <button key={id} type="button" role="tab" aria-selected={tab === id} onClick={() => setTab(id)}>
            {label} {n !== undefined && <span>{n}</span>}
          </button>
        ))}
      </div>

      <main className={styles.panel} role="tabpanel">
        {!inventory ? (
          <p className={styles.empty}>
            <Loader2 size={14} className={styles.spin} /> Carregando inventário…
          </p>
        ) : tab === 'vulns' ? (
          <VulnTable inventory={inventory} session={session} />
        ) : tab === 'config' ? (
          <ConfigTable inventory={inventory} session={session} />
        ) : tab === 'techs' ? (
          <TechTable inventory={inventory} />
        ) : tab === 'pages' ? (
          <PagesTable inventory={inventory} />
        ) : (
          <HostsTable inventory={inventory} />
        )}
      </main>
    </div>
  );
}

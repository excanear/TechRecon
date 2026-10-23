// Export of a whole-site scan: JSON (machine-readable, complete), Markdown (report), CSV (one
// table at a time, for spreadsheets) and a self-contained static HTML report. All builders are
// pure. Content that came from the target or from vulnerability sources is untrusted: it is
// escaped for each format, URLs are redacted, and only http(s) URLs become links.

import type { AggregatedTech } from '../crawler/aggregate';
import type { AssetRecord, PageRecord } from '../crawler/types';
import { formatEpss, priorityTier } from '../cve/enrich';
import { CATEGORY_LABELS } from '../fingerprinting/signature';
import type { MisconfigRecord, ScanSession, TechCveRecord, VulnFindingRecord } from '../scan/types';
import { redactUrl } from '../shared/redact';
import { safeHttpUrl } from '../shared/sanitize';
import { DISCLAIMER, mdCell } from './index';

export interface ScanInventory {
  technologies: AggregatedTech[];
  pages: PageRecord[];
  assets: AssetRecord[];
  techCve: TechCveRecord[];
  vulnerabilities: VulnFindingRecord[];
  misconfigurations: MisconfigRecord[];
}

export interface ScanExportInput {
  session: ScanSession;
  inventory: ScanInventory;
  toolVersion: string;
  generatedAt?: Date;
}

export type CsvTable = 'vulnerabilities' | 'technologies' | 'pages' | 'configuration';

const SEVERITY_PT: Record<string, string> = { CRITICAL: 'Crítica', HIGH: 'Alta', MEDIUM: 'Média', LOW: 'Baixa', NONE: 'Nenhuma', UNKNOWN: 'Sem score' };
const MISCONFIG_PT: Record<string, string> = { high: 'Alta', medium: 'Média', low: 'Baixa', info: 'Info' };
const STATUS_PT: Record<string, string> = { draft: 'rascunho', authorized: 'autorizada', running: 'em andamento', paused: 'pausada', done: 'concluída', aborted: 'interrompida', error: 'erro' };
const CVE_STATUS_PT: Record<string, string> = {
  ok: 'consultada',
  'no-version': 'sem versão',
  'version-uncertain': 'versão incerta',
  unmapped: 'sem fonte',
  disabled: 'desativada',
  error: 'falha',
  pending: 'pendente',
};

function stamp(date: Date): string {
  return date.toISOString().replace(/[:]/g, '-').replace(/\..+$/, '');
}

export function scanFileName(session: ScanSession, ext: 'json' | 'md' | 'csv' | 'html', table?: CsvTable, now = new Date()): string {
  const label = session.label.replace(/[^a-z0-9.-]/gi, '_').slice(0, 60) || 'scan';
  return `techrecon-scan-${label}${table ? `-${table}` : ''}-${stamp(now)}.${ext}`;
}

/** Sorted, display-ready copies of the inventory (never mutates the input). */
function ordered(inv: ScanInventory) {
  return {
    vulns: [...inv.vulnerabilities].sort((a, b) => a.rank - b.rank),
    techs: [...inv.technologies].sort((a, b) => Number(a.inferred) - Number(b.inferred) || b.pageCount - a.pageCount || a.name.localeCompare(b.name)),
    pages: [...inv.pages].sort((a, b) => a.depth - b.depth || a.url.localeCompare(b.url)),
    misconfig: [...inv.misconfigurations].sort((a, b) => a.rank - b.rank),
  };
}

function summary(input: ScanExportInput) {
  const { session, inventory } = input;
  const bySeverity: Record<string, number> = {};
  for (const f of inventory.vulnerabilities) bySeverity[f.vuln.severity] = (bySeverity[f.vuln.severity] ?? 0) + 1;
  return {
    pagesFetched: inventory.pages.length,
    technologies: inventory.technologies.length,
    observedTechnologies: inventory.technologies.filter((t) => !t.inferred).length,
    vulnerabilities: inventory.vulnerabilities.length,
    knownExploited: inventory.vulnerabilities.filter((f) => f.vuln.kev).length,
    bySeverity,
    configurationFindings: inventory.misconfigurations.length,
    thirdPartyHosts: inventory.assets.filter((a) => a.thirdParty).length,
    cveCorrelation: session.cve ? { status: session.cve.status, eligible: session.cve.eligible, queried: session.cve.done, failed: session.cve.errors } : null,
  };
}

// ───────────────────────── JSON ─────────────────────────

export function buildScanJson(input: ScanExportInput) {
  const { session, inventory } = input;
  const o = ordered(inventory);
  return {
    schema: 'techrecon.scan-report/v1',
    tool: { name: 'TechRecon', version: input.toolVersion },
    generatedAt: (input.generatedAt ?? new Date()).toISOString(),
    disclaimer: DISCLAIMER,
    session: {
      id: session.id,
      label: session.label,
      status: session.status,
      createdAt: session.createdAt,
      startedAt: session.startedAt ?? null,
      finishedAt: session.finishedAt ?? null,
      error: session.error ?? null,
      authorization: session.authorization,
      scope: { ...session.scope, seeds: session.scope.seeds.map(redactUrl) },
    },
    summary: summary(input),
    exploitationIntel: session.cve?.enrichment ?? null,
    vulnerabilities: o.vulns.map((f) => ({
      rank: f.rank + 1,
      id: f.vuln.id,
      aliases: f.vuln.aliases,
      title: f.vuln.title,
      severity: f.vuln.severity,
      cvss: f.vuln.cvss,
      priority: priorityTier(f.vuln),
      kev: f.vuln.kev,
      epss: f.vuln.epss,
      technologies: f.techs,
      affected: f.vuln.affected,
      fixedIn: f.vuln.fixedIn ?? null,
      matchBasis: f.vuln.matchBasis,
      conditions: f.vuln.conditions ?? null,
      source: f.vuln.source,
      sourceUrl: f.vuln.sourceUrl,
      references: f.vuln.references,
    })),
    technologies: o.techs.map((t) => {
      const cve = inventory.techCve.find((r) => r.techId === t.id);
      return {
        id: t.id,
        name: t.name,
        categories: t.categories,
        version: t.version ?? null,
        versionExact: t.versionExact,
        versionConflicts: t.versionConflicts,
        confidence: t.confidence,
        inferred: t.inferred,
        source: t.source ?? 'curated',
        pageCount: t.pageCount,
        samplePages: t.samplePages.map(redactUrl),
        cpe: t.cpe ?? [],
        npm: t.npm ?? null,
        cveCorrelation: cve ? { status: cve.status, message: cve.message ?? null, vulnerabilities: cve.vulnIds } : null,
      };
    }),
    configuration: o.misconfig.map((f) => ({
      check: f.check,
      severity: f.severity,
      title: f.title,
      detail: f.detail,
      evidence: f.evidence ?? null,
      pageCount: f.pageCount,
      samplePages: f.samplePages,
    })),
    pages: o.pages.map((p) => ({
      url: redactUrl(p.url),
      finalUrl: redactUrl(p.finalUrl),
      depth: p.depth,
      status: p.status,
      contentType: p.contentType,
      technologies: p.technologies,
      error: p.error ?? null,
    })),
    hosts: [...inventory.assets].sort((a, b) => b.count - a.count).map((a) => ({ host: a.host, requests: a.count, thirdParty: a.thirdParty })),
  };
}

export function scanToJson(input: ScanExportInput): string {
  return `${JSON.stringify(buildScanJson(input), null, 2)}\n`;
}

// ───────────────────────── CSV ─────────────────────────

/**
 * RFC 4180 quoting, plus spreadsheet formula neutralization: a cell starting with = + - @ (or a
 * tab/CR) is prefixed with an apostrophe so Excel/Sheets show it as text instead of evaluating it.
 */
export function csvCell(value: unknown): string {
  let s = value === null || value === undefined ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function csv(header: string[], rows: unknown[][]): string {
  // BOM so Excel opens UTF-8 (accents) correctly.
  return `﻿${[header, ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n')}\r\n`;
}

export function scanToCsv(input: ScanExportInput, table: CsvTable): string {
  const o = ordered(input.inventory);
  switch (table) {
    case 'vulnerabilities':
      return csv(
        ['prioridade', 'id', 'aliases', 'severidade', 'cvss', 'kev', 'kev_ransomware', 'epss', 'epss_percentil', 'tecnologias', 'corrigida_em', 'titulo', 'fonte'],
        o.vulns.map((f) => [
          f.rank + 1,
          f.vuln.id,
          f.vuln.aliases.join(' '),
          f.vuln.severity,
          f.vuln.cvss?.score ?? '',
          f.vuln.kev === undefined ? 'não verificado' : f.vuln.kev ? `sim (${f.vuln.kev.dateAdded})` : 'não',
          f.vuln.kev ? (f.vuln.kev.ransomware ? 'sim' : 'não') : '',
          f.vuln.epss === undefined ? 'não verificado' : f.vuln.epss ? f.vuln.epss.score : 'sem score',
          f.vuln.epss ? f.vuln.epss.percentile : '',
          f.techs.map((t) => `${t.name} ${t.version ?? ''}`.trim()).join('; '),
          f.vuln.fixedIn ?? '',
          f.vuln.title,
          safeHttpUrl(f.vuln.sourceUrl) ?? '',
        ]),
      );
    case 'technologies':
      return csv(
        ['nome', 'versao', 'versao_exata', 'categorias', 'confianca', 'inferida', 'fonte', 'paginas', 'cpe', 'cves', 'correlacao'],
        o.techs.map((t) => {
          const cve = input.inventory.techCve.find((r) => r.techId === t.id);
          return [
            t.name,
            t.version ?? '',
            t.versionExact ? 'sim' : 'não',
            t.categories.map((c) => CATEGORY_LABELS[c]).join('; '),
            t.confidence,
            t.inferred ? 'sim' : 'não',
            t.source ?? 'curated',
            t.pageCount,
            (t.cpe ?? []).join(' '),
            cve?.vulnIds.length ?? '',
            cve ? CVE_STATUS_PT[cve.status] ?? cve.status : '',
          ];
        }),
      );
    case 'pages':
      return csv(
        ['url', 'url_final', 'profundidade', 'status', 'content_type', 'tecnologias', 'erro'],
        o.pages.map((p) => [redactUrl(p.url), redactUrl(p.finalUrl), p.depth, p.status, p.contentType, p.technologies.join(' '), p.error ?? '']),
      );
    case 'configuration':
      return csv(
        ['severidade', 'checagem', 'titulo', 'detalhe', 'evidencia', 'paginas', 'exemplos'],
        o.misconfig.map((f) => [MISCONFIG_PT[f.severity], f.check, f.title, f.detail, f.evidence ?? '', f.pageCount, f.samplePages.join(' ')]),
      );
  }
}

// ───────────────────────── Markdown ─────────────────────────

function mdLink(label: string, url: string): string {
  const safe = safeHttpUrl(url);
  return safe ? `[${mdCell(label)}](${safe.replace(/[()\s]/g, encodeURIComponent)})` : mdCell(label);
}

function exploitText(f: VulnFindingRecord): string {
  const parts: string[] = [];
  if (f.vuln.kev) parts.push(f.vuln.kev.ransomware ? 'KEV (ransomware)' : 'KEV');
  if (f.vuln.epss) parts.push(`EPSS ${formatEpss(f.vuln.epss.score)}`);
  if (parts.length) return parts.join(' · ');
  return f.vuln.kev === undefined || f.vuln.epss === undefined ? 'não verificado' : '—';
}

export function scanToMarkdown(input: ScanExportInput): string {
  const { session, inventory } = input;
  const o = ordered(inventory);
  const s = summary(input);
  const lines: string[] = [];
  lines.push(`# TechRecon — varredura ${mdCell(session.label)}`, '');
  lines.push(`- Gerado em: ${(input.generatedAt ?? new Date()).toISOString()} (TechRecon ${mdCell(input.toolVersion)})`);
  lines.push(`- Escopo: ${session.scope.seeds.map((u) => mdCell(redactUrl(u))).join(', ')} · hosts ${session.scope.includeHosts.map((h) => mdCell(h.pattern)).join(', ') || '—'}`);
  lines.push(`- Autorização: ${mdCell(session.authorization.statement)} (${mdCell(session.authorization.at)})`);
  lines.push(`- Status: ${mdCell(STATUS_PT[session.status] ?? session.status)} · ${s.pagesFetched} páginas · ${s.technologies} tecnologias · ${s.vulnerabilities} vulnerabilidades (${s.knownExploited} no CISA KEV) · ${s.configurationFindings} achados de configuração`);
  lines.push('', `> ${mdCell(DISCLAIMER)}`, '');

  const intel = session.cve?.enrichment;
  if (intel && (intel.kev.error || intel.epss.error)) {
    lines.push(`> Inteligência de exploração parcial: ${[intel.kev.error && `KEV: ${intel.kev.error}`, intel.epss.error && `EPSS: ${intel.epss.error}`].filter(Boolean).map(mdCell).join(' · ')}`, '');
  }

  lines.push('## Vulnerabilidades priorizadas', '');
  if (!o.vulns.length) lines.push(session.cve?.status === 'disabled' ? '_Correlação de CVEs desativada._' : '_Nenhuma vulnerabilidade correlacionada por versão._', '');
  else {
    lines.push('| # | ID | Severidade | CVSS | Exploração | Tecnologias | Corrigida em |', '|---|---|---|---|---|---|---|');
    for (const f of o.vulns) {
      lines.push(
        `| ${f.rank + 1} | ${mdLink(f.vuln.id, f.vuln.sourceUrl)} | ${SEVERITY_PT[f.vuln.severity]} | ${f.vuln.cvss?.score ?? '—'} | ${mdCell(exploitText(f))} | ${mdCell(f.techs.map((t) => `${t.name} ${t.version ?? ''}`.trim()).join(', '))} | ${mdCell(f.vuln.fixedIn ?? 'não informado')} |`,
      );
    }
    lines.push('');
  }

  const failed = inventory.techCve.filter((r) => r.status === 'error' || (r.status === 'ok' && r.message));
  if (failed.length) {
    lines.push('### Consultas com falha (nenhum resultado presumido)', '');
    for (const r of failed) lines.push(`- ${mdCell(`${r.techName} ${r.version ?? ''}`.trim())}: ${mdCell(r.message ?? '')}`);
    lines.push('');
  }

  lines.push('## Configuração (passiva)', '');
  if (!o.misconfig.length) lines.push('_Nenhum problema de configuração observado._', '');
  else {
    lines.push('| Severidade | Achado | Páginas | Evidência |', '|---|---|---|---|');
    for (const f of o.misconfig) lines.push(`| ${MISCONFIG_PT[f.severity]} | ${mdCell(f.title)}: ${mdCell(f.detail)} | ${f.pageCount} | ${mdCell(f.evidence ?? '—')} |`);
    lines.push('');
  }

  lines.push('## Tecnologias', '');
  lines.push('| Tecnologia | Versão | Categorias | Páginas | Fonte | CVEs |', '|---|---|---|---|---|---|');
  for (const t of o.techs) {
    const cve = inventory.techCve.find((r) => r.techId === t.id);
    lines.push(
      `| ${mdCell(t.name)}${t.inferred ? ' _(inferida)_' : ''} | ${mdCell(t.version ?? '—')}${t.version && !t.versionExact ? ' (imprecisa)' : ''} | ${mdCell(t.categories.map((c) => CATEGORY_LABELS[c]).join(', '))} | ${t.pageCount} | ${t.source === 'wappalyzer' ? 'Wappalyzer' : 'curada'} | ${cve ? (cve.status === 'ok' ? String(cve.vulnIds.length) : mdCell(CVE_STATUS_PT[cve.status] ?? cve.status)) : '—'} |`,
    );
  }
  lines.push('');

  lines.push('## Páginas varridas', '');
  lines.push('| Profundidade | Status | URL |', '|---|---|---|');
  for (const p of o.pages) lines.push(`| ${p.depth} | ${p.status || mdCell(p.error ?? '—')} | ${mdCell(redactUrl(p.finalUrl))} |`);
  lines.push('');
  return `${lines.join('\n')}\n`;
}

// ───────────────────────── HTML ─────────────────────────

export function escapeHtml(value: unknown): string {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

function htmlLink(label: string, url: string): string {
  const safe = safeHttpUrl(url);
  return safe ? `<a href="${escapeHtml(safe)}" rel="noreferrer noopener">${escapeHtml(label)}</a>` : escapeHtml(label);
}

const HTML_STYLE = `
:root{--bg:#fff;--fg:#1d2330;--muted:#5d6676;--line:#dde1e8;--crit:#c2304b;--high:#c4601b;--med:#9a7a12;--low:#3d6f9e}
@media (prefers-color-scheme:dark){:root{--bg:#12151c;--fg:#e4e7ee;--muted:#9aa3b2;--line:#2a303c;--crit:#f0607a;--high:#f0904a;--med:#d9b44a;--low:#7fa6cf}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--line)}
.meta,.note{color:var(--muted)}.note{border-left:3px solid var(--line);padding:4px 10px;margin:12px 0}
.kpis{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}.kpi{border:1px solid var(--line);border-radius:8px;padding:8px 14px;min-width:120px}.kpi b{display:block;font-size:22px}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}.kev{color:var(--crit);font-weight:700}
.s-CRITICAL,.s-high{color:var(--crit)}.s-HIGH{color:var(--high)}.s-MEDIUM,.s-medium{color:var(--med)}.s-LOW,.s-low{color:var(--low)}a{color:inherit}`;

export function scanToHtml(input: ScanExportInput): string {
  const { session, inventory } = input;
  const o = ordered(inventory);
  const s = summary(input);
  const generated = (input.generatedAt ?? new Date()).toISOString();
  const row = (cells: string[]) => `<tr>${cells.map((c) => `<td>${c}</td>`).join('')}</tr>`;
  const table = (head: string[], rows: string[]) =>
    `<div class="scroll"><table><thead><tr>${head.map((h) => `<th>${escapeHtml(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;

  const vulnRows = o.vulns.map((f) =>
    row([
      String(f.rank + 1),
      `<span class="mono">${htmlLink(f.vuln.id, f.vuln.sourceUrl)}</span><br>${escapeHtml(f.vuln.title)}`,
      `<span class="s-${escapeHtml(f.vuln.severity)}">${escapeHtml(SEVERITY_PT[f.vuln.severity])}${f.vuln.cvss?.score != null ? ` ${f.vuln.cvss.score}` : ''}</span>`,
      f.vuln.kev ? `<span class="kev">KEV${f.vuln.kev.ransomware ? ' · ransomware' : ''}</span>${f.vuln.epss ? `<br>EPSS ${formatEpss(f.vuln.epss.score)}` : ''}` : escapeHtml(exploitText(f)),
      escapeHtml(f.techs.map((t) => `${t.name} ${t.version ?? ''}`.trim()).join(', ')),
      escapeHtml(f.vuln.fixedIn ?? 'não informado'),
    ]),
  );
  const configRows = o.misconfig.map((f) =>
    row([
      `<span class="s-${escapeHtml(f.severity)}">${escapeHtml(MISCONFIG_PT[f.severity])}</span>`,
      `<b>${escapeHtml(f.title)}</b><br>${escapeHtml(f.detail)}`,
      String(f.pageCount),
      f.evidence ? `<code>${escapeHtml(f.evidence)}</code>` : '—',
    ]),
  );
  const techRows = o.techs.map((t) => {
    const cve = inventory.techCve.find((r) => r.techId === t.id);
    return row([
      `${escapeHtml(t.name)}${t.inferred ? ' <i>(inferida)</i>' : ''}`,
      `<span class="mono">${escapeHtml(t.version ?? '—')}</span>`,
      escapeHtml(t.categories.map((c) => CATEGORY_LABELS[c]).join(', ')),
      String(t.pageCount),
      t.source === 'wappalyzer' ? 'Wappalyzer' : 'curada',
      cve ? (cve.status === 'ok' ? String(cve.vulnIds.length) : escapeHtml(CVE_STATUS_PT[cve.status] ?? cve.status)) : '—',
    ]);
  });
  const pageRows = o.pages.map((p) => row([String(p.depth), escapeHtml(p.status || p.error || '—'), `<span class="mono">${escapeHtml(redactUrl(p.finalUrl))}</span>`]));
  const intel = session.cve?.enrichment;
  const intelNote =
    intel && (intel.kev.error || intel.epss.error)
      ? `<p class="note">Inteligência de exploração parcial: ${escapeHtml([intel.kev.error && `KEV: ${intel.kev.error}`, intel.epss.error && `EPSS: ${intel.epss.error}`].filter(Boolean).join(' · '))}</p>`
      : '';

  // No scripts at all; the CSP forbids them and any remote load, so the file is safe to open and share.
  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>TechRecon — ${escapeHtml(session.label)}</title>
<style>${HTML_STYLE}</style>
</head>
<body>
<main>
<h1>TechRecon — varredura ${escapeHtml(session.label)}</h1>
<p class="meta">Gerado em ${escapeHtml(generated)} · TechRecon ${escapeHtml(input.toolVersion)} · status ${escapeHtml(STATUS_PT[session.status] ?? session.status)}</p>
<p class="meta">Escopo: <span class="mono">${escapeHtml(session.scope.seeds.map(redactUrl).join(', '))}</span> · Autorização: ${escapeHtml(session.authorization.statement)} (${escapeHtml(session.authorization.at)})</p>
<div class="kpis">
<div class="kpi"><b>${s.pagesFetched}</b>páginas</div>
<div class="kpi"><b>${s.observedTechnologies}</b>tecnologias observadas</div>
<div class="kpi"><b>${s.vulnerabilities}</b>vulnerabilidades</div>
<div class="kpi"><b class="kev">${s.knownExploited}</b>no CISA KEV</div>
<div class="kpi"><b>${s.configurationFindings}</b>achados de configuração</div>
</div>
<p class="note">${escapeHtml(DISCLAIMER)}</p>
${intelNote}
<h2>Vulnerabilidades priorizadas (${o.vulns.length})</h2>
<p class="meta">Ordem: CISA KEV, depois EPSS alto (≥ 10%) e médio (≥ 1%), depois CVSS.</p>
${o.vulns.length ? table(['#', 'ID', 'Severidade', 'Exploração', 'Tecnologias', 'Corrigida em'], vulnRows) : '<p class="meta">Nenhuma vulnerabilidade correlacionada por versão.</p>'}
<h2>Configuração passiva (${o.misconfig.length})</h2>
${o.misconfig.length ? table(['Severidade', 'Achado', 'Páginas', 'Evidência'], configRows) : '<p class="meta">Nenhum problema de configuração observado.</p>'}
<h2>Tecnologias (${o.techs.length})</h2>
${table(['Tecnologia', 'Versão', 'Categorias', 'Páginas', 'Fonte', 'CVEs'], techRows)}
<h2>Páginas varridas (${o.pages.length})</h2>
${table(['Profundidade', 'Status', 'URL'], pageRows)}
</main>
</body>
</html>
`;
}

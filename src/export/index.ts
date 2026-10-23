import { comparePriority, formatEpss, priorityTier, type PriorityTier } from '../cve/enrich';
import { CATEGORY_LABELS } from '../fingerprinting/signature';
import { redactUrl } from '../shared/redact';
import type { AnalysisState, Confirmations, Severity, Vulnerability } from '../types';

export const DISCLAIMER =
  'Resultados de análise passiva. Vulnerabilidades "potenciais" indicam apenas que a versão observada está dentro de um ' +
  'intervalo afetado segundo a fonte citada; não confirmam que a aplicação é explorável (configuração, backports e ' +
  'mitigações não são verificáveis passivamente). "Confirmada" significa verificada manualmente pelo analista.';

export interface ExportMeta {
  toolVersion: string;
  generatedAt?: Date;
}

export interface ExportedVulnerability {
  id: string;
  aliases: string[];
  technology: string;
  technologyVersion?: string;
  status: 'potential' | 'confirmed-by-analyst';
  confirmedAt?: string;
  severity: Severity;
  cvss: Vulnerability['cvss'];
  title: string;
  affected: string[];
  fixedIn?: string;
  matchBasis: string;
  conditions?: string;
  source: string;
  sourceUrl: string;
  references: Vulnerability['references'];
  published?: string;
  /** Exploitation priority (KEV, then EPSS band). */
  priority: PriorityTier;
  /** null = checked and not listed; undefined = not checked (source unavailable). */
  kev: Vulnerability['kev'];
  epss: Vulnerability['epss'];
}

function exploitCell(v: ExportedVulnerability): string {
  const parts: string[] = [];
  if (v.kev) parts.push(v.kev.ransomware ? '**KEV** (ransomware)' : '**KEV**');
  if (v.epss) parts.push(`EPSS ${formatEpss(v.epss.score)}`);
  if (!parts.length) return v.kev === undefined || v.epss === undefined ? 'não verificado' : '—';
  return parts.join(' · ');
}

/** Every vulnerability of the analysis, most urgent first (KEV → EPSS band → CVSS). */
export function collectVulnerabilities(state: AnalysisState, confirmations: Confirmations): ExportedVulnerability[] {
  const pairs = Object.values(state.vulnReports).flatMap((report) => report.vulns.map((v) => ({ report, v })));
  pairs.sort((a, b) => comparePriority(a.v, b.v));
  return pairs.map(({ report, v }) => {
    const confirmation = confirmations[v.id];
    return {
      id: v.id,
      aliases: v.aliases,
      technology: report.techName,
      technologyVersion: report.version,
      status: confirmation ? 'confirmed-by-analyst' : 'potential',
      confirmedAt: confirmation?.at,
      severity: v.severity,
      cvss: v.cvss,
      title: v.title,
      affected: v.affected,
      fixedIn: v.fixedIn,
      matchBasis: v.matchBasis,
      conditions: v.conditions,
      source: v.source === 'nvd' ? 'NVD (NIST)' : 'OSV (GitHub Advisory Database e outras)',
      sourceUrl: v.sourceUrl,
      references: v.references,
      published: v.published,
      priority: priorityTier(v),
      kev: v.kev,
      epss: v.epss,
    };
  });
}

export function buildJsonReport(state: AnalysisState, confirmations: Confirmations, meta: ExportMeta) {
  const vulnerabilities = collectVulnerabilities(state, confirmations);
  const bySeverity: Partial<Record<Severity, number>> = {};
  for (const v of vulnerabilities) bySeverity[v.severity] = (bySeverity[v.severity] ?? 0) + 1;
  return {
    schema: 'techrecon.report/v1',
    tool: { name: 'TechRecon', version: meta.toolVersion },
    generatedAt: (meta.generatedAt ?? new Date()).toISOString(),
    target: {
      url: redactUrl(state.url),
      domain: state.domain,
      analysisStartedAt: state.startedAt,
      analysisFinishedAt: state.finishedAt,
      headerSource: state.recon?.headerSource ?? 'none',
    },
    disclaimer: DISCLAIMER,
    summary: {
      technologies: state.technologies.length,
      observedTechnologies: state.technologies.filter((t) => !t.inferred).length,
      potentialVulnerabilities: vulnerabilities.filter((v) => v.status === 'potential').length,
      confirmedByAnalyst: vulnerabilities.filter((v) => v.status === 'confirmed-by-analyst').length,
      knownExploited: new Set(vulnerabilities.filter((v) => v.kev).map((v) => v.id)).size,
      bySeverity,
    },
    exploitationIntel: state.enrichment ?? null,
    technologies: state.technologies.map((t) => {
      const report = state.vulnReports[t.id];
      return {
        id: t.id,
        name: t.name,
        categories: t.categories,
        version: t.version ?? null,
        versionExact: t.versionExact,
        versionConflicts: t.versionConflicts,
        confidence: t.confidence,
        confidenceLevel: t.confidenceLevel,
        inferred: t.inferred,
        impliedBy: t.impliedBy ?? [],
        evidence: t.evidence,
        notes: t.notes,
        cpe: t.cpe ?? [],
        npm: t.npm ?? null,
        website: t.website ?? null,
        source: t.source ?? 'curated',
        vulnerabilityCorrelation: report
          ? { status: report.status, message: report.message ?? null, queries: report.queries, matches: report.vulns.map((v) => v.id) }
          : null,
      };
    }),
    vulnerabilities,
    recon: state.recon,
  };
}

export function toJson(state: AnalysisState, confirmations: Confirmations, meta: ExportMeta): string {
  return JSON.stringify(buildJsonReport(state, confirmations, meta), null, 2);
}

// ───────── Markdown ─────────

/** Escapes text for a Markdown table cell / inline context. */
export function mdCell(value: unknown): string {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/[`*_[\]<>]/g, (c) => `\\${c}`)
    .replace(/\s*\n\s*/g, ' ')
    .trim();
}

function mdLink(label: string, url: string): string {
  return `[${mdCell(label)}](${url.replace(/[()\s]/g, encodeURIComponent)})`;
}

export function toMarkdown(state: AnalysisState, confirmations: Confirmations, meta: ExportMeta): string {
  const report = buildJsonReport(state, confirmations, meta);
  const lines: string[] = [];
  lines.push(`# TechRecon — ${mdCell(report.target.domain)}`, '');
  lines.push(`- **URL:** ${mdCell(report.target.url)}`);
  lines.push(`- **Análise:** ${mdCell(report.target.analysisStartedAt)}${report.target.analysisFinishedAt ? ` → ${mdCell(report.target.analysisFinishedAt)}` : ''}`);
  lines.push(`- **Gerado em:** ${mdCell(report.generatedAt)} (TechRecon ${mdCell(report.tool.version)})`);
  lines.push(`- **Headers de resposta:** ${report.target.headerSource === 'probe' ? 'observados (requisição same-origin)' : 'não observados'}`);
  lines.push(`- **Tecnologias:** ${report.summary.technologies} (${report.summary.observedTechnologies} observadas diretamente)`);
  lines.push(`- **Vulnerabilidades potenciais:** ${report.summary.potentialVulnerabilities} · **confirmadas pelo analista:** ${report.summary.confirmedByAnalyst}`);
  lines.push('', `> ${mdCell(DISCLAIMER)}`, '');

  lines.push('## Tecnologias', '');
  if (!report.technologies.length) lines.push('_Nenhuma tecnologia detectada._', '');
  else {
    lines.push('| Tecnologia | Categoria | Versão | Confiança | Detecção | CVEs |', '|---|---|---|---|---|---|');
    for (const t of report.technologies) {
      const methods = [...new Set(t.evidence.map((e) => e.type))].join(', ');
      const corr = t.vulnerabilityCorrelation;
      const cves = !corr ? '—' : corr.status === 'ok' ? String(corr.matches.length) : corr.status;
      lines.push(
        `| ${mdCell(t.name)}${t.inferred ? ' _(inferida)_' : ''}${t.source === 'wappalyzer' ? ' _(Wappalyzer)_' : ''} | ${mdCell(t.categories.map((c) => CATEGORY_LABELS[c]).join(', '))} | ${mdCell(t.version ?? '—')}${t.version && !t.versionExact ? ' (imprecisa)' : ''} | ${t.confidence}% (${t.confidenceLevel}) | ${mdCell(methods)} | ${mdCell(cves)} |`,
      );
    }
    lines.push('');
    lines.push('### Evidências', '');
    for (const t of report.technologies) {
      lines.push(`**${mdCell(t.name)}**${t.version ? ` ${mdCell(t.version)}` : ''}`, '');
      for (const e of t.evidence) {
        lines.push(`- ${e.observed ? 'Observado' : 'Inferência'} · ${mdCell(e.type)}${e.key ? ` \`${e.key.replace(/`/g, "'")}\`` : ''}: ${mdCell(e.value)}${e.version ? ` → versão ${mdCell(e.version)}` : ''} (${e.confidence}%)`);
      }
      for (const n of t.notes) lines.push(`- Nota: ${mdCell(n)}`);
      if (t.vulnerabilityCorrelation?.message) lines.push(`- Correlação: ${mdCell(t.vulnerabilityCorrelation.message)}`);
      lines.push('');
    }
  }

  lines.push('## Vulnerabilidades', '');
  if (!report.vulnerabilities.length) {
    lines.push('_Nenhuma vulnerabilidade correlacionada por versão._', '');
  } else {
    lines.push('| ID | Status | Severidade | CVSS | Exploração | Tecnologia | Afetadas | Corrigida em | Fonte |', '|---|---|---|---|---|---|---|---|---|');
    for (const v of report.vulnerabilities) {
      lines.push(
        `| ${mdLink(v.id, v.sourceUrl)} | ${v.status === 'confirmed-by-analyst' ? '**Confirmada (analista)**' : 'Potencial'} | ${v.severity} | ${v.cvss?.score ?? '—'}${v.cvss ? ` (v${mdCell(v.cvss.version)})` : ''} | ${exploitCell(v)} | ${mdCell(`${v.technology} ${v.technologyVersion ?? ''}`)} | ${mdCell(v.affected.join('; '))} | ${mdCell(v.fixedIn ?? 'não informado')} | ${mdCell(v.source)} |`,
      );
    }
    lines.push('');
    for (const v of report.vulnerabilities) {
      lines.push(`### ${mdCell(v.id)} — ${mdCell(v.title)}`, '');
      if (v.aliases.length) lines.push(`- Aliases: ${mdCell(v.aliases.join(', '))}`);
      if (v.cvss?.vector) lines.push(`- Vetor: \`${v.cvss.vector.replace(/`/g, "'")}\``);
      lines.push(`- Base da correspondência: ${mdCell(v.matchBasis)}`);
      if (v.conditions) lines.push(`- Condições: ${mdCell(v.conditions)}`);
      if (v.kev) lines.push(`- CISA KEV: exploração ativa confirmada, incluída em ${v.kev.dateAdded}${v.kev.ransomware ? ', usada em ransomware' : ''}. Ação exigida: ${mdCell(v.kev.requiredAction)}`);
      if (v.epss) lines.push(`- EPSS: ${formatEpss(v.epss.score)} em 30 dias (percentil ${Math.round(v.epss.percentile * 100)}, modelo de ${v.epss.date})`);
      lines.push(`- Fonte oficial: ${mdLink(v.sourceUrl, v.sourceUrl)}`);
      for (const r of v.references.slice(0, 6)) lines.push(`- Referência: ${mdLink(r.label, r.url)}`);
      lines.push('');
    }
  }

  const recon = report.recon;
  if (recon) {
    lines.push('## Reconhecimento complementar', '');
    lines.push('| Header | Estado | Valor / observações |', '|---|---|---|');
    for (const h of recon.securityHeaders) {
      const state = h.state === 'present' ? `presente${h.origin === 'meta' ? ' (meta)' : ''}` : h.state === 'absent' ? 'ausente' : 'não observado';
      lines.push(`| ${mdCell(h.label)} | ${state} | ${mdCell([h.value, ...h.notes].filter(Boolean).join(' — '))} |`);
    }
    lines.push('');
    if (recon.notes.length) {
      for (const n of recon.notes) lines.push(`- ${mdCell(n)}`);
      lines.push('');
    }
    lines.push(`### Scripts externos (${recon.scripts.length}) · inline: ${recon.inlineScriptCount}`, '');
    for (const s of recon.scripts) {
      lines.push(`- ${mdCell(s.url)} — ${s.thirdParty ? 'terceiro' : 'próprio'}, ${s.loading}${s.integrity ? ', SRI' : ''}${s.insecure ? ', **HTTP inseguro**' : ''}`);
    }
    lines.push('');
    lines.push(`### Cookies legíveis por JavaScript (${recon.cookies.length})`, '');
    lines.push('_Valores não coletados. Cookies legíveis via document.cookie não possuem HttpOnly; Secure/SameSite não são observáveis._', '');
    for (const c of recon.cookies) lines.push(`- \`${c.name.replace(/`/g, "'")}\` (${c.valueLength} caracteres)`);
    lines.push('');
  }
  return lines.join('\n');
}

export function reportFileName(state: AnalysisState, ext: 'json' | 'md', now = new Date()): string {
  const domain = state.domain.replace(/[^a-z0-9.-]/gi, '_') || 'page';
  const stamp = now.toISOString().replace(/[:]/g, '-').replace(/\..+$/, '');
  return `techrecon-${domain}-${stamp}.${ext}`;
}

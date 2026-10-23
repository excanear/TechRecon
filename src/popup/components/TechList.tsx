import { ChevronRight, ExternalLink, Search } from 'lucide-react';
import { useMemo, useState } from 'react';
import { CATEGORY_LABELS, CATEGORY_ORDER } from '../../fingerprinting/signature';
import { safeHttpUrl } from '../../shared/sanitize';
import type { CategoryId, Detection, TechVulnReport } from '../../types';
import { CONFIDENCE_LABEL, EVIDENCE_LABEL, plural, REPORT_STATUS_LABEL } from '../format';
import { CATEGORY_ICON } from './icons';
import ui from './ui.module.css';

interface TechListProps {
  technologies: Detection[];
  reports: Record<string, TechVulnReport>;
  onShowVulns: (techId: string) => void;
  headerHint: boolean;
  onCaptureHeaders: () => void;
}

function primaryCategory(d: Detection): CategoryId {
  return [...d.categories].sort((a, b) => CATEGORY_ORDER.indexOf(a) - CATEGORY_ORDER.indexOf(b))[0]!;
}

function CveLine({ report, onShow }: { report?: TechVulnReport; onShow: () => void }) {
  if (!report) return null;
  if (report.status === 'ok') {
    if (!report.vulns.length) return <span>Nenhuma vulnerabilidade conhecida para esta versão nas fontes consultadas.</span>;
    return (
      <button type="button" className={ui.linkButton} onClick={onShow}>
        Ver {plural(report.vulns.length, 'vulnerabilidade potencial', 'vulnerabilidades potenciais')}
      </button>
    );
  }
  return (
    <span>
      {REPORT_STATUS_LABEL[report.status]}
      {report.message ? `: ${report.message}` : ''}
    </span>
  );
}

function TechDetail({ det, report, onShowVulns }: { det: Detection; report?: TechVulnReport; onShowVulns: () => void }) {
  const website = safeHttpUrl(det.website);
  return (
    <div className={ui.detail} id={`tech-${det.id}`}>
      <dl className={ui.kv}>
        <dt>Versão</dt>
        <dd>
          {det.version ? (
            <>
              <span className="mono">{det.version}</span>
              {!det.versionExact && <span className={ui.chip} style={{ marginLeft: 6 }}>imprecisa</span>}
            </>
          ) : (
            'não determinada'
          )}
        </dd>
        <dt>Confiança</dt>
        <dd>
          {det.confidence}% · {CONFIDENCE_LABEL[det.confidenceLevel]}
        </dd>
        <dt>Detecção</dt>
        <dd>{det.inferred ? `Inferida (${det.impliedBy?.join(', ')})` : [...new Set(det.evidence.map((e) => EVIDENCE_LABEL[e.type]))].join(', ')}</dd>
        {!det.inferred && det.impliedBy?.length ? (
          <>
            <dt>Coerente com</dt>
            <dd>{det.impliedBy.join(', ')}</dd>
          </>
        ) : null}
        <dt>CVEs</dt>
        <dd>
          <CveLine report={report} onShow={onShowVulns} />
        </dd>
      </dl>

      <h4 className={ui.subheading}>Evidências</h4>
      <ul className={ui.evidenceList}>
        {det.evidence.map((e, i) => (
          <li key={i} className={ui.evidence} data-observed={e.observed}>
            <span className={ui.evidenceType}>{EVIDENCE_LABEL[e.type]}</span>
            <span className={`${ui.evidenceValue} mono`}>
              {e.value}
              <small>
                {e.observed ? 'observado' : 'inferência'}
                {e.key && e.type !== 'implied' ? ` · ${e.key}` : ''}
                {e.version ? ` · versão ${e.version}` : ''}
                {` · ${e.confidence}%`}
              </small>
            </span>
          </li>
        ))}
      </ul>

      {det.notes.map((n, i) => (
        <p key={i} className={ui.note} data-tone="warn">
          {n}
        </p>
      ))}

      {website && (
        <p style={{ margin: '8px 0 0' }}>
          <a href={website} target="_blank" rel="noreferrer noopener">
            Site oficial <ExternalLink size={11} />
          </a>
        </p>
      )}
    </div>
  );
}

export function TechList({ technologies, reports, onShowVulns, headerHint, onCaptureHeaders }: TechListProps) {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState<CategoryId | ''>('');
  const [open, setOpen] = useState<string | null>(null);

  const presentCategories = useMemo(
    () => CATEGORY_ORDER.filter((c) => technologies.some((t) => t.categories.includes(c))),
    [technologies],
  );

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = technologies.filter(
      (t) =>
        (!category || t.categories.includes(category)) &&
        (!q || t.name.toLowerCase().includes(q) || t.version?.includes(q) || t.categories.some((c) => CATEGORY_LABELS[c].toLowerCase().includes(q))),
    );
    const map = new Map<CategoryId, Detection[]>();
    for (const t of filtered) {
      const c = category || primaryCategory(t);
      map.set(c, [...(map.get(c) ?? []), t]);
    }
    return CATEGORY_ORDER.filter((c) => map.has(c)).map((c) => [c, map.get(c)!] as const);
  }, [technologies, query, category]);

  return (
    <>
      <div className={ui.toolbar}>
        <label className={ui.search}>
          <Search size={13} aria-hidden="true" />
          <span className="sr-only">Buscar tecnologia</span>
          <input type="search" placeholder="Buscar tecnologia ou versão" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>
        <select className={ui.select} value={category} onChange={(e) => setCategory(e.target.value as CategoryId | '')} aria-label="Filtrar por categoria">
          <option value="">Todas as categorias</option>
          {presentCategories.map((c) => (
            <option key={c} value={c}>
              {CATEGORY_LABELS[c]}
            </option>
          ))}
        </select>
      </div>
      <div className={ui.scroll}>
        {groups.length === 0 && (
          <div className={ui.empty}>
            <p>{technologies.length ? 'Nenhuma tecnologia corresponde ao filtro.' : 'Nenhuma tecnologia identificada com evidência suficiente nesta página.'}</p>
            {technologies.length ? (
              <button type="button" className={ui.button} onClick={() => { setQuery(''); setCategory(''); }}>
                Limpar filtros
              </button>
            ) : null}
          </div>
        )}
        {groups.map(([cat, list]) => {
          const Icon = CATEGORY_ICON[cat];
          return (
            <section key={cat} aria-label={CATEGORY_LABELS[cat]}>
              <h3 className={ui.groupHeading}>
                {CATEGORY_LABELS[cat]} <span>{list.length}</span>
              </h3>
              {list.map((t) => {
                const expanded = open === t.id;
                const report = reports[t.id];
                const vulnCount = report?.status === 'ok' ? report.vulns.length : 0;
                return (
                  <div key={t.id}>
                    <button
                      type="button"
                      className={ui.row}
                      aria-expanded={expanded}
                      aria-controls={`tech-${t.id}`}
                      onClick={() => setOpen(expanded ? null : t.id)}
                    >
                      <span className={ui.iconBox} aria-hidden="true">
                        <Icon size={13} />
                      </span>
                      <span className={ui.rowMain}>
                        <span className={ui.rowTitle}>
                          <span>{t.name}</span>
                          {t.version && <span className={ui.version}>{t.version}</span>}
                        </span>
                        <span className={ui.rowSub}>
                          {t.inferred ? `Inferida de ${t.impliedBy?.join(', ')}` : t.categories.map((c) => CATEGORY_LABELS[c]).join(', ')}
                        </span>
                      </span>
                      <span className={ui.rowMeta}>
                        {vulnCount > 0 && (
                          <span className={ui.chip} style={{ borderColor: 'var(--sev-high)', color: 'var(--sev-high)' }} title="Vulnerabilidades potenciais">
                            {vulnCount} CVE
                          </span>
                        )}
                        {report?.status === 'pending' && <span className={ui.chip}>consultando</span>}
                        <span className={ui.confidence} data-level={t.confidenceLevel} title={`Confiança ${CONFIDENCE_LABEL[t.confidenceLevel].toLowerCase()} (${t.confidence}%)`} />
                      </span>
                      <ChevronRight size={12} className={ui.chevron} aria-hidden="true" />
                    </button>
                    {expanded && <TechDetail det={t} report={report} onShowVulns={() => onShowVulns(t.id)} />}
                  </div>
                );
              })}
            </section>
          );
        })}
        {headerHint && technologies.length > 0 && (
          <p className={ui.note} style={{ margin: '10px var(--pad) 12px' }}>
            Servidores, CDNs e WAFs são identificados principalmente por headers, que não foram observados.{' '}
            <button type="button" className={ui.linkButton} onClick={onCaptureHeaders}>
              Capturar headers
            </button>
          </p>
        )}
      </div>
    </>
  );
}

import { CircleCheck, CircleDashed, CircleX, RadioTower } from 'lucide-react';
import type { ReconData, SecurityHeaderCheck } from '../../types';
import styles from './ReconPanel.module.css';
import ui from './ui.module.css';

function HeaderState({ check }: { check: SecurityHeaderCheck }) {
  if (check.state === 'present') return <CircleCheck size={14} className={styles.present} aria-label="presente" />;
  if (check.state === 'absent') return <CircleX size={14} className={styles.absent} aria-label="ausente" />;
  return <CircleDashed size={14} className={styles.unknown} aria-label="não observado" />;
}

export function ReconPanel({ recon, onCaptureHeaders, busy }: { recon: ReconData; onCaptureHeaders: () => void; busy: boolean }) {
  const thirdParty = recon.scripts.filter((s) => s.thirdParty);
  const firstParty = recon.scripts.length - thirdParty.length;
  return (
    <div className={ui.scroll}>
      <section className={styles.section} aria-labelledby="recon-headers">
        <div className={styles.sectionHead}>
          <h3 id="recon-headers">Headers de segurança</h3>
          <button type="button" className={ui.button} onClick={onCaptureHeaders} disabled={busy} title="Faz uma única requisição GET same-origin para a URL atual e lê os headers de resposta">
            <RadioTower size={13} />
            {recon.headerSource === 'probe' ? 'Recapturar' : 'Capturar headers'}
          </button>
        </div>
        <p className={styles.caption}>
          {recon.headerSource === 'probe'
            ? `Observados em uma requisição same-origin (HTTP ${recon.headerStatus}). A resposta pode diferir da navegação original.`
            : 'Não observados: a análise é passiva. CSP e Referrer-Policy via <meta> aparecem mesmo assim.'}
        </p>
        <ul className={styles.headerList}>
          {recon.securityHeaders.map((h) => (
            <li key={h.id}>
              <HeaderState check={h} />
              <div className={styles.headerBody}>
                <span className={styles.headerName}>
                  {h.label}
                  {h.origin === 'meta' && <span className={ui.chip}>meta</span>}
                  {h.state === 'not-observed' && <span className={styles.stateText}>não observado</span>}
                  {h.state === 'absent' && <span className={styles.stateText}>ausente</span>}
                </span>
                {h.value && <span className={`${styles.headerValue} mono`}>{h.value}</span>}
                {h.notes.map((n, i) => (
                  <span key={i} className={styles.headerNote}>
                    {n}
                  </span>
                ))}
              </div>
            </li>
          ))}
        </ul>
      </section>

      {recon.notes.length > 0 && (
        <section className={styles.section} aria-label="Observações">
          {recon.notes.map((n, i) => (
            <p key={i} className={ui.note}>
              {n}
            </p>
          ))}
        </section>
      )}

      <details className={styles.section} open={recon.scripts.length > 0 && recon.scripts.length <= 12}>
        <summary>
          Scripts externos <span className={styles.count}>{recon.scripts.length}</span>
          <span className={styles.summaryMeta}>
            {firstParty} próprios, {thirdParty.length} de terceiros, {recon.inlineScriptCount} inline
          </span>
        </summary>
        <ul className={styles.scriptList}>
          {recon.scripts.map((s, i) => (
            <li key={i}>
              <span className={`${styles.url} mono`} title={s.url}>
                {s.url}
              </span>
              <span className={styles.flags}>
                <span className={ui.chip}>{s.thirdParty ? 'terceiro' : 'próprio'}</span>
                <span className={ui.chip}>{s.loading}</span>
                {s.integrity && <span className={ui.chip}>SRI</span>}
                {s.insecure && (
                  <span className={ui.chip} style={{ color: 'var(--danger)', borderColor: 'var(--danger)' }}>
                    HTTP
                  </span>
                )}
              </span>
            </li>
          ))}
        </ul>
      </details>

      <details className={styles.section}>
        <summary>
          Hosts contactados <span className={styles.count}>{recon.hosts.length}</span>
          <span className={styles.summaryMeta}>{recon.hosts.filter((h) => h.thirdParty).length} de terceiros</span>
        </summary>
        <ul className={styles.hostList}>
          {recon.hosts.map((h) => (
            <li key={h.host}>
              <span className="mono">{h.host}</span>
              <span className={styles.hostTypes}>
                {Object.entries(h.types)
                  .map(([t, n]) => `${t} ${n}`)
                  .join(', ')}
              </span>
            </li>
          ))}
        </ul>
        <p className={styles.caption}>Agrupamento próprio/terceiro por domínio registrável aproximado (heurística).</p>
      </details>

      <details className={styles.section}>
        <summary>
          Cookies legíveis por JavaScript <span className={styles.count}>{recon.cookies.length}</span>
        </summary>
        <p className={styles.caption}>
          Valores não são coletados. Cookies visíveis em document.cookie não têm HttpOnly; cookies HttpOnly e os atributos Secure/SameSite não são observáveis por extensões sem permissões adicionais.
        </p>
        <ul className={styles.hostList}>
          {recon.cookies.map((c) => (
            <li key={c.name}>
              <span className="mono">{c.name}</span>
              <span className={styles.hostTypes}>{c.valueLength} caracteres</span>
            </li>
          ))}
        </ul>
      </details>

      {recon.mixedContent.length > 0 && (
        <details className={styles.section} open>
          <summary>
            Conteúdo misto <span className={styles.count}>{recon.mixedContent.length}</span>
          </summary>
          <ul className={styles.scriptList}>
            {recon.mixedContent.map((u) => (
              <li key={u}>
                <span className={`${styles.url} mono`}>{u}</span>
              </li>
            ))}
          </ul>
        </details>
      )}

      {recon.headerSource === 'probe' && Object.keys(recon.headers).length > 0 && (
        <details className={styles.section}>
          <summary>
            Todos os headers de resposta <span className={styles.count}>{Object.keys(recon.headers).length}</span>
          </summary>
          <ul className={styles.hostList}>
            {Object.entries(recon.headers).map(([k, v]) => (
              <li key={k} className={styles.rawHeader}>
                <span className="mono">{k}</span>
                <span className={`${styles.hostTypes} mono`}>{v}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

import { ArrowLeft, CircleStop, Globe2, Loader2, Play, Trash2 } from 'lucide-react';
import { useMemo, useState } from 'react';
import { CATEGORY_LABELS } from '../../fingerprinting/signature';
import type { ScanSession } from '../../scan/types';
import { useScan, type Inventory } from '../useScan';
import styles from './ScanView.module.css';
import ui from './ui.module.css';

const RUNNING = new Set(['running', 'authorized']);

function statusLabel(s: ScanSession['status']): string {
  return { draft: 'rascunho', authorized: 'autorizado', running: 'varrendo', paused: 'pausado', done: 'concluído', aborted: 'interrompido', error: 'erro' }[s];
}

function NewScan({ onStart, defaultSeed, error }: { onStart: ReturnType<typeof useScan>['startScan']; defaultSeed: string; error: string | null }) {
  const [seed, setSeed] = useState(defaultSeed);
  const [statement, setStatement] = useState('');
  const [followSub, setFollowSub] = useState(false);
  const [maxPages, setMaxPages] = useState(100);
  const [depth, setDepth] = useState(3);
  const [rps, setRps] = useState(2);
  const [busy, setBusy] = useState(false);

  const host = useMemo(() => {
    try {
      return new URL(seed).hostname;
    } catch {
      return '';
    }
  }, [seed]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    const includeHosts = followSub && host ? [{ pattern: `*.${host}` }] : host ? [{ pattern: host }] : [];
    await onStart(host || 'Scan', [seed], { includeHosts, followSubdomains: followSub, maxPages, maxDepth: depth, requestsPerSecond: rps }, statement);
    setBusy(false);
  };

  return (
    <form className={styles.form} onSubmit={submit}>
      <label className={styles.field}>
        <span>URL inicial</span>
        <input type="url" required value={seed} onChange={(e) => setSeed(e.target.value)} placeholder="https://exemplo.com/" />
      </label>
      <label className={styles.field}>
        <span>Autorização (obrigatória)</span>
        <input type="text" required value={statement} onChange={(e) => setStatement(e.target.value)} placeholder="Ex.: Pentest ACME-2026, cliente autorizou por escrito" />
      </label>
      <p className={styles.consent}>
        Declaro que estou autorizado a varrer {host || 'este alvo'}. A extensão fará requisições GET reais ao site, na sua sessão, dentro do escopo.
      </p>
      <div className={styles.row3}>
        <label className={styles.field}>
          <span>Páginas</span>
          <input type="number" min={1} max={5000} value={maxPages} onChange={(e) => setMaxPages(Number(e.target.value))} />
        </label>
        <label className={styles.field}>
          <span>Profundidade</span>
          <input type="number" min={0} max={12} value={depth} onChange={(e) => setDepth(Number(e.target.value))} />
        </label>
        <label className={styles.field}>
          <span>Req/s</span>
          <input type="number" min={0.2} max={20} step={0.2} value={rps} onChange={(e) => setRps(Number(e.target.value))} />
        </label>
      </div>
      <label className={styles.checkbox}>
        <input type="checkbox" checked={followSub} onChange={(e) => setFollowSub(e.target.checked)} />
        Incluir subdomínios de {host || 'o host'}
      </label>
      {error && <p className={styles.error}>{error}</p>}
      <button type="submit" className={ui.buttonPrimary} disabled={busy || !host}>
        {busy ? <Loader2 size={14} className={styles.spin} /> : <Play size={14} />} Autorizar e iniciar varredura
      </button>
    </form>
  );
}

function SessionCard({ session, inventory, onOpen, onAbort, onDelete, open }: {
  session: ScanSession;
  inventory?: Inventory;
  onOpen: () => void;
  onAbort: () => void;
  onDelete: () => void;
  open: boolean;
}) {
  const running = session.status === 'running';
  const pct = session.scope.maxPages ? Math.min(100, Math.round((session.counters.fetched / session.scope.maxPages) * 100)) : 0;
  return (
    <div className={styles.card}>
      <button type="button" className={styles.cardHead} onClick={onOpen} aria-expanded={open}>
        <Globe2 size={14} />
        <span className={styles.cardTitle}>
          {session.label}
          <small>
            {statusLabel(session.status)} · {session.counters.fetched} págs · {session.counters.technologies} techs
          </small>
        </span>
        {running ? <Loader2 size={14} className={styles.spin} /> : null}
      </button>
      {running && (
        <div className={styles.progress} role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
          <span style={{ width: `${pct}%` }} />
        </div>
      )}
      <div className={styles.cardActions}>
        {running ? (
          <button type="button" className={ui.button} onClick={onAbort}>
            <CircleStop size={13} /> Interromper
          </button>
        ) : (
          <button type="button" className={ui.button} onClick={onDelete}>
            <Trash2 size={13} /> Excluir
          </button>
        )}
        {session.error && <span className={styles.error}>{session.error}</span>}
      </div>
      {open && inventory && <InventoryView inventory={inventory} />}
    </div>
  );
}

function InventoryView({ inventory }: { inventory: Inventory }) {
  const observed = inventory.technologies.filter((t) => !t.inferred);
  return (
    <div className={styles.inventory}>
      <p className={styles.invMeta}>
        {inventory.pages.length} páginas varridas · {observed.length} tecnologias observadas · {inventory.assets.filter((a) => a.thirdParty).length} hosts de terceiros
      </p>
      <ul className={styles.invList}>
        {inventory.technologies.slice(0, 60).map((t) => (
          <li key={t.id}>
            <span className={styles.invName}>
              {t.name}
              {t.version && <span className={`${styles.invVer} mono`}>{t.version}</span>}
              {t.inferred && <span className={ui.chip}>inferida</span>}
              {t.source === 'wappalyzer' && (
                <span className={ui.chip} title="Detectada pela base comunitária Wappalyzer">
                  WA
                </span>
              )}
            </span>
            <span className={styles.invCat}>
              {t.categories.map((c) => CATEGORY_LABELS[c]).join(', ')} · {t.pageCount} pág.
            </span>
          </li>
        ))}
      </ul>
      {inventory.technologies.length === 0 && <p className={styles.invMeta}>Nenhuma tecnologia agregada ainda.</p>}
    </div>
  );
}

export function ScanView({ onBack, defaultSeed }: { onBack: () => void; defaultSeed: string }) {
  const { sessions, inventories, error, startScan, abortScan, deleteScan, loadInventory } = useScan();
  const [openId, setOpenId] = useState<string | null>(null);

  const toggle = (id: string) => {
    const next = openId === id ? null : id;
    setOpenId(next);
    if (next) loadInventory(next);
  };

  return (
    <div className={ui.scroll}>
      <div className={styles.head}>
        <button type="button" className={ui.button} onClick={onBack}>
          <ArrowLeft size={13} /> Voltar
        </button>
        <h2>Varredura do site</h2>
      </div>
      <p className={styles.intro}>
        Varre o site inteiro no escopo autorizado — na sua sessão logada — e agrega tecnologias e versões de todas as páginas. Requer autorização explícita e permissão de acesso aos domínios.
      </p>
      <section className={styles.section}>
        <h3>Nova varredura</h3>
        <NewScan onStart={startScan} defaultSeed={defaultSeed} error={error} />
      </section>
      {sessions.length > 0 && (
        <section className={styles.section}>
          <h3>Varreduras ({sessions.length})</h3>
          {sessions.map((s) => (
            <SessionCard
              key={s.id}
              session={s}
              inventory={inventories[s.id]}
              open={openId === s.id}
              onOpen={() => toggle(s.id)}
              onAbort={() => abortScan(s.id)}
              onDelete={() => deleteScan(s.id)}
            />
          ))}
        </section>
      )}
      {sessions.some((s) => RUNNING.has(s.status)) && (
        <p className={styles.intro}>Mantenha o popup aberto durante a varredura; fechá-lo não cancela, mas pausa a atualização ao vivo.</p>
      )}
    </div>
  );
}

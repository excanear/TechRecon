import { ArrowLeft, Eye, EyeOff, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { clearCveCache, countCveCache } from '../../storage';
import type { Settings } from '../../types';
import styles from './SettingsView.module.css';
import ui from './ui.module.css';

interface SettingsViewProps {
  settings: Settings;
  onChange: (patch: Partial<Settings>) => Promise<void>;
  onBack: () => void;
  notify: (msg: string) => void;
}

export function SettingsView({ settings, onChange, onBack, notify }: SettingsViewProps) {
  const [apiKey, setApiKey] = useState(settings.nvdApiKey);
  const [showKey, setShowKey] = useState(false);
  const [cacheCount, setCacheCount] = useState<number | null>(null);

  useEffect(() => {
    countCveCache().then(setCacheCount).catch(() => setCacheCount(null));
  }, []);

  const saveKey = async () => {
    await onChange({ nvdApiKey: apiKey });
    notify(apiKey ? 'Chave do NVD salva' : 'Chave do NVD removida');
  };

  const clearCache = async () => {
    const n = await clearCveCache();
    setCacheCount(0);
    notify(`Cache limpo (${n} consulta${n === 1 ? '' : 's'})`);
  };

  return (
    <div className={ui.scroll}>
      <div className={styles.head}>
        <button type="button" className={ui.button} onClick={onBack}>
          <ArrowLeft size={13} /> Voltar
        </button>
        <h2>Opções</h2>
      </div>

      <section className={styles.group}>
        <label className={styles.toggle}>
          <input type="checkbox" checked={settings.cveLookup} onChange={(e) => onChange({ cveLookup: e.target.checked })} />
          <span>
            Consultar vulnerabilidades
            <small>Envia apenas nome do produto e versão detectada ao NVD (NIST) e ao OSV. Nenhum dado da página é enviado.</small>
          </span>
        </label>
        <label className={styles.toggle}>
          <input type="checkbox" checked={settings.autoHeaderProbe} onChange={(e) => onChange({ autoHeaderProbe: e.target.checked })} />
          <span>
            Capturar headers automaticamente
            <small>Cada análise fará uma requisição GET same-origin extra para a URL da aba (equivale a recarregar a página). Desligado = totalmente passivo.</small>
          </span>
        </label>
      </section>

      <section className={styles.group}>
        <label htmlFor="nvd-key" className={styles.label}>
          Chave de API do NVD <small>opcional</small>
        </label>
        <div className={styles.keyRow}>
          <input
            id="nvd-key"
            className={styles.input}
            type={showKey ? 'text' : 'password'}
            value={apiKey}
            autoComplete="off"
            spellCheck={false}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            onChange={(e) => setApiKey(e.target.value)}
          />
          <button type="button" className={ui.button} onClick={() => setShowKey((v) => !v)} aria-label={showKey ? 'Ocultar chave' : 'Mostrar chave'}>
            {showKey ? <EyeOff size={13} /> : <Eye size={13} />}
          </button>
          <button type="button" className={ui.buttonPrimary} onClick={saveKey} disabled={apiKey === settings.nvdApiKey}>
            Salvar
          </button>
        </div>
        <p className={styles.help}>
          Sem chave, o NVD permite cerca de 5 consultas a cada 30 s, e a extensão espaça as consultas automaticamente. Com chave, o limite sobe para 50. Solicite em{' '}
          <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noreferrer noopener">
            nvd.nist.gov
          </a>
          . A chave fica apenas neste navegador (chrome.storage.local).
        </p>
      </section>

      <section className={styles.group}>
        <label htmlFor="ttl" className={styles.label}>
          Validade do cache de CVEs
        </label>
        <div className={styles.keyRow}>
          <select id="ttl" className={ui.select} value={settings.cacheTtlHours} onChange={(e) => onChange({ cacheTtlHours: Number(e.target.value) })}>
            {[1, 6, 12, 24, 72, 168].map((h) => (
              <option key={h} value={h}>
                {h < 24 ? `${h} h` : `${h / 24} dia${h === 24 ? '' : 's'}`}
              </option>
            ))}
          </select>
          <button type="button" className={ui.button} onClick={clearCache} disabled={cacheCount === 0}>
            <Trash2 size={13} /> Limpar cache{cacheCount !== null ? ` (${cacheCount})` : ''}
          </button>
        </div>
      </section>

      <section className={styles.group}>
        <span className={styles.label}>Tema</span>
        <div className={ui.filters} role="group" aria-label="Tema">
          {(['dark', 'light'] as const).map((t) => (
            <button key={t} type="button" className={ui.filter} aria-pressed={settings.theme === t} onClick={() => onChange({ theme: t })}>
              {t === 'dark' ? 'Escuro' : 'Claro'}
            </button>
          ))}
        </div>
      </section>

      <p className={styles.footer}>
        TechRecon {chrome.runtime.getManifest().version}. Análise passiva: nenhuma requisição é feita ao alvo sem a sua ação, e resultados não são enviados a terceiros.
      </p>
    </div>
  );
}

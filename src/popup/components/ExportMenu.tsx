import { Download } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import headerStyles from './Header.module.css';
import styles from './ExportMenu.module.css';

export type ExportAction = 'copy-md' | 'copy-json' | 'download-md' | 'download-json';

const ITEMS: Array<[ExportAction, string]> = [
  ['copy-md', 'Copiar como Markdown'],
  ['copy-json', 'Copiar como JSON'],
  ['download-md', 'Baixar Markdown (.md)'],
  ['download-json', 'Baixar JSON (.json)'],
];

export function ExportMenu({ disabled, onAction }: { disabled: boolean; onAction: (a: ExportAction) => void }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    rootRef.current?.querySelector<HTMLButtonElement>('[role="menuitem"]')?.focus();
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      setOpen(false);
      rootRef.current?.querySelector<HTMLButtonElement>('[aria-haspopup]')?.focus();
      return;
    }
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    e.preventDefault();
    const items = [...(rootRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [])];
    const i = items.indexOf(document.activeElement as HTMLButtonElement);
    items[(i + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length]?.focus();
  };

  return (
    <div className={styles.root} ref={rootRef} onKeyDown={onKeyDown}>
      <button
        type="button"
        className={headerStyles.iconButton}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Exportar resultados"
        title="Exportar resultados"
        disabled={disabled}
        onClick={() => setOpen((v) => !v)}
      >
        <Download size={15} />
      </button>
      {open && (
        <div className={styles.menu} role="menu">
          {ITEMS.map(([id, label]) => (
            <button
              key={id}
              type="button"
              role="menuitem"
              className={styles.item}
              onClick={() => {
                setOpen(false);
                onAction(id);
              }}
            >
              {label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

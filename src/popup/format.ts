import type { ConfidenceLevel, EvidenceType, Severity, VulnReportStatus } from '../types';

export const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: 'Crítica',
  HIGH: 'Alta',
  MEDIUM: 'Média',
  LOW: 'Baixa',
  NONE: 'Nenhuma',
  UNKNOWN: 'Sem score',
};

export const SEVERITY_VAR: Record<Severity, string> = {
  CRITICAL: 'var(--sev-critical)',
  HIGH: 'var(--sev-high)',
  MEDIUM: 'var(--sev-medium)',
  LOW: 'var(--sev-low)',
  NONE: 'var(--sev-none)',
  UNKNOWN: 'var(--sev-none)',
};

export const CONFIDENCE_LABEL: Record<ConfidenceLevel, string> = { high: 'Alta', medium: 'Média', low: 'Baixa' };

export const EVIDENCE_LABEL: Record<EvidenceType, string> = {
  html: 'HTML',
  scriptSrc: 'Script',
  script: 'Script inline',
  stylesheet: 'Stylesheet',
  meta: 'Meta tag',
  header: 'Header',
  cookie: 'Cookie',
  global: 'Variável JS',
  dom: 'DOM',
  url: 'URL',
  resource: 'Recurso',
  implied: 'Inferência',
};

export const REPORT_STATUS_LABEL: Record<VulnReportStatus, string> = {
  pending: 'Consultando…',
  ok: 'Consultado',
  'no-version': 'Sem versão',
  'version-uncertain': 'Versão incerta',
  unmapped: 'Sem fonte',
  disabled: 'Desativado',
  error: 'Falha na consulta',
};

export function formatTime(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
}

export function formatDate(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString('pt-BR');
}

export function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

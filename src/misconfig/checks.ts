// Passive configuration checks over a page the crawler already fetched. Nothing here makes a
// request: every finding is derived from the response headers and the parsed document that the
// crawl obtained anyway. Absence is only reported when the headers were actually observed.

import type { FetchedPage } from '../crawler/types';
import { cspNotes, hstsNotes, siteOf } from '../recon';
import { redactUrl } from '../shared/redact';
import { sanitizeText } from '../shared/sanitize';

export type MisconfigSeverity = 'high' | 'medium' | 'low' | 'info';

export type MisconfigCheckId =
  | 'http-page'
  | 'hsts-missing'
  | 'hsts-weak'
  | 'csp-missing'
  | 'csp-weak'
  | 'nosniff-missing'
  | 'framing-unprotected'
  | 'version-disclosure'
  | 'cors-wildcard-credentials'
  | 'cors-wildcard'
  | 'mixed-content-script'
  | 'mixed-content-style'
  | 'sri-missing';

export interface MisconfigObservation {
  check: MisconfigCheckId;
  severity: MisconfigSeverity;
  title: string;
  /** Why it matters / what was seen. */
  detail: string;
  /** Short, redacted evidence (header value, resource URL). */
  evidence?: string;
}

export const SEVERITY_ORDER: Record<MisconfigSeverity, number> = { high: 3, medium: 2, low: 1, info: 0 };

const EVIDENCE_MAX = 200;
const MAX_RESOURCES = 5;

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

function isHttp(url: string): boolean {
  return url.toLowerCase().startsWith('http:');
}

/** All checks for one crawled HTML page. Skipped/failed pages yield nothing. */
export function checkPage(page: FetchedPage): MisconfigObservation[] {
  if (page.skippedReason || !page.ok) return [];
  const out: MisconfigObservation[] = [];
  const h = page.headers;
  const https = page.finalUrl.toLowerCase().startsWith('https:');
  const ev = (value: string) => sanitizeText(value, EVIDENCE_MAX);

  if (!https) {
    out.push({
      check: 'http-page',
      severity: 'medium',
      title: 'Página servida sem HTTPS',
      detail: 'O conteúdo e os cookies desta página trafegam sem criptografia.',
      evidence: redactUrl(page.finalUrl),
    });
  }

  // Transport security only applies to HTTPS responses.
  if (https) {
    const hsts = h['strict-transport-security'];
    if (hsts === undefined) {
      out.push({ check: 'hsts-missing', severity: 'medium', title: 'HSTS ausente', detail: 'Sem Strict-Transport-Security, o primeiro acesso pode ser rebaixado para HTTP.' });
    } else {
      const notes = hstsNotes(hsts).filter((n) => !n.startsWith('Marcado para preload'));
      if (notes.length) out.push({ check: 'hsts-weak', severity: 'low', title: 'HSTS fraco', detail: notes.join(' '), evidence: ev(hsts) });
    }
  }

  const csp = h['content-security-policy'] ?? page.snapshot.meta['content-security-policy']?.[0];
  if (csp === undefined) {
    out.push({ check: 'csp-missing', severity: 'medium', title: 'CSP ausente', detail: 'Sem Content-Security-Policy, não há mitigação de XSS no navegador.' });
  } else {
    const notes = cspNotes(csp).filter((n) => !n.startsWith('frame-ancestors'));
    if (notes.length) out.push({ check: 'csp-weak', severity: 'low', title: 'CSP permissiva', detail: notes.join(' '), evidence: ev(csp) });
  }

  if ((h['x-content-type-options'] ?? '').toLowerCase().trim() !== 'nosniff') {
    out.push({ check: 'nosniff-missing', severity: 'low', title: 'X-Content-Type-Options ausente', detail: 'Sem "nosniff", o navegador pode reinterpretar o tipo de conteúdo.' });
  }

  // frame-ancestors only counts when delivered as a header (it is ignored in a meta tag).
  const headerCsp = h['content-security-policy'] ?? '';
  if (h['x-frame-options'] === undefined && !/(^|;)\s*frame-ancestors\s/i.test(headerCsp)) {
    out.push({ check: 'framing-unprotected', severity: 'low', title: 'Sem proteção contra framing', detail: 'Nem X-Frame-Options nem CSP frame-ancestors: a página pode ser embutida (clickjacking).' });
  }

  for (const name of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
    const value = h[name];
    if (value && /\d+\.\d+/.test(value)) {
      out.push({ check: 'version-disclosure', severity: 'info', title: 'Versão divulgada em header', detail: `O header ${name} expõe a versão do software.`, evidence: ev(`${name}: ${value}`) });
    }
  }

  const acao = h['access-control-allow-origin'];
  if (acao?.trim() === '*') {
    const credentials = (h['access-control-allow-credentials'] ?? '').trim().toLowerCase() === 'true';
    out.push(
      credentials
        ? {
            check: 'cors-wildcard-credentials',
            severity: 'medium',
            title: 'CORS curinga com credenciais',
            detail: 'Access-Control-Allow-Origin: * junto de Allow-Credentials: true indica configuração de CORS incoerente (o navegador recusa a combinação, mas ela costuma vir de reflexo de origem mal configurado).',
            evidence: 'access-control-allow-origin: * · access-control-allow-credentials: true',
          }
        : {
            check: 'cors-wildcard',
            severity: 'info',
            title: 'CORS aberto (*)',
            detail: 'Qualquer origem pode ler esta resposta sem credenciais. Adequado para conteúdo público; revise se a página tiver dados do usuário.',
            evidence: 'access-control-allow-origin: *',
          },
    );
  }

  if (https) {
    const httpScripts = page.snapshot.scriptSrcs.filter(isHttp);
    if (httpScripts.length) {
      out.push({
        check: 'mixed-content-script',
        severity: 'high',
        title: 'Script carregado via HTTP em página HTTPS',
        detail: `${httpScripts.length} script(s) sem criptografia; navegadores modernos bloqueiam, e onde não bloqueiam o script pode ser adulterado em trânsito.`,
        evidence: httpScripts.slice(0, MAX_RESOURCES).map(redactUrl).join(' · '),
      });
    }
    const httpStyles = page.snapshot.stylesheets.filter(isHttp);
    if (httpStyles.length) {
      out.push({
        check: 'mixed-content-style',
        severity: 'medium',
        title: 'CSS carregado via HTTP em página HTTPS',
        detail: `${httpStyles.length} folha(s) de estilo sem criptografia.`,
        evidence: httpStyles.slice(0, MAX_RESOURCES).map(redactUrl).join(' · '),
      });
    }
  }

  const pageSite = siteOf(hostOf(page.finalUrl));
  const thirdParty = (page.scriptsWithoutIntegrity ?? []).filter((u) => {
    const host = hostOf(u);
    return host !== '' && siteOf(host) !== pageSite;
  });
  if (thirdParty.length) {
    out.push({
      check: 'sri-missing',
      severity: 'low',
      title: 'Scripts de terceiros sem SRI',
      detail: `${thirdParty.length} script(s) de outro domínio sem atributo integrity: se o fornecedor for comprometido, o código alterado roda no site.`,
      evidence: thirdParty.slice(0, MAX_RESOURCES).map(redactUrl).join(' · '),
    });
  }

  return out;
}

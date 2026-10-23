// Pages where Chrome does not allow extensions to run scripts, detected up front so the popup
// can explain the situation instead of failing.

const BLOCKED_HOSTS = ['chromewebstore.google.com', 'chrome.google.com', 'microsoftedge.microsoft.com'];

export function checkUrlSupport(url: string): { ok: true } | { ok: false; reason: string } {
  if (!url) return { ok: false, reason: 'Não foi possível ler a URL desta aba.' };
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, reason: 'URL inválida.' };
  }
  if (parsed.protocol === 'file:') {
    return { ok: false, reason: 'Arquivos locais (file://) não são analisados.' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, reason: `Páginas ${parsed.protocol}// são internas do navegador e não podem ser analisadas por extensões.` };
  }
  if (BLOCKED_HOSTS.includes(parsed.hostname) && (parsed.hostname !== 'chrome.google.com' || parsed.pathname.startsWith('/webstore'))) {
    return { ok: false, reason: 'Lojas de extensões são protegidas pelo navegador e não podem ser analisadas.' };
  }
  return { ok: true };
}

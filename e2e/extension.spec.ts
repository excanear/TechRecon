import { chromium, expect, test, type BrowserContext, type Worker } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { startServer } from './server';

// End-to-end: loads dist/ as an unpacked extension in Playwright's Chromium and drives the real
// popup against a local page. CVE lookups go to the live NVD and OSV APIs (network required).

const dist = fileURLToPath(new URL('../dist', import.meta.url));

let context: BrowserContext;
let worker: Worker;
let extensionId: string;
let site: Awaited<ReturnType<typeof startServer>>;

test.beforeAll(async () => {
  const manifest = JSON.parse(readFileSync(`${dist}/manifest.json`, 'utf8'));
  if (!manifest.host_permissions.includes('http://127.0.0.1/*')) {
    throw new Error('Build with TECHRECON_E2E=1 (npm run e2e) so the test page can be scripted without clicking the toolbar.');
  }
  site = await startServer();
  context = await chromium.launchPersistentContext('', {
    channel: 'chromium',
    headless: true,
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`],
    acceptDownloads: true,
  });
  worker = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'));
  extensionId = new URL(worker.url()).host;
});

test.afterAll(async () => {
  await context?.close();
  site?.server.close();
});

async function tabIdFor(url: string): Promise<number> {
  return worker.evaluate(async (u) => {
    const tabs = await chrome.tabs.query({});
    const tab = tabs.find((t) => t.url?.startsWith(u));
    if (!tab?.id) throw new Error(`tab not found for ${u}`);
    return tab.id;
  }, url);
}

test('analyzes a page end to end: fingerprinting, CVEs, recon, export', async () => {
  const target = await context.newPage();
  await target.goto(site.url);
  const tabId = await tabIdFor(site.url);
  const requestsBefore = site.requests.length;

  const popup = await context.newPage();
  await popup.setViewportSize({ width: 400, height: 580 });
  await popup.goto(`chrome-extension://${extensionId}/popup.html?tabId=${tabId}`);

  // Header and technologies (passive: headers not observed yet).
  await expect(popup.getByText('127.0.0.1', { exact: true })).toBeVisible();
  await expect(popup.getByRole('button', { name: /WordPress\s*6\.4\.2/ })).toBeVisible();
  await expect(popup.getByRole('button', { name: /jQuery\s*3\.4\.1/ })).toBeVisible();
  await expect(popup.getByRole('button', { name: /Google Analytics/ })).toBeVisible();
  await expect(popup.getByRole('button', { name: /^PHP/ })).toContainText('Inferida de WordPress');
  expect(site.requests.length, 'passive analysis must not request the target').toBe(requestsBefore);

  // Expand a technology: version, confidence and evidence.
  await popup.getByRole('button', { name: /jQuery\s*3\.4\.1/ }).click();
  const detail = popup.locator('#tech-jquery');
  await expect(detail).toContainText('jQuery.fn.jquery');
  await expect(detail).toContainText('100%');

  // Search filter.
  const search = popup.getByPlaceholder('Buscar tecnologia ou versão');
  await search.fill('jquery');
  await expect(popup.getByRole('button', { name: /WordPress/ })).toHaveCount(0);
  await search.fill('');

  // Correlation via live OSV/NVD: wait until it finishes.
  await expect(popup.getByRole('status').first()).toContainText('Analisado às', { timeout: 120_000 });
  await popup.screenshot({ path: 'test-results/popup-technologies.png' });
  await popup.getByRole('tab', { name: /Vulnerabilidades/ }).click();
  const panel = popup.getByRole('tabpanel');
  if (await panel.getByRole('alert').count()) console.warn('Some live queries failed:', await panel.getByRole('alert').innerText());
  await expect(panel.getByRole('button', { name: /CVE-2020-11022/ })).toBeVisible();
  // Exploitation intelligence (live CISA KEV + EPSS): CVE-2020-11023 is in KEV, and a KEV entry
  // ranks first (which KEV entry depends on live data, e.g. a newer WordPress CVE).
  const partial = panel.getByText(/Inteligência de exploração parcial/);
  if (await partial.count()) console.warn(await partial.innerText());
  const kevRow = panel.getByRole('button', { name: /CVE-2020-11023/ }).first();
  await expect(kevRow).toContainText('KEV');
  await expect(kevRow).toContainText(/EPSS \d/);
  await expect(panel.getByRole('button', { name: /CVE-\d{4}-\d+/ }).first()).toContainText('KEV');
  await expect(popup.getByText(/^\d+ no CISA KEV$/)).toBeVisible();
  await popup.screenshot({ path: 'test-results/popup-vulnerabilities.png' });

  // Expand and confirm a finding (analyst action): status changes from potential to confirmed.
  await panel.getByRole('button', { name: /CVE-2020-11022/ }).first().click();
  const vulnDetail = panel.locator('[id="vuln-CVE-2020-11022"]').first();
  await expect(vulnDetail).toContainText('3.5.0');
  await expect(vulnDetail.locator('a').first()).toHaveAttribute('href', /^https:\/\/(osv\.dev|nvd\.nist\.gov)\//);
  await panel.getByRole('button', { name: 'Marcar como confirmada' }).click();
  await expect(panel.getByRole('button', { name: /CVE-2020-11022/ }).first()).toContainText('Confirmada');

  const exportVia = async (item: RegExp) => {
    const [download] = await Promise.all([
      popup.waitForEvent('download'),
      (async () => {
        await popup.getByRole('button', { name: 'Exportar resultados' }).click();
        await popup.getByRole('menuitem', { name: item }).click();
      })(),
    ]);
    return readFileSync((await download.path())!, 'utf8');
  };

  const report = JSON.parse(await exportVia(/Baixar JSON/));
  expect(report.target.domain).toBe('127.0.0.1');
  expect(report.technologies.map((t: { name: string }) => t.name)).toEqual(expect.arrayContaining(['WordPress', 'jQuery']));
  const cve = report.vulnerabilities.find((v: { id: string }) => v.id === 'CVE-2020-11022');
  expect(cve.status).toBe('confirmed-by-analyst');
  expect(cve.sourceUrl).toMatch(/^https:\/\//);
  expect(cve.epss.score).toBeGreaterThan(0);
  const exploited = report.vulnerabilities.find((v: { id: string }) => v.id === 'CVE-2020-11023');
  expect(exploited).toMatchObject({ priority: 'kev', kev: { dateAdded: '2025-01-23' } });
  expect(report.summary.knownExploited).toBeGreaterThanOrEqual(1);

  const md = await exportVia(/Baixar Markdown/);
  expect(md).toContain('# TechRecon — 127.0.0.1');
  expect(md).toContain('CVE-2020-11022');
  expect(md).toContain('CISA KEV: exploração ativa confirmada');

  // Recon: meta CSP observed passively, cookie listed without its value.
  await popup.getByRole('tab', { name: 'Recon' }).click();
  await expect(panel).toContainText('Content-Security-Policy');
  await expect(panel).toContainText('unsafe-inline');
  await panel.getByText('Cookies legíveis por JavaScript').click();
  await expect(panel).toContainText('_ga');
  await expect(panel).not.toContainText('GA1.1.123456');

  // Opt-in header capture: exactly one extra GET, then server/language detections.
  await panel.getByRole('button', { name: 'Capturar headers' }).click();
  await expect(popup.getByRole('status').first()).toContainText('headers observados', { timeout: 60_000 });
  const pageRequests = site.requests.slice(requestsBefore).filter((r) => r === 'GET /');
  expect(pageRequests).toHaveLength(1);
  await popup.getByRole('tab', { name: /Tecnologias/ }).click();
  await expect(popup.getByRole('button', { name: /Nginx\s*1\.18\.0/ })).toBeVisible();
  await expect(popup.getByRole('button', { name: /PHP\s*7\.4\.3/ })).toBeVisible();
  await popup.getByRole('tab', { name: 'Recon' }).click();
  await expect(panel).toContainText('X-Content-Type-Options');
  await expect(panel).toContainText('server divulga versão');
  await popup.screenshot({ path: 'test-results/popup-recon.png' });
});

test('explains unsupported pages', async () => {
  const blank = await context.newPage();
  await blank.goto('data:text/html,<p>internal</p>');
  await blank.bringToFront();
  // Without the "tabs" permission Chrome hides URLs of tabs the extension has no access to,
  // so the tab is located as the active one.
  const tabId = await worker.evaluate(async () => (await chrome.tabs.query({ active: true }))[0]?.id ?? -1);
  expect(tabId).toBeGreaterThan(0);
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup.html?tabId=${tabId}`);
  await expect(popup.getByRole('heading', { name: 'Esta página não pode ser analisada' })).toBeVisible();
  await expect(popup.getByRole('button', { name: 'Exportar resultados' })).toBeDisabled();
});

test('settings persist and the cache can be cleared', async () => {
  const target = await context.newPage();
  await target.goto(site.url);
  const popup = await context.newPage();
  await popup.setViewportSize({ width: 400, height: 580 });
  await popup.goto(`chrome-extension://${extensionId}/popup.html?tabId=${await tabIdFor(site.url)}`);
  await popup.getByRole('button', { name: 'Opções' }).click();
  await popup.getByLabel(/Capturar headers automaticamente/).check();
  await popup.getByRole('button', { name: 'Claro' }).click();
  await expect(popup.locator('html')).toHaveAttribute('data-theme', 'light');
  await popup.getByRole('button', { name: /Limpar cache/ }).click();
  await expect(popup.getByRole('status').last()).toContainText('Cache limpo');
  await popup.screenshot({ path: 'test-results/popup-settings.png' });
  const stored = await worker.evaluate(async () => (await chrome.storage.local.get('settings')).settings);
  expect(stored).toMatchObject({ autoHeaderProbe: true, theme: 'light' });
});

import { chromium, expect, test, type BrowserContext, type Worker } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { startServer } from './server';

// End-to-end for the whole crawl path: real offscreen document (fetch + DOMParser), BFS over a
// multi-page local site, site-wide aggregation, persisted inventory, all driven from the popup.

const dist = fileURLToPath(new URL('../dist', import.meta.url));

let context: BrowserContext;
let worker: Worker;
let extensionId: string;
let site: Awaited<ReturnType<typeof startServer>>;

test.beforeAll(async () => {
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

test('crawls a whole site, aggregates technologies and never follows destructive links', async () => {
  const popup = await context.newPage();
  await popup.setViewportSize({ width: 400, height: 580 });
  await popup.goto(`chrome-extension://${extensionId}/popup.html`);

  // Open the scan view.
  await popup.getByRole('button', { name: 'Varredura do site' }).click();
  await popup.getByLabel('URL inicial').fill(site.url);
  await popup.getByLabel(/Autorização/).fill('Teste automatizado, alvo local autorizado.');
  await popup.getByRole('button', { name: /Autorizar e iniciar/ }).click();

  // The crawl finishes: the session card shows "concluído".
  // Crawl, then the CVE phase over the inventory (live NVD/OSV, throttled), then "concluído".
  test.setTimeout(300_000);
  const card = popup.locator('text=concluído').first();
  await expect(card).toBeVisible({ timeout: 240_000 });

  // Open the inventory.
  await popup.getByRole('button', { name: /varrendo|concluído/ }).first().click();
  const techs = popup.getByRole('list', { name: 'Tecnologias do site' });
  await expect(techs.getByText('WordPress', { exact: true })).toBeVisible();
  await expect(techs.getByText('jQuery', { exact: true })).toBeVisible();
  await expect(techs.getByText('Nginx', { exact: true })).toBeVisible();

  // It visited several linked pages but NEVER /logout.
  const fetchedPaths = site.requests.filter((r) => r.startsWith('GET ')).map((r) => r.slice(4).split('?')[0]);
  expect(fetchedPaths).toContain('/about');
  expect(fetchedPaths).toContain('/products/widget');
  expect(fetchedPaths, 'crawler must never follow /logout').not.toContain('/logout');

  await popup.screenshot({ path: 'test-results/popup-scan.png' });

  // Inventory reports a page count greater than one (whole-site aggregation).
  await expect(popup.getByText(/páginas varridas/)).toBeVisible();

  // Site-wide CVE correlation: deduped, enriched with KEV/EPSS, KEV first.
  const vulns = popup.getByRole('region', { name: 'Vulnerabilidades do site' });
  await expect(vulns).toContainText('Vulnerabilidades priorizadas');
  if (await vulns.getByRole('alert').count()) console.warn('Live queries failed:', await vulns.getByRole('alert').innerText());
  await expect(vulns.getByText('CVE-2020-11023')).toBeVisible();
  await expect(vulns.locator('li').first()).toContainText('KEV');
  await expect(popup.getByText(/· \d+ KEV/)).toBeVisible();
  await vulns.scrollIntoViewIfNeeded();
  await vulns.screenshot({ path: 'test-results/popup-scan-vulns.png' });

  // Passive configuration findings, derived from responses the crawl already had.
  const config = popup.getByRole('region', { name: 'Configuração do site' });
  const findings = config.getByRole('list', { name: 'Achados de configuração' });
  await expect(findings).toContainText('Página servida sem HTTPS');
  await expect(findings).toContainText('server: nginx/1.18.0 (Ubuntu)');
  await expect(findings).toContainText('x-powered-by: PHP/7.4.3');
  await expect(findings).toContainText('Sem proteção contra framing');
  await expect(findings).toContainText("'unsafe-inline'");
  await expect(findings).not.toContainText('X-Content-Type-Options ausente');
  await config.scrollIntoViewIfNeeded();
  await config.screenshot({ path: 'test-results/popup-scan-config.png' });

  // The checks add no requests: everything fetched is a page linked by the site or an asset it references.
  const linked = new Set(['/', '/about', '/team', '/products', '/products/widget', '/contact']);
  const unexpected = site.requests
    .map((r) => r.replace(/^GET /, '').split('?')[0]!)
    .filter((p) => !linked.has(p) && !p.startsWith('/wp-includes/'));
  expect(unexpected, 'no path outside the crawl may be requested').toEqual([]);

  // Full-tab dashboard, opened from the session card.
  const [dashboard] = await Promise.all([context.waitForEvent('page'), popup.getByRole('button', { name: 'Abrir painel' }).click()]);
  await dashboard.setViewportSize({ width: 1280, height: 900 });
  await expect(dashboard).toHaveURL(/dashboard\.html\?session=/);
  await expect(dashboard.getByRole('heading', { name: '127.0.0.1' })).toBeVisible();
  await expect(dashboard.getByText('Autorização registrada: “Teste automatizado, alvo local autorizado.”')).toBeVisible();
  const vulnTable = dashboard.getByRole('table', { name: 'Vulnerabilidades' });
  await expect(vulnTable.locator('tbody tr').first()).toContainText('KEV');
  await dashboard.screenshot({ path: 'test-results/dashboard-vulns.png' });

  // KEV filter keeps only exploited CVEs; expanding a row shows the KEV detail.
  const total = await vulnTable.locator('tbody tr').count();
  await dashboard.getByLabel('Somente CISA KEV').check();
  const kevRows = vulnTable.locator('tbody tr');
  expect(await kevRows.count()).toBeLessThan(total);
  for (const row of await kevRows.all()) await expect(row).toContainText('KEV');
  await vulnTable.getByText('CVE-2020-11023').click();
  await expect(vulnTable).toContainText('Exploração ativa confirmada');

  // Other tabs.
  await dashboard.getByRole('tab', { name: /Configuração/ }).click();
  await expect(dashboard.getByRole('table', { name: 'Achados de configuração' })).toContainText('Página servida sem HTTPS');
  await dashboard.getByRole('tab', { name: /Tecnologias/ }).click();
  await expect(dashboard.getByRole('table', { name: 'Tecnologias' })).toContainText('jQuery');
  await dashboard.getByRole('tab', { name: /Páginas/ }).click();
  await expect(dashboard.getByRole('table', { name: 'Páginas varridas' })).toContainText('/products/widget');
  expect(await dashboard.getByRole('table', { name: 'Páginas varridas' }).textContent()).not.toContain('/logout');

  // Exports: a static HTML report and a CSV, from the real session data.
  const save = async (name: RegExp) => {
    const [file] = await Promise.all([dashboard.waitForEvent('download'), dashboard.getByRole('button', { name }).click()]);
    return { name: file.suggestedFilename(), body: readFileSync((await file.path())!, 'utf8') };
  };
  const html = await save(/Relatório HTML/);
  expect(html.name).toMatch(/^techrecon-scan-127\.0\.0\.1-.*\.html$/);
  expect(html.body).not.toMatch(/<script/i);
  expect(html.body).toContain('CVE-2020-11023');
  expect(html.body).toContain('Teste automatizado, alvo local autorizado.');
  const csvFile = await save(/CSV Vulnerabilidades/);
  expect(csvFile.body.startsWith('﻿prioridade,id,')).toBe(true);
  expect(csvFile.body).toContain('CVE-2020-11023');
  const json = JSON.parse((await save(/^JSON$/)).body);
  expect(json.schema).toBe('techrecon.scan-report/v1');
  expect(json.summary.pagesFetched).toBeGreaterThan(1);

  // The exported HTML renders standalone.
  const report = await context.newPage();
  await report.setContent(html.body);
  await expect(report.getByRole('heading', { level: 1 })).toContainText('TechRecon — varredura 127.0.0.1');
  await report.screenshot({ path: 'test-results/scan-report-html.png', fullPage: true });
});

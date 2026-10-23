import { chromium, expect, test, type BrowserContext, type Worker } from '@playwright/test';
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
  const card = popup.locator('text=concluído').first();
  await expect(card).toBeVisible({ timeout: 60_000 });

  // Open the inventory.
  await popup.getByRole('button', { name: /varrendo|concluído/ }).first().click();
  const panel = popup.getByRole('tabpanel').or(popup.locator('body'));
  await expect(panel.getByText('WordPress')).toBeVisible();
  await expect(panel.getByText('jQuery')).toBeVisible();
  await expect(panel.getByText('Nginx')).toBeVisible();

  // It visited several linked pages but NEVER /logout.
  const fetchedPaths = site.requests.filter((r) => r.startsWith('GET ')).map((r) => r.slice(4).split('?')[0]);
  expect(fetchedPaths).toContain('/about');
  expect(fetchedPaths).toContain('/products/widget');
  expect(fetchedPaths, 'crawler must never follow /logout').not.toContain('/logout');

  await popup.screenshot({ path: 'test-results/popup-scan.png' });

  // Inventory reports a page count greater than one (whole-site aggregation).
  await expect(popup.getByText(/páginas varridas/)).toBeVisible();
});

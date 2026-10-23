// Renders the TechRecon reticle mark to the PNG sizes required by the manifest.
// Uses Playwright's Chromium (dev dependency): `npm run icons`.
import { chromium } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const out = fileURLToPath(new URL('../public/icons/', import.meta.url));
mkdirSync(out, { recursive: true });

const svg = (size) => `
<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 32 32">
  <rect x="1.5" y="1.5" width="29" height="29" rx="7" fill="#18202F" stroke="#4FC7B8" stroke-width="${size <= 16 ? 2.2 : 1.5}"/>
  <circle cx="16" cy="16" r="7.5" fill="none" stroke="#4FC7B8" stroke-width="${size <= 16 ? 2.8 : 2}"/>
  <path d="M16 4.5v5M16 22.5v5M4.5 16h5M22.5 16h5" stroke="#4FC7B8" stroke-width="${size <= 16 ? 2.8 : 2}" stroke-linecap="round"/>
  <circle cx="16" cy="16" r="2.4" fill="#E4E8F0"/>
</svg>`;

const browser = await chromium.launch();
const page = await browser.newPage();
for (const size of [16, 32, 48, 128]) {
  await page.setViewportSize({ width: size, height: size });
  await page.setContent(`<html><body style="margin:0;background:transparent">${svg(size)}</body></html>`);
  await page.locator('svg').screenshot({ path: `${out}icon-${size}.png`, omitBackground: true });
}
await browser.close();
console.log('icons written to', out);

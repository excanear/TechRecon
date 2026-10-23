import { defineConfig } from 'vite';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));

// The page collector is injected with chrome.scripting.executeScript({ files }),
// which requires a classic, self-contained script: build it separately as an IIFE.
export default defineConfig({
  publicDir: false,
  build: {
    outDir: resolve(here, 'dist'),
    emptyOutDir: false,
    target: 'es2022',
    lib: {
      entry: resolve(here, 'src/content/collector.ts'),
      formats: ['iife'],
      name: 'TechReconCollector',
      fileName: () => 'content.js',
    },
  },
});

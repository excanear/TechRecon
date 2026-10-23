import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
import { readFileSync, writeFileSync } from 'node:fs';

const root = resolve(here, 'src/popup');
const outDir = resolve(here, 'dist');

/** Writes dist/manifest.json from public/manifest.json (adds broad host access only for the e2e build). */
function manifestPlugin() {
  return {
    name: 'techrecon-manifest',
    writeBundle() {
      const manifest = JSON.parse(readFileSync(resolve(here, 'src/manifest.json'), 'utf8'));
      const pkg = JSON.parse(readFileSync(resolve(here, 'package.json'), 'utf8'));
      manifest.version = pkg.version;
      if (process.env.TECHRECON_E2E === '1') {
        // Automated tests cannot click the toolbar icon to grant activeTab.
        manifest.host_permissions = [...(manifest.host_permissions ?? []), 'http://127.0.0.1/*', 'http://localhost/*'];
      }
      writeFileSync(resolve(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2));
    },
  };
}

export default defineConfig({
  root,
  base: '',
  publicDir: resolve(here, 'public'),
  plugins: [react(), manifestPlugin()],
  build: {
    outDir,
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
    modulePreload: false,
    rollupOptions: {
      input: {
        popup: resolve(root, 'popup.html'),
        background: resolve(here, 'src/background/index.ts'),
      },
      output: {
        entryFileNames: (chunk) => (chunk.name === 'background' ? 'background.js' : 'assets/[name]-[hash].js'),
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
});

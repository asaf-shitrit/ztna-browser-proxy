import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

/**
 * Vite marks emitted module scripts `crossorigin`, which makes the browser
 * fetch them in CORS mode. On a chrome-extension:// page that fetch fails and
 * the script silently never executes — the popup renders an empty <div>.
 */
const stripCrossorigin = {
  name: 'strip-crossorigin',
  transformIndexHtml(html: string) {
    return html.replace(/\s+crossorigin(="[^"]*")?/g, '');
  },
};

export default defineConfig({
  plugins: [react(), stripCrossorigin],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        background: resolve(__dirname, 'src/background.ts'),
        popup: resolve(__dirname, 'popup.html'),
      },
      output: {
        // MV3 names the service worker explicitly in the manifest, so entry
        // filenames must be stable rather than content-hashed.
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: 'assets/[name][extname]',
      },
    },
  },
});

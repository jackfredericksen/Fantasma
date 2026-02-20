import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import sveltePreprocess from 'svelte-preprocess';
import { resolve } from 'path';
import { readFileSync, writeFileSync, copyFileSync } from 'fs';

const browserTarget = process.env.BROWSER || 'chrome';

export default defineConfig({
  plugins: [
    svelte({
      preprocess: sveltePreprocess()
    }),
    {
      name: 'copy-manifest',
      closeBundle() {
        const manifestFile = browserTarget === 'firefox'
          ? 'manifest.firefox.json'
          : 'manifest.chrome.json';
        const src = resolve(__dirname, manifestFile);
        const dest = resolve(__dirname, 'dist', 'manifest.json');
        const manifest = readFileSync(src, 'utf-8');
        writeFileSync(dest, manifest);
      }
    }
  ],
  resolve: {
    alias: {
      '$lib': resolve(__dirname, 'src/lib')
    }
  },
  build: {
    outDir: 'dist',
    emptyDir: true,
    sourcemap: browserTarget === 'firefox' ? 'inline' : false,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/popup.html'),
        options: resolve(__dirname, 'src/options/options.html'),
        background: resolve(__dirname, 'src/background/service-worker.ts'),
        'content-script': resolve(__dirname, 'src/content/content-script.ts')
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'background') return 'background/service-worker.js';
          if (chunkInfo.name === 'content-script') return 'content/content-script.js';
          return '[name]/[name].js';
        },
        chunkFileNames: 'shared/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]'
      }
    },
    target: 'es2021'
  }
});

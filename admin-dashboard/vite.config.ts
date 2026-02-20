import { svelte } from '@sveltejs/vite-plugin-svelte';
import sveltePreprocess from 'svelte-preprocess';
import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  plugins: [
    svelte({
      preprocess: sveltePreprocess()
    })
  ],
  resolve: {
    alias: {
      '$lib': resolve(__dirname, 'src/lib')
    }
  },
  server: {
    proxy: {
      '/admin': 'http://localhost:3000'
    }
  }
});

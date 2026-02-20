import App from './App.svelte';

const target = document.getElementById('app');

if (!target) {
  throw new Error('Could not find #app mount point');
}

const app = new App({ target });

export default app;

<script lang="ts">
  import { onMount } from 'svelte';
  import { authenticated, adminKey } from '$lib/stores';
  import { setApiKey, getStats } from '$lib/api';
  import Sidebar from '$lib/components/Sidebar.svelte';

  import Dashboard from './pages/Dashboard.svelte';
  import Clients from './pages/Clients.svelte';
  import Proofs from './pages/Proofs.svelte';
  import Issuers from './pages/Issuers.svelte';
  import Audit from './pages/Audit.svelte';
  import Settings from './pages/Settings.svelte';

  let currentPage = 'dashboard';
  let loginKey = '';
  let loginError = '';
  let loading = false;

  function updatePage() {
    const hash = window.location.hash.slice(1) || 'dashboard';
    currentPage = hash;
  }

  onMount(() => {
    updatePage();
    window.addEventListener('hashchange', updatePage);
    return () => window.removeEventListener('hashchange', updatePage);
  });

  async function handleLogin() {
    if (!loginKey.trim()) {
      loginError = 'Please enter an API key';
      return;
    }
    loading = true;
    loginError = '';
    setApiKey(loginKey.trim());
    try {
      await getStats();
      $adminKey = loginKey.trim();
      $authenticated = true;
    } catch {
      loginError = 'Invalid API key or server unreachable';
      setApiKey('');
    } finally {
      loading = false;
    }
  }
</script>

{#if $authenticated}
  <Sidebar {currentPage} />
  <main class="main-content">
    {#if currentPage === 'dashboard'}
      <Dashboard />
    {:else if currentPage === 'clients'}
      <Clients />
    {:else if currentPage === 'proofs'}
      <Proofs />
    {:else if currentPage === 'issuers'}
      <Issuers />
    {:else if currentPage === 'audit'}
      <Audit />
    {:else if currentPage === 'settings'}
      <Settings />
    {:else}
      <Dashboard />
    {/if}
  </main>
{:else}
  <div class="login-container">
    <div class="login-card">
      <h1>Fantasma</h1>
      <p>Enter your admin API key to continue</p>
      <form on:submit|preventDefault={handleLogin}>
        <label>
          Admin API Key
          <input
            type="password"
            bind:value={loginKey}
            placeholder="Enter admin key..."
            autocomplete="off"
          />
        </label>
        <button class="btn btn-primary" type="submit" disabled={loading}>
          {loading ? 'Authenticating...' : 'Sign In'}
        </button>
        {#if loginError}
          <div class="error-message">{loginError}</div>
        {/if}
      </form>
    </div>
  </div>
{/if}

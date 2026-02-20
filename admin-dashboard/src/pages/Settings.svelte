<script>
  import { authenticated } from '$lib/stores';
  import { getApiKey, setApiKey } from '$lib/api';

  let showKey = false;

  $: maskedKey = getApiKey() ? '*'.repeat(Math.max(0, getApiKey().length - 4)) + getApiKey().slice(-4) : '';
  $: displayKey = showKey ? getApiKey() : maskedKey;

  function handleLogout() {
    setApiKey('');
    $authenticated = false;
    window.location.hash = 'dashboard';
  }
</script>

<div class="header">
  <h1>Settings</h1>
</div>

<div class="card">
  <h2>Authentication</h2>
  <table>
    <tbody>
      <tr>
        <td>API Key</td>
        <td>
          <code>{displayKey}</code>
          <button class="btn" style="margin-left: 0.75rem;" on:click={() => showKey = !showKey}>
            {showKey ? 'Hide' : 'Reveal'}
          </button>
        </td>
      </tr>
      <tr>
        <td>Server URL</td>
        <td><code>{window.location.origin}/admin</code></td>
      </tr>
    </tbody>
  </table>
</div>

<div class="card">
  <h2>Session</h2>
  <p style="color: var(--text-muted); font-size: 0.875rem; margin-bottom: 1rem;">
    Clear the current API key and return to the login screen.
  </p>
  <button class="btn btn-danger" on:click={handleLogout}>
    Change API Key / Logout
  </button>
</div>

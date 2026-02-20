<script lang="ts">
  import { onMount } from 'svelte';
  import browser from 'webextension-polyfill';
  import type { ExtensionMessage, ExtensionResponse, WalletSettings } from '$lib/types';

  let serverUrl = 'http://localhost:3000';
  let autoLockMinutes = 15;
  let serverStatus: 'checking' | 'online' | 'offline' = 'checking';
  let saved = false;
  let errorMsg = '';

  async function send<T = unknown>(
    type: string,
    payload: Record<string, unknown> = {}
  ): Promise<T> {
    const msg: ExtensionMessage = { type: type as any, payload };
    const resp = (await browser.runtime.sendMessage(msg)) as ExtensionResponse<T>;
    if (!resp.success) throw new Error(resp.error ?? 'Request failed');
    return resp.data as T;
  }

  onMount(async () => {
    try {
      const settings = await send<WalletSettings>('SETTINGS_GET');
      serverUrl = settings.serverUrl;
      autoLockMinutes = settings.autoLockMinutes;
    } catch {
      // Use defaults
    }
    checkServer();
  });

  async function saveSettings(): Promise<void> {
    errorMsg = '';
    saved = false;
    try {
      await send('SETTINGS_UPDATE', {
        settings: { serverUrl, autoLockMinutes }
      });
      saved = true;
      checkServer();
      setTimeout(() => (saved = false), 3000);
    } catch (err) {
      errorMsg = (err as Error).message;
    }
  }

  async function checkServer(): Promise<void> {
    serverStatus = 'checking';
    try {
      await send('SERVER_DISCOVER', { serverUrl });
      serverStatus = 'online';
    } catch {
      serverStatus = 'offline';
    }
  }
</script>

<div class="page">
  <header class="header">
    <div class="logo">
      <div class="logo-icon">F</div>
      <h1>Fantasma Wallet Settings</h1>
    </div>
  </header>

  <main class="content">
    <section class="card">
      <h2>Server Configuration</h2>
      <p class="muted">Configure the Fantasma proof server that this wallet connects to.</p>

      <div class="field">
        <label for="server-url">Server URL</label>
        <div class="input-row">
          <input id="server-url" type="url" bind:value={serverUrl}
                 placeholder="http://localhost:3000" />
          <div class="status-indicator">
            <div class="status-dot" class:online={serverStatus === 'online'}
                 class:offline={serverStatus === 'offline'}></div>
            <span class="muted">
              {#if serverStatus === 'checking'}Checking...
              {:else if serverStatus === 'online'}Connected
              {:else}Offline{/if}
            </span>
          </div>
        </div>
      </div>

      <button class="btn btn-outline" on:click={checkServer}>
        Test Connection
      </button>
    </section>

    <section class="card">
      <h2>Security</h2>

      <div class="field">
        <label for="auto-lock">Auto-lock timeout (minutes)</label>
        <input id="auto-lock" type="number" bind:value={autoLockMinutes}
               min="1" max="120" />
        <p class="hint">The wallet will automatically lock after this period of inactivity.</p>
      </div>
    </section>

    {#if errorMsg}
      <div class="error-box">{errorMsg}</div>
    {/if}

    {#if saved}
      <div class="success-box">Settings saved successfully.</div>
    {/if}

    <button class="btn btn-primary" on:click={saveSettings}>
      Save Settings
    </button>
  </main>
</div>

<style>
  .page {
    max-width: 640px;
    margin: 0 auto;
    padding: 32px 24px;
  }

  .header {
    margin-bottom: 32px;
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .logo-icon {
    width: 40px;
    height: 40px;
    background: linear-gradient(135deg, #8b5cf6, #3b82f6);
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 22px;
    font-weight: bold;
    color: white;
  }
  h1 {
    font-size: 22px;
    font-weight: 600;
  }

  .content {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .card {
    background: #252550;
    border: 1px solid #3b3b6d;
    border-radius: 12px;
    padding: 20px;
  }
  .card h2 {
    font-size: 16px;
    margin-bottom: 6px;
  }
  .card > .muted {
    margin-bottom: 16px;
  }

  .muted { color: #a0a0cc; font-size: 13px; }
  .hint { color: #a0a0cc; font-size: 12px; margin-top: 6px; }

  .field {
    margin-bottom: 16px;
  }
  .field label {
    display: block;
    margin-bottom: 6px;
    font-size: 13px;
    color: #a0a0cc;
  }
  .field input {
    width: 100%;
    padding: 10px 14px;
    background: #1a1a3e;
    border: 1px solid #3b3b6d;
    border-radius: 8px;
    color: white;
    font-size: 14px;
  }
  .field input:focus {
    outline: none;
    border-color: #8b5cf6;
  }

  .input-row {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .input-row input { flex: 1; }

  .status-indicator {
    display: flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
  }
  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #6b7280;
  }
  .status-dot.online { background: #10b981; }
  .status-dot.offline { background: #ef4444; }

  .btn {
    padding: 12px 20px;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: opacity 0.2s;
  }
  .btn:hover { opacity: 0.9; }
  .btn-primary {
    background: linear-gradient(135deg, #8b5cf6, #3b82f6);
    color: white;
    width: 100%;
  }
  .btn-outline {
    background: transparent;
    color: #8b5cf6;
    border: 1px solid #8b5cf6;
  }

  .error-box {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid #ef4444;
    color: #ef4444;
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 13px;
  }
  .success-box {
    background: rgba(16, 185, 129, 0.1);
    border: 1px solid #10b981;
    color: #10b981;
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 13px;
  }
</style>

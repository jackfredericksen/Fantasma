<script lang="ts">
  import { onMount } from 'svelte';
  import browser from 'webextension-polyfill';
  import type {
    ExtensionMessage,
    ExtensionResponse,
    DecryptedCredential,
    CredentialImportData,
    CredentialType,
    AuthRequest
  } from '$lib/types';

  // ── State ──────────────────────────────────────────────────────────────

  type Screen = 'loading' | 'setup' | 'locked' | 'main';
  type Tab = 'credentials' | 'import' | 'settings';

  let screen: Screen = 'loading';
  let activeTab: Tab = 'credentials';
  let errorMsg = '';

  // Lock / Setup
  let setupPassword = '';
  let setupConfirm = '';
  let unlockPassword = '';

  // Credentials
  let credentials: DecryptedCredential[] = [];

  // Auth approval
  let pendingAuth: (AuthRequest & { callbackId: string }) | null = null;
  let selectedCredentialIds: string[] = [];

  // Import form
  let importType: CredentialType = 'identity';
  let importIssuer = '';
  let importCommitment = '';
  let importJson = '';

  // Settings
  let serverUrl = 'http://localhost:3000';
  let autoLockMinutes = 15;
  let serverStatus: 'checking' | 'online' | 'offline' = 'checking';

  // ── Messaging ──────────────────────────────────────────────────────────

  async function send<T = unknown>(
    type: string,
    payload: Record<string, unknown> = {}
  ): Promise<T> {
    const msg: ExtensionMessage = { type: type as any, payload };
    const resp = (await browser.runtime.sendMessage(msg)) as ExtensionResponse<T>;
    if (!resp.success) throw new Error(resp.error ?? 'Request failed');
    return resp.data as T;
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────

  onMount(async () => {
    try {
      const initialized = await send<boolean>('WALLET_IS_INITIALIZED');
      if (!initialized) {
        screen = 'setup';
        return;
      }

      const unlocked = await send<boolean>('WALLET_IS_UNLOCKED');
      if (unlocked) {
        await enterMainScreen();
      } else {
        screen = 'locked';
      }
    } catch {
      screen = 'setup';
    }
  });

  async function enterMainScreen(): Promise<void> {
    screen = 'main';
    await loadCredentials();
    await loadSettings();
    await checkPendingAuth();
    checkServer();
  }

  // ── Wallet Setup ───────────────────────────────────────────────────────

  async function handleSetup(): Promise<void> {
    errorMsg = '';

    if (setupPassword.length < 8) {
      errorMsg = 'Password must be at least 8 characters';
      return;
    }
    if (setupPassword !== setupConfirm) {
      errorMsg = 'Passwords do not match';
      return;
    }

    try {
      await send('WALLET_INITIALIZE', { password: setupPassword });
      setupPassword = '';
      setupConfirm = '';
      await enterMainScreen();
    } catch (err) {
      errorMsg = (err as Error).message;
    }
  }

  // ── Unlock ─────────────────────────────────────────────────────────────

  async function handleUnlock(): Promise<void> {
    errorMsg = '';
    try {
      await send('WALLET_UNLOCK', { password: unlockPassword });
      unlockPassword = '';
      await enterMainScreen();
    } catch (err) {
      errorMsg = (err as Error).message;
    }
  }

  // ── Lock ───────────────────────────────────────────────────────────────

  async function handleLock(): Promise<void> {
    await send('WALLET_LOCK');
    screen = 'locked';
  }

  // ── Credentials ────────────────────────────────────────────────────────

  async function loadCredentials(): Promise<void> {
    try {
      credentials = await send<DecryptedCredential[]>('CREDENTIALS_GET');
    } catch (err) {
      console.error('Failed to load credentials:', err);
      credentials = [];
    }
  }

  async function deleteCredential(id: string): Promise<void> {
    await send('CREDENTIALS_DELETE', { credentialId: id });
    await loadCredentials();
  }

  function credentialTitle(type: CredentialType): string {
    const map: Record<CredentialType, string> = {
      identity: 'Identity Credential',
      kyc: 'KYC Verification',
      degree: 'Academic Degree',
      license: 'Professional License',
      membership: 'Membership'
    };
    return map[type] ?? 'Credential';
  }

  function isExpired(expiresAt: string | null): boolean {
    if (!expiresAt) return false;
    return new Date(expiresAt) < new Date();
  }

  function formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  }

  // ── Import ─────────────────────────────────────────────────────────────

  async function handleImport(): Promise<void> {
    errorMsg = '';

    if (!importIssuer.trim() || !importCommitment.trim()) {
      errorMsg = 'Issuer and commitment are required';
      return;
    }

    let attributes: Record<string, unknown> = {};
    if (importJson.trim()) {
      try {
        attributes = JSON.parse(importJson);
      } catch {
        errorMsg = 'Invalid JSON in attributes field';
        return;
      }
    }

    const credential: CredentialImportData = {
      type: importType,
      issuerName: importIssuer.trim(),
      commitment: importCommitment.trim(),
      expiresAt: null,
      attributes
    };

    try {
      await send('CREDENTIALS_IMPORT', { credential });
      importIssuer = '';
      importCommitment = '';
      importJson = '';
      activeTab = 'credentials';
      await loadCredentials();
    } catch (err) {
      errorMsg = (err as Error).message;
    }
  }

  // ── Auth Approval ──────────────────────────────────────────────────────

  async function checkPendingAuth(): Promise<void> {
    try {
      const result = await send<(AuthRequest & { callbackId: string }) | null>(
        'AUTH_REQUEST'
      );
      if (result) {
        pendingAuth = result;
        selectedCredentialIds = credentials.map((c) => c.id);
      }
    } catch {
      // No pending auth
    }
  }

  async function approveAuth(): Promise<void> {
    if (!pendingAuth) return;
    try {
      await send('AUTH_APPROVE', {
        callbackId: pendingAuth.callbackId,
        selectedCredentialIds
      });
    } catch (err) {
      console.error('Auth approval failed:', err);
    }
    pendingAuth = null;
  }

  async function denyAuth(): Promise<void> {
    if (!pendingAuth) return;
    try {
      await send('AUTH_DENY', { callbackId: pendingAuth.callbackId });
    } catch (err) {
      console.error('Auth deny failed:', err);
    }
    pendingAuth = null;
  }

  function toggleCredentialSelection(id: string): void {
    if (selectedCredentialIds.includes(id)) {
      selectedCredentialIds = selectedCredentialIds.filter((c) => c !== id);
    } else {
      selectedCredentialIds = [...selectedCredentialIds, id];
    }
  }

  // ── Settings ───────────────────────────────────────────────────────────

  async function loadSettings(): Promise<void> {
    try {
      const settings = await send<{ serverUrl: string; autoLockMinutes: number }>(
        'SETTINGS_GET'
      );
      serverUrl = settings.serverUrl;
      autoLockMinutes = settings.autoLockMinutes;
    } catch {
      // Use defaults
    }
  }

  async function saveSettings(): Promise<void> {
    await send('SETTINGS_UPDATE', {
      settings: { serverUrl, autoLockMinutes }
    });
    checkServer();
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

<div class="container">
  <!-- Header -->
  <header class="header">
    <div class="logo">
      <div class="logo-icon">F</div>
      <span class="logo-text">Fantasma</span>
    </div>
    {#if screen === 'main'}
      <button class="icon-btn" on:click={handleLock} title="Lock Wallet">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
      </button>
    {/if}
  </header>

  <!-- Loading -->
  {#if screen === 'loading'}
    <div class="center-screen">
      <p class="muted">Loading...</p>
    </div>

  <!-- Setup -->
  {:else if screen === 'setup'}
    <div class="center-screen">
      <div class="lock-icon-large">F</div>
      <h2>Welcome to Fantasma</h2>
      <p class="muted">Create a password to secure your wallet</p>

      {#if errorMsg}
        <div class="error-box">{errorMsg}</div>
      {/if}

      <form on:submit|preventDefault={handleSetup} class="form">
        <div class="field">
          <label for="setup-pw">Password</label>
          <input id="setup-pw" type="password" bind:value={setupPassword}
                 placeholder="Enter password (min 8 chars)" required />
        </div>
        <div class="field">
          <label for="setup-confirm">Confirm Password</label>
          <input id="setup-confirm" type="password" bind:value={setupConfirm}
                 placeholder="Confirm password" required />
        </div>
        <button type="submit" class="btn btn-primary">Create Wallet</button>
      </form>
    </div>

  <!-- Locked -->
  {:else if screen === 'locked'}
    <div class="center-screen">
      <div class="lock-icon-large">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
      </div>
      <h2>Wallet Locked</h2>
      <p class="muted">Enter your password to unlock</p>

      {#if errorMsg}
        <div class="error-box">{errorMsg}</div>
      {/if}

      <form on:submit|preventDefault={handleUnlock} class="form">
        <div class="field">
          <input type="password" bind:value={unlockPassword}
                 placeholder="Enter password" required />
        </div>
        <button type="submit" class="btn btn-primary">Unlock</button>
      </form>
    </div>

  <!-- Main -->
  {:else if screen === 'main'}
    <!-- Auth Approval Dialog -->
    {#if pendingAuth}
      <div class="auth-dialog">
        <h3>Authorization Request</h3>
        <p class="muted">{pendingAuth.origin}</p>

        <div class="scope-list">
          <span class="label">Requested scopes:</span>
          {#each pendingAuth.scopes as scope}
            <div class="scope-badge">{scope}</div>
          {/each}
        </div>

        <div class="credential-select">
          <span class="label">Select credentials:</span>
          {#each credentials as cred}
            <label class="credential-option"
                   class:selected={selectedCredentialIds.includes(cred.id)}>
              <input type="checkbox"
                     checked={selectedCredentialIds.includes(cred.id)}
                     on:change={() => toggleCredentialSelection(cred.id)} />
              <span>{credentialTitle(cred.type)} - {cred.issuerName}</span>
            </label>
          {/each}
        </div>

        <div class="btn-row">
          <button class="btn btn-secondary" on:click={denyAuth}>Deny</button>
          <button class="btn btn-primary" on:click={approveAuth}>Approve</button>
        </div>
      </div>
    {:else}
      <!-- Tabs -->
      <div class="tabs">
        <button class="tab" class:active={activeTab === 'credentials'}
                on:click={() => (activeTab = 'credentials')}>Credentials</button>
        <button class="tab" class:active={activeTab === 'import'}
                on:click={() => (activeTab = 'import')}>Import</button>
        <button class="tab" class:active={activeTab === 'settings'}
                on:click={() => (activeTab = 'settings')}>Settings</button>
      </div>

      <!-- Credentials Tab -->
      {#if activeTab === 'credentials'}
        {#if credentials.length === 0}
          <div class="empty-state">
            <p>No credentials yet</p>
            <p class="muted small">Import credentials from verified issuers</p>
          </div>
        {:else}
          <div class="credential-list">
            {#each credentials as cred (cred.id)}
              <div class="credential-card">
                <div class="credential-header">
                  <div class="credential-type">
                    <div class="credential-icon">{cred.type.slice(0, 2).toUpperCase()}</div>
                    <div class="credential-info">
                      <h4>{credentialTitle(cred.type)}</h4>
                      <span class="muted">{cred.issuerName}</span>
                    </div>
                  </div>
                  <span class="badge" class:expired={isExpired(cred.expiresAt)}>
                    {isExpired(cred.expiresAt) ? 'Expired' : 'Valid'}
                  </span>
                </div>
                <div class="credential-details">
                  <div><span>Issued</span><span>{formatDate(cred.issuedAt)}</span></div>
                  {#if cred.expiresAt}
                    <div><span>Expires</span><span>{formatDate(cred.expiresAt)}</span></div>
                  {/if}
                </div>
                <button class="btn-link danger" on:click={() => deleteCredential(cred.id)}>
                  Remove
                </button>
              </div>
            {/each}
          </div>
        {/if}

      <!-- Import Tab -->
      {:else if activeTab === 'import'}
        {#if errorMsg}
          <div class="error-box">{errorMsg}</div>
        {/if}

        <form on:submit|preventDefault={handleImport} class="form">
          <div class="field">
            <label for="import-type">Credential Type</label>
            <select id="import-type" bind:value={importType}>
              <option value="identity">Identity</option>
              <option value="kyc">KYC Verification</option>
              <option value="degree">Academic Degree</option>
              <option value="license">Professional License</option>
              <option value="membership">Membership</option>
            </select>
          </div>

          <div class="field">
            <label for="import-issuer">Issuer Name</label>
            <input id="import-issuer" type="text" bind:value={importIssuer}
                   placeholder="e.g. Example Government" required />
          </div>

          <div class="field">
            <label for="import-commitment">Commitment (hex)</label>
            <input id="import-commitment" type="text" bind:value={importCommitment}
                   placeholder="0xabc..." required />
          </div>

          <div class="field">
            <label for="import-json">Attributes (JSON, optional)</label>
            <textarea id="import-json" bind:value={importJson} rows="4"
                      placeholder={'{"name": "...", "birthdate": "..."}'}></textarea>
          </div>

          <button type="submit" class="btn btn-primary">Import Credential</button>
        </form>

      <!-- Settings Tab -->
      {:else if activeTab === 'settings'}
        <form on:submit|preventDefault={saveSettings} class="form">
          <div class="field">
            <label for="server-url">Server URL</label>
            <input id="server-url" type="url" bind:value={serverUrl}
                   placeholder="http://localhost:3000" />
          </div>

          <div class="field">
            <label for="auto-lock">Auto-lock after (minutes)</label>
            <input id="auto-lock" type="number" bind:value={autoLockMinutes}
                   min="1" max="120" />
          </div>

          <button type="submit" class="btn btn-secondary">Save Settings</button>
        </form>
      {/if}
    {/if}
  {/if}

  <!-- Status Bar -->
  <div class="status-bar">
    <div class="status-indicator">
      <div class="status-dot" class:online={serverStatus === 'online'}
           class:offline={serverStatus === 'offline'}></div>
      <span>
        {#if serverStatus === 'checking'}Checking...
        {:else if serverStatus === 'online'}Connected
        {:else}Offline{/if}
      </span>
    </div>
    <span>v0.1.0</span>
  </div>
</div>

<style>
  .container {
    padding: 16px;
    min-height: 500px;
    display: flex;
    flex-direction: column;
  }

  /* ── Header ─────────────────────────────────────────── */
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 20px;
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .logo-icon {
    width: 32px;
    height: 32px;
    background: linear-gradient(135deg, #8b5cf6, #3b82f6);
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 18px;
    font-weight: bold;
    color: white;
  }
  .logo-text {
    font-size: 18px;
    font-weight: 600;
  }
  .icon-btn {
    background: none;
    border: none;
    color: #a0a0cc;
    cursor: pointer;
    padding: 6px;
    border-radius: 6px;
    transition: all 0.2s;
  }
  .icon-btn:hover {
    background: #252550;
    color: white;
  }

  /* ── Common ─────────────────────────────────────────── */
  .center-screen {
    text-align: center;
    padding-top: 32px;
    flex: 1;
  }
  .muted { color: #a0a0cc; }
  .small { font-size: 12px; }
  .label { font-size: 13px; color: #a0a0cc; margin-bottom: 6px; display: block; }

  .lock-icon-large {
    width: 64px;
    height: 64px;
    background: #252550;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 20px;
    font-size: 28px;
    font-weight: bold;
    color: white;
  }

  h2 { margin-bottom: 8px; }

  .error-box {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid #ef4444;
    color: #ef4444;
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 13px;
    margin: 12px 0;
    text-align: left;
  }

  /* ── Forms ──────────────────────────────────────────── */
  .form {
    text-align: left;
    margin-top: 16px;
  }
  .field {
    margin-bottom: 14px;
  }
  .field label {
    display: block;
    margin-bottom: 4px;
    font-size: 13px;
    color: #a0a0cc;
  }
  .field input,
  .field select,
  .field textarea {
    width: 100%;
    padding: 10px 14px;
    background: #252550;
    border: 1px solid #3b3b6d;
    border-radius: 8px;
    color: white;
    font-size: 14px;
    font-family: inherit;
  }
  .field input:focus,
  .field select:focus,
  .field textarea:focus {
    outline: none;
    border-color: #8b5cf6;
  }
  .field textarea {
    resize: vertical;
  }
  .field select {
    cursor: pointer;
  }

  /* ── Buttons ────────────────────────────────────────── */
  .btn {
    width: 100%;
    padding: 12px;
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
  }
  .btn-secondary {
    background: #252550;
    color: white;
    border: 1px solid #3b3b6d;
  }
  .btn-row {
    display: flex;
    gap: 10px;
    margin-top: 16px;
  }
  .btn-row .btn { flex: 1; }
  .btn-link {
    background: none;
    border: none;
    color: #a0a0cc;
    cursor: pointer;
    font-size: 12px;
    padding: 4px 0;
    margin-top: 8px;
  }
  .btn-link.danger:hover { color: #ef4444; }

  /* ── Tabs ───────────────────────────────────────────── */
  .tabs {
    display: flex;
    gap: 6px;
    margin-bottom: 16px;
  }
  .tab {
    flex: 1;
    padding: 8px;
    background: transparent;
    border: none;
    color: #a0a0cc;
    font-size: 13px;
    cursor: pointer;
    border-radius: 8px;
    transition: all 0.2s;
  }
  .tab.active {
    background: #252550;
    color: white;
  }
  .tab:hover:not(.active) { color: white; }

  /* ── Credentials ────────────────────────────────────── */
  .credential-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .credential-card {
    background: #252550;
    border: 1px solid #3b3b6d;
    border-radius: 12px;
    padding: 14px;
  }
  .credential-header {
    display: flex;
    justify-content: space-between;
    align-items: start;
    margin-bottom: 10px;
  }
  .credential-type {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .credential-icon {
    width: 36px;
    height: 36px;
    background: #8b5cf6;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 13px;
    font-weight: 600;
    color: white;
  }
  .credential-info h4 {
    font-size: 14px;
    margin-bottom: 2px;
  }
  .credential-info span {
    font-size: 12px;
  }
  .badge {
    font-size: 11px;
    padding: 3px 8px;
    border-radius: 12px;
    background: rgba(16, 185, 129, 0.2);
    color: #10b981;
  }
  .badge.expired {
    background: rgba(239, 68, 68, 0.2);
    color: #ef4444;
  }
  .credential-details {
    font-size: 12px;
    color: #a0a0cc;
  }
  .credential-details div {
    display: flex;
    justify-content: space-between;
    padding: 3px 0;
  }

  .empty-state {
    text-align: center;
    padding: 40px 16px;
    color: #a0a0cc;
  }

  /* ── Auth Dialog ────────────────────────────────────── */
  .auth-dialog {
    background: #252550;
    border: 1px solid #3b3b6d;
    border-radius: 12px;
    padding: 16px;
  }
  .auth-dialog h3 {
    margin-bottom: 4px;
  }
  .scope-list {
    margin: 12px 0;
  }
  .scope-badge {
    display: inline-block;
    background: #8b5cf6;
    color: white;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 12px;
    margin: 4px 4px 4px 0;
  }
  .credential-select {
    margin: 12px 0;
  }
  .credential-option {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    background: #1a1a3e;
    border-radius: 6px;
    margin-bottom: 6px;
    cursor: pointer;
    font-size: 13px;
    border: 2px solid transparent;
    transition: border-color 0.2s;
  }
  .credential-option.selected {
    border-color: #8b5cf6;
  }

  /* ── Status Bar ─────────────────────────────────────── */
  .status-bar {
    margin-top: auto;
    padding-top: 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 12px;
    color: #a0a0cc;
  }
  .status-indicator {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #6b7280;
  }
  .status-dot.online { background: #10b981; }
  .status-dot.offline { background: #ef4444; }
</style>

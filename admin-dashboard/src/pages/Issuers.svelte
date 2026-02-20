<script>
  import { onMount } from 'svelte';
  import { getIssuers, createIssuer, deleteIssuer } from '$lib/api';

  let issuers = [];
  let loading = true;
  let showForm = false;
  let formError = '';

  let formData = {
    issuer_id: '',
    name: '',
    public_key: '',
    public_key_algorithm: 'dilithium3',
    verification_url: '',
    trusted: false
  };

  onMount(() => fetchIssuers());

  async function fetchIssuers() {
    loading = true;
    try {
      issuers = await getIssuers();
    } catch (e) {
      console.error('Failed to fetch issuers:', e);
    } finally {
      loading = false;
    }
  }

  async function handleCreate() {
    formError = '';
    if (!formData.issuer_id || !formData.name || !formData.public_key) {
      formError = 'Issuer ID, Name, and Public Key are required';
      return;
    }
    try {
      await createIssuer({
        issuer_id: formData.issuer_id,
        name: formData.name,
        public_key: formData.public_key,
        public_key_algorithm: formData.public_key_algorithm,
        verification_url: formData.verification_url || undefined,
        trusted: formData.trusted
      });
      formData = { issuer_id: '', name: '', public_key: '', public_key_algorithm: 'dilithium3', verification_url: '', trusted: false };
      showForm = false;
      await fetchIssuers();
    } catch (e) {
      formError = e.message || 'Failed to create issuer';
    }
  }

  async function handleDelete(issuerId) {
    if (!confirm(`Delete issuer "${issuerId}"?`)) return;
    try {
      await deleteIssuer(issuerId);
      await fetchIssuers();
    } catch (e) {
      alert('Failed to delete issuer: ' + e.message);
    }
  }

  function formatDate(d) {
    if (!d) return '';
    return new Date(d).toLocaleDateString();
  }
</script>

<div class="header">
  <h1>Issuers</h1>
  <button class="btn btn-primary" on:click={() => showForm = !showForm}>
    {showForm ? 'Cancel' : 'Add Issuer'}
  </button>
</div>

{#if showForm}
  <div class="card">
    <h2>Add New Issuer</h2>
    <form on:submit|preventDefault={handleCreate}>
      <div class="form-row">
        <label>
          Issuer ID
          <input bind:value={formData.issuer_id} placeholder="issuer-001" />
        </label>
        <label>
          Name
          <input bind:value={formData.name} placeholder="Government ID Authority" />
        </label>
      </div>
      <label>
        Public Key (hex)
        <textarea bind:value={formData.public_key} placeholder="Enter public key in hex format..." rows="3"></textarea>
      </label>
      <div class="form-row">
        <label>
          Public Key Algorithm
          <select bind:value={formData.public_key_algorithm}>
            <option value="dilithium3">Dilithium3</option>
            <option value="ed25519">Ed25519</option>
          </select>
        </label>
        <label>
          Verification URL (optional)
          <input bind:value={formData.verification_url} placeholder="https://issuer.example.com/verify" />
        </label>
      </div>
      <label class="checkbox-label">
        <input type="checkbox" bind:checked={formData.trusted} />
        Trusted Issuer
      </label>
      <div class="form-actions">
        <button class="btn btn-primary" type="submit">Create Issuer</button>
      </div>
      {#if formError}
        <div class="error-message">{formError}</div>
      {/if}
    </form>
  </div>
{/if}

<div class="card">
  {#if loading}
    <div class="empty-state">Loading...</div>
  {:else if issuers.length === 0}
    <div class="empty-state">No issuers registered</div>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Issuer ID</th>
          <th>Name</th>
          <th>Algorithm</th>
          <th>Trusted</th>
          <th>Created</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each issuers as issuer}
          <tr>
            <td><code>{issuer.issuer_id}</code></td>
            <td>{issuer.name}</td>
            <td>{issuer.public_key_algorithm}</td>
            <td>
              <span class="badge" class:badge-success={issuer.trusted} class:badge-warning={!issuer.trusted}>
                {issuer.trusted ? 'Trusted' : 'Untrusted'}
              </span>
            </td>
            <td>{formatDate(issuer.created_at)}</td>
            <td>
              <button class="btn btn-danger" on:click={() => handleDelete(issuer.issuer_id)}>
                Delete
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

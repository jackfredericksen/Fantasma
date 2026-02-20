<script>
  import { onMount } from 'svelte';
  import { getClients, createClient, deleteClient } from '$lib/api';

  let clients = [];
  let total = 0;
  let limit = 20;
  let offset = 0;
  let loading = true;
  let showForm = false;
  let formError = '';

  let formData = {
    client_id: '',
    client_name: '',
    redirect_uris: '',
    allowed_scopes: '',
    client_type: 'confidential'
  };

  onMount(() => fetchClients());

  async function fetchClients() {
    loading = true;
    try {
      const res = await getClients(limit, offset);
      clients = res.data;
      total = res.total;
    } catch (e) {
      console.error('Failed to fetch clients:', e);
    } finally {
      loading = false;
    }
  }

  async function handleCreate() {
    formError = '';
    if (!formData.client_id || !formData.client_name) {
      formError = 'Client ID and Name are required';
      return;
    }
    try {
      await createClient({
        client_id: formData.client_id,
        client_name: formData.client_name,
        redirect_uris: formData.redirect_uris.split(',').map(s => s.trim()).filter(Boolean),
        allowed_scopes: formData.allowed_scopes.split(',').map(s => s.trim()).filter(Boolean),
        client_type: formData.client_type
      });
      formData = { client_id: '', client_name: '', redirect_uris: '', allowed_scopes: '', client_type: 'confidential' };
      showForm = false;
      await fetchClients();
    } catch (e) {
      formError = e.message || 'Failed to create client';
    }
  }

  async function handleDelete(clientId) {
    if (!confirm(`Delete client "${clientId}"?`)) return;
    try {
      await deleteClient(clientId);
      await fetchClients();
    } catch (e) {
      alert('Failed to delete client: ' + e.message);
    }
  }

  function prevPage() {
    offset = Math.max(0, offset - limit);
    fetchClients();
  }

  function nextPage() {
    offset = offset + limit;
    fetchClients();
  }

  function formatDate(d) {
    if (!d) return '';
    return new Date(d).toLocaleDateString();
  }

  $: currentPage = Math.floor(offset / limit) + 1;
  $: totalPages = Math.ceil(total / limit) || 1;
</script>

<div class="header">
  <h1>Clients</h1>
  <button class="btn btn-primary" on:click={() => showForm = !showForm}>
    {showForm ? 'Cancel' : 'Register Client'}
  </button>
</div>

{#if showForm}
  <div class="card">
    <h2>Register New Client</h2>
    <form on:submit|preventDefault={handleCreate}>
      <div class="form-row">
        <label>
          Client ID
          <input bind:value={formData.client_id} placeholder="my-app" />
        </label>
        <label>
          Client Name
          <input bind:value={formData.client_name} placeholder="My Application" />
        </label>
      </div>
      <label>
        Redirect URIs (comma-separated)
        <input bind:value={formData.redirect_uris} placeholder="http://localhost:3000/callback, https://app.example.com/callback" />
      </label>
      <label>
        Allowed Scopes (comma-separated)
        <input bind:value={formData.allowed_scopes} placeholder="openid, profile, email" />
      </label>
      <label>
        Client Type
        <select bind:value={formData.client_type}>
          <option value="confidential">Confidential</option>
          <option value="public">Public</option>
        </select>
      </label>
      <div class="form-actions">
        <button class="btn btn-primary" type="submit">Create Client</button>
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
  {:else if clients.length === 0}
    <div class="empty-state">No clients registered</div>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Client ID</th>
          <th>Name</th>
          <th>Type</th>
          <th>Created</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each clients as client}
          <tr>
            <td><code>{client.client_id}</code></td>
            <td>{client.client_name}</td>
            <td>{client.client_type}</td>
            <td>{formatDate(client.created_at)}</td>
            <td>
              <button class="btn btn-danger" on:click={() => handleDelete(client.client_id)}>
                Delete
              </button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>

    <div class="paginator">
      <button on:click={prevPage} disabled={offset === 0}>Previous</button>
      <span>Page {currentPage} of {totalPages}</span>
      <button on:click={nextPage} disabled={offset + limit >= total}>Next</button>
    </div>
  {/if}
</div>

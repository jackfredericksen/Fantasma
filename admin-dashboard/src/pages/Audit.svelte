<script>
  import { onMount } from 'svelte';
  import { getAudit } from '$lib/api';

  let entries = [];
  let total = 0;
  let limit = 50;
  let offset = 0;
  let loading = true;

  onMount(() => fetchAudit());

  async function fetchAudit() {
    loading = true;
    try {
      const res = await getAudit(limit, offset);
      entries = res.data;
      total = res.total;
    } catch (e) {
      console.error('Failed to fetch audit log:', e);
    } finally {
      loading = false;
    }
  }

  function formatDate(d) {
    if (!d) return '';
    return new Date(d).toLocaleString();
  }

  function prevPage() {
    offset = Math.max(0, offset - limit);
    fetchAudit();
  }

  function nextPage() {
    offset = offset + limit;
    fetchAudit();
  }

  $: currentPage = Math.floor(offset / limit) + 1;
  $: totalPages = Math.ceil(total / limit) || 1;
</script>

<div class="header">
  <h1>Audit Log</h1>
</div>

<div class="card">
  {#if loading}
    <div class="empty-state">Loading...</div>
  {:else if entries.length === 0}
    <div class="empty-state">No audit entries</div>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Event Type</th>
          <th>User ID</th>
          <th>Client ID</th>
          <th>IP Address</th>
          <th>Timestamp</th>
        </tr>
      </thead>
      <tbody>
        {#each entries as entry}
          <tr>
            <td><code>{entry.event_type}</code></td>
            <td>{entry.user_id || '-'}</td>
            <td>{entry.client_id || '-'}</td>
            <td>{entry.ip_address || '-'}</td>
            <td>{formatDate(entry.created_at)}</td>
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

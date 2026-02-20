<script>
  import { onMount } from 'svelte';
  import { getProofs } from '$lib/api';

  let proofs = [];
  let total = 0;
  let limit = 20;
  let offset = 0;
  let loading = true;
  let circuitFilter = '';

  onMount(() => fetchProofs());

  async function fetchProofs() {
    loading = true;
    try {
      const res = await getProofs(limit, offset, circuitFilter || undefined);
      proofs = res.data;
      total = res.total;
    } catch (e) {
      console.error('Failed to fetch proofs:', e);
    } finally {
      loading = false;
    }
  }

  function handleFilterChange() {
    offset = 0;
    fetchProofs();
  }

  function truncate(s, len = 16) {
    if (!s) return '';
    return s.length > len ? s.slice(0, len) + '...' : s;
  }

  function formatDate(d) {
    if (!d) return '';
    return new Date(d).toLocaleString();
  }

  function prevPage() {
    offset = Math.max(0, offset - limit);
    fetchProofs();
  }

  function nextPage() {
    offset = offset + limit;
    fetchProofs();
  }

  $: currentPage = Math.floor(offset / limit) + 1;
  $: totalPages = Math.ceil(total / limit) || 1;
</script>

<div class="header">
  <h1>Proofs</h1>
  <div>
    <select bind:value={circuitFilter} on:change={handleFilterChange}>
      <option value="">All Circuit Types</option>
      <option value="age_verification">Age Verification</option>
      <option value="identity">Identity</option>
      <option value="membership">Membership</option>
      <option value="credential">Credential</option>
    </select>
  </div>
</div>

<div class="card">
  {#if loading}
    <div class="empty-state">Loading...</div>
  {:else if proofs.length === 0}
    <div class="empty-state">No proofs found</div>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Proof ID</th>
          <th>Circuit Type</th>
          <th>Verified</th>
          <th>User</th>
          <th>Created</th>
        </tr>
      </thead>
      <tbody>
        {#each proofs as proof}
          <tr>
            <td><code title={proof.proof_id}>{truncate(proof.proof_id)}</code></td>
            <td>{proof.circuit_type}</td>
            <td>
              <span class="badge" class:badge-success={proof.verified} class:badge-danger={!proof.verified}>
                {proof.verified ? 'Verified' : 'Unverified'}
              </span>
            </td>
            <td>{proof.user_id || '-'}</td>
            <td>{formatDate(proof.created_at)}</td>
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

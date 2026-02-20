<script>
  import { onMount } from 'svelte';
  import { getStats, getDetailedHealth } from '$lib/api';
  import StatCard from '$lib/components/StatCard.svelte';

  let stats = null;
  let health = null;
  let loading = true;

  onMount(async () => {
    try {
      const [s, h] = await Promise.all([getStats(), getDetailedHealth()]);
      stats = s;
      health = h;
    } catch (e) {
      console.error('Failed to load dashboard data:', e);
    } finally {
      loading = false;
    }
  });

  function formatUptime(seconds) {
    if (!seconds) return 'N/A';
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h}h ${m}m ${Math.floor(s)}s`;
  }
</script>

<div class="header">
  <h1>Dashboard</h1>
</div>

{#if loading}
  <div class="empty-state">Loading...</div>
{:else if stats}
  <div class="grid-4">
    <StatCard title="Clients" value={stats.clients} subtitle="Registered clients" />
    <StatCard title="Proofs" value={stats.proofs} subtitle="Stored proofs" />
    <StatCard title="Issuers" value={stats.issuers} subtitle="Credential issuers" />
    <StatCard title="Audit Entries" value={stats.audit_entries} subtitle="Log entries" />
  </div>

  <div class="card">
    <h2>System Status</h2>
    {#if health}
      <table>
        <tbody>
          <tr>
            <td>Status</td>
            <td>
              <span class="badge" class:badge-success={health.status === 'healthy'} class:badge-danger={health.status !== 'healthy'}>
                {health.status}
              </span>
            </td>
          </tr>
          <tr>
            <td>Database Connected</td>
            <td>
              <span class="badge" class:badge-success={health.database.connected} class:badge-danger={!health.database.connected}>
                {health.database.connected ? 'Yes' : 'No'}
              </span>
            </td>
          </tr>
          <tr>
            <td>Database Pool Size</td>
            <td>{health.database.pool_size}</td>
          </tr>
          <tr>
            <td>Database Pool Idle</td>
            <td>{health.database.pool_idle}</td>
          </tr>
          <tr>
            <td>Using Database</td>
            <td>
              <span class="badge" class:badge-success={stats.using_database} class:badge-warning={!stats.using_database}>
                {stats.using_database ? 'Yes' : 'In-Memory'}
              </span>
            </td>
          </tr>
          <tr>
            <td>Uptime</td>
            <td>{formatUptime(health.uptime_seconds)}</td>
          </tr>
        </tbody>
      </table>
    {:else}
      <div class="empty-state">Health data unavailable</div>
    {/if}
  </div>
{:else}
  <div class="empty-state">Failed to load dashboard data</div>
{/if}

<script>
  export let title = '';
  export let value = '';
  export let subtitle = '';
</script>

<div class="stat-card">
  <div class="stat-title">{title}</div>
  <div class="stat-value">{value}</div>
  {#if subtitle}
    <div class="stat-subtitle">{subtitle}</div>
  {/if}
</div>

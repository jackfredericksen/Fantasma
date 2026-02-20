<script>
  export let columns = [];
  export let rows = [];
</script>

{#if rows.length === 0}
  <div class="empty-state">No data</div>
{:else}
  <table>
    <thead>
      <tr>
        {#each columns as col}
          <th>{col.label}</th>
        {/each}
        <slot name="header-extra" />
      </tr>
    </thead>
    <tbody>
      {#each rows as row}
        <tr>
          {#each columns as col}
            <td>
              <slot name="cell" {row} column={col.key}>
                {row[col.key] ?? ''}
              </slot>
            </td>
          {/each}
          <slot name="row-actions" {row} />
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

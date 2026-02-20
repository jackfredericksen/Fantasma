<script>
  export let currentPage = 'dashboard';

  const links = [
    { href: '#dashboard', key: 'dashboard', label: 'Dashboard' },
    { href: '#clients', key: 'clients', label: 'Clients' },
    { href: '#proofs', key: 'proofs', label: 'Proofs' },
    { href: '#issuers', key: 'issuers', label: 'Issuers' },
    { href: '#audit', key: 'audit', label: 'Audit Log' },
    { href: '#settings', key: 'settings', label: 'Settings' }
  ];
</script>

<nav class="sidebar">
  <div class="sidebar-title">Fantasma Admin</div>
  {#each links as link}
    <a href={link.href} class:active={currentPage === link.key}>
      {link.label}
    </a>
  {/each}
</nav>

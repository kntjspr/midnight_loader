<script>
  export let status = 'idle'
  const colors = { idle: '#888888', building: '#f0b429', success: '#3ecf8e', error: '#ff5c5c' }
</script>

<span class="badge" style="color: {colors[status] || '#888888'}">● {status}</span>

<style>
  .badge {
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
  }
</style>

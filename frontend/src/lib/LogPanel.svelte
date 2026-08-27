<script>
  import { logs } from '../stores.js'
  import { tick } from 'svelte'

  let logContainer

  async function scrollToBottom() {
    await tick()
    if (logContainer) {
      logContainer.scrollTop = logContainer.scrollHeight
    }
  }

  $: if ($logs && logContainer) {
    scrollToBottom()
  }
</script>

<div id="log-panel" bind:this={logContainer} class="log">
  {#if $logs.length === 0}
    <div class="placeholder">awaiting build...</div>
  {/if}
  {#each $logs as line}
    <div class:err={line.startsWith('[g++]') || line.startsWith('[error]')}>{line}</div>
  {/each}
</div>

<style>
  .log {
    background: #11111e;
    color: #c0c0d0;
    padding: 0.85rem;
    height: 240px;
    overflow-y: auto;
    font-family: monospace;
    font-size: 0.85rem;
    border: 1px solid #2e2e4a;
    border-radius: 4px;
    margin-top: 1rem;
    box-sizing: border-box;
    text-align: left;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .placeholder {
    color: #555577;
    font-style: italic;
  }
  .err {
    color: #ff5c5c;
  }
</style>

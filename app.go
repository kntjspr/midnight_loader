package main

import (
	"context"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"midnight_loader/internal/builder"
	"midnight_loader/internal/config"
)

type App struct{ ctx context.Context }

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

// CheckDeps reports which build-time deps exist on PATH.
func (a *App) CheckDeps() map[string]bool {
	return map[string]bool{"g++": builder.ExistsOnPath("g++")}
}

// GenerateKey returns a fresh alphanumeric XOR key.
func (a *App) GenerateKey() string { return builder.GenerateKey() }

// EncryptFile XOR-encrypts inputPath with key and writes result to outputPath.
func (a *App) EncryptFile(inputPath, outputPath, key string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	enc := builder.XOREncrypt(data, key)
	return os.WriteFile(outputPath, enc, 0644)
}

// Build runs the full compile pipeline. Log lines are emitted as "build:log" events.
func (a *App) Build(cfg config.BuildConfig) error {
	return builder.Build(a.ctx, cfg, func(line string) {
		runtime.EventsEmit(a.ctx, "build:log", line)
	})
}

// PickFile opens a native file dialog filtered by filter (e.g. "*.bin").
func (a *App) PickFile(filter string) string {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Filters: []runtime.FileFilter{{DisplayName: filter, Pattern: filter}},
	})
	if err != nil {
		return ""
	}
	return path
}

// PickDir opens a native directory picker.
func (a *App) PickDir() string {
	path, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{})
	if err != nil {
		return ""
	}
	return path
}

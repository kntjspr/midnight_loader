package main

import (
	"context"

	"midnight_loader/internal/config"
)

type App struct {
	ctx context.Context
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

// CheckDeps reports which build deps are on PATH.
func (a *App) CheckDeps() map[string]bool {
	return map[string]bool{
		"g++": commandExists("g++"),
	}
}

func commandExists(cmd string) bool {
	importExec := func() bool {
		// resolved in task 3
		return false
	}
	_ = config.BuildConfig{}
	return importExec()
}

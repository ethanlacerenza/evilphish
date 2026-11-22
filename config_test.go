package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadConfig_MissingFileReturnsDefaults(t *testing.T) {
	c, err := LoadConfig(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("LoadConfig on a missing file should not error, got: %v", err)
	}
	s := c.Snapshot()
	if s.PollIntervalSeconds != 5 {
		t.Errorf("default PollIntervalSeconds = %d, want 5", s.PollIntervalSeconds)
	}
	if s.RidQueryParam != "rid" {
		t.Errorf("default RidQueryParam = %q, want \"rid\"", s.RidQueryParam)
	}
	if !s.DryRun {
		t.Errorf("DryRun default = false, want true (a fresh config must never write into gophish)")
	}
}

func TestReady_MissingApiKey(t *testing.T) {
	// Defaults fill the evilginx path and gophish URL but never the API key.
	c, _ := LoadConfig(filepath.Join(t.TempDir(), "x.json"))
	ready, missing := c.Ready()
	if ready {
		t.Fatalf("Ready() = true with no API key, want false")
	}
	if len(missing) != 1 || missing[0] != "gophish api key" {
		t.Fatalf("missing = %v, want [\"gophish api key\"]", missing)
	}
}

func TestReady_CompleteConfig(t *testing.T) {
	c, _ := LoadConfig(filepath.Join(t.TempDir(), "x.json"))
	if err := c.SetGophishAPIKey("k"); err != nil {
		t.Fatalf("SetGophishAPIKey: %v", err)
	}
	ready, missing := c.Ready()
	if !ready {
		t.Fatalf("Ready() = false with a complete config, missing: %v", missing)
	}
}

func TestInterval_NonPositiveFallsBackToFiveSeconds(t *testing.T) {
	c, _ := LoadConfig(filepath.Join(t.TempDir(), "x.json"))
	if err := c.SetPollInterval(0); err != nil {
		t.Fatalf("SetPollInterval: %v", err)
	}
	if got := c.Interval(); got.Seconds() != 5 {
		t.Errorf("Interval() with 0 = %v, want 5s", got)
	}
	if err := c.SetPollInterval(12); err != nil {
		t.Fatalf("SetPollInterval: %v", err)
	}
	if got := c.Interval(); got.Seconds() != 12 {
		t.Errorf("Interval() with 12 = %v, want 12s", got)
	}
}

func TestSaveLoad_RoundTripAndFilePerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c, _ := LoadConfig(path)
	if err := c.SetGophishAPIKey("SECRET-KEY"); err != nil {
		t.Fatalf("SetGophishAPIKey: %v", err)
	}
	if err := c.SetEvilginxDBPath("/tmp/evilginx/data.db"); err != nil {
		t.Fatalf("SetEvilginxDBPath: %v", err)
	}
	if err := c.SetDryRun(false); err != nil {
		t.Fatalf("SetDryRun: %v", err)
	}

	// Reload from the same path: every change must have persisted.
	c2, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	s := c2.Snapshot()
	if s.GophishAPIKey != "SECRET-KEY" {
		t.Errorf("reloaded APIKey = %q, want SECRET-KEY", s.GophishAPIKey)
	}
	if s.EvilginxDBPath != "/tmp/evilginx/data.db" {
		t.Errorf("reloaded EvilginxDBPath = %q", s.EvilginxDBPath)
	}
	if s.DryRun {
		t.Errorf("reloaded DryRun = true, want false")
	}

	// The config holds the gophish API key: it must be written 0600.
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("config file perms = %o, want 600", perm)
		}
	}
}

func TestSnapshot_MapIsDetached(t *testing.T) {
	c, _ := LoadConfig(filepath.Join(t.TempDir(), "x.json"))
	s := c.Snapshot()
	s.FormFieldMapping["injected"] = "oops"
	// Mutating the snapshot's map must not leak back into the config.
	if _, ok := c.Snapshot().FormFieldMapping["injected"]; ok {
		t.Fatalf("Snapshot() map is not detached: a mutation leaked back into Config")
	}
}

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadState_MissingFile(t *testing.T) {
	st, err := LoadState(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("LoadState on a missing file should not error: %v", err)
	}
	if st.LastSeenID != 0 {
		t.Errorf("LastSeenID = %d, want 0", st.LastSeenID)
	}
	if st.ForwardedUpdateTime == nil {
		t.Fatalf("ForwardedUpdateTime must be a non-nil map on a fresh state")
	}
}

func TestLoadState_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("seed empty file: %v", err)
	}
	st, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState on an empty file should not error: %v", err)
	}
	if st.ForwardedUpdateTime == nil {
		t.Fatalf("ForwardedUpdateTime must be a non-nil map")
	}
}

func TestState_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bridge-state.json")
	st := &State{
		LastSeenID:          42,
		ForwardedUpdateTime: map[string]int64{"sess-abc": 1700000000},
	}
	if err := st.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got.LastSeenID != 42 {
		t.Errorf("LastSeenID = %d, want 42", got.LastSeenID)
	}
	if got.ForwardedUpdateTime["sess-abc"] != 1700000000 {
		t.Errorf("ForwardedUpdateTime[sess-abc] = %d, want 1700000000", got.ForwardedUpdateTime["sess-abc"])
	}

	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("state file perms = %o, want 600 (it gates re-forwarding into gophish)", perm)
		}
	}
}

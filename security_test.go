package main

import (
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRedactSecret(t *testing.T) {
	cases := []struct {
		in        string
		plaintext bool
		want      string
	}{
		{"hunter2", false, "<7 chars>"},
		{"", false, "<empty>"},
		{"café", false, "<4 chars>"}, // counts runes, not bytes
		{"hunter2", true, "hunter2"},
		{"", true, ""},
	}
	for _, c := range cases {
		if got := redactSecret(c.in, c.plaintext); got != c.want {
			t.Errorf("redactSecret(%q, %v) = %q, want %q", c.in, c.plaintext, got, c.want)
		}
	}
	// Core invariant: a redacted secret never leaks its own characters.
	if strings.Contains(redactSecret("TopSecretValue", false), "Secret") {
		t.Fatalf("redacted secret leaked its plaintext")
	}
}

func TestRedactEmail(t *testing.T) {
	cases := []struct {
		in        string
		plaintext bool
		want      string
	}{
		{"john.doe@corp.tld", false, "j***@corp.tld"},
		{"", false, "<empty>"},
		{"no-at-sign", false, "***"},
		{"john.doe@corp.tld", true, "john.doe@corp.tld"},
	}
	for _, c := range cases {
		if got := redactEmail(c.in, c.plaintext); got != c.want {
			t.Errorf("redactEmail(%q, %v) = %q, want %q", c.in, c.plaintext, got, c.want)
		}
	}
}

func TestRedactFields(t *testing.T) {
	f := url.Values{
		"username": {"bob"},
		"password": {"secret"},
	}
	// Keys are sorted and values masked by length when not plaintext.
	if got, want := redactFields(f, false), "[password=<6 chars> username=<3 chars>]"; got != want {
		t.Errorf("redactFields(redacted) = %q, want %q", got, want)
	}
	if got, want := redactFields(f, true), "[password=secret username=bob]"; got != want {
		t.Errorf("redactFields(plaintext) = %q, want %q", got, want)
	}
}

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := atomicWriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "first" {
		t.Fatalf("content = %q, want first", string(b))
	}

	// Overwrite must replace the contents, not append.
	if err := atomicWriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "second" {
		t.Fatalf("content = %q, want second", string(b))
	}

	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("perms = %o, want 600", perm)
		}
	}

	// No temp files may be left behind in the target directory.
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".evilphish-*.tmp"))
	if len(leftovers) != 0 {
		t.Errorf("atomicWriteFile left temp files behind: %v", leftovers)
	}
}

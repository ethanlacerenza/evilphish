// evilphish — bridges evilginx3 captures into gophish
// Copyright (C) 2026  Ethan Lacerenza
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// --- credential-safe logging -----------------------------------------
//
// evilphish runs on the operator's own box, usually headless under systemd,
// where everything it prints lands in the journal and persists there for the
// whole engagement. The captured credentials are the operator's legitimate
// deliverable — but the journal is the wrong place for them: it is an
// uncontrolled side channel and, in a blue-team turnaround, one of the first
// things a responder reads off a compromised C2 host.
//
// So by default we log enough to confirm the pipeline works — which field got
// filled, how long its value is, which recipient/campaign it correlated to —
// without writing the secret itself. The operator loses nothing from the normal
// workflow: the on-demand `sessions` command still prints full captured data to
// their own terminal, and gophish's dashboard shows the forwarded result.
//
// An operator who genuinely wants raw values in the log can opt back in with
// `config log_plaintext true`. The capability is preserved; only the default
// changes, from "leak by default" to "redact by default".

// redactSecret masks a captured value by length (e.g. "<8 chars>") unless
// plaintext logging has been explicitly enabled.
func redactSecret(v string, plaintext bool) string {
	if plaintext {
		return v
	}
	if v == "" {
		return "<empty>"
	}
	return fmt.Sprintf("<%d chars>", utf8.RuneCountInString(v))
}

// redactEmail keeps the domain (handy to confirm the right target org) but
// masks the local part: "john.doe@corp.tld" -> "j***@corp.tld".
func redactEmail(e string, plaintext bool) string {
	if plaintext {
		return e
	}
	if e == "" {
		return "<empty>"
	}
	at := strings.IndexByte(e, '@')
	if at <= 0 {
		return "***"
	}
	return e[:1] + "***@" + e[at+1:]
}

// redactFields renders a form-value map for logging with every value masked by
// length unless plaintext logging is enabled. Keys are always shown (so the
// operator can confirm the mapping produced every expected field) and sorted
// for stable, diffable output.
func redactFields(fields url.Values, plaintext bool) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('[')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%s", k, redactSecret(fields.Get(k), plaintext))
	}
	b.WriteByte(']')
	return b.String()
}

// --- crash-safe file writes ------------------------------------------
//
// config.json and bridge-state.json both hold data we never want to half-write
// on a crash: the gophish API key, and the idempotency state that stops
// already-forwarded captures from being replayed into gophish. Write to a temp
// file in the same directory, fsync it, then rename over the target — on POSIX
// the rename is atomic, so a reader (or the next startup) ever sees either the
// old file or the complete new one, never a torn mix of both.

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".evilphish-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	discard := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		discard()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		discard()
		return err
	}
	if err := tmp.Sync(); err != nil {
		discard()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

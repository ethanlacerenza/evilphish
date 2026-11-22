package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// respCmd encodes one RESP array-of-bulk-strings command exactly as evilginx3's
// append-only data.db stores it (byte-length prefixes, CRLF terminators).
func respCmd(args ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return b.String()
}

func TestReadRESPCommands_Basic(t *testing.T) {
	in := respCmd("set", "sessions:1", "{}") + respCmd("set", "sessions:0:id", "7")
	cmds, err := readRESPCommands(strings.NewReader(in))
	if err != nil {
		t.Fatalf("readRESPCommands: %v", err)
	}
	if len(cmds) != 2 {
		t.Fatalf("parsed %d commands, want 2", len(cmds))
	}
	if cmds[0][0] != "set" || cmds[0][1] != "sessions:1" || cmds[0][2] != "{}" {
		t.Errorf("cmd[0] = %v", cmds[0])
	}
	if cmds[1][1] != "sessions:0:id" || cmds[1][2] != "7" {
		t.Errorf("cmd[1] = %v", cmds[1])
	}
}

func TestReadRESPCommands_TruncatedTailDropped(t *testing.T) {
	// A complete command followed by a half-written one (evilginx was mid-write).
	in := respCmd("set", "sessions:1", "{}") + "*3\r\n$3\r\nset\r\n$12\r\nsession" // truncated
	cmds, err := readRESPCommands(strings.NewReader(in))
	if err != nil {
		t.Fatalf("a truncated tail must not be an error, got: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("parsed %d commands, want 1 (truncated tail dropped)", len(cmds))
	}
}

func TestReplaySessionState_LastWriteWinsAndDelete(t *testing.T) {
	in := respCmd("set", "sessions:1", "v1") +
		respCmd("set", "sessions:1", "v2") + // overwrites v1
		respCmd("set", "sessions:2", "x") +
		respCmd("del", "sessions:2") + // removes id 2
		respCmd("set", "sessions:0:id", "9") // counter key, must be ignored

	cmds, err := readRESPCommands(strings.NewReader(in))
	if err != nil {
		t.Fatalf("readRESPCommands: %v", err)
	}
	latest := replaySessionState(cmds)
	if len(latest) != 1 {
		t.Fatalf("surviving keys = %d, want 1 (got %v)", len(latest), latest)
	}
	if latest[1] != "v2" {
		t.Errorf("latest[1] = %q, want v2 (last write wins)", latest[1])
	}
	if _, ok := latest[2]; ok {
		t.Errorf("id 2 survived a DEL")
	}
}

func writeFixtureDB(t *testing.T, commands ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data.db")
	if err := os.WriteFile(path, []byte(strings.Join(commands, "")), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestFetchNewSessions_ParsesCredentialsAndTokens(t *testing.T) {
	s1 := `{"id":1,"phishlet":"faketarget","username":"alice","password":"pw1","tokens":{"a":"b"},"session_id":"S1","useragent":"UA","create_time":100,"update_time":200}`
	s2 := `{"id":2,"phishlet":"faketarget","tokens":{},"body_tokens":[{"x":1}],"session_id":"S2","create_time":101,"update_time":150}`
	path := writeFixtureDB(t,
		respCmd("set", "sessions:1", s1),
		respCmd("set", "sessions:0:id", "2"),
		respCmd("set", "sessions:2", s2),
	)

	sessions, err := NewRESPAOFSource(path).FetchNewSessions(0)
	if err != nil {
		t.Fatalf("FetchNewSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(sessions))
	}
	// Sorted ascending by ID.
	if sessions[0].ID != 1 || sessions[1].ID != 2 {
		t.Fatalf("sessions not sorted by ID: %d, %d", sessions[0].ID, sessions[1].ID)
	}

	a := sessions[0]
	if a.Username != "alice" || a.Password != "pw1" {
		t.Errorf("session 1 creds = %q/%q", a.Username, a.Password)
	}
	if !a.HasCredentials() {
		t.Errorf("session 1 HasCredentials() = false, want true")
	}
	if !a.TokensPresent {
		t.Errorf("session 1 TokensPresent = false, want true")
	}

	b := sessions[1]
	if b.HasCredentials() {
		t.Errorf("session 2 HasCredentials() = true, want false")
	}
	if b.TokensPresent {
		t.Errorf("session 2 TokensPresent = true, want false (tokens were {})")
	}
	if !b.BodyTokensPresent {
		t.Errorf("session 2 BodyTokensPresent = false, want true")
	}
	if !b.HasAnyCapture() {
		t.Errorf("session 2 HasAnyCapture() = false, want true (it has body tokens)")
	}
}

func TestDumpSchema_SummarizesSessions(t *testing.T) {
	s1 := `{"id":1,"username":"alice","password":"pw"}`
	s2 := `{"id":2,"username":"bob","password":"pw"}`
	path := writeFixtureDB(t,
		respCmd("set", "sessions:1", s1),
		respCmd("set", "sessions:2", s2),
	)

	out, err := NewRESPAOFSource(path).DumpSchema()
	if err != nil {
		t.Fatalf("DumpSchema: %v", err)
	}
	if !strings.Contains(out, "format: RESP/AOF") {
		t.Errorf("DumpSchema output missing format line:\n%s", out)
	}
	if !strings.Contains(out, "distinct session ids present: 2") {
		t.Errorf("DumpSchema did not report 2 distinct sessions:\n%s", out)
	}
}

func TestFetchNewSessions_MissingFileErrors(t *testing.T) {
	_, err := NewRESPAOFSource(filepath.Join(t.TempDir(), "absent.db")).FetchNewSessions(0)
	if err == nil {
		t.Fatalf("FetchNewSessions on a missing file should error")
	}
}

func TestJSONNonEmpty(t *testing.T) {
	empty := []string{"", "null", "{}", "[]", `""`}
	for _, s := range empty {
		if jsonNonEmpty(json.RawMessage(s)) {
			t.Errorf("jsonNonEmpty(%q) = true, want false", s)
		}
	}
	nonEmpty := []string{`{"a":1}`, `[1]`, `"x"`}
	for _, s := range nonEmpty {
		if !jsonNonEmpty(json.RawMessage(s)) {
			t.Errorf("jsonNonEmpty(%q) = false, want true", s)
		}
	}
}

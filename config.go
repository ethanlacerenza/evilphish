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
	"sync"
	"time"
)

// Settings holds every tunable for the bridge. It is the serializable part
// of the configuration (loaded from / saved to a JSON file). Everything that
// used to be edited by hand in config.json is now editable at runtime from
// the interactive shell (see terminal.go), which writes the file back
// automatically on every change — the JSON file is just the persistence
// layer now, not something you normally touch by hand.
type Settings struct {
	// --- evilginx side -----------------------------------------------
	EvilginxDBPath string `json:"evilginx_db_path"` // e.g. /root/.evilginx/data.db

	PollIntervalSeconds int `json:"poll_interval_seconds"`

	// --- correlation -------------------------------------------------
	RidQueryParam string `json:"rid_query_param"` // default "rid"

	// --- gophish side ------------------------------------------------
	GophishAPIBaseURL    string `json:"gophish_api_base_url"` // e.g. http://127.0.0.1:3333
	GophishAPIKey        string `json:"gophish_api_key"`
	GophishInsecureTLS   bool   `json:"gophish_insecure_tls"`
	CampaignCacheSeconds int    `json:"campaign_cache_seconds"`

	GophishPhishURL string `json:"gophish_phish_url"`

	FormFieldMapping map[string]string `json:"form_field_mapping"`

	SubmitUserAgentFallback string `json:"submit_user_agent_fallback"`
	SubmitInsecureTLS       bool   `json:"submit_insecure_tls"`

	// --- bookkeeping -------------------------------------------------
	StateFilePath string `json:"state_file_path"`
	DryRun        bool   `json:"dry_run"`
}

// Config wraps the settings with a lock so the background poller can read
// them while the interactive shell writes them, without a data race.
type Config struct {
	mu   sync.RWMutex
	s    Settings
	path string // where this config is persisted
}

func defaultSettings() Settings {
	return Settings{
		PollIntervalSeconds:  5,
		RidQueryParam:        "rid",
		CampaignCacheSeconds: 30,
		GophishAPIBaseURL:    "http://127.0.0.1:3333",
		GophishPhishURL:      "http://127.0.0.1:8080",
		EvilginxDBPath:       "/root/.evilginx/data.db",
		FormFieldMapping: map[string]string{
			"username": "{{username}}",
			"password": "{{password}}",
		},
		SubmitUserAgentFallback: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		StateFilePath:           "bridge-state.json",
		DryRun:                  true, // safe default: first run never writes into gophish
	}
}

// LoadConfig reads the JSON config if present, falling back to sane defaults
// for anything missing. A missing file is NOT an error: the bridge can be
// configured entirely from the interactive shell and will create the file on
// the first change.
func LoadConfig(path string) (*Config, error) {
	c := &Config{s: defaultSettings(), path: path}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil // no file yet — configure from the shell, we'll save it
		}
		return nil, fmt.Errorf("opening config %q: %w", path, err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	if err := dec.Decode(&c.s); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}
	if c.s.FormFieldMapping == nil {
		c.s.FormFieldMapping = map[string]string{}
	}
	return c, nil
}

// Ready reports whether the minimum required fields are set to actually run
// the bridge. Used to warn the user instead of crashing on startup.
func (c *Config) Ready() (bool, []string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var missing []string
	if c.s.EvilginxDBPath == "" {
		missing = append(missing, "evilginx db path")
	}
	if c.s.GophishAPIBaseURL == "" {
		missing = append(missing, "gophish api url")
	}
	if c.s.GophishAPIKey == "" {
		missing = append(missing, "gophish api key")
	}
	return len(missing) == 0, missing
}

// Snapshot returns a detached copy of the settings (with its own map) that
// the poller can read freely without holding the lock.
func (c *Config) Snapshot() Settings {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cp := c.s
	cp.FormFieldMapping = make(map[string]string, len(c.s.FormFieldMapping))
	for k, v := range c.s.FormFieldMapping {
		cp.FormFieldMapping[k] = v
	}
	return cp
}

// Save writes the current settings back to disk (0600).
func (c *Config) Save() error {
	c.mu.RLock()
	b, err := json.MarshalIndent(c.s, "", "  ")
	path := c.path
	c.mu.RUnlock()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func (c *Config) Path() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.path }

// --- live reads used on every poll tick ------------------------------

func (c *Config) Interval() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.s.PollIntervalSeconds <= 0 {
		return 5 * time.Second
	}
	return time.Duration(c.s.PollIntervalSeconds) * time.Second
}

func (c *Config) IsDryRun() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.s.DryRun }

// --- setters (each persists immediately) ------------------------------
// They return (changedConnection) so the caller can tell the user whether a
// poller restart is needed for the change to take effect.

func (c *Config) setAndSave(mutate func(*Settings)) error {
	c.mu.Lock()
	mutate(&c.s)
	c.mu.Unlock()
	return c.Save()
}

func (c *Config) SetDryRun(v bool) error {
	return c.setAndSave(func(s *Settings) { s.DryRun = v })
}
func (c *Config) SetPollInterval(sec int) error {
	return c.setAndSave(func(s *Settings) { s.PollIntervalSeconds = sec })
}
func (c *Config) SetRidParam(v string) error {
	return c.setAndSave(func(s *Settings) { s.RidQueryParam = v })
}
func (c *Config) SetEvilginxDBPath(v string) error {
	return c.setAndSave(func(s *Settings) { s.EvilginxDBPath = v })
}
func (c *Config) SetStateFilePath(v string) error {
	return c.setAndSave(func(s *Settings) { s.StateFilePath = v })
}
func (c *Config) SetGophishAPIBaseURL(v string) error {
	return c.setAndSave(func(s *Settings) { s.GophishAPIBaseURL = v })
}
func (c *Config) SetGophishAPIKey(v string) error {
	return c.setAndSave(func(s *Settings) { s.GophishAPIKey = v })
}
func (c *Config) SetGophishPhishURL(v string) error {
	return c.setAndSave(func(s *Settings) { s.GophishPhishURL = v })
}
func (c *Config) SetGophishInsecureTLS(v bool) error {
	return c.setAndSave(func(s *Settings) { s.GophishInsecureTLS = v })
}
func (c *Config) SetSubmitInsecureTLS(v bool) error {
	return c.setAndSave(func(s *Settings) { s.SubmitInsecureTLS = v })
}
func (c *Config) SetSubmitUserAgent(v string) error {
	return c.setAndSave(func(s *Settings) { s.SubmitUserAgentFallback = v })
}
func (c *Config) SetCampaignCache(sec int) error {
	return c.setAndSave(func(s *Settings) { s.CampaignCacheSeconds = sec })
}

// SetFormField sets (or, with empty value, deletes) one form-field mapping.
func (c *Config) SetFormField(field, tmpl string) error {
	return c.setAndSave(func(s *Settings) {
		if s.FormFieldMapping == nil {
			s.FormFieldMapping = map[string]string{}
		}
		if tmpl == "" {
			delete(s.FormFieldMapping, field)
		} else {
			s.FormFieldMapping[field] = tmpl
		}
	})
}

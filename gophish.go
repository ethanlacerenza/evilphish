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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Campaign mirrors the subset of gophish's campaign JSON we need.
type Campaign struct {
	Id      int64            `json:"id"`
	Name    string           `json:"name"`
	URL     string           `json:"url"`
	Results []CampaignResult `json:"results"`
}

// CampaignResult mirrors gophish's per-recipient result. gophish serializes
// its internal "RId" tracking token (the value that appears as ?rid=... in
// every tracking link) as the JSON field "id" — NOT the numeric database id.
type CampaignResult struct {
	RId       string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Status    string `json:"status"`
}

type ridLocation struct {
	CampaignID  int64
	CampaignURL string
	Result      CampaignResult
}

// GophishClient talks only to gophish's existing, documented interfaces.
type GophishClient struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client

	SubmitHTTPClient *http.Client

	mu          sync.Mutex
	ridIndex    map[string]ridLocation
	lastRefresh time.Time
	cacheTTL    time.Duration

	refreshMu sync.Mutex // serializes refreshIndex so concurrent misses coalesce
}

func NewGophishClient(s Settings) *GophishClient {
	apiTransport := &http.Transport{}
	if s.GophishInsecureTLS {
		// #nosec G402 -- explicit operator opt-in for a self-signed gophish admin cert.
		apiTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	submitTransport := &http.Transport{}
	if s.SubmitInsecureTLS {
		// #nosec G402 -- explicit operator opt-in for a self-signed phish-server cert.
		submitTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	ttl := time.Duration(s.CampaignCacheSeconds) * time.Second
	if ttl <= 0 {
		ttl = 30 * time.Second
	}

	return &GophishClient{
		BaseURL:          strings.TrimRight(s.GophishAPIBaseURL, "/"),
		APIKey:           s.GophishAPIKey,
		HTTPClient:       &http.Client{Timeout: 10 * time.Second, Transport: apiTransport},
		SubmitHTTPClient: &http.Client{Timeout: 10 * time.Second, Transport: submitTransport},
		ridIndex:         map[string]ridLocation{},
		cacheTTL:         ttl,
	}
}

func (g *GophishClient) apiGet(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, g.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+g.APIKey)
	resp, err := g.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gophish API %s returned %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Test performs a lightweight authenticated call to verify the admin API is
// reachable and the API key is accepted. Used by the shell "test" command.
func (g *GophishClient) Test() (int, error) {
	var campaigns []Campaign
	if err := g.apiGet("/api/campaigns/", &campaigns); err != nil {
		return 0, err
	}
	return len(campaigns), nil
}

// refreshIndex rebuilds the rid -> campaign/recipient map from gophish's admin
// API. It costs one call to list campaigns plus one per campaign, so it is
// serialized and coalesced: if another caller already refreshed while this one
// waited for the lock, and the cache is still fresh, it returns without
// repeating the sweep. This bounds the API load to roughly one refresh per
// cacheTTL even under a burst of new captures.
func (g *GophishClient) refreshIndex() error {
	g.refreshMu.Lock()
	defer g.refreshMu.Unlock()

	g.mu.Lock()
	fresh := len(g.ridIndex) > 0 && time.Since(g.lastRefresh) <= g.cacheTTL
	g.mu.Unlock()
	if fresh {
		return nil
	}

	var campaigns []Campaign
	if err := g.apiGet("/api/campaigns/", &campaigns); err != nil {
		return err
	}
	newIndex := make(map[string]ridLocation, 64)
	for _, c := range campaigns {
		var full Campaign
		if err := g.apiGet(fmt.Sprintf("/api/campaigns/%d", c.Id), &full); err != nil {
			continue
		}
		for _, r := range full.Results {
			newIndex[r.RId] = ridLocation{CampaignID: full.Id, CampaignURL: full.URL, Result: r}
		}
	}
	g.mu.Lock()
	g.ridIndex = newIndex
	g.lastRefresh = time.Now()
	g.mu.Unlock()
	return nil
}

// ResolveRID returns which campaign/recipient a captured rid belongs to.
func (g *GophishClient) ResolveRID(rid string) (ridLocation, bool, error) {
	g.mu.Lock()
	loc, ok := g.ridIndex[rid]
	stale := time.Since(g.lastRefresh) > g.cacheTTL
	g.mu.Unlock()

	if ok && !stale {
		return loc, true, nil
	}
	if err := g.refreshIndex(); err != nil {
		return loc, ok, err
	}
	g.mu.Lock()
	loc, ok = g.ridIndex[rid]
	g.mu.Unlock()
	return loc, ok, nil
}

// SubmitCapturedLogin performs the same HTTP request a victim's browser would
// make when submitting gophish's own landing page form.
func (g *GophishClient) SubmitCapturedLogin(campaignURL, rid, ridParam, userAgent string, fields url.Values) error {
	u, err := url.Parse(campaignURL)
	if err != nil {
		return fmt.Errorf("invalid campaign URL %q: %w", campaignURL, err)
	}
	q := u.Query()
	q.Set(ridParam, rid)
	u.RawQuery = q.Encode()
	target := u.String()

	// 1) GET first — registers "Clicked Link" in gophish.
	if getReq, gerr := http.NewRequest(http.MethodGet, target, nil); gerr == nil {
		if userAgent != "" {
			getReq.Header.Set("User-Agent", userAgent)
		}
		if gresp, derr := g.SubmitHTTPClient.Do(getReq); derr == nil {
			gresp.Body.Close()
		}
	}

	// 2) POST the captured fields — registers "Submitted Data".
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(fields.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := g.SubmitHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("posting to gophish landing page: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("gophish landing page returned %s", resp.Status)
	}
	return nil
}

// End-to-end functional tests for the lab fake-target server. They exercise the
// real HTTP handlers in-process (httptest), covering the login -> session cookie
// -> dashboard flow that evilginx proxies and the bridge relies on.
package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// noRedirectClient returns an *http.Client that never follows redirects, so a
// test can inspect the raw 3xx response and its Set-Cookie headers.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestFakeTarget_ValidLoginSetsSessionAndReachesDashboard(t *testing.T) {
	ts := httptest.NewServer(newMux())
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{Jar: jar} // follows redirects, keeps cookies

	resp, err := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"labuser"},
		"password": {"labpass"},
	})
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	// The 302 to /dashboard is followed, carrying the session cookie, so the
	// final response is the dashboard with HTTP 200.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("after login+redirect: status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "logged in") {
		t.Fatalf("expected dashboard body, got: %q", string(body))
	}

	// A session cookie must have been issued for the server's origin.
	u, _ := url.Parse(ts.URL)
	var gotSession bool
	for _, c := range jar.Cookies(u) {
		if c.Name == "session" && c.Value != "" {
			gotSession = true
		}
	}
	if !gotSession {
		t.Fatalf("no non-empty 'session' cookie was set after a valid login")
	}
}

func TestFakeTarget_EmptyCredentialsRejected(t *testing.T) {
	ts := httptest.NewServer(newMux())
	defer ts.Close()

	client := noRedirectClient()
	resp, err := client.PostForm(ts.URL+"/login", url.Values{
		"username": {""},
		"password": {""},
	})
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	// Empty creds re-serve the login page (200) and must NOT set a session.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("empty creds: status = %d, want 200 (login page re-served)", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "session" {
			t.Fatalf("a 'session' cookie was set for empty credentials")
		}
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<form") {
		t.Fatalf("expected the login form to be re-served, got: %q", string(body))
	}
}

func TestFakeTarget_DashboardWithoutCookieRedirectsToLogin(t *testing.T) {
	ts := httptest.NewServer(newMux())
	defer ts.Close()

	client := noRedirectClient()
	resp, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /dashboard without cookie: status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("GET /dashboard redirect Location = %q, want /login", loc)
	}
}

func TestFakeTarget_RootRedirectsToLogin(t *testing.T) {
	ts := httptest.NewServer(newMux())
	defer ts.Close()

	client := noRedirectClient()
	resp, err := client.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET / status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("GET / redirect Location = %q, want /login", loc)
	}
}

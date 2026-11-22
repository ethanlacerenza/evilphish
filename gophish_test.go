package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func newTestClient(srvURL string) *GophishClient {
	return NewGophishClient(Settings{
		GophishAPIBaseURL:    srvURL,
		GophishAPIKey:        "testkey",
		CampaignCacheSeconds: 30,
	})
}

func TestGophishTest_SendsBearerAndCountsCampaigns(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/campaigns/" {
			gotAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":1},{"id":2}]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	n, err := newTestClient(srv.URL).Test()
	if err != nil {
		t.Fatalf("Test(): %v", err)
	}
	if n != 2 {
		t.Errorf("campaign count = %d, want 2", n)
	}
	if gotAuth != "Bearer testkey" {
		t.Errorf("Authorization header = %q, want \"Bearer testkey\"", gotAuth)
	}
}

func TestResolveRID_MapsRidToCampaignRecipient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/campaigns/":
			// list: ids only; full detail fetched per campaign
			_, _ = w.Write([]byte(`[{"id":10}]`))
		case "/api/campaigns/10":
			_, _ = w.Write([]byte(`{"id":10,"url":"https://lure.example/landing","results":[{"id":"RID123","email":"bob@corp.tld","status":"Email Sent"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)

	loc, ok, err := client.ResolveRID("RID123")
	if err != nil {
		t.Fatalf("ResolveRID: %v", err)
	}
	if !ok {
		t.Fatalf("ResolveRID(RID123) not found, want found")
	}
	if loc.CampaignID != 10 {
		t.Errorf("CampaignID = %d, want 10", loc.CampaignID)
	}
	if loc.CampaignURL != "https://lure.example/landing" {
		t.Errorf("CampaignURL = %q", loc.CampaignURL)
	}
	if loc.Result.Email != "bob@corp.tld" {
		t.Errorf("recipient email = %q, want bob@corp.tld", loc.Result.Email)
	}

	if _, ok, _ := client.ResolveRID("does-not-exist"); ok {
		t.Errorf("ResolveRID(unknown) = found, want not found")
	}
}

type submittedRequest struct {
	method      string
	rid         string
	contentType string
	userAgent   string
	form        url.Values
}

func TestSubmitCapturedLogin_PostsFieldsWithRid(t *testing.T) {
	posts := make(chan submittedRequest, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Method == http.MethodPost {
			posts <- submittedRequest{
				method:      r.Method,
				rid:         r.URL.Query().Get("rid"),
				contentType: r.Header.Get("Content-Type"),
				userAgent:   r.Header.Get("User-Agent"),
				form:        r.PostForm,
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	err := client.SubmitCapturedLogin(
		srv.URL+"/landing",
		"RID9",
		"rid",
		"UA/1.0",
		url.Values{"username": {"bob"}, "password": {"pw"}},
	)
	if err != nil {
		t.Fatalf("SubmitCapturedLogin: %v", err)
	}

	select {
	case got := <-posts:
		if got.rid != "RID9" {
			t.Errorf("rid query param = %q, want RID9", got.rid)
		}
		if got.form.Get("username") != "bob" || got.form.Get("password") != "pw" {
			t.Errorf("posted form = %v, want username=bob password=pw", got.form)
		}
		if got.contentType != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got.contentType)
		}
		if got.userAgent != "UA/1.0" {
			t.Errorf("User-Agent = %q, want UA/1.0", got.userAgent)
		}
	default:
		t.Fatalf("no POST reached the landing page")
	}
}

func TestSubmitCapturedLogin_ErrorStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := newTestClient(srv.URL).SubmitCapturedLogin(
		srv.URL+"/landing", "RID1", "rid", "", url.Values{"username": {"x"}},
	)
	if err == nil {
		t.Fatalf("expected an error when the landing page returns 500")
	}
}

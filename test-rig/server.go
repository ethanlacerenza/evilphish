// Fake "origin" site used ONLY as a lab target so you can build and test
// an evilginx phishlet + the gophish/evilginx bridge end to end, without
// ever touching a real third-party login system.
//
// It accepts any non-empty username/password, sets a session cookie, and
// serves a tiny "dashboard" page — enough for evilginx to have something
// real to proxy, capture credentials from, and capture a session cookie
// from.
//
// Usage with its own TLS (self-signed cert):
//
//	go run server.go -addr :8443 -cert cert.pem -key key.pem
//
// Generate a quick self-signed cert for that mode with:
//
//	openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
//	  -days 365 -subj "/CN=www.faketarget.lab" \
//	  -addext "subjectAltName=DNS:www.faketarget.lab"
//
// Usage behind Caddy (or any reverse proxy doing TLS for you) — plain
// HTTP, no cert needed here:
//
//	go run server.go -plain-http -addr 127.0.0.1:8080
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	"net/http"
)

const loginPage = `<!DOCTYPE html>
<html><head><title>Fake Target - Login</title></head>
<body>
  <h1>Fake Target (lab only)</h1>
  <form method="POST" action="/login">
    <input type="text" name="username" placeholder="username"><br>
    <input type="password" name="password" placeholder="password"><br>
    <button type="submit">Log in</button>
  </form>
</body></html>`

const dashboardPage = `<!DOCTYPE html>
<html><head><title>Fake Target - Dashboard</title></head>
<body>
  <h1>Welcome, you are "logged in" (lab test target)</h1>
</body></html>`

func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	certFile := flag.String("cert", "cert.pem", "TLS certificate (ignored with -plain-http)")
	keyFile := flag.String("key", "key.pem", "TLS private key (ignored with -plain-http)")
	plainHTTP := flag.Bool("plain-http", false, "serve plain HTTP instead of TLS (use this when Caddy/another reverse proxy terminates TLS for you)")
	flag.Parse()

	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte(loginPage))
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			user := r.FormValue("username")
			pass := r.FormValue("password")
			if user == "" || pass == "" {
				w.Write([]byte(loginPage))
				return
			}
			log.Printf("fake target: login attempt username=%q (lab test data, not a real account)", user)
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    randomToken(),
				Path:     "/",
				HttpOnly: true,
			})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("session"); err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.Write([]byte(dashboardPage))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})

	if *plainHTTP {
		log.Printf("fake lab target listening on %s (plain HTTP, expecting Caddy/a proxy in front)", *addr)
		log.Fatal(http.ListenAndServe(*addr, mux))
		return
	}

	log.Printf("fake lab target listening on %s (TLS)", *addr)
	log.Fatal(http.ListenAndServeTLS(*addr, *certFile, *keyFile, mux))
}

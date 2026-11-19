<p align="center">
  <img src="media/img/evilphish_logo.png" width="500" alt="evilphish logo">
</p>

# Evilphish

An external bridge, written in Go, that forwards credentials captured by
**evilginx3** into **gophish** so they appear as native **Submitted Data**
on the matching campaign recipient — **without modifying the source code of
either tool**.

For **authorized** engagements only (red team / phishing assessments with
explicit written permission). Do not use it against systems you are not
authorized to test.

---

## What it does

1. Reads evilginx's `data.db` **read-only**. That file is not SQLite or
   BoltDB — it is a Redis-protocol (RESP) append-only command log. The
   bridge parses it directly (no external dependency, no Redis client, no
   writes to the file).
2. For every captured session that has plaintext credentials, it extracts
   the gophish tracking id (`rid`) from the lure URL (`landing_url`).
3. It asks gophish's admin API which campaign/recipient that `rid` belongs
   to (read-only).
4. It replays the capture against gophish's **phish server** (a `GET` to
   register *Clicked Link*, then a `POST` to register *Submitted Data*),
   exactly as a browser would. gophish's own landing-page handler is what
   records the event — nothing in gophish is patched or bypassed.

Neither evilginx nor gophish is modified. The bridge talks to evilginx
only through its file (read), and to gophish only over HTTP on localhost.

---

## Validated architecture

This is the single-host layout the bridge was built and tested against.
All services run on one box; the bridge talks to gophish over loopback.

```
          Victim's browser
                 |
                 |  email link: https://<lure-host>/<lure-path>?rid=XXXX
                 v
        +------------------+        proxies login to the real/origin site
        |    evilginx      |  ---->  (your target, or the test rig below)
        |  :443  (lures)   |
        +------------------+
                 |
       captures username/password/cookies into
                 |
          ~/.evilginx/data.db   (RESP/AOF log)
                 |
                 |  read-only poll
                 v
        +------------------+     GET+POST  http://127.0.0.1:8080/?rid=XXXX
        |   this bridge    |  ------------------------------------------>  +----------------+
        +------------------+                                               | gophish        |
                 ^                                                         | phish server   |
                 |  resolve rid -> recipient (read-only)                   |  :8080         |
                 +-------- http://127.0.0.1:3332/api/ --------------------> | admin  :3332   |
                                                                           +----------------+
                                                                                   |
                                                                      records "Submitted Data"
                                                                       in gophish.db (events)
```

Reference port map (adjust to your own):

| Service                    | Address              | Notes                                             |
|----------------------------|----------------------|---------------------------------------------------|
| evilginx (lures / MITM)    | `:443`               | email links point here                            |
| gophish admin API          | `127.0.0.1:3332`     | plain HTTP; the bridge talks here directly        |
| gophish phish server       | `0.0.0.0:8080`       | plain HTTP; the bridge POSTs captures here         |
| (optional) Caddy for admin | `:3333 -> 3332`      | TLS front for the admin UI only                   |

> **Important:** the bridge talks to gophish directly over loopback
> (`127.0.0.1:3332` for the API, `127.0.0.1:8080` for the phish server).
> Do **not** point it at a public HTTPS address fronted by a reverse proxy
> — the proxy's certificate is issued for the public hostname, not for
> `127.0.0.1`, which causes `tls: internal error`. Loopback + plain HTTP is
> both simpler and more reliable for a co-located bridge.

---

## Prerequisites

- Go 1.21+ to build (`go version`).
- evilginx3 and gophish already installed and running on the same host.
- A gophish **API key** (gophish UI → Settings).

No other dependencies: the bridge uses only the Go standard library.

---

## Build

```bash
go build -o evilphish .
```

If your Go is older than what `go.mod` requests, lower the version line in
`go.mod` to match your installed Go (e.g. `go 1.21`); the code uses no
recent-only features.

---

## Configure

```bash
cp config.example.json config.json
```

Edit `config.json`:

| Key                        | What to set                                                                 |
|----------------------------|------------------------------------------------------------------------------|
| `evilginx_db_path`         | Path to evilginx's `data.db` (usually `/root/.evilginx/data.db`).            |
| `gophish_api_base_url`     | gophish admin, direct over loopback: `http://127.0.0.1:3332`.               |
| `gophish_api_key`          | Your gophish API key.                                                        |
| `gophish_phish_url`        | gophish phish server, direct over loopback: `http://127.0.0.1:8080`.        |
| `rid_query_param`          | The tracking param name (gophish default: `rid`).                            |
| `form_field_mapping`       | Form fields to POST (see below).                                             |
| `dry_run`                  | `true` to simulate (log only), `false` to actually inject.                   |
| `poll_interval_seconds`    | How often to re-scan `data.db` (default 5).                                  |
| `state_file_path`          | Where the bridge remembers what it already forwarded.                        |

### Form field mapping

The left side is the form field name POSTed to gophish; the right side is a
template filled from the captured session. gophish stores every POSTed
field in Submitted Data, so you can carry more than just credentials:

```json
"form_field_mapping": {
  "username": "{{username}}",
  "password": "{{password}}",
  "tokens":   "{{tokens}}"
}
```

Available placeholders: `{{username}}`, `{{password}}`, `{{tokens}}` (raw
captured cookies/auth tokens as JSON), `{{session_id}}`, `{{phishlet}}`,
`{{remote_addr}}`, `{{update_time}}`.

> Match the left-side field names to the `<input name="...">` fields your
> gophish **Landing Page** expects, and make sure that landing page has
> **Capture Submitted Data** (and **Capture Passwords**) enabled.

---

## One-time gophish setup

1. **Landing Page** — create one with **Capture Submitted Data** and
   **Capture Passwords** enabled. (Its HTML content is irrelevant to the
   bridge; the bridge only needs the campaign's capture to be on.)
2. **Campaign URL** — set the campaign's **URL** to your **evilginx lure**,
   e.g. `https://login.example.com/aBcD1234`. gophish appends `?rid=...`
   automatically, so the email link sends the victim straight to evilginx
   with the tracking id embedded. evilginx records that `rid` inside
   `landing_url`, which is what the bridge correlates on.

> With this layout gophish will show **Email Sent** and (via the bridge)
> **Clicked Link** + **Submitted Data**. The victim never touches gophish's
> phish server directly — the bridge replays the click and the submission
> on their behalf.

---

## Run

Always start in dry-run to confirm correlation and the POST target:

```bash
# config.json has "dry_run": true
./evilphish --config config.json
```

You should see lines like:

```
[DRY RUN] would POST to http://127.0.0.1:8080?rid=XXXX campaign="user@org"(175) recipient=user@org fields=map[password:[...] tokens:[...] username:[...]]
```
<img width="917" height="110" alt="image" src="https://github.com/user-attachments/assets/e12932aa-9373-494f-8f23-fbfc3d7067fb" />

When the target and recipient look right, go live:

```json
"dry_run": false
```

```bash
rm -f bridge-state.json      # so already-captured sessions get forwarded once
./evilphish --config config.json
```

Successful forwards log:

```
session 212: forwarded capture for recipient user@org into campaign 175
```

Check gophish → that campaign → the recipient's timeline: **Clicked Link**
and **Submitted Data** (with the captured fields) should appear.


<img width="987" height="456" alt="image" src="https://github.com/user-attachments/assets/c541f34f-b82c-4015-bd08-1970e4536f70" />


### Run it as a service (optional)

```ini
# /etc/systemd/system/evilphish.service
[Unit]
Description=evilphish gophish-evilginx bridge
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/evilphish
ExecStart=/root/evilphish/evilphish --config /root/evilphish/config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now evilphish
journalctl -u evilphish -f
```

---

## How it works internally

- **`-dump-schema`** parses `data.db` and prints a summary (format, command
  count, a few recent sessions). Use it to sanity-check parsing on your
  host: `./evilphish --config config.json -dump-schema`.
- **De-duplication:** evilginx updates the same session row several times
  (first the landing visit with empty fields, then username/password, then
  tokens). The bridge re-reads the whole log every poll and decides what to
  forward using each session's `session_id` + `update_time`, so a row that
  first appears empty is still forwarded once it fills in — and the final
  token-bearing update is forwarded too. Because each POST is a separate
  event, you may see two Submitted Data entries for one victim (credentials
  only, then credentials + tokens); the later one is complete.
- **State:** `bridge-state.json` records what was already forwarded so a
  restart doesn't re-send. Delete it to force a full re-scan.
- **Tokens:** the authoritative copy of the session cookies always lives in
  evilginx (`sessions` in its console, or `data.db`); that is what you use
  to actually import a session. The `tokens` field in gophish is for
  centralized reporting/visibility.

Reading captured data straight from gophish's DB (optional):

```bash
sqlite3 gophish.db "SELECT campaign_id, email, time, details FROM events WHERE message='Submitted Data' ORDER BY time DESC LIMIT 5;"
```

---

## Testing safely (no real target)

`test-rig/` contains a self-contained fake login target and a matching
phishlet so you can exercise the whole chain
(gophish → evilginx → bridge → gophish) without touching any third-party
service. See `test-rig/` — in short:

1. Run the fake target (plain HTTP, put TLS in front with your own proxy if
   needed):
   ```bash
   cd test-rig
   go build -o faketarget server.go
   ./faketarget -plain-http -addr 127.0.0.1:9090
   ```
2. Edit `test-rig/phishlets/faketarget.yaml` so every `domain:` points at
   the hostname that serves the fake target, then copy it into evilginx's
   `phishlets/` directory.
3. In evilginx: `phishlets hostname faketarget <your-lure-host>`,
   `phishlets enable faketarget`, `lures create faketarget`,
   `lures get-url <id>`.
4. Point a gophish test campaign's URL at that lure, launch it, click the
   link, and log in with any non-empty username/password. Watch the bridge
   and gophish.

The fake target accepts any non-empty credentials, sets a `session` cookie,
and serves a trivial dashboard — enough for evilginx to proxy, capture
credentials, and capture a session cookie.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `failed to load phishlet ... login: domain must contain ...` | In the phishlet, `login.domain` and `auth_tokens.domain` must equal `orig_sub` + `domain` from `proxy_hosts` (the full origin host), not the bare domain. |
| Phishlet not listed in evilginx | evilginx keys phishlets by **file name**, not the `name:` field. Use the file name in `phishlets ...` commands, and restart evilginx after copying the file. |
| `phishlet hostname must end with '<x>'` | The lure hostname must be a subdomain of evilginx's configured base `domain` (see `config` in evilginx). |
| Lure URL shows nothing / hangs | The lure host must resolve (DNS A record) to evilginx's IP, and evilginx must own port 443. A reverse proxy also on 443 will collide. |
| `tls: internal error` resolving rid | The bridge is hitting gophish over HTTPS via a reverse proxy whose cert doesn't match `127.0.0.1`. Point `gophish_api_base_url` at the admin **directly** over loopback plain HTTP (`http://127.0.0.1:3332`). |
| `no "rid" param found in landing_url` | That session came from visiting the lure **directly**, not via a gophish email. Only sessions reached through a gophish tracking link carry a `rid`. |
| Dry run looks right but nothing in gophish | Dry run never sends. Set `"dry_run": false`, delete `bridge-state.json`, re-run. |
| Credentials appear but tokens don't | Add `"tokens": "{{tokens}}"` to `form_field_mapping`. |

---

## Files

- `main.go` — poll loop, rid correlation, forwarding logic
- `config.go` — configuration struct and defaults
- `evilginx.go` — read-only RESP/AOF parser for evilginx's `data.db`
- `gophish.go` — gophish admin API client + GET/POST into the phish server
- `state.go` — forwarded-state persistence (idempotency)
- `config.example.json` — configuration template
- `test-rig/` — fake login target + phishlet for safe end-to-end testing


## License
This project is licensed under the GNU General Public License v3.0.
See the [LICENSE](LICENSE) file for the full text.
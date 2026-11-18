# Test rig — fake login target + phishlet

A self-contained target so you can test the whole
gophish → evilginx → bridge chain **without touching any real third-party
login system**. It impersonates no brand: it's a plain login page of your
own.

## 1. Pick a hostname you control

You need a hostname **you own** that resolves to the box serving the fake
target (it can be the same box as evilginx). The phishlet placeholder is
`fake-target.example.com:8443` — replace it everywhere in
`phishlets/faketarget.yaml` with your real origin host.

## 2. Run the fake target

With its own TLS (self-signed):

```bash
go build -o faketarget server.go
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
  -days 365 -subj "/CN=<your-host>" -addext "subjectAltName=DNS:<your-host>"
./faketarget -addr :8443 -cert cert.pem -key key.pem
```

Or behind a reverse proxy that terminates TLS for you (plain HTTP backend):

```bash
go build -o faketarget server.go
./faketarget -plain-http -addr 127.0.0.1:9090
# then proxy https://<your-host> -> 127.0.0.1:9090
```

The fake target accepts any non-empty username/password, sets a `session`
cookie, and serves a trivial dashboard.

## 3. Install the phishlet

Edit `phishlets/faketarget.yaml` first: set every `domain:` (in
`proxy_hosts`, `auth_tokens`, `login`) to your origin host. `login.domain`
and `auth_tokens.domain` must equal `orig_sub` + `domain` from
`proxy_hosts`.

```bash
cp phishlets/faketarget.yaml /path/to/evilginx/phishlets/
```

In evilginx (phishlets are keyed by **file name** = `faketarget`):

```
phishlets hostname faketarget <your-lure-host>
phishlets enable faketarget
lures create faketarget
lures get-url <id>
```

## 4. Wire gophish and test

Set a gophish test campaign's **URL** to the lure URL from
`lures get-url`. Launch the campaign to a test group (just your own
address), click the email link, and log in with any non-empty
credentials. Watch the bridge log and the gophish campaign timeline.

## Files

- `server.go` — fake login target (login + session cookie + dashboard)
- `phishlets/faketarget.yaml` — evilginx phishlet pointing at the fake target

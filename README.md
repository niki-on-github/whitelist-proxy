# whitelist-proxy

A small reverse proxy that exposes an upstream HTTP service to the public internet
behind an **IP whitelist**, with a web UI to manage the whitelist and inspect all
access attempts.

It is designed to sit behind a **Tailscale Funnel** configured with the
[PROXY protocol](https://tailscale.com/docs/reference/tailscale-cli/funnel#use-the-proxy-protocol)
so the real client IP is available:

```sh
tailscale funnel --proxy-protocol=2 --tls-terminated-tcp=443 tcp://127.0.0.1:8080
```

Without PROXY protocol (i.e. when reached directly), Funnel only exposes `127.0.0.1`,
which makes IP-based allow-listing useless.

## How it works

- **Proxy port** `8080` — accepts connections and **requires** a valid PROXY
  protocol header (fail-closed). Requests from an IP/CIDR on the whitelist are
  reverse-proxied to `UPSTREAM`; all others get a generic `403` OpenAI-compatible
  error (`access denied`) that reveals nothing about the whitelist, allowed paths,
  or the client IP. An empty whitelist denies everything. With `ALLOW_PATHS` set,
  only paths under the listed prefixes are proxied; anything else is also denied
  with the same generic `403`. The real reason (`ip`/`path`), client IP, method and
  path are written to the container log and the admin UI, never to the caller.
  Streaming/SSE responses are flushed through. `/healthz` always returns `200` and
  is not logged as an attempt.
- **Admin port** `8081` — basic-auth protected web UI + JSON API to manage the
  whitelist and to browse access attempts (timestamp, client IP, allow/deny with
  reason, method, path, status, duration).
- The whitelist (allow list) is stored in a single SQLite database. Whitelist
  entries can optionally be restricted to a day list (`days`) and/or a time
  window (`start`/`end`, `HH:MM`, `start < end`), evaluated in the configured
  `TIMEZONE`. If any matching entry has no restriction (or is currently in its
  window), access is allowed; otherwise it is denied with reason `time`. The
  **access log lives only in RAM** as a bounded circular buffer
  (`LOG_BUFFER_SIZE`, default 10000 entries) and is **never persisted** — it is
  lost on restart.

## Configuration (environment)

| Variable | Default | Description |
|---|---|---|
| `UPSTREAM` | *(required)* | Upstream URL, e.g. `http://llama-cpp-webui.apps:8080` |
| `ADMIN_USER` | *(required)* | Basic auth user for the admin UI |
| `ADMIN_PASSWORD` | *(required)* | Basic auth password for the admin UI |
| `PROXY_LISTEN` | `127.0.0.1:8080` | Proxy listener address |
| `ADMIN_LISTEN` | `127.0.0.1:8081` | Admin listener address |
| `DB_PATH` | `data/whitelist-proxy.db` | SQLite database file (whitelist only) |
| `TIMEZONE` | `UTC` | IANA location used to evaluate whitelist day/time windows |
| `LOG_BUFFER_SIZE` | `10000` | Number of access attempts kept in the in-memory ring buffer; oldest entries are evicted when full |
| `ACCEPT_PROXY` | `true` | Require a valid PROXY protocol header on the proxy port |
| `ALLOW_PATHS` | *(empty)* | Comma-separated path prefixes that may be proxied (e.g. `/v1`). Empty = all paths allowed. Other paths are denied with the same generic `403` and logged as denied with reason `path`. |

## Admin API

All endpoints require basic auth.

- `GET /api/whitelist` — list entries
- `POST /api/whitelist` — add entry `{"entry": "IP or CIDR", "comment": "...", "days": [1,2,3], "start": "09:00", "end": "17:00"}` (`days` numbers 1=Monday … 7=Sunday; `days`, `start`, `end` optional)
- `DELETE /api/whitelist/{id}` — remove entry
- `GET /api/attempts?page=&limit=&allowed=&path=` — access attempts (in-memory ring buffer, paginated, filterable by allow status and path)
- `POST /api/attempts/{id}/allow` — one-click whitelist the IP of a denied attempt; optional JSON body `{"comment": "...", "days": [1,2,3], "start": "09:00", "end": "17:00"}` to attach a comment and/or schedule, empty body allows without a window

## Security notes

- The proxy port rejects connections without a valid PROXY header (`ACCEPT_PROXY=true`).
- Both listeners bind to `127.0.0.1` by default: the Tailscale funnel (which forwards to
  `127.0.0.1:8080`) must be the only network path to the proxy. PROXY protocol is **not**
  authentication — anyone who can open a TCP connection to the proxy could forge a header
  claiming any source IP, so keep the port unreachable from everything except the funnel
  (loopback binding or a NetworkPolicy). Override `PROXY_LISTEN`/`ADMIN_LISTEN` if you need
  a different topology.
- Client-supplied `X-Forwarded-For` / `X-Real-IP` headers are always overwritten
  with the real peer IP derived from the PROXY header / socket.
- An empty whitelist denies everything (fail-closed) — add entries via the admin UI.
- Access attempts are only kept in RAM (ring buffer) and are lost on restart; nothing about them is written to disk.
- Keep the admin port out of public reach (cluster-internal only).

## Local development

```sh
go build -o whitelist-proxy .
UPSTREAM=http://127.0.0.1:11434 \
ADMIN_USER=admin ADMIN_PASSWORD=changeme \
ACCEPT_PROXY=false \
./whitelist-proxy
```

## Build

```sh
docker build -t whitelist-proxy .
```

GitHub Actions pushes images to `ghcr.io/niki-on-github/whitelist-proxy`
(`latest`, branch, `sha-*`, and `v*` tags) on push to `main` / version tags.
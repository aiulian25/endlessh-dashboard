<img src="assets/logo.png" alt="" width="96" align="left" hspace="12" vspace="4">

# endlessh-dashboard

A single-container, self-hosted dashboard for [endlessh-go](https://github.com/shizunge/endlessh-go)
SSH tarpits. It polls the Prometheus `/metrics` endpoint of every machine you register, keeps its
own history in SQLite, and serves an embedded web UI showing sampled connection time, recently active IPs, junk
bytes sent, and per-machine/IP rows across all your machines. Theme defaults to **System**,
following the operating system preference; dark is the stylesheet fallback. There is no individual
attacker detail page.

<br clear="left">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platforms: linux/amd64, linux/arm64](https://img.shields.io/badge/platforms-linux%2Famd64%20%7C%20linux%2Farm64-informational)

![The overview page: headline counters, a stacked activity chart, the country breakdown and a world map of attacker origins](docs/screenshots/overview.png)


## What it is

- One statically linked Go binary in one container: API, scraper, datastore, and UI together.
- Its own history in `/data/endlessh.db`, so totals survive tarpit restarts and counter resets.
- Multi-machine: register as many tarpits as you run, view one or several at once.
- Authenticated by default. No outbound traffic except the scrapes to the machines you registered,
  with one exception you have to switch on yourself: online GeoIP lookups, which send attacker
  addresses to the configured provider (ip-api.com over plain HTTP by default). Off unless you set `GEOIP_ONLINE=true`.

## What it is not

- **Not a Prometheus or Grafana replacement, and not a dependency on either.** You do not need to
  run Prometheus, an exporter, or Grafana. This app scrapes the endlessh-go `/metrics` endpoints
  directly. If you already run Prometheus + Grafana, keep them — this is for people who do not want
  a monitoring stack just to watch a tarpit.
- **Not a modification of endlessh-go.** Upstream is treated strictly as a black-box metrics source.
  Nothing is installed on the monitored hosts beyond the flags described below.
- **Not a threat-intelligence product.** It shows only what the six endlessh-go metrics contain.
  There is no reputation lookup, no log ingestion, no remote blocklist.
- **Not a phone-home app — with one opt-in exception, named.** No telemetry, no analytics, no update
  check, no CDN assets, no fonts or scripts fetched at runtime, and no map tiles. By default the only
  addresses this container talks to are the tarpits you registered. The exception is
  `GEOIP_ONLINE=true`: switch it on and unplaced attacker addresses are sent, one per request, to
  the configured provider (ip-api.com over plain HTTP by default). That discloses attacker addresses to that destination, and it never happens unless you ask for it. See
  [Where attacker geography comes from](#where-attacker-geography-comes-from).

## Quick start

The example below uses a published image reference. Verify that your chosen reference exists and
contains your architecture using the manifest command in [Supported platforms](#supported-platforms).
If it does not, use [Building from source](#building-from-source). This checkout does not establish
the availability or compiler provenance of a remotely published tag.

**1. Make a directory and drop in two files.**

```bash
mkdir -p endlessh-dashboard && cd endlessh-dashboard
```

**2. `docker-compose.yml`** — copy this as-is:

```yaml
services:
  dashboard:
    image: ghcr.io/aiulian25/endlessh-dashboard:latest
    container_name: endlessh-dashboard
    restart: unless-stopped
    stop_grace_period: 20s
    env_file: .env
    ports:
      # Reachable from your LAN. Bind to 127.0.0.1 instead if a reverse proxy
      # is in front of it: "127.0.0.1:18222:18222"
      - "18222:18222"
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    volumes:
      # The only writable path: endlessh.db and backups/ live here.
      - endlessh-data:/data
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=32m
    healthcheck:
      test: ["CMD", "/usr/local/bin/endlessh-dashboard", "-healthcheck"]
      interval: 30s
      timeout: 5s
      start_period: 10s
      retries: 3

volumes:
  endlessh-data:
```

A named volume is used rather than a bind mount, so there is no `chown` step and nothing to get
wrong about permissions — the container runs as uid 65532 and Docker sets the volume up for it. If
you would rather use a host directory, replace the volume with `- ./data:/data` and run
`sudo chown 65532:65532 data` first.

**3. `.env`** — the minimum is one line, but this is the useful starting set:

```ini
# Required on first start. You are forced to change it at first login, after
# which this value is dead and can be deleted.
ADMIN_PASSWORD=change-me-on-first-login

ADMIN_USERNAME=admin
LISTEN_ADDR=:18222
DATA_DIR=/data

# How often each registered tarpit is polled, and how long history is kept.
SCRAPE_INTERVAL=15s
SCRAPE_TIMEOUT=5s
RETENTION_DAYS=90

# Session cookie Secure flag: auto | on | off. auto sets it whenever the request
# arrived over TLS directly, or through a peer in TRUSTED_PROXY_CIDRS that
# overwrites X-Forwarded-Proto with a single https value.
SECURE_COOKIES=auto

# Log out and ask for the password again this long after signing in.
SESSION_LIFETIME=12h

# Nightly backups into /data/backups, and how many to keep.
BACKUP_DAILY=false
BACKUP_KEEP_LAST=7

# Geography. Both of these are off by default; the second one is the only
# setting in this app that sends anything to a third party.
GEOIP_MMDB_PATH=
GEOIP_ONLINE=false
```

Every variable, with its default and what it does, is in the
[Configuration](#configuration) table below and in
[`.env.example`](.env.example).

**4. Start it and open the UI.**

```bash
docker compose up -d
```

```bash
curl -fsS http://127.0.0.1:18222/healthz   # -> ok
```

Then open `http://<the-host's-IP>:18222` from any machine on your network — the compose above
publishes the port on every interface, so this works from your laptop or phone with no extra
configuration. See [Reaching it from another machine](#reaching-it-from-another-machine) if it does
not.

Log in with `ADMIN_USERNAME` / `ADMIN_PASSWORD`. The first login forces a password change; the seed
password stops working immediately afterwards, so you can leave it in `.env` or remove it — either
way it is no longer a valid credential. A fresh install shows an empty state prompting you to add
your first machine.

Password changes save the new credential and revoke every existing session in one database
transaction, including the browser making the change. If revocation fails, the password and
sessions remain unchanged. A concurrent login verified against the old credential cannot
create a valid session after rotation; overlapping password changes require fresh verification
if another change wins first. Password hashing runs before the write transaction. This uses
the existing salted credential as a version check, so no schema migration or upgrade sign-out
is required. Backups and full-database restores retain their existing account/session semantics.

Sign-in throttling keeps at most **4,096 records per process**, including pending requests,
keyed by username and the client address selected by the existing trusted-proxy rules. Only
one request per key is admitted at a time; overlapping requests receive HTTP 429 before
password verification. Five failed attempts in 15 minutes lock that key for 15 minutes.
Active lockouts and unexpired failure history are never evicted to admit a different key.
At capacity, new keys receive HTTP 429 until expired records can be reclaimed or a record
is freed; existing unlocked keys can still sign in. This favors preserving lockouts over
admitting new clients during saturation, so even a valid user on a new key may need to retry.
Users sharing both an account and the same reported proxy/client address also share the
per-key limit. `TRUSTED_PROXY_CIDRS` behavior is unchanged. Successful login clears its
history; cancellation, internal errors and a busy hashing queue release the reservation
without adding a failed attempt. Password hashing remains limited to two concurrent operations.

To upgrade later:

```bash
docker compose pull && docker compose up -d
```

Your database is in the named volume, so it survives the upgrade untouched.

## Reaching it from another machine

**It is reachable from your LAN out of the box.** The compose above publishes `18222:18222`, which
binds every interface on the host, and the container listens on `:18222`, which is every interface
inside it. Nothing extra is needed — find the host's address and open it:

```bash
hostname -I | awk '{print $1}'
```

If `http://<that-address>:18222` does not answer, it is one of three things, in the order they are
worth checking:

**1. The host firewall.** The most common cause by far, and the port is unusual enough that no
firewall knows about it. On ufw:

```bash
sudo ufw allow 18222/tcp
```

**2. `LISTEN_ADDR` was narrowed.** `LISTEN_ADDR=:18222` means "every interface inside the
container", which is what you want. Setting it to `127.0.0.1:18222` makes the app listen on the
container's own loopback only, and the published port then reaches nothing — connections are
refused from the LAN even though `docker ps` looks perfectly healthy. Leave it as `:18222` and
control exposure with the `ports:` line instead, which is what it is for.

**3. The port was bound to loopback.** `- "127.0.0.1:18222:18222"` publishes only to the host
itself. That is the right setting when a reverse proxy on the same machine is the only thing that
should reach it — and the wrong one if you want to open the dashboard from your laptop.

### If the page loads but signing in does nothing

This one is worth knowing about, because nothing on screen explains it. `SECURE_COOKIES=on` marks
the session cookie `Secure`, and **every browser silently discards a `Secure` cookie that arrives
over plain `http://`** on anything other than `localhost`. The page loads, the password is correct,
the login request returns 200 — and you land back on the login screen with no error, because the
cookie was thrown away before it was ever stored.

Over a LAN address on plain HTTP, use the default:

```ini
SECURE_COOKIES=auto
```

`auto` sets the flag for direct TLS, or when the immediate peer is in `TRUSTED_PROXY_CIDRS`
and sends one `X-Forwarded-Proto: https` value. It leaves it off otherwise. A TLS-terminating proxy
must be configured as trusted and overwrite this header; see
[TLS and reverse proxies](#tls-and-reverse-proxies). Use `SECURE_COOKIES=on` if you want Secure
cookies forced for an exclusively HTTPS deployment.

### A word about what LAN access means

Plain HTTP on a LAN means the session cookie crosses your network unencrypted. On a home network
you control, that is a normal trade-off. It stops being one the moment the dashboard is reachable
from beyond it — put TLS in front before that happens, and see
[TLS and reverse proxies](#tls-and-reverse-proxies).

## Supported platforms

| | |
| --- | --- |
| **Source build targets** | Linux `amd64` and `arm64`; `GOARCH` selects the target. Verify a published image manifest separately rather than assuming both entries exist. |
| **Docker tooling** | Docker Engine plus the `docker compose` plugin. Compose is a separate prerequisite; no minimum Engine release or complete version matrix is certified here. |
| **Compose file** | No `version:` key — that has been obsolete since Compose v2 and current versions warn about it. |
| **Hardware sizing** | No Raspberry Pi, NAS or fleet-capacity guarantee. Measure your retained rows, scrape workload, authentication and backup operations on the intended host. |
| **Not built for** | 32-bit ARM (`armv7`, e.g. Pi Zero/1/2 or a 32-bit Pi OS install) and 32-bit x86. A 64-bit OS is required even on 64-bit hardware. |

Check what your machine will pull:

```bash
docker manifest inspect ghcr.io/aiulian25/endlessh-dashboard:latest
```

## What it costs to run

No current container-wide idle/loaded/peak memory, CPU, binary-size or OCI-image-size measurement
is claimed here. The retained-row and scraper experiments in [Resource measurements](#resource-measurements)
name their fixtures and commands; they do not establish a universal deployment budget.

| Resource | Contract and sizing considerations |
| --- | --- |
| **Image and binary** | One static binary with embedded assets, packaged on distroless. Executable bytes, compressed registry layers and unpacked local-image bytes are different measurements. CI's image-size threshold is a build gate, not a measured release size. |
| **Memory** | New password hashes use 64 MiB of Argon2 working memory each ([parameters](internal/auth/password.go)); the authentication service admits two concurrent hashes ([limit](internal/auth/service.go)), allowing roughly 128 MiB of workspace for two current-format hashes alone. Add Go/runtime, SQLite, scraper/parser, query and backup/restore memory. Idle RSS is not a peak or a memory-limit recommendation. |
| **CPU** | Work depends on scrape bytes/series, cadence and concurrency, retained history and queries, password hashing, enrichment and backup/restore. No fixed idle or polling CPU percentage is established. |
| **Disk** | Include tables and indexes, retained attacker/IP-port baselines, coverage, SQLite pages/freelist, WAL/SHM, backups and temporary verification/restore copies. Retention is not a fixed database-size cap and freed pages need not shrink files immediately. |
| **Network** | Registered-machine HTTP scrapes at the nominal `SCRAPE_INTERVAL`, with backoff and worker pressure. Optional configured online enrichment adds lookup requests; it is off by default. |

For arithmetic only, an **illustrative, unmeasured** 30 bytes per machine per minute would total
`30 × 60 × 24 × 365 = 15,768,000` bytes per year (15.768 decimal MB, about 15.04 MiB), before
indexes, WAL, backups or any other data. It is neither a measured row cost nor a storage forecast.
Continuously exposed IP/port baselines and preserved legacy archives can outlive the rollup window.
Backup creation needs a snapshot plus a verifier copy before rotation; restore needs candidate and
rollback headroom as described in [Backups and restore](#backups-and-restore).

For new footprint evidence, record the source revision, compiler/build flags, architecture, image
digest, host/storage, machines/IP-port series, payload sizes, retention and operations. Distinguish
idle, sustained scrape/query load, concurrent authentication and backup/restore peaks; record
process RSS and any container-memory measurement separately. `go version -m` plus `wc -c` identify
a specific executable; `docker image inspect --format '{{.Size}}' IMAGE` reports local image size,
not compressed registry transfer bytes. Report compressed layer sizes separately for the chosen
platform manifest. The existing benchmark commands below provide disposable workloads for future
measurements; no new loaded/peak or compressed-image result is implied by this guidance.

## TLS and reverse proxies

**The dashboard speaks plain HTTP and expects TLS to be terminated in front of it.** Publish it
through Caddy, nginx, Traefik, or your existing ingress; bind the container port to `127.0.0.1` (as
above) so nothing reaches it except the proxy.

Session cookies are always issued with `HttpOnly` and `SameSite=Strict`. The `Secure` flag follows
`SECURE_COOKIES`, which defaults to `auto`: the flag is set when the request arrived over TLS —
directly, or when the immediate socket peer is in `TRUSTED_PROXY_CIDRS` and supplies one
`X-Forwarded-Proto: https` value. Untrusted forwarded headers do not affect cookies or HSTS.
A plain-HTTP trial still works with no trusted proxy configured.

If you want the flag set unconditionally, use `SECURE_COOKIES=on`; browsers will then refuse to
store the cookie over plain `http://` on a non-localhost origin, which is a deliberate way to make
sure nobody quietly runs it without TLS. `SECURE_COOKIES=off` forces it off and should stay a
local-testing setting only.

**Upgrade note:** auto mode now requires explicit proxy trust for forwarded HTTPS. If you previously
relied on an unconfigured proxy, set `TRUSTED_PROXY_CIDRS` to the proxy's immediate peer address as
seen by the dashboard (IPv4 or IPv6 CIDR). For containers this may be the proxy/container network
address rather than the browser or host-loopback address. Trust only controlled proxy addresses.
For a deployment exclusively behind TLS, `SECURE_COOKIES=on` also forces Secure cookies, but does
not configure forwarded-client trust for login throttling.

The immediate trusted proxy must **overwrite** `X-Forwarded-Proto` with exactly one `http` or
`https` value reflecting the external connection. Case and surrounding whitespace are normalized;
duplicate header fields, comma-separated lists and other values are ignored. Only this single-hop
scheme assertion is supported: a multi-proxy deployment must normalize it at the final trusted hop.
`Forwarded: proto=...` is not used. `X-Forwarded-For` keeps its existing last-entry policy for
client throttling and cannot grant trust to an otherwise untrusted socket peer. Restrict direct
backend access; an asserted scheme does not establish encryption. Explicit `on`/`off` modes take
precedence, including over direct TLS. The same decision controls issued/cleared cookies and HSTS.

The UI uses fragment routes such as `/#/machines`; the fragment is not sent to the server. Serve
the dashboard at the origin root and proxy `/api/` plus the root static assets to the same backend.
No SPA path-rewrite fallback is needed for hash navigation. Hosting below a URL subpath has not
been validated and is not a supported contract here; API requests use `/api/` independently of the
page path, while the index loads its assets relative to the document.

Caddy is the shortest correct example:

```caddyfile
tarpit.example.com {
    reverse_proxy 127.0.0.1:18222
}
```

## Configuration

The application reads its **process environment**. It does not load `.env`, mounted secret files,
or `*_FILE` variables. In the quick start, Compose's `env_file: .env` injects the values; Docker's
`--env-file` is another launcher option. A mounted file alone does nothing. If using a secret manager,
arrange for the launcher to inject the value into the process environment; the distroless image has
no shell for an inline wrapper. Do not put real passwords in examples or commit a populated `.env`.

`make run` inherits exported variables and sets `DATA_DIR=./data`; it does not parse `.env`.
For a local loopback-only development run, supply values explicitly (replace the sample password):

```sh
ADMIN_PASSWORD='replace-with-a-new-random-password' LISTEN_ADDR=127.0.0.1:18222 make run
```

Use `make run LOCAL_DATA_DIR=/path/to/disposable-data` to choose a different local data directory.
The actual defaults and validation rules are listed below.

| Variable | Default | Meaning |
| --- | --- | --- |
| `LISTEN_ADDR` | `:18222` | Address the HTTP server binds to. Keep the host part empty — `:18222` listens on every interface *inside the container*, which is what lets the published port reach it. Narrowing it to `127.0.0.1:18222` makes the container unreachable from anywhere, including your LAN. Control exposure with the compose `ports:` line instead. |
| `LOG_LEVEL` | `info` | How much reaches the container log: `debug`, `info`, `warn` or `error`. `debug` adds one line per HTTP request — method, path, status and duration — which is what to reach for when a reverse proxy or a CSRF header is misbehaving. Only the path is logged, never the query string. Noticeable on a busy dashboard, so turn it on to look at something and off again. |
| `DATA_DIR` | `/data` | Directory for `endlessh.db` and `backups/`. The only path the app writes to. |
| `ADMIN_USERNAME` | `admin` | Seed admin account, created on first start only — changing it later does nothing, since it is read only while the account is being created. At most 64 **bytes** (not characters, so accented or non-Latin names reach the limit sooner); longer is refused at startup. Empty or blank falls back to `admin`. |
| `ADMIN_PASSWORD` | *(required on first start)* | Seed password. Must be changed at first login; ignored once a user row exists. |
| `SECURE_COOKIES` | `auto` | `auto` marks the session cookie `Secure` for direct TLS or one `X-Forwarded-Proto: https` value from a peer in `TRUSTED_PROXY_CIDRS`. `on` forces it, `off` disables it for local plain-HTTP testing only. |
| `TRUSTED_PROXY_CIDRS` | *(empty)* | Comma-separated CIDRs of reverse proxies trusted for client addresses and the forwarded HTTPS scheme. Empty means the address a request arrives from **is** the client, which is correct when the dashboard is reached directly. Behind a proxy every request arrives from one address, so without this the login throttle counts them all as a single client and five wrong passwords from anybody locks the account for everybody. Set it to the proxy's own address only — anything listed here is trusted to name the client and, in auto cookie mode, assert HTTPS. The proxy must overwrite `X-Forwarded-Proto` with one scheme value. |
| `SESSION_LIFETIME` | `12h` | How long a sign-in stays valid before you are logged out and asked for the password again. The clock starts at sign-in and does not slide with activity. Go duration string with no day unit — write `168h`, not `7d`. Minimum `1m`, maximum `720h`. |
| `SCRAPE_INTERVAL` | `15s` | Nominal start interval per enabled target. Worker pressure and backoff can delay starts. Go duration string. |
| `SCRAPE_TIMEOUT` | `5s` | Total per-scrape timeout (2s connect). Redirects are never followed. |
| `SCRAPE_CONCURRENCY` | `4` | Maximum simultaneous metric fetch/parse/persist jobs, including Test connection. Integer `1`–`32`; queued targets hold metadata, not response bodies. A smaller cap can delay starts; inspect last-success age and coverage. |
| `SCRAPE_BLOCK_PRIVATE` | `false` | When `true`, refuse RFC1918 / ULA scrape targets as well (see Security posture). |
| `SCRAPE_ALLOWLIST_CIDRS` | *(empty)* | Comma-separated CIDRs exempt from the blocked-range checks, e.g. `127.0.0.1/32` to allow a tarpit on the same host. |
| `RETENTION_DAYS` | `90` | History older than this is pruned nightly. |
| `GEOIP_MMDB_PATH` | *(empty)* | Path to a mounted GeoLite2 `.mmdb`. Unset means local GeoIP is off entirely. |
| `GEOIP_ONLINE` | `false` | Look unplaced attackers up with an online provider. `true` sends attacker IP addresses to the configured provider; the default is ip-api.com over plain HTTP. Off unless you set it. |
| `GEOIP_ONLINE_RATE_PER_MINUTE` | `40` | Cap on lookups per minute. ip-api.com's free tier allows 45 per source address; 45 is the maximum accepted here, 1 the minimum. |
| `GEOIP_ONLINE_ENDPOINT` | ip-api.com's free endpoint | Lookup URL template. Must be `http://` or `https://` and contain `{ip}` where the address goes. |
| `BACKUP_KEEP_LAST` | `7` | How many backup files to retain; older ones are deleted after each new backup. |
| `BACKUP_DAILY` | `false` | Take an automatic backup once every 24 hours. |

The effective values are visible in the UI under **Settings** (read-only), so you can check what a
running container actually loaded without shell access — the runtime image has no shell.

### Retention

The default is **90 days**. Every night the app prunes per-minute rollups and attacker
aggregates, then reclaims freed pages with `PRAGMA incremental_vacuum`. Change the window
by setting the variable and restarting:

```ini
RETENTION_DAYS=365
```

Attacker expiry uses **last measured activity**: a positive counter change between known
samples, dated at the dashboard's sample time. This is not an exact session timestamp.
Unchanged exporter labels update **last observed**, but do not extend activity retention.
First lifetime imports have unknown activity dates and expire from their first dashboard
observation if no measured growth follows. Lifetime machine totals survive retention.
Lowering the window prunes excess history on the next nightly run, not immediately.

The Attackers range defaults to measured activity. Choose **Range: exporter observation**
to inspect retained rows whose labels are still exposed, including undated lifetime imports.
Row totals remain cumulative, even when the list is window-filtered; an asterisk marks
undated imported history. The API retains `first_seen` and `last_seen` as observation
fields and adds `last_observed_at`, nullable `last_measured_activity_at`,
`has_undated_history`, and `first_observation_known`. Use `basis=observed` on the attackers
and attackers/countries endpoints for observation windows. Latest activity and windowed
geography use measured growth. Fleet-new counts use the earliest retained observation
across selected machines; uncertain reappearances are excluded.

Raw per-client baselines expire after they stop being observed for the retention window.
Continuously exposed keys can therefore remain after their attacker aggregates expire;
retention is not complete IP erasure or a strict disk/cardinality cap. Unchanged baselines
do not recreate expired aggregates. After any client history/baseline expiry on a machine,
its persisted policy becomes baseline-only: unseen series establish a baseline without
importing lifetime values, and subsequent growth creates an aggregate. This conservative
policy also applies to newly arriving IPs on that machine, avoiding double imports without
keeping a permanent IP tombstone. Deleting a machine removes its baselines too.

Schema 9 preserves observation timestamps and any prior positive-delta activity timestamps;
it does not infer activity from old `last_seen` values. Legacy totals remain marked as
potentially undated. Take a backup before upgrading. Rolling back requires a pre-upgrade
backup and a compatible older binary; no down-migration is provided.

To stop collecting data while keeping a machine's recorded history, edit the machine and turn off
**Enabled**. Disabling stops scheduled scrapes; its existing history remains subject to retention.
**Delete machine** removes that machine and its stored totals, per-minute rollups, attacker rows
and counter baselines. Deletion cannot be undone directly. To preserve history, disable the machine
instead.

Take a backup through **Settings → Backups** before deleting a machine if you may need its history
later. Recovery requires restoring a backup taken before deletion: this replaces the **whole
dashboard database**, including all machines, history and accounts, with that snapshot. It is not
a per-machine recovery and reverts changes made after the backup. Back up the current database
before restoring; see [Backups and restore](#backups-and-restore).

## The rest of the UI

Every address, every host, one row each, filterable by country, machine and whether they are still
on the hook. The country column appears only when something has resolved an ISO code; with tarpit
labels alone the country is shown in the location column instead.

![The attackers page: a filterable table of every address, with country chips, cumulative connection time and counts, and sampled activity status](docs/screenshots/attackers.png)

Machines are registered here, and tested before they are added — the **Test connection** button
proves the tarpit answers on that host and port so you never save a dead target.

![The machines page: registered tarpits with host, metrics path, group, health status and how many attackers each is holding](docs/screenshots/machines.png)

## What each monitored endlessh-go host needs

Metrics are **off by default** upstream. Each tarpit you want to monitor must run with
`-prometheus_enabled` (the older `-enable_prometheus` spelling still works):

```bash
endlessh-go -logtostderr -v=1 \
  -prometheus_enabled \
  -prometheus_host=0.0.0.0 \
  -prometheus_port=2112 \
  -prometheus_entry=metrics
```

or in compose:

```yaml
services:
  tarpit:
    image: ghcr.io/shizunge/endlessh-go:latest
    restart: unless-stopped
    command:
      - -logtostderr
      - -v=1
      - -prometheus_enabled
      - -prometheus_port=2112
    ports:
      - "22:2222"      # the tarpit itself
      - "127.0.0.1:2112:2112"   # metrics: reachable by the dashboard, not by the internet
```

Defaults worth knowing: metrics listen on port **2112** at path **`/metrics`**, and the tarpit
itself listens on **2222**. Register the machine in the dashboard with the metrics host, port
`2112`, and path `/metrics`.

Do not expose the metrics port to the internet. It is unauthenticated upstream, and it lists
attacker IPs.

`-geoip_supplier` is **optional**. The dashboard works fine without it — country and location simply
come back empty and the UI leaves those columns out. Turning it on upstream is the cheapest way to
get geography, because the tarpit publishes it in the labels the dashboard already reads; see
[Where attacker geography comes from](#where-attacker-geography-comes-from) for the flag and the two
alternatives.

## Metrics consumed

Six series, all from the endlessh-go `/metrics` endpoint:

| Metric | Labels | Used for |
| --- | --- | --- |
| `endlessh_client_open_count_total` | `local_port` | Connection attempts per tarpit port. |
| `endlessh_client_closed_count_total` | `local_port` | Connections that gave up or dropped. |
| `endlessh_sent_bytes_total` | `local_port` | Junk bytes fed to attackers. |
| `endlessh_trapped_time_seconds_total` | `local_port` | Cumulative attacker time wasted. |
| `endlessh_client_open_count` | `ip`, `local_port`, `geohash`, `country`, `location` | Per-attacker connection count, and the only geography the metrics carry. |
| `endlessh_client_trapped_time_seconds` | `ip`, `local_port` | Per-attacker seconds trapped. |

Two notes that matter more than they look:

- Upstream registers all six as **counters**, including the two per-client series that some
  documentation describes as gauges. Country, geohash, and location live only on
  `endlessh_client_open_count`; the dashboard joins them onto trapped time by IP.
- **Per-client series are ephemeral and counters reset.** A monitored host started with
  `-prometheus_clean_unseen_seconds=N` *deletes* the per-IP series for any attacker not seen for N
  seconds, and every restart of a tarpit resets every counter to zero. A Prometheus + Grafana setup
  absorbs both. A direct scraper cannot — which is exactly why this app keeps its own history: it
  stores deltas with counter-reset detection, and the SQLite database, not the live scrape, is the
  source of truth for totals and for first/last-seen timestamps. An attacker that vanishes from the
  tarpit's metrics stays in your history.

## Where attacker geography comes from

An attacker row is only a country, a place name and a point on the map if something turned its IP
address into one. Three things can, and they win in this order — a source never overwrites what an
earlier one already established:

1. **The labels the tarpit itself publishes**, when it runs with `-geoip_supplier`. Recommended.
2. **A MaxMind `.mmdb` mounted on this dashboard**, for attackers the labels left blank. Offline.
3. **An online lookup**, for whatever the first two could not place. Off by default, and the only
   thing in this app that talks to a third party.

### 1. Labels from the tarpit (recommended, nothing leaves this app)

`endlessh_client_open_count` carries `country`, `location` and `geohash` labels whenever the
monitored host runs with `-geoip_supplier`. The dashboard already parses them on every scrape, and
decodes the geohash into the coordinate the map plots. This dashboard fetches nothing extra for it:
the work was already done on the tarpit host and shipped in the metrics you were scraping anyway.

Point the tarpit at a MaxMind database of its own:

```yaml
services:
  tarpit:
    image: ghcr.io/shizunge/endlessh-go:latest
    restart: unless-stopped
    command:
      - -logtostderr
      - -v=1
      - -prometheus_enabled
      - -prometheus_port=2112
      - -geoip_supplier=max-mind-db
      - -max_mind_db=/geoip/GeoLite2-City.mmdb
    volumes:
      - ./GeoLite2-City.mmdb:/geoip/GeoLite2-City.mmdb:ro
    ports:
      - "22:2222"
      - "127.0.0.1:2112:2112"
```

Upstream also offers `-geoip_supplier=ip-api`, which needs no database file: the **tarpit host** then
makes one plain-HTTP call to ip-api.com per attacker it sees. That is a trade the operator of that
host makes, not this dashboard — but the consequence is the same one described in section 3 below,
with the tarpit's IP as the source address instead of the dashboard's.

Geography from the labels appears after the next successful scrape; worker pressure or backoff can delay it.

### 2. A MaxMind database mounted here (offline, accurate)

If the tarpits run without `-geoip_supplier` — or run with a country-only database — the dashboard can
resolve addresses itself from a GeoLite2 `.mmdb` you mount. Download it yourself from MaxMind (a free
GeoLite2 account, `GeoLite2-City.mmdb`); nothing is bundled and nothing is downloaded for you. Mount
it read-only and point `GEOIP_MMDB_PATH` at it:

```yaml
    volumes:
      - ./data:/data
      - ./GeoLite2-City.mmdb:/geoip/GeoLite2-City.mmdb:ro
    environment:
      GEOIP_MMDB_PATH: /geoip/GeoLite2-City.mmdb
```

Lookups are pure-Go reads of that file — no network, no daemon, no CGO. The file must be readable by
uid 65532, and a City database is what gives you coordinates: a Country database carries no position,
and the dashboard stores no coordinate rather than inventing one, so those attackers get a country
but no bubble on the map. Leave `GEOIP_MMDB_PATH` unset and local lookups are off entirely.

### 3. Online lookup (opt-in, off by default)

**This is the one deliberate exception to this project's rule that nothing phones home, and it is off
until you set `GEOIP_ONLINE=true`.**

Switched on, a background worker takes attacker addresses that neither of the sources above could
place and looks them up at `GEOIP_ONLINE_ENDPOINT`, which defaults to ip-api.com's free endpoint:

- **What is sent:** one attacker IP address per request in the configured URL. The default provider
  uses **plain unencrypted HTTP**; custom HTTPS endpoints encrypt transport. Requests also carry
  any credentials you configure in the URL and expose the lookup host’s source address to the provider.
- **To whom:** ip-api.com, unless you point `GEOIP_ONLINE_ENDPOINT` somewhere else. It must be an
  `http://` or `https://` URL containing `{ip}` where the address goes.
- **Safe disclosure:** Settings and startup logs show only the configured host (including port) and
  HTTP/HTTPS transport. Userinfo, path, query and fragment are omitted from logs and Settings;
  lookup errors retain a safe error class rather than the request URL or response text. A custom
  destination can be local/private; it is not automatically described as a third party. Disabled
  mode sends no lookup requests, while Settings still describes the configured destination.
- **What comes back:** country and country code, region and city, coordinates, and the ISP or hosting
  network behind the address — the only source of that last one.
- **How fast:** at most `GEOIP_ONLINE_RATE_PER_MINUTE` requests a minute, evenly spaced, default 40.
  ip-api.com's free tier allows **45 requests per minute per source address** and throttles hosts
  that exceed it, so 45 is the maximum this app will accept and 40 leaves headroom. A large backlog
  therefore takes minutes to hours to clear, which is the intended trade.
- **Retry eligibility is remembered in SQLite**, including provider misses, so restarting does not
  repeatedly query unresolved addresses. Eligible retries refresh cached provider answers.
- **Redirects are not followed**, the response is size-capped, and a request that fails teaches the
  worker nothing — it retries with the bounded delays described below.

Nothing enables this by accident. It is `false` unless set, and when it is on the container logs a
warning at startup naming the endpoint and the rate, so an operator reading the log can see what this
install is doing.

### What has no location, and what is late

- **Private, loopback and link-local addresses have no location.** A tarpit on a LAN sees attackers
  from that LAN; upstream labels them `Unknown` (or `Geohash off` when it has no supplier at all),
  which the dashboard discards rather than showing as data — placeholders are not places. MaxMind has
  no record of them either, and they are never sent to the online provider at all. Those
  rows keep their IP, their times and their counts, and stay off the map and out of the country
  breakdown. Some public addresses are simply absent from GeoLite2 too, and land the same way.
- **Geography is not backfilled instantly.** An attacker recorded before you mounted a database or
  switched the online lookup on has no location until the backfill worker reaches it: it sweeps once
  a minute, up to 100 distinct eligible addresses at a time. Unattempted addresses go first
  (newest first within that group), followed by the least recently attempted eligible addresses.
  Recorded misses let later batches advance; the online rate limit paces requests. A resolved address is written to every machine's copy of that row, since
  where an address is does not depend on which tarpit met it.
- **The map is a country outline compiled into the binary** (Natural Earth 1:110m, public domain),
  not a tile service. Nothing is fetched when you look at it, and no map provider learns that you
  opened the page or what you were looking at.

### Country identity and filters

Country summaries, overview counts, map ranking and attacker filters use a shared country key.
A trimmed two-letter ASCII code is uppercased (`code:DE`); different source spellings with that
code form one group. Its display name is the lexicographically smallest nonempty trimmed source
name (or the code if none exists). Country controls show codes beside names to distinguish conflicting labels. Source names remain
unchanged in attacker rows.

Without a usable code, a trimmed name with ASCII case folded forms a separate `name:` group,
marked “name only” in country views. Names are never guessed into codes: uncoded “Germany” stays
separate from `code:DE`, and rows labeled “Germany” with different codes stay separate. Outer ASCII whitespace is trimmed; non-ASCII
case/whitespace and internal whitespace are preserved. Codes are shape-checked, not validated against an ISO
registry. Rows with neither a usable code nor a name have unknown country and are omitted from
known-country summaries, but remain in the attacker list (and on the map if coordinates exist).
Shared IPs count once within each identity across selected machines; cumulative connections sum
all selected machine/IP rows. A conflicting IP can belong to multiple country groups.

`/api/attackers/countries`, `/api/geo/countries` and `/api/geo/points` include `country_key`;
attacker country summaries also include `country_code`. Use `country_key` to select the entire
group in `/api/attackers`; it takes precedence over the retained legacy `country` name/code filter.
Summary limits still apply (300 country groups, 500 map bubbles). This query-time change adds no
migration or stored-label rewrite; normal backup/rollback compatibility is unchanged.

### Backfill retries and upgrades

Backfill records one current attempt per canonical IP across all retained machines, with its source
generation and next retry time. Provider errors retry after one minute, doubling after each failure
up to 24 hours. Unknown addresses and successful but incomplete answers retry after 24 hours.
Addresses ineligible for online lookup are skipped until the source generation changes, after first
trying the local database. No lookup runs when both sources are disabled; online mode remains opt-in.
Existing location fields stay available during retries, and empty answers never erase them.

Restart the dashboard after replacing the mounted local database or changing provider configuration.
The source generation includes a content hash of the loaded database and the online enabled state
and endpoint. A changed generation makes incomplete addresses eligible again without waiting for
old delays. Replacing a database with identical content or restarting unchanged configuration does
not reset retries. Complete addresses are not queued solely because the source changes. Local file
hashing adds one streaming read at startup; no database or provider data is downloaded automatically.

Schema 12 adds the compact progress table, an IP index and last-copy cleanup trigger; it does not
rewrite attacker history. Progress disappears when the final retained copy of an IP is deleted.
Take a backup before upgrading. To roll back, restore a pre-upgrade backup with its matching older
binary, accepting loss of subsequent changes; do not delete migration markers or open schema 12
with an older binary. No down-migration is provided.

## Editing a machine endpoint

Changing a machine's host, metrics port or metrics path preserves its recorded totals, rollups
and attacker history, and starts a new collection generation. Its old raw baselines are cleared;
the replacement endpoint's first readings establish baselines without importing its lifetime
counters. Its client-series policy becomes `baseline_only`, including later unseen ports/families.
Subsequent observed growth is added to the preserved history. Machine detail shows the latest
endpoint-change timestamp and explains that counters were rebaselined; this is a configuration
boundary, not an exact exporter restart time or session event.

Delayed results from an earlier generation cannot change metrics, health or the new target's retry
schedule. Baseline revisions and sample timestamps prevent competing/out-of-order results from
committing stale deltas. Name, group and colour edits preserve counter continuity. Disabling or
re-enabling also invalidates in-flight work, but retains the same endpoint's baselines and last
known health information. Deletion still removes that machine's history as documented above.

Migration **0008** adds the durable generation, revision and observation timestamps without
rewriting historical values. Back up before upgrading. Restore a pre-upgrade backup with the
matching older binary to roll back; do not edit migration records. If a host/path change is only a
relocation of the same exporter, the conservative rebaseline still applies and may omit the first
uncertain interval rather than combining two potentially unrelated exporters.

## Attacker IP identity and legacy review

New client labels must be valid, unscoped IP addresses. IPv6 uses compressed lowercase text;
IPv4-mapped IPv6 (for example, `::ffff:192.0.2.1`) becomes IPv4 (`192.0.2.1`). Whitespace,
missing/empty IPs, scoped addresses such as `fe80::1%eth0`, hostnames, ports and invalid text
reject the whole scrape without advancing history or baselines. Private/LAN addresses remain
valid attacker identities. Normalization happens before grouping by metric/IP/local port.
Full-address searches and enrichment updates accept equivalent valid spellings; partial search
prefixes still match stored canonical text. IPs are address identities, not unique people.

The [upstream metric definitions](https://github.com/shizunge/endlessh-go/blob/main/metrics/metrics.go)
use per-client counters with IP and local-port labels, with geography on the opens family.
This change preserves the existing sampled-delta, reset and missing-family rules; no precise
session times or concurrent-person counts are inferred.

Migration **0010** (the next available schema version) normalizes retained history in one
transaction. One-to-one aliases retain all values. Colliding machine/IP rows are **not added**:
connections and trapped seconds use independent maxima, first observation uses the earliest
time, last observation/activity uses the latest known time, and geography/ISP/coordinates come
from the most recently observed source row (lexical original-IP order breaks ties). Existing
unknown-history flags are combined conservatively. These maxima can undercount independent
historical observations; the exact correct repair cannot be inferred automatically. Machine
lifetime totals and rollups are untouched, so they need not match the retained IP aggregates.

Every changed, colliding or invalid source row is retained with its original spelling and full
JSON payload in `attacker_ip_archive`. Invalid IPs leave the active attacker table. Original
raw baseline rows needing transition are kept in `counter_ip_archive`. Unambiguous valid
per-port baselines retain their values/timestamps under canonical keys. Colliding raw keys,
invalid keys and old collapsed keys are removed from active baselines. Affected ambiguous
machines use persisted `baseline_only` behavior for unseen client series, including late/new
IPs: the first uncertain sample establishes continuity and only subsequent growth contributes.
This prevents lifetime reimport after migration/restart; an uncertain interval can be omitted.

Startup reports the number of ambiguous/invalid or collapsed records retained for review,
without logging raw labels. On an **offline copy** of the database, inspect the archive tables:

```sql
SELECT machine_id, original_ip, canonical_ip, reason, row_json FROM attacker_ip_archive;
SELECT machine_id, original_series, canonical_series, reason, row_json FROM counter_ip_archive;
```

Archives are excluded from dashboard counts, geography and enrichment. They remain for review
outside normal activity retention and are included in backups; deleting their machine cascades
to its archives. Keep this extra IP-data retention and disk use in mind. There is no automatic
sum, destructive archive cleanup, or automated repair of ambiguous values. The migration needs
memory proportional to retained attacker/client-baseline rows plus disk for archives and the
transaction. Take a backup before upgrading. Verification upgrades only a disposable copy of
older backups and checks canonical active identities in current-schema files too. To roll back schema 10, restore a pre-upgrade backup with a compatible older
binary; do not edit migration markers or copy archived counters blindly into live tables.

## Selected time ranges

Windowed API requests use one half-open UTC interval: **start included, end excluded**.
Both requested bounds round **forward** to minute boundaries. For example, a start of
`12:01:30Z` becomes `12:02:00Z`; an end of `13:01:30Z` becomes `13:02:00Z`. This selects
stored minute-start rows consistently and does not interpolate sub-minute events. An
exact-minute end excludes that minute. Equal effective bounds produce zero window sums
and no chart points. The ongoing minute can be included and may still change.

`window=24h|7d|30d|90d` retains its existing defaults and display bucket sizes. Related
requests can reuse `as_of=<RFC3339 timestamp>` with the window, or specify both `from` and
`to` directly (RFC3339, offsets accepted). Do not mix an explicit pair with `as_of`.
Malformed, reversed, pre-1970 or longer-than-90-day ranges return HTTP 400; empty ranges
are valid. Invalid window names still fall back to 24h. The overview, timeseries,
attackers, attacker-country chips and geography endpoints all use this contract. Every
response exposes `X-Range-From`, `X-Range-To` and `X-Range-Resolution-Seconds: 60` headers;
overview and timeseries also expose effective `from`/`to` JSON fields.

The overview and machine detail share one cutoff across their related requests; attacker
pagination/filters retain the cutoff until refresh, when table and country chips refresh
together. Chart bins aggregate **only** selected minute rows, even when the first/last
hour/day display bin is clipped. Each point's `t` and `to` describe its included interval;
`partial` marks clipped display bins. Chart labels, keyboard tooltips and screen-reader
intervals use UTC, including across local daylight-saving transitions. Visible connections, time and byte window deltas come from the same plotted response;
server summary time/byte deltas use the same bounded rollup rows.

A shared cutoff fixes boundaries, not database snapshots. Delayed scrapes or writes to the
current minute can change data between HTTP requests. Lifetime totals, current health/
recent-activity badges and the latest-activity card remain outside the selected historical
window. Per-IP row totals remain cumulative; range filters select retained rows by their
latest measured activity (or explicit observation basis), without reconstructing historical
per-IP events overwritten by later samples. Numeric zero fields remain compatible; observation coverage distinguishes missing data in the chart.
These range rules do not rewrite stored history; earlier releases' edge totals can differ.

## Reading activity and cumulative totals

**Recently active IPs** means distinct IP addresses with positive measured counter growth
within twice the configured scrape interval. It estimates sampled activity, not simultaneous
sessions or people. One IP can represent several clients or appear on several machines;
per-machine counts therefore need not sum to the fleet distinct-IP count. **No recent measured
activity** does not establish a disconnect. First lifetime imports have **Activity time unknown**.
The UI shows the actual threshold and successful scrape age; failed/disabled machines can retain
old readings, so consult that context before interpreting an activity badge.

The Attackers population reports both matching machine/IP rows and distinct IPs across the
entire filtered result, before pagination. Its range selects rows by latest measured growth or
exporter observation; row connection counts and connection time remain **retained cumulative**
values, including undated imports marked `*`. Map bubbles, country shares and top rows use
cumulative connection counts among rows selected by the range, not per-IP window events.
Window cards and charts use sampled counter deltas. Connection time sums **connection-seconds**
across concurrent connections and may exceed elapsed wall-clock time. Displayed absolute
timestamps and half-open range boundaries use **UTC**.

Existing API names (`trapped_now`, `trapped`, `gave_up`) remain compatible and carry these sampled
meanings. Overview/list `activity` metadata exposes `threshold_seconds`, `evaluated_at`, oldest/
newest successful scrape times, and counts of unobserved, failed-latest and disabled machines;
machines expose `activity_threshold_seconds`. Attacker lists add `distinct_ips` alongside the
existing row `total`, plus effective `from`/`to` bounds. Label/population fields do not transform stored counter values; coverage storage is described below.

## Observation coverage and collector health

Chart zeroes alone do not establish quiet traffic. Timeseries points retain all existing
numeric fields and add `coverage` (`complete`, `incomplete`, `unknown`), `observed_seconds`,
completed `attempts`/`successes`, and nullable `uncertain_from`/`uncertain_to` UTC timestamps.
`complete` means that the whole selected bucket was bracketed by successful samples at the
expected cadence, with all four aggregate counter families present, stable reported series,
no observed reset or intervening recorded failure, and the same endpoint generation and
configured interval. The accepted gap is at most twice the scrape interval, capped at one hour.
This describes sampled exporter observations; it cannot rule out a reset or outage hidden
between samples. First samples, missing families/ports, failures/backoff, long stops and
interval/endpoint changes cannot establish full coverage. Historical coverage is unknown.

Neutral chart shading marks any selected machine's incomplete/unknown coverage or uncertain
recovery timing. Tooltips and accessible tables identify each machine's coverage; an unknown
zero is shown as an unknown observation with a recorded subtotal of zero. Known values remain
visible. Sidebar sparklines also shade incomplete buckets. Window cards describe recorded
subtotals rather than guaranteeing all events were collected. Current edge buckets can be
incomplete until a later observation brackets them.

Recovered growth remains in its collection-minute bucket to preserve existing deltas and
range selection. Its uncertainty timestamps enclose the earliest relevant retained baseline
and the recovery sample; they can extend before the selected range. The chart does not spread
that growth across missing minutes or present the collection bucket as exact event timing.
Counters first seen without a baseline still establish a baseline, with the existing client
lifetime-import policy unchanged. Totals are neither discarded nor redistributed by coverage.

Machine status is age-aware: `ok` expires to `stale` once successful-scrape age exceeds twice
the current scrape interval (also exposed as `activity_threshold_seconds`). A future success
timestamp is stale until the clock catches up. `disabled`, `never_scraped`, `degraded` after a
recent failed attempt, and `down` after three consecutive failures remain distinct; disabled
and down take precedence. `never_scraped` means no successful observation, even if an attempt
failed. The UI retains last attempt, last success, errors and recorded history.

`GET /healthz` remains cheap HTTP liveness and still returns `200 ok`. `GET /readyz` returns
`200 ready` only while the collector loop is running and has made scheduler progress within
`2 × SCRAPE_INTERVAL + SCRAPE_TIMEOUT`; before startup, after stop or after stalled progress it
returns `503 collector not ready`. It reads only in-process state, never polls targets, and
reveals no machine details. A reachable collector with unavailable targets can be ready;
readiness is not a promise that every target or the database is healthy. Existing container
liveness configuration is unchanged. To diagnose collector progress locally:

```bash
curl -fsS http://127.0.0.1:18222/readyz
```

Migration **0011** adds coalesced per-machine/minute coverage and one continuity row per machine;
no old numeric history is rewritten or backfilled. Coverage minutes follow normal rollup
retention and machine deletion cascades, and backups include coverage automatically. At most
one minute row per machine is retained for each observed/failed minute, rather than one row
per request; a success can fill at most one hour of observation coverage. Back up before
upgrading. Older binaries must not open schema 11: roll back using the matching older binary
and a pre-upgrade backup, accepting loss of subsequent changes, rather than deleting migration
markers. Restore validation continues to accept supported historical schemas and upgrades them
on a staged copy.

## Client counter continuity across ports

Client connection and time counters are differenced separately for each metric, IP address and
local port before their deltas are added to the existing per-machine/IP history. Missing samples
are not zero readings: only present raw series update baselines. An unchanged series returning
within baseline retention contributes zero; a lower returning value is treated as an observed
reset. Identical duplicate series are counted once; conflicting values for the same identity
reject the whole scrape. Raw baseline keys and attacker rows use the same validated, canonical IP identity.

Migration **0007** adds the durable `machines.client_counter_policy` setting and leaves recorded
totals, attacker rows, rollups and old baseline values intact. Existing machines use
`baseline_only`: every previously unseen raw client/port series establishes a baseline without
importing lifetime values, including ports or families absent during the upgrade. Growth after
that reading is counted normally. This policy persists across restarts. A newly registered machine
uses `import_lifetime`, retaining the prior behavior of adopting each client series' first lifetime
reading. First imports and baseline-only observations alone do not establish measured activity.

The old collapsed baselines cannot be split reliably across ports. The upgrade therefore sacrifices
an uncertain first interval rather than importing old lifetime counts again. Already-inaccurate
historical totals are not reconstructed. Back up before upgrading; older binaries must not open a
database migrated by this build. Roll back by restoring a pre-upgrade backup with the matching older
binary, accepting loss of changes after that backup, rather than editing migration markers.

Exporter resets that catch up above the last observed value between scrapes remain undetectable.
Missing series retain their last raw reading only until normal baseline retention prunes it;
reappearance after pruning follows the machine's first-observation policy. These samples do not
provide exact session start/end times or unique-person counts.

## Per-port traffic and sampled time

Machine details include an **All ports** selector beside the chart range and a **Ports** table
below the statistics. Selecting a port filters the chart and its recorded connection-open,
connection-time and byte subtotals without changing the machine or time range. The URL preserves
`#/machines/ID?port=22`. IP/activity rows remain explicitly **all ports**; aggregate port counters
cannot establish per-IP sessions or unique people.

The same scrape already provides four aggregate counter families with `local_port`. Deltas are
calculated independently per family and port, including counter resets. Schema **13** stores
forward-only minute rollups keyed by machine, target generation, port and bucket, in the same
transaction as existing machine rollups and raw baselines. Fleet queries retain the merged tables;
no additional exporter polling occurs. Missing labels form an explicit **Unlabelled** group
(`unknown` in the API). Numeric labels must be canonical ports 1–65535; a scrape accepts at most
128 distinct aggregate ports. Invalid labels or excess cardinality reject the whole scrape.

Merged historical rollups cannot be divided retrospectively. The Ports table shows the first
successful collection timestamp; older or absent port intervals are **unavailable**, not measured
zeroes. Coverage is evaluated for each port's four families: first observations, new/missing
families, failures, cadence changes, endpoint generations and resets prevent complete coverage.
Recovery deltas remain recorded subtotals in their collection bucket, with uncertainty spanning
the earlier observations. A quiet interval is distinguished from an unobserved one. Table values
and charts use the same minute-aligned, half-open range rules as existing metrics; time is sampled
connection-seconds, not exact session duration. Retained generations are combined for a port's
historical display, while their baselines and observation continuity remain separate.

Authenticated `GET /api/ports?machines=ID&window=24h` returns effective `from`/`to`, nullable
`collection_started_at`, `available`, and per-port recorded opens/closes/bytes/time, observed seconds,
sample count and retained generation count. Both this summary endpoint and `/api/timeseries` accept
optional `port=22` or `port=unknown`; omitted means all ports. The new summary uses only collected
port rows, whereas the existing unfiltered chart retains legacy merged history. Port-filtered chart
points have `available` and nullable values for absent observations; an unknown/new valid port gives
unavailable data and does not reset the selector. Invalid, empty or repeated port filters return 400.
Supply the same `as_of` or explicit `from`/`to` to compare charts and summaries. Summary values are
window subtotals, not all-time port totals. Existing fleet/IP summary APIs remain all-port metrics.

Port rollups follow history retention and machine deletion cascades; their collection boundary
metadata survives retention. Storage grows with retained port-minute observations, and retired
numeric labels remain bounded by the TCP port domain. Schema verification and backups include the
new tables. Take and download a backup **before upgrading**: the migration adds tables without
rewriting merged history, but older binaries do not accept schema 13. Roll back using a pre-upgrade
backup and matching older binary, accepting loss of subsequent changes; do not delete migration
markers or try to reconstruct ports from merged totals. Verification and restore require the
temporary-copy headroom described under [Backups and restore](#backups-and-restore).

## Numeric metric validation and existing history

The six selected Endlessh families must be counters. Untyped exposition (including samples without
a TYPE declaration) remains supported for compatibility; gauge, histogram and summary declarations
for these families are rejected. Unrelated exporter families are ignored. Connection and byte
readings must be whole numbers from 0 through **2^53−1 (9,007,199,254,740,991)**, including the current
per-IP sums across ports. Time counters may be fractional but must be finite and nonnegative.
Float64 exposition cannot recover precision already lost by an exporter.

Cross-port and persisted connection/byte accumulations must fit a nonnegative signed 64-bit integer;
time sums must remain finite. SQLite and JSON retain accumulated int64 counts, but browser number
rendering can round counts above 2^53−1. Invalid samples, unsafe conversions or overflowing additions reject
the entire scrape, including its new baselines. A failed scrape updates failure status rather than
success status. Existing totals are not silently replaced with zero. JSON serialization failures
return a controlled HTTP 500 and are logged rather than returning an empty HTTP 200.

If an earlier build has already recorded invalid numbers:

1. Turn off **Enabled** for the affected machine and take/download a backup before any repair.
   Work on an offline copy, preserving the original database and backup files.
2. Inspect the machine's `machine_totals`, `machine_rollups`, `attackers` and `counter_states` rows.
   Count/byte columns should have SQLite type `integer` and nonnegative values. Time columns and
   raw baseline `value` should be numeric, nonnegative and no greater than the largest finite
   float64 value (`1.7976931348623157e308`); NULL/non-numeric values and infinities are invalid.
   Raw count baselines must also satisfy the 2^53−1 whole-number limit above. The scraper reports
   invalid stored baselines as requiring operator repair. These are diagnostic checks on a copy,
   not instructions to run an update against the live database.
3. Prefer a known-good pre-incident backup after inspecting its numeric history. Restoring replaces
   the whole database and reverts later changes for every machine. Keep a current backup first.
   A compatibility check alone does not establish that historical numbers are trustworthy.
4. Without trustworthy prior values, the lost readings cannot be reconstructed reliably. Keep the
   original evidence and make an explicit recovery decision: repair a separate copy from trusted
   records, or back up and delete/re-register the affected machine to discard its history and start
   fresh. Re-registration establishes new machine-total baselines; initial per-IP rows still adopt
   the exporter's available lifetime values. Do not guess replacement values or merely clear
   baselines, which can reimport cumulative counters and inflate history.

No automatic historical repair or schema migration is performed by this validation change.

Metrics responses are limited to **8 MiB (8,388,608 bytes)**. A response exceeding this limit is
rejected as a failed scrape or connection test, even if its first 8 MiB are valid metrics. The
limit applies to bytes read from the HTTP response body, not the advertised Content-Length.
Rejection preserves the last successful history and baselines; the error states the size limit.


## Backups and restore

Backups are taken with SQLite's own `VACUUM INTO`, never a raw file copy, so a backup taken while
the scraper is writing is still consistent. Files land in `/data/backups/`, so they are on the same
volume as the database — copy them off-host if you want them to survive losing the volume.

New snapshots are written under a hidden temporary name, checked for application compatibility,
secured to mode `0600`, and synced before atomic publication. Incomplete files are never published;
failed or cancelled attempts clean up their temporary output. Rotation runs only after a verified
snapshot is published. Requests in the same second reuse the existing snapshot only after it passes
verification; an unverified collision is rejected and left untouched for operator inspection.

Creation needs disk headroom for the snapshot plus the verifier's temporary full copy before any
older backups are rotated. The backup filesystem must support hard links and directory syncing;
publication fails rather than overwriting an existing destination if those operations are unavailable.


From the **Backups** card on the **Settings** page you can take a backup, download it, restore one,
and delete one. Daily
backups run automatically when `BACKUP_DAILY=true`, keeping the last `BACKUP_KEEP_LAST`
files.

The same thing from the API:

```bash
# take one
curl -fsS -X POST -b cookies.txt -H "X-CSRF-Token: $TOKEN" http://127.0.0.1:18222/api/backups

# list
curl -fsS -b cookies.txt http://127.0.0.1:18222/api/backups

# download
curl -fsS -b cookies.txt -o backup.db \
  http://127.0.0.1:18222/api/backups/endlessh-20260824-030000.db

# restore (verified with PRAGMA integrity_check, then swapped in on restart)
curl -fsS -X POST -b cookies.txt -H "X-CSRF-Token: $TOKEN" \
  http://127.0.0.1:18222/api/backups/endlessh-20260824-030000.db/restore
```

Before staging a restore, the dashboard checks the migration sequence, application schema,
foreign keys and stored credential format. It tests older supported schemas by upgrading a
throwaway copy and checking startup reads; the uploaded or selected source is not upgraded.
Unexpected schema objects (including custom triggers or indexes), incompatible databases and
unsupported password-hash costs are rejected. Verification allows 30 seconds and needs writable
disk space beside the source for a temporary full database copy, which is removed afterward.
Normal startup also rejects newer or incomplete migration sequences before migration work.

Restore uses a recovery journal on the same data volume; replacing a database and its WAL
files is **not** a single atomic filesystem operation. On restart, before opening the live
database, the app creates and verifies standalone candidate and rollback snapshots with
SQLite `VACUUM INTO`, including committed data from the old WAL. Files and directory entries
are synced before replacement begins. If an installation attempt is interrupted before
startup confirmation, the next start restores the old snapshot. If no old database existed,
it retries the verified candidate. A prepared operation can resume installation; a confirmed
one completes cleanup. Repeated recovery is safe.

Confirmation happens after migrations, application setup and successful listener binding,
before background workers or HTTP requests start. Until then the older `.previous` generation
is preserved. A startup error leaves the journal for recovery on the next start. A corrupt or
ambiguous recovery layout stops startup with an error, rather than creating an empty database.
The candidate must verify before replacement; missing or modified recovery snapshots are
never guessed around.

This protocol assumes **one dashboard process per data volume**, same-filesystem atomic
rename, and working file/directory `fsync` on a local Linux filesystem. Network filesystems,
concurrent containers sharing a volume, failing storage and dishonest storage caches are not
covered. Tests terminate subprocesses and inject filesystem errors; actual power-loss durability
has not been tested. Normal SQLite writes still use `synchronous=NORMAL`; this protocol does
not change the durability of ordinary recent transactions. Allow room for the live DB/WAL,
staged upload, candidate, rollback, retained `.previous`, publication temporaries and verifier
copies. Each SQLite snapshot query and each verifier has a 30-second deadline; slow/large
restores can fail safely and require more headroom or operator recovery.

### Undoing a restore

After startup confirmation, the standalone snapshot of the database immediately before the
restore is kept as `/data/endlessh.db.previous`. It includes committed WAL data and can be
uploaded alone through **Settings → Backups → Restore from file** to undo a mistaken restore.
The next successfully confirmed restore replaces `.previous`; an undo is also a restore.
Download or copy recovery generations off-host before attempting another restore if needed.

If startup cannot recover automatically, stop the container and any restart loop, then copy
**the entire data directory**, including WAL/SHM, `.restore`, `.restore-journal`,
`.restore-candidate`, `.restore-rollback` and `.previous`, to a safe location. Do not delete
individual WAL files or mix them with another database base file. Correct transient permission,
space or filesystem errors and restart with the same binary to let the journal finish.

For manual recovery, use a **verified standalone** backup, `.previous` or
`.restore-rollback` (check with SQLite/application-compatible tools on a disposable copy).
Keep the untouched directory copy. With all dashboard processes stopped, move the live DB,
its WAL/SHM and all restore-operation files together into a separate recovery directory, then
copy the chosen standalone file to `endlessh.db` and start a compatible binary. Do not copy a
WAL-dependent base file alone. Manual selection of an older snapshot loses newer data in the
chosen live history, so preserve all generations first. Avoid downgrading during a pending
restore: older binaries do not understand this journal. No database schema migration is added
by this change.

## Scrape scheduling and limits

`SCRAPE_CONCURRENCY` defaults to **4**, with a validated range of **1–32**. One fixed worker
pool dispatches the oldest due enabled target first, with one scheduled scrape per machine
at a time across endpoint generations. Dispatch is unbuffered: registry metadata is retained
for the fleet, while fetches, parsers, snapshots and database work are limited by the shared
budget. Test connection shares the same budget and its timeout includes waiting for a slot.
The online geography worker keeps its separate existing rate limit.

`SCRAPE_INTERVAL` is a nominal start interval. A healthy peer can be scheduled again while
another target is still slow; there is no whole-fleet completion barrier. Failed targets retain
1/2/4/8-interval backoff and HTTP timeouts; slots and per-machine ownership release on failure
or cancellation. A cap of one necessarily waits for a slow request's timeout before serving the
next target. Overloaded pools can miss the nominal cadence: last successful scrape times,
stale health and chart coverage remain visible, and their thresholds are not silently relaxed.

The scheduler refreshes enabled-target metadata each interval. Removed/disabled targets lose
retry state at the next successful refresh; late results cannot recreate it. Generation changes
clear obsolete backoff. Jobs recheck current enable/generation state after waiting for a slot,
and existing transaction fences still reject edits/deletions that race an in-flight scrape.
Cancellation stops dispatch, abandons queued metadata, and joins the fixed pool before the
scraper worker exits. The HTTP client remains shared so connection reuse is preserved.

The focused benchmark in `internal/scrape/poller_benchmark_test.go` compares 1/10/100 synthetic
targets and caps 1/2/4, using small counter responses and an approximately 8 MiB padded response.
The initial collection experiment favored four workers for completion latency with similar
total allocations. Run the actual scheduler benchmark in separate processes per case to compare
process peak RSS; `VmHWM` is cumulative within a process. First-success measurements include
2ms database observation intervals; reported age is observation age at sweep completion.
Timing and allocation figures include the success observer.
These padded, low-cardinality fixtures and local SQLite writes do not establish production
fleet capacity or worst-case metric-label/parser memory. A concurrency cap bounds overlapping
jobs, not heap bytes, registry cardinality, total retained history or kernel I/O duration.

## Shutdown and restore restarts

SIGINT, SIGTERM, an accepted restore restart, and unexpected HTTP listener failure all
use the same shutdown sequence. The application rejects new HTTP requests (including on
existing keep-alive connections), stops accepting connections, cancels its scraper,
maintenance and geography workers, and waits for both workers and admitted HTTP handlers.
Only after they have exited does it close the online resolver, local GeoIP database and
SQLite store. Existing restore staging and startup confirmation rules are unchanged.

One **15-second budget** covers HTTP draining and worker completion together. Shutdown logs
`background workers and HTTP handlers stopped` when they have joined. If work has not
finished by the deadline, it names pending workers/handlers, logs a timeout and exits with
an error. Shared resources are left open for process termination rather than closed beneath
unfinished work; this is a forced exit, not a successful graceful shutdown. SQLite/file
recovery on the next start still applies. Individual filesystem operations can be
uninterruptible, so a deadline cannot guarantee completion of an in-flight disk operation.

Workers check cancellation before starting another phase or target. Pending HTTP scrapes
and online lookups use their cancelled contexts; backup creation can leave a contended
publication lock and cancels SQLite verification as well as snapshot work. Unpublished
backup files are removed when cancellation unwinds; previously published snapshots remain
subject to the existing atomic publication/durability rules.

Give the container runtime at least **20 seconds** before forcing a stop. The supplied
Compose file and quick-start example set `stop_grace_period: 20s`; `make docker-run` sets
`--stop-timeout 20`. Apply the same allowance in other supervisors. These source settings do
not change an already running deployment until it is recreated with the updated settings.

## Browser refresh lifecycle and regression tests

Each page load captures its selected machines, range and filters. A newer load cancels and
invalidates the previous one; results and labels paint only for the accepted request. Navigation
and sign-out dispose route loads, refresh subscriptions and pending search debounces. The shared
machine cache also rejects superseded loads. Aborted work does not display a server error or
redirect a later login. Refresh rounds wait for their page callbacks, isolate individual failures,
and skip overlapping ticks; range/filter actions can still start immediately.

This does not create a server-side snapshot across API calls or change pagination or metrics.
Panel failures retain data as described below; keyboard continuity is described below. There is no runtime
dependency or database migration.
The lifecycle module is embedded with the existing JavaScript assets.

The test-only browser harness uses Node.js 20+ with exactly pinned Playwright and its lockfile:

```sh
cd e2e
npm ci --ignore-scripts
npx playwright install chromium
npm run test:ui
```

Tests run Chromium in dark and light modes with reduced motion, serve the real frontend from a temporary
loopback mock server, allow no external browser requests, and deliberately reverse old/new responses. They cover range and machine selection,
filters, sorting, pagination, country time bases, debounce, route disposal, logout/new login, and
serialized refresh with rejected callbacks. The simulated transport ignores cancellation so stale
result guards must work independently of the network. Every test closes its server and browser,
including failed runs; no dashboard backend, registered endpoint, real credentials, Docker resource
or user database is used. The suite's built-in Node runner needs no Playwright configuration file.

For offline environments with the same cached Playwright version, set `UI_PLAYWRIGHT_MODULE` to
that package directory. `UI_WEB_ROOT` can select an isolated frontend snapshot for a before/after
regression; the default is this checkout's `web/`. JavaScript syntax checks remain useful but do
not substitute for these browser interleaving tests.

### Partial refresh failures and last-known data

Overview panels, the machine sidebar, attacker rows and country choices keep their last successful
response separately from the newest request error. A failure displays a compact warning with the
last successful refresh time in UTC, its age, the retained range/filter context and a local retry.
These timestamps describe successful UI fetches; the existing scrape/activity timestamps still
describe collection freshness. A failed first load says there is no successful data yet. Healthy
panels remain usable and continue refreshing; recovery clears the warning.

Map/country failures are not empty results or evidence that geography is unconfigured. A successful
empty geography result says no geography is known in the selected range; Settings remains the
place to inspect enabled sources. Known empty machine lists are distinguished from unavailable
metadata, so a failed machine refresh does not hide otherwise available overview data.

Retry controls issue reads only. Map, country and attacker-list retries target their own endpoint;
summary/chart retry fetches their paired overview and time-series inputs so card totals and chart
context stay consistent. Machine retry uses the existing serialized refresh round. The selected
country/search/status filters survive failures and retries, including a selected country absent
from a later successful choice list. Each panel still uses FIX-022 cancellation and generation
checks. There is no extra refresh scheduler or unbounded response history.

The local browser suite also tests individual endpoint failures, repeated transport failures,
first-load failures, stale values/timestamps, empty success, targeted recovery, filter retention
and machine-cache failure/recovery. Chromium may transparently retry a failed GET connection;
the harness distinguishes that from another logical application request. Optional
`UI_SCREENSHOT_PATH` captures the first-load map-failure view for visual review.

### Machine scope and attacker navigation

The sidebar defaults to all registered machines, including disabled machines' retained history.
Every dashboard request sends the checked IDs explicitly; **All** includes disabled history and
**None** sends `machines=0`. Disabled machines remain unscheduled for collection. Direct API clients
that omit `machines` still receive enabled machines only; this API default is unchanged.

Attacker URLs capture machine IDs, range, search, country key, status, time basis, sort/direction
and page. Changing controls updates the current history entry, so browser Back restores the
investigation. Changing the sidebar scope preserves filters and resets page to 1 only when the machine set changes. Machine-detail
“View all” links carry that machine's ID and range and update the checked sidebar scope. The table
shows its active machines, disabled-history intent and range. Unknown/deleted IDs in a URL are
pruned against an available machine list; an empty result remains None, rather than selecting all.

This uses URL state and the existing local selection preference, with no saved profiles, schema
migration or server API change. Existing complete sort/IP/machine-ID ordering keeps tied rows stable
on an unchanged dataset; it does not freeze data while collection changes it.

## Isolated real-exporter smoke tests

Run `make e2e` on Linux with Docker Compose, Bash, GNU `timeout`/`setsid`, and the repository's
Go toolchain. This opt-in test builds the dashboard and starts a fresh, uniquely named Compose
project. Dashboard, SSH tarpit and fixture-metrics ports use ephemeral **127.0.0.1-only** bindings,
so repeated and concurrent runs do not share ports, containers or data. Both dashboard enrichment
sources and exporter geography are explicitly disabled; no registered machine or live database is used.

`e2e/run.sh` installs EXIT/INT/TERM cleanup before creation, waits for its foreground process group,
then captures container logs, tears down project volumes/networks, removes remaining project-labelled
resources and checks that the project's container/volume/network inventories are empty. It never
runs a global prune. Cleanup verification failure makes an otherwise successful run fail. SIGKILL,
host power loss or an unavailable Docker daemon cannot be repaired by a shell trap; the printed
project name and retained inventory logs identify any resources requiring recovery.

Each invocation prints its log directory (a unique directory under `/tmp` by default). Set
`E2E_ARTIFACT_DIR` to choose the parent directory. Build/startup/test/container/cleanup logs,
`remaining.log`, the exporter image identity and `exporter.prom` survive teardown. Built images and
Docker build cache are retained; containers, volumes and networks are removed. For an intentionally
prebuilt test image, set `E2E_DASHBOARD_IMAGE` and `E2E_SKIP_BUILD=1`. `E2E_COMPOSE_OVERRIDE` accepts
a test-only override file; `./e2e/run.sh false` deliberately exercises assertion-failure cleanup.
All these paths keep fresh project ownership and loopback-port checks.

The daemon-free `go test ./e2e` lifecycle regression covers startup/assertion failures, INT/TERM,
teardown fallback, success and concurrent runs while preserving unrelated inventory. The optional
GitHub Actions **Run workflow → run_e2e** job runs the real harness with a 35-minute limit (including cleanup headroom) and
uploads retained logs even on failure. Normal CI continues running the daemon-free regression.

| Exporter evidence | Version / fixture | Verified scope |
| --- | --- | --- |
| [Upstream release](https://github.com/shizunge/endlessh-go/releases/tag/2026.0730.0), pinned in `e2e/exporter.env` | `2026.0730.0`, manifest `sha256:8826dad32623c503ec862f9266c1374da3f4a2821e8f9356bda5463a335b6225` | Linux amd64 real-image login/password change, scrape/attacker growth, disabled geography, and six counter-family types after connect/disconnect; exact observed metrics retained as `exporter.prom` |
| Existing parser fixtures under `internal/scrape/testdata/` | Synthetic/legacy data; upstream release unidentified | Parser regressions only; these do not establish support for another exporter release |

This is a one-release compatibility matrix, not an all-version or multi-architecture claim. When
changing the pin, update the explicit identity assertion in `e2e/smoke_test.go`, run the real stack,
and record the observed contract before extending this table. The new release flag is
`-prometheus_enabled`; the test uses that flag and `-geoip_supplier=off` explicitly.

## Resource measurements

The datastore has one SQLite writer. Retained row counts, query windows, scrape batch size and
cadence, concurrent readers, and storage affect responsiveness. No fixed machine/IP capacity or
idle-memory budget is established by the query measurements below. Reproduce the relevant
workload on your host before relying on a particular refresh or collection interval.

### Reproducing retained-row query measurements

`internal/store/queries_benchmark_test.go` generates disposable 10k/100k/1m attacker-row
fixtures without polling machines. Each has ten machines, half its rows on one machine, 20% of
rows sharing IPs in pairs, country aliases, missing geography, and activity spread over 90 days.
The generated age/machine pattern concentrates the 24-hour population on machine 1; the 90-day
page cases span all ten. This is one skewed workload, not a sample of every fleet distribution.
Enrichment progress starts empty (a fresh backfill backlog). The fixture focuses on attacker
queries; it does not seed a full historical rollup/counter archive.
It compares the existing schema-12 IP index with a temporary test-only index removal. No migration
is added by this performance change, and no production index is removed.

Run on an otherwise quiet host, retaining output outside temporary databases:

```sh
GOMAXPROCS=4 go test ./internal/store -run '^$' \
  -bench '^BenchmarkDashboardQueries$' -benchtime=20x -count=1 -v -timeout=45m \
  > query-bench.log 2>&1
```

Use `/rows=100000$/ipindex=true$/page-` after the benchmark name to select just the indexed
100k page cases. Set `DASHBOARD_BENCH_WIDE_PAGE=1` to compare the former wide-row sorting strategy
against current narrow-key page selection. Both include total/distinct counts and
full detail decoding. Page order is sort value (requested direction), canonical IP text ascending,
then machine ID ascending. OFFSET still has to visit and sort preceding rows.
Narrow-key selection fetches full details after sorting keys. It improves the measured million-row
deep-page workload, with a small-dataset latency tradeoff described below. API fields and page numbers are
unchanged. A complete order stabilizes ties in an unchanged dataset;
it does not freeze pages while scrapes or retention change the data.

Output includes SQLite query plans, first-operation latency after reopening SQLite connections,
warm p50/p95 operation latency, Go allocations, database bytes and WAL file growth. Reopening does
not evict OS caches, so “first” is not a physical cold-disk measurement. WAL file growth is an
allocated-file high-water change, not total bytes written; automatic checkpoints can make growth
zero. Explicit final truncating checkpoints are outside timed operations. Go allocations exclude
fixture setup and are not RSS or SQLite page counts; concurrent-case allocations include the writer.
Twenty samples give a rough percentile, not a stable tail-latency or capacity guarantee.

Scrape cases use real `ApplyScrape` transactions for 100 existing or new attacker rows and one
aggregate counter baseline (no network/parser work or full client-series baseline load). A separate
stress case runs overview reads with a 100-row writer paused one millisecond
between commits and reports read and write percentiles. This is deliberately more frequent than
typical polling. The keyset probe returns keys only, has a supplied cursor and omits counts, detail
fetches and cursor discovery; it evaluates sequential navigation, not an equivalent page-number API.
Shared/as-of reads across browser requests would require a separate consistency contract; this change adds
no cache or cross-request snapshot and preserves current independent-read semantics.

### Observed query results (2026-11-06)

These observations used Go 1.26.10, modernc SQLite 3.53.3, an Intel i7-10750H with
`GOMAXPROCS=4`, WAL / `synchronous=NORMAL`, and `/tmp` on tmpfs. They are not persistent-disk,
HTTP response-time or low-memory-host guarantees. Setup was excluded; timed benchmark runs were
serial. Raw measurements, allocations, first-read times and plans are retained in the
[baseline log](docs/benchmarks/queries-20261106-baseline.txt) and
[narrow-key log](docs/benchmarks/queries-20261106-narrow.txt).

Page results below include counts, 50 returned rows, and detail decoding; deep pages start at
75% of the fixture. All times are **median / p95 in milliseconds**, with the existing IP index.
The baseline predates explicit machine-ID tie-breaking; the final query and wide-row reference
both specify it. Sample percentiles are observations, not statistical confidence bounds.

| Rows | First page: before | First page: narrow keys | Deep page: before | Deep page: narrow keys |
| --- | ---: | ---: | ---: | ---: |
| 10,000 | 18.9 / 20.3 | 29.7 / 31.2 | 47.0 / 48.9 | 59.7 / 79.4 |
| 100,000 | 188.9 / 214.2 | 224.3 / 305.9 | 626.4 / 748.1 | 645.5 / 919.2 |
| 1,000,000 | 2,335.0 / 2,723.0 | 2,268.0 / 2,841.0 | 10,867.0 / 12,363.0 | 5,929.0 / 7,041.0 |

Narrow-key selection reduced the million-row deep-page median by about 45% and p95 by about 43%.
It is not universally faster: at 10k rows the deep-page median increased by about 13 ms; at 100k
rows it was roughly flat, with a worse observed p95. First-page results also varied. The retained
change targets the costly million-row deep page without a new index or write path. OFFSET and
exact counts still scale with retained rows; no cursor API, cache or cross-request snapshot is added.

The full IP index was already delivered by schema 12 (FIX-019). This task measured its value
rather than adding a duplicate. The following compares temporary fixtures with that index removed
against the same schema with it present. IP-update and 100-new-row write times are median / p95 ms.

| Rows | IP update: no index → indexed | Extra database bytes (MiB / %) | 100 new rows: no index → indexed |
| --- | ---: | ---: | ---: |
| 10,000 | 10.6 / 12.0 → 0.068 / 0.166 | 0.22 / 9.2% | 13.9 / 14.9 → 14.8 / 19.8 |
| 100,000 | 200.1 / 280.9 → 0.076 / 0.117 | 2.32 / 9.5% | 15.3 / 16.5 → 16.6 / 19.3 |
| 1,000,000 | 4,537.0 / 4,838.0 → 0.101 / 0.157 | 24.22 / 9.6% | 21.6 / 25.2 → 18.8 / 21.6 |

Plans change from a full attacker-index scan to a search using `idx_attackers_enrichment_ip`
with `ip_address=?`. This measured lookup benefit supports retaining the index despite its roughly
9–10% fixture-size overhead. Write latency did not show a uniform direction across sizes;
20 samples do not establish an insert-throughput guarantee. This task adds no DDL or write changes.
At 1m rows, the 100-existing-row write series grew the allocated WAL file by about 1.87 MiB in both
index modes; the subsequent new-row series grew it by zero because the file was already allocated.
Final truncating checkpoints returned WAL size to zero. These are file-growth figures, not write volume.

The indexed million-row overview and country summary remained slow (medians about 4.8 s and
2.0 s). Narrow-key pagination does not improve those queries. Go allocation size for the million-row
deep page stayed near 87 KiB/op with 1,492 allocations/op; SQLite work and temporary sorter storage
are not measured by that figure. Use the full logs and your own workload before choosing refresh
intervals or storage. Physical cold-cache/durable-disk tests and broader fleet distributions remain
unmeasured; no universal machine/IP capacity is asserted.

## Security posture

- **Authentication required by default.** No unauthenticated access to attacker data or machine
  configuration. Argon2id password hashing, server-side sessions, forced password change on first
  login, login rate limiting, CSRF tokens on every mutating request, and a `'self'`-only CSP.
- **Scrape targets are SSRF-vetted** on every add and edit, and again at scrape time. Host syntax,
  port range, and path are validated; DNS is resolved and the result checked before dialing, and the
  vetted IP is the one actually dialed, so a DNS answer that changes afterwards cannot redirect the
  request. Loopback, link-local (`169.254.0.0/16` and `fe80::/10`, which covers cloud metadata at
  `169.254.169.254`), multicast, and unspecified addresses are rejected. Redirects are never
  followed; response size and time are capped.
- **Documented deviation: RFC1918 private ranges are allowed by default.** The original security
  requirement said to block "arbitrary internal addresses", but home-lab and single-host tarpits on
  private LANs are the primary use case for this tool, and blocking private ranges would break it.
  Set `SCRAPE_BLOCK_PRIVATE=true` if all your targets are public and you want the tighter posture.
  Anything you genuinely need — including loopback for a tarpit on the same host — can be permitted
  precisely with `SCRAPE_ALLOWLIST_CIDRS` instead of relaxing the rule globally.
- **Container hardening**: `gcr.io/distroless/static-debian12:nonroot` pinned by digest, no shell and
  no package manager in the image, runs as uid 65532, `read_only: true` root filesystem,
  `cap_drop: [ALL]`, `no-new-privileges`, and `/data` as the only writable path.
- **No phone-home by default, one opt-in exception**: out of the box the only outbound connections
  the container makes are the scrapes to the machines you registered. Setting `GEOIP_ONLINE=true`
  adds one more — unplaced attacker addresses sent to the configured provider (HTTP by default), rate-limited, with
  private and loopback addresses never sent and redirects never followed. It is off unless set, and
  when it is on the container says so in a startup warning naming only the host and transport. There is no
  telemetry, no update check, and no external asset; the `'self'`-only CSP is the runtime tripwire if
  that ever regresses.
- **SQL safety**: parameterized statements only; machine names and labels are user-supplied.
- **Dependency hygiene**: a short, justified dependency list, with `govulncheck` in CI.

## Testing a machine before you add it

The **Add machine** and **Edit machine** dialogs carry a **Test connection** button. It runs one
bounded read against the typed host using the scheduled scraper's address policy, redirect refusal,
response-size limit and parser. It does not save a machine or poll registered targets as part of this test.

The response separates `reachable` (an HTTP response arrived), `exposition_valid` (the complete
bounded response was accepted by the dashboard, including supported type/value checks) and
`endlessh_evidence`. Valid metrics with no supported samples are **inconclusive**: an unrelated
runtime metrics service and a fresh, childless Endlessh exporter can look identical. Saving remains
available; check the target rather than treating the result as verified product identity.

One to five supported sample families give **partial** evidence; all six give **compatible** evidence
for the supported metric contract. Missing families can be normal before traffic or a disconnect.
These states do not authenticate product/version identity or infer a tarpit version from `go_info`.
Family diagnostics include only the six known names, observed counter/untyped types and sample
counts, without raw labels. The pinned exporter compatibility evidence is described in
[Isolated real-exporter smoke tests](#isolated-real-exporter-smoke-tests).

The legacy address, counts, reported ports and `geoip_enabled` fields remain; that last field means
usable country labels were observed, not that exporter GeoIP configuration was verified. Per-IP
samples are cumulative and do not establish active sessions. Wrong types, malformed/oversized
responses and transport failures still fail the test; reached-but-invalid responses are distinguished
from connection failures. Registration remains independent of testing.

## Troubleshooting

### A machine shows "down"

Status is `down` after repeated consecutive scrape failures, `degraded` after the first one. The UI
shows the last error text on the machine — read that first. Then, from a host that can reach the
target:

```bash
curl -fsS http://TARPIT_HOST:2112/metrics | head -20
```

- Empty or connection refused: the tarpit is not running with `-prometheus_enabled`, or it is bound
  to `127.0.0.1` on its own host, or the port is not published from its container.
- Works from your laptop but not from the dashboard: it is a network path or firewall issue between
  the two containers or hosts, not a dashboard problem. Two containers on the same Docker network
  can address each other by service name.
- Error text mentions a blocked address: your target resolves to loopback, link-local, or (with
  `SCRAPE_BLOCK_PRIVATE=true`) a private range. Allow exactly what you need with
  `SCRAPE_ALLOWLIST_CIDRS`.

History is never discarded because a machine went down. When it comes back, scraping resumes and the
status returns to `ok`; the gap stays visible in the charts.

### No data appearing

- Give it two scrape intervals. Nothing shows up before the second scrape, because the first one
  only establishes the counter baseline to compute deltas from.
- A tarpit no attacker has touched yet reports zeros. Confirm real traffic by connecting to it
  yourself: `nc TARPIT_HOST 2222` should hang and slowly print junk. Leave it open for a minute and
  you should appear in the Attackers list.
- Check that the machine is `enabled` and selected in the machine multi-select at the top of the
  page — an empty selection means all enabled machines, but an explicit selection can hide the one
  you are looking at.
- Check the selected time window. A 24h window on a tarpit that was down all day looks identical to
  a broken dashboard.

### Forgotten password

The runtime image has no shell, so recovery is done against the database file with a throwaway
container. Clearing the user rows makes the app re-seed from `ADMIN_PASSWORD` at the next start,
with the forced-password-change flow active again:

Set a new `ADMIN_PASSWORD` in `.env` first, then find your data volume and clear the user rows:

```bash
docker volume ls --filter name=endlessh-data
```

```bash
docker compose stop dashboard
```

```bash
docker run --rm -v endlessh-dashboard_endlessh-data:/data alpine sh -lc \
  'apk add --no-cache sqlite >/dev/null && sqlite3 /data/endlessh.db "DELETE FROM sessions; DELETE FROM users;"'
```

```bash
docker compose up -d dashboard
```

The volume is named after the directory you ran `docker compose up` in, so substitute whatever
`docker volume ls` reported above. If you swapped the named volume for a bind mount, use
`-v "$PWD/data:/data"` instead.

Take a backup before doing this if the data matters to you — **Settings → Backups** has a
**Back up now** button, and the file can be downloaded from there.

### GeoIP labels are empty

Blank country and location are a supported, normal state, not an error — the UI hides those columns
rather than showing placeholder text. Causes, in order of likelihood:

- The monitored host runs without `-geoip_supplier` (the upstream default is `off`) and you have not
  set `GEOIP_MMDB_PATH` here. Do one or the other.
- `GEOIP_MMDB_PATH` is set but the file is not actually mounted, is not readable by uid 65532, or is
  a Country database where a City database is expected — the file must be a MaxMind GeoLite2
  `.mmdb`. Check the startup logs and the GeoIP status shown on the Settings page.
- Rows recorded before you mounted the database are filled in by the backfill worker, not instantly:
  it sweeps once a minute, up to 100 eligible addresses at a time; recorded misses do not block older IPs.
- The address is private, loopback or link-local. Nothing can place those, by design.
- Some public IPs are genuinely absent from GeoLite2. That is a gap in the database; only the opt-in
  online lookup (`GEOIP_ONLINE=true`) will fill it, and nothing is fetched online while it is off.

## Building from source

Source builds require **Go 1.26.10** on the 1.26 line, or a security-patched newer release
(**Go 1.27.3 or later** on the 1.27 line). CI and the digest-pinned Docker builder use
**Go 1.26.10** and disable automatic toolchain switching so the compiler is explicit. The
`go.mod` minimum refuses older 1.26 compilers; when choosing another release line, check its
corresponding security patch level rather than relying only on that minimum.

```bash
go version
make build
go version -m bin/endlessh-dashboard
```

The last command reports the compiler embedded in the binary. CI checks this metadata for both
the local build and the binary extracted from the container image, alongside the existing tests
and image-size gate. `make docker-build` uses the pinned builder without requiring a local Go
installation.

Go 1.26.10 includes the fixes referenced in
[GO-2026-6609](https://pkg.go.dev/vuln/GO-2026-6609),
[GO-2026-6608](https://pkg.go.dev/vuln/GO-2026-6608), and
[GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809). Go's standard library is compiled into this
static binary: updating the host's Go installation or only the runtime base image does not patch
an existing binary. Rebuild and redeploy the dashboard, or install a release verified to contain
the patched compiler. This compiler update changes no database schema or configuration.

## Versions and upgrading

The versioned reference for this release is `ghcr.io/aiulian25/endlessh-dashboard:1.5.0`:

```yaml
image: ghcr.io/aiulian25/endlessh-dashboard:1.5.0
```

The quick start references `ghcr.io/aiulian25/endlessh-dashboard:latest`, a mutable tag. Verify
its platform manifest and compiler provenance before deployment; this checkout's CI builds and
tests an image but contains no release-publishing workflow. A version-looking tag is not proof of
immutability: for reproducible deployment, choose and record a verified platform/index digest, and
use `image: ghcr.io/aiulian25/endlessh-dashboard@sha256:<verified-digest>` in Compose after replacing
the placeholder with that digest. Do not infer image size or architecture support from a tag name.

Startup migrates the database forward automatically. Migrations are **not all additive**:
`0002_drop_distinct_ips.sql` drops a column, and later migrations transform identities and metadata.
There are no down-migrations. Take and download a verified backup **before every upgrade**, including
patch upgrades that contain schema changes, and retain the matching previous image/binary plus its
configuration. Backups are stored on the data volume, so copy them off-host.

Before upgrading, read the relevant migration and restore notes and budget for temporary database
copies. Replacing the image with an older version does not reverse schema or data transformations;
newer/unsupported schemas are rejected. A downgrade requires an appropriate **pre-upgrade backup**
and compatible older binary. Restore replaces the entire database, including accounts and all
machines' history, reverting later changes; it is not a per-machine merge. The restore verifier
checks compatibility and upgrades disposable copies of supported older schemas. Follow
[Backups and restore](#backups-and-restore) for the journaled replacement/recovery protocol and its
filesystem limits. Disable a machine to preserve history; deleting it cascades its stored data.

## Credits

This dashboard watches somebody else's tarpit. The tarpits deserve the credit:

- **[endlessh](https://github.com/skeeto/endlessh)** by Chris Wellons (skeeto) — the original SSH
  tarpit, and the idea this whole thing rests on: answer a scanner with an endless SSH banner and
  let it sit there.
- **[endlessh-go](https://github.com/shizunge/endlessh-go)** by shizunge — the Go implementation
  that adds the Prometheus metrics this dashboard reads. Without its `/metrics` endpoint there
  would be nothing to show. It is treated strictly as a black-box source; nothing here modifies or
  redistributes it.

The world map outline is derived from [Natural Earth](https://www.naturalearthdata.com/) public
domain vector data, projected once and embedded, so the map needs no tile server and no request
that could tell anyone who is looking at your dashboard.

## Licence

MIT — see [LICENSE](LICENSE).

### Keyboard focus and mobile navigation

Background redraws restore the same sidebar link, table sort/pagination control or machine action
when it still exists; otherwise focus moves to the region heading or the region itself. A focused chart or map keeps its
inspected content until focus leaves that region, while other panels continue updating. Editing
fields, dialogs and machine reordering retain their existing refresh pause. Route navigation focuses
the main heading; changing the selected machines keeps focus on the selection control. Search has a
visible container focus ring. A successful retry moves focus to a heading before hiding its button.

At widths up to 900px the Machines drawer is modal: opening focuses Close machines, Tab stays
inside, and Escape, Close or the scrim returns focus to the opener. Following a machine link closes
it and focuses the route heading. Background controls are inert while it is open. Desktop sidebar
navigation remains nonmodal. Tables retain their columns and horizontal scrolling at narrow widths.

The local Chromium suite covers desktop, 900px and 520px keyboard paths, 200% CSS zoom with long
IPv6/country/organisation content, long errors, chart/map text alternatives and reduced motion.
Rendered dark/light focus-to-card contrast is 5.40/5.35:1; main text is 13.30/16.42:1 and muted
text is 5.60/5.59:1. These representative measurements are not a complete WCAG conformance audit.
Manual screen-reader testing, other browser engines and browser-toolbar zoom remain unverified.

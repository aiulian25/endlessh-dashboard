# Pre-release test checklist

A human walks this list before tagging a release. Record the pass at the bottom.

## Running the automated suites first

Do not start the manual pass until these are green — the checklist below is for what automation
cannot see.

**Unit tests** (fast, no containers, no network):

```bash
go test ./...
```

**End-to-end smoke test** (real endlessh-go container plus the dashboard built from this repo; data
on tmpfs so every run starts clean). It is behind the `e2e` build tag and skips unless `E2E=1`, so
it never runs in the normal pass:

```bash
docker compose -f e2e/docker-compose.e2e.yml up --build -d
E2E=1 go test -tags e2e -count=1 -timeout 15m ./e2e/...
docker compose -f e2e/docker-compose.e2e.yml down -v
```

**Browser checks** are driven with `playwright-cli` against a seeded instance (`playwright-cli
--help` for the available commands). This is **dev-only tooling and is never part of the shipped
image** — the runtime image is distroless with no shell, no Node, and no browser.

Also worth confirming before the manual pass: `CGO_ENABLED=0 go build ./...` succeeds,
`govulncheck ./...` is clean, and the built image is under 30 MB (`docker image ls`).

## Install and empty state

- [ ] Fresh volume, first start: `GET /healthz` returns `ok`.
- [ ] Container writes nothing outside `/data`; `data/endlessh.db` is created on first start.
- [ ] With no machines registered, Overview shows the "add your first machine" empty state — not
      blank charts, not zeroed cards presented as real data.
- [ ] Attackers and Backups pages render an honest empty state too.
- [ ] Settings shows the effective configuration matching the `.env` actually loaded.

## Authentication

- [ ] Any API call without a session returns 401 and the UI shows the login view.
- [ ] Login with the seed `ADMIN_USERNAME` / `ADMIN_PASSWORD` succeeds.
- [ ] First login forces the password change before anything else is reachable.
- [ ] After the change, the seed password no longer works.
- [ ] Repeated bad logins hit the rate limiter.
- [ ] A mutating request without `X-CSRF-Token` is rejected with 403.
- [ ] Session cookie carries `HttpOnly`, `SameSite=Strict`, and `Secure` (with `COOKIE_SECURE=true`).
- [ ] Logout invalidates the session — the old cookie gets 401, not a cached page.
- [ ] Password change from Settings works and invalidates the old password.
- [ ] Response headers include the `'self'`-only CSP on every page.

## Machines CRUD and SSRF rejection

- [ ] Add a machine: it appears in the list and in the machine multi-select.
- [ ] Edit name, port, path, and group label: changes persist across a reload.
- [ ] Disable a machine: it stops being scraped and shows the `disabled` status.
- [ ] Delete a machine: it disappears from the list and the selector.
- [ ] `127.0.0.1` as host is rejected inline with a readable message, not a stack trace.
- [ ] `169.254.169.254` is rejected.
- [ ] `fe80::1` is rejected.
- [ ] `192.168.1.10` is accepted (RFC1918 allowed by default — the documented deviation).
- [ ] With `SCRAPE_BLOCK_PRIVATE=true`, the same `192.168.1.10` is rejected.
- [ ] A loopback target is accepted only when its CIDR is in `SCRAPE_ALLOWLIST_CIDRS`.
- [ ] Validation fires on **edit**, not just on create.
- [ ] An invalid port (`0`, `70000`) and a path with unexpected characters are both rejected.

## Data correctness

- [ ] Overview stat cards match the numbers the API returns for the same window and selection.
- [ ] Window switch (24h / 7d / 30d / 90d) re-renders the chart and changes the deltas.
- [ ] Selecting one machine shows only that machine's data; selecting several aggregates correctly.
- [ ] Per-machine drill-down agrees with that machine's slice of the multi-machine view.
- [ ] Attackers table sorts by trapped time, first seen, last seen, and connections, both directions
      (there is deliberately no per-attacker byte count — the metrics do not carry one).
- [ ] Filters (country, trapped / gave up, IP prefix) return counts consistent with the country chips.
- [ ] Pagination edges are correct: first page, last page, and a page beyond the end.
- [ ] Restart a monitored endlessh-go instance (counters reset to zero): dashboard totals keep
      growing rather than dropping to zero or spiking.

## Attacker geography and the map

Geography has three sources — the tarpit's own labels, a mounted MaxMind `.mmdb`, and the opt-in
online lookup — and this section checks each one, plus that the last stays asleep when it is off.
Walk it with at least one tarpit whose attackers are public addresses; a LAN-only tarpit can never
produce a location and proves nothing here.

**The map and the breakdown**

- [ ] With placed attackers in the window, the map renders: country outlines plus a bubble per
      location, and nothing is fetched from the network to draw it (no tile requests — check the
      browser's network panel, which should show only this app's own origin).
- [ ] Bubble sizes/counts agree with the country breakdown beside them: the same window and machine
      selection, the same numbers, and both agree with the attackers table filtered to that country.
- [ ] An attacker with no coordinate is absent from the map but still present in the attackers
      table — never plotted at 0,0 or off the coast of Africa (endlessh-go's `s000` placeholder).
- [ ] Selecting a single machine, then several, re-renders both the map and the breakdown
      consistently with the table.
- [ ] The map is legible in both themes and has a text or table equivalent for screen readers.

**GeoIP off on the monitored host**

- [ ] A tarpit running without `-geoip_supplier` shows the "geography is off" state — an explanation
      of how to switch it on — not an empty map frame and not a zeroed breakdown presented as data.
- [ ] Its attacker rows show a blank country and location — never the literal "Geohash off" or
      "Unknown" leaking through from the labels.
- [ ] Private and LAN attacker addresses stay unplaced: no country, no bubble, row otherwise intact.

**Switching the tarpit's own supplier on**

- [ ] Restart a monitored tarpit with `-geoip_supplier=ip-api` (which makes *that host*, not the
      dashboard, call ip-api.com): new attacker rows gain country and location within one
      `SCRAPE_INTERVAL`, and the map gains bubbles for them.
- [ ] Same with `-geoip_supplier=max-mind-db -max_mind_db=...`, for an operator who does not want
      the tarpit calling out either.
- [ ] The tarpit's labels are not overwritten afterwards by a local `.mmdb` mounted on the dashboard.

**Mounted `.mmdb` on the dashboard**

- [ ] With a GeoLite2 City `.mmdb` mounted and `GEOIP_MMDB_PATH` set, new attacker rows gain country,
      location and a map bubble.
- [ ] Rows recorded *before* the file was mounted are filled in by the backfill worker within a few
      sweeps (once a minute, 100 addresses at a time, most-recently-seen first) rather than staying
      blank forever.
- [ ] A missing, unreadable, or non-`.mmdb` file fails loudly at startup instead of silently
      disabling geography.

**Settings names the source**

- [ ] Settings → Effective configuration names the geography source actually in use — the local
      MaxMind database, the online provider, or disabled — rather than only "enabled", and it matches
      what the `.env` actually loaded.

**The online lookup stays silent when it is off**

- [ ] With `GEOIP_ONLINE` unset (the default), the startup log contains no online-GeoIP warning.
- [ ] With it unset, a capture on the host over several backfill sweeps shows no traffic to
      ip-api.com from the dashboard container — only the scrapes to registered machines:
      `sudo tcpdump -nn -i any 'tcp port 80 and not host <your-tarpit>'` stays quiet for ten minutes
      with unplaceable attackers in the database.
- [ ] `GEOIP_ONLINE=true` logs the startup warning naming the endpoint and the rate.
- [ ] With it on, unplaced public addresses gain country, location and an ISP, and the same capture
      now shows requests to ip-api.com — at or below `GEOIP_ONLINE_RATE_PER_MINUTE`, never in a
      burst, and never carrying a private or loopback address.
- [ ] `GEOIP_ONLINE_RATE_PER_MINUTE=46` and a `GEOIP_ONLINE_ENDPOINT` without `{ip}` are both refused
      at startup with a readable message.

## Unreachable machine and recovery

- [ ] Stop a monitored tarpit: the machine goes `degraded`, then `down`, with the last error shown.
- [ ] Its recorded history stays visible; the gap is visible in the chart rather than backfilled.
- [ ] Other machines keep scraping normally while one is down.
- [ ] Start the tarpit again: status returns to `ok` and new data resumes within a couple of intervals.
- [ ] Point a machine at a host that accepts the connection but serves non-Prometheus content: the
      error is readable and the machine is marked down, nothing panics.

## Backup and restore

- [ ] Take a manual backup while scraping is active: it succeeds and is listed with size and time.
- [ ] Download the backup file and confirm `PRAGMA integrity_check` passes on the downloaded copy.
- [ ] Restore that backup: the app returns to a queryable state with the expected data.
- [ ] A corrupted or non-SQLite upload is refused with a readable error, and the live database is
      untouched.
- [ ] Rotation deletes the oldest backups beyond `BACKUP_KEEP_LAST`.
- [ ] Delete a backup from the UI: the file is gone from `/data/backups/`.

## Persistence across restart

- [ ] `docker compose restart`: no history lost, machines still registered, sessions behave sanely.
- [ ] `docker compose down && docker compose up -d` with the same volume: same result.
- [ ] Machine health recovers on its own after the restart, with no manual re-registration.

## Retention and settings visibility

- [ ] Settings shows scrape interval, retention days, GeoIP status and source, backup settings, and
      version — matching the running environment.
- [ ] Changing `RETENTION_DAYS` and restarting is reflected in Settings.
- [ ] After a nightly prune (or a manually triggered run in a test build), rows older than the
      retention boundary are gone, rows just inside it remain, and the database file has not grown.

## Theming

Check every page — Overview, Machines, Attackers, Backups, Settings — plus the login view and the
empty state, in both themes:

- [ ] Dark is the default on a fresh browser profile with no stored preference.
- [ ] The light toggle switches every page, including charts, tables, badges, and status colours.
- [ ] The choice persists across reload and across navigation.
- [ ] With no stored choice, `prefers-color-scheme: light` is honoured.
- [ ] No unstyled flash on load in either theme.
- [ ] Charts, status chips, and error states are legible in both themes.

## Accessibility spot-checks

- [ ] Keyboard-only pass: reach and operate every control on every page with Tab / Shift+Tab /
      Enter / Space / arrow keys — including the machine multi-select, window switcher, table sorts,
      modals, and the delete confirmations.
- [ ] Focus is always visible, and focus order follows the visual order.
- [ ] Modals trap focus while open and return focus to the trigger on close; Escape closes them.
- [ ] Contrast: text and meaningful UI elements meet 4.5:1 in both themes, checked on the darkest and
      lightest surface pairings and on the status colours (red/amber/green) specifically.
- [ ] Status is never conveyed by colour alone — there is text or an icon alongside.
- [ ] Charts have an `aria-label` and a text or table equivalent for screen readers.
- [ ] Pages remain readable with JavaScript disabled.

## Release record

| Version | Date | Tested by | Result | Notes |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

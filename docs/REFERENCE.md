# Configuration, CLI and operational reference

All device addresses, names and tailnet authorities in examples are synthetic.
Commands that change services are for a new installation or planned maintenance.

## CLI

```bash
netwatch scan
netwatch devices
netwatch devices --online
netwatch devices --review
netwatch review 1
netwatch unknown
netwatch events --limit 50
netwatch events --device 1
netwatch trust 1
netwatch trust 1 --revoke
netwatch edit 1 --name "Office NAS" --notes "Storage server"
netwatch info 1
netwatch --json devices
netwatch --config /etc/netwatch/netwatch.yaml monitor
netwatch --config /etc/netwatch/netwatch.yaml healthcheck
netwatch web --port 8765
netwatch install-service
netwatch set-password
```

Place global options (`--config`, `--json`, `--verbose`) before the command.
Selectors accept numeric IDs, MAC addresses, current IPs, or assigned names.
IP reuse and duplicate names can be ambiguous; numeric IDs and MACs are stable.
`unknown` includes offline devices. `info` shows recent events and observations;
`--limit` controls history length. JSON returns the full fields without table
truncation. `devices --review` includes first/last seen and assigned names.
`review` prompts for name, notes, and trust; blank answers keep current values,
and Ctrl+C cancels before anything is saved. Choose `unknown` to leave a device
untrusted. To clear a name or notes, use `edit --name ""` or `edit --notes ""`.
Console notifications and monitor logs go to stderr.

New devices produce:

```text
NEW DEVICE DETECTED
IP: 192.168.203.10
MAC: 02:00:00:00:00:10
HOSTNAME: -
VENDOR: -
TIME: 2026-01-01T00:00:00.000000+00:00
TRUST: UNKNOWN DEVICE
```

Exit status is 0 for success, 1 for failure/degraded discovery/unhealthy monitor,
2 for invalid command arguments, and 130 for an interrupted one-shot command.
The monitor stops gracefully on SIGINT/SIGTERM.

## Local dashboard

Start the monitor and dashboard in separate terminals, or install the user
services below:

```bash
.venv/bin/netwatch --config netwatch.yaml monitor
# In another terminal:
.venv/bin/netwatch --config netwatch.yaml web
```

Open **http://127.0.0.1:8765/** on this machine. Waitress serves the Flask app;
the development server is not used. There is no public bind option.

- `/` and `/security`: Security Overview followed by the existing device inventory.
  Live counters show online/offline, TRUSTED / KNOWN / UNKNOWN / BLOCKED, new
  identities and security events in the last 24 hours. The overview shows the last
  **successful** scan separately from current monitor health and the latest attempt.
- `/devices`: device table, monitor health, last scan, recent real alerts/events,
  categories, search, filters and sorting. Counts refresh every ten
  seconds; lists refresh every 30 seconds, pausing while a filter field has focus.
- `/unknown`: all UNKNOWN identities, including offline devices.
- `/events`: recent events with UTC timestamps.
- `/device/<id>`: identity, current and previous IPs, first/last seen, observations,
  event timeline, and a review form for name, notes, and trust. The current trust
  choice is preserved unless you explicitly change it.

The overview's status is derived from stored evidence:

| Status | Meaning |
|---|---|
| SECURE | No new unknown or blocked activity requiring attention; monitor healthy. This is not a vulnerability assessment. |
| ATTENTION | Unreviewed UNKNOWN identity (including newly detected devices), other security evidence requiring review, or stopped/stale monitor. |
| ALERT | Currently online BLOCKED device or unresolved high-priority trusted-MAC mismatch / blocked-presence evidence. |

New UNKNOWN identities are MEDIUM review items in the dashboard (ATTENTION).
Telegram's existing HIGH new-device notification priority is unchanged. The status
uses current UNKNOWN review states, current blocked presence and security evidence
from the last 24h, independently of the event
window selected. Historical events remain visible after a device is reviewed; a
subsequent explicit review-state change resolves earlier actionable identity
evidence. Routine reconnects, DHCP IP changes, scans, and manual review/name edits
are not security events. BLOCKED is a monitoring flag, not a firewall action.

Recent security events can be viewed for **24h / 7d / 30d**, with timestamp,
severity, friendly name, recorded IP/MAC and a short explanation. Up to 100 are
shown; counters use the full bounded window. Device details have the same security
history selector, alongside observation/IP history and identification notes.
The UNKNOWN review cards show vendor, age, first/last seen and a review action;
they never classify or approve devices automatically.

The lightweight map groups inventory by review state, with the recorded gateway
shown separately. It defaults to online devices and offers an offline toggle.
Internet is a conceptual node: map links do not establish physical topology,
Wi-Fi band, connectivity or traffic paths. On iPhone-width screens, inventories,
observations and events become readable cards with touch-sized controls rather
than wide tables. Authentication, CSRF, Host validation and loopback binding still
apply. Dashboard reads use a consistent SQLite WAL snapshot and never send alerts.

Search covers name, hostname, vendor, IP, MAC, category, and ID. Status and trust
filters combine, and IP sorting is numerical. Untrusted identities first seen
within the last 24 hours carry a NEW badge. Recent alerts represent real persisted
state transitions; they do not claim Telegram delivery succeeded.

The dashboard reads the same database and uses the existing Inventory service
for audited updates. Reading inventory does not start scans. Authenticated Device Investigation can optionally invoke one bounded ICMP reachability check. Unknown
identities remain `UNKNOWN`; a manufacturer lookup is not a device identification.
Default history views show 100 records; `?limit=500` increases the view limit.
The database retains the complete history, also accessible through the CLI.

Screenshots: [capture guide and placeholders](screenshots/README.md) for
`devices.png`, `device-detail.png`, and `events.png`. Live screenshots contain
private LAN inventory; anonymize them before adding them to documentation.

The local JSON API provides `GET /api/summary`, `/api/security`, `/api/devices`,
`/api/devices?unknown=true`, `/api/events`, `/api/device/<id>`, and `/healthz`.
`PATCH /api/device/<id>` accepts only `name` (string or null), `notes` (string),
`trusted` (boolean), and `trust_state` (TRUSTED / KNOWN / UNKNOWN / BLOCKED).
Updates require the signed session cookie and CSRF token
returned by `GET /api/csrf`; send the token as `X-CSRF-Token`. No trust or identity
fields change on a GET request. API errors use JSON and omit database internals.
Inventory endpoints accept `q`, `status=online|offline|all`,
`trust=trusted|known|unknown|blocked|all`, `category`, `sort=id|ip|name|vendor|last_seen|first_seen|category`,
and `order=asc|desc`. Device details include the stored fingerprint evidence.
Security endpoints accept `window=24h|7d|30d` (default 24h); the overview also
accepts `show_offline=true|false` for the logical map. `/api/summary` includes a
`security` summary. These GET requests never start scans or send Telegram messages.

```bash
curl --fail http://127.0.0.1:8765/api/summary
curl --fail http://127.0.0.1:8765/api/device/1
curl --fail http://127.0.0.1:8765/healthz
```

`/healthz` returns HTTP 200 when the dashboard can read SQLite, with a separate
`monitor_healthy` boolean for monitor readiness. Use `netwatch healthcheck` when
the exit status must reflect monitor health.

## Alerts

### Security alerts and device review

Review states are **TRUSTED** (explicitly approved), **KNOWN** (recognized but not
trusted), **UNKNOWN** (awaiting review), and **BLOCKED** (flagged for alerts).
Use the authenticated device detail form to choose a state, or run
`netwatch state <device-id> KNOWN` (also accepts TRUSTED, UNKNOWN and BLOCKED).
No vendor, hostname or fingerprint automatically changes review state. BLOCKED
does not block packets or alter any router/firewall configuration.

Telegram sends HIGH priority alerts for a new UNKNOWN MAC, a BLOCKED device
observed online, and a trusted MAC mismatch candidate. The last rule requires
a unique matching hostname and vendor on the same interface while the expected
trusted MAC is absent from the scan. It is evidence for review, not proof of the
same physical device: records are never merged and trust is never transferred.
For an explicitly trusted gateway, a different MAC at the current kernel gateway
address is also eligible without hostname/vendor evidence. Ordinary client DHCP
addresses do not qualify for this exception.
DHCP address reuse alone cannot trigger this rule. Without hostname/vendor
evidence, a new MAC still triggers the new-unknown rule.

MEDIUM alerts cover simultaneous meaningful hostname **and** vendor changes on
KNOWN/TRUSTED records, and an offline device returning after 24 hours without an
observation. Case-only changes, metadata enrichment, a single changed signal,
ordinary DHCP IP changes, short reconnects and routine online/offline events
do not notify Telegram. Existing historical events are not replayed on upgrade.

SQLite schema 3 adds review states and notification claims without deleting
inventory/history. Existing trusted flags migrate to TRUSTED; all other records
migrate to UNKNOWN. Back up SQLite with its backup API before upgrading. The legacy
`trusted` API boolean remains supported; `trust_state` is the four-state field.

Persistent claims prevent the same event from being notified twice across
restarts. Identical security evidence has a minimum 60-minute cooldown, even if
new event IDs arise. Suppressed events are recorded as suppressed and cannot be
replayed later. Changed identity evidence or a new explicit BLOCKED review can
notify immediately. Claims are made before enqueueing: delivery remains best
effort; provider failure does not replay the event or stop the monitor.

With `notifications.console: true`, the monitor logs a combined new/unknown
device alert, device offline, device online again, and IP address changed.
Alerts follow persisted state-change events; unchanged scans do not repeat them.
Offline detection retains the configured timeout and complete-scan requirement.

`NotificationService` accepts providers implementing `send(Alert)`. A Telegram,
Discord, or other provider can be injected without changing discovery or inventory
logic. Console and Telegram providers are implemented. Provider errors are isolated
from monitoring. Delivery is best effort after the transaction commits: there is
no durable delivery queue or crash replay.

### Telegram setup

Create a bot and an authorized destination chat using the
[Telegram Bot API](https://core.telegram.org/bots/api). Keep the bot token and chat
ID outside YAML, source, notes, shell history, and Git. Either provide
`NETWATCH_TELEGRAM_BOT_TOKEN` and `NETWATCH_TELEGRAM_CHAT_ID` through your service's
secure environment, or create an owner-only `netwatch.secrets` file with an editor:

```bash
install -m 600 /dev/null netwatch.secrets
${EDITOR:-nano} netwatch.secrets
```

The file accepts plain `KEY=value` lines for those two variables, without shell
expansion, `export`, or surrounding quotes. Insert the actual values only in this
private file. `.secrets` and `.env` files are ignored by Git and excluded from
packages. It must be owned by the service account; symlinks and group/world-readable
files are rejected. Do not overwrite an existing secrets file with the command above.

```yaml
secrets_file: ./netwatch.secrets
notifications:
  console: true
  telegram: true
  security_cooldown: 3600  # seconds; cannot be less than one hour
  long_absence: 86400     # seconds since the last observation; default 24 hours
```

`NETWATCH_SECRETS_FILE` can also supply the path; individual environment values take
precedence over file values. Restart `netwatch.service` after changing credentials.
Missing or invalid credentials disable Telegram with a redacted warning while
console alerts and monitoring continue.
Enabling Telegram delivers future transitions; it does not replay old events.

Telegram delivery uses verified HTTPS directly to `api.telegram.org`, plain text,
disabled link previews, no redirects, a five-second socket timeout, up to three
attempts with exponential backoff, and bounded handling of rate-limit responses.
A background queue of 128 alerts prevents network waits from delaying scans.
Repeated unchanged observations do not enqueue alerts; persistent security claims
and recent in-memory event IDs prevent duplicate enqueueing. Long rate limits, queue overflow, or exhausted
attempts can drop an alert. Shutdown can discard pending work; inspect the local
event history for the authoritative record. One-shot scans allow a 20-second
delivery window before exiting. Response/error text and token-bearing URLs are
never logged. A timeout after Telegram accepts a message can still produce a
duplicate on retry: the Bot API has no idempotency key for this call.

## Evidence-based fingerprints

Categories are Computer, Mobile Device, Tablet, Smart TV, IoT, Network Equipment,
Printer, Server, and Unknown. Fingerprints combine recorded vendor/OUI information,
reported hostnames, assigned NetWatch names, neighbour observations, previous IPs,
and optional locally readable dnsmasq DHCP leases. Existing DNS/NSS enrichment
contributes reported hostnames when enabled; fingerprinting adds no new DNS probes.

```yaml
dhcp_files: [/var/lib/misc/dnsmasq.leases]
```

DHCP hints require a matching MAC/current IP and an unexpired or non-expiring lease.
Malformed, conflicting, unavailable, and oversized local files are ignored; no
router or DHCP-server queries are made. Only dnsmasq lease syntax is currently
supported. File paths are opt-in; no permissions are widened to read them.

Explicit category words in reported names support medium confidence. Corroborating
Apple names/OUI or a confirmed kernel default-gateway role support high confidence.
Vendor alone is inconclusive; contradictory category hints remain Unknown. Confidence
is a rule label, not a measured probability or authentication. Names/OUI can be
spoofed. No exact device model is inferred. The detail page shows every retained
clue and the rule or conflict behind its category. Refreshes change neither trust
nor liveness and create no synthetic device events.

## Configuration

See [netwatch.example.yaml](../netwatch.example.yaml). Config selection: explicit
`--config`, then `NETWATCH_CONFIG`, then `./netwatch.yaml`. If the implicit default
file is absent, safe built-in defaults apply. An explicitly requested missing
file is an error. Relative database/vendor paths resolve against the config
file's directory. Without a config file, data lives in
`$XDG_STATE_HOME/netwatch/netwatch.db` (default `~/.local/state/netwatch/netwatch.db`).

```yaml
subnet: null
interface: null
scan_interval: 60
offline_timeout: 300
database_path: ./data/netwatch.db
discovery_methods: [neighbor]
max_hosts: 1024
ping_workers: 8
resolve_hostnames: false
notifications:
  console: true
```

Automatic detection chooses a connected private IPv4 subnet, preferring the
lowest-metric default-route interface when there are multiple candidates. An
ambiguous result fails closed: set `subnet` and `interface` explicitly. Configured
subnets must be canonical RFC1918 CIDRs and contained in a currently connected
interface subnet. `/31` and `/32` are unsupported. Active sweeps must fit
`max_hosts` (default 1024, maximum 4096); configure a narrower subnet if needed.
Intervals must be finite and at least ten seconds; offline timeout must be at
least the scan interval. The monitor waits the interval after each completed
scan, so slow scans cannot trigger catch-up bursts.

`discovery_methods: [neighbor, ping]` warms the neighbour cache using one ICMP
probe per host. Starts are limited to ten per second, with at most sixteen workers.
`[neighbor, nmap]` runs `nmap -sn -n` with bounded rate, retries, and host timeout;
there is no port inventory scan. Both active adapters correlate IPs with local
neighbour MACs. nmap chooses its available discovery techniques according to OS
permissions; root is optional, and this project does not request privilege
escalation. Without raw-packet privileges, hosts that reject TCP/ICMP discovery
may not appear.

`resolve_hostnames: true` enables bounded `getent hosts` lookups. Each lookup has
a two-second timeout and each scan has a ten-second enrichment budget (plus one
in-flight lookup). The monitor rotates lookup order across scans. This can consult
the host's configured DNS/NSS services. DNS may be external depending on your
resolver configuration; hostname resolution is disabled by default. A lookup
failure leaves the observation hostname absent without erasing known inventory
metadata. `vendor_file` optionally names a local `nmap-mac-prefixes` file with
`001122 Manufacturer Name` lines, or an IEEE `oui.txt` file such as
`/usr/share/ieee-data/oui.txt`. Randomized/locally administered MAC addresses
do not have reliable OUI vendor information.

## Architecture and history

```text
cli → services → discovery adapters
              → SQLite store
              → notification providers
web → dashboard queries / Inventory → same SQLite store
models: immutable records    utils: configuration, validation, processes, locking
```

The `netwatch/discovery`, `database`, `models`, `services`, `cli`, `notifications`,
and `utils` packages separate network I/O, persistence, and business logic. A scan
atomically stores its scan record, observations, inventory updates, and events.
SQLite uses WAL, foreign keys, a busy timeout, and schema versioning. New database
files use owner-only permissions. A process lock prevents overlapping scans or
multiple monitors against the same database; inventory reads and metadata edits
remain available during monitoring.
Schema version 2 adds fingerprint and network-context tables. Version-1 databases
migrate transactionally without replacing devices, observations, events, names,
or trust. Back up the database before upgrading and restart both processes together.
HTML templates and static assets ship in the
Python package; there is no separate frontend build or external asset service.

Devices are identified by normalized unicast MAC, with IP, hostname, vendor,
first/last seen UTC timestamps, online state, trust, assigned name, and notes.
Every successful observation is preserved. Events include `new_device`,
`device_online`, `device_offline`, `ip_changed`, `hostname_changed`,
`vendor_changed`, and metadata/trust changes. `mac_at_ip_changed` records a
previously known IP appearing with another MAC on both identities. This creates
a new unknown identity; it does not transfer trust or claim a physical device
changed its MAC. Missing enrichment values never erase previously known values.

"Online" means recently observed, not guaranteed reachable now. Passive scans
accept only REACHABLE neighbours. STALE, FAILED, INCOMPLETE, and static PERMANENT
entries alone are not liveness evidence. `/proc/net/arp` has no freshness signal
and is used only as a fallback when an active method confirms reachability.
Passive discovery sees only peers the host has recently communicated with and
can miss quiet or sleeping devices. If coverage matters, enable bounded active
discovery and choose an offline timeout appropriate to device sleep cycles.

Unobserved devices become offline after the timeout, only on a complete scan of
their current subnet and interface. Failed/degraded scans preserve previous
online state. Positive observations from degraded scans are still recorded.
Duplicate/conflicting observations are rejected atomically. Failed monitor
attempts are logged and recorded; the next scheduled attempt continues.

## Docker deployment

```bash
cp netwatch.example.yaml netwatch.yaml
docker compose up --build -d
docker compose logs -f netwatch
docker compose exec netwatch netwatch --config /etc/netwatch/netwatch.yaml devices
```

Compose uses Linux host networking to access host interfaces and neighbours.
Bridge networking usually exposes only container peers; it cannot inventory
the physical LAN. Docker Desktop host-network behavior differs from native
Linux and is not a supported deployment target for LAN discovery here.
The image runs as UID/GID 10001 with capabilities dropped. Passive discovery
needs no root. nmap/ping may need additional capabilities on hosts that restrict
unprivileged probing; keep passive mode or grant only necessary capabilities
after testing your OS policy. Do not enable `privileged: true`.

The named volume persists `/data/netwatch.db`; Compose overrides
`NETWATCH_DATABASE_PATH` to this path. Bind-mounted configuration is read-only.
The image has a read-only filesystem and writable data/tmp mounts. Ensure a
bind-mounted replacement for `/data` is writable by UID/GID 10001. Healthchecks
only read SQLite; they never scan. Health requires a running monitor and recent
heartbeat and complete scan within `max(3 × scan_interval, offline_timeout)`.
Increase the healthcheck start period and `offline_timeout` for unusually slow
optional active sweeps. Health grace must exceed the scan duration plus interval.

## Always-on Linux services

For a checkout installed into `.venv`, generate and enable user services:

```bash
.venv/bin/netwatch --config netwatch.yaml install-service
systemctl --user daemon-reload
systemctl --user enable --now netwatch.service netwatch-web.service
systemctl --user status netwatch.service netwatch-web.service
journalctl --user -u netwatch.service -u netwatch-web.service -f
.venv/bin/netwatch --config netwatch.yaml healthcheck
```

The installer writes `~/.config/systemd/user/netwatch.service` and
`netwatch-web.service` with absolute checkout/config paths and owner-only permissions.
Run it from the checkout root. Re-run it and reload/restart the units after changing
discovery methods. Both units restart ten seconds after a process failure, log to
the journal, and stop on SIGTERM. Neither needs root. Keep the checkout, virtual
environment, config, and configured database path in place.

For startup at boot without a login, the account must have systemd lingering
enabled; inspect `loginctl show-user "$USER" -p Linger`. The installer does not change account policy. On another host,
an administrator can authorize `loginctl enable-linger <user>` if appropriate.
The user service retries discovery while the network starts; network failures
do not terminate the monitor.

The dashboard uses `NoNewPrivileges` and address-family restrictions. A monitor
configured with active ping preserves the OS-packaged ping executable's existing
file capability by omitting those restrictions: some hosts disable unprivileged
ping sockets, and user-manager seccomp filters also imply `NoNewPrivileges`.
This exception applies only to the monitor unit; it does not grant new capabilities,
run NetWatch as root, or change global kernel/network policy. Passive-only monitor
units retain the restrictions.

```bash
# Graceful maintenance shutdown; the database stays in place:
systemctl --user stop netwatch.service netwatch-web.service
# Start again:
systemctl --user start netwatch.service netwatch-web.service
# Also remove automatic startup if desired:
systemctl --user disable netwatch.service netwatch-web.service
```

For administrator-managed alternatives, see [docs/netwatch.service](netwatch.service)
and [docs/netwatch-web.service](netwatch-web.service). Adapt
paths, create a dedicated service user and writable state directory, and install
the config under `/etc/netwatch/`. The monitor is a foreground process intended
to be managed by systemd or Docker. Shutdown waits for the current bounded scan;
increase the service/container stop timeout for large active sweeps or low worker
counts. Optional active discovery should normally stay within a `/24`.

## Security model

NetWatch accepts only RFC1918 IPv4 networks directly attached to an UP interface.
It revalidates that boundary on every scan and filters all discovered addresses.
Public, IPv6, loopback, link-local, off-link, multicast, and broadcast targets are
excluded. Private VPN interfaces can qualify if connected; specify the physical
LAN interface to avoid choosing one. Private routed VLANs beyond the current
interface subnet are intentionally not scanned. Administrative permission to
monitor the configured LAN remains the operator's responsibility.

External tools receive argument lists with `shell=False` and a fixed system PATH;
there is no shell interpolation. Config uses safe YAML loading with a size limit
and strict keys/types. SQL values are parameterized. Untrusted display values
have control characters removed; JSON escapes them. There are no cloud vendor lookups. Telegram is an opt-in external notification service; console notifications are configurable.
Treat the database, logs, names, and notes as
private inventory information and protect backups appropriately.

The web listener binds only `127.0.0.1` and accepts localhost/127.0.0.1 Host headers,
plus a configured Tailscale hostname. Local users are trusted by default. Optional
password authentication protects every inventory page/API and uses an owner-only
scrypt hash, HTTP Basic challenges, and bounded failed-login throttling. The
Tailscale endpoint uses HTTPS; never send Basic credentials over a plain LAN proxy.
Changes require a signed session, a CSRF token, and same-origin requests; forms
and database text are escaped, framing is denied, and request sizes are bounded.
`Referrer-Policy: same-origin` preserves the browser's origin on device form
submissions while suppressing referrers to other origins. `no-referrer` would
make these POSTs send `Origin: null`, which remains forbidden. Origin checks
match the request's validated Host; configuring both local and Tailscale access
does not permit updates from one origin to the other. Waitress strips untrusted
`Forwarded` and `X-Forwarded-*` headers; they cannot override Host or scheme.
The session key is generated locally in an owner-only `.web-key` file beside the
database. Existing database/key/auth files must also be owner-only; unsafe symlinks
are rejected. Cookies use HttpOnly and SameSite=Strict, and Secure on the Tailscale
HTTPS authority. HTTP endpoints cannot accept executable commands or manage services. Authenticated Investigation optionally invokes one bounded ICMP check against a validated, fresh UNKNOWN-device address.

## LAN and Tailscale access

Direct LAN binding remains disabled. `127.0.0.1` refers to the machine running the
browser, so the local URL cannot be used from a phone or a different computer.
Use Tailscale for access from another device without router forwarding or firewall
changes. [Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve)
provides a tailnet-only HTTPS proxy; only users/devices permitted by your tailnet's
access policy should reach the endpoint. Treat that policy as application access
control and restrict the service port to the intended operators. Do not enable Funnel.

An administrator can add a separate endpoint while preserving existing Serve routes:

```bash
tailscale status
sudo tailscale serve --bg --https=8443 http://127.0.0.1:8765
tailscale serve status
```

Set the exact machine URL returned by Serve in YAML and restart the dashboard:

```yaml
tailscale_url: https://your-machine.your-tailnet.ts.net:8443
```

Then open that HTTPS URL from a device connected to the authorized tailnet. The
backend still listens on loopback; Serve preserves the original Host, and origin,
secure cookies, and CSRF are checked against the configured authority. The HTTPS
authority is accepted only from the loopback peer and at its configured port.
No forwarded headers need to be trusted. Do not reset the whole Serve config
when another application uses it. To remove only this endpoint, use
`sudo tailscale serve --https=8443 off`. If Serve reports access denied, an administrator
must run the command; NetWatch does not change Tailscale operator policy.

For a second authentication layer, set a password interactively:

```bash
.venv/bin/netwatch --config netwatch.yaml set-password
systemctl --user restart netwatch-web.service
```

The browser prompts for username `netwatch` and your password. Set
`web_auth_required: true` in YAML so a missing hash fails closed. Alternatively,
provide `NETWATCH_WEB_PASSWORD_HASH` through the private secrets file or environment.
API clients must also authenticate; authentication never replaces CSRF protection.
Changing the password requires a dashboard restart. Browser Basic credentials may
remain cached until the browser closes. There are no separate viewer/operator roles.

## Troubleshooting and operations

- **No connected LAN / ambiguous subnet:** install `iproute2`; specify a connected
  RFC1918 `subnet` and `interface`. NetWatch does not guess across ambiguous LANs.
- **Few or no devices:** passive cache visibility is limited; enable `ping` or
  `nmap`, check firewall policy, or place the host on the target LAN. The scanner
  does not add its own host to the neighbour inventory.
- **Devices appear offline while powered on:** they may be idle, asleep, filtering
  probes, or absent from the cache. Increase timeout or enable active discovery.
- **Missing hostname/vendor:** enrichment is optional and best effort. Install
  local OUI data, enable DNS lookups if appropriate, or assign a friendly name.
- **Permission/program failures:** read monitor logs; install optional tools or
  use passive mode. Failures do not expire inventory state.
- **Another scan owns this database:** use the running monitor's inventory; stop
  it before a manual scan. Do not delete a live process's lock file.
- **Unhealthy:** check monitor logs, permissions, discovery completeness, and scan
  durations. `healthcheck` before any monitor run is intentionally unhealthy.
- **Ping works in a terminal but fails as a service:** re-run `install-service`
  after enabling ping. Restrictive user-unit sandbox settings can block the ping
  binary's existing capability; do not change host firewall or kernel policy.
- **Dashboard unavailable:** check `netwatch-web.service` logs and port 8765.
  Open it on this machine using `127.0.0.1` or `localhost`; LAN IP access is disabled.
- **Tailscale URL unavailable:** confirm the accessing device is connected to the
  permitted tailnet, Serve is activated on the chosen port, and `tailscale_url`
  matches exactly. Configuring the URL alone does not activate Serve.
- **Telegram missing:** check the opt-in setting, private-file ownership/mode, bot
  membership in the target chat, and outbound HTTPS access. Never paste tokens
  into logs or issue reports. Recent alerts show events, not delivery receipts.
- **Secrets file prevents dashboard startup:** authentication fails closed when a
  configured private file is missing or unsafe. Correct its ownership/path/mode;
  do not relax permissions to bypass the check.
- **Backup:** use SQLite's online backup API or `sqlite3 /path/netwatch.db
  '.backup /path/backup.db'`; stop the monitor if copying files directly. Copying
  only the main file while WAL is active can lose recent transactions.

History has no automatic retention policy in v0.1; monitor database growth.
At a 60-second interval, a continuously observed device adds up to 1440 observation
rows per day; scan duration reduces that rate. Device identity is one MAC with one
current IP; multiple addresses
on a MAC are reduced to one per scan. Randomized MACs become separate unknown
devices. Console alerts are best effort after commit and are not replayed after
a crash. MAC spoofing is possible; trust is a labeling feature, not authentication.

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pytest --cov=netwatch
.venv/bin/python -m build
```

Tests use temporary databases and mocked network/process operations. An autouse
fixture blocks subprocess execution and common socket operations unless a test
explicitly installs a mock. Tests cover dashboard pages, API/CSRF/Host protections,
authentication, secret redaction/permissions, mocked Telegram retries, fingerprint
evidence/conflicts, additive database migration, interactive review, alert transitions, service
generation, and monitor recovery as well as discovery and inventory. CI runs lint,
format, tests, package builds, and a
Docker image smoke test with no live discovery. See [CONTRIBUTING.md](../CONTRIBUTING.md).

Licensed under [MIT](../LICENSE).

### Unknown Device Investigation Mode

On an UNKNOWN device's detail page, **Investigate Device** collects a bounded snapshot
of local evidence. It requires dashboard authentication, the existing CSRF session,
and same-origin POST protection. The server resolves the numeric device ID from its
inventory and rejects browser-supplied identity or discovery parameters. KNOWN,
TRUSTED and BLOCKED devices cannot be investigated through this action.

Investigation reads inventory MAC/vendor/interface/timestamps, hostname/vendor/IP
observation history, recent identity/presence events, stored route context, and any
configured unexpired local dnsmasq DHCP lease matching both MAC and IP. Notes remain
in the Identity section rather than being duplicated into investigation storage.
Missing optional sources are reported explicitly. This implementation does not
query Home Assistant, routers, mDNS or SSDP. By default, no network request is sent.
An administrator may explicitly select one bounded reachability check: only after
LOW/INSUFFICIENT passive evidence, for an online UNKNOWN device seen within five
minutes (or the shorter configured offline timeout), with a valid unicast MAC and
a usable IP in the configured RFC1918 LAN. It sends one ICMP echo using an argument
array, with a one-second reply wait and at most a two-second process timeout within
the overall deadline. The configured interface is used when available. It probes
no ports, authenticates to nothing, and never changes device settings. Stale or
invalid records are not probed. Active evidence is marked separately, and
reachability never increases identity confidence. Failures are inconclusive.
The normal monitor continues its existing discovery independently.

Results distinguish observations from suggested categories, identity matches and
missing/conflicting evidence. Vendor alone yields **INSUFFICIENT** confidence. A
reported category name yields **LOW**; repeated consistent names or a matching
local DHCP name can yield **MEDIUM**. Conflicting categories, vendor attribution
changes and malformed/private MAC evidence lower confidence. These self-reported
sources never yield **HIGH** identity confidence; that level is reserved for direct,
independently validated evidence. Possible matches against up to 500 KNOWN/TRUSTED
records use reported hostname similarity or a shared recorded IP; vendor is only
supporting evidence. Suggestions never merge records or transfer trust.

Presence describes counts and recorded transitions. One observation cannot support
behavioral inference; records last seen over seven days ago are marked historical.
Neighbour/cache sightings do not prove continuous uptime or usage periods.

A web-owned additive `investigations` table stores status, investigation time and
bounded JSON results, with at most five conclusions per device and a 60-second
per-device cooldown. It retains schema version 3 compatibility so an already running
monitor does not need restarting. Evidence queries use a five-second deadline and
SQLite cancellation; history display uses at most 500 recent observations, 20 distinct
historical names/IPs, eight vendor attributions and 100 recent events. An interrupted
worker displays Failed after 15 seconds and can be retried after the cooldown.
Persisted JSON is capped at 60,000 characters, with a 65,536-character database guard.
Original observations are preserved when a displayed result is abbreviated.

Investigation changes only its own result table, creates no notification events,
and imports no notifier. Existing notification priorities and Telegram configuration
are unchanged. Suggested identity/name/category never changes trust or inventory.
Confirm identity and explicitly submit the existing manual review form to save a name
or classification. Investigation content is rendered through Jinja HTML escaping.

Regression checks: `python -m pytest --cov=netwatch`, `ruff check .`,
`ruff format --check .`, `node --check netwatch/web/static/app.js`,
`node tests/check_investigation_ui.mjs`, `node tests/mobile_ui.mjs`, and
`node tests/dashboard_polling.mjs`.

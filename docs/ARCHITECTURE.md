# Architecture

The Python package separates network I/O, state, policies, and presentation.

| Component | Responsibility |
| --- | --- |
| `discovery` | Connected-LAN validation, neighbour parsing, bounded optional ping/nmap, local vendor and optional hostname enrichment |
| `database` | SQLite schema/migrations, WAL snapshots, transactions, inventory/history and persistent notification claims |
| `services.inventory` | Atomic scan recording, explicit manual review and event generation |
| `services.monitor` | Non-overlapping scheduled scans, heartbeat, recoverable failure handling and shutdown |
| `services.fingerprints` | Explainable category hints from stored evidence and optional local DHCP leases |
| `services.security_overview` | Actionable evidence/status, bounded history windows and logical map |
| `services.investigation` | Passive-first UNKNOWN review with bounded stored conclusions and optional one-device ICMP check |
| `notifications` | Security policy, cooldown/deduplication, console and bounded asynchronous Telegram transport |
| `web` | Flask templates/JSON APIs, authentication, session/CSRF/Host/origin checks, loopback Waitress server |
| `cli` | Scan, monitor, inventory/review, health, password and user-service commands |

A scan transaction records scan metadata, observations, inventory changes and events.
Notification processing happens after persistence. Provider errors cannot roll back
a completed scan. Notification claims precede delivery; there is no durable retry
queue. Reads do not produce alert events.

A process lock prevents overlapping monitors/scans for one database. WAL lets the
web app read a coherent snapshot while monitoring continues. Foreign keys, bounded
busy waits and additive migrations preserve relationships and history. Failed or
degraded discovery cannot incorrectly mark all missing devices offline.

Device identity is a normalized unicast MAC record, not a proven physical-device
identity. Metadata enrichment never implicitly approves a device. Category and
match suggestions are explainable hints; MAC randomization and spoofing remain
limitations. The logical map shows stored roles/states, not traffic paths.

Investigation persists only its own results, at most five per device, with a
60-second cooldown, a five-second evidence deadline, bounded history queries,
and bounded JSON. It does not mutate trust, names, inventory, or notification
settings. A fresh validated target and explicit request are required for its
optional single-packet reachability check.

The dashboard serves local assets only. It binds `127.0.0.1`; optional Tailscale
Serve terminates private HTTPS. Authenticated writes need signed-session CSRF
and matching validated origin. No endpoint manages systemd, routers or Tailscale.

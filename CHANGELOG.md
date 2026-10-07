# Changelog

## Unreleased

- Publish the existing 0.1.0 source with private runtime state excluded, reproducible
  installation guidance, architecture and backup/restore documentation.
- Add UNKNOWN Device Investigation with authenticated/CSRF-protected requests,
  bounded passive evidence, optional single ICMP reachability, persisted conclusions,
  per-device cooldown and no automatic identity/trust changes.
- Add responsive mobile cards, safe disclosures/relative times, health polling and
  Security Overview/history with explainable status and a logical inventory map.
- Add publication/privacy checks, Git-history secret scanning and JavaScript CI.

- Add explicit TRUSTED/KNOWN/UNKNOWN/BLOCKED review states with an additive
  schema-3 migration, authenticated dashboard filters/forms and CLI state command.
- Restrict Telegram to security alerts, persist event deduplication and a minimum
  one-hour identical-state cooldown, and suppress routine DHCP/liveness messages.
- Detect evidence-backed trusted MAC mismatch candidates without transferring
  trust, dual-signal identity changes and returns after 24 hours absent.

- Opt-in asynchronous Telegram alerts with bounded retry/backoff, secret-file
  permission checks, redacted failures and no monitoring delays.
- Explainable device categories with persistent evidence and additive schema-2
  migration, preserving inventory/observations/events and trust.
- Dashboard search/filter/sort, live summary/last scan, recent real alerts/events,
  new-unknown highlights and local-kernel network overview.
- Optional scrypt password authentication for all dashboard/API views and private
  Tailscale HTTPS authority support; direct LAN/public binding remains disabled.
- Harden existing database/key/auth permissions and symlink handling, external
  cookie finalization, Telegram response cleanup and conflicting DHCP hints.

- Local-only Flask/Waitress dashboard, inventory JSON API, and protected review forms.
- Device details with observations, timeline, previous IPs, names, notes, and trust.
- Interactive CLI review and expanded identity listing without automatic trust.
- Event-driven console alert providers for unknown/new, offline, online, and IP changes.
- User systemd service installer for persistent monitor/dashboard operation.
- Evidence-backed identity enrichment that preserves last-seen and liveness state.
- Preserve packaged ping capabilities in active-ping user services without changing
  host network policy; validate generated systemd working-directory syntax.
- Reject incomplete review forms and untrusted Host headers safely; respect the
  environment configuration path when installing services.
- Fix narrow-screen dashboard overflow with a real-browser geometry regression.

- Handle iproute2 neighbour JSON that omits `dev` after an interface-scoped query.
- Support installed IEEE `oui.txt` vendor data and tab-separated OUI records.

## 0.1.0 — 2026-10-03

- Initial Linux/Python 3.12+ implementation with passive neighbour discovery.
- Connected RFC1918 LAN detection and strict scan boundaries.
- Optional bounded ping/nmap host discovery and offline OUI/hostname enrichment.
- SQLite inventory, immutable observations, scan records, and per-device events.
- Unknown-device alerts, trust management, names/notes, and JSON-capable CLI.
- Resilient continuous monitoring, process locking, shutdown, and healthchecks.
- Non-root Docker image, host-network Compose deployment, and systemd example.
- Mocked-network tests, Ruff lint/format checks, and GitHub Actions CI.

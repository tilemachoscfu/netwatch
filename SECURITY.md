# Security policy

NetWatch is intended for authorized monitoring of directly connected private IPv4
LANs. Keep the dashboard private. It does not provide intrusion prevention,
packet inspection, vulnerability scanning, or real traffic blocking.

## Supported version

The published source identifies itself as 0.1.0. Fixes are maintained on `main`;
there is no long-term support guarantee or independent penetration-test claim.

## Reporting

Use GitHub private vulnerability reporting when enabled on this repository.
Otherwise, open a public issue requesting a private contact channel without
including exploit details, credentials, device inventories, or identifying logs.
Never post tokens, cookies, database files, or private tailnet addresses.

## Security boundaries

- Discovery is restricted to validated, connected RFC1918 IPv4 networks. Active
  methods are opt-in and bounded. No arbitrary commands are accepted by HTTP.
- The dashboard binds to loopback. Host and same-origin checks restrict requests;
  CSRF tokens protect writes. Waitress strips untrusted forwarded headers.
- Password authentication is optional by default. Configure a strong password and
  set `web_auth_required: true` before providing access to other users. Credentials
  use HTTP Basic, so remote access must use HTTPS. All users share one role.
- Tailscale Serve can provide private HTTPS access. NetWatch does not manage ACLs,
  router settings, Serve configuration, or public exposure. Do not use Funnel.
- Secrets, authentication hashes, and session keys require owner-only permissions;
  symlink checks reject unsafe credential/state paths. Keep backups equally private.
- Device Investigation requires configured authentication and CSRF. Its optional
  single ICMP probe does not identify a device or establish that it is safe.
- BLOCKED labels trigger monitoring evidence; they do not enforce network policy.
  Self-reported names and MAC/OUI data can be spoofed.
- Alerts are best effort. A claim can suppress replay after a failed delivery;
  an ambiguous transport retry can duplicate a message. Consult stored history.

## Repository hygiene

Production YAML, databases, WAL/SHM files, credentials, backups, logs, reports,
browser profiles and screenshots must stay outside source control. `.gitignore`
does not clean history. Run Gitleaks on both the working tree and all Git history
before any public push. If a real secret enters history, stop publication and
agree on remediation; a deletion commit is insufficient.

Tests use synthetic fixtures and block real network operations. Publication checks
and CI are useful safeguards, not proof that all security defects are absent.

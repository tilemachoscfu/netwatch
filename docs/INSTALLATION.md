# Installation

Use Linux and Python 3.12+. Install your distribution's `python3-venv` and
`iproute2` packages. Optional ping discovery requires `iputils-ping`; optional
nmap discovery requires `nmap`. No root execution is required by NetWatch.

## Fresh installation

```bash
git clone https://github.com/tilemachoscfu/netwatch.git
cd netwatch
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install .
cp netwatch.example.yaml netwatch.yaml
chmod 600 netwatch.yaml
```

Review your private YAML before scanning. Automatic subnet selection fails closed
when ambiguous; choose the authorized physical LAN subnet/interface explicitly if
necessary. Leave passive neighbour discovery enabled until you understand coverage
and permissions. All RFC1918 examples in tests are synthetic.

```bash
.venv/bin/netwatch --config netwatch.yaml scan
.venv/bin/netwatch --config netwatch.yaml devices
.venv/bin/netwatch --config netwatch.yaml set-password
```

Set `web_auth_required: true` in your private YAML after creating the password.
The username is `netwatch`. Then start monitor and web in separate terminals:

```bash
.venv/bin/netwatch --config netwatch.yaml monitor
.venv/bin/netwatch --config netwatch.yaml web
```

Open `http://127.0.0.1:8765` on the host. Do not proxy Basic authentication over
unencrypted LAN HTTP. A missing required password prevents the web app starting.
Runtime state remains private in the configured database directory.

## User services

For a new installation, the CLI generates user units using the current checkout
and configuration paths:

```bash
.venv/bin/netwatch --config netwatch.yaml install-service
systemctl --user daemon-reload
systemctl --user enable --now netwatch.service netwatch-web.service
systemctl --user status netwatch.service netwatch-web.service
.venv/bin/netwatch --config netwatch.yaml healthcheck
```

Account lingering is an administrator decision if startup without login is needed.
Do not regenerate or restart an existing production installation merely to publish
its source. Keep its checkout and virtual environment in place.

Administrator-managed templates are [netwatch.service](netwatch.service) and
[netwatch-web.service](netwatch-web.service). They assume a dedicated `netwatch`
account, `/opt/netwatch` installation, `/etc/netwatch/netwatch.yaml` config, and
`/var/lib/netwatch` writable state. The environment database override is intentional.
Adapt these paths and discovery permissions before enabling either template.

## Optional integrations

Configure Telegram using an owner-only secrets file or secure service environment;
never store token/chat ID values in YAML or Git. Missing credentials disable
Telegram without stopping monitoring. See [the reference](REFERENCE.md).

For private remote HTTPS, an administrator may configure Tailscale Serve to proxy
loopback port 8765, then set the exact private HTTPS authority in `tailscale_url`.
Restrict tailnet access and enable application authentication. Preserve existing
Serve routes and do not enable Funnel. NetWatch does not perform this setup.

Docker/Compose installation and exact configuration, CLI/API, timeout, discovery,
and alert semantics are documented in [REFERENCE.md](REFERENCE.md).

## Upgrades

Back up SQLite and private credentials first. Validate an isolated candidate
installation and its migration tests, then schedule maintenance if deploying.
Source publication itself requires no deployment or service restart. See
[backup/restore](BACKUP_RESTORE.md) and [the changelog](../CHANGELOG.md).

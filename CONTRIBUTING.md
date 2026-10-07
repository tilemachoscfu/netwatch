# Contributing

Use Linux, Python 3.12+ and Node 22+. Install pinned runtime dependencies first,
then `python -m pip install -e '.[dev]'`. Run the checks listed in the README.
CI installs dependencies, tests Python 3.12/3.13/3.14, enforces at least 96% combined
line/branch coverage, checks Ruff formatting/lint, runs dependency-free JavaScript
behaviour checks, builds packages, scans Git history and validates publication files.

Discovery safety is an invariant. Tests must use synthetic inventory, temporary
SQLite databases and mocked network/process calls. The autouse fixture blocks real
network operations and removes credential environment values. Never discover a CI
runner's LAN or connect tests to an operator's dashboard.

Maintain argument-list subprocess calls with finite timeouts, parameterized SQL,
UTC timestamps, explicit review transitions, and additive schema migrations.
Do not reduce coverage thresholds, remove failing tests, or weaken privacy checks
to make a contribution pass. Document changed public configuration/API behavior.

Optional `browser_layout.mjs` and `investigation_layout.mjs` checks need isolated
Firefox WebDriver BiDi sessions and a synthetic dashboard on loopback port 18765.
They are manual checks, separate from CI; never point them at production inventory.
No browser credentials from a production installation are required by any test.

Before pushing, run Gitleaks against all Git history and the working tree. Review
staged files explicitly. Keep runtime state, real IP/MAC inventories, names,
credentials, screenshots and reports outside Git. A deletion commit does not
sanitize prior commits. Report vulnerabilities as described in SECURITY.md.

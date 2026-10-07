# Security review scope

The publication review checks source and tests, excludes all live operational state,
and verifies Gitleaks, privacy checks, dependency vulnerability scanning, the full
mocked-network test suite, Ruff, JavaScript checks and packaging. Git history must
be scanned independently before visibility changes.

This is a source publication review, not an independent penetration test or
certification. Operational baselines and audit logs remain private. See
[SECURITY.md](../SECURITY.md) for the supported security boundaries and limitations.

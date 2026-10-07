# Backup and restore

Inventory, history, configuration and credentials are private operational data.
Keep backups outside the Git checkout, owner-only, and encrypted when transported.
Never commit SQLite databases, WAL/SHM files, session keys or authentication hashes.

## Consistent live SQLite backup

A normal file copy of a live WAL database is not a consistent backup. Use SQLite's
backup API. The following example reads the source in read-only mode and creates a
new private destination; replace both paths for your installation:

```python
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

source = Path("/var/lib/netwatch/netwatch.db")
backup_dir = Path("/var/backups/netwatch")
backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
os.chmod(backup_dir, 0o700)
stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
destination = backup_dir / f"netwatch-{stamp}.db"
fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
os.close(fd)
with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True) as src:
    src.execute("PRAGMA query_only=ON")
    with sqlite3.connect(destination) as dst:
        src.backup(dst)
        assert dst.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
```

Back up private YAML, the secrets file, `.web-auth` password hash and `.web-key`
session key separately with mode 0600. Do not print their contents. Retain the
matching application version and dependency manifest. A backup of the session
key permits session validation and must be treated as a credential.

## Planned restore

Restore requires a scheduled maintenance window; never replace a live database.
These are operator instructions, not actions performed during source publication.

1. Verify the selected backup with read-only `PRAGMA integrity_check`.
2. Stop both monitor and web services gracefully during authorized maintenance.
3. Preserve the current database, WAL/SHM and private files in a new timestamped
   recovery directory. Do not discard or overwrite existing backups.
4. Restore the consistent database backup with service-account ownership and mode
   0600. Keep old WAL/SHM files with the preserved database; do not reuse them with
   the restored file. Restore appropriate config and private authentication files.
5. Check integrity, version compatibility and permissions before starting services.
6. Start both services, verify monitor health and authenticated dashboard access,
   and review timestamps/inventory counts. Never restore by merging raw SQLite files.

Changing a session key invalidates sessions. Restoring a password hash restores
that password. Coordinate these choices with the operator and keep secrets private.

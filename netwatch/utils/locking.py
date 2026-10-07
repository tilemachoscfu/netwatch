import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def scan_lock(database_path: Path) -> Iterator[None]:
    database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = database_path.with_name(database_path.name + ".lock")
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("Another scan or monitor owns this database") from exc
        yield
    finally:
        os.close(descriptor)

import multiprocessing
from pathlib import Path

import pytest

from netwatch.utils.locking import scan_lock


def _acquire_in_child(database: str, result: object) -> None:
    try:
        with scan_lock(Path(database)):
            result.send("acquired")
    except ValueError:
        result.send("busy")
    finally:
        result.close()


def child_result(database: Path) -> str:
    # Spawn a fresh interpreter so the child cannot inherit the parent's lock FD.
    context = multiprocessing.get_context("spawn")
    receiving, sending = context.Pipe(duplex=False)
    child = context.Process(target=_acquire_in_child, args=(str(database), sending))
    child.start()
    sending.close()
    try:
        assert receiving.poll(10), "Lock acquisition blocked instead of failing promptly"
        result = receiving.recv()
        child.join(10)
        assert child.exitcode == 0
        return result
    finally:
        receiving.close()
        if child.is_alive():
            child.terminate()
        child.join(10)
        child.close()


def test_lock_excludes_another_process_and_releases_after_exit(tmp_path: Path) -> None:
    database = tmp_path / "state" / "inventory.db"
    with scan_lock(database):
        assert child_result(database) == "busy"
    assert child_result(database) == "acquired"
    assert not database.exists()  # Taking a lock must not create a database.
    assert database.with_suffix(".db.lock").stat().st_mode & 0o777 == 0o600


def test_lock_releases_when_protected_work_raises(tmp_path: Path) -> None:
    database = tmp_path / "inventory.db"
    with pytest.raises(RuntimeError, match="synthetic failure"), scan_lock(database):
        raise RuntimeError("synthetic failure")
    assert child_result(database) == "acquired"

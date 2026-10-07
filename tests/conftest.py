import socket
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from netwatch.database.store import Store


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch: pytest.MonkeyPatch) -> None:
    # Never import an operator's real credentials into a test fixture or failure report.
    for key in (
        "NETWATCH_TELEGRAM_BOT_TOKEN",
        "NETWATCH_TELEGRAM_CHAT_ID",
        "NETWATCH_WEB_PASSWORD_HASH",
        "NETWATCH_SECRETS_FILE",
    ):
        monkeypatch.delenv(key, raising=False)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Tests must mock network and subprocess operations")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket.socket, "sendto", forbidden)
    monkeypatch.setattr(socket, "gethostbyaddr", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    with Store(tmp_path / "netwatch.db") as database:
        yield database

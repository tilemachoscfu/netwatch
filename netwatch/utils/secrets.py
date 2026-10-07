"""Read private local credentials without interpolation or diagnostic disclosure."""

import os
import stat
from pathlib import Path

KEYS = {
    "NETWATCH_TELEGRAM_BOT_TOKEN",
    "NETWATCH_TELEGRAM_CHAT_ID",
    "NETWATCH_WEB_PASSWORD_HASH",
}


def private_text(path: Path, *, maximum: int = 16384) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as file:
            info = os.fstat(file.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_size > maximum
            ):
                raise ValueError
            payload = file.read(maximum + 1)
            if len(payload) > maximum:
                raise ValueError
            return payload.decode("utf-8")
    except (OSError, UnicodeError, ValueError):
        raise ValueError("Private file must be owned by this user, mode 0600, and valid") from None


def load_secrets(path: Path | None = None) -> dict[str, str]:
    values: dict[str, str] = {}
    if path is not None:
        for line in private_text(path).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            if not separator or key not in KEYS or key in values or not value.strip():
                raise ValueError("Invalid secrets file; use unique supported KEY=value lines")
            values[key] = value.strip()
    for key in KEYS:
        if key in os.environ:
            values[key] = os.environ[key]
    return values

import hmac
import os
import tempfile
import threading
import time
from pathlib import Path

from flask import Flask, abort, request
from flask.sessions import SecureCookieSessionInterface
from werkzeug.security import check_password_hash, generate_password_hash

from netwatch.utils.config import Config
from netwatch.utils.secrets import load_secrets, private_text


def password_hash(config: Config) -> str | None:
    value = load_secrets(config.secrets_file).get("NETWATCH_WEB_PASSWORD_HASH")
    path = config.database_path.with_suffix(".web-auth")
    if value is None and (path.exists() or path.is_symlink()):
        value = private_text(path).strip()
    if value is not None and not value.startswith(("scrypt:", "pbkdf2:sha256:")):
        raise ValueError("Invalid dashboard password hash")
    if config.web_auth_required and value is None:
        raise ValueError("Dashboard authentication is required; configure a password first")
    return value


def set_password(config: Config, password: str) -> Path:
    if not 12 <= len(password) <= 1024:
        raise ValueError("Choose a dashboard password between 12 and 1024 characters")
    path = config.database_path.with_suffix(".web-auth")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() or path.is_symlink():
        private_text(path)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as file:
        temporary = Path(file.name)
        file.write(generate_password_hash(password))
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


class CookieSecurity(SecureCookieSessionInterface):
    def __init__(self, external_host: str | None) -> None:
        self.external_host = external_host

    def get_cookie_secure(self, app: Flask) -> bool:
        # Cookie finalization also runs for rejected Hosts, before URL routing is
        # available. Comparing the raw authority to our configured authority is
        # safe; request.host would raise SecurityError a second time here.
        authority = request.headers.get("Host", "").lower().removesuffix(":443")
        return request.is_secure or bool(self.external_host and authority == self.external_host)


class PasswordGate:
    def __init__(self, hashed: str | None) -> None:
        self._hash = hashed
        self._failures: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def protect(self) -> None:
        if self._hash is None:
            return
        address = request.remote_addr or "local"
        now = time.monotonic()
        with self._lock:
            start, attempts = self._failures.get(address, (now, 0))
            if now - start > 60:
                start, attempts = now, 0
            if attempts >= 10:
                abort(429, "Too many authentication failures; try again in a minute")
        auth = request.authorization
        if (
            auth is not None
            and auth.type == "basic"
            and hmac.compare_digest((auth.username or "").encode(), b"netwatch")
            and len(auth.password or "") <= 1024
            and check_password_hash(self._hash, auth.password or "")
        ):
            with self._lock:
                self._failures.pop(address, None)
            return
        if auth is not None:
            with self._lock:
                if len(self._failures) >= 128:
                    self._failures.clear()
                self._failures[address] = (start, attempts + 1)
        abort(401, "Dashboard authentication required")

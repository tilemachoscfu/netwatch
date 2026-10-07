import hmac
import os
import secrets
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException, SecurityError

from netwatch.database.store import Store
from netwatch.services.dashboard import DashboardQueries
from netwatch.services.fingerprints import CATEGORIES, FingerprintService
from netwatch.services.inventory import Inventory
from netwatch.services.investigation import InvestigationBusy, InvestigationService
from netwatch.services.security_overview import WINDOWS, SecurityOverview
from netwatch.utils.config import Config
from netwatch.utils.secrets import private_text
from netwatch.web.auth import CookieSecurity, PasswordGate, password_hash


def _secret(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        value = private_text(path)
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("Invalid dashboard session key") from None
        return value
    value = secrets.token_hex(32)
    with os.fdopen(descriptor, "w") as file:
        file.write(value)
    return value


def create_app(config: Config, *, secret_key: str | None = None) -> Flask:
    app = Flask(__name__)
    external = urlsplit(config.tailscale_url) if config.tailscale_url else None
    external_host = external.netloc.lower().removesuffix(":443") if external else None
    hashed = password_hash(config)
    gate = PasswordGate(hashed)
    app.session_interface = CookieSecurity(external_host)
    app.config.update(
        SECRET_KEY=secret_key or _secret(config.database_path.with_suffix(".web-key")),
        MAX_CONTENT_LENGTH=32768,
        MAX_FORM_MEMORY_SIZE=32768,
        MAX_FORM_PARTS=10,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_NAME="netwatch_session",
        TRUSTED_HOSTS=["localhost", "127.0.0.1", *([external.hostname] if external else [])],
    )
    with Store(config.database_path) as store:
        store.initialize_investigations()
        FingerprintService(store, config).refresh(collect_topology=True)

    def database() -> Store:
        if "store" not in g:
            g.store = Store(config.database_path, readonly=request.method in ("GET", "HEAD"))
            if request.method in ("GET", "HEAD"):
                # A WAL read snapshot keeps counters, identities and events consistent
                # if the monitor commits a new device halfway through a request.
                g.store.connection.execute("BEGIN")
        return g.store

    def queries() -> DashboardQueries:
        return DashboardQueries(database(), config)

    @app.teardown_appcontext
    def close_store(_: BaseException | None) -> None:
        if "store" in g:
            g.store.close()

    @app.before_request
    def protect() -> None:
        if (
            external
            and request.host.split(":")[0].lower() == external.hostname
            and (
                request.host.lower().removesuffix(":443") != external_host
                or request.remote_addr != "127.0.0.1"
            )
        ):
            abort(403, "Use the configured private HTTPS endpoint")
        gate.protect()
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("Origin")
            expected_origin = (
                f"https://{external_host}"
                if external and request.host.lower().removesuffix(":443") == external_host
                else request.host_url.rstrip("/")
            )
            if origin and origin != expected_origin:
                abort(403, "Cross-origin updates are forbidden")
            if request.headers.get("Sec-Fetch-Site") == "cross-site":
                abort(403)
            supplied = request.headers.get("X-CSRF-Token", request.form.get("csrf_token", ""))
            expected = session.get("csrf_token", "")
            if not expected or not hmac.compare_digest(expected.encode(), supplied.encode()):
                abort(403, "Reload the page before updating a device")

    @app.context_processor
    def csrf_context() -> dict[str, str]:
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return {"csrf_token": session["csrf_token"]}

    @app.after_request
    def headers(response: Response) -> Response:
        response.headers.update(
            {
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                # no-referrer makes ordinary form POSTs send Origin: null,
                # which the strict origin check correctly rejects. Preserve
                # same-origin form provenance without sending external referrers.
                "Referrer-Policy": "same-origin",
                "Cache-Control": "no-store",
            }
        )
        if response.status_code == 401:
            response.headers["WWW-Authenticate"] = 'Basic realm="NetWatch", charset="UTF-8"'
        if response.status_code == 429:
            response.headers["Retry-After"] = "60"
        return response

    @app.errorhandler(HTTPException)
    def http_error(error: HTTPException) -> tuple[Response | str, int]:
        code = error.code or 500
        if isinstance(error, SecurityError):
            # Host rejection occurs before Flask can create a URL adapter. Do not
            # render a template that calls url_for in this invalid request context.
            return jsonify(error="Untrusted Host header"), 400
        if request.path.startswith("/api/"):
            return jsonify(error=error.description), code
        return render_template("error.html", code=code, message=error.description), code

    @app.errorhandler(sqlite3.Error)
    def database_error(error: sqlite3.Error) -> tuple[Response | str, int]:
        app.logger.error("Dashboard database unavailable: %s", type(error).__name__)
        if request.path.startswith("/api/"):
            return jsonify(error="Inventory temporarily unavailable"), 503
        return render_template(
            "error.html", code=503, message="Inventory temporarily unavailable"
        ), 503

    def detail(device_id: int) -> dict[str, Any]:
        try:
            return queries().detail(device_id, limit(), security_options()[0])
        except ValueError:
            abort(404, "Device not found")

    def limit() -> int:
        try:
            value = int(request.args.get("limit", "100"))
        except ValueError:
            abort(400, "Invalid history limit")
        if not 1 <= value <= 500:
            abort(400, "History limit must be between 1 and 500")
        return value

    @app.get("/")
    @app.get("/security")
    @app.get("/devices")
    @app.get("/unknown")
    def devices_page() -> str:
        unknown = request.path == "/unknown"
        filters, devices = filtered_devices(unknown)
        show_security = request.path in ("/", "/security")
        window, include_offline = security_options()
        return render_template(
            "devices.html",
            devices=devices,
            summary=queries().summary(),
            unknown=unknown,
            title="Unknown devices" if unknown else "Devices",
            filters=filters,
            categories=CATEGORIES,
            security=SecurityOverview(database(), config).overview(
                window, include_offline=include_offline
            )
            if show_security
            else None,
        )

    def security_options() -> tuple[str, bool]:
        window = request.args.get("window", "24h")
        offline = request.args.get("show_offline", "false")
        if window not in WINDOWS or offline not in ("true", "false"):
            abort(400, "Use window=24h|7d|30d and show_offline=true|false")
        return window, offline == "true"

    def filtered_devices(unknown: bool = False) -> tuple[dict[str, str], list[dict[str, Any]]]:
        filters = {
            key: request.args.get(key, default)
            for key, default in (
                ("q", ""),
                ("status", "all"),
                ("trust", "unknown" if unknown else "all"),
                ("category", "all"),
                ("sort", "id"),
                ("order", "asc"),
            )
        }
        if unknown:
            filters["trust"] = "unknown"
        try:
            return filters, queries().devices(
                query=filters["q"], **{key: value for key, value in filters.items() if key != "q"}
            )
        except ValueError as error:
            abort(400, str(error))

    @app.get("/events")
    def events_page() -> str:
        return render_template(
            "events.html", events=database().events(limit=limit()), title="Events"
        )

    @app.get("/device/<int:device_id>")
    def device_page(device_id: int) -> str:
        return render_template("device.html", **detail(device_id), title=f"Device {device_id}")

    @app.get("/api/csrf")
    def csrf_api() -> Response:
        return jsonify(csrf_context())

    @app.get("/api/summary")
    def summary_api() -> Response:
        return jsonify(queries().summary())

    @app.get("/api/security")
    def security_api() -> Response:
        window, include_offline = security_options()
        return jsonify(
            SecurityOverview(database(), config).overview(window, include_offline=include_offline)
        )

    @app.get("/api/devices")
    def devices_api() -> Response:
        unknown = request.args.get("unknown", "false")
        if unknown not in ("true", "false"):
            abort(400, "unknown must be true or false")
        return jsonify(devices=filtered_devices(unknown == "true")[1])

    @app.get("/api/events")
    def events_api() -> Response:
        return jsonify(events=[asdict(event) for event in database().events(limit=limit())])

    @app.get("/api/device/<int:device_id>")
    def device_api(device_id: int) -> Response:
        return jsonify(detail(device_id))

    def investigate(device_id: int) -> dict[str, Any]:
        # The existing Basic authentication gate authenticates each request;
        # the session supplies CSRF. Require authentication even in optional-auth setups.
        if hashed is None:
            abort(401, "Configure dashboard authentication before investigating devices")
        try:
            device = database().device(str(device_id))
        except ValueError:
            abort(404, "Device not found")
        if device.trust_state != "UNKNOWN":
            abort(409, "Only UNKNOWN devices can be investigated")
        active = False
        if request.is_json:
            values = request.get_json()
            if (
                not isinstance(values, dict)
                or set(values) - {"active"}
                or type(values.get("active", False)) is not bool
            ):
                abort(400, "Investigation accepts no device metadata or discovery parameters")
            active = values.get("active", False)
        else:
            if (
                set(request.form) - {"csrf_token", "active"}
                or request.data
                or request.form.getlist("active") not in ([], ["on"])
            ):
                abort(400, "Investigation accepts only CSRF and the optional reachability choice")
            active = request.form.get("active") == "on"
        try:
            return InvestigationService(database(), config).run(device.id, active=active)
        except InvestigationBusy as error:
            abort(429, str(error))
        except ValueError as error:
            abort(409, str(error))

    @app.post("/api/device/<int:device_id>/investigate")
    def investigate_api(device_id: int) -> tuple[Response, int]:
        run = investigate(device_id)
        return jsonify(investigation=run), 200 if run["status"] == "Complete" else 503

    @app.post("/device/<int:device_id>/investigate")
    def investigate_page(device_id: int) -> Response:
        run = investigate(device_id)
        flash(
            "Investigation complete. Review the evidence before making any changes."
            if run["status"] == "Complete"
            else "Investigation failed. Retry later."
        )
        return redirect(
            url_for("device_page", device_id=device_id, _anchor="investigation"), code=303
        )

    def update(device_id: int, values: Any) -> None:
        detail(device_id)
        if (
            not isinstance(values, dict)
            or not values
            or set(values) - {"name", "notes", "trusted", "trust_state"}
        ):
            abort(400, "Only name, notes, trusted, and trust_state may be updated")
        if "name" in values and values["name"] is not None and not isinstance(values["name"], str):
            abort(400, "name must be a string or null")
        if "notes" in values and not isinstance(values["notes"], str):
            abort(400, "notes must be a string")
        if "trusted" in values and type(values["trusted"]) is not bool:
            abort(400, "trusted must be true or false")
        if "trust_state" in values and values["trust_state"] not in (
            "TRUSTED",
            "KNOWN",
            "UNKNOWN",
            "BLOCKED",
        ):
            abort(400, "Invalid trust state")
        try:
            Inventory(database(), config.offline_timeout).edit(
                str(device_id),
                name=values.get("name") or None,
                set_name="name" in values,
                notes=values.get("notes"),
                trusted=values.get("trusted"),
                trust_state=values.get("trust_state"),
            )
            FingerprintService(database(), config).refresh()
        except ValueError as exc:
            abort(400, str(exc))

    @app.patch("/api/device/<int:device_id>")
    def update_api(device_id: int) -> Response:
        update(device_id, request.get_json())
        return jsonify(detail(device_id))

    @app.post("/device/<int:device_id>")
    def update_page(device_id: int) -> Response:
        allowed = {"csrf_token", "name", "notes", "trust"}
        if (
            set(request.form) - allowed
            or not {"name", "notes", "trust"}.issubset(request.form)
            or request.form.get("trust") not in ("unknown", "trusted", "known", "blocked")
        ):
            abort(400, "Invalid device form")
        update(
            device_id,
            {
                "name": request.form.get("name", ""),
                "notes": request.form.get("notes", ""),
                "trust_state": request.form["trust"].upper(),
            },
        )
        flash("Device updated. The change is recorded in its timeline.")
        return redirect(url_for("device_page", device_id=device_id), code=303)

    @app.get("/healthz")
    def health_api() -> tuple[Response, int]:
        # Dashboard liveness and monitor readiness are intentionally separate.
        summary = queries().summary()
        return jsonify(dashboard="healthy", monitor_healthy=summary["monitor_healthy"]), 200

    return app

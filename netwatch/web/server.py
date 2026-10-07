import logging
import signal

from waitress import create_server

from netwatch.utils.config import Config
from netwatch.web.app import create_app

logger = logging.getLogger(__name__)


def run_dashboard(config: Config, port: int = 8765) -> None:
    server = create_server(
        create_app(config),
        host="127.0.0.1",
        port=port,
        threads=4,
        connection_limit=32,
        channel_timeout=30,
        max_request_body_size=32768,
        max_request_header_size=16384,
        expose_tracebacks=False,
        # Serve preserves Host. Resolve the HTTPS origin only from the exact
        # configured authority and loopback peer; never from forwarded headers.
        trusted_proxy=None,
        clear_untrusted_proxy_headers=True,
    )

    def stop(*_: object) -> None:
        raise KeyboardInterrupt

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    logger.info("Dashboard listening at http://127.0.0.1:%d", port)
    try:
        server.run()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        server.task_dispatcher.shutdown(timeout=5)
        for sig, handler in previous.items():
            signal.signal(sig, handler)

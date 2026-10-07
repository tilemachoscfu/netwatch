import subprocess
from collections.abc import Sequence


class DiscoveryError(RuntimeError):
    """An unavailable or failed local discovery mechanism."""


def run_command(arguments: Sequence[str], timeout: float = 10) -> str:
    try:
        result = subprocess.run(
            list(arguments),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except FileNotFoundError as exc:
        raise DiscoveryError(f"Required program unavailable: {arguments[0]}") from exc
    except PermissionError as exc:
        raise DiscoveryError(f"Permission denied running {arguments[0]}") from exc
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise DiscoveryError(f"{arguments[0]} failed or timed out") from exc
    if result.returncode != 0:
        # Tool output may contain sensitive/local information; log only a concise status.
        raise DiscoveryError(f"{arguments[0]} exited with status {result.returncode}")
    return result.stdout

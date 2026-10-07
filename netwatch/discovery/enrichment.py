import logging
from pathlib import Path

from netwatch.utils.process import DiscoveryError, run_command

logger = logging.getLogger(__name__)


class VendorLookup:
    """Offline OUI lookup using nmap or IEEE oui.txt data; never fetches the internet."""

    def __init__(self, path: Path | None = None) -> None:
        self.vendors: dict[str, str] = {}
        if path is None:
            path = Path("/usr/share/nmap/nmap-mac-prefixes")
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                columns = line.split(maxsplit=1)
                if len(columns) != 2:
                    continue
                prefix, vendor = columns
                # IEEE's compact OUI line includes this marker before the vendor.
                vendor = vendor.removeprefix("(base 16)").strip()
                if (
                    len(prefix) == 6
                    and all(c in "0123456789abcdefABCDEF" for c in prefix)
                    and vendor.strip()
                ):
                    self.vendors[prefix.lower()] = vendor.strip()
        except (OSError, UnicodeError):
            logger.debug("Local vendor data unavailable")

    def lookup(self, mac: str) -> str | None:
        # Locally administered/randomized MACs do not identify a manufacturer reliably.
        if int(mac[:2], 16) & 2:
            return None
        return self.vendors.get(mac.replace(":", "")[:6])


def resolve_hostname(ip: str) -> str | None:
    try:
        payload = run_command(["getent", "hosts", ip], timeout=2)
        for line in payload.splitlines():
            columns = line.split()
            if len(columns) >= 2 and columns[0] == ip:
                return columns[1][:253]
    except DiscoveryError:
        logger.debug("Hostname lookup unavailable for %s", ip)
    return None

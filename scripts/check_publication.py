"""Validate publishable paths, privacy boundaries and local Markdown links."""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    result = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
    paths = [Path(name) for name in result.stdout.decode().split("\0") if name]
    errors = []
    forbidden_parts = {"data", "backups", "reports", "logs", "sessions", "dist", ".venv"}
    forbidden_suffixes = {
        ".db",
        ".sqlite",
        ".sqlite3",
        ".secrets",
        ".web-key",
        ".web-auth",
        ".log",
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".har",
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
    }
    for path in paths:
        if (
            forbidden_parts.intersection(path.parts)
            or path.suffix in forbidden_suffixes
            or path.name in {"netwatch.yaml", ".env", ".coverage", "coverage.json"}
            or path.name.endswith(("-wal", "-shm"))
        ):
            errors.append(f"Forbidden publication path: {path}")
        raw = (ROOT / path).read_bytes()
        if b"\0" in raw:
            errors.append(f"Unexpected binary file: {path}")
            continue
        text = raw.decode("utf-8")
        if re.search(r"/home/[a-zA-Z0-9_.-]+/", text):
            errors.append(f"Personal filesystem path: {path}")
        if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", text):
            errors.append(f"Private key material: {path}")
        for authority in re.findall(r"[a-zA-Z0-9.-]+\.ts\.net", text):
            if authority not in {
                "your-machine.your-tailnet.ts.net",
                "fixture-node.fixture-tailnet.ts.net",
            }:
                errors.append(f"Non-synthetic tailnet authority: {path}")
        if path.suffix == ".md":
            for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
                if target.startswith(("https://", "http://", "#", "mailto:")):
                    continue
                target = target.split("#", 1)[0]
                if target and not (ROOT / path.parent / target).exists():
                    errors.append(f"Broken documentation link: {path}")
    for error in errors:
        print(error)
    print(f"Publication validation: {len(paths)} files, {len(errors)} errors")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())

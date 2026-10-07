import os
from pathlib import Path

from netwatch.utils.config import load_config

UNIT = """[Unit]
Description=NetWatch {description}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={working_directory}
ExecStart={executable} --config {config} {command}
Environment=PYTHONUNBUFFERED=1
Restart=on-failure
RestartSec=10
TimeoutStopSec=120
KillSignal=SIGTERM
KillMode=control-group
{sandbox}
UMask=0077
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
"""


def _quoted(path: Path) -> str:
    value = str(path.absolute())
    if "\n" in value or "\r" in value:
        raise ValueError("Service paths must not contain newlines")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def install_user_units(
    project_root: Path, config_path: Path, *, unit_dir: Path | None = None
) -> tuple[Path, Path]:
    executable = project_root / ".venv/bin/netwatch"
    if not executable.is_file() or not config_path.is_file():
        raise ValueError("User services require the project's .venv and an existing config")
    if unit_dir is None:
        unit_dir = (
            Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "systemd/user"
        )
    unit_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    active_ping = "ping" in load_config(config_path).discovery_methods
    paths = []
    for name, description, command in (
        ("netwatch.service", "private LAN monitor", "monitor"),
        ("netwatch-web.service", "local dashboard", "web --port 8765"),
    ):
        path = unit_dir / name
        # User-manager seccomp filtering implies NoNewPrivileges. Preserve the
        # system ping binary's existing file capability when raw ICMP is needed;
        # do not change global ping_group_range, capabilities, or networking.
        sandbox = (
            "NoNewPrivileges=false"
            if command == "monitor" and active_ping
            else (
                "NoNewPrivileges=true\n"
                "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET"
            )
        )
        path.write_text(
            UNIT.format(
                working_directory=_quoted(project_root)[1:-1],
                executable=_quoted(executable),
                config=_quoted(config_path),
                description=description,
                command=command,
                sandbox=sandbox,
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        paths.append(path)
    return paths[0], paths[1]

# Dependencies and licensing

The project already carries an MIT license; publication retains that license.
No third-party implementation was copied into application source during publication.
The runtime dependency manifest pins installation versions; `pyproject.toml`
declares compatibility ranges. Developer tools are installed separately.

Runtime distributions and their license metadata were inspected locally. PyYAML
uses MIT; Flask and its Pallets dependencies use BSD licenses; Blinker uses MIT; Waitress uses ZPL
2.1. These dependencies are installed separately and retain their own notices.
Linux tools (`iproute2`, ping, nmap), Python, Docker and Tailscale are external
software with their own licenses. A locally supplied OUI dataset is not bundled.
This repository does not relicense them or distribute production vendor datasets.

Use `python -m pip_audit -r requirements.txt` for current advisory checks. A passing
scan means no known advisory was returned at that time; it is not a guarantee
against undisclosed flaws. Pin updates should be reviewed and tested before deployment.

# Gilgamesh

**Home-network intrusion detection for a Raspberry Pi 4.**

Gilgamesh is a network intrusion detection system (NIDS) that a non-expert plugs into
their home network like a router. It watches traffic, detects common home-network
attacks, and alerts the owner through **Discord, Telegram, or email**.

> **Detect-and-alert only.** Gilgamesh never blocks traffic and never degrades the
> internet connection. It is not a firewall and not a router.

Everything is configured from a **web UI** — there is no CLI, TUI, or mobile app.

---

## Status

Under active development (college project). Milestones, proof of work, and known gaps
are tracked in [`docs/PROGRESS.md`](docs/PROGRESS.md) and [`docs/PLAN.md`](docs/PLAN.md).

## What it detects (MVP)

| # | Attack | Engine |
|---|---|---|
| 1 | ARP spoofing / poisoning | custom detector |
| 2 | DNS spoofing | custom detector |
| 3 | Rogue DHCP server, DHCP starvation | custom detector |
| 4 | Port scans (horizontal/vertical), SYN floods | custom detector + Suricata thresholds |
| 5 | New / unknown device on the network | custom detector |
| 6 | Emerging Threats Open signature alerts | Suricata |

## How it is built

* **Hardware:** Raspberry Pi 4 Model B (4 GB), onboard Ethernet + USB 3 Gigabit adapter.
* **Placement:** inline transparent bridge (`br0`) between the modem/router and the LAN.
* **Sensors:** Suricata 8 (signature engine, separate process) and custom Python/Scapy
  detectors for L2–L3 attacks a signature engine handles poorly.
* **Web app:** FastAPI + Jinja2 + htmx + Alpine.js + Tailwind CSS v4.
* **Storage:** SQLite in WAL mode, with retention tuned for SD-card wear.
* **Runs natively under systemd** on Raspberry Pi OS Lite 64-bit (Debian 13 `trixie`).

See [`docs/PLAN.md`](docs/PLAN.md) for the architecture diagram and full design.

## Install (Raspberry Pi)

Target: Raspberry Pi 4 Model B (4 GB), Raspberry Pi OS Lite 64-bit (Debian 13 `trixie`),
with two network interfaces — the onboard Ethernet and a USB 3 Gigabit adapter.

```sh
git clone <this-repo> gilgamesh && cd gilgamesh
sudo ./install.sh
```

`install.sh` is idempotent — re-running it is the upgrade path. It creates the two
service accounts, copies the application to `/opt/gilgamesh`, builds the virtualenv with
`uv sync --frozen --no-dev` (Python is managed by `uv` only), writes
`/etc/gilgamesh/gilgamesh.env` **on first run only** (later edits survive upgrades),
installs the systemd units, the timer and the journald log caps, then starts the web UI
and the sensor. Options: `--offline`, `--no-start`, `--prefix DIR`, `--help`.

Then, from a browser on the same network:

1. open `http://<pi-address>:8080` — the first visit shows the **setup wizard**;
2. the one-time setup token is printed in the journal:
   `journalctl -u gilgamesh-web | grep 'setup token'`;
3. create the admin account, pick the capture interface, and add alert channels.

Editing `/etc/gilgamesh/gilgamesh.env` is how the deployment is configured: at minimum set
`GILGAMESH_INTERFACE` to the interface Gilgamesh should capture from, and once you know the
Pi's management address set `GILGAMESH_ALLOWED_HOSTS` to it (the default `*` answers to any
`Host:` header, which is what makes the first visit work but is looser than necessary).
Every key is documented in `deploy/gilgamesh.env.example`.

**The installer does not create the bridge.** Bridging is host network configuration and
Gilgamesh stays out of it; `docs/research/07-deployment.md` has the step-by-step for the
Pi. It only ever configures the Pi, never the machine you develop on.

## Development (no Pi, no hardware)

The detectors run on synthetic packets and recorded captures, so the whole test suite runs
on a normal Linux machine:

```sh
uv sync                                                  # create the venv (uv only)
uv run pytest                                            # hermetic: no network, no e2e
uv run pytest tests/e2e -m e2e --browser-channel chrome   # real server + real browser
uv run ruff check . && uv run ruff format --check . && uv run pyright
GILGAMESH_DATA_DIR=/tmp/gg-dev uv run gilgamesh-web       # http://127.0.0.1:8080
```

To exercise the sensor without any hardware, replay a capture instead of capturing:
`GILGAMESH_PCAP=/path/to/capture.pcap GILGAMESH_DATA_DIR=/tmp/gg-dev uv run gilgamesh-sensor`.

## Uninstall

```sh
sudo systemctl disable --now gilgamesh-web gilgamesh-sensor gilgamesh-rules-update.timer
sudo rm -f /etc/systemd/system/gilgamesh-*.service /etc/systemd/system/gilgamesh-rules-update.timer
sudo rm -rf /etc/gilgamesh /opt/gilgamesh
sudo rm -f /etc/sysusers.d/gilgamesh.conf
sudo userdel gilgamesh && sudo userdel gilgamesh-sensor     # optional
sudo rm -rf /var/lib/gilgamesh                              # deletes the alert history and config
sudo systemctl daemon-reload
```

## Licence

GPL-2.0-or-later — see [`LICENSE`](LICENSE). Every dependency is open source; the full
SPDX table is in [`docs/research/12-licenses.md`](docs/research/12-licenses.md).

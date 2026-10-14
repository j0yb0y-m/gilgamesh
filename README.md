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

## Licence

GPL-2.0-or-later — see [`LICENSE`](LICENSE). Every dependency is open source; the full
SPDX table is in [`docs/research/12-licenses.md`](docs/research/12-licenses.md).

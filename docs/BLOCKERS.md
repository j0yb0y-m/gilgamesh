# Gilgamesh — Blockers & Open Items

**Rule:** after 3 failed attempts at the same step, write it here and ask the user.
Also list anything that needs the real Pi, a real network, or a user decision.

**Last updated:** 2026-10-18 (audit pass; the deployment artifacts were rewritten)

---

## Found by the 2026-10-18 audit — needs the Pi to confirm

| # | Item | Why it cannot be checked here |
|---|------|-------------------------------|
| C1 | `install.sh` end to end on a fresh Pi (users, venv build, unit enable, journald caps) | it installs a service; the dev machine is not the target |
| C2 | `systemd-sysusers` `u!` (fully locked account) needs systemd ≥ 257 | trixie ships 257, but confirm on the installed image |
| C3 | The systemd hardening set (`ProtectSystem=strict`, `StateDirectoryMode`, capabilities) actually permitting the sensor to capture | requires CAP_NET_RAW on the target's kernel/AppArmor profile |
| C4 | `GILGAMESH_INTERFACE=br0` naming a bridge that exists *before* first start | the install script warns and tells the owner what to run |

---

## Waiting on the user (Phase 2 clarification batch)

The batch was sent once after Phase 1. Answers are recorded in `docs/DECISIONS.md`.

| # | Item | Blocks |
|---|------|--------|
| Q | Licence choice (was A1): GPL-2.0-or-later + keep Scapy, vs permissive + `AF_PACKET` | public repo + sensor code |
| Q | Alert channels to build (Discord / Telegram / email) | Phase 6 |
| Q | UI language (English, or English + Arabic RTL) | all templates |
| Q | GitHub repo visibility (private vs public) | publishing |
| Q | Deadline / college deliverables | priority of Later items |

## Needs the real Pi / target hardware (cannot be done on the dev machine)

| # | Item | Where it is tracked |
|---|------|---------------------|
| A2 | ET Open ↔ Suricata 8 rule-format compatibility (`suricata-update` source for 8.x) | 09 §A2 |
| A4 | Measured Scapy / `AF_PACKET` packets-per-second ceiling on a Pi 4 | 09 §A4 |
| A5 | Suricata 8 RSS on 4 GB with the chosen rule subset | 09 §A5 |
| B1 | `br0` vs member-port frame duplication for `AF_PACKET` | 09 §B1 |
| B2 | USB3 NIC `gro`/`lro`/`tso` settability (`ethtool -k`) | 09 §B2 |
| B3 | Sustained bidirectional bridge throughput | 09 §B3 |
| B4 | Boot-time coverage gap | 09 §B4 |
| B5 | `trixie-backports` apt access for Suricata 8.0.7 | 09 §B5 |
| B6 | Exact systemd hardening directive values on target | 09 §B6 |
| B7 | `uv sync --frozen --offline` on aarch64 | 09 §B7 |
| B8 | `suricata-update` offline mode + atomic output swap | 09 §B8 |

> The dev machine is **x86_64 Fedora 44 (Python 3.14.8)**; the target is
> **aarch64 Raspberry Pi OS Lite 64-bit (Debian 13 trixie, Python 3.13.5)**.
> The project pins **Python 3.13** so the two match.

## Resolved

_(none yet — Phase 1 was research only)_

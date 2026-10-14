# Gilgamesh — Progress

**Rule:** read this file FIRST at the start of every turn. Tick a milestone only after its
acceptance command actually ran and passed; paste the command + key output lines here.
**Target:** Raspberry Pi 4 (4 GB), Raspberry Pi OS Lite 64-bit (Debian 13 trixie, Py 3.13).
**Dev machine:** x86_64 Fedora 44 (Py 3.14.8). Project pinned to **Python 3.13**.
**Last updated:** 2026-10-14

Legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked/needs decision

---

## Phase 0 — Bootstrap (`[x]`)

- [x] `docs/PROGRESS.md`, `docs/DECISIONS.md`, `docs/BLOCKERS.md`, `docs/PLAN.md`
- [x] `AGENTS.md` (hard constraints, safety rules, layout, commands)
- [x] `.gitignore` (DB/config/certs/keys/venv excluded)
- [x] `LICENSE` = GPL-2.0 text (project = GPL-2.0-or-later)
- [x] `git init` + first commit (`31415d0`)
- [x] Environment noted: `uname -m` = x86_64 · `python3 --version` = 3.14.8 (dev)

## Phase 1 — Research (`[x]`) — complete 2026-10-14

| File | Status |
|---|---|
| `research/01-network-placement.md` | [x] |
| `research/02-detection-catalogue.md` | [x] |
| `research/03-tooling-and-versions.md` | [x] |
| `research/04-architecture.md` | [x] |
| `research/05-web-and-stack.md` | [x] |
| `research/06-security-hardening.md` | [x] |
| `research/07-deployment.md` | [x] |
| `research/08-detection-matrix.md` | [x] |
| `research/09-open-questions.md` | [x] |
| `research/12-licenses.md` | [x] (canonical licence table, C1) |

## Phase 2 — Clarification batch (`[x]`) — answered 2026-10-14

Recorded as **D-020…D-027** in `docs/DECISIONS.md`:

- [x] Licence → **GPL-2.0-or-later**, keep Scapy, avoid `python-multipart` (D-020)
- [x] Channels → **Discord + Telegram + email** (D-021)
- [x] Language → **English only, translation-ready** (D-022)
- [x] Target OS → **Raspberry Pi OS Lite 64-bit** (D-023)
- [x] Placement → **inline bridge default**, no SPAN here (D-024)
- [x] GitHub → **private repo now** (D-025)
- [x] Scope → **MVP only** (D-026)
- [x] Suricata → **keep 8 + ET Open**, trim subset if needed (D-027)

## Phase 3 — Plan (`[x]`)

- [x] `docs/PLAN.md` rewritten to the required 13 sections + **14 milestones**, each with an
      exact acceptance test.

## Phase 4 — Build loop (milestones)

| M | Goal | Status | Proof |
|---|---|---|---|
| M1 | Walking skeleton (uv, FastAPI, SQLite, fake detector, dashboard) | [ ] | |
| M2 | Event pipeline (dedup/cooldown/rate-limit/aggregate/global cap) | [ ] | |
| M3 | ARP spoofing detector (#1) | [ ] | |
| M4 | DNS spoofing detector (#2) | [ ] | |
| M5 | DHCP detector (#3) | [ ] | |
| M6 | Scan + SYN-flood detector (#4) | [ ] | |
| M7 | Device inventory (#5) | [ ] | |
| M8 | Capture abstraction + sensor runner + PCAP replay | [ ] | |
| M9 | Suricata integration (#6) | [ ] | |
| M10 | Notifiers (Discord/Telegram/email) | [ ] | |
| M11 | Rules & allowlist UI | [ ] | |
| M12 | Auth + first-run wizard | [ ] | |
| M13 | UI completion (dashboard SSE, alerts, devices, health, settings) | [ ] | |
| M14 | Hardening + install.sh + systemd + docs | [ ] | |

## Phase 5 — Finish

- [ ] `README.md`, `docs/DEMO.md`
- [ ] Clean-room check: `uv sync --frozen` + `uv run pytest` + `uv run ruff check` green
- [ ] Final report

---

## Notes

- Web access confirmed 2026-10-14. Suricata **8.0.7** current stable (2026-09-15); 7.x EOL.
- Every technical claim is backed by a source URL + version in `docs/research/*`, or tagged `UNVERIFIED`.
- All UNVERIFIED/open items live in `docs/research/09-open-questions.md`; hardware-only items in `docs/BLOCKERS.md`.

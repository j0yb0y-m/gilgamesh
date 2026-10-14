# Gilgamesh — Implementation Plan (Phase 2 onward)

**Status:** Phase 1 (research & plan) complete. This document plans the build. **No application code exists yet.**
**Date:** 2026-10-14 · **Author:** lead (synthesised from `docs/research/01`–`09`).
**Product:** a home-network NIDS for a Raspberry Pi 4 (4 GB) that sits inline, detects common home-network attacks, and alerts via Discord/Telegram/email through a **web-only** UI. **Detect-and-alert only — it never blocks or degrades traffic.**

---

## 1. Goal, non-goals, and definition of MVP

### 1.1 Goal
A non-expert owner plugs the Pi inline (or into a mirror port), completes a browser wizard, and thereafter receives clear alerts when Gilgamesh sees a home-network attack.

### 1.2 Non-goals for v1 (explicit)
- **No blocking / no IPS / no response actions.** Detection + alert only.
- **No router role** (no NAT, no DHCP server, no DNS server).
- **No CLI/TUI/desktop/mobile app for the user.** systemd units and the install script are infrastructure, not user interfaces (C2).
- **No cloud service.** Everything runs on the box.
- No ML/heuristic "advanced" detectors (DNS tunnelling, beaconing) — deferred to v1.1.

### 1.3 MVP acceptance criteria (v1 is "done" when all are true)
1. Detects **ARP poisoning** (gateway-MAC change, IP↔MAC conflict, gARP flood, unsolicited replies) and raises a **high**-severity alert.
2. Detects **DNS spoofing** (response with no matching query; answers from a non-allowlisted resolver; conflicting answers).
3. Detects **rogue DHCP server** and **DHCP starvation**.
4. Detects **port scans (vertical/horizontal)** and **SYN floods**.
5. Maintains a **device inventory** and alerts on new/unknown devices (with a "likely randomised MAC" label).
6. Surfaces **Suricata/ET Open signature alerts** with sane severity.
7. Alerts reach at least one of Discord/Telegram/email, with per-channel minimum severity and a working **"Send test"** button.
8. The dashboard updates **live** (SSE) and a non-expert can complete setup **entirely in the browser**.
9. Runs stably within the **4 GB** budget for a 7-day soak with normal home traffic and **zero unhandled exceptions**.
10. Every dependency is **open source** with a recorded SPDX id + source URL (C1); `uv` is the only Python tool (C4); no Node.js on the device (C5); native systemd, no Docker (C6).

---

## 2. Locked technology choices (from Phase 1)

| Area | Choice | Version | Licence | Ref |
|---|---|---|---|---|
| OS | Raspberry Pi OS Lite 64-bit (Debian 13 `trixie`) | image 2026-10-06 | platform (proprietary firmware blobs noted) | 03 §1 |
| Signature IDS | **Suricata** (arm64 `.deb` from `trixie-backports`) | **8.0.7** | GPL-2.0 (separate process → no linkage) | 03 §2.4, D-002 |
| Rules | Emerging Threats **Open** | `suricata-7.0.3` build dir (compat TBC) | ambiguous MIT/BSD-3-Clause-style (both permissive) | 03, A2 |
| Custom capture | **Scapy** (with a raw `AF_PACKET` fast path where needed) | 2.8.0 | **GPL-2.0-only** → see blocker A1 | 03 §5 |
| Web | FastAPI + Starlette + Uvicorn | 0.143.0 / 1.8.0 / 0.54.0 | MIT / BSD-3 / BSD-3 | 05 |
| Validation | Pydantic v2 | 2.14.1 | MIT | 05 §2 |
| Templates | Jinja2 | 3.1.6 | BSD-3-Clause | 05 §3 |
| UI | **htmx** | **2.0.11** (4.0.0 exists; not adopted) | 0BSD | D-009 |
| UI state | Alpine.js **CSP build** | 3.17.4 | MIT | 05 §5 |
| CSS | **Tailwind v4** via arm64 standalone CLI, output committed | 4.3.3 | MIT | D-010 |
| Live updates | **FastAPI native SSE** (`fastapi.sse`) | — | MIT | D-011 |
| Storage | SQLite (WAL) | OS sqlite3 | Public domain | 04 §4 |
| Hashing | argon2-cffi (Argon2id) | 25.1.0 | MIT | D-013 |
| Rate limiting | `limits` (not `slowapi`) | 5.8.0 | MIT | D-016 |
| Secrets/session | `itsdangerous` (explicit) | — | BSD-3-Clause | D-014 |
| HTTP client | httpx (Discord/Telegram) | — | BSD-3-Clause | 04 §6 |
| Email | `aiosmtplib` | — | MIT | 04 §6 |
| Package mgr | **uv** only | 0.13.0 | MIT/Apache-2.0 | 03 §2.5 |
| Process mgr | systemd (native) | OS | LGPL-2.1+ | 07 §3 |

**C1 status:** everything above is open source. **One open licence issue (A1):** Scapy `GPL-2.0-only` in-process (+ Apache-2.0 `python-multipart`) — must be resolved before the repo goes public.

---

## 3. Planned repository layout

```text
gilgamesh/
├── pyproject.toml            # uv project, [project.scripts] console entry (infra only)
├── uv.lock                   # committed (reproducible installs)
├── .python-version
├── README.md
├── LICENSE                   # pending decision A1
├── install.sh                # idempotent, non-interactive (doc 07)
├── deploy/
│   ├── systemd/              # gilgamesh-sensor.service, gilgamesh-web.service,
│   │                         # gilgamesh-rules-update.{service,timer}
│   ├── sysusers.d/           # service accounts
│   ├── tmpfiles.d/           # /run/gilgamesh socket dir
│   ├── logrotate/
│   └── suricata/             # generated overrides + disable/enable.conf templates
├── src/gilgamesh/
│   ├── __init__.py
│   ├── config.py             # Pydantic settings; DB-as-source-of-truth rendering
│   ├── models.py             # normalized Event, Device, Rule, Channel, User (Pydantic v2)
│   ├── db.py                 # SQLite WAL, schema, migrations, retention/pruning
│   ├── pipeline.py           # dedup → cooldown → rate-limit → aggregate → global limiter
│   ├── sensors/
│   │   ├── arp.py            # IP↔MAC / gateway MAC state machine        (#1)
│   │   ├── dns.py            # query/response correlation + resolver allowlist (#2)
│   │   ├── dhcp.py           # rogue server + starvation                 (#3)
│   │   ├── scan_flood.py     # vertical/horizontal scans + SYN flood     (#4)
│   │   ├── inventory.py      # new/unknown device                         (#5)
│   │   └── suricata_ingest.py# EVE JSON tailer                            (#6)
│   ├── notifiers/            # discord.py, telegram.py, email.py, base.py (retry/backoff queue)
│   ├── web/
│   │   ├── app.py            # FastAPI, lifespan, routers
│   │   ├── auth.py           # login, sessions, CSRF, lockout
│   │   ├── routes/           # dashboard, alerts, devices, rules, notifications, health, settings, wizard
│   │   ├── sse.py            # native SSE event bus
│   │   └── templates/        # Jinja2 + htmx partials
│   └── util/                 # redaction, time, mac/ip normalisation, atomic file writes
├── static/
│   ├── css/app.css           # built Tailwind output (committed)
│   ├── js/vendor/            # htmx.min.js, alpine csp build (VENDOR.md w/ sha256)
│   └── js/app.js             # our own EventSource glue + small helpers
├── tests/                    # pytest: unit + integration + fixtures (pcap-based)
└── docs/                     # PROMPT.md, PROGRESS.md, DECISIONS.md, PLAN.md, research/
```

---

## 4. Data model (outline — full schema in `docs/research/04-architecture.md` §4)

- `events` — normalized detector events (id, ts, type, severity, src/dst MAC+IP, iface, summary, `details` JSON, detector, `dedup_key`, `incident_id`).
- `incidents` — aggregation rollups (first/last seen, count, severity max).
- `devices` — inventory (mac, ips, hostnames, vendor OUI, first/last seen, `trusted`).
- `dhcp_state`, `arp_bindings` — detector state (rebuildable; may live in a separate state table).
- `rules` — per-rule enabled flag + typed params (rendered → Suricata `disable.conf`/`enable.conf` + custom thresholds).
- `channels` — notifier config + min severity + enabled (secrets handling per B12).
- `users`, `sessions`, `login_attempts` — auth.
- `suppressions` — user-maintained allowlist to silence a known-benign signature (audited).
- `audit_log` — who changed what config, when.

**Retention:** age-based + row-cap pruning in bounded batches; indexes on `(ts)`, `(type,ts)`, `(severity,ts)`, `(dedup_key)`. SD-wear mitigations: WAL, `noatime`, transient files on `tmpfs`, bounded batch deletes. (doc 04 §5)

---

## 5. Phased build plan

> Each phase ends with its **verification gate** met and evidence recorded. Work is TDD where practical (a failing test first for each detector/behaviour).

### Phase 2 — Foundation + nail the blockers (spike/benchmark)
**Exit criteria = the A/B blockers in `09-open-questions.md` are resolved or explicitly accepted.**

Tasks:
1. Resolve **A1 (licence)**: choose GPL-and-keep-Scapy **or** stdlib `AF_PACKET` + permissive parsers. Record in `DECISIONS.md`. **Do this first — it shapes the sensor code.**
2. Bring up the target OS image on the Pi; flash, enable `trixie-backports`, install Suricata **8.0.7** + `suricata-update` from the arm64 debs (**B5**); run `suricata-update` and confirm it resolves a rule set for 8.x (**A2**).
3. Set up `uv init` (first code action), `uv add`, commit `uv.lock`; verify `uv sync --frozen` and `--offline` (**B7**).
4. **Benchmarks (feed back into docs):** Scapy pkt/s (**A4**), Suricata RSS with the rule subset (**A5**), `br0` duplicate semantics (**B1**), `ethtool -k` offloads (**B2**), bridge throughput one-way + bidir (**B3**), boot coverage window (**B4**).
5. Configure `br0` with NetworkManager (`bridge.stp no`), STP off, management IP on the bridge (D-018); disable GRO/LRO/TSO.
6. Confirm systemd directive names on the target systemd (**B6**), `uv` binary path (**B9**), openssl presence (**D18**).

Deliverable: a short `docs/research/10-lab-benchmarks.md` capturing measured numbers + any decision changes.

### Phase 3 — Core: config, models, DB, event pipeline
1. `models.py` — normalized `Event` (D-004) + `Device`/`Rule`/`Channel`/`User` Pydantic v2 models with validators.
2. `db.py` — schema, WAL pragmas, migrations, bounded pruning, indexes; a throwaway-DB pytest fixture.
3. `pipeline.py` — dedup → cooldown → per-key rate limit → incident aggregation → global limiter (D-012). **Unit tests** for each stage: same-key suppression, cooldown expiry, bucket refill, aggregation rollup, global cap, bounded-memory eviction.
4. `config.py` — DB-as-source-of-truth; render engine config atomically (no shell).

Gate: `uv run pytest` green; a synthetic burst of 10,000 events produces a bounded, sane number of alerts.

### Phase 4 — Sensors (the detection core)
TDD each detector against **captured/synthetic pcaps** plus unit tests of the state machines. Order: `inventory` → `arp` → `dhcp` → `dns` → `scan_flood`.
- `arp.py` (#1): binding table, gateway-MAC-change (immediate high), unsolicited-reply rule, gARP-flood counter, ethernet-vs-ARP mismatch.
- `dhcp.py` (#3): trusted-server learning, rogue OFFER/ACK, `routers[]`/`dns_servers[]` baseline drift, starvation rate + distinct-`chaddr`.
- `dns.py` (#2): outstanding-query table keyed on `dns_id`; no-match window; resolver allowlist from DHCP; conflicting-answer detector; **FP guards** for CDN/round-robin/split-horizon.
- `scan_flood.py` (#4): per-source dst-port and dst-host sets; per-dst SYN counters; completion-ratio heuristic.
- `inventory.py` (#5): first-seen devices, locally-administered-bit → "likely randomised".
- Capture runs **off the asyncio loop** (thread/process), with BPF filters and `store=False` (doc 04 §3).

Gate: each detector has (a) a positive test that alerts and (b) an FP test (mesh/roaming/CDN/DHCP-renew) that does **not** alert.

### Phase 5 — Suricata integration (#6)
- EVE JSON tailer → `suricata_ingest.py`; map `alert` objects to `Event`; map ARP/DNS/DHCP EVE records as **evidence** for the custom detectors.
- Rule management: render `disable.conf`/`enable.conf` from the DB; per-category default severities; noisy categories start at `limit`/`threshold`.
- Runtime reload: `suricata-update` + `suricatasc reload-rules` / `kill -USR2` (doc 04 §9) — reload **without reboot**.
- Rules-update systemd timer + safe offline path (**B8**).

Gate: a known ET Open test signature fires end-to-end into the pipeline and the UI.

### Phase 6 — Notifiers
- `notifiers/base.py`: bounded async queue + worker; retries with exponential backoff; **never blocks** the pipeline; per-channel min severity; secrets redacted from logs.
- `discord.py` (webhook, `wait=true`), `telegram.py` (`sendMessage`), `email.py` (aiosmtplib).
- "Send test" action surfacing real HTTP status.
- Unit tests with a mocked transport: transient failure → retry → success; permanent failure → dropped + surfaced in health.

Gate: an injected high-severity event delivers to a real test channel; a channel outage does not stall detection.

### Phase 7 — Web UI + auth
- `auth.py`: Argon2id login (params from **C2**), server-side sessions + rotation + idle/absolute timeouts, **CSRF synchronizer token** via `<body hx-headers>` + hidden inputs, per-account lockout + per-IP `limits` (D-014/D-015/D-016).
- Pages: **first-run wizard** (admin account, interface/mode, alert channel), dashboard (live SSE), alerts (filter/ack/suppress), devices (trust/untrust), detection rules (toggle + typed params — **no user regex**, D-017), notifications, system health, settings.
- htmx 2.0.11 + Alpine CSP build + Tailwind v4 committed CSS; **our own** tiny `EventSource` glue (no `htmx-ext-sse`, B14); **single Uvicorn worker** (B15).
- Security headers (CSP without `unsafe-eval` given Alpine CSP, HSTS only under HTTPS, etc.).

Gate: a non-technical tester completes the wizard unaided; CSRF/token-missing requests are rejected; live alerts appear without refresh.

### Phase 8 — Deployment
- Idempotent `install.sh` (check-before-act, `set -euo pipefail`, non-interactive; **install = infrastructure only**, wizard = UI — doc 07 §0.1).
- systemd units with least privilege (D-019): `gilgamesh-sensor` (`AmbientCapabilities=CAP_NET_RAW` ± `CAP_NET_ADMIN` per **D21**), `gilgamesh-web` unprivileged; `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=`, `SystemCallFilter=@system-service`, `UMask=0077`; validate B6/D19/D20.
- Offline install path (vendored wheelhouse + `--offline`) once B7/B8 are settled; apt pinning to hold 8.x (**B10**).
- logrotate + journald caps (C17); `noatime`; tmpfs for transient files.
- Update path: git pull + `uv sync --frozen` + unit restart; rules update independently.

Gate: a clean flash → `install.sh` → wizard → live alerts, with **no shell interaction** beyond running the installer.

### Phase 9 — Hardening & review
- Walk OWASP Top 10 against the app; verify secrets (0600, dedicated user), parameterized SQL only, Pydantic on every input, no shell from user input, path-traversal guards.
- `systemd-analyze security` on the units; trim capabilities.
- Dependency audit (`uvx pip-audit`) wired into CI/dev; SBOM-style licence list generated from `uv.lock`.

### Phase 10 — Validation & FP soak (the credibility phase)
- **Attack validation** in an isolated lab (never on the user's live network without permission): ARP spoof (e.g. `arpspoof`/Scapy), DNS spoof, rogue DHCP (`dnsmasq`), `nmap` scans, SYN flood (`hping3`) — each must produce the right alert with correct evidence.
- **False-positive soak:** run 7 days on a real home network; log every alert; tune thresholds; document the final numbers back into `08-detection-matrix.md`.
- Memory/CPU profiling over the soak; confirm the 4 GB budget.

### Phase 11 — Polish & docs
- README (install guide with photos/diagram), `docs/DETECTIONS.md` (what each rule catches and its defaults), known-limitations page (blind spots from doc 01 §3 — **honesty is a feature**), and an alert-tuning guide.
- Finalise `LICENSE` (per A1) and `THIRD-PARTY-LICENCES.md` from doc 03.

---

## 6. Definition of Done (whole project)

1. All MVP acceptance criteria (§1.3) met and demonstrated.
2. `uv run ruff check` + `uv run ruff format --check` + `uv run pyright` clean; `uv run pytest` green (unit + integration).
3. Attacks in Phase 10 detected; FP soak documented.
4. Install/run verified end-to-end on the actual Pi 4.
5. No secrets in the repo; `.gitignore` covers `.venv/`, `*.db`, `*.db-wal`, `.env`, `__pycache__/`.
6. Every dependency has a recorded SPDX id + URL; A1 resolved.
7. Blind spots and limitations documented honestly.

---

## 7. Risk register (top risks)

| Risk | Impact | Mitigation |
|---|---|---|
| **Scapy GPL vs project licence (A1)** | Blocks public repo | Decide in Phase 2 before writing sensor code; stdlib `AF_PACKET` fast path is the escape hatch |
| **Scapy too slow on Pi 4 (A4)** | Missed packets | BPF filters, `store=False`, off-loop thread, raw `AF_PACKET` fast path; measure early |
| **Suricata 8 + ET Open mismatch (A2)** | No signature coverage | Verify in Phase 2; fallback = pin 7.0.10 temporarily or curate rules |
| **FP flood makes the tool useless** | Owner stops trusting alerts | Conservative defaults, dedup/cooldown/aggregation, allowlists, 7-day soak before "done" |
| **4 GB exhaustion** | Crashes / packet loss | Budgets + cgroup caps, `OOMScoreAdjust` favouring the sensor; measure on target |
| **Power loss while inline kills the link** | Home loses internet | Document honestly; recommend UPS; investigate fail-to-wire (likely unavailable on a Pi) |
| **SD-card wear** | Device dies in months | tmpfs for transient files, `noatime`, bounded writes, optional USB SSD |
| **Self-signed HTTPS trust** | Browser warnings scare the owner | Document; offer HTTP-on-LAN with clear warnings as the default, HTTPS opt-in |

---

## 8. Immediate next actions (when the user says "go" for build)

1. **Decide A1** (licence/Scapy) — one focused question to the user.
2. Create the git repo + GitHub repo; seed `LICENSE` per A1; commit Phase 1 docs.
3. `uv init` + `uv add` the locked stack; commit `uv.lock`.
4. Start Phase 3 (models → DB → pipeline) with tests, *after* the Phase 2 measurements that affect the capture design.

> **Reminder:** Phase 1 produced **no application code** and installed **nothing**. The first `uv init` happens only in Phase 2, on the user's go-ahead.

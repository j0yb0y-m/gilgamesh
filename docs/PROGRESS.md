# Gilgamesh — Research Progress

**Session:** Phase 1 — Research & Plan (Markdown only. NO application code, NO `uv init`, NO installs.)
**Date started:** 2026-10-14 · **Last updated:** 2026-10-14
**Rule:** Read this file FIRST at the start of every turn. Tick a topic only after its file is written to disk.

Legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked/needs decision

---

## Deliverables

| # | File | Topic | Status |
|---|------|-------|--------|
| 00 | `docs/PROGRESS.md` | This file | [x] |
| 00 | `docs/DECISIONS.md` | Decision log (decision / reason / alternative rejected) | [x] |
| 01 | `docs/research/01-network-placement.md` | Mode A bridge vs Mode B SPAN; blindness; fail-open; distro bridge tool; capture interfaces; NIC offload; USB3 gigabit | [x] |
| 02 | `docs/research/02-detection-catalogue.md` | Per-attack feasibility: ARP, DNS, DHCP, scans/floods, device inventory, Suricata signatures | [x] |
| 03 | `docs/research/03-tooling-and-versions.md` | Versions, SPDX licenses, aarch64 wheel availability, ET Open ruleset + update tool | [x] |
| 04 | `docs/research/04-architecture.md` | Components, event pipeline, storage/SD wear, notifiers, privilege separation, systemd hardening | [x] |
| 05 | `docs/research/05-web-and-stack.md` | FastAPI lifespan, Pydantic v2, htmx 2.x, Alpine CSP, Tailwind standalone CLI arm64, SSE | [x] |
| 06 | `docs/research/06-security-hardening.md` | Argon2/bcrypt aarch64, CSRF, sessions, login rate limiting, HTTPS/self-signed | [x] |
| 07 | `docs/research/07-deployment.md` | Idempotent install script, systemd units, uv on Pi, offline-first | [x] |
| 08 | `docs/research/08-detection-matrix.md` | Consolidated detection matrix (MVP + Later) | [x] |
| 09 | `docs/research/09-open-questions.md` | All UNVERIFIED items + open questions | [x] |
| 10 | `docs/PLAN.md` | Phased implementation plan (no code) | [x] |

**Phase 1 research is COMPLETE.** No application code was written and nothing was installed (`uv init`, `uv add`, `uv sync` not run).

## Pinch points (hard constraints C1–C8)

- [x] C1 — licences recorded (SPDX + URL) in doc 03 §2/§5; ET Open ambiguous (BSD-3-Clause-style vs MIT, both permissive); ET Pro excluded. **Open risk: Scapy `GPL-2.0-only` in-process (D-008).**
- [x] C2 — web UI only; systemd units + install script are infrastructure (doc 07 §0.1)
- [x] C3 — Python + FastAPI 0.143.0, htmx 2.0.11, Alpine 3.17.4 (CSP build), Tailwind 4.3.3 (doc 05)
- [x] C4 — `uv` only (doc 03 §2.5, doc 07 §2.2)
- [x] C5 — no Node.js; `tailwindcss-linux-arm64` verified; built CSS committed (doc 05 §6)
- [x] C6 — native, systemd, no Docker (doc 07 §3)
- [x] C7 — RAM/CPU budget: ≤ ~2.0 GiB target of 4 GB (doc 04 §8); Suricata RSS on Pi is UNVERIFIED
- [x] C8 — tool choice evidenced (doc 03 tables; doc 01/02 citations)

## Pitfall checklist (PROMPT §4) — verified against current docs

- [x] Tailwind **v4.3.3** is CSS-first (`@import "tailwindcss"`) — **not** v3's `@tailwind` directives + `tailwind.config.js`; do not mix (doc 05 §6)
- [x] FastAPI **`lifespan`** recommended; `@app.on_event` is the deprecated path and is overridden by `lifespan` (doc 05 §1)
- [x] Pydantic **v2** (2.14.1) is what FastAPI 0.143.0 requires; `model_validate`/`model_dump`/`field_validator`/`model_config` (doc 05 §2)
- [x] Scapy `sniff()` blocks; use `AsyncSniffer` (thread) and never run it in the asyncio loop (doc 04 §3)
- [x] Suricata **8.0.7** rule syntax/config keys checked; **no ARP rule keyword** (ARP is decoder+logger only) (doc 02 §0)
- [x] aarch64 wheel availability audited — every compiled dep ships an aarch64 wheel; **no compiler on the Pi** (doc 03 §3)
- [x] htmx: **1.x vs 2.x outdated** — 2.x current (npm `latest` = **2.0.11**), **4.0.0** released 2026-08-28 but not `latest`; pin 2.0.11 (doc 03 §2.3, doc 05 §4)
- [x] Alpine strict-CSP case **requires** the separate `@alpinejs/csp` build (doc 05 §5)

## Notes

- Web access confirmed (2026-10-14). Suricata stable = **8.0.7**; 7.x EOL since 2026-07-07.
- **Independently re-verified by the lead** (not just subagent claims): Suricata `8.0.7-1~bpo13+1` **arm64 .deb** exists in trixie-backports; `suricata-update 1.3.8-1~bpo13+1` arm64 .deb exists; FastAPI 0.143.0, Starlette 1.8.0, Pydantic 2.14.1, Scapy 2.8.0 (`GPL-2.0-only`), argon2-cffi 25.1.0; **htmx 4.0.0** exists (2026-08-28) and npm `latest`=2.0.11; Tailwind v4.3.3 publishes `tailwindcss-linux-arm64`; FastAPI ships **`fastapi/sse.py`**; Starlette ships **`RequestBodyLimitMiddleware`**; ET Open feed dirs = `suricata-5.0`, `suricata-7.0.3` only.
- All UNVERIFIED/open items are consolidated in `docs/research/09-open-questions.md`.

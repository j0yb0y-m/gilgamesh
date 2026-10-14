# Gilgamesh — Decision Log

Format per entry: **Decision** · **Reason** · **Alternative rejected** · **Status** · **Evidence**
Status values: `LOCKED` (approved/final for Phase 1) · `PROVISIONAL` (best guess, verify in build) · `OPEN` (needs user or evidence).

---

## D-001 — Target platform: Raspberry Pi OS Lite 64-bit (Bookworm/Trixie), not Kali ARM64

- **Decision:** Primary target is **Raspberry Pi OS Lite 64-bit** (Debian-based). Kali ARM64 is documented as an alternative only.
- **Reason:** Pi OS Lite ships a smaller, better-supported Debian userland for a headless appliance, has first-class Raspberry Pi kernel/firmware support, and avoids Kali's offensive-tool baggage that a *defensive* product does not need (thinner attack surface, fewer CVEs, smaller image). Package availability for Suricata/systemd/NetworkManager is the Debian one, which we can verify chapter-and-verse.
- **Alternative rejected:** Kali ARM64 as primary — heavier, security-tooling bloat conflicts with C7 (4 GB budget) and with hardening goals; its rolling repos complicate reproducible installs.
- **Status:** LOCKED (confirmed in doc 03).
- **Evidence:** doc 03 §1 — current image `2026-10-06-raspios-trixie-arm64-lite.img.xz`, Debian 13 `trixie` (current stable), kernel 6.18, system Python 3.13.5, glibc 2.41. Caveat recorded: Pi OS ships proprietary VideoCore firmware blobs (platform layer is not 100% open — unavoidable on Pi 4).

## D-002 — Suricata major version 8.x

- **Decision:** Target **Suricata 8.x** (current stable 8.0.7, released 2026-09-15).
- **Reason:** The 7.x branch reached **End of Life**; the vendor explicitly tells users to upgrade to the 8 branch. Building v1 on an EOL engine would ship known-unfixed CVEs into a security product.
- **Alternative rejected:** Suricata 7.x — EOL, no security fixes. Snort 3 — viable but Suricata is the more common home-lab/NSM choice with a cleaner EVE JSON output and `suricata-update`; revisit only if 8.x packaging for aarch64 is absent.
- **Status:** LOCKED (package path confirmed) — one residual open item on ET Open rule-format compat.
- **Evidence:** doc 03 §2.4 + lead re-verification: `suricata 1:8.0.7-1~bpo13+1` and `suricata-update 1.3.8-1~bpo13+1` ship **arm64 `.deb`s in `trixie-backports`** — no source build. Trixie stable only has the EOL `1:7.0.10`. Residual: `suricata-update` must resolve a rule source for an 8.x engine (public feed's newest build dir is `suricata-7.0.3`).

## D-003 — Network placement Mode A (inline transparent L2 bridge) is the v1 default

- **Decision:** v1 default = transparent bridge `br0` over `eth0`+`eth1`; Mode B (SPAN/mirror) supported as an option; full router (NAT/DHCP) explicitly out of scope.
- **Reason (hypothesis, to be verified):** a passively-plugged Pi on a switch sees almost nothing; an inline bridge is the only placement a non-expert can insert without a managed switch, and it captures LAN↔WAN plus broadcast ARP/DHCP/NDP.
- **Alternative rejected:** Passive tap only — misses unicast LAN↔WAN traffic on switched networks. Full router mode — large scope, higher risk, degrades/blocks connectivity, violates "never degrade the connection".
- **Status:** PROVISIONAL (verify bridge tooling, fail-open behaviour, blindness list in doc 01).
- **Evidence:** pending — see `docs/research/01-network-placement.md`.

## D-004 — Event schema = one normalized Pydantic v2 model per detector event

- **Decision:** All detectors (Suricata EVE + custom) normalize into a single event model: `id, timestamp, type, severity, src/dst MAC+IP, interface, evidence summary, raw details JSON, detector name`.
- **Reason:** Single pipeline for dedup/cooldown/rate-limit/store/notify; keeps notifiers and storage decoupled from detector internals.
- **Alternative rejected:** Detector-specific tables/notifications — duplicated logic, no unified dedup.
- **Status:** PROVISIONAL.

## D-005 — SQLite (WAL) as the single source of truth; generated config is derived

- **Decision:** DB is the source of truth for config + events. Any engine config (e.g. Suricata overrides, threshold values) is **rendered** from the DB.
- **Reason:** One config store avoids drift; enables "apply without reboot"; simple, no extra service on a 4 GB box.
- **Alternative rejected:** Flat config files as source of truth (drift, harder live edits); Postgres (overkill, extra RAM).
- **Status:** PROVISIONAL.

## D-006 — Privilege separation: privileged sensors, unprivileged web app, IF a DB/log medium

- **Decision:** Capture/sensors run as a low-privilege system user with only `CAP_NET_RAW` (+`CAP_NET_ADMIN` where needed); web app runs unprivileged; the two communicate via SQLite (WAL) and/or a Unix socket.
- **Reason:** Least privilege for a security product; systemd sandboxing applies to the web tier.
- **Alternative rejected:** Single root process doing capture + web (unacceptable exposure); CAP-heavy web process.
- **Status:** PROVISIONAL (verify exact capability set + systemd hardening directives in doc 04).

## D-007 — No Node.js on device (C5); Tailwind via standalone CLI, built artifact committed

- **Decision:** Use the Tailwind standalone CLI to build CSS; commit the built CSS; no Node/npm on the Pi.
- **Reason:** Constraint C5; keeps the appliance light and offline-installable.
- **Alternative rejected:** Node toolchain on Pi (violates C5); CDN Tailwind (needs internet, not offline-first, and JIT-in-browser is not the supported build path).
- **Status:** PROVISIONAL (verify arm64 standalone binary exists for the chosen Tailwind major).

## D-008 — Scapy's licence (GPL-2.0-only) imported in-process must be resolved before publishing a repo

- **Decision:** **OPEN — decide before creating the GitHub repo.** Recommended: license Gilgamesh **GPL-2.0-or-later/GPL-3.0** and keep Scapy, **or** replace Scapy on hot paths with stdlib `AF_PACKET` + permissively licensed parsers.
- **Reason:** Scapy is `GPL-2.0-only` (verified via PyPI `license_expression`) and would be **imported in-process**, making a distributed Gilgamesh arguably a derivative work. Aggravating: `python-multipart` is `Apache-2.0`, which is commonly treated as **incompatible with GPL-2.0-only**. Suricata's GPLv2 is fine because it runs as a **separate process**.
- **Alternative rejected:** (a) Ignore it — a real licence problem if the repo is public; (b) rely on "internal-only" — untrue once the college project is published.
- **Status:** OPEN (blocker for a public repo; not a blocker for local development).
- **Evidence:** doc 03 §5.1, doc 03 §5.2.

## D-009 — htmx pinned to 2.0.11 (not 4.0.0)

- **Decision:** Pin **htmx 2.0.11** (vendored), treat 4.0.0 as an evaluate-later upgrade.
- **Reason:** 4.0.0 was released 2026-08-28 (a <2-month-old fetch-based rewrite); npm `latest` = 2.0.11, which is what htmx.org currently documents and what the ecosystem/extensions target. A home appliance wants the documented, stable path.
- **Alternative rejected:** htmx 4.0.0 now — bleeding edge on a device we can't easily debug remotely.
- **Status:** PROVISIONAL (re-evaluate before v1.1).
- **Evidence:** doc 03 §2.3, doc 05 §4; lead-verified htmx 4.0.0 release date and npm `latest`=2.0.11.

## D-010 — Tailwind v4 (CSS-first), built with the arm64 standalone CLI, output committed

- **Decision:** Tailwind **v4.3.3**, CSS-first (`@import "tailwindcss"` + `@source`), built with `tailwindcss-linux-arm64`, `app.build.css` committed. **No Node.js on the Pi.**
- **Reason:** C5; v4 CLI standalone binary verified for linux-arm64. Mixing v3 (`@tailwind` directives + `tailwind.config.js`) with v4 is the exact pitfall to avoid.
- **Alternative rejected:** Tailwind v3 (older syntax, not current); Node/PostCSS on the Pi (violates C5).
- **Status:** LOCKED (syntax + asset verified).
- **Evidence:** doc 05 §6; lead-verified `tailwindcss-linux-arm64` asset in the v4.3.3 release.

## D-011 — Live dashboard via FastAPI native SSE; no `sse-starlette`, no `htmx-ext-sse`

- **Decision:** Use `fastapi.sse.EventSourceResponse` / `ServerSentEvent` with a **small `EventSource` glue script we own**; keep htmx polling only for coarse health widgets.
- **Reason:** Native since FastAPI 0.135.0 (we are on 0.143.0) — `sse-starlette` would duplicate it; `htmx-ext-sse`'s **licence is unverified**, which fails C1.
- **Alternative rejected:** `sse-starlette` (redundant); `htmx-ext-sse` (licence unverified); per-tab polling (wasteful on a Pi).
- **Status:** PROVISIONAL (multi-worker SSE broadcast is an open item; run one Uvicorn worker).
- **Evidence:** doc 05 §7; lead-verified `fastapi/sse.py` exists.

## D-012 — Event pipeline: dedup → cooldown → per-key rate limit → incident aggregation → global limiter

- **Decision:** Implement all five stages keyed on a derived `dedup_key`; defaults DEDUP 5 s, COOLDOWN 300 s, RATE 5/60 s, AGG 900 s, ESCALATE_AT 50, GLOBAL 10/min, MAX_TRACKED_KEYS 10,000 (all tunable in the UI).
- **Reason:** The brief's requirement that one attack must not send thousands of alerts; bounded-memory LRU state.
- **Alternative rejected:** Per-event notifications; a single global threshold (loses per-attack context).
- **Status:** PROVISIONAL (numbers to be tuned after real traffic).
- **Evidence:** doc 04 §2.

## D-013 — Password hashing: Argon2id via `argon2-cffi`

- **Decision:** Argon2id via `argon2-cffi` 25.1.0 (MIT), start at t=3/m=64 MiB/p=4, `check_needs_rehash` on login, single module-level `PasswordHasher`.
- **Reason:** OWASP's first-choice; aarch64 wheel via `argon2-cffi-bindings`; MIT. Rehash-on-login handles parameter drift.
- **Alternative rejected:** `bcrypt` 5.0.0 (fine, but Argon2id stronger); PBKDF2 (weakest); `passlib` (unmaintained).
- **Status:** PROVISIONAL (benchmark exact params on the Pi).
- **Evidence:** doc 06 §1.

## D-014 — Sessions: opaque `sid` in a signed cookie + server-side `sessions` table

- **Decision:** Starlette `SessionMiddleware` carries only a random `sid`; a SQLite `sessions` row enforces revocability, idle + absolute timeouts, and rotation on login.
- **Reason:** OWASP requires revocability and both timeouts; a fat signed cookie is readable and not revocable. Add `itsdangerous` explicitly (Starlette `full`-extra dep only).
- **Alternative rejected:** Signed cookie holding session data (no revoke, no idle timeout).
- **Status:** PROVISIONAL (timeout values in doc 04/09).
- **Evidence:** doc 06 §2.

## D-015 — CSRF: Synchronizer Token via `<body hx-headers>` + hidden form field

- **Decision:** Per-session token rendered into a meta tag and `<body hx-headers>`, plus hidden inputs in real forms; validate on every unsafe method with `hmac.compare_digest`; add Fetch-Metadata/Origin checks and `SameSite=Lax` as depth.
- **Reason:** Stateful cookie app → OWASP-recommended Synchronizer Token pattern; htmx inherits `hx-headers` into fragments.
- **Alternative rejected:** Naive double-submit (OWASP DISCOURAGED); `SameSite` alone (not a CSRF control).
- **Status:** PROVISIONAL.
- **Evidence:** doc 06 §3.

## D-016 — Login rate limiting: persisted per-account lockout + per-IP `limits` + hashing concurrency cap

- **Decision:** SQLite `login_attempts` for lockout/backoff, `limits` (5.8.0) `MemoryStorage` per-IP throttle, and a semaphore capping concurrent Argon2 verifications; single Uvicorn worker.
- **Reason:** Different threats need different counters; persistence survives restarts; avoids `slowapi`'s thin-wrapper/maintenance risk.
- **Alternative rejected:** `slowapi` only (slow cadence); in-memory dict keyed by IP (bypassable, memory-exhaustion vector).
- **Status:** PROVISIONAL.
- **Evidence:** doc 06 §4.

## D-017 — Detection config: structured allowlists only; no user regex, no raw rule authoring in v1

- **Decision:** Users toggle a **fixed catalogue** of built-in rules and set typed, bounded parameters (IP/CIDR/MAC/enum/int). No user-supplied regex; no free-text Suricata rules. Values rendered into fixed paths atomically; never via a shell.
- **Reason:** Removes the ReDoS surface (Python `re` has no timeout), the rule-injection surface, and config resource-exhaustion; aligns with OWASP.
- **Alternative rejected:** Free-text regex/rules (ReDoS + injection); denylist filtering (bypassable).
- **Status:** LOCKED (design principle for v1).
- **Evidence:** doc 06 §7/§8.

## D-018 — Bridge config: NetworkManager + `nmcli`, `bridge.stp no`; capture on `br0` only

- **Decision:** Configure `br0` with NetworkManager (`nmcli`), STP off, management IP on the bridge; run Suricata and Scapy on `br0` (one capture vantage point), never on both member ports.
- **Reason:** Current RPi OS documents NetworkManager; NetworkManager defaults STP **on**, so it must be disabled for a 2-port loop-free bridge; one capture device avoids double-counting.
- **Alternative rejected:** `systemd-networkd`/ifupdown as primary (documented as alternatives); dual captures on `eth0`+`eth1` (duplicate frames).
- **Status:** PROVISIONAL (duplicate-packet semantics on `br0` vs members still UNVERIFIED — test on target).
- **Evidence:** doc 01 §2.4/§6.3.

## D-019 — Privilege separation + systemd hardening

- **Decision:** `gilgamesh-sensor` runs unprivileged with `AmbientCapabilities=CAP_NET_RAW` (+`CAP_NET_ADMIN` only if it must touch interface state); `gilgamesh-web` runs unprivileged with **no** capabilities and `DynamicUser=yes`; both `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=`, `SystemCallFilter=@system-service`, `UMask=0077`.
- **Reason:** Least privilege for a security product (D-006); verified directive names in systemd docs.
- **Alternative rejected:** One root process doing capture + web; broad capabilities on the web tier.
- **Status:** PROVISIONAL (validate `RestrictAddressFamilies=AF_PACKET` and the `@system-service` set on the target systemd).
- **Evidence:** doc 04 §7, doc 07 §3.

---

## Pending decisions / open items (see `docs/research/09-open-questions.md`)

- Scapy GPL licence resolution (D-008) — **OPEN, blocks public repo**
- Suricata rule subset + sensitivity presets (doc 02) — **OPEN**
- Scapy vs raw `AF_PACKET` and the Pi 4 packet-rate ceiling (doc 02/04) — **UNVERIFIED**
- Exact detection thresholds (ARP/DNS/DHCP/scan/flood) (doc 02) — **proposed, tunable**
- Alert transport security model (TLS, token storage/encryption-at-rest) (doc 06) — **OPEN**
- Storage retention numbers + SD-wear mitigations (doc 04) — **proposed, tunable**
- Suricata RSS on a Pi 4 + ET Open ↔ Suricata 8 rule compat (doc 03) — **UNVERIFIED, blocks LOCKED**

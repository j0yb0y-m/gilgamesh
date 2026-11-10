# Gilgamesh v1.1 — Design: reliability, detection breadth, triage depth

**Date:** 2026-10-26
**Status:** direction approved by the owner in conversation; pending builder check.
**Input:** an independent review of the v1 codebase (all file:line anchors below were verified
against the tree on this date) plus the project's own deferred catalogue
(`docs/research/02-detection-catalogue.md` items #7–#11).

## 1. Intent and why

Gilgamesh v1 is built and green (412 unit + 13 e2e tests, two audit passes, docs produced),
but it has never run against the real Pi, and the review found its failure modes are
mostly **silent**: a dead sensor looks like a quiet network, Suricata may capture on the
wrong interface, packet drops are invisible, quiet hours destroy alerts, and incident
state evaporates on restart. Detection breadth (v1 deferred items #7–#11, DoH/DoT
blindness, device intelligence) and triage depth (no alert state, in-Python filtering)
were deliberately held back by D-026 (MVP scope).

v1.1 makes the box **trustworthy first** (A), then **more capable** (B), and **usable at
real alert volume** (C) — interleaved in the risk-removal order below. The owner chose
"all of A, B and C".

## 2. Goals / non-goals / anti-goals

**Goals**

1. No silent failure: the owner is told within a minute when capture is dead, stalled,
   dropping packets, or Suricata is not watching the bridge.
2. Durable alerting across restarts; quiet hours defer rather than discard.
3. Incident continuity across sensor restarts.
4. Alert triage: acknowledge / false-positive as real state; false-positive writes a
   suppression; SQL-side filtering and pagination.
5. Detection additions: ICMP redirect, IPv6 rogue RA/NDP, OUI vendors + DHCP
   fingerprints, encrypted-DNS (DoH/DoT) visibility, resolver-allowlist wiring fix —
   and, enabled-off until calibrated, DNS-tunnelling and beaconing heuristics.
6. Secrets and TLS moved from "stored intent" to working behaviour, or removed.

**Non-goals (unchanged from v1)**

- **Never blocking traffic** — detect-and-alert only (project charter).
- No Node.js on the Pi; no CDN/external fonts; htmx/Alpine stay vendored (C5/C6).
- No firmware/host network changes performed by Gilgamesh itself; bridge setup stays
  documented, user-run steps.
- No ML. The tunnelling/beaconing heuristics are simple statistics with thresholds,
  default-disabled until calibrated on real traffic (see D-026 note in §6).

**Anti-goals (what failure would look like even if it works)**

- A box that silently stops detecting (the true anti-goal).
- A "hardening change" that can wedge capture — every new probe path must degrade to
  "feature unavailable" and log, never fail the packet loop (mirrors `gate.py`'s
  fail-towards-alerting stance).
- New detectors that alert on ordinary home traffic — every detector ships with its
  false-positive guard tests before merging, per the v1 practice.

## 3. Constraints (inherited, non-negotiable)

- **C1** open-source only; SPDX + source URL recorded in `docs/research/12-licenses.md`
  *before* adding or generating any dependency or data file (OUI file, `cryptography`,
  any feed).
- **C3/C4/C5/C6** stack discipline; **C7** native systemd; **C8** capture abstraction;
  **C9** tool choices with evidence; **C10** everything testable without the Pi.
- Repo discipline: commands gate (`uv run ruff check .`, `uv run ruff format --check .`,
  `uv run pyright`, `uv run pytest`), evidence pasted into `docs/PROGRESS.md`, new
  licence rows recorded before use, decisions logged in `docs/DECISIONS.md`.
- **Safety:** lab steps involving network namespaces, real interfaces, `sudo`, or attack
  traffic are written as scripts/docs for the owner to run on the lab box — not executed
  by the agent. Detectors are validated on synthetic Scapy packets and PCAPs (C10).

## 4. Approaches considered

Three independent directions were laid out and the owner picked all:

- **A — deployability/reliability** (watchdog, heartbeats, capture truth, DB hygiene,
  durable delivery, Suricata wired right, secrets/TLS honesty).
- **B — detection breadth** (catalogue items #7/#9/#10/#11, OUI/DHCP fingerprint, DoH/DoT
  visibility, resolver wiring fix).
- **C — triage depth** (alert state machine, suppression-from-alert, SQL filters,
  pagination, incident persistence).

Chosen order: **R1 (A-core) → R2 (A: Suricata) → R3 (A: durability) → R4 (C) → R5 (B:
device intel) → R6 (B: IPv6/redirect) → R7 (B: encrypted DNS + heuristics) → R8 (A:
secrets/TLS/budgets/docs)**. Rationale: R1–R4 make detection *observable and trustworthy*
before new detectors (B) are evaluated on this box — otherwise B's false-positive-rate
judgements would be made against an instrument with unproven eyes.

## 5. Phases

Each phase lands its own tests, docs evidence, and (where noted) a DECISIONS entry.
Millstone rows go into `docs/PROGRESS.md` as M16…M23.

### R1 — No silent failure

**Problem, verified.** Systemd restarts only on exit; nothing detects a hung capture or
tailer. Health liveness is only `MAX(events.ts)` (`web/routes/health.py:75-82`) and cannot
distinguish quiet from dead. AF_PACKET drops are never read; the live queue is unbounded
(`sensors/capture.py:133`). SQLite has no checkpoint/vacuum policy and no backup.

**Deliverables**

- `sensor_status` single-row table (`db.py`, schema v3 migration): wall clock ts,
  monotonic ticks, `packets_seen`, `events_stored`, `capture_drops`, `eve_lines_seen`,
  `last_eve_ts`, `pid`, `interface`. Written from the capture loop every ~5 s and from
  the EVE tailer thread (each thread updates its slice under a small lock; the runner
  writes the row). Survives restarts so the web sees history.
- Web maintenance sweep classifies staleness: readable row older than **90 s** while a
  live interface is configured → writes a real CRITICAL event
  (`type=sensor_down`, `detector=health`) through storage directly, so delivery +
  notifier act. Re-alerts at most every 10 min while still stale. Health pages expose a
  live tile ("alive / stale / drops accumulating / EVE stopped") from this same row.
- Capture truth: per-socket drop counters read from `/proc/net/packet` (match own
  socket inodes; stdlib only) surfaced in `sensor_status.capture_drops`; a sustained
  growth (>0 within a window) raises a logged WARN event. `LiveSource` queue becomes
  bounded (`maxsize`, oldest-dropped counter — a Queue can drop oldest only in consumer;
  alternative: `put_nowait` + drop-newest counter, chosen: drop-newest like the notifier
  queue for consistency) — account both drop locations in one health metric.
- systemd: sensor unit becomes `Type=notify` + `WatchdogSec=30`; small stdlib notify
  helper (reads `NOTIFY_SOCKET`, sends `READY=1` then `WATCHDOG=1` at half-interval from
  the same 5 s status loop; no new dependency). Sensor also reports `STATUS=packets=…`
  occasionally for journal triage.
- DB hygiene in the maintenance sweep: `wal_checkpoint(TRUNCATE)` hourly; after prune
  batches `PRAGMA incremental_vacuum;`; nightly `VACUUM INTO backups/gilgamesh-YYYYMMDD.db`
  keeping the newest 3 (bounded, in the data dir).
- `docs/LAB.md` + `scripts/lab/` (owner-run, never agent-run): netns+veth live-capture
  checks for watchdog, drops, heartbeat, EVE severity direction, ET-Open format — the
  C10-complement acceptance for hardware-layer behaviour.

**Acceptance:** unit tests for status table, staleness event, drop accounting, backup
rotation (with injected clock/paths); a test proves the notify helper is a no-op when
`NOTIFY_SOCKET` is unset; full gate green. `deploy` tests assert `Type=notify`,
`WatchdogSec=`, and that sysusers still resolves both accounts.

### R2 — Suricata actually capturing on the bridge

**Problem, verified.** `deploy/suricata/10-gilgamesh.conf` only relaxes `ReadWritePaths`;
Debian's default `suricata.yml` interface (eth0, not br0) wins, so ET Open coverage is
charitably hypothetical.

**Deliverables**

- Ship `deploy/suricata/suricata-gilgamesh.yml`: complete minimal home-config — af-packet
  capture from the Gilgamesh interface (single source; placeholder substituted by
  install.sh), EVE to `/var/log/suricata/eve.json` (`alert`, plus `stats` and
  flow/dns/http records as facts available to later phases — ingest processes only
  `alert` today and ignores the rest, unchanged), TLS app-layer with `ja4` enabled
  (feature-flagged; availability matters R7), thresholds conservative, memcap per
  the PLAN §10 budget.
- install.sh: installs it, adds an `ExecStart=/usr/bin/suricata -c /etc/suricata/suricata-gilgamesh.yml`
  drop-in (in the same directory style as the existing `10-gilgamesh.conf`), keeps the
  existing `ReadWritePaths` drop-in, refuses to proceed if `suricata -T` fails (owner-run).
- `rules_update.py` confirms reload via `suricatasc` and fails loudly on zero loaded
  rules (the "0 rules loaded" failure mode must be an alert-level complaint, not silence).
- EVE severity direction (B17) resolved as a documented acceptance step on the lab
  (owner-run), with the mapping made reloadable from config as it already is
  (`suricata_ingest.py` supports an override map).

**Acceptance:** YAML is parsed in tests (basic structural assertions, interface
placeholder substitution, `ja4` flag present); updated `tests/test_deploy_artifacts.py`
for the new drop-in; gate green. Lab note in `docs/LAB.md` for severity/compat (owners).

### R3 — Durable alerting + persistent incidents

**Problem, verified.** Notifier queue is in-process memory, at-most-once (drop-newest at
1000), restart loses queued-but-unsent; quiet hours discard permanently
(`notifiers/base.py:204-207`). Pipeline incidents/escalation live only in sensor RAM
(`pipeline.py:106-108`); `events.incident_id` is vestigial.

**Deliverables**

- New `deliveries` table: `(id, event_id, channel_kind, state queued| deferred |
  delivered | failed, attempts, next_attempt_ts, last_error, created_ts)` + indexes on
  `(state,next_attempt_ts)`. The delivery loop's source of truth becomes these rows:
  on web start, pending rows are picked up (at-least-once); `Send test` keeps its
  bypass path (no row, or a row purged on completion — builder's minor call).
- Quiet hours become **defer**: row re-scheduled to window end (`deferred_until` at
  queue time), leaving a per-channel boolean "discard during quiet hours" for owners who
  prefer v1 behaviour (call recorded in §6). Cap on pending rows reuses retention (days).
- Incidents persisted: new `incidents` table (per original PLAN §6 columns + `escalated`).
  STORE inserts, AGGREGATE updates count/last_ts, escalation flips the flag. Sensor start
  hydrates open incidents (agg-window lookback) into `Pipeline` with `escalated` =
  `count >= escalate_at` (one re-announce nuance lost on restart is acceptable vs. state
  loss; log the hydration line). `events.incident_id` becomes real; dashboards can read
  counts later.
- Notifier internals unchanged (bounded asyncio queue stays) — durability lives in DB
  rows, memory queue is just a pump; cap semantics keep drop-newest accounting for the
  in-memory transition only.

**Acceptance:** restart tests (kill/rebuild delivery service mid-flow → row completes);
quiet-hours defer test with midnight-wrapping window; migration test for schema v3→v4;
pipeline hydration test; gate green.

### R4 — Triage UX

**Problem, verified.** Ack/false-positive routes only append audit strings
(`web/routes/alerts.py:69-99`); no state column exists; the FP route has no UI surface;
alert filters run in Python over the last 200 events (`alerts.py:28-35`).

**Deliverables**

- `events.state` (enum `open|acknowledged|false_positive`, default `open`) + index
  `(state, ts)` in the v3/v4 migration. Ack and FP flip state atomically; audit log keeps
  its entries. Alerts list and detail show the state; FP action **writes a suppression**
  (`rule_id_for_event` + normalized src_ip/src_mac, note auto-generated) so the noise
  class it represents goes away going forward; adding the suppression shows the effect.
- False-positive button on detail *and* list rows (htmx swap, same contract as rules);
  a one-click undo (delete suppression) from the alert detail.
- SQL-side filtering: severity/type/device/window/q as WHERE clauses with existing
  indexes; cursor pagination (`rowid < :before`, page size 50) on `/alerts` and
  `/devices`; the 200-row cap is removed. `q` search matches summary + JSON details via
  pre-extracted indexed columns only if cheap — otherwise summary-only (builder call;
  document the limit).

**Acceptance:** route/UI tests (state transitions, suppression creation + undo,
pagination cursor invalidation), e2e extended for "mark false positive from the list",
gate green.

### R5 — Device intelligence

- Vendor OUI: a build script (`scripts/vendor/generate-oui.py`) fetches IEEE's public
  registry, outputs a compact CSV subset (`prefix,org`) committed to
  `src/gilgamesh/data/oui.csv` (bounded size; only organisation names, no other data).
  Licence row recorded **before first use** (IEEE registry terms + attribution note).
  A small module loads it into a prefix trie; `DeviceStore.upsert` fills
  `devices.vendor`; new-device events include the org; Devices page shows it.
- DHCP option-55 fingerprint: map observed parameter-request-lists to rough
  OS/behaviour hints (a fixed lookup table, no fuzzy claims), stored as a device detail
  + surfaced on `new_device` events. False-negative tolerated (no match = no hint);
  never an alert by itself.
- Device attribution sharpener (recorded observation in PROGRESS Phase 7): when an ARP
  frame's Ethernet source disagrees with its ARP sender (`arp.py` already detects this),
  inventory keys the sighting on the *ARP sender MAC* (the asserted identity) but
  stores `ethernet_mac` in details so the audit-recorded misattribution disappears.

**Acceptance:** licence-record-first test (pattern exists for vendored assets in
`design-system` tests); trie correctness + bounded memory; fingerprint table tests;
inventory attribution regression tests; gate green.

### R6 — ICMP redirect + IPv6 rogue RA/NDP

From the shipped research designs (`docs/research/02-detection-catalogue.md:269-298`),
not reinvented. Both are detect-only; thresholds land in the catalogue with the same
typed-param discipline (D-017).

- **`sensors/icmp_redirect.py`** — ICMP type 5 observed: alert when the redirect target
  is not the learned default gateway AND the router relationship check holds (a redirect
  must originate from the current first-hop gateway). HIGH. Evidence: from/to/target.
  Lab-verifiable step included (C13 for adults: this one is v4 and low-risk).
- **`sensors/ndp6.py`** — mirrors ARP detector discipline for ND: rule A "first router
  learned, then a different link-local RA with comparable lifetime" (HIGH, with FP guard
  for real multi-router homes → threshold param; defaulted to 1 extra router beyond
  learned); rule B "RA announcing a new prefix while an existing one is younger than X"
  (MEDIUM); rule C "NS/NA DAD-style conflict (same target claimed by two MACs)"
  (HIGH, direct analogue of `ip_mac_conflict`); rule D "RA with non-zero router lifetime
  from an Ethernet source that is not a learned router MAC" (MEDIUM). Warm-up parity
  with ARP (300 s). Explicitly gated on the lab check that NDP is visible in bridge
  mode (C13) before enable-by-default; unit tests run regardless (C10).
- BPF stays covered (`icmp` and `icmp6` already in `DEFAULT_BPF`); catalogue rules
  `icmp.redirect`, `ndp6.rogue_ra`, `ndp6.spoofing` added with params; runner builds
  them; Defaults surfaced in the UI rules page (no new UI machinery needed).

**Acceptance:** synthetic Scapy packet tests, positive + benign-negative pairs per
detector; PCAP replay fixtures added; gate green.

### R7 — Encrypted-DNS visibility + calibrating heuristics

- **Resolver-allowlist wiring fix (independent of everything else):** DHCP-learned server
  IPs now populate `DnsConfig.trusted_resolvers` through the gate's 30 s refresh
  (allowlist joins existing UI state; sensor reads learned servers from `dhcp_state`).
  Until this lands, `untrusted_resolver` can never fire — verified
  (`sensors/runner.py:336-342` builds `DnsConfig` with no resolvers; `dns.py:259` only
  acts against a non-empty set). Tests for both directions.
- **DoH/DoT visibility via signals we can see:** ship a small local Suricata ruleset
  (`deploy/suricata/50-gilgamesh.rules`) with fixed signatures for well-known public
  encrypted-resolver endpoints (DoT 853; DoH provider IP sets list kept conservative and
  commented) + `ja4` signature for known DoH-capable clients when available; loaded from
  `suricata-gilgamesh.yml`; SIDs owned by us; severity LOW/MEDIUM "device adopted
  encrypted DNS" classification through `suricata_ingest` unchanged. D-017 stays intact:
  no user-written regex, this is a fixed curated catalogue shipped with the product.
- **DNS-tunnelling heuristic** (`sensors/dns_tunnel.py`): per-client long-qname /
  TXT-weight / NXDOMAIN-rate counters over sliding windows; reports LOW single events
  with counters as evidence. **Default disabled**; a calibration page section (Rules
  page) shows live counters only while `calibrate` is on — so the owner tunes thresholds
  with real numbers before turning detection on (C11's "no vendor defaults" resolved the
  honest way).
- **Beaconing heuristic** (`sensors/beacon.py`): inter-arrival coefficient-of-variation
  per (src,dst) for repeated flows over a window; default disabled; same calibration
  approach. Explicitly excluded from total-budget guarantees — if it costs too much on
  the Pi it stays off; measurement task noted.

**Acceptance:** wiring tests, rule-file content tests (no `#` filters, fixed SIDs,
curated IP list correctness), tunnel/beacon heuristics unit-tested with synthetic
packets + defaults verified disabled, gate green, DECISIONS note recorded (§6).

### R8 — Secrets, TLS, budgets, closure

- **Secrets at rest:** `channels` sensitive fields encrypted (AES Fernet) with a key file
  created 0600 by install.sh (path from env, dev-friendly fallback documented). `cryptography`
  is the one new dependency (dual Apache-2.0/BSD; record per C1 before touching code).
  Lazy migration: unencrypted rows are rewritten on read; after migration, plaintext
  check in tests.
- **HTTPS mode implemented:** `self-signed` generates a cert/key via `cryptography` into
  the data dir with sane defaults, configures uvicorn TLS (`web/server.py`), cookie
  Secure flag follows (`deps.py:168`), UI shows the cert fingerprint at creation
  (trust-on-first-use documented). `provided` loads user paths from settings with
  existence/validation errors surfaced in the health page rather than crashing the boot.
- **Resource budgets:** `MemoryMax`, `OOMScoreAdjust` (sensor protected), `CPUQuota`
  values shipped with honest comments "verify on target first Pi run" — the values bound
  runaway while lab verification updates them.
- **Docs/closure:** README/USAGE/INSTALL updated for every user-visible behaviour above
  (in particular: new sensor-down alert, deferred quiet hours, FP button, new detectors
  + their tuning, encrypted-DNS signals, backups location); `docs/BLOCKERS.md` and
  `docs/research/09-open-questions.md` re-truthed (CONFIRMED-ON-LAB prefixes, stale
  "Resolved: none" header fixed); DECISIONS entries for the §6 calls.

**Acceptance:** migration/roundtrip tests; cert generation test; settings-UI e2e;
deploy-artifact tests updated; full gate; final walkthrough on lab (owner) recorded.

## 6. Decisions made (owner-approved direction, recorded here as design calls)

| # | Call | Reason |
|---|---|---|
| D-031 | Hand-rolled sd_notify helper (no sdnotify dep) | ~40 stdlib lines; one less C1 licence row to maintain |
| D-032 | Heartbeat = DB row, not extra IPC | SQLite is already the cross-process spine; no new protocol |
| D-033 | Quiet hours default → defer | Discard permanently hidden real attacks (verified `base.py:204-207`); per-channel opt-out preserved |
| D-034 | Live queue drop-newest accounting | Consistent with notifier queue semantics; both counted into one health metric |
| D-035 | OUI = raw IEEE registry → generated committed CSV, parsed internally | No new runtime dep; data file is the product's; attribution recorded per C1 |
| D-036 | BeVaconing + tunnelling ship **disabled by default** with a calibration surface | C11 "no vendor defaults" is honest as calibration, not hand-tuned guesses; D-026's heuristic-deferral is reopened explicitly by the owner for this phase only |
| D-037 | Local Suricata rules for encrypted-DNS signals (not custom Python DoH detection) | D-017 D-027 intact; reuse of the existing alert ingest path; zero new parser code |
| D-038 | Incident hydration trades one re-announce edge case for state continuity | State loss was catastrophic (silent restart during attack), edge case is one extra alert ever |
| D-039 | Implement self-signed HTTPS (not remove the setting) | The wizard already promises it; promise/behaviour mismatch is a credibility bug |
| D-040 | `cryptography` becomes the single new runtime dependency | One dependency unlocks secrets-at-rest, TLS generation; both A items |

## 7. Left to the builder

- Verify every Scapy API detail against the installed 2.8.0 before use (project
  discipline: facts are checked against installed packages, every time).
- Licence record first for: IEEE OUI data, `cryptography` (+ transitives), any lab
  tooling named in `docs/LAB.md`.
- Exact `suricata.yml` structure/pragmas against Debian trixie's packaged Suricata 8
  (docs.suricata.io; stable 8.0.7 as of 2026-09-15; 7.x EOL) — lab-verify with
  `suricata -T`.
- JA4 availability/type correctness in 8.0.x on Debian before the R7 rules use it
  (feature-flagged; fall back to IP/endpoints-only signatures if absent).
- Index/column choices for the SQL-side alert filters (existing indexes in `db.py:32-125`
  cover `(severity,ts)`, `(type,ts)`; `(state,ts)` added in the migration).
- Migration numbering (schema v2 → v4 across R1/R3/R4) and the lazy-creation fallback
  for web DBs that predate the split service schemas.

## 8. Notes on repo integration

- New docs: `docs/LAB.md`, `scripts/lab/`, `scripts/vendor/`; existing docs updated per R8.
- `docs/PROGRESS.md` gains milestone rows M16–M23 with per-phase acceptance commands.
- `docs/DECISIONS.md` gains D-031…D-040 as they land (the table above is the proposal;
  entries land with the phase that implements them).
- `docs/research/12-licenses.md` gains rows before the first line of dependant code.
- No repo-wide refactors, no dependency upgrades beyond R8's named additions, no commits
  without explicit owner request.

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
| M1 | Walking skeleton (uv, FastAPI, SQLite, fake detector, dashboard) | [x] | `uv run pytest tests/test_skeleton.py -q` → **3 passed**; ruff/pyright clean; live server smoke-tested |
| M2 | Event pipeline (dedup/cooldown/rate-limit/aggregate/global cap) | [x] | `uv run pytest tests/test_pipeline.py -q` → **10 passed**; 10 000-event burst → 1 alert; ruff/pyright clean |
| M3 | ARP spoofing detector (#1) | [x] | `uv run pytest tests/test_arp.py -q` → **14 passed**; gateway-MAC-change alerts, benign re-announcement silent; ruff/pyright clean |
| M4 | DNS spoofing detector (#2) | [x] | `uv run pytest tests/test_dns.py -q` → **15 passed**; forged id, untrusted resolver, conflicting answers detected; CDN/round-robin/TTL-rewrite silent; ruff/pyright clean |
| M5 | DHCP detector (#3) | [x] | `uv run pytest tests/test_dhcp.py -q` → **15 passed**; rogue server, config drift, starvation detected; mesh/boot-storm/renewal silent; ruff/pyright clean |
| M6 | Scan + SYN-flood detector (#4) | [x] | `uv run pytest tests/test_scan_flood.py -q` → **13 passed**; vertical/horizontal scan + SYN flood detected; 25 completed handshakes and bulk downloads silent; ruff/pyright clean |
| M7 | Device inventory (#5) | [ ] | |
| M8 | Capture abstraction + sensor runner + PCAP replay | [ ] | |
| M9 | Suricata integration (#6) | [ ] | |
| M10 | Notifiers (Discord/Telegram/email) | [ ] | |
| M11 | Rules & allowlist UI | [ ] | |
| M12 | Auth + first-run wizard | [ ] | |
| M13 | UI completion (dashboard SSE, alerts, devices, health, settings) | [ ] | |
| M14 | Hardening + install.sh + systemd + docs | [ ] | |

## Evidence log

### M1 — walking skeleton (2026-10-14)

Scaffold: `uv init --package --python 3.13` → `uv python install 3.13` (3.13.16) →
`uv add fastapi uvicorn jinja2 pydantic-settings` + dev `pytest pytest-asyncio ruff pyright httpx`.
Resolved versions match the Phase 1 research: **fastapi 0.143.0, starlette 1.8.0, pydantic 2.14.1,
jinja2 3.1.6, uvicorn 0.54.0**.

```text
$ uv run pytest tests/test_skeleton.py -q
...                                                                      [100%]
3 passed in 0.29s

$ uv run ruff check .            → All checks passed!
$ uv run ruff format --check .   → 14 files already formatted
$ uv run pyright                 → 0 errors, 0 warnings, 0 informations
```

Live smoke test (real server, real HTTP, temp data dir):

```text
$ GILGAMESH_DATA_DIR=/tmp/opencode/gg-smoke uv run gilgamesh-web &
$ curl -s localhost:8080/api/healthz
{"status":"ok"}
$ curl -s localhost:8080/api/events
[{"id":"25d99690...","type":"test","severity":"info","detector":"fake",
  "summary":"hello gilgamesh","details":{"note":"synthetic event ..."},
  "dedup_key":"fake|test|-|-"}]
$ curl -s localhost:8080/   → rendered HTML containing "hello gilgamesh"
```

Storage check on the file that was actually written:

```text
$ sqlite3 gilgamesh.db
journal_mode = wal
busy_timeout = 5000
tables       = ['events', 'schema_version']
event count  = 1
```

**Two corrections made during M1 (both would have been wrong from memory):**

1. **Starlette 1.8.0 deprecates `httpx` for `TestClient`** and raises
   `StarletteDeprecationWarning: ... install httpx2 instead`. `httpx2 2.13.1` was added as a
   dev dependency. (`filterwarnings = ["error"]` in pytest turned the warning into a collection
   error, which is exactly why it was caught.)
2. **Ruff 0.17 formats Python code blocks inside Markdown.** Left alone it would have
   rewritten the quoted code samples inside `docs/research/*.md` — the evidence records.
   Fixed with `extend-exclude = ["docs"]`.

Also resolved: `host = "0.0.0.0"` trips ruff `S104`; kept with an inline explanation of why
it is safe (bridge members hold no IP addresses) rather than muting it silently.

### M2 — event pipeline (2026-10-14)

`src/gilgamesh/pipeline.py`. Five bounded stages in order, with an injected clock so the
time-based behaviour is tested deterministically rather than with sleeps. The pipeline is
pure — it returns a `PipelineResult` and never touches the database, so a storage failure
can never be mistaken for a detection result.

```text
$ uv run pytest tests/test_pipeline.py -q
..........                                                               [100%]
10 passed in 0.14s

$ uv run pytest
.............                                                            [100%]
13 passed in 0.35s

$ uv run ruff check .            → All checks passed!
$ uv run ruff format --check .   → 16 files already formatted
$ uv run pyright                 → 0 errors, 0 warnings, 0 informations
```

Each stage has its own test, plus the two properties that matter most:

| Test | Asserts |
|---|---|
| `test_identical_event_inside_dedup_window_is_deduplicated` | repeat inside 5 s → `DEDUPED` |
| `test_same_attack_after_dedup_window_is_cooled_down` | repeat at 10 s → `COOLDOWNED` |
| `test_per_key_rate_limit_applies` | 3rd event in 60 s → `RATE_LIMITED` |
| `test_global_limiter_caps_alerts_across_keys` | ceiling honoured across *distinct* keys |
| `test_repeats_aggregate_into_the_same_incident` | same incident id, `count == 2` |
| `test_incident_escalates_once_the_threshold_is_reached` | `escalate_at` → re-announce at `CRITICAL` |
| `test_tracked_keys_are_bounded` | 200 distinct keys → `tracked_key_count <= 10` |
| `test_ten_thousand_event_burst_yields_bounded_alerts` | **10 000 events → 1 alert** |

pyright strict also caught `field(default_factory=deque)` inferring `deque[Unknown]`;
fixed by `default_factory=lambda: deque[float]()`.

### M3 — ARP spoofing detector (2026-10-14)

`src/gilgamesh/sensors/arp.py` + `src/gilgamesh/util/net.py`. Scapy 2.8.0 added. Five
detections: `gateway_mac_changed`, `ip_mac_conflict`, `ethernet_source_mismatch`,
`unsolicited_arp_reply`, `gratuitous_arp_flood`.

**Scapy API verified against the installed 2.8.0** rather than from memory:
`ARP` fields are `hwtype, ptype, hwlen, plen, op, hwsrc, psrc, hwdst, pdst`;
`op` is an `int`; `psrc`/`pdst` are `str` subclasses; `ARP in packet` / `packet[ARP]` work.

```text
$ uv run pytest tests/test_arp.py -q
..............                                                           [100%]
14 passed in 0.22s

$ uv run pytest            → 27 passed
$ uv run ruff check .      → All checks passed!
$ uv run ruff format --check . → 20 files already formatted
$ uv run pyright           → 0 errors, 0 warnings, 0 informations
```

Attack caught / benign tolerated pairs (the part that decides whether the tool is usable):

| Attack → detected | Benign → silent |
|---|---|
| gateway advertised from a new MAC → `HIGH` | 20 rounds of normal host↔gateway ARP → silent |
| two MACs claim one IP → `HIGH` | host re-announcing its own IP/MAC (DHCP-renewal shape) → silent |
| Ethernet src ≠ ARP sender → `MEDIUM` | RFC 5227 gratuitous ARPs (5×) → silent |
| reply matching no request → `MEDIUM` | reply to a request seen 0.1 s earlier → silent |
| 26 gratuitous ARPs in 5.2 s → `HIGH` | ARP probes (all-zero sender) → ignored entirely |
| — | packets seen during warm-up → learned, not judged |

Two bugs caught by the tests themselves: a `ether`/`ethernet` typo in `parse_arp`, and a
test helper whose `**overrides` could not override its own `warmup_seconds` default.

**A note on the unsolicited-reply rule.** The first version flagged any reply with no
matching request, which made `test_device_reannouncing_itself_does_not_alert` fail — a
device updating its neighbours is legitimate. The shipped rule only fires when the reply
matches no recent request **and** disagrees with a binding already learned. That guard is
the difference between a detector people trust and one they mute.

### M4 — DNS spoofing detector (2026-10-14)

`src/gilgamesh/sensors/dns.py`. Three detections: `response_without_matching_query`,
`untrusted_resolver`, `conflicting_answers`.

```text
$ uv run pytest tests/test_dns.py -q
...............                                                          [100%]
15 passed in 0.24s

$ uv run pytest            → 42 passed
$ uv run ruff check .      → All checks passed!
$ uv run ruff format --check . → 22 files already formatted
$ uv run pyright           → 0 errors, 0 warnings, 0 informations
```

**Scapy 2.8.0 API correction found by the tests.** `qd`/`an` are now `PacketListField`s —
they are *lists*. Writing `dns.qd.qname` does not fail; it falls through to Scapy's
`__getattr__` shim and raises a `DeprecationWarning` ("use `pkt.an[0]` instead of
`pkt.an`"). Because pytest is configured with `filterwarnings = ["error"]`, the first test
run failed loudly instead of silently parsing garbage. Index access is now used everywhere.

**Two design bugs the tests caught:**

1. *Transaction key included the resolver.* A spoofed reply comes from a different address
   than the query went to, so it could **never** match its query — every forgery also
   reported "no matching query". Worse, a LAN where the router is the resolver would break
   too. The key is now `(client, transaction id)`, which is how DNS identifies a
   transaction anyway.
2. *Unmatched responses are not always attacks.* An unmatched response is flagged only
   when we watched that transaction age out, **or** the client was querying moments ago. A
   client we have never seen querying is silence, because that only means Gilgamesh
   started capturing mid-session.

False-positive guards, each with a test: answers compared on `(name, type, rdata)` with
**TTL excluded** (so TTL rewriting is not a conflict); conflicts counted **per resolver**;
conflicting sets must be **pairwise disjoint** (a CDN returning a superset does not
trip it); entries age out; and the resolver allowlist must be **populated** before anyone
is called untrusted. Round-robin below threshold is silent; three disjoint sets report
`LOW`.

Known limits are documented in the module docstring: **DoH/DoT is invisible** (it never
appears on port 53), and a name genuinely served round-robin from one resolver will
report `conflicting_answers` — owners should raise `conflict_threshold`.

### M5 — DHCP detector (2026-10-14)

`src/gilgamesh/sensors/dhcp.py`. Three detections: `rogue_dhcp_server`,
`dhcp_config_drift`, `dhcp_starvation`.

```text
$ uv run pytest tests/test_dhcp.py -q
...............                                                          [100%]
15 passed in 0.28s

$ uv run pytest            → 57 passed
$ uv run ruff check .      → All checks passed!
$ uv run ruff format --check . → 24 files already formatted
$ uv run pyright           → 0 errors, 0 warnings, 0 informations
```

**Scapy 2.8.0 DHCP facts verified against the installed package:** options are a list of
`(name, value)` tuples (`'message-type'`, `'server_id'`, `'router'`, `'name_server'`, …);
there is **no** `.message_type` attribute; `BOOTP.chaddr` is **bytes**
(`b'aa:bb:cc:00:00:02'`), so it must be decoded before `normalize_mac`.

**A real design flaw the tests caught.** The first version tracked competing servers in a
time window and only reported a rogue once *N distinct servers* had been seen inside it.
That let the attacker's own packet authorise itself: a second server was recorded but,
being the only one in the window, got *learned as trusted*. Replaced with a two-state
rule that needs no window at all:

* nothing trusted yet → the first server to answer is **learned**;
* something trusted already → a different server answering is a **rogue**.

This covers both the configured-allowlist case (pre-seeded, so any other server is
immediately rogue) and the learning case. `test_rogue_server_is_not_learned_as_trusted`
locks the property in. `test_warmup_learns_without_alerting` also proves warm-up can no
longer mask an attack forever.

FP guards: 10 clients booting at once is silent; repeated ACKs from the trusted server
with the same gateway/resolvers are silent; drift is judged only against a learned
baseline and only for options the message actually carries; the DISCOVER-flood window
expires so a burst is not remembered forever.

Out of scope for v1 (D-026): DHCPv6 (546/547), relays, IPv6 RA.

### M6 — scan / SYN-flood detector (2026-10-14)

`src/gilgamesh/sensors/scan_flood.py`. `vertical_port_scan`, `horizontal_port_scan`,
`syn_flood`.

```text
$ uv run pytest tests/test_scan_flood.py -q
.............                                                            [100%]
13 passed in 0.36s
$ uv run pytest → 70 passed · ruff → All checks passed! · pyright → 0 errors
```

**The key false-positive guard: a completed handshake exonerates the port.** The internet
scans a home connection constantly, so alerting per-probe is useless. What separates a
scanner from a busy application is that a scanner's probes *do not complete*. Once a
SYN-ACK is seen for `(source, host, port)` that combination is dropped from the scan
counters. `test_completed_connections_are_not_a_scan` opens 25 ports in sequence with
full handshakes and asserts total silence — each handshake completes before the next SYN
arrives, so the never-established count never climbs.

Also proven silent: 200 data packets of a bulk download (volume alone is never a scan);
8 ordinary browsing sessions; alerts expiring with the window; and remembered
handshakes expiring so a port can be re-probed later.

Bug caught by the tests: `_prune` deleted from `_destination_syns` while iterating it
(`RuntimeError: dictionary changed size during iteration`).

Known limits are in the module docstring — NAT dilutes per-source counts, and a
knocking/service-discovery tool that completes handshakes is not distinguishable.

## Phase 5 — Finish- [ ] `README.md`, `docs/DEMO.md`
- [ ] Clean-room check: `uv sync --frozen` + `uv run pytest` + `uv run ruff check` green
- [ ] Final report

---

## Notes

- Web access confirmed 2026-10-14. Suricata **8.0.7** current stable (2026-09-15); 7.x EOL.
- Every technical claim is backed by a source URL + version in `docs/research/*`, or tagged `UNVERIFIED`.
- All UNVERIFIED/open items live in `docs/research/09-open-questions.md`; hardware-only items in `docs/BLOCKERS.md`.

# Gilgamesh — Progress

**Rule:** read this file FIRST at the start of every turn. Tick a milestone only after its
acceptance command actually ran and passed; paste the command + key output lines here.
**Target:** Raspberry Pi 4 (4 GB), Raspberry Pi OS Lite 64-bit (Debian 13 trixie, Py 3.13).
**Dev machine:** x86_64 Fedora 44 (Py 3.14.8). Project pinned to **Python 3.13**.
**Last updated:** 2026-10-18 (audit pass — see "Phase 6 — Audit")

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
| M7 | Device inventory (#5) | [x] | `uv run pytest tests/test_inventory.py -q` → **11 passed**; new device info/low, randomised MACs downgraded to info, learning period absorbs the boot storm; ruff/pyright clean |
| M8 | Capture abstraction + sensor runner + PCAP replay | [x] | `uv run pytest tests/test_pcap_replay.py -q` → **15 passed**; a recorded ARP-spoof pcap produces a stored alert on a plain dev machine (C10 satisfied); ruff/pyright clean |
| M9 | Suricata integration (#6) | [x] | `uv run pytest tests/test_suricata_ingest.py -q` → **24 passed**; EVE alert → event; rule filters rendered without `#`; ruff/pyright clean |
| M10 | Notifiers (Discord/Telegram/email) | [x] | `uv run pytest tests/test_notifiers.py -q` → **28 passed**; all three channels built, retries/backoff, quiet hours, redaction, bounded queue; no network in tests; ruff/pyright clean |
| M11 | Rules & allowlist UI | [x] | `uv run pytest tests/test_rules.py tests/test_rules_ui.py -q` → **51 passed**; typed bounded params, exact-match allowlist, CSRF on every mutation; verified over real HTTP; ruff/pyright clean |
| M12 | Auth + first-run wizard | [x] | `uv run pytest tests/test_auth.py -q` → **40 passed**; Argon2id, revocable sessions, CSRF, lockout; verified over real HTTP; **built before M11 per D-028** |
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

### M7 — device inventory (2026-10-14)

`src/gilgamesh/sensors/inventory.py`. First-sighting `new_device` event plus the
inventory the Devices page and allowlists read from.

```text
$ uv run pytest tests/test_inventory.py -q
...........                                                            [100%]
11 passed in 0.25s
$ uv run pytest → 81 passed · ruff → All checks passed! · pyright → 0 errors
```

**MAC randomisation is the whole false-positive problem here.** The I/G-adjacent
*locally administered* bit (low bit of the first octet, IEEE 802) marks a per-network
randomised address, so such devices are reported `INFO` and labelled *"likely randomised
device"* rather than `LOW` *"unknown device"*. Trusted devices never alert; the learning
period absorbs the storm when the bridge comes up; the inventory is an LRU bounded by
`max_devices` so a spoofed source sweep cannot exhaust memory (both bounds tested).

**Two bugs found while writing the tests — both worth remembering:**

1. *Operator precedence in my own test helper.* `Ether(...)/IP(...)/b"\x00" * 20` parses as
   `(Ether(...)/IP(...)/b"\x00") * 20` — `/` and `*` have equal precedence and associate
   left to right — which silently produces a **list of twenty packets**. The detector
   correctly rejected the list, so the failure pointed at the detector before the real
   cause was found. Parenthesised now, with a comment.
2. *`aa:`-prefixed test MACs were not globally unique.* `0xAA & 0x02` is set, so every
   `aa:bb:cc:…` address was being classified as randomised. Test constants now use a
   first octet with bits 0 and 1 clear (`00:…`), with the randomised case (`8a:…`) kept
   deliberately.

**One real product gap closed:** a device's address was only learned from IP headers, but
an ARP announcement has no IP header — it is very often the only place a device states
its address. `observe_device` now reads ARP `psrc` as a fallback (ignoring the
`0.0.0.0` of an ARP probe).

Learning-period semantics were also corrected mid-milestone: devices seen during learning
are absorbed permanently and are never retroactively reported as "new".

### M8 — capture abstraction, runner, PCAP replay (2026-10-14)

`sensors/capture.py`, `sensors/runner.py`, `sensors/base.py`. This milestone is what
makes **C10** true: the entire detection stack is exercised on an ordinary Linux box.

```text
$ uv run pytest tests/test_pcap_replay.py -q
...............                                                          [100%]
15 passed in 0.40s
$ uv run pytest → 96 passed · ruff → All checks passed! · pyright → 0 errors
```

`PacketSource` is the abstraction (C8): `PcapSource` replays a file, `LiveSource` wraps
Scapy's `AsyncSniffer` in its own thread with `store=False` and a default BPF
(`arp or (udp port 53) or (udp port 67 or 68) or icmp or icmp6`) that drops payload
traffic in the kernel. The runner cannot tell which one it has. `SensorRunner` fans each
packet out to every detector in isolation, pushes results through the pipeline, and
stores only what survives.

Proven end to end:

* a recorded ARP-spoof pcap → **exactly one** `gateway_mac_changed` alert in SQLite;
* the legitimate reply in the same capture produces **no** alert;
* 200 copies of the poisoning packet collapse to **one** stored event;
* a benign 61-packet capture → **zero** alerts (the false-positive check from the plan);
* a detector that raises on every packet is logged, skipped, and the others continue;
* a corrupt pcap raises `OSError`; a *missing* one yields nothing.

**Bugs found and fixed here:**

1. *Scapy leaks a file descriptor on a corrupt capture.* `PcapReader` opens the file in
   its constructor and leaves it open when header parsing throws. `iter_pcap` now checks
   the 4-byte pcap magic first, which both prevents the leak and gives a better message.
2. *The runner never stamped `interface` on events.* Only the detector's own config could
   set it, and the detector does not know where the packet came from. The runner now
   stamps it, since it is the only component that does.
3. *`Detector` did not declare `process`*, so the runner called a duck-typed attribute.
   Added an explicit `PacketDetector` subclass that declares the capture contract, and
   all five real detectors now implement it.
4. *My dedup test asserted the wrong thing*: the first ARP seen for the gateway
   legitimately *teaches* its MAC, so a capture of only spoofed packets yields no alert.
   The fixture now includes the honest exchange first — which is also the realistic case.

### M9 — Suricata integration (2026-10-14)

`sensors/suricata_ingest.py`. EVE JSON → normalized events; rule filters rendered from
the database.

```text
$ uv run pytest tests/test_suricata_ingest.py -q
........................                                                 [100%]
24 passed in 0.10s
$ uv run pytest → 120 passed · ruff → All checks passed! · pyright → 0 errors
```

**Everything here was verified against upstream sources before writing code**
(all retrieved 2026-10-14), not from memory:

| Fact | Source |
|---|---|
| EVE common fields are `src_ip`, `src_port`, **`dest_ip`**, `dest_port`, `proto`, `in_iface`, `app_proto`, `flow_id` — *not* `dst_ip` | `docs.suricata.io/en/latest/output/eve/eve-json-format.html` |
| `alert` object = `action`, `gid`, `signature_id`, `rev`, `signature`, `category`, `severity`, optional `metadata`/`source`/`target` | same |
| `suricata-update` has **no** `disable-rule`/`enable-rule` command — only source-level ones | its `suricata/update/commands/` tree |
| Per-rule control is via `/etc/suricata/{enable,disable,drop,modify}.conf`, options `--disable-conf=` / `--enable-conf=` | `suricata-update/doc/update.rst`, `doc/quickstart.rst` |
| Filter files accept `gid:sid`, `sid`, `gid:sid:rev`, `re:`, `group:`, `metadata:` | `suricata/update/configs/disable.conf` |
| **`load_filters()` skips every line starting with `#`** — which is why the shipped samples are fully commented out | `suricata/update/main.py` |

That last row is the one I would have got backwards: Gilgamesh therefore renders
`disable.conf` / `enable.conf` directives **without** a `#` prefix, which is asserted by
`test_disable_conf_uses_gid_sid_without_a_hash`.

**Honest UNVERIFIED (recorded as B17).** The EVE docs never state that `severity: 1` is
the *highest*. The examples (1 on a malware C2 signature, 2 on "generic suspicious POST")
are consistent with 1 = highest, so that is the default — but the map lives in an
overridable constructor argument with a test proving it can be inverted, rather than being
hard-coded. Confirm against a real ET Open signature on the Pi.

Security properties tested: non-integer signature ids and out-of-range ids are rejected
by validation (not escaping), so no rule text can ever reach `disable.conf` (D-017); the
reload command is returned as an **argv list**, never a shell string.

Also handled: non-`alert` records (`dns`, `dhcp`, `arp`, `flow`, `http`) are ignored —
Suricata gives facts, Gilgamesh gives verdicts — and an incomplete trailing line is never
parsed, because a live tailer constantly sees half-written records.

### M10 — notifiers (2026-10-14)

`notifiers/{base,discord,telegram,email}.py`. All three channels (D-021). Added
`aiosmtplib` 5.1.3.

```text
$ uv run pytest tests/test_notifiers.py -q
............................                                             [100%]
28 passed
$ uv run pytest → 148 passed in 1.05s · ruff → All checks passed! · pyright → 0 errors
```

**API contracts verified before coding** (2026-10-14):

* **Telegram** — `core.telegram.org/bots/api`: every request is
  `https://api.telegram.org/bot<token>/METHOD_NAME`, HTTPS, GET or POST, parameters as
  query string / urlencoded / JSON. `sendMessage` requires `chat_id` and `text`. The token
  comes from **@BotFather**; the chat id from **@userinfobot** or `getUpdates`.
* **Discord** — `discord.com/developers/docs/resources/webhook`: webhooks post JSON with
  `content` and need no bot. `wait=true` is appended so a rate-limited message produces a
  real non-2xx instead of a misleading `204`.
* **`aiosmtplib.send`** signature checked directly: the parameter is **`use_tls`**, *not*
  `tls` — my first draft passed a parameter that does not exist. `validate_certs`
  defaults to `True` and is now set explicitly, with a comment saying why it stays on.

**Honest UNVERIFIED:** Discord's per-webhook rate limit (widely cited as 5 requests /
5 s) is on a JS-rendered page I could not read. No constant is baked in; throttling is
handled generically via HTTP 429 plus `Retry-After` / `X-RateLimit-*`, recorded as B17-
adjacent in `09-open-questions.md`.

**A real secret leak, found by a test.** `httpx` exception strings embed the request
URL — and for a Discord webhook **the URL is the secret**. Redaction was only applied to
raised exceptions, not to the `error` string a transport *returns*, so a failing request
would have written the webhook token into the log. `deliver()` now redacts every result
unconditionally; `test_errors_are_redacted` locks it in.

**A real behaviour bug, found by the slowest-test report.** A channel with no webhook URL
configured was being retried 4× with exponential backoff — 3.5 seconds wasted on an
error that cannot fix itself. `DeliveryResult.permanent` now short-circuits retries, and
the suite went from 4.5 s to 1.03 s.

Also covered: per-channel minimum severity, quiet hours **including a window that wraps
midnight** (22:00→07:00), message truncation to each provider's limit, Telegram tokens
percent-encoded so a stray `/` cannot move the path segment, Discord `allowed_mentions`
disabled so a scan never pings a human, and a bounded queue that drops the newest alert
rather than growing without limit.

### M12 — auth, sessions, CSRF, first-run wizard (2026-10-14)

`web/auth.py`, rewritten `web/app.py`, four new templates. Added `argon2-cffi`.

```text
$ uv run pytest tests/test_auth.py -q
........................................                                 [100%]
40 passed in 5.93s
$ uv run pytest → 189 passed · ruff → All checks passed! · pyright → 0 errors
```

Live smoke test over real HTTP (curl against a running server):

```text
GET  /                 (anonymous)          → 303 → /setup
POST /setup  password=short                  → 400  (policy enforced)
POST /setup  password=<long passphrase>      → 303  + Set-Cookie gilgamesh_session
     cookie flags                              #HttpOnly_ ... SameSite=lax
GET  /                 (authenticated)       → 200, dashboard shows "hello gilgamesh"
POST /settings  (no CSRF token)              → 403  ← the point of the test
POST /logout                                  → session destroyed
GET  /                 (after logout)        → 303 → /login
```

**Decisions made, with reasons (D-028, D-029, D-030 in `DECISIONS.md`):**

* **Auth was built before M11, inverting the prompt's order.** Every configuration route
  mutates security-relevant state, so building them first would mean committing a window
  where anyone on the LAN can silently disable detection or mute alerts.
* **Sessions are opaque random tokens**, not a signed cookie — revocability is the whole
  point, and signing a value that *is* the secret protects nothing.
* **Argon2id** at `t=3, m=64 MiB, p=4` (D-013), with `check_needs_rehash` available so the
  cost can be raised later. Password policy accepts a ≥ 20-character passphrase *or* ≥ 12
  characters across three character classes — rejecting only "short and simple" pushes
  people towards `Passw0rd!`.
* **Lockout is tracked per account *and* per client address**, so an attacker cannot lock
  a household out of its own box, and one NAT address cannot grind an account forever.

**A hard blocker found by verification — `python-multipart` is unavoidable in Starlette
1.8 (D-030).** D-020 deliberately excluded it (`Apache-2.0` vs `GPL-2.0-only`). Checked
on the installed versions:

* `fastapi/dependencies/utils.py:129` raises *"Form data requires `python-multipart`"* —
  unconditionally, for any route declaring `Form()`.
* `starlette/requests.py:278` asserts `parse_options_header is not None` for **every**
  form body — **including `application/x-www-form-urlencoded`** (confirmed by an ASGI
  round-trip).

So there is no way to read a form without it. Rather than re-open the licence question the
user already answered, Gilgamesh parses the body itself with `urllib.parse.parse_qs` and
refuses anything that is not URL-encoded. Verified working.

**Four bugs caught while wiring this up:**

1. **Dependencies defined inside `create_app` broke silently.** With
   `from __future__ import annotations`, FastAPI re-evaluates `Depends(current_session)`
   in *module* scope; a closure local cannot be resolved, so the dependency degraded into
   a **query parameter** and every route returned a puzzling `422`. Dependencies now live
   at module scope, with the reason documented in the module docstring.
2. **`verify_csrf` never awaited `read_form`** — the coroutine was created and discarded,
   so form-token CSRF checks were silently broken (a `RuntimeWarning` caught it).
3. **Redundant `absolute_expiry` column** meant back-dating a session's `created_ts` did
   nothing, so the absolute timeout was untestable. Validation now derives both limits
   from `created_ts`/`last_seen_ts`.
4. The M1 skeleton tests broke because `/` now requires a session — correct behaviour, so
   those tests were updated to complete the wizard first.

### M11 — detection rules and allowlist (2026-10-14)

`src/gilgamesh/rules.py`, two templates, six routes. 12 built-in rules covering every MVP
detector, plus exact-match allowlists.

```text
$ uv run pytest tests/test_rules.py tests/test_rules_ui.py -q
...................................................                      [100%]
51 passed
$ uv run pytest → 240 passed · ruff → All checks passed! · pyright → 0 errors
```

Live smoke test (curl against a running server):

```text
disable a rule         → "scan.vertical disabled."
threshold 99999        → "Not saved: port_threshold must be at most 200, got 99999"
allowlist DE-AD-BE-…   → added, stored normalised as "de:ad:be:ef:00:01"
POST without CSRF      → 403
```

**D-017 held in practice.** No user regex and no free-text rules, and the module docstring
says why: Python's `re` has no timeout, so a user-supplied pattern is a remote-triggerable
CPU exhaustion on a box whose only job is to stay up. Parameters are typed and bounded
(`int`, `float`, `bool`, `enum` with fixed choices), and allowlist entries match on exact
normalised values — MACs canonicalised, IPs parsed with `ipaddress` — so `.*` is stored as
the four literal characters and matches nothing.

Properties tested rather than assumed: a rejected value leaves the stored state untouched
(partial form saves are impossible), unknown rule ids and unknown parameters are refused
rather than ignored, a suppression is scoped to its rule *and* its source, and a bogus
match field (`regex`) is rejected instead of accepted as free text.

Also fixed while wiring: `Database.execute` returned an `int`, so `remove_suppression`
could not see `rowcount` and could not tell a deleted row from a missing one — it now
returns the cursor. Rules survive a restart because the database is the source of truth
(D-005), which has its own test.

## Phase 5 — Finished

### M13 — UI completion (2026-10-15)
- Split web app into `web/deps.py` + route modules (`auth`, `dashboard`, `alerts`, `rules`, `devices`, `notifications`, `health`, `settings`) with shared dependencies at module scope.
- Added device/channel/preferences/health services and runner device tracking (throttled).
- Created all templates (devices/notifications/health) and wired routes; rebuilt Tailwind CSS assets (vendored).
- Expanded UI tests; SSE test rewritten with ASGI harness.
- All tests pass: 310 passed; ruff clean; pyright 0 errors.

### M14 — Hardening + deploy (2026-10-15)
- Added console scripts (`gilgamesh-sensor`, `gilgamesh-rules-update`) and entrypoint `main()` functions.
- Created `rules_update.py` for update flow.
- Added deploy artifacts: systemd units (web/sensor/rules-update + timer), sysusers.d, tmpfiles.d, logrotate, suricata drop-in.
- Added install.sh (placeholder), README/DEMO stubs, and `tests/test_deploy_artifacts.py`.
- Updated deps: httpx moved to runtime (the notifiers post with it). `httpx2` is **kept**
  as a dev dependency: Starlette 1.8's `TestClient` prefers it and warns — an error under
  `filterwarnings`, see the M1 correction above. The duplicate `httpx` specifier that this
  edit left behind in `pyproject.toml` was removed during the 2026-10-18 audit.
- All tests pass: 311 passed; ruff/pyright clean.

```text
$ uv run pytest -q
........................................................................ [ 92%]
.......................                                                  [100%]
311 passed in 7.37s
$ uv run ruff check .
All checks passed!
$ uv run pyright src
0 errors, 0 warnings, 0 informations
```

### M15 — browser end-to-end suite (2026-10-18)

Permanent Playwright suite as a dev dependency, driving the **system Google Chrome**
(`--browser-channel chrome`, no browser download, no sudo) against the real server:
`tests/e2e/conftest.py` spawns `.venv/bin/gilgamesh-web` on `127.0.0.1` with a temp
`GILGAMESH_DATA_DIR`, waits on `/api/healthz`, and tears the process down.

- Licences recorded per C1 **before** adding: playwright 1.64.0 (Apache-2.0),
  pytest-playwright 0.10.0 (Apache-2.0) — verified against installed metadata — plus
  transitives python-slugify (MIT), pyee (MIT), text-unidecode (Artistic-1.0 OR GPL-2.0+).
- Opt-in design: `e2e` marker; default `addopts` run `-m "not e2e"` so `uv run pytest`
  stays hermetic (311 unit tests, e2e deselected).
- Nine flows: first-run wizard → dashboard, wrong password, sign out/in, dashboard tiles
  + seeded event, rule toggle round-trip, Discord secret saved-but-not-echoed, one-sided
  quiet hours rejected, settings persistence across reload, health page report.

**Bug the suite caught:** the `role="alert"` banner rendered **twice** — Jinja shares
context between `base.html` and page templates, and devices/health/notifications/settings/
suppressions each also rendered the shared `error` flash. Fixed at the root: `base.html`
is now the single render site of `error` (page-level blocks removed; `notice` was already
single-rendered). Playwright's strict mode is the regression guard — a second alert
element fails the test.

```text
$ uv sync --frozen → Checked 46 packages
$ uv run pytest tests/e2e -m e2e --browser-channel chrome
.........                                                                [100%]
9 passed in 7.28s
$ uv run pytest -q
311 passed, 9 deselected in 10.67s
$ uv run ruff format --check . → 69 files already formatted
$ uv run pyright src → 0 errors, 0 warnings, 0 informations
```

### Gate cleanup — ruff and pyright fully quiet (2026-10-18)

The five pre-existing ruff errors and the 44 strict-mode pyright errors (unscoped run,
which includes `tests/`) are fixed at the root — no new suppressions beyond one
documented per-file ignore:

- `rules_update.py`: `contextlib.suppress(OSError)` for the version stamp.
- `runner.py`: the signal handler gets `signum: int, frame: object`.
- `routes/notifications.py`: `_send_test` returns its real type, `DeliveryResult`.
- The SSE test harness in `test_ui_routes.py` was rebuilt around starlette's own typed
  aliases (`starlette.types.ASIGIApp`/`Message`) instead of untyped `dict`/`Queue`
  placeholders, and `_wait_until` uses `asyncio.timeout` (renamed param `window` —
  ASYNC109 bans `timeout` on async defs); the poll loop carries a scoped ASYNC110
  ignore because there is no `Event` to await — cooperative polling is the design.
- `test_pcap_replay.py`: `CountingStore.upsert` mirrors the base signature exactly
  instead of forwarding `**kwargs: object`, dropping the `# type: ignore[override]`.

**Diagnosed en route:** pyright unions `Unknown` into a variable whose initialiser
carries a `type: ignore` (`bus: EventBus = client.app.state.bus  # type: ignore` made
every member access resolve as `int | Unknown`). The honest fix binds from the real
runtime type instead of suppressing a diagnostic: `cast(FastAPI, client.app).state.bus`
— Starlette declares `.state` on the app and `State.__getattr__` is its explicitly
typed escape hatch, so the line needs no ignore at all.

```text
$ uv run pyright        (unscoped: src + tests)   → 0 errors, 0 warnings, 0 informations
$ uv run ruff check .   → All checks passed!
$ uv run ruff format --check .  → 69 files already formatted
$ uv run pytest -q      → 311 passed, 9 deselected in 10.62s
$ uv run pytest tests/e2e -m e2e --browser-channel chrome → 9 passed in 6.56s
```


## Phase 5 — Finish

- [x] `README.md`, `docs/DEMO.md`
- [x] Clean-room check: `uv sync --frozen` + `uv run pytest` + `uv run ruff check` green
- [x] Final report

## Phase 6 — Audit (2026-10-18)

An independent audit of the generated codebase ("is it real, and does it work?"), not a
feature milestone. Every finding below was reproduced before it was fixed, and each fix
carries a regression test.

### What was actually wrong (reproduced, then fixed)

| # | Finding | Evidence it was real | Fix |
|---|---------|----------------------|-----|
| 1 | `sensors/fake.py` shipped a detector that emitted invented events; nothing imported it after the fake seeding was removed | `grep -rn FakeDetector src tests` → only its own file | file deleted (`git rm`); the production pipeline tests already build real packets |
| 2 | Static assets were sent with **no `Cache-Control`**: a browser may keep executing the `app.js` it downloaded before an upgrade | the MCP browser served a stale `app.js` and the console filled with `Alpine Expression Error: Undefined variable: liveFeed`; a fresh context (e2e) was fine | `/static/*` now answers `Cache-Control: no-cache` (Starlette's ETag makes it a 304), and every asset URL carries a content stamp `?v=` (`web/deps.py: asset_version`) |
| 3 | `systemctl stop gilgamesh-web` never completed while a dashboard was open — Uvicorn waits for in-flight request tasks *before* the lifespan shutdown, and an SSE stream never finishes | two web processes were still alive 12 s after SIGTERM and had to be SIGKILLed; the log showed no shutdown line | `timeout_graceful_shutdown=5` in `web/server.py`, with the uvicorn ordering written down; the cancelled stream drops its subscription in the generator's `finally` |
| 4 | Three templates rendered as raw HTML (sign-in, first-run setup, allowlist) and controls on alerts/rules/notifications were unstyled | screenshot of `/setup` vs `/settings`; `grep -c 'class="' login.html` → 0 | all four files restyled with the app's vocabulary, `app.css` rebuilt, regression test scans every template for a control without a class |

### Evidence — the gate, run on the final tree

```text
$ uv sync --frozen                     → Checked 46 packages in 1ms
$ uv run ruff check .                  → All checks passed!
$ uv run ruff format --check .         → 77 files already formatted
$ uv run pyright                       → 0 errors, 0 warnings, 0 informations
$ uv run pytest                        → 380 passed, 13 deselected in 17.65s
$ uv run pytest tests/e2e -m e2e --browser-channel chrome
.............                                                       [100%]
13 passed
```

New test files added by the audit: `test_gate.py`, `test_delivery.py`,
`test_runner_wiring.py`, `test_rules_update.py`, `test_suricata_ingest.py`,
`test_deploy_artifacts.py`, `test_rules_ui.py`; the e2e file grew to 13 flows (htmx toggle
without a reload, Alpine pause/resume with buffering, no CSP violations, and the server
exiting promptly on SIGTERM with a dashboard open).

### Evidence — the detectors, end to end, without the Pi (C10)

A capture is built with Scapy and replayed through the real sensor into a real database;
the alerts below are the real output of the real detectors.

```text
$ GILGAMESH_DATA_DIR=/tmp/opencode/gg-demo GILGAMESH_PCAP=/tmp/opencode/gg-demo/demo-capture.pcap \
  GILGAMESH_GATEWAY_IP=192.168.1.1 uv run gilgamesh-sensor
sensor started: replay capture from pcap file /tmp/opencode/gg-demo/demo-capture.pcap
stored high event from dns: response without matching query for mybank.example (id 1) from 9.9.9.9
stored medium event from scan_flood: 192.168.1.66 probed 21 ports on 192.168.1.20 without completing a handshake
stored high event from scan_flood: 101 SYNs from 192.168.1.30 to 192.168.1.20 within 1s
replay finished: 191 packets processed
```

The ARP and DHCP detectors stayed silent on purpose: both hold a five-minute warm-up
(`arp.py`, `dhcp.py`), which a replay finishes long before. That is the documented
anti-false-positive design, not a broken detector — the unit tests cover them with an
explicit clock. It is listed in `docs/BLOCKERS.md` as a Pi-only item to observe.

Two guest devices were then replayed after setting *New device → Learning period* to `0`
**in the Rules page**, which proves the UI → sensor parameter path with no code change:

```text
stored low event from inventory: New device 00:11:22:33:44:11 seen on the network
stored low event from inventory: New device 00:11:22:33:44:12 seen on the network
```

### Frontend pass (Playwright MCP, real server, real browser)

Walked every page with a real browser against the running instance and exercised the
interactive parts:

- htmx rule toggle: clicked "Disable" on *IP/MAC conflict* — the URL stayed `/rules`, the
  control flipped to *Enable · off*, and the swapped control still responded.
- Alpine live feed: pressed **Pause live feed** (state → *Paused*, button → *Resume live
  feed*), replayed another new device while paused (counter → *+1 while paused*), then
  resumed and watched it flush into the feed.
- Console: **0 errors, 0 warnings** across the whole tour — no CSP violations from the
  inline-free markup (`style-src 'self'` would catch a stray `x-show`).
- A Discord webhook was saved and the page then showed *configured* with the field masked
  (*"•••• saved — leave blank to keep"*) — secrets are never echoed back.

### Documentation corrected in this pass

- `README.md`: real *Install (Raspberry Pi)*, *Development*, and *Uninstalling* sections —
  `install.sh` printed "Uninstall see the README" against a README that had no such section.
- `docs/DEMO.md`: rewritten from a 5-line stub into two runnable demos (laptop replay, Pi
  live) plus the safety rule that attack traffic belongs to an isolated lab.
- `docs/PLAN.md`: layout now matches the repository (`journald/` + `gilgamesh.env.example`
  instead of the dropped `tmpfiles.d/` and `logrotate/`); the resource-budget line explains
  why logrotate was dropped.
- `docs/BLOCKERS.md`: the four things this audit cannot verify without the target hardware.

---

## Notes

- Web access confirmed 2026-10-14. Suricata **8.0.7** current stable (2026-09-15); 7.x EOL.
- Every technical claim is backed by a source URL + version in `docs/research/*`, or tagged `UNVERIFIED`.
- All UNVERIFIED/open items live in `docs/research/09-open-questions.md`; hardware-only items in `docs/BLOCKERS.md`.

# 04 — Architecture

**Scope:** components, the event pipeline, Scapy/raw-packet capture performance, SQLite WAL storage, SD-card wear, notifiers, privilege separation + systemd hardening, RAM/CPU budget, and Suricata runtime reload.
**Rule for this file:** every config key, API name and systemd directive below is cited against official docs. Anything I could not verify is marked `UNVERIFIED` and repeated in the [Open questions](#open-questions--unverified) section.
**Related decisions:** D-004 (normalized event model), D-005 (SQLite = source of truth), D-006 (privilege separation).

---

## 1. Component overview

Gilgamesh is split into a **privileged capture tier** (needs packet sockets) and an **unprivileged application tier** (web UI, DB, notifiers). The two communicate only through the database (SQLite WAL) and a Unix domain socket for control commands. Nothing in the capture tier serves HTTP; nothing in the web tier holds raw-packet capabilities.

| Component | Role | Privilege | Talks to |
|---|---|---|---|
| **Sensor A — Suricata** | Signature IDS, EVE JSON alerts | own systemd unit (see §7) | writes `eve.json`; receives reload commands |
| **Sensor B — `gilgamesh-sensor`** | Python custom detectors (ARP/DNS/DHCP/scan/flood/device inventory) | unprivileged user + `CAP_NET_RAW`, `CAP_NET_ADMIN` | writes normalized events to SQLite; Unix socket |
| **Pipeline / engine** | Normalize → dedup/cooldown/rate-limit/aggregate → persist → enqueue notifications | unprivileged (same process as web app or its own unit) | SQLite; notifier queue |
| **Storage** | SQLite (WAL) — events, incidents, devices, config, secrets | file perms `0600`, dir `0700` | read/write by app tier, write by sensor |
| **Notifiers** | Discord / Telegram / SMTP workers, async, retrying | unprivileged | outbound HTTPS/SMTP |
| **Web app** | FastAPI + Jinja2 + htmx + Alpine + Tailwind; the ONLY user interface | unprivileged, hardened unit | SQLite, sensor Unix socket, SSE to browser |
| **Config model** | DB is the source of truth; engine config (Suricata overrides, thresholds) is **rendered** from it and applied live | unprivileged writer; privileged apply helper | SQLite → rendered files → reload |

### 1.1 Data flow

```
            br0 (inline bridge)  ──┐
                                   │
   ┌───────────────┐   AF_PACKET   │   ┌───────────────────────────────┐
   │ Suricata      │◀──────────────┼──▶│ gilgamesh-sensor (CAP_NET_RAW) │
   │ (Sensor A)    │  ring buffer  │   │ Scapy AsyncSniffer (store=False)│
   └───────┬───────┘               │   │  ├ ARP detector                 │
           │ eve.json (EVE JSON)   │   │  ├ DNS detector                 │
           ▼                       │   │  ├ DHCP detector                │
   ┌───────────────┐               │   │  ├ scan/flood detector          │
   │ eve tailer    │───────────────┘   │  └ device inventory             │
   └───────┬───────┘                    └───────────────┬────────────────┘
           │ normalize (pydantic v2)                     │ normalize
           └───────────────────┬─────────────────────────┘
                               ▼
                 ┌──────────────────────────────┐
                 │ Pipeline: dedup → cooldown →  │
                 │ rate-limit → aggregate        │
                 └───────┬───────────────┬───────┘
                         ▼               ▼
                 ┌──────────────┐  ┌───────────────────┐
                 │ SQLite (WAL) │  │ Notifier queue    │
                 │ events/incid.│  │ (asyncio.Queue)   │
                 └──────┬───────┘  └────────┬──────────┘
                        │                   ▼
                        │        ┌────────────────────────┐
                        └───────▶│ Discord / Telegram /    │
                                 │ SMTP workers (httpx)    │
                                 └────────────────────────┘
                        ▲
                ┌───────┴────────┐
                │ FastAPI web UI │  (SSE live feed, config, rules)
                └────────────────┘
```

**Design rules**

- Suricata and Sensor B both write to the **same** normalized shape (D-004) so the pipeline is engine-agnostic.
- The pipeline never blocks on the network: notifier work is pushed onto a queue and drained by async workers (§6).
- The web app must never require root and never opens a packet socket.

**Sources:** [1][2][3][4] (see [Sources](#sources)).

---

## 2. Event pipeline

### 2.1 Normalized event model (pydantic v2)

One model for every detector, per D-004. Pydantic v2 is what current FastAPI expects (covered in doc 05); this doc only fixes the schema.

| Field | Type | Notes |
|---|---|---|
| `id` | `str` (UUIDv7 or ULID) | time-ordered, primary key; sortable by insertion time |
| `timestamp` | `datetime` (aware, UTC) | event time from source; store as ISO-8601 UTC |
| `type` | `str` (enum) | e.g. `arp_spoof`, `dns_spoof`, `rogue_dhcp`, `dhcp_starvation`, `port_scan`, `syn_flood`, `new_device`, `suricata_signature` |
| `severity` | `str` (enum) | `info < low < medium < high < critical` |
| `src_mac` / `src_ip` | `str \| None` | source L2/L3 |
| `dst_mac` / `dst_ip` | `str \| None` | destination L2/L3 |
| `interface` | `str` | capture interface (e.g. `br0`) |
| `summary` | `str` | one-line human-readable evidence |
| `details` | `dict` (JSON) | raw detector evidence / full EVE JSON body |
| `detector` | `str` | `suricata` or `gilgamesh.arp` etc. |
| `dedup_key` | `str` | derived signature (see §2.2), indexed |
| `count` | `int` | ≥1; increased by aggregation |
| `first_seen` / `last_seen` | `datetime` | aggregation window bounds |

`details` is stored as TEXT containing JSON (`json.dumps`, sorted keys). MAC addresses normalized to lowercase `aa:bb:cc:dd:ee:ff`; IPs stored as text (SQLite has no IP type) — see §4.

### 2.2 Dedup, cooldown, rate-limit, aggregation

The goal (PROMPT §3.3): one attack must not generate 5,000 alerts. Four mechanisms, applied in order, all keyed on a **dedup key**:

```
dedup_key = f"{type}|{detector}|{src_key}|{dst_key}|{signature}"
# src_key/dst_key = MAC if present else IP else "-"
# signature = detector-specific discriminator
#   arp_spoof → spoofed IP + claimed MAC
#   dns_spoof → query name + resolver + answer
#   port_scan → scan type + target
#   suricata_signature → signature id (sid)
```

**Mechanism 1 — exact dedup (short window).** Identical `dedup_key` within `DEDUP_WINDOW` seconds (default **5 s**) is dropped entirely (not counted).

**Mechanism 2 — cooldown gate.** After an event is *notified*, further events with the same `dedup_key` are suppressed until `COOLDOWN_SECONDS` (default **300 s / 5 min**) elapse, **unless severity increases** (an escalated severity bypasses the cooldown). Suppressed events still increment the aggregate counter (§ mechanism 4) so nothing is lost.

**Mechanism 3 — sliding-window rate limit (token bucket).** Per `dedup_key`, a token bucket bounds notifications:

```
capacity C  = RATE_MAX          (default 5 notifications per key)
window W    = RATE_WINDOW_SECS  (default 60 s)
refill r    = C / W             (5/60 ≈ 0.0833 tokens/s)

on event for key k:
    now = monotonic()
    tokens[k] = min(C, tokens[k] + (now - last[k]) * r)
    last[k] = now
    if tokens[k] >= 1:
        tokens[k] -= 1
        emit notification
    else:
        suppressed[k] += 1        # goes into aggregation digest
```

A bucket for a key is evicted when `now - last[k] > W` and `suppressed[k] == 0` (bounded memory: prune an LRU dict above e.g. 10,000 keys).

**Mechanism 4 — aggregation / incident rollup.** Instead of emitting one row per suppressed event, the pipeline maintains an **incident** row per `dedup_key`:

- First qualifying event (after failed dedup/cooldown/rate-limit) creates an incident and sets `first_seen`.
- Every subsequent event with the same key within `AGG_WINDOW` (default **900 s / 15 min**) increments `count` and updates `last_seen`; `details` keeps the last (or a small sample of) raw payload(s).
- When the window closes, the incident is finalised (no more increments) and a **digest notification** ("N more `<type>` events suppressed in the last 15 min") may be sent subject to the global limiter.
- Severity escalation rule: if `count` crosses `ESCALATE_AT` (default **50**) within the window, bump severity one level (capped at `critical`) and send an escalation notification (bypasses cooldown).

**Global notifier limiter.** A process-wide token bucket bounded to `GLOBAL_RATE_MAX` (default **10 notifications/minute**) across all keys/channels prevents an alert storm from itself becoming a DoS on Discord/Telegram/SMTP. Exceeding it queues a digest rather than a per-event message.

**Tunable defaults (single table)**

| Setting | Default | Purpose |
|---|---|---|
| `DEDUP_WINDOW` | 5 s | drop byte-identical repeats |
| `COOLDOWN_SECONDS` | 300 s | quiet period per key after a notify |
| `RATE_MAX` / `RATE_WINDOW_SECS` | 5 / 60 s | per-key token bucket |
| `AGG_WINDOW` | 900 s | incident rollup window |
| `ESCALATE_AT` | 50 | count → severity bump |
| `GLOBAL_RATE_MAX` | 10 / min | storm safety valve |
| `MAX_TRACKED_KEYS` | 10,000 | LRU cap on in-memory state |

All of these are per-rule overridable from the DB (source of truth, D-005). Defaults are first-pass engineering choices to be tuned in build; the *algorithm* is the deliverable here.

**Sources:** [5] (OPS/queue), [6] (Python `deque`/`time.monotonic` stdlib).

---

## 3. Sensor B — Scapy / raw `AF_PACKET` performance on a Pi 4

### 3.1 What is verified

- Scapy's `sniff()` **blocks**, and `AsyncSniffer` runs capture in its own thread — this is why the sniffer must **never** run inside the asyncio event loop (PROMPT §4 pitfall). `sniff()`/`AsyncSniffer` accept `store=False`, `prn`, `iface`, `opened_socket`, `L2socket`, `offline` ([Scapy `sendrecv` API](https://scapy.readthedocs.io/en/stable/api/scapy.sendrecv.html)).
- `store=False` means Scapy does **not** accumulate packets in the `results` list, which is the single biggest memory/CPU win for long-running capture.
- A Linux **`AF_PACKET`** raw socket is created with `socket(AF_PACKET, socket_type, protocol)` and is the mechanism Scapy uses for L2 capture ([packet(7)](https://manpages.debian.org/bookworm/manpages/packet.7.en.html)).
- `CAP_NET_RAW` is exactly "Use RAW and PACKET sockets; bind to any address for transparent proxying." ([capabilities(7)](https://manpages.debian.org/bookworm/manpages/capabilities.7.en.html)). So Sensor B needs **only** `CAP_NET_RAW` for capture; `CAP_NET_ADMIN` is only needed if we also configure interfaces (e.g. offload/`ethtool`), which we will avoid in the sensor.

### 3.2 Performance ceiling — `UNVERIFIED`

**No official, measured "Scapy on Raspberry Pi 4 packets/second" figure exists.** I could not find one from Suricata, Scapy, Raspberry Pi, or Python docs. Any number would be a guess, so:

- **`UNVERIFIED`: maximum sustainable Scapy packet rate on a Pi 4.** Must be benchmarked on real hardware in Phase 2 before choosing filters and thresholds.
- **Engineering consequence:** we must (a) push as much filtering as possible into the **kernel** with a BPF filter (Chebyshev/`tcpdump`-style expression), (b) only hand Scapy the traffic it actually needs, and (c) design for graceful load-shedding (§3.4) rather than assume a fixed budget.

**Design that minimises Scapy load**

1. **Kernel-level BPF filter first.** Use a narrow BPF expression so the kernel drops irrelevant traffic before it ever reaches Python. Detector-specific expressions, e.g.:
   - ARP: `arp`
   - DHCPv4: `udp and (port 67 or port 68)`
   - DNS: `udp port 53 or tcp port 53`
   - NDP/RA (Later): `icmp6`
   Rather than one `prn` callback doing all protocol dispatch in Python, run **separate sniffers with separate BPF filters** (ARP is low volume; DNS/DHCP are moderate).
2. **`store=False`** on every sniffer.
3. **Separate process from the web app.** Run the sensor as its own systemd unit with its own CPU/IO budget; a Scapy stall must never block the UI or the notifier.
4. **Scapy in a dedicated thread** (via `AsyncSniffer`, which is thread-based) inside the sensor process; the sensor's own control/health loop is asyncio. Capture thread ↔ asyncio hand-off via a bounded `queue.Queue` / `asyncio.Queue` with `put_nowait` + drop-on-full (backpressure).
5. **Prefer structured decoding paths.** Use Scapy layers only for the protocols needed; avoid full `pkt.show()` and avoid keeping last-N packet buffers.

### 3.3 AF_PACKET fallback

If profiling shows Scapy's Python object construction is the bottleneck, fall back to a **raw `AF_PACKET` socket** (`socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`) reading into fixed buffers, attaching an in-kernel BPF program (`SO_ATTACH_FILTER`), and parsing only the minimum bytes needed for the ARP/DNS/DHCP/scan detectors. This keeps `CAP_NET_RAW` as the only capability and removes most per-packet Python object overhead. Scapy then remains only as a parser for the specific frames we keep (or is dropped entirely for hot paths).

### 3.4 Graceful degradation when overloaded

The box must never "degrade the user's internet connection" (PROMPT §2 scope). Therefore:

- **Never inline-drop.** We are detect-only; capture must not affect forwarding.
- **Measure first.** Sensor tracks kernel `PACKET_STATISTICS`/`SOL_PACKET` drop counters and its own bounded-queue depth. **`UNVERIFIED`: exact `getsockopt` details for per-socket drop counters** — verify in build.
- **Load-shedding ladder** (automatic, logged, surfaced in the UI health page):
  1. Narrow BPF filters (drop the least valuable protocols first, keep ARP/DNS).
  2. Increase `snaplen` reduction (capture only headers, e.g. 96–128 bytes) — reduces copy cost.
  3. Disable the most expensive detector(s) temporarily (e.g. full port-scan state tracking).
  4. Raise a `sensor_overload` operational event (severity `high`) so the user knows custom detection is degraded while Suricata continues.
- **Health metric:** expose dropped-packet ratio and queue depth; alert when drop ratio exceeds a threshold (default **1 %** over 60 s).

**Sources:** [7] (Scapy API), [8] (packet(7)), [9] (capabilities(7)).

---

## 4. Storage — SQLite in WAL mode

### 4.1 Verified facts

- **WAL** is available since SQLite **3.7.0** and provides: faster operation in most scenarios, **more concurrency (readers do not block writers and a writer does not block readers)**, more **sequential** disk I/O, and **many fewer `fsync()`** operations. A key limitation: *all processes using the database must be on the same host* — fine, since sensor and web app are co-located ([sqlite.org/wal.html](https://sqlite.org/wal.html)).
- Enable with `PRAGMA journal_mode=WAL`.
- `PRAGMA synchronous` accepts `0|OFF|1|NORMAL|2|FULL|3|EXTRA`; **EXTRA** is FULL plus a directory sync after journal unlink; **FULL** uses the VFS `xSync()` ([pragma.html#synchronous](https://sqlite.org/pragma.html#pragma_synchronous)).
- `PRAGMA wal_autocheckpoint=N`: a checkpoint runs automatically once the WAL reaches **N pages**; set `N` to 0 or negative to disable auto-checkpointing ([pragma.html#wal_autocheckpoint](https://sqlite.org/pragma.html#pragma_wal_autocheckpoint)).
- `PRAGMA journal_size_limit=N` bounds the leftover rollback-journal size ([pragma.html#journal_size_limit](https://sqlite.org/pragma.html#pragma_journal_size_limit)).

**Recommended connection setup**

```sql
PRAGMA journal_mode = WAL;        -- enable WAL
PRAGMA synchronous  = NORMAL;     -- crash-safe for WAL, far fewer fsync than FULL
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;       -- ms; wait rather than fail on brief writer lock
PRAGMA wal_autocheckpoint = 1000; -- ~4 MiB WAL at 4 KiB pages, then checkpoint
PRAGMA journal_size_limit = 67108864; -- cap leftover journal at 64 MiB
```

Rationale for `synchronous=NORMAL`: in WAL mode it is durable across application crashes and only risks the most recent transactions on a power loss — an acceptable trade for an alert store, and it materially cuts write amplification on SD cards (§5).

**Design consequence (SD wear):** reader/writer concurrency from WAL lets the sensor write while the web app reads without blocking, but *every* write still dirties a page. Keep the write rate low by (a) not persisting suppressed/dropped events (only incidents + first events), (b) batching inserts in transactions, and (c) periodic `PRAGMA wal_checkpoint(TRUNCATE)` + `PRAGMA incremental_vacuum` (or `optimize`) during the pruning job.

### 4.2 Schema (tables)

| Table | Key columns | Purpose |
|---|---|---|
| `events` | `id`, `ts`, `type`, `severity`, `src_mac`, `src_ip`, `dst_mac`, `dst_ip`, `interface`, `detector`, `summary`, `details_json`, `dedup_key`, `acknowledged`, `false_positive` | canonical normalized events (§2.1) |
| `incidents` | `id`, `dedup_key`, `type`, `severity`, `count`, `first_seen`, `last_seen`, `state`, `sample_details_json` | aggregation rollups (§2.2) |
| `devices` | `mac`, `first_seen`, `last_seen`, `vendor`, `hostname`, `trusted` (0/1), `label` | device inventory / trust state |
| `bindings` | `ip`, `mac`, `first_seen`, `last_seen`, `trusted` | IP↔MAC observations for ARP/DNS detection + allowlists |
| `rules` | `id`, `type`, `enabled`, `severity`, `thresholds_json`, `updated_at` | per-detector enable/threshold config |
| `notifier_channels` | `id`, `kind` (`discord`/`telegram`/`smtp`), `enabled`, `min_severity`, `config_encrypted`, `updated_at` | channel config; secrets encrypted at rest |
| `settings` | `key`, `value_json` | global settings (retention, network mode, HTTPS) |
| `audit_log` | `id`, `ts`, `actor`, `action`, `details_json` | config changes / logins |
| `schema_version` | `version` | migrations |

Indexes: `events(ts)`, `events(type)`, `events(severity)`, `events(dedup_key)`, `incidents(state, last_seen)`, `devices(mac)`, `bindings(ip)`.

IP/MAC columns are `TEXT`. To avoid string-comparison pitfalls, normalize (lowercase MAC, canonical IP) at write time; optionally add generated integer columns for range queries. **`UNVERIFIED`: whether to use SQLite generated columns vs plain text for IP prefix queries** — decide in build with a benchmark.

### 4.3 Retention & pruning

Two independent caps; whichever triggers first wins:

| Policy | Default |
|---|---|
| Age cap | delete `events` older than **30 days** (configurable in UI) |
| Row cap | keep at most **500,000** events; delete oldest beyond it |
| Incident cap | keep **100,000** incidents or 180 days |
| Prune schedule | hourly systemd timer (or an in-app asyncio task) |
| Space reclaim | `PRAGMA wal_checkpoint(TRUNCATE)` after prune; `VACUUM` (or `incremental_vacuum`) weekly off-peak |

Pruning uses indexed range deletes (`DELETE FROM events WHERE ts < ?`), run in bounded batches (e.g. 5,000 rows per transaction) to avoid long write locks and to spread SD writes. **`UNVERIFIED`: exact batch size that avoids UI-visible latency on a Pi 4** — tune in build.

**Sources:** [10] (WAL), [11] (pragma).

---

## 5. SD-card wear mitigation

The Pi 4 boots from microSD by default; SD cards are the least durable part of the box. Raspberry Pi's own SD-card page states: Raspberry Pi cards carry Speed Class ratings **C10, U3, V30, A2**, and — measured with 4 KiB random data — a **Pi 4** over **DDR50** reaches **3,200 IOPS read / 1,200 IOPS write** ([SD Cards doc](https://www.raspberrypi.com/documentation/accessories/sd-cards.html)). That write IOPS figure is the reason we minimise writes: an always-on IDS that fsyncs per alert will chew through those cycles.

**Mitigations (in order of impact)**

1. **Reduce fsyncs at the application layer.** `PRAGMA synchronous=NORMAL` + WAL (fewer `fsync()` per sqlite.org/wal.html); batch writes; do not persist suppressed events (§2, §4).
2. **Cap and rotate logs.**
   - Suricata EVE: use `outputs: - eve-log:` with a time-rotated `filename` and `rotate-interval` (values `minute`/`hour`/`day`) so files stay small ([EVE JSON output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)).
   - `journald`: "systemd-journald will automatically remove the oldest archived journal files to limit disk use" via `SystemMaxUse=` and related `journald.conf(5)` settings ([systemd-journald.service(8)](https://manpages.debian.org/bookworm/systemd/systemd-journald.service.8.en.html)). Set a modest `SystemMaxUse=` (e.g. 100–200 MiB) so logs can't grow unbounded.
3. **tmpfs for transient data.** Put scratch/derived files (rendered config staging, PID/runtime files, the notification spool) under `/run` (tmpfs) using systemd `RuntimeDirectory=`; systemd treats `/run` as a tmpfs API filesystem ([systemd.exec(5)](https://manpages.debian.org/bookworm/systemd/systemd.exec.5.en.html), `MountAPIVFS=`).
4. **Mount options.** Add `noatime` (and consider `commit=`/`nodiratime`) to the root/data mount in `/etc/fstab` to stop metadata writes just for reads. **`UNVERIFIED`: Raspberry Pi / Debian does not publish an official `noatime` recommendation for Pi OS** — this is standard Linux practice (see `mount(8)`); treat the exact fstab line as build-time work, verified against that system's `fstab`.
5. **Strongest option: boot from USB SSD.** Raspberry Pi documents USB mass-storage boot as available since **Pi 2B v1.2** (and on Compute Module/Zero series), noting power requirements for USB SSDs ([Raspberry Pi boot modes — USB mass storage boot](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#usb-mass-storage-boot)). Booting from an SSD (or using an SSD for `/var` + the database) removes SD-card wear almost entirely.
6. **Don't over-engineer.** Do **not** aggressively remount `/` read-only on v1: it complicates first-run setup, rule updates, and recovery, and the fs is needed writable for the DB. Prefer (1)–(3) first, offer (5) as the recommended deployment.

**Sources:** [12] (SD cards), [13] (journald), [14] (USB boot), [15] (systemd.exec).

---

## 6. Notifiers

Three channels: **Discord webhook**, **Telegram Bot API**, **SMTP email**. All run in **async workers** inside the unprivileged app tier, fed by an `asyncio.Queue`. The detection pipeline only does `queue.put_nowait(event_or_incident)` — it never awaits a network call, so a dead channel cannot stall detection.

### 6.1 Verified API/config facts

**Discord (Incoming Webhook).** Execute endpoint: `POST /webhooks/{webhook.id}/{webhook.token}`. Query param `wait` (boolean, default `false`) — "waits for server confirmation of message send before response, and returns the created message body". When `wait=false` and the message is not saved, no error is returned; response is a message or `204 No Content` depending on `wait`. You **must** supply at least one of `content`, `embeds`, `components`, `file`, or `poll`. `content` ≤ **2000** characters; `embeds` is an array of **up to 10** embed objects; `username`, `avatar_url`, `tts`, `allowed_mentions` are optional. Discord warns that it may strip certain characters, and recommends sanitising user-generated content and setting `allowed_mentions` ([Discord Webhook resource](https://discord.com/developers/docs/resources/webhook#execute-webhook)). → We use `wait=true` for the **test-message** action (to surface real errors) and `wait=false` for live alerts (fire-and-forget).

**Telegram Bot API.** Base URL `https://api.telegram.org/bot<token>/METHOD_NAME`. `sendMessage` params: `chat_id` (required), `text` (required, **1–4096 characters**), plus optional `parse_mode`, `link_preview_options`, etc.; supports GET and POST ([Telegram Bot API](https://core.telegram.org/bots/api#sendmessage)). → Alerts longer than 4096 chars must be truncated/split.

**SMTP.** Python's `smtplib` provides `SMTP`, `SMTP_SSL`, and `starttls()`; combine with the `email` package to build messages ([smtplib docs](https://docs.python.org/3/library/smtplib.html)). → Support both implicit TLS (`SMTP_SSL`, port 465) and STARTTLS (port 587).

### 6.2 Delivery semantics

- **Worker pool.** One async task per enabled channel, each with its own bounded queue. On `queue.Full`, drop the *oldest* and increment a `notifier_backlog_dropped` counter (never block capture).
- **Retries with exponential backoff + jitter.** For transient failures (network error, HTTP 429/5xx, SMTP 4xx), retry up to **N=5** attempts with delays `base * 2^attempt` capped at **≤ 300 s**, plus full jitter. Respect `Retry-After` when present (Discord/Telegram). Honour Discord 429 rate-limit headers. Non-retryable failures (HTTP 400/401/403, SMTP 5xx) are logged as a channel health error and not retried.
- **Per-channel minimum severity.** Each channel stores `min_severity`; events below it are never queued for that channel. Defaults: Discord `low`, Telegram `medium`, SMTP `high` (user-adjustable).
- **Test-message action.** A "Send test" button per channel renders a canned payload and (for Discord) uses `wait=true` so the UI can show the real HTTP status and body. **`UNVERIFIED`: exact Telegram/Discord/SMTP error-body shapes for clean UI messages** — model in build.
- **Quiet hours / digest.** Optional suppressed-hours window; during it, events are aggregated and a single digest is sent at the end (reuses the incident rollup from §2).

### 6.3 Secret hygiene

- Channel secrets (Discord webhook URL/token, Telegram bot token, SMTP password) are stored **encrypted at rest** in `notifier_channels.config_encrypted`; the DB file is `0600`, its directory `0700` (see §7 `StateDirectory=`/`UMask=`).
- **Never log secrets.** Notifier log lines carry only channel kind, id, status code, and latency. A redaction helper masks tokens before any exception string is emitted.
- Secrets are supplied/rotated via the UI only; environment variables are an alternative for headless provisioning. Redact query strings in any diagnostic output (Telegram tokens live in the URL path — a real leak risk).
- Outbound calls use `httpx` (async) with **explicit timeouts**; TLS verification stays on. (httpx is the recommended async client for FastAPI; verified in doc 05.)

**Sources:** [16] (Discord), [17] (Telegram), [18] (smtplib).

---

## 7. Privilege separation & systemd hardening

**Split (D-006):** privileged capture, unprivileged application. Suricata has its own upstream-recommended service; our `gilgamesh-sensor` needs packet sockets; the web app must run as an unprivileged user with no packet access.

### 7.1 Capabilities

- Sensor: `AmbientCapabilities=CAP_NET_RAW` is sufficient for raw/packet capture (`CAP_NET_RAW` = "Use RAW and PACKET sockets; bind to any address for transparent proxying"). Add `CAP_NET_ADMIN` **only** when the sensor must touch interface state (e.g. offload/ethtool); prefer to keep it out.
- Web app: **no** capabilities.
- Current docs recommend `CapabilityBoundingSet=` to drop everything not needed and `AmbientCapabilities=` to keep a capability for a non-root process (systemd automatically adds `keep-caps` to `SecureBits=` in that case).

### 7.2 Verified systemd directives (systemd 252.36-1~deb12u1, Debian bookworm)

All of the following are documented in [systemd.exec(5)](https://manpages.debian.org/bookworm/systemd/systemd.exec.5.en.html):

| Directive | Verified behaviour (short) |
|---|---|
| `User=` / `Group=` | run as an unprivileged user/group |
| `DynamicUser=` | allocate a transient user; *implies* `NoNewPrivileges=`, `RestrictSUIDSGID=`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=`, `RemoveIPC=` |
| `CapabilityBoundingSet=` | restrict the capability bounding set (`~` prefix inverts) |
| `AmbientCapabilities=` | keep listed capabilities for a non-root process |
| `NoNewPrivileges=` | no privilege gain via `execve()` |
| `ProtectSystem=` | `true`/`full`/`strict` — mounts system (or all) read-only |
| `ProtectHome=` | make `/home`, `/root`, `/run/user` inaccessible/read-only |
| `PrivateTmp=` | private `/tmp` + `/var/tmp` |
| `PrivateDevices=` | minimal private `/dev` |
| `PrivateUsers=` | user-namespace isolation (enables other namespacing in user services) |
| `ProtectKernelTunables=` | `/proc/sys`, `/sys` etc. read-only |
| `ProtectKernelModules=` | block kernel module loading |
| `ProtectKernelLogs=` | block kernel log access |
| `ProtectClock=` | block clock changes |
| `ProtectHostname=` | block hostname changes |
| `ProtectProc=` | restrict `/proc/*PID*` visibility (`noaccess`/`invisible`/`ptraceable`/`default`; suggests `invisible`) |
| `RestrictAddressFamilies=` | allow-list AF names (`AF_UNIX`, `AF_INET`, `AF_INET6`, … or `none`) |
| `RestrictNamespaces=` | restrict namespace creation |
| `RestrictRealtime=` | refuse realtime scheduling |
| `RestrictSUIDSGID=` | deny setting SUID/SGID bits |
| `LockPersonality=` | lock the `personality(2)` domain |
| `MemoryDenyWriteExecute=` | forbid W+X memory mappings |
| `SystemCallFilter=` | seccomp allow/deny list (supports `@set` groups) |
| `SystemCallArchitectures=native` | disable other ABIs (recommended with the filters above) |
| `SystemCallLog=` | log filtered syscalls |
| `StateDirectory=` / `LogsDirectory=` / `RuntimeDirectory=` / `CacheDirectory=` | managed writable dirs under `/var/lib`, `/var/log`, `/run`, `/var/cache`; `RuntimeDirectory=` is removed on stop |
| `ReadWritePaths=` / `ReadOnlyPaths=` / `InaccessiblePaths=` | carve exceptions inside `ProtectSystem=strict` |
| `UMask=` | creation mask (default `0022`) |

### 7.3 Proposed units (directives only — no code)

**`gilgamesh-sensor.service`** (unprivileged + `CAP_NET_RAW`)

```ini
[Service]
Type=notify                     # or simple; decide in build
User=gilgamesh
Group=gilgamesh
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
StateDirectory=gilgamesh
LogsDirectory=gilgamesh
UMask=0077
```

**`gilgamesh-web.service`** (fully unprivileged, UI only)

```ini
[Service]
DynamicUser=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
StateDirectory=gilgamesh
ReadWritePaths=/var/lib/gilgamesh
UMask=0077
```

Notes / caveats:

- **`RestrictAddressFamilies=AF_PACKET`** is included for the sensor because AF_PACKET is a Linux address family ([packet(7)](https://manpages.debian.org/bookworm/manpages/packet.7.en.html)) and the directive accepts address-family names. **`UNVERIFIED`: that the systemd allow-list parser accepts `AF_PACKET` verbatim** — confirm with `systemd-analyze security`/service start in build; if not, keep `AF_PACKET` implicitly available by not restricting, or validate the exact token.
- **`SystemCallFilter=@system-service`** is a predefined set; confirm the running systemd's set name with `systemd-analyze` in build (`UNVERIFIED`: exact set list on bookworm).
- **`gilgamesh-sensor` + `gilgamesh-web` over SQLite WAL** is the primary channel; a **Unix socket** (AF_UNIX) handles control commands (e.g. "reload rules"), which is why `AF_UNIX` is allowed in both units.
- The **fail-open concern (Mode A bridge)** is a doc-01 topic; here we only note that systemd units must not be in the packet-forwarding path.

**Sources:** [19] (systemd.exec), [9] (capabilities), [8] (packet).

---

## 8. RAM / CPU budget on a 4 GB Pi 4

**Caveat first:** the figures below are *engineering budgets* (targets to verify by measurement), not measured values. Only the SD-card IOPS figure in §5 is an official number. Anything specific to Suricata's RSS on a Pi is `UNVERIFIED` here and cross-referenced to doc 03.

| Component | RAM target | CPU (idle / busy) | Notes |
|---|---|---|---|
| OS (Raspberry Pi OS Lite 64-bit) + systemd | ~200–300 MiB | low | headless |
| Suricata 8.x (IDS, ET Open subset) | ~300–600 MiB | 0.2–1.0 core | **`UNVERIFIED`: RSS scales with rule count + flow table; cap via rule subset + `memcap` (verify config keys against Suricata 8 docs in doc 03)** |
| `gilgamesh-sensor` (Scapy/raw) | ~80–200 MiB | 0.2–1.0 core | depends on packet rate (§3) |
| FastAPI + Uvicorn + Jinja2/htmx | ~80–150 MiB | low | per-request bursts |
| SQLite (WAL), page cache | ~20–64 MiB | low | set `PRAGMA cache_size` modestly |
| Miscellaneous (journald, ssh, etc.) | ~50–100 MiB | low | |
| **Total budget** | **≤ ~2.0 GiB** | | leaves ≥ ~1.8 GiB headroom on 4 GB |

**Guardrails so it fits and stays stable**

- Enforce per-service caps with **cgroup** controls (`MemoryMax=`, `MemoryHigh=`, `CPUQuota=`, `TasksMax=`) from `systemd.resource-control(5)` — **`UNVERIFIED`: exact units/limits for a Pi 4**; set them after first real measurement.
- Set `OOMScoreAdjust=` so the web app is more likely to be killed than the sensor if memory spikes; use `OOMPolicy=` to control restart behaviour (both documented in systemd.exec(5)). **`UNVERIFIED`: chosen values** — set in build.
- Prefer **fewer rules** in Suricata over more RAM: pick an ET Open subset (doc 03) rather than the full ruleset.
- Disable Suricata features not needed for v1 (e.g. heavy protocol parsers / file extraction) to shrink RSS — **`UNVERIFIED`: exact config keys for Suricata 8**; confirm in doc 03.
- Provide a **"low-memory" preset** in the UI that turns off the most expensive detectors and trims the Suricata rule set.

**Sources:** [19] (systemd.exec), [20] (systemd.resource-control — verify at build).

---

## 9. Suricata runtime rule / config reload

Verified against [Suricata rule-reload docs](https://docs.suricata.io/en/latest/rule-management/rule-reload.html):

**Triggers**

- Signal: `kill -USR2 $(pidof suricata)` — USR2 starts a rule reload.
- Unix socket client `suricatasc`:
  - `suricatasc -c reload-rules` — **blocking** reload (caller waits).
  - `suricatasc -c ruleset-reload-nonblocking` — **non-blocking** reload.

**What a reload actually refreshes**

- The main `suricata.yaml` (and any `--include <config-file.yaml>`), but **only rule-related information** is reloaded: `vars` (rule variables), `rule-files`, ancillary `classification.config`, `reference.config`, `threshold.config`, rule `datasets`, and per-tenant rule config in multi-tenant mode. It is **not** a full config-file reload of engine settings.
- Reload steps: main config reloaded → rule files reloaded with new variables → **new detection engine created** → old and new engines **swapped** → threads updated → old engine freed.
- **Extra memory is used during the reload** because two detection engines exist briefly. On a 4 GB box this is the main reason to keep the rule set modest (§8) and to prefer **non-blocking** reloads from the UI so the sensor/UI thread isn't stalled.

**How Gilgamesh uses this**

- The DB (D-005) is the source of truth. On a config change, the renderer writes the new rule-related config into the path `suricata.yaml` points at (`default-rule-path` / `rule-files: - suricata.r`, per [suricata-update docs](https://docs.suricata.io/en/latest/rule-management/suricata-update.html)), then issues **`ruleset-reload-nonblocking`** over the Unix socket so the web app doesn't block.
- Rule updates: `suricata-update` downloads the ET Open set into the Suricata rule directory (bundled since Suricata 4.1). **Licence (corrected against doc 02/03):** ET Open is permissively licensed but the exact SPDX id is **AMBIGUOUS** — the shipped `BSD-License.txt` is BSD-3-Clause-style while the OISF `index.yaml` labels it `MIT`; ET Pro is the commercial oinkcode-gated tier and is excluded by C1. Suricata 8.0.7 installs as a prebuilt arm64 `.deb` from `trixie-backports` (doc 03). The remaining open item is **ET Open ↔ Suricata 8 rule-format compatibility** (public feed tree's newest build dir is `suricata-7.0.3`) — cross-ref doc 03.
- The UI shows the current rule-set version and a "reload rules" / "update rules" action; the status comes back via the Unix socket (`suricatasc` commands / last-reload info).

**Sources:** [21] (rule reload), [22] (suricata-update), [23] (EVE output).

---

## Sources

1. Scapy `sendrecv` API — `sniff`/`AsyncSniffer` — https://scapy.readthedocs.io/en/stable/api/scapy.sendrecv.html
2. Suricata rule reload — https://docs.suricata.io/en/latest/rule-management/rule-reload.html
3. Suricata EVE JSON output — https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
4. Suricata `suricata-update` — https://docs.suricata.io/en/latest/rule-management/suricata-update.html
5. Python `asyncio` queues — https://docs.python.org/3/library/asyncio-queue.html
6. Python `time.monotonic` — https://docs.python.org/3/library/time.html#time.monotonic
7. Scapy API (as #1)
8. `packet(7)` — https://manpages.debian.org/bookworm/manpages/packet.7.en.html
9. `capabilities(7)` — https://manpages.debian.org/bookworm/manpages/capabilities.7.en.html
10. SQLite Write-Ahead Logging — https://sqlite.org/wal.html
11. SQLite pragmas (`synchronous`, `wal_autocheckpoint`, `journal_size_limit`) — https://sqlite.org/pragma.html
12. Raspberry Pi SD Cards — https://www.raspberrypi.com/documentation/accessories/sd-cards.html
13. `systemd-journald.service(8)` — https://manpages.debian.org/bookworm/systemd/systemd-journald.service.8.en.html
14. Raspberry Pi boot modes / USB mass storage boot — https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#usb-mass-storage-boot
15. `mount(8)` (for `noatime`) — https://manpages.debian.org/bookworm/mount/mount.8.en.html
16. Discord Webhook resource (Execute Webhook) — https://discord.com/developers/docs/resources/webhook#execute-webhook
17. Telegram Bot API (`sendMessage`) — https://core.telegram.org/bots/api#sendmessage
18. Python `smtplib` — https://docs.python.org/3/library/smtplib.html
19. `systemd.exec(5)` — https://manpages.debian.org/bookworm/systemd/systemd.exec.5.en.html
20. `systemd.resource-control(5)` — https://manpages.debian.org/bookworm/systemd/systemd.resource-control.5.en.html
21. Suricata rule reload (as #2)
22. `suricata-update` (as #4)
23. Suricata EVE output (as #3)

---

## Open questions / UNVERIFIED

1. **`UNVERIFIED`: measured Scapy packets/second on a Raspberry Pi 4** (and the same for raw `AF_PACKET`). No official figure exists; must be benchmarked on hardware before fixing filters/thresholds.
2. **`UNVERIFIED`: per-socket packet-drop counters** via `getsockopt(PACKET_STATISTICS / SOL_PACKET)` — verify option names/flags in build before wiring the overload detector.
3. **`UNVERIFIED`: exact `Retry-After` / rate-limit header names and error-body shapes** for Discord and Telegram, and SMTP error classifications, for clean retry + UI reporting.
4. **`UNVERIFIED`: Suricata 8.0.7 memory profile on a Pi 4** and the exact config keys to trim rule set / memory (`memcap` etc.) — cross-ref doc 03.
5. **ET Open licence is AMBIGUOUS (BSD-3-Clause-style shipped file vs `MIT` in the OISF index); ET Open ↔ Suricata 8 rule-format compatibility is UNVERIFIED** (feed's newest build dir is `suricata-7.0.3`). Suricata 8.0.7 aarch64 `.deb` path is **resolved** (doc 03: `trixie-backports`).
6. **`UNVERIFIED`: whether `RestrictAddressFamilies=` accepts `AF_PACKET`** verbatim on bookworm's systemd; validate with `systemd-analyze security` / a real service start.
7. **`UNVERIFIED`: the exact `SystemCallFilter=@*` set list** available on bookworm's systemd (`@system-service` assumed).
8. **`UNVERIFIED`: cgroup limits** (`MemoryMax=`, `CPUQuota=`, `TasksMax=`, `OOMScoreAdjust=`, `OOMPolicy=`) and their values for a 4 GB Pi 4 — set after first measurement.
9. **`UNVERIFIED`: optimal prune batch size and `VACUUM`/`incremental_vacuum` cadence** to avoid UI-visible stalls on SD.
10. **`UNVERIFIED`: generated columns vs plain TEXT for IP prefix queries** in SQLite.
11. **`UNVERIFIED`: official Raspberry Pi / Pi OS `noatime` recommendation** — the fstab line is standard Linux practice (tracked via `mount(8)`), to be validated on the target image.
12. **`UNVERIFIED`: exact directory/paths** for the Suricata rule files on the chosen Debian package (`default-rule-path`) — confirm on the installed package in doc 03/07.

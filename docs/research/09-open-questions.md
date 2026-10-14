# 09 — Open Questions / UNVERIFIED Register (consolidated)

**Purpose:** single list of everything not yet proven, merged from `docs/research/01`–`07`. Nothing here is invented; each row names the source doc.
**Date:** 2026-10-14 · **Phase 1 (research only).**
**Severity:** `BLOCKER` = must resolve before coding that area · `HIGH` = resolve during Phase 2 build · `MED` = tune with measurement · `LOW` = record/ship later.

---

## A. Blockers (resolve before/at the start of Phase 2)

| # | Item | Why it matters | How to close | Src |
|---|---|---|---|---|
| A1 | **Scapy `GPL-2.0-only` imported in-process; `python-multipart` is `Apache-2.0`.** If Gilgamesh is published as a repo, the combined work's licence is a real problem (Apache-2.0 is commonly treated as GPL-2.0-only-incompatible). | Determines the project's own licence and whether Scapy stays on the hot path. | Choose: (a) license Gilgamesh **GPL** and keep Scapy, or (b) replace Scapy on hot paths with stdlib `AF_PACKET` + permissive parsers. **Decide before creating the repo.** | 03 §5.1/§5.2 |
| A2 | **ET Open ↔ Suricata 8 rule-format compatibility.** Public feed's newest build dir is `suricata-7.0.3` (and `suricata-5.0`); there is no `suricata-8.0` dir. Does 8.0.7 load it cleanly, and which source does `suricata-update` pick for an 8.x engine? | Signature coverage (#6) on the chosen engine; Suricata 8 otherwise has no rules. | Run `suricata-update` against Suricata 8.0.7 on the Pi; inspect resolved source URL + rule-load warnings. | 02 §356, 03 §208, 04 §525 |
| A3 | **ET Open exact SPDX id** — OISF `index.yaml` says `MIT`; the shipped `BSD-License.txt` is BSD-3-Clause-style. | C1 licence recording. | Record **both** sources and the discrepancy; both are permissive, so it does not block. | 02, 03 §209 |
| A4 | **Measured Scapy packets/second on a Pi 4** (and raw `AF_PACKET`), i.e. the real capture ceiling. | Sizes the Sensor B design (threads vs process, BPF, `store=False`) and the thresholds (#4). | Benchmark on the target box; feed result back into doc 04 §3 and the RAM/CPU budget. | 02 §356, 04 §522 |
| A5 | **Suricata 8 RSS on a 4 GB Pi 4** with the chosen ET Open subset, plus the exact config keys to trim rules/memory (`memcap`, disabled parsers). | C7 (4 GB budget). | Measure RSS on target; tune rule subset + `memcap`. | 03, 04 §525 |

## B. High (resolve during Phase 2 build)

| # | Item | Why it matters | How to close | Src |
|---|---|---|---|---|
| B1 | **`br0` vs member-port duplicate-packet semantics** for `AF_PACKET` on the target kernel. | Fixes the capture topology (one tap on `br0`, or per-port). | Lab frame-count with `tcpdump` on `br0` vs `eth0`/`eth1`; then lock doc 01 §6. | 01 §440 |
| B2 | **Does the specific USB3 NIC expose settable `gro`/`lro`/`tso`?** (`ethtool -k` may print `[fixed]`.) | Offloads corrupt IDS accuracy if they cannot be disabled. | `ethtool -k` on the target; if fixed, assess behaviour. | 01 §441, 04 |
| B3 | **Sustained bidirectional throughput through the bridge** — do not promise ~2 Gbps aggregate. | Honest capability claim; the brief forbids degrading the connection. | Measure on the unit (iperf3) one-way and bidirectional. | 01 §445 |
| B4 | **Boot-time coverage gap** — is the bridge up before DHCP/network is available? | Frames during boot are missed; document the window. | Observe boot on target; document in doc 01. | 01 §446 |
| B5 | **`apt` access to `trixie-backports`** for Suricata 8.0.7 + `suricata-update` 1.3.8 (trixie stable only has the EOL 7.0.10). | Install path: apt vs source build. | `apt-cache policy suricata` after enabling backports on the image. | 03 §210 |
| B6 | **`RestrictAddressFamilies=` accepting `AF_PACKET` verbatim**, and the exact `SystemCallFilter=@*` set on the target systemd (bookworm/trixie differ). | Unit hardening correctness; a wrong value blocks capture/startup. | `systemd-analyze security` / real service start on target. | 04 §527/§528, 07 §825 |
| B7 | **`uv` offline viability** — `uv sync --offline` from a populated cache, cross-arch wheelhouse (`--python-platform aarch64-unknown-linux-gnu`), `uv python install` layout / `UV_PYTHON_INSTALL_DIR`. | Offline-first install (C-later). | Test `uv sync --frozen --offline` in Phase 2; prefer same-arch seeding + OS Python 3.13. | 03 §216, 07 §815–820 |
| B8 | **`suricata-update` offline mode** — local/`--local` or tarball source, and whether its output swap is atomic. | Rules update on an air-gapped box; crash-safety. | Read `suricata-update --help`/source on target; test. | 07 §821 |
| B9 | **`uv` binary path for system units** and the standalone-installer `UV_INSTALL_DIR`/`--path` behaviour. | systemd `ExecStart` must reference a fixed path. | Verify installer docs/layout on target. | 07 §834 |
| B10 | **apt pinning** (`apt_preferences(5)`) to prevent a downgrade 8.x → 7.0.10. | Keeps the EOL engine out after upgrades. | Write + test a pin file. | 07 §837 |
| B11 | **Wizard write path + unit reload** — how the sandboxed web service persists derived config that must live under `/etc/…` and reloads units (root helper vs state-dir rendering). | Without it, "apply config without reboot" is unsafe/incomplete. | Design in doc 04 §privilege separation; implement + test. | 07 §843 |
| B12 | **Notifier credential storage** — plaintext-in-DB (0600) vs Fernet-encrypted; threat-model call. | Ties to encryption-at-rest (C-security). | Lock the decision; document the tradeoff. | 06 §391 |
| B13 | **htmx version — 2.0.11 (npm `latest`) vs 4.0.0 (npm `next`, 2026-08-28).** PROMPT's "1.x vs 2.x" note is outdated. | Vendored asset choice; 4.0.0 is a <2-month-old rewrite. | Default **2.0.11**; re-evaluate before v1.1. | 03 §212, 05, 06 §392 |
| B14 | **`htmx-ext-sse` licence is unverified** (npm has no `license`, repo has no detected licence file). | C1. | **Do not use it**: ship a ~10-line native `EventSource` script we own (FastAPI serves SSE natively). | 05 §341 |
| B15 | **Multi-worker SSE broadcast** — if Uvicorn runs >1 worker, an in-process event bus won't reach all SSE clients. | Dashboard live updates. | Run a **single worker** for v1 (documented); revisit if scaling. | 05 §346 |
| B16 | **`slowapi` vs `limits`** — is `slowapi` worth it given its cadence? | Rate-limiting implementation. | Use `limits` directly (maintenance); do not add `slowapi`. | 06 §393 |
| B17 | **Suricata `alert.severity` scale direction (1 = highest?) is not stated outright in the docs.** The EVE docs only show `severity: 1` on a malware C2 signature and `severity: 2` on "Potentially Bad Traffic", which is *consistent with* 1 = highest. | Wrong direction would invert every signature alert's severity — the loudest attacks shown as `low`. | M9 implements the map as an **overridable constructor argument** (`EveIngestor(severity_map=...)`) with `1=highest` as default, plus `test_severity_mapping_is_overridable`. **Confirm on the Pi** with a real ET Open test signature. | M9, doc 03 |
| B18 | **`suricata-update` has NO `disable-rule`/`enable-rule` command** — verified against its command tree (only `add-source`, `disable-source`, `enable-source`, `remove-source`, `list-sources`, `update-sources`, `check-versions`). Per-rule control is via the `/etc/suricata/{disable,enable,drop,modify}.conf` filter files. `load_filters()` in `suricata-update/main.py` **skips any line starting with `#`**, so the shipped samples are fully commented out. | Any design assuming `suricata-update disable-rule 2019401` would fail at runtime. | Resolved in M9: Gilgamesh renders `disable.conf`/`enable.conf` with **un-prefixed** `gid:sid` directives, atomically. | M9, `suricata-update` docs + source (2026-10-14) |

## C. Medium (tune with measurement on the target)

| # | Item | Why it matters | How to close | Src |
|---|---|---|---|---|
| C1 | **Suricata rule subset + sensitivity presets** and per-category default severities. | Alert volume; FP tuning. | Baseline on real home traffic. | 04 |
| C2 | **Argon2 parameters** (`time_cost`/`memory_cost`/`parallelism`) on the Pi. | Login latency vs RAM budget. | `python -m argon2 --profile RFC_9106_LOW_MEMORY` on target. | 06 §385 |
| C3 | **Session idle/absolute timeouts, lockout thresholds/backoff, hashing concurrency cap.** | Security policy numbers. | Propose defaults, confirm with the user. | 06 §390 |
| C4 | **cgroup limits** (`MemoryMax=`, `CPUQuota=`, `TasksMax=`, `OOMScoreAdjust=`, `OOMPolicy=`). | Protect the sensor on a 4 GB box. | Set after first measurement. | 04 §529 |
| C5 | **Prune batch size + `VACUUM`/`incremental_vacuum` cadence** on SD. | Avoid UI-visible stalls / write amplification. | Benchmark on target. | 04 §530 |
| C6 | **SQLite generated columns vs plain TEXT** for IP-prefix queries. | Query speed. | Benchmark. | 04 §531 |
| C7 | **Per-socket packet-drop counters** — exact `getsockopt(PACKET_STATISTICS / SOL_PACKET)` usage. | Overload detection. | Verify option names/flags in build. | 04 §523 |
| C8 | **Retry-After / rate-limit header names and error-body shapes** for Discord, Telegram, SMTP. | Clean retry + UI reporting. | Read official API docs at implement time. | 04 §524 |
| C9 | **Arpwatch flip-flop numeric window** (not in the man page; it is a source constant). | Do not quote an invented number. | Read `arpwatch` source, or keep our own bounds. | 02 §359 |
| C10 | **Locally-administered/randomised MAC bit wording** (IEEE 802-2014 / EUI-48). | "Likely randomised device" label (#5). | Verify before implementing. | 02 §360 |
| C11 | **DNS-tunnelling entropy cut-off + beaconing jitter thresholds** (v1.1). | No vendor defaults exist. | Calibrate on Gilgamesh's own traffic. | 02 §361 |
| C12 | **DHCPv6 (546/547) scope** decision. | Later IPv6 coverage. | Decide scope for v1.1. | 02 §358 |
| C13 | **NTP / NDP capture completeness in bridge mode** (are all NS/NA seen?). | Item #7 viability. | Confirm capture on target. | 02 §357 |
| C14 | **Uvicorn `--ssl-version` status** in 0.54.0 and end-to-end self-signed HTTPS smoke test. | TLS config correctness. | Verify in build. | 06 §386/§387 |
| C15 | **FastAPI/Starlette extra body-size / JSON-depth limits** beyond `RequestBodyLimitMiddleware`. | DoS hardening. | Test deep-JSON / zip-bomb inputs. | 06 §389 |
| C16 | **Suricata rule-syntax escaping** for any rendered value (we will not author raw rules, so scope is small). | Rule-injection safety. | Owned by doc 03; keep typed-params-only rule. | 06 §388 |
| C17 | **journald `SystemMaxUse`, logrotate `rotate`/`maxsize`, `Storage=volatile` vs `persistent`.** | SD wear + disk. | Placeholders in doc 07; finalize with doc 04. | 07 §839 |

## D. Low (record / verify on hardware, no design impact)

| # | Item | Why it matters | How to close | Src |
|---|---|---|---|---|
| D1 | **Exact EVE config block for ARP logging** (placement in `types:`; VLAN/source-interface attachment). | ARP evidence from Suricata. | `suricata -T` on target. | 02 §354 |
| D2 | **Does Suricata flag an unmatched DNS response as an anomaly?** (It does for HTTP.) | Could add a free DNS signal. | Craft a spoofed reply and test. | 02 §353 |
| D3 | **Any 8.0.x backport of `ether.hdr` / ARP keywords?** | ARP stays a custom module regardless. | Check 8.0.x changelogs. | 02 §352 |
| D4 | **Tailwind standalone arm64 `--help` on-device** (flags were read from v4 CLI source). | Build wiring. | `./tailwindcss-linux-arm64 --help`. | 05 §342 |
| D5 | **Tailwind v4 browser support** (Safari 16.4+/Chrome 111+/Firefox 128+). | If the admin's tablet is older → v3 route (different syntax). | Check the admin's browser. | 05 §343 |
| D6 | **Alpine CSP build completeness** — no globals/`x-html`/arrow fns/destructuring. | Component design. | Confirm planned dropdowns/modals/tabs comply; else `Alpine.data()`. | 05 §344 |
| D7 | **htmx `<hx-partial>`/View Transitions** at 2.0.11. | Optional polish. | Verify pinned build. | 05 §347 |
| D8 | **Vendored asset sha256 values** (htmx/Alpine/Tailwind). | Supply-chain record. | `static/vendor/VENDOR.md` at vendoring time. | 05 §348 |
| D9 | **`bridge-utils` presence** on the current RPi OS Lite image. | Only for the documented ifupdown alternative. | Confirm on target. | 01 §443 |
| D10 | **`systemd.netdev(5)` `STP=` default**; set explicitly regardless. | Bridge correctness. | Set `STP=off` explicitly. | 01 §442 |
| D11 | **`nmcli` token spelling across versions** (`controller` vs `master`; `bridge.stp`). | Bridge config script. | Confirm against installed `nmcli`. | 01 §447 |
| D12 | **Bridge × multicast snooping** interaction (kernel default on). | Must not suppress detection-relevant multicast. | Confirm on target. | 01 §448 |
| D13 | **A Pi-4-compatible 1 Gbps hardware bypass / fail-to-wire module.** | Only true fail-open option; likely unavailable. | If unavailable, document the outage risk + UPS advice. | 01 §444 |
| D14 | **Which proprietary firmware blobs ship** in the current image. | C1 honesty about the platform layer. | Enumerate `/boot/firmware`. | 03 §215 |
| D15 | **`passlib` BSD clause count** (if used at all). | Licence record. | Prefer `argon2-cffi`/`pwdlib`; drop `passlib`. | 03 §214 |
| D16 | **Managed-Python `python-build-standalone` `MPL-2.0`** if `uv python install` is used. | Extra licence + offline plan. | Prefer OS Python 3.13. | 03 §213 |
| D17 | **mDNS discovery (`gilgamesh.local` via avahi)** — ship or not? | Convenience vs extra attack surface. | Decide in doc 01/04. | 07 §832 |
| D18 | **`openssl`/CSPRNG availability** for bootstrap secret generation. | Install script. | Assumed present; verify on image. | 07 §841 |
| D19 | **Suricata hardening drop-in safety** — `SystemCallFilter=`, `RestrictAddressFamilies=` (AF_NETLINK?), `MemoryDenyWriteExecute=` vs hyperscan/JIT. | Unit hardening. | Boot Suricata under the drop-in and test. | 07 §824–827 |
| D20 | **App `MemoryDenyWriteExecute=yes`** safe only if no Python dep JITs. | Unit hardening. | Confirm final dependency set (doc 03). | 07 §828 |
| D21 | **Capture capability set** (`CAP_NET_RAW` alone vs `+CAP_NET_ADMIN`) — depends on promiscuous mode + AF_PACKET vs libpcap. | Least privilege. | Confirm in doc 01/04 build. | 07 §830 |

## E. Subagent-reported leads that were NOT independently re-verified

These were asserted by research subagents and used in the docs but not re-checked by the lead. Treat as `PROVISIONAL`:

- Exact Scapy `AF_PACKET`/`AsyncSniffer` throughput technique list (doc 04 §3) — the *API* names were cited but no measurement was reproduced.
- Per-signature severity mappings and the specific ET Open category names (doc 02 §6).
- The specific SlidingWindow/token-bucket parameter values (D-012) — engineering defaults, not vendor values.

## F. Resolved during this phase (for the record)

- Suricata **8.0.7** arm64 `.deb` in `trixie-backports` + `suricata-update 1.3.8-1~bpo13+1` arm64 — **verified** (lead).
- FastAPI **0.143.0**, Starlette **1.8.0** (ships `RequestBodyLimitMiddleware`), Pydantic **2.14.1**, Scapy **2.8.0** (`GPL-2.0-only`), argon2-cffi **25.1.0** — **verified** (lead, PyPI JSON).
- htmx **4.0.0** released 2026-08-28; npm `latest` = **2.0.11** — **verified** (lead).
- Tailwind **v4.3.3** publishes `tailwindcss-linux-arm64` — **verified** (lead, GitHub release assets).
- FastAPI ships **`fastapi/sse.py`** (native SSE) — **verified** (lead, repo tree).
- ET Open public feed dirs = `suricata-5.0`, `suricata-7.0.3` only — **verified** (lead).
- Raspberry Pi OS Lite 64-bit = Debian 13 **trixie**, image `2026-10-06`, Python 3.13.5 — per doc 03 §1.

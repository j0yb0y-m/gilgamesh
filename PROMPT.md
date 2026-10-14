# Project Gilgamesh: Research, Ask, Plan, Build

## 0. Your role and how to work

You are a senior Python engineer and a blue-team (defensive security) specialist.
Your job is to **design and build Gilgamesh end to end**: a working network intrusion detection system for home networks (my college project). You research first, ask me clarification questions **once**, plan, then build the whole project yourself, milestone by milestone.

### Work rules (follow strictly)

1. **Small steps, save often.** Your context is limited. After every step, update `docs/PROGRESS.md`. At the start of every turn (and after any context compaction), read `docs/PROGRESS.md` and `AGENTS.md` first so you know exactly where you are.
2. **Persist these rules.** In Phase 0, create `AGENTS.md` at the project root (60 lines max) containing: the hard constraints (section 2), the safety rules (section 2), the project layout, and the exact commands to test and lint (`uv run pytest`, `uv run ruff check`). Update it as the project grows. This prompt may drop out of your context; `AGENTS.md` must not.
3. **Evidence rule.** Every technical claim about a tool, library, config key, CLI flag, API, or rule syntax needs a source URL from **official docs, official repos, or man pages**, plus the version checked. Blog posts and forums are leads, not proof. Summarize in your own words.
4. **Never invent.** If you cannot verify something, mark it `UNVERIFIED` and handle it in the clarification batch or the blockers file. Do not guess API names, flags, config keys, or Suricata rule syntax from memory.
5. **Research just in time, too.** Before using a library for the first time in a milestone, re-read its current docs for the exact API you need. Do not rely on memory.
6. **Never claim success without proof.** A milestone is done only when its tests and its acceptance command actually ran and passed. Paste the command and the key lines of its output into `docs/PROGRESS.md`.
7. **Use your web fetch/search tools.** If you have no web access, say so in your first message and STOP.
8. **Be honest about limits.** If something in my idea cannot work the way I described, say so plainly and propose the closest thing that works.

### When you may stop and talk to me (and only then)

- **The clarification batch** in Phase 2 (one message, once).
- You failed the same step **3 times**. Write what you tried in `docs/BLOCKERS.md`, then ask me.
- You need to run a **privileged or system-changing command** (see safety rules below).
- A decision would **break a hard constraint**.
- All milestones are finished (final report).

Otherwise **keep going without waiting for approval.** After each milestone print a 3-line status, then continue with the next one.

---

## 1. Project brief

**Gilgamesh** is a network intrusion detection system (NIDS) that a non-expert plugs into their home network, like a home router. It watches traffic, detects attacks, and alerts the owner.

- **Hardware:** Raspberry Pi 4 Model B (4 GB RAM), onboard Gigabit Ethernet + one USB 3 to Gigabit Ethernet adapter.
- **Target OS:** 64-bit Debian-based (Raspberry Pi OS Lite or Kali ARM64). Verify package availability and versions; do not assume them.
- **Detects:** ARP poisoning and DNS spoofing at minimum, plus other common home-network attacks (section 3.2).
- **Alerts via:** Discord, Telegram, or email (the user can enable one or more).
- **Only interface:** a web UI used to configure everything, manage detection rules, set up alerts, and view detected attacks.
- **Scope of v1:** _detect and alert only._ Gilgamesh never blocks traffic and never degrades the user's internet connection.
- **Project folder:** create it as `gilgamesh/` inside the current working directory (unless the current directory already is an empty or Gilgamesh repo). Run `git init` and commit after every milestone with a clear message.

---

## 2. Hard constraints and safety rules

| #   | Constraint                                                                                                                                                                                                                                                                                |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C1  | **Open source only.** Every dependency, tool, and rule set must be open source. Record the license (SPDX id) and source URL of each in `docs/research/12-licenses.md` **before** adding it. Reject anything proprietary, paid, or freemium-gated (for example subscriber-only rule sets). |
| C2  | **Web interface only.** No CLI tool, TUI, desktop app, or mobile app for users. All user configuration happens in the web UI, including first-run setup. (systemd units and an install script for deploying the box are allowed; they are not user interfaces.)                           |
| C3  | **Stack:** Python + FastAPI; **htmx** for server-driven UI updates, **Alpine.js** only for small client-side state; **Tailwind CSS** for styling.                                                                                                                                         |
| C4  | **`uv` only.** Use `uv init`, `uv add`, `uv add --dev`, `uv sync`, `uv lock`, `uv run`. Never use `pip`, `python -m pip`, `uv pip`, or hand-made venvs.                                                                                                                                   |
| C5  | **Offline-first.** The UI must work with no internet: vendor htmx, Alpine.js, and the built Tailwind CSS locally. No CDN links, no external fonts.                                                                                                                                        |
| C6  | **No Node.js on the Pi.** Build Tailwind CSS with the standalone CLI (verify it exists for your dev OS and for linux-arm64) and commit the built CSS.                                                                                                                                     |
| C7  | **Native install, no Docker.** Services run under systemd.                                                                                                                                                                                                                                |
| C8  | **Fits the Pi.** Define a RAM/CPU budget per component. The whole system must stay stable on 4 GB.                                                                                                                                                                                        |
| C9  | **Allowed tools:** Scapy, Suricata, Snort 3, Zeek, and similar open-source tools. Choose with evidence.                                                                                                                                                                                   |
| C10 | **Testable without the Pi.** All detectors must run against synthetic Scapy packets and PCAP files on a normal Linux dev machine, so the project can be built and tested before it ever touches the Pi.                                                                                   |

### Safety rules (the machine you run on is my real computer)

- **Never change the host's network configuration** (bridges, `ip link`, `iptables`/`nftables`, NetworkManager, `sysctl`, interface offload settings) and never put an interface in promiscuous mode on a real interface. Write such steps as scripts or docs for the Pi, and do not execute them.
- **Never use `sudo`** or any privileged command without asking me first and explaining exactly what it does.
- **No attack tool** (arpspoof, bettercap, dnschef, yersinia, nmap against real hosts, and so on) may be run against any real network or device. Only generate and replay traffic using synthetic Scapy packets, PCAP files, or an isolated lab I set up myself (network namespaces/veth), and only after asking me.
- **Secrets:** never hard-code, log, commit, or ask me to paste webhook URLs, bot tokens, or SMTP passwords into chat. They are entered only through the web UI. Add a `.gitignore` that excludes the database, config, certificates, and keys.
- Never build shell commands from user input. Never run `rm -rf` outside the project folder.

---

## 3. Starting architecture (my hypothesis: verify, challenge, improve)

### 3.1 Network placement

A Pi that is merely "plugged in" to a switched network sees almost nothing: ARP replies are unicast, and only broadcast traffic reaches every port. Research and document these modes:

- **Mode A (default for v1): transparent inline L2 bridge.** `eth0` (onboard) and `eth1` (USB adapter) are bridged as `br0`, placed between the ISP modem/router and the rest of the home network (switch or Wi-Fi access point). The Pi has a management IP on `br0` for the web UI. Gilgamesh sees all LAN↔Internet traffic plus ARP, DHCP, and IPv6 NDP broadcasts.
- **Mode B (optional): passive mirror port**, for users whose managed switch supports port mirroring (SPAN).
- **Out of scope for v1:** acting as a full router (NAT + DHCP). Mention it in future work only.

For Mode A, research and document honestly:

- What Gilgamesh can **not** see (for example LAN↔LAN traffic that stays inside another switch).
- What happens if the Pi loses power while inline, and the best mitigation.
- How to configure the bridge on Raspberry Pi OS/Debian with the tool that distro actually uses (NetworkManager, systemd-networkd, or ifupdown; verify).
- Which interface(s) Suricata and Scapy should capture on when a bridge is involved, and whether packets get duplicated.
- NIC offload settings (GRO/LRO/checksum) that affect IDS accuracy and how to set them persistently.
- Whether the USB 3 adapter can sustain gigabit on a Pi 4, which USB port to use, and chipset caveats.

The code must treat the capture source as an abstraction (live interface **or** PCAP file) so that C10 holds.

### 3.2 Detection catalogue (research feasibility for each; do not assume)

**MVP (must work in v1)**

1. **ARP spoofing/poisoning:** IP-to-MAC binding changes, gateway MAC change, two MACs claiming one IP, gratuitous ARP floods, unsolicited ARP replies.
2. **DNS spoofing:** response with no matching query, conflicting answers for one query, response from a server that is not the configured resolver, suspicious TTLs. Think hard about false positives (CDNs, round-robin DNS, split-horizon).
3. **Rogue DHCP server** and **DHCP starvation.**
4. **Port scans** (horizontal and vertical) and **SYN floods.**
5. **New or unknown device joined the network** (device inventory with trusted/untrusted state).
6. **Suricata signature alerts** (open-source Emerging Threats Open rules; verify license and update tool).

**Later (v1.1, only if all MVP milestones are finished)** 7. IPv6 rogue Router Advertisement / NDP spoofing. 8. MAC flooding. 9. ICMP redirect abuse. 10. DNS tunneling heuristics. 11. Beaconing / unusual outbound connections.

For every item, record in the detection matrix: can Suricata do it alone? Can Scapy? What data is needed? What are the home-network false-positive sources (mDNS, VPNs, Wi-Fi roaming, DHCP renewals, phones with randomized MACs, IoT devices)? What are sensible default thresholds?

### 3.3 Components

1. **Sensor A, Suricata** in IDS mode, writing EVE JSON, using ET Open rules. Research the 4 GB RAM impact and choose a rule subset if needed. If Suricata is too heavy, say what you would do instead.
2. **Sensor B, custom Python detectors** (Scapy or raw AF_PACKET) for L2/L3 attacks that signature engines handle poorly. Research Scapy's real packet-rate limits on a Pi 4 and how to stay under them (BPF filters, `store=False`, sniffer in a thread or process, **never** inside the asyncio event loop).
3. **Event pipeline:** every detector emits one normalized event (pydantic model): id, timestamp, type, severity, source/destination MAC/IP, interface, evidence summary, details JSON, detector name. Then dedup + cooldown + rate limiting (one attack must not send 5,000 alerts) → store → notify.
4. **Storage:** SQLite in WAL mode. Schema, retention policy (auto-delete after N days or max rows), and **SD-card wear minimization** (rotating logs, `tmpfs` for transient files, optional USB SSD).
5. **Notifiers:** Discord webhook, Telegram Bot API, SMTP email. Retries with backoff, a "send test message" button, per-channel minimum severity, quiet hours, secrets never in logs, and a failing channel must never block detection.
6. **Web app:** FastAPI + Jinja2 + htmx + Alpine + Tailwind. Pages:
   - First-run setup wizard (admin account, interfaces and mode, alert channel).
   - Login.
   - Dashboard (live alert feed via SSE or similar; verify what is supported and its license).
   - Alerts (filter, search, detail view, acknowledge / mark false positive).
   - Devices (inventory, trust/untrust, rename).
   - Detection rules (enable/disable, thresholds, sensitivity presets, allowlists/trusted bindings, suppression).
   - Notifications (channels, test, severity filters, quiet hours).
   - System health (CPU, temperature, RAM, disk, interface status, sensor status, rule-set version, "update rules").
   - Settings (network mode, retention, account, HTTPS).
7. **Privilege separation:** capture needs `CAP_NET_RAW`/`CAP_NET_ADMIN`; the web app must run as an unprivileged user. Prefer Linux capabilities over root. Choose how the two sides communicate (SQLite, Unix socket, or similar) and which systemd hardening options to use (verify directive names).
8. **Security of Gilgamesh itself:** modern password hashing (Argon2 or bcrypt; check license and aarch64 wheel), `HttpOnly`/`SameSite`/`Secure` cookies, CSRF protection, login rate limiting, optional self-signed HTTPS, UI bound only to the management interface, secrets stored with strict file permissions, strict validation on every threshold and rule field.
9. **Config model:** the database is the single source of truth. Generated config (for example Suricata overrides) is rendered from it, and changes apply without a reboot. Verify how Suricata reloads rules and config.
10. **Deployment:** one idempotent install script + systemd units + a `uv`-managed project. Check that **every dependency has an aarch64 wheel or is pure Python** (inspect the wheel list in `uv.lock` or the package's PyPI file list).

---

## 4. Phases

### Phase 0: Bootstrap (no research needed)

Create `docs/PROGRESS.md` (a checklist of every phase and milestone), `docs/DECISIONS.md` (decision, reason, rejected alternative), `docs/BLOCKERS.md`, and `AGENTS.md` (rule 2 above). Run `uname -m` and `python --version` and note where you are running (dev machine or Pi).

### Phase 1: Research (one file each in `docs/research/`, keep each under about one page)

Format of every file: _question → findings → versions → source URLs → design impact → UNVERIFIED items._ Write the file, then tick it in `docs/PROGRESS.md`.

| File                          | Question to answer                                                                                                                                                                                                                                   |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `01-suricata.md`              | Install on ARM64 Debian (apt vs source), version, `af-packet` setup, EVE JSON config, runmode and memory tuning for 4 GB, `suricata-update` and the ET Open license, live rule reload, realistic Pi 4 performance from official or measured sources. |
| `02-detection-matrix.md`      | The feasibility matrix from section 3.2.                                                                                                                                                                                                             |
| `03-scapy-and-capture.md`     | Scapy and Python versions, `sniff` / `AsyncSniffer`, BPF filters, packet-rate limits on a Pi, threading model, ARP/DNS/DHCP layer classes, reading PCAPs, building synthetic packets for tests.                                                      |
| `04-bridge-and-network.md`    | Everything under Mode A and Mode B in section 3.1.                                                                                                                                                                                                   |
| `05-fastapi.md`               | Current version, lifespan handlers, Jinja2 templates, static files, SSE/WebSocket, dependencies, session auth options, background worker vs separate service.                                                                                        |
| `06-frontend.md`              | Current htmx and Alpine.js versions and how to vendor them. Tailwind CSS current major version and **its exact setup syntax**, the standalone CLI, how to build the CSS.                                                                             |
| `07-notifications.md`         | Discord webhook payload and rate limits, Telegram `sendMessage` (how a user obtains a bot token and chat id), SMTP with STARTTLS/SSL and app passwords. Libraries (prefer `httpx` and the stdlib) and licenses.                                      |
| `08-storage.md`               | SQLite WAL on SD cards, ORM vs plain `sqlite3`/`aiosqlite`, migrations, retention.                                                                                                                                                                   |
| `09-systemd-and-hardening.md` | Unit files, `AmbientCapabilities`, ordering, restart policy, hardening options, mDNS (`gilgamesh.local` via Avahi).                                                                                                                                  |
| `10-uv-project.md`            | `uv` project layout, lockfile, `uv sync --frozen`, `uv run`, deploying to aarch64, wheel availability for every planned dependency.                                                                                                                  |
| `11-testing.md`               | How to prove detection works safely: unit tests with synthetic packets, PCAP replay tests, `pytest`, `httpx` mocking for notifiers, FastAPI `TestClient` for UI routes, and how I could later run a real attack lab (documented only, not executed). |
| `12-licenses.md`              | One table of every planned component: name, version, SPDX license, source URL, OSS yes/no.                                                                                                                                                           |

### Phase 2: Clarification batch (ask me ONCE)

After research, send **one message** with at most 8 numbered questions. Only ask what research and your own judgment cannot settle. Every question must have a recommended default so I can reply "defaults" or just "1: B, 4: ...". Cover at least these, skipping any you can already answer:

1. Where are you running right now: my dev machine or the Pi? Which Linux distro and CPU architecture?
2. Confirm the network placement (inline bridge by default). Does the home network have a managed switch with port mirroring?
3. Which alert channels should be built (default: all three)?
4. Pi OS for the deployment target (default: Raspberry Pi OS Lite 64-bit)?
5. UI language: English only, or English + Arabic with right-to-left layout (default: English, with strings structured so a translation can be added later)?
6. Is there a deadline or required deliverables for the college project (report, slides, demo)?
7. Anything from the research that surprised you or that forces a trade-off I should choose (for example Suricata being too heavy)?

Then **wait for my answers.** Record them in `docs/DECISIONS.md`.

### Phase 3: Plan (`docs/PLAN.md`, written section by section)

1. Summary (10 lines max).
2. Final architecture: Mermaid diagram + a short explanation of each component and why.
3. Detection matrix: `Attack | Method | Data source | Default thresholds | False-positive sources | Severity | MVP/Later | How to test`.
4. Tech stack table: component, exact version, license, source URL.
5. Repository layout: directory tree with a one-line purpose per folder/file.
6. Data model: tables, fields, indexes, and the normalized event schema.
7. Routes and pages: HTTP routes (method, path, purpose) and the UI page list.
8. Configuration schema: exactly what the user can configure in the web UI.
9. Security design and a short threat model of Gilgamesh itself.
10. Resource budget per component (RAM, CPU, disk writes).
11. **Milestones: at most 14.** Each has: goal, files touched, dependencies, and an **acceptance test** (exact command and expected result). Each must be small enough for one session (roughly 300 changed lines). Required order:
    - M1 **walking skeleton:** `uv` project, FastAPI app, SQLite, one fake detector emits an event, it appears in the web UI.
    - Then the event pipeline (dedup/cooldown), then **one real detector per milestone** (ARP, DNS, DHCP, scans, new device), then Suricata integration, then notifiers, then rules/allowlist UI, then auth + setup wizard, then system health, then hardening + install script + systemd units.
12. Test plan and demo script for my college presentation (what to run, which alert should appear).
13. Risks, honest limitations (what each network mode can not see), and future work.

No approval step: once the plan is written and consistent with my answers, start Phase 4.

### Phase 4: Build loop (repeat for every milestone, in order)

1. Read `docs/PROGRESS.md`, `AGENTS.md`, and the milestone in `docs/PLAN.md`.
2. Re-check the docs for every library API you are about to use (rule 5).
3. Add dependencies only after their license is in `12-licenses.md` (C1), using `uv add` / `uv add --dev`.
4. Implement **only this milestone.** Do not refactor earlier work unless this milestone needs it.
5. Write tests together with the code (`pytest`). Detectors get unit tests with synthetic Scapy packets **and** a PCAP-based test where practical, covering both "attack detected" and "benign traffic not flagged."
6. Run `uv run ruff check`, `uv run ruff format`, and `uv run pytest`. Fix everything.
7. Run the milestone's acceptance command. Fix until it passes. Three failed attempts at the same problem means: write it in `docs/BLOCKERS.md` and ask me.
8. `git commit` (clear message), tick the milestone in `docs/PROGRESS.md` with the proof output, update `AGENTS.md` if layout or commands changed.
9. Print a 3-line status. Go to the next milestone.

Code quality rules: type hints everywhere; small modules (split any file over about 300 lines); every detector has a docstring explaining the attack, the detection logic, thresholds, and known false positives (this is a college project and will be read and graded); use `logging`, never `print`; handle errors explicitly; no global mutable state hiding in modules.

### Phase 5: Finish

After the last milestone:

1. `README.md`: what Gilgamesh is, architecture diagram, hardware and network setup for both modes, install on the Pi, first-run wizard walk-through, limitations.
2. `docs/DEMO.md`: the demo script from the plan, with the exact expected alert for each attack.
3. Final check: `uv run pytest` and `uv run ruff check` pass from a clean `uv sync --frozen`; every MVP detector has passing tests; the self-check below is clean.
4. Send a final report (under 25 lines): what works, what was tested and how, what was **not** tested because it needs the real Pi or a real network, and remaining risks.

**Self-check before the final report:**

- C1–C10 respected (open source only, web only, uv only, offline-first, no Node on the Pi, no Docker, fits 4 GB, runs without the Pi)?
- Safety rules respected (no host network changes, no secrets committed, no real attacks)?
- Every technical claim has a source URL and version, or an `UNVERIFIED` tag with an explanation?
- Anything claimed as "working" was actually run, with output recorded?

---

## 5. Pitfalls that are commonly gotten wrong (check each against current docs)

- Tailwind CSS v3 and v4 use **different setup syntax** (config file vs CSS-first). Pick the current version and never mix the two.
- FastAPI startup/shutdown: use the currently recommended **lifespan** approach; check whether `@app.on_event` is deprecated.
- Pydantic v1 and v2 APIs differ. Use the version FastAPI currently expects.
- Scapy's `sniff()` blocks. Never run it inside the asyncio event loop.
- Suricata rule syntax and config keys change between major versions. Verify against the docs for the version you choose.
- Do not assume a Python package has an aarch64 wheel. Check.
- htmx 1.x and 2.x differ in attributes and extensions. Check the version you vendor.
- Alpine.js has a CSP-friendly build; check whether you need it.
- SQLite with several writers needs WAL, a busy timeout, and short transactions. A sensor process and a web process will both write.
- A detector that has never been tested against benign traffic is not finished. Home networks are noisy.

---

## 6. Reminder (read once more)

**Research, then ask me your questions once, then plan, then build the entire project milestone by milestone. Verify with official docs. Open source only. Web UI only. `uv`, never `pip`. Offline-first. Fits a Raspberry Pi 4 with 4 GB. Never touch my host network, never use sudo without asking, never run real attacks. Tests and proof for every milestone. Save progress to `docs/PROGRESS.md` and `AGENTS.md` after every step. initilize a repo you have access to github-cli and git and if you really need sudo prompt me with pkexec**

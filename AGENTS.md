# AGENTS.md — Gilgamesh

Gilgamesh is a **home-network NIDS** for a Raspberry Pi 4 (4 GB). It sits inline,
detects common home-network attacks, and alerts the owner. **Detect-and-alert only:
it never blocks traffic and never degrades the connection.** Web UI only.

> Read order at the start of **every turn**: (1) `docs/PROGRESS.md`, (2) this file,
> (3) the current milestone in `docs/PLAN.md`, (4) the relevant `docs/research/*.md`.

## Hard constraints (C1–C10) — never break

- **C1 Open source only.** Record the SPDX id + source URL in
  `docs/research/12-licenses.md` *before* adding any dependency. No paid/subscriber data.
- **C2 Web UI only.** First-run setup, config, rules, alerts all in the browser.
  `install.sh` + systemd units are infrastructure, not a user interface.
- **C3 Stack:** Python 3.13 + FastAPI; **htmx**; **Alpine.js** (CSP build) for small
  client state; **Tailwind CSS v4** (CSS-first).
- **C4 `uv` only.** Never `pip`, `python -m pip`, `uv pip`, or hand-made venvs.
- **C5 Offline-first.** Vendor htmx/Alpine and commit the built Tailwind CSS. No CDN,
  no external fonts.
- **C6 No Node.js on the Pi.** Tailwind built with the standalone CLI, output committed.
- **C7 Native install, no Docker.** systemd. Whole system ≤ ~2.0 GiB RSS of 4 GB.
- **C8 Capture is an abstraction:** live interface **or** PCAP file.
- **C9 Allowed tools:** Scapy, Suricata, etc. — open source, chosen with evidence.
- **C10 Testable without the Pi.** Detectors run on synthetic Scapy packets + PCAPs
  on a normal Linux dev machine.

## Safety rules (the host machine is a real computer)

- **Never change the host's network config** (bridge, `ip link`, `iptables`/`nftables`,
  NetworkManager, `sysctl`, offloads) and **never** set promiscuous mode on a real
  interface. Write those steps as scripts/docs for the Pi; do not execute them.
- **Never use `sudo`.** Ask first with an exact explanation (prefer a `pkexec` prompt).
- **Never run attack tools** (arpspoof, bettercap, dnschef, nmap on real hosts, …)
  against any real network/device. Only synthetic Scapy packets, PCAP files, or an
  isolated lab the user sets up — and only after asking.
- **Secrets** are never hard-coded, logged, or committed. They are entered only through
  the web UI. `.gitignore` excludes the DB, config, certs, and keys.
- Never build shell commands from user input. Never `rm -rf` outside the project folder.

## Layout

```
src/gilgamesh/  models.py db.py pipeline.py config.py
                sensors/ notifiers/ web/{app,auth,routes,sse,templates} util/
static/         css/app.css  js/vendor/  js/app.js
tests/          deploy/{systemd,sysusers.d,tmpfiles.d,logrotate,suricata/}  docs/
```

## Commands — run before claiming anything is done

```
uv sync --frozen
uv run ruff check . && uv run ruff format --check .
uv run pyright
uv run pytest
```

Evidence rule: paste the real command + key output lines into `docs/PROGRESS.md`.

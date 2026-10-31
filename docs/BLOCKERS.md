# Gilgamesh — Blockers & Open Items

**Rule:** after 3 failed attempts at the same step, write it here and ask the user.
Also list anything that needs the real Pi, a real network, or a user decision.

**Last updated:** 2026-11-01 (post-audit; four confirmed bugs and the deployment
issues from `report.md` are fixed — see the last section)

---

## Needs the real Pi (cannot be checked on the dev machine)

| # | Item | Why it cannot be checked here |
|---|------|-------------------------------|
| C1 | `install.sh` end to end on a fresh Pi (users, venv build, unit enable, journald caps, watchdog drop-in) | it installs services; the dev machine is not the target |
| C2 | `systemd-sysusers` `u!` (fully locked account) needs systemd ≥ 257 | trixie ships 257, but confirm on the installed image |
| C3 | The systemd hardening set (`ProtectSystem=strict`, `StateDirectoryMode`, capabilities) actually permitting the sensor to capture | requires `CAP_NET_RAW` on the target's kernel/AppArmor profile |
| C4 | `GILGAMESH_INTERFACE=br0` naming a bridge that exists *before* first start | the install script warns and tells the owner what to run |
| C5 | Hardware watchdog actually armed (`systemctl show --property=RuntimeWatchdogUSec` reports `30s` after a reboot) | depends on the Pi firmware exposing `/dev/watchdog`; the dev machine has no such device |
| C6 | The default BPF filter compiles under the Pi's `tcpdump`/libpcap | the filter is compiled by the real `tcpdump -r` in the dev tests, but the target's libpcap version can differ |
| C7 | Sustained live-capture throughput and the drop counter under a busy LAN | needs real traffic and a Pi 4; tests use synthetic packets and PCAPs |
| C8 | A phone/laptop accepts the generated self-signed certificate after trusting it | browser trust stores differ per device |

## Needs an isolated lab (not done yet)

These are measurement tasks, not code blockers. Do them with your own devices,
never on a real network you do not own:

| # | Item | Where it is tracked |
|---|------|---------------------|
| A2 | ET Open ↔ Suricata 8 rule-format compatibility (`suricata-update` source for 8.x) | `docs/research/09-open-questions.md` §A2 |
| A4 | Measured Scapy / `AF_PACKET` packets-per-second ceiling on a Pi 4 | 09 §A4 |
| A5 | Suricata 8 RSS on 4 GB with the chosen rule subset | 09 §A5 |
| B1 | `br0` vs member-port frame duplication for `AF_PACKET` | 09 §B1 |
| B2 | USB3 NIC `gro`/`lro`/`tso` settability (`ethtool -k`) | 09 §B2 |
| B3 | Sustained bidirectional bridge throughput | 09 §B3 |
| B4 | Boot-time coverage gap | 09 §B4 |
| B5 | `trixie-backports` apt access for Suricata 8.0.7 | 09 §B5 |
| B6 | Exact systemd hardening directive values on target | 09 §B6 |
| B7 | `uv sync --frozen --offline` on aarch64 | 09 §B7 |
| B8 | `suricata-update` offline mode + atomic output swap | 09 §B8 |

> The dev machine is **x86_64 Fedora 44**; the target is **aarch64 Raspberry Pi
> OS Lite 64-bit (Debian 13 trixie, Python 3.13)**. The project pins Python 3.13
> so the two match.

## Known limitations accepted for v1

- **An inline bridge is a single point of failure.** A power cut, boot, kernel
  panic, or dead USB NIC stops forwarding until the Pi is back. The hardware
  watchdog (installed by `install.sh`, armed at the next boot) bounds a *hang* to
  one reboot; it cannot help a power loss. A UPS and, where the switch supports
  it, a **mirror/SPAN port instead of inline** are the honest mitigations. See
  `docs/INSTALL.md` → Mode B → "The honest failure mode".
- **No hardware bypass.** Standard Pi NICs cannot fail-to-wire. Gilgamesh never
  claims otherwise; research §4.3 records the trade-off.
- **Blocking SQLite calls still run in some async handlers.** Fine at one-user
  scale, and the login path (the expensive Argon2 + slowdown) now runs in a
  worker thread. Revisit if the app ever serves concurrent users.
- **Detectors are proven on synthetic packets and PCAPs, not a live attack lab.**
  That is constraint C10; the isolated-lab measurements above are the next step
  before claiming field accuracy.
- **Suricata history is deliberately ignored.** On first open the EVE tailer
  starts at end-of-file; only alerts appended after startup are delivered, so a
  month-old log can never be re-announced as new.
- **Notifications are at-least-once.** The cursor advances only after the
  delivery attempt, so a crash can duplicate one alert; it cannot silently skip
  one. Channel retries are bounded, and a permanently failing channel is logged
  rather than blocking the others.

## Fixed in the 2026-11-01 audit

| Area | What changed |
|------|--------------|
| Live TCP detection | default BPF now includes TCP handshake flags; `SensorRunnerConfig.bpf` actually reaches `make_source`; bounded live queue with a drop counter shown on Health |
| Suricata restarts | EVE tailer starts at end, uses the record's own timestamp, persists inode/offset, handles rotation |
| Incident counts | new `incidents` table with database-assigned ids; cooldown/rate-limit suppressions still count; UI shows "seen N×" |
| HTTPS | real Uvicorn TLS for off / self-signed / provided; generated key is `0600`; provided mode fails loudly instead of downgrading |
| Update rules button | starts the sandboxed `gilgamesh-rules-update.service` through a one-unit polkit rule instead of running in the web sandbox |
| Notification durability | cursor advances only after channel attempts, so a restart replays undelivered events |
| Discord webhook | only `https://discord.com/api/webhooks/<id>/<token>` is accepted; errors never echo the token |
| Login throttling | per-client lockout remains, now on the policy's own monotonic clock so it actually expires; a global delay grows once failures from many addresses accumulate, without locking the owner out |

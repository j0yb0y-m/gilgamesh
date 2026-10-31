# Architecture

Gilgamesh is a home-network intrusion-detection appliance: it observes traffic,
turns it into a small number of alerts, and shows them in a browser. It is
**detect-and-alert only** — it never blocks a packet, changes a firewall, or
rewrites a bridge.

## Two processes, one database

```
 traffic ──► gilgamesh-sensor (CAP_NET_RAW) ──┐
                                              ├──► SQLite (WAL) ──► gilgamesh-web ──► browser
 Suricata EVE log ────────────────────────────┘        │                 │
                                                       │                 └──► Discord / Telegram / SMTP
                                                       └── events, incidents, config, sessions
```

| Process | Entry point | Privilege | Job |
|---|---|---|---|
| Sensor | `gilgamesh.sensors.runner:main` | `CAP_NET_RAW` only | capture packets (or replay a PCAP), run detectors, apply rules, pipeline events, write survivors |
| Web | `gilgamesh.web.server:main` | no capabilities | browser UI, auth, delivery to channels, retention, health |
| Rules update | `gilgamesh.rules_update:main` | oneshot with Suricata write access | `suricata-update`, then reload Suricata |

The split is the main security boundary. A compromised web process cannot sniff
the network; a sensor crash does not take the UI down; the sensor can keep
detecting while the web tier restarts. The only shared state is the SQLite
database in WAL mode, which is why every writer keeps transactions short and the
delivery cursor is durable.

## Sensor path

1. **Capture** (`sensors/capture.py`, `sensors/runner.py`) reads a live
   interface or a PCAP. Live capture is filtered by a default BPF expression
   that includes ARP, DNS, DHCP, ICMP, and TCP handshake flags; the filter is
   configurable. The live queue is bounded: when the box cannot keep up, packets
   are dropped and the drop count is published for the Health page rather than
   letting memory grow without limit.
2. **Detectors** (`sensors/arp.py`, `dns.py`, `dhcp.py`, `scan_flood.py`,
   `inventory.py`) each receive one packet at a time and emit normalized
   `Event` objects (`models.py`). One broken detector is isolated and cannot stop
   the others.
3. **Rule gate** (`sensors/gate.py`) applies the owner's switches, allowlist, and
   trusted-device decisions before an event reaches the pipeline.
4. **Pipeline** (`pipeline.py`) collapses repetition in five ordered stages:
   dedup → cooldown → per-key rate limit → global limit → incident aggregation.
   The requirement is "one attack must not produce thousands of alerts". Repeats
   suppressed by a limiter still count toward the incident, so the UI can say
   "seen N×" without storing N rows.
5. **Persistence** (`db.py`) writes one `events` row for a stored alert and one
   `incidents` row per logical attack. Incident ids come from SQLite
   (`AUTOINCREMENT`), so they stay unique across sensor restarts. A second
   source, the Suricata EVE tailer (`sensors/suricata_ingest.py`), feeds the same
   gate and pipeline; it starts at end-of-file on first open and persists
   inode/offset so history is never replayed as new.

## Web path

- FastAPI + Jinja templates + htmx + Alpine (CSP build). Tailwind CSS v4 is built
  once with the standalone CLI and committed; the Pi runs no Node.js and loads no
  CDN assets.
- `web/auth.py` owns the single administrator account, Argon2id hashing, opaque
  sessions, CSRF, per-client lockout, and a global slowdown. The setup token is
  printed to the journal and required before the first account exists.
- `web/delivery.py` polls `events` by `rowid`, publishes each new event on the
  in-process SSE bus, and hands it to the notifier fan-out. The durable cursor is
  written **after** the channel attempts, making delivery at-least-once.
- `web/maintenance.py` deletes rows past the retention setting, but never deletes
  an event the delivery cursor has not passed.
- `web/tls.py` turns the Settings HTTPS choice into Uvicorn TLS options. The
  self-signed pair is generated under the state directory; "provided" mode reads
  explicit paths and refuses to start if they are unusable.
- `web/routes/health.py` exposes the one privileged operation: it asks systemd to
  start `gilgamesh-rules-update.service`, permitted by a single-unit polkit rule.
  The web sandbox never gains Suricata's write access.

## Storage (schema highlights)

| Table | Purpose |
|---|---|
| `events` | stored alerts, one row per announcement |
| `incidents` | one row per attack, with `count`, `first_ts`, `last_ts`, database id |
| `devices` | inventory, names, trust state |
| `rules` | per-rule switches and thresholds |
| `channels` | notification configuration; secrets are write-only in the UI |
| `users`, `sessions`, `login_attempts` | authentication and audit |
| `app_settings` | delivery cursor, setup token, preferences |

## Deployment modes

- **Mode B — inline bridge (recommended):** `eth0` and `eth1` are ports of
  `br0`; all traffic crosses the Pi. Maximum coverage, but the Pi is a single
  point of failure. The installer arms a hardware watchdog (bounds a hang to one
  reboot); a UPS and a mirror/SPAN port are the honest mitigations for power and
  NIC failure. The app never configures the bridge itself.
- **Mode A — tap / mirror:** one interface receives traffic (a switch mirror port
  where available). The Pi cannot take the household offline, at the cost of
  seeing less traffic.

## Constraints that shape the code

- Python 3.13, `uv` for every environment operation, FastAPI + htmx + Alpine +
  Tailwind, native systemd install, no Docker, no Node on the Pi.
- Open-source dependencies only, with SPDX ids and source URLs recorded in
  `docs/research/12-licenses.md` before a dependency is added.
- The web UI is the only user interface. `install.sh` and the systemd units are
  infrastructure; bridge creation is a documented owner step, never an app
  action.
- Detectors must be testable on a normal Linux box with synthetic Scapy packets
  and PCAPs (constraint C10); no test requires the Pi.

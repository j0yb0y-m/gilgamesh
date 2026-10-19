# Gilgamesh — demonstration script

Two ways to demonstrate Gilgamesh. **A** runs entirely on a laptop with no hardware and no
network traffic; **B** is the real deployment on the Pi. If both are available, run A first
(it cannot fail on someone else's Wi-Fi) and finish with B to show the real thing.

Both demos end in the same place: a real alert in the web UI, delivered to a real channel.

> **Safety, before anything else.** During any demo: never run attack tools
> (`arpspoof`, `bettercap`, `nmap`, `dnschef`, …) against a network you do not own, and
> never against the college/home network you are presenting on. Gilgamesh detects; the
> only traffic a demo needs is traffic that was recorded earlier, or traffic the audience
> itself creates (a phone joining Wi-Fi). Attack traffic belongs in an isolated lab.

---

## A — Laptop demo (replay a capture)

Everything here is CPU-only: the sensor reads bytes from a file, exactly as it would read
them from a bridge. This is constraint C10 — the detector is testable without the Pi.

```sh
uv sync
GILGAMESH_DATA_DIR=/tmp/gg-demo uv run gilgamesh-web      # leave running; http://127.0.0.1:8080
```

In a second terminal, replay a recorded capture instead of capturing:

```sh
GILGAMESH_DATA_DIR=/tmp/gg-demo GILGAMESH_PCAP=/path/to/arp-spoof.pcap uv run gilgamesh-sensor
```

Where to get the capture: record one in an **isolated lab** (`tcpdump -i eth0 -w lab.pcap`
while the two lab machines do nothing else), or use the capture the test suite builds for
itself — `tests/test_pcap_replay.py` assembles an ARP-spoof capture packet by packet with
Scapy and asserts that it produces a stored alert:

```sh
uv run pytest tests/test_pcap_replay.py -q     # the whole replay path, in 1 second
```

Then in the browser: the setup wizard appears (token:
`journalctl`-equivalent for a local run is the terminal output — the web process logs
`setup token '…'`), create the account, and the replayed alert appears on the dashboard.

## B — Pi demo (live)

1. `sudo ./install.sh`, then open `http://<pi-address>:8080` and complete the wizard.
   Show the one-time setup token: `journalctl -u gilgamesh-web | grep 'setup token'`.
2. **A device appears.** Join a phone to the Wi-Fi. Within seconds the dashboard shows a
   `new_device` alert (severity `low`, or `info` for a randomised MAC) with the MAC, IP and
   vendor. This is detection with no attack traffic at all.
3. **The feed is live, and controllable.** Leave the dashboard open on the projector; the
   feed updates as events arrive. Press **Pause live feed** to freeze it while you talk
   (new alerts are counted, not lost), then **Resume** and they appear.
4. **Alerts are configurable from the UI.** Open *Rules*, switch a rule off — the control
   updates in place. Open *Settings* → *Notifications*, configure Discord/Telegram/email
   and press **Send test** to deliver a real message.
5. **Everything the owner sees is a web page.** No terminal is used after the install; the
   systemd units are infrastructure, not an interface.

Optional, lab only: with two isolated lab machines, run an ARP-spoofing tool against the
lab victim and show the `arp_spoof` alert (severity `high`) arrive with its evidence.

## What to say while it runs

* **Detect and alert only** — nothing is blocked; the connection is never degraded.
* **Two engines** — custom Scapy/AF_PACKET detectors for L2–L3 attacks Suricata handles
  poorly, and Suricata's signature engine (ET Open) for the rest.
* **Evidence, not vibes** — `docs/PROGRESS.md` records the command and its output for every
  claim; `docs/research/*` cites the sources; `docs/BLOCKERS.md` lists what still needs the
  real hardware.
* **Testable without the hardware** — `uv run pytest` (unit) and
  `uv run pytest tests/e2e -m e2e --browser-channel chrome` (real browser against the real
  server) both run on a laptop.

## Screenshots

`docs/audit-screenshots/` holds the UI captures taken from a running instance (dashboard
with the live feed, rules, alerts, alert detail, settings, notifications, health, and the
first-run wizard) — useful as slides if the live demo is not possible.

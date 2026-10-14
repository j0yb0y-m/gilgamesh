# 08 — Consolidated Detection Matrix

**Purpose:** one-page cross-reference of what each engine can do, what state is needed, the home-network false-positive traps, and the proposed (tunable) defaults — merged from `docs/research/02-detection-catalogue.md` (detail lives there).
**Date:** 2026-10-14 · **Phase 1 (research only).**
**Engines:** Suricata **8.0.7** (EVE JSON + ET Open) · custom Python detectors (Scapy 2.8.0 / raw `AF_PACKET`).
Legend: **Y** = yes · **P** = partial (needs correlation/thresholds) · **N** = no · **MVP** = v1 must-have · **Later** = v1.1+.

---

## Matrix — MVP

| # | Attack | Suricata alone | Custom (Scapy/raw) | Data needed | State to maintain | Main home FP sources | Proposed default (tunable) |
|---|---|---|---|---|---|---|---|
| 1 | **ARP spoof/poisoning** | **N** — 8.0.7 has an ARP **decoder+logger** (`event_type:"arp"`, off by default) but **no ARP rule protocol/keyword** | **Y** | Ethernet src/dst MAC; ARP `op, hwsrc, hwdst, psrc, pdst` | IP→MAC binding table (+ts/counts), gateway IP+MAC, per-source gARP counters, recent-request cache, DHCP lease events | DHCP churn/lease handover, Wi-Fi roaming/repeaters/mesh, VM/failover, secondary IPs, gARP at interface-up (RFC 5227), the Pi itself forwarding ARP | Gateway MAC change → **alert immediately, high**. Non-GW binding change → 1st change outside ±5 s of a DHCP event. gARP flood → **>20 replies/10 s from one MAC**. Ethernet-vs-ARP src mismatch → 1st. Learning warm-up 300 s |
| 2 | **DNS spoofing** | **P** — parses/logs DNS v3 (`id`, `queries[]`, `answers[].ttl`); **no resolver-trust/baseline verdict** | **Y** | 5-tuple, `dns_id`, `qr`, `rcode`, `aa`, `queries[]`, `answers[]+ttl` | Outstanding-query table (per-client), resolver allowlist (from DHCP `dns_servers[]`), recent `(qname,qtype)→answerset` cache | CDN/anycast/GSLB, round-robin/LB, split-horizon + mDNS/LLMNR, multiple resolvers, DoH/DoT (invisible), 0x20/EDNS padding, CNAME chains, TTL rewrite by forwarders, IPv6 RDNSS | No matching query → 1st (window **2 s**). Non-allowlisted responder → 1st, only after allowlist populated. Conflicting answers → **≥3 differing, non-overlapping sets, same source, 30 s**, severity **low**. TTL ≤1 → enrichment flag only |
| 3 | **Rogue DHCP / starvation** | **P** — full EVE DHCP (`dhcp_type`, `client_mac`, `routers[]`, `dns_servers[]`); rule keywords only `dhcp.leasetime/renewal_time/rebinding_time`; **no trusted-server logic** | **Y** | DHCP msg type, `xid`, `chaddr`, `yiaddr`, server-id, `routers[]`, `dns_servers[]` | Trusted-server set, per-server offer counts, global DISCOVER rate + distinct-`chaddr` counter, expected gateway/DNS baseline | Two legit servers (ISP + mesh/Eero/Nest/Orbi), failover, DHCP relay, travel routers/hotspots/NAS/`dnsmasq` bridges, flapping NIC, reboot storms, MAC-randomising phones, DHCPv6/SLAAC | Rogue OFFER/ACK from untrusted server → 1st once trust set exists; else **≥2 distinct servers in 60 s**. Changed `routers[]`/`dns_servers[]` vs baseline → 1st, medium. Starvation → **>50 DISCOVER/s or >100 distinct `chaddr`/10 s**. Learning 5 min |
| 4 | **Port scans + SYN flood** | **P** — no `sfPortscan`; use `threshold`/`detection_filter`/`rate_filter` + ET `emerging-scan.rules`/`emerging-dos.rules` | **Y** | TCP flags (SYN/RST/ACK), src/dst IP, dst port, per-flow counts, handshake completion | Per-source dst-port sets; per-source dst-IP sets; per-dst SYN counters; optional handshake tracker | Speed tests/downloads, P2P/torrents, backups, OS/AV update fan-out, **constant inbound WAN scan noise** (rate-limit, don't alert-per-packet), NAT, mDNS/SSDP/NetBIOS (UDP — filter), IPv6 address-space counting | Vertical scan → **>20 distinct dst ports/src/10 s** (exclude established). Horizontal → **>20 distinct dst hosts/port/10 s**. SYN flood → **>100 SYN/s to one dst or >1000/s to HOME_NET**, and/or inbound SYN completion ratio **<0.2** |
| 5 | **New/unknown device** | **N** — no inventory concept; contributes MAC↔IP evidence via EVE `dhcp`/`arp`/`flow` | **Y** | MAC, IP(s), DHCP hostname/client-id, OUI vendor, first/last seen, optional mDNS name | `devices` inventory + `trusted` flag (owner-driven) | **MAC randomisation (biggest)** — new MAC per network/profile, guests, mesh/repeaters bridging client MACs, IoT link-local (`169.254.x`) then DHCP, IPv6 privacy addresses (RFC 4941), containers/VMs, wrong/unknown OUI for virtual MACs | **Event not rate.** Emit **info/low** on first sighting after **600 s** learning. Coalesce per MAC; if locally-administered bit set → label "likely randomised device" (low) not "unknown" (medium). New device promoting ARP/DHCP/DNS alerts inherits their severity |
| 6 | **ET Open signature alerts** | **Y** (core) | n/a | EVE `alert` object: `signature_id, rev, signature, category, severity` + flow/ether + `app_proto` | Rule-set version; per-signature enable/disable rendered from DB (`disable.conf`/`enable.conf`) | Enterprise/perimeter tuning: P2P, games, "potentially unwanted", IoT protocols, CDN/QUIC/DoH | None on the signatures themselves; per-category default severities; noisiest categories start at `threshold: type limit, track by_src, seconds 3600, count 1` |

**Licence note (C1):** ET Open is permissively licensed and **not** subscriber-gated (ET Pro is the paid oinkcode tier). Exact SPDX id **AMBIGUOUS**: shipped `BSD-License.txt` is BSD-3-Clause-style; OISF `index.yaml` says `MIT`. SID range 2000000–2099999 = ET Open; forked Snort-GPL rules are GPL. Source: doc 02 §6, doc 03 §2.1.

---

## Matrix — Later (v1.1+)

| # | Attack | Suricata alone | Custom | Notes / why it's hard | Verdict |
|---|---|---|---|---|---|
| 7 | IPv6 rogue RA / NDP spoof | **P** (`icmpv6.hdr`, `ip_proto:58` can match RA type 134; no RA awareness) | **Y** (`ICMPv6ND_RA`) | Track known router `(link-local src, MAC, prefix, lifetime)`; RA Guard is a switch feature (RFC 6105), not available on our bridge; capture of NDP in bridge mode UNVERIFIED | needs-care |
| 8 | MAC flooding / CAM overflow | **N** | **P** (heuristic) | On our bridge an upstream CAM overflow → unknown-unicast flooding: burst of new source MACs + rise in frames to unknown dst MACs + FDB thrash | fragile |
| 9 | ICMP redirect abuse | **P** (easy `itype:5` rule, weak signal) | **Y** | Redirect is normal from the real gateway; only abuse if sender ≠ gateway. RFC 792 | fragile |
| 10 | DNS tunnelling | **P** (Suricata 8 `entropy` keyword + `dns.query`) | **P** | Needs baseline; CDN/DNSSEC/SPF-DKIM TXT/IoT GUIDs, DoH hides it | fragile (proposed entropy ≥4.0 post-zone, tunable, UNVERIFIED) |
| 11 | Beaconing / unusual outbound | **N** (flow + `ja3`/`ja4` only) | **P** | Post-processing: inter-arrival regularity, consistent payloads, periodic DNS. NTP/OCSP/telemetry/push/smart-home all beacon; needs weeks of baseline | fragile (v1.1+) |

---

## Engine capability baseline (the five facts behind the table)

1. **Suricata cannot alert on ARP** in 8.0.7 — ARP is decoder+logger only (`arp` is not a rule protocol; `ether.hdr` exists only in 9.x-dev). ARP spoofing is **Gilgamesh's own module**. (doc 02 §0.1)
2. **Suricata gives parsed facts, not verdicts.** Any detection requiring a *baseline* (trusted resolver/server, gateway MAC, inventory) is implemented by Gilgamesh on top of EVE/Scapy. (doc 02 §0.4)
3. **Suricata's DHCP keyword surface is tiny** (`dhcp.leasetime`/`renewal_time`/`rebinding_time`) — no `dhcp.msgtype`. Rogue/starvation decisions are correlation. (doc 02 §0.2)
4. **Suricata DNS EVE is rich** (v3, includes `id` + `answers[].ttl`) — the correlation key is already there; the *trust* logic is ours. (doc 02 §0.2)
5. **Scapy dissects everything we need** (ARP, DHCP, DNS, ICMPv6 NDP); its Pi-4 throughput ceiling is **UNVERIFIED** and needs benchmark + BPF filters + `store=False` + out-of-loop thread (doc 04 §3).

---

## Requirement → coverage checklist (PROMPT §3.2)

| Brief requirement | Covered by | Status |
|---|---|---|
| ARP poisoning (binding change, gateway MAC change, two MACs one IP, gARP floods, unsolicited replies) | #1 custom module | MVP |
| DNS spoofing (no matching query, conflicting answers, wrong resolver, suspicious TTL) | #2 custom module | MVP (FP-sensitive) |
| Rogue DHCP server + DHCP starvation | #3 custom module | MVP |
| Port scans (vertical/horizontal) + SYN floods | #4 Suricata thresholds + custom | MVP |
| New/unknown device inventory (trusted/untrusted) | #5 custom module | MVP |
| Suricata signature alerts (ET Open) | #6 Suricata | MVP |
| IPv6 rogue RA / NDP | #7 | Later |
| MAC flooding | #8 | Later |
| ICMP redirect abuse | #9 | Later |
| DNS tunnelling | #10 | Later |
| Beaconing / unusual outbound | #11 | Later |

## Detection modules to build in v1 (derived)

`arp`, `dns`, `dhcp`, `scan_flood`, `device_inventory`, `suricata_ingest` — six detectors, each emitting the normalized event (D-004 / doc 04 §2.1) into one pipeline.

## Sources

All detail and citations live in `docs/research/02-detection-catalogue.md` (Suricata 8.0.7 docs, ET licence/index files, Scapy docs, RFC 826/5227/2131/2132/1035/6762/4861/4862/6105/792, `arpwatch(8)`). Engine versions and licences: `docs/research/03-tooling-and-versions.md`.

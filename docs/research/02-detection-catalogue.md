# 02 — Detection Catalogue (per-attack feasibility)

**Project:** Gilgamesh — home-network NIDS (detect & alert only; never blocks).
**Session:** Phase 1 research. **Date:** 2026-10-14. **Author:** blue-team subagent.
**Scope of this file:** feasibility of each attack in the brief (PROMPT §3.2), engine by engine, with the data, state, home-network false-positive sources, a *proposed* (tunable) default threshold, and a verdict.

**Evidence rule used here:** every non-obvious engine claim is cited to an official doc (docs.suricata.io, suricata.io, scapy.readthedocs.io, RFCs, vendor/Primary source). Anything I could not confirm is marked **UNVERIFIED** and listed at the end. Thresholds are **never** presented as vendor defaults — they are labelled *proposed default (tunable)* with the reasoning.

**Pinned versions studied**

| Component | Version studied | Source |
|---|---|---|
| Suricata | **8.0.7** (docs `/en/suricata-8.0.7/`) | https://docs.suricata.io/ |
| Scapy | 2.x (`latest` docs, 2.8.0) | https://scapy.readthedocs.io/ |

---

## 0. Engine capability baseline (verified before the per-attack work)

These five facts drive almost every verdict below. Read them first.

1. **Suricata 8.0 added an ARP decoder + logger, but *not* an ARP detection keyword.**
   - Release note: "ARP: decoder and logger" (Suricata 8.0.0, 2025-07-08) — https://suricata.io/2025/07/08/suricata-8-0-0-released/
   - The ARP packet is emitted to EVE as `event_type: "arp"` with fields `hw_type, proto_type, opcode, src_mac, src_ip, dest_mac, dest_ip` — https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html (§15.1.2.25 "Event type: ARP").
   - ARP logging is **disabled by default** because of volume: `- arp: enabled: no` — https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-output.html (EVE output types).
   - The rule header protocol list for 8.0.7 is `tcp, udp, icmp, ip` + L7 apps — **`arp` is not a valid rule protocol** — https://docs.suricata.io/en/suricata-8.0.7/rules/intro.html (§8.1.2 Protocol).
   - The 8.0.7 rule-keyword index has **no `arp`/`ethernet` keyword page** (pages: header-keywords, payload-keywords, dns-keywords, dhcp-keywords, mdns-keywords, …) — https://docs.suricata.io/en/suricata-8.0.7/rules/index.html. The EthernetKeywords/`ether.hdr` sticky buffer exists **only in the `latest`/9.0.0-dev docs**, not in 8.0.7 (8.0.7 §8.3 is titled "IP Keywords") — compare https://docs.suricata.io/en/suricata-8.0.7/rules/header-keywords.html with https://docs.suricata.io/en/latest/rules/header-keywords.html.
   - **Consequence:** in Suricata 8.0.7 you cannot write a rule that matches ARP fields and raises an alert. Suricata can only *log* ARP frames; the spoofing logic must live in Gilgamesh. (An `arp.opcode:` rule keyword seen on the public internet is **not** in the Suricata docs — treat as invalid.)
2. **Suricata has real DHCP and DNS parsers with rich EVE output, but the DHCP *rule* keyword surface is tiny.**
   - DHCP keywords are only `dhcp.leasetime`, `dhcp.rebinding_time`, `dhcp.renewal_time` — https://docs.suricata.io/en/suricata-8.0.7/rules/dhcp-keywords.html. There is **no** `dhcp.msgtype`/`dhcp.discover` keyword, so you cannot write a rule "alert on OFFER/ACK".
   - EVE DHCP events carry everything needed for correlation: `type, id (xid), client_mac, assigned_ip, client_ip, dhcp_type, client_id, hostname, params, requested_ip, relay_ip, next_server_ip, subnet_mask, routers[], lease_time, renewal_time, rebinding_time, dns_servers[]` — https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html (§15.1.2.24). Default logging keeps the MAC↔IP mapping; "extended" adds the rest.
   - DNS keywords are rich: `dns.opcode`, `dns.rcode`, `dns.rrtype`, `dns.query`, `dns.queries.rrname`, `dns.answers.rrname`, `dns.response.rrname`, … (several new in 8.0) — https://docs.suricata.io/en/suricata-8.0.7/rules/dns-keywords.html. EVE DNS (format **version 3** by default in 8.0) logs `type (request/response), id, flags, qr, aa, tc, rd, ra, rcode, queries[], answers[] (rrname, rrtype, ttl, rdata)` — https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html (§15.1.2.6) and https://docs.suricata.io/en/suricata-8.0.7/upgrade/8.0-dns-logging-changes.html.
   - Note: the EVE `dns.id` field **is the DNS transaction ID**, so Suricata's own logs give Gilgamesh a ready-made query↔response correlation key. (Whether Suricata also emits an *anomaly* when a response matches no request was **not** verified for DNS — see UNVERIFIED.)
3. **Suricata 8 also added an mDNS parser and mDNS keywords** (`mdns.queries.rrname`, `mdns.answers.rrname`, …), which matters a lot for home-network false positives — https://docs.suricata.io/en/suricata-8.0.7/rules/mdns-keywords.html.
4. **Suricata cannot match "new device", "rogue server" or "spoof" by itself.** It is a signature/flow engine; every attack below that depends on *knowing your own network's baseline* (trusted resolver, trusted DHCP server, gateway MAC, inventory) must be implemented by Gilgamesh on top of EVE/Scapy. Suricata gives parsed facts, not verdicts.
5. **Scapy can see and dissect all layers we need** — ARP (`scapy.layers.l2.ARP`), DHCP/BOOTP (`scapy.layers.dhcp`, options list), DNS (`scapy.layers.dns`: `DNS`, `DNSQR`, `DNSRR`; also mDNS per RFC 6762), ICMPv6 NDP (`scapy.layers.inet6`: `ICMPv6ND_RA`, etc.), ICMP — https://scapy.readthedocs.io/en/latest/api/scapy.layers.dhcp.html , …/scapy.layers.dns.html , …/scapy.layers.inet6.html , …/scapy.layers.l2.html . Capture via `sniff(filter="...", prn=..., store=0)` — https://scapy.readthedocs.io/en/latest/usage.html . Scapy's own docs show an ARP monitor and the `filter="arp or (udp and (port 67 or 68))"` pattern — https://scapy.readthedocs.io/en/latest/extending.html . The per-packet Python throughput ceiling on a Pi 4 is **not** established here (see UNVERIFIED; belongs to doc 04).

### Summary matrix (detail below)

Legend: **Y** = yes, **P** = partial (needs correlation/thresholds), **N** = no.

| # | Attack | Suricata alone | Scapy | Verdict |
|---|---|---|---|---|
| 1 | ARP spoof / poisoning | **N** (logs ARP; no rule keyword) | **Y** | **MVP-fit** (Scapy/correlation core) |
| 2 | DNS spoofing | **P** (parses/logs; no verdict) | **Y** | MVP-fit but fragile (FP-heavy) |
| 3 | Rogue DHCP / starvation | **P** (logs; no trusted-server logic) | **Y** | MVP-fit |
| 4 | Port scans / SYN flood | **P** (rules + thresholds) | **Y** | MVP-fit |
| 5 | New/unknown device | **N** (no inventory) | **Y** | **MVP-fit** (event-driven) |
| 6 | ET Open signature alerts | **Y** (core) | n/a | MVP-fit |
| 7 | IPv6 rogue RA / NDP | **P** (buffer match; no RA logic) | **Y** | needs-care |
| 8 | MAC flooding / CAM overflow | **N** | **P** | fragile |
| 9 | ICMP redirect abuse | **P** | **Y** | fragile |
| 10 | DNS tunnelling | **P** (entropy keyword) | **P** | fragile |
| 11 | Beaconing | **N** (flow logs only) | **P** | fragile |

---

# MVP items (must be in v1)

## 1. ARP spoofing / poisoning

Sub-behaviours from the brief: IP↔MAC binding change, gateway MAC change, two MACs claiming one IP, gratuitous-ARP floods, unsolicited ARP replies.

**How arpwatch-class tools define these (primary source).** The classic reference is LBNL `arpwatch`, which "keeps track of ethernet/ip address pairings" and emits:
- **new station** — "The ethernet address has not been seen before."
- **changed ethernet address** — "The host switched to a new ethernet address."
- **flip flop** — "The ethernet address has changed from the most recently seen address to the second most recently seen address."
- **new activity** — pair first seen again after ~6 months.
- syslog-only events include **ethernet mismatch** ("The source mac ethernet address didn't match the address inside the arp packet"), **reused old ethernet address**, **bogon**, and **ethernet/ip broadcast**.

Source: Debian `arpwatch(8)` man page (4th Berkeley Distribution, LBNL Network Research Group) — https://manpages.debian.org/bookworm/arpwatch/arpwatch.8.en.html . Note arpwatch ships a **`-z ignorenet/ignoremask`** option explicitly to ignore a **DHCP range** — i.e. even the original tool treats DHCP pools as an FP source to be excluded. The **numeric** flip-flop window is not in the man page (it is in the source); see UNVERIFIED.

The protocol definition of "gratuitous ARP"/ARP Announcement & ARP Probe (the unsolicited-reply case) is RFC 5227 §1.1 — https://www.rfc-editor.org/rfc/rfc5227.html .

**Can Suricata detect it alone? No.**
- Suricata 8.0.7 decodes ARP and can log `event_type:"arp"` with `opcode/src_mac/src_ip/dest_mac/dest_ip` (cite above), but there is **no ARP rule keyword and no ARP rule protocol**, so it cannot raise an *alert* on an ARP anomaly. It also does not maintain an IP↔MAC trust table, so it cannot know that a binding "changed".
- Practical use of Suricata here is **as a sensor, not a detector**: enable `- arp: enabled: yes` in EVE and feed the `arp` events into Gilgamesh's ARP state machine. Warning from the docs: ARP logging is off by default specifically because "ARP can generate a large number of events" — budget for volume on a busy LAN with many IoT devices.

**Can Scapy detect it? Yes.** Sniff `filter="arp"` and maintain state. Scapy dissects `ARP.hwsrc/hwdst/psrc/pdst/op` (op 1 = who-has, 2 = is-at) — the docs' own ARP-monitor callback reads `pkt[ARP].op in (1,2)` and `.hwsrc/.psrc` — https://scapy.readthedocs.io/en/latest/extending.html .

State/logic required:
- **Binding table:** `ip -> (mac, first_seen, last_seen, count)`. On every ARP (reply *and* request — a request's `hwsrc/psrc` is also a claim), compare `psrc→hwsrc` against the table.
- **Gateway table:** learn the gateway IP (from DHCP `routers[]`, EVE) and its MAC; a *change* to the gateway MAC is high severity. A second, different MAC asserting the gateway IP is the classic MITM signature.
- **Two-MACs-one-IP:** if a second distinct MAC asserts an IP already mapped (outside a DHCP-transition window), alert.
- **Unsolicited/gratuitous:** count ARP replies (`op=2`) whose `psrc == pdst` (announcement) or that were not preceded by a matching request within the window; rate-limit.
- **Ethernet mismatch:** compare Ethernet source MAC vs ARP `hwsrc` (arpwatch's "ethernet mismatch"); a mismatch is strong evidence of injection/tooling.
- Suppress during the host's own DHCP renewal (see FP below).

**Data needed:** Ethernet src/dst MAC, ARP `op, hwsrc, hwdst, psrc, pdst`; maintained state: IP→MAC binding table (+ timestamps/counts), gateway IP+MAC, per-source gARP counters, a short "recent ARP requests" cache for request↔reply correlation, and DHCP lease events (to explain legitimate MAC changes).

**Home-network false-positive sources**
- **DHCP churn / lease handover:** a new device can legitimately reuse an IP that was previously mapped to another MAC. (This is why arpwatch exposes `-z` for the DHCP range.)
- **Wi-Fi roaming & repeaters/mesh:** an AP or mesh node may answer ARP for clients, and clients may move between radios with the same MAC but different paths.
- **Virtualisation / failover:** a VM or a router failover can move an IP to a new MAC.
- **Multiple addresses / secondary IPs** on one host; and one host legitimately sending gARP at interface-up or address change (RFC 5227).
- **Pi itself** acting as a bridge is proxying/forwarding ARP.
- **Containers/VPN** creating extra MAC↔IP pairs.

**Proposed default thresholds (tunable)**
- **Learning/warm-up:** 5 minutes (300 s) after start, learn bindings without alerting (N.B. arpwatch uses a 6-month "new activity" horizon; 5 min is a *practical* home default).
- **Binding change for a non-gateway IP:** alert on the 1st change observed *outside* a ±5 s window around a DHCP event for that IP — but downgrade to "info" if the old MAC has not been used for > 60 s.
- **Gateway MAC change:** alert immediately, severity high (no count threshold).
- **Gratuitous/unsolicited ARP flood:** alert at **> 20 gARP replies from one source MAC in 10 s** (normal hosts send a handful at boot/roam). Rationale: RFC 5227 announcements are rare and event-driven, so a sustained burst indicates tooling (e.g., `arpspoof`/`ettercap`).
- **Ethernet-vs-ARP source mismatch:** alert on the 1st occurrence (any count > 1 is already anomalous).
- **Faithful-to-arpwatch alternative:** implement "new station" and "changed ethernet address" verbatim and use the above only for the flood case; record all events and let the user tune.

**Verdict: MVP-fit — but the detector is *Gilgamesh's*, not Suricata's.** ARP is the headline feature and Suricata cannot alert on it in 8.0.7, so this must be a first-class Scapy/correlation module. Budget code + state + FP tuning; the logic is well-defined by arpwatch + RFC 5227.

---

## 2. DNS spoofing

Sub-behaviours: response with no matching query (5-tuple + transaction-ID correlation), conflicting answers for the same query, response from a server that is not the configured resolver, suspicious TTLs.

**Can Suricata detect it alone? Partial — it parses and logs, but does not issue a spoofing verdict.**
- Suricata's DNS parser emits EVE `dns` events (format v3) containing `type` (request/response), **`id` (DNS transaction ID)**, `flags`, `rcode`, `queries[{rrname,rrtype}]`, `answers[{rrname,rrtype,ttl,rdata}]` — https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html (§15.1.2.6). This is exactly the data needed to correlate, and `id`+`queries` make "response with no matching query" computable *outside* Suricata.
- Rules can match query content/type/rcode (`dns.query`, `dns.queries.rrname`, `dns.answers.rrname`, `dns.rrtype`, `dns.rcode`, …) — https://docs.suricata.io/en/suricata-8.0.7/rules/dns-keywords.html — **but there is no Suricata feature that knows your configured resolver or your network's answer baseline.** So "response from a non-configured resolver" and "conflicting answers" are **not** Suricata detections.
- Whether Suricata flags an *unmatched DNS response* as an anomaly is **UNVERIFIED** (it does this for HTTP: anomaly `UNABLE_TO_MATCH_RESPONSE_TO_REQUEST` — §15.1.2.3.1 example). Do not rely on it until tested.

**Can Scapy detect it? Yes.** Dissect `DNS`/`DNSQR`/`DNSRR` — https://scapy.readthedocs.io/en/latest/api/scapy.layers.dns.html . Maintain a short-lived **outstanding-queries table** keyed by `(client_ip, client_port, server_ip, server_port, dns_id, qname, qtype)` and check every response against it.

State/logic required:
- **Query↔response correlation:** a response (`qr=1`) whose `(5-tuple, dns_id)` has no outstanding query (within the timeout) is suspicious. Most DNS spoofing is an off-path attacker guessing `(src port, dns_id)`; a wrong guess shows up as "no matching query" or "answer to a query we sent to a *different* server".
- **Resolver allowlist:** learn the legitimate resolver(s) from DHCP `dns_servers[]` (EVE DHCP) and/or config; alert when a DNS **response** arrives from an IP not on the list (note: on many home nets the *only* resolver seen is the router running dnsmasq/DoH-forwarder).
- **Conflicting answers:** for the same `(qname,qtype)` seen within a short window, compare answer RRsets; if the answer for an identical query differs in a way that cannot be explained by a legitimate second resolver, flag (see FP below — this is the fragile one).
- **TTL heuristics:** flag `ttl` of 0/1, or inconsistent TTLs across answers, as a *low-confidence* signal only.

**Data needed:** for each DNS message: 5-tuple, `dns_id`, `qr`, `rcode`, `aa`, `queries[]`, `answers[]` with `ttl`; maintained state: outstanding-query table (with per-client TTL/timeout), resolver allowlist, recent `(qname,qtype)→answerset` cache.

**Home-network false-positive sources (this is the hard part)**
- **CDNs / anycast / GSLB:** the same qname legitimately returns different A/AAAA sets at different times and from different resolvers. Do **not** alert on set changes alone.
- **Round-robin DNS & load balancers:** multiple A records and rotating order are normal.
- **Split-horizon DNS:** internal names (`.local`, `.lan`, NAS/router hostnames) resolve to different addresses than the public answer; and mDNS/LLMNR coexist. Must scope by suffix/zone.
- **Multiple legitimate resolvers** (ISP DNS + router + configured 8.8.8.8/1.1.1.1) and **DoH/DoT** (queries leave as HTTPS on 443, invisible to DNS parsing).
- **Resolver behaviours:** 0x20 encoding, EDNS padding, CNAME chains, negative caching, `ttl` rewriting by forwarders (so TTL is unreliable), retries to a second server after a timeout.
- **IPv6 RDNSS** supplying resolvers that DHCP didn't.
- **mDNS/Bonjour and `.local`** traffic (port 5353) is not unicast DNS and must be excluded — Suricata now has a dedicated mDNS parser for this — https://docs.suricata.io/en/suricata-8.0.7/rules/mdns-keywords.html.

**Proposed default thresholds (tunable)**
- **Response with no matching query:** alert on the **1st** such response; correlation window **2 s** (well above typical LAN RTT, below resolver retry/backoff). Rationale: a legitimate response always has a preceding query; 2 s covers a slow resolver without inviting stale collisions.
- **Response from a non-allowlisted server:** alert on the 1st, but only after the resolver allowlist has been populated (require ≥ 1 DHCP/observed resolver before enabling, else suppress).
- **Conflicting answers:** require **≥ 3 differing answer-sets for the same (qname,qtype) within 30 s**, *and* the source server is the same, *and* the sets have no overlap; severity low. (Deliberately conservative because CDNs/GSLB make any tighter rule noisy.)
- **Suspicious TTL:** report only as an enrichment flag (`ttl <= 1`), never as a standalone alert.

**Verdict: MVP-fit but fragile — needs-care.** The "no matching query" and "non-allowlisted responder" checks are reliable and should ship in v1. The "conflicting answers" / TTL checks are low-confidence heuristics and must default to *low* severity / advisory, with an interactive allowlist. The doc-08 matrix should mark this item "MVP, FP-sensitive".

---

## 3. Rogue DHCP server + DHCP starvation

**Can Suricata detect it alone? Partial.** Suricata parses DHCP and logs full EVE DHCP events (`type`, `dhcp_type`, `client_mac`, `assigned_ip`, `routers[]`, `dns_servers[]`, `lease_time`, `hostname`, …) — https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html (§15.1.2.24). **But:**
- The only DHCP **rule keywords** are `dhcp.leasetime`, `dhcp.rebinding_time`, `dhcp.renewal_time` — https://docs.suricata.io/en/suricata-8.0.7/rules/dhcp-keywords.html — so you **cannot** write a rule keyed on `dhcp_type` (OFFER/ACK/DISCOVER).
- Suricata has **no concept of a trusted DHCP server**, so "rogue" is a correlation decision, not a signature.

**Can Scapy detect it? Yes.** Sniff `filter="udp and (port 67 or 68)"` (the exact filter is shown in Scapy's own DHCP example — https://scapy.readthedocs.io/en/latest/extending.html ), or use the `scapy.layers.dhcp` `DHCP`/`BOOTP` layers and the `DHCP` options list — https://scapy.readthedocs.io/en/latest/api/scapy.layers.dhcp.html .

State/logic required:
- **Trusted-server set:** learn the legitimate DHCP server from the first server that completes a DORA exchange for a trusted host (or from config), then alert on any **DHCPOFFER/DHCPACK from a different server IP or `chaddr`/server-id**.
- **Rogue with no trust set:** fall back to "more than one distinct DHCP server answering on the segment" (very common spoof signature).
- **Starvation:** count DHCP `DISCOVER`/`REQUEST` rate and **distinct client hardware addresses (`chaddr`)** per unit time, and/or DISCOVERs that never complete a DORA. A starvation attack exhausts the pool with many fabricated MACs.
- **Both DHCPv4 (67/68) and DHCPv6** should be in scope eventually; this doc covers v4 (ports per RFC 2131 — server 67, client 68 — https://www.rfc-editor.org/rfc/rfc2131.html ; options per RFC 2132 — https://www.rfc-editor.org/rfc/rfc2132.html ).

**Data needed:** DHCP message type, `xid`, `chaddr`/client-mac, `ciaddr`, offered/assigned IP (`yiaddr`), server identifier, `routers[]`, `dns_servers[]`; maintained state: trusted-server set, per-server offer counts, global DISCOVER rate and distinct-chaddr counter, and (optional) a "expected vs offered gateway/DNS" baseline (a rogue server often hands out a *different* gateway/DNS, which is itself a strong tell).

**Home-network false-positive sources**
- **Two legitimate DHCP servers**: ISP gateway + a mesh system (Eero/Nest/Orbi) that runs its own DHCP, or a second router in "router mode".
- **ISP/router failover** to a backup DHCP; **DHCP relay** in larger homes.
- **Devices that also serve DHCP**: travel routers, phone hotspots, some NAS/mini-PCs, Docker/libvirt `dnsmasq` bridges, Windows ICS.
- **Starvation FPs:** a device with a flapping NIC or a firmware bug can emit repeated DISCOVERs; a **VM/host reboot storm** or a **Wi-Fi device that lost its lease** can spike DISCOVER rate without malice; MAC-randomising phones present *many distinct MACs* over time (see item 5) and can look like a slow starvation.
- DHCPv6 / SLAAC on IPv6 coexisting.

**Proposed default thresholds (tunable)**
- **Rogue server:** alert on the **1st** OFFER/ACK from a server not in the trusted set **once a trusted set exists** (populate after the first clean DORA, or let the user pin it in setup). If no trust set, alert only when **≥ 2 distinct DHCP servers** are seen within 60 s.
- **Rogue config (same server, different lease):** alert when an assigned `routers[]`/`dns_servers[]` differs from the learned baseline — 1st occurrence, medium.
- **Starvation:** alert at **> 50 DHCPDISCOVER/s** *or* **> 100 distinct `chaddr` in 10 s** from the segment. Rationale: a healthy home nets a handful of DHCP transactions per reboot wave; 50/s is far above organic churn yet well below a naive starvation tool that fires thousands. Apply a 5-minute learning period and exclude known/stressed clients after the FP work above.

**Verdict: MVP-fit.** Suricata supplies the parsed DHCP facts; Gilgamesh supplies trust + counts. Thresholds need care because mesh systems and MAC-randomising devices are the main noise sources; ship with the "≥ 2 servers" fallback and an interactive trusted-server approval (fits the web-UI requirement).

---

## 4. Port scans (vertical/horizontal) + SYN flood

**Can Suricata detect it alone? Partial — via signatures + thresholding, not a dedicated scan engine.**
- Suricata does **not** ship a Snort-`sfPortscan`-style preprocessor; scan detection is done with rules plus thresholding. The thresholding keywords `threshold` (`type threshold|limit|both|backoff`, `track by_src|by_dst|by_rule|by_both|by_flow`) and `detection_filter` (`track …, count N, seconds T`) exist to do exactly counters-per-source — https://docs.suricata.io/en/suricata-8.0.7/rules/thresholding.html .
- Global, config-level `threshold/event_filter` and **`rate_filter`** (change a rule's action after `count` hits in `seconds`, with a `timeout`) exist in `threshold.config` — https://docs.suricata.io/en/suricata-8.0.7/configuration/global-thresholds.html . `rate_filter` is the natural fit for "scan/flood" escalation.
- ET Open ships `emerging-scan.rules` (and `emerging-dos.rules`) which can be enabled with `suricata-update` — https://docs.suricata.io/en/suricata-8.0.7/rule-management/suricata-update.html ; see the file listing at https://rules.emergingthreats.net/open/suricata-7.0.3/rules/ .
- Suricata also emits `flow` EVE events with `pkts_toserver/pkts_toclient`, `tcp.tcp_flags`, `tcp.syn/rst/...` and `flow.state/reason` — https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html (§15.1.2.15) — useful for a supplementary analyzer.

**Can Scapy detect it with custom state? Yes.**
- **Vertical scan (one host, many ports):** count distinct destination ports per source IP in a window.
- **Horizontal scan (many hosts, one port):** count distinct destination IPs per source IP on the same port.
- **SYN flood:** count TCP SYNs (`flags==S`) per destination/source in a window, plus the *completion ratio* (SYN vs SYN-ACK vs ACK) to distinguish a real flood from a burst of legitimate connection attempts.

State/logic required: per-source sets of destination ports/IPs within a sliding window; per-destination SYN counters; optionally a TCP handshake tracker to compute completion ratio.

**Data needed:** TCP flags (SYN/RST/ACK), src/dst IP, dst port, per-flow packet counts, handshake completion.

**Home-network false-positive sources**
- **Legitimate bulk connections:** speed tests, large downloads (a browser opens many parallel connections to *few* IPs/ports — usually not a scan, but can hit an over-broad "many SYN" rule), P2P, torrents, backup tools, antivirus/OS updates fanning out to many CDN IPs.
- **Remote scans against you are constant background noise on the WAN side** — scope rules to `-> $HOME_NET` (inbound) vs `$HOME_NET ->` (outbound) deliberately; inbound internet "scan" noise from the whole IPv4 space is expected and should be *rate-limited*, not alerted per packet.
- **NAT/port-forwarding** can make many internal hosts look like one external source.
- **mDNS/SSDP/NetBIOS discovery** are multicast/broadcast, not TCP scans, but naive "many destinations" counters can catch them — must filter UDP.
- **IPv6** has enormous address space; avoid per-/64 counting mistakes.

**Proposed default thresholds (tunable)**
- **Vertical scan:** `> 20 distinct TCP dst ports from one src in 10 s` (and exclude established connections). Rationale: real apps rarely touch >20 distinct ports on one host that fast; a fast SYN scan does thousands.
- **Horizontal scan:** `> 20 distinct dst hosts from one src on the same port in 10 s`.
- **SYN flood:** `> 100 SYN/s to a single dst` **or** `> 1000 SYN/s aggregate to $HOME_NET`, and/or **inbound SYN completion ratio < 0.2**. Rationale: a healthy host completes most handshakes; a spoofed flood shows SYNs with almost no completed handshakes.
- All four are counters → use Suricata `threshold`/`detection_filter`/`rate_filter` where possible and mirror with Scapy for L2/per-source precision. Apply learning-period calibration and per-source cooldowns (the event pipeline's dedup/cooldown, doc 04) to avoid alert storms.

**Verdict: MVP-fit.** Reliable, but threshold-sensitive; must expose sensitivity presets and an "inbound scan noise" suppression in the web UI.

---

## 5. New / unknown device joined the network (inventory + trusted/untrusted state)

**Can Suricata detect it alone? No.** Suricata has no device-inventory or "first seen" concept. It can *contribute evidence*:
- EVE `dhcp` events (enabled by default) map **`client_mac` → `assigned_ip`** and carry the client **`hostname`** and `client_id` — https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html (§15.1.2.24, "default DHCP logging … enough information to map a MAC address to an IP address").
- EVE `arp` events give additional MAC↔IP pairs (enable explicitly) — same doc, §15.1.2.25.
- EVE `flow`/`alert` events carry `ether.src_mac`/`dest_mac` — §15.1.2.1.
- Syslog/EVE can also reveal mDNS names — https://docs.suricata.io/en/suricata-8.0.7/rules/mdns-keywords.html .

**Can Scapy detect it? Yes.** Sniff ARP/DHCP and record first-seen `(mac, ip, hostname, vendor-oui)`. The MAC OUI can be resolved via Scapy's `manuf` DB (`conf.manufdb`) — see the `ARPingResult.show()` example using `conf.manufdb._get_short_manuf` in https://scapy.readthedocs.io/en/latest/api/scapy.layers.l2.html .

State/logic required: an **inventory** table `mac -> {first_seen, last_seen, ips[], hostnames[], vendor, trusted:bool}`. "New device" = a MAC/IP not seen before (after the initial learning period). "Trusted/untrusted" is owner-driven (web UI), not automatic.

**Data needed:** MAC, IP(s), DHCP hostname/client-id, OUI vendor, first/last seen, optionally mDNS name and DHCP fingerprint.

**Home-network false-positive sources**
- **MAC randomisation on phones/laptops** (iOS/Android "private Wi-Fi address" / "randomised MAC") creates a **new MAC per network/profile** and sometimes per association — this is the single biggest FP source; every new random MAC looks like a "new device".
- **Guests** join constantly (should be "new, expect user approval" rather than "attack").
- **Wi-Fi repeaters/mesh nodes** may bridge client MACs and re-originate traffic.
- **IoT devices** reboot and may briefly use a link-local/`169.254.x.x` address before DHCP; IPv6 devices have multiple addresses (SLAAC + temporary privacy addresses — RFC 4941).
- **Containers/VMs** on a laptop present extra MACs.
- Vendor-OUI lookup can be wrong/unknown for virtualised/randomised MACs.

**Proposed default thresholds (tunable)**
- **No rate threshold** — this is an event, not a rate. Emit **info/low** severity on first sighting after a **10-minute learning period** at install.
- **De-duplication:** coalesce per MAC; if a "new" MAC's first frames are DHCP with a **locally-administered bit set** (bit 1 of the first octet = 1 → randomised MAC), label as "likely randomised device" (low) rather than "unknown device" (medium), to defuse the phone problem. (Locally-administered/universal bits are defined in IEEE 802-2014 / EUI-48; exact wording **UNVERIFIED** — verify in doc 05 if we implement the bit check.)
- **Promotion:** a first-seen device that also triggers ARP/DHCP/DNS modules inherits their severity.

**Verdict: MVP-fit.** Cheap, high user value, event-driven; the *only* real work is good UX for MAC randomisation and a clear trusted/untrusted toggle.

---

## 6. Signature alerts from Suricata with the Emerging Threats Open ruleset

**Can Suricata detect it? Yes — this is Suricata's core competency.** Alerts are written to EVE as `event_type:"alert"` with `alert.signature_id, alert.rev, alert.signature, alert.category, alert.severity` plus flow/ether context and `app_proto` — https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html (§15.1.2.2). Gilgamesh consumes these and maps `category`/`severity` to its own severity.

**Licence — verified open source, not subscriber-gated.**
- ET Open rules carry the **3-clause BSD licence**: the header of each rule file and the `BSD-License.txt` shipped in the ruleset both contain the standard "Redistribution and use in source and binary forms … Neither the name … endorse" text — https://rules.emergingthreats.net/open/suricata-7.0.3/rules/BSD-License.txt and https://rules.emergingthreats.net/open/suricata-7.0.3/rules/botcc.rules .
- ET's own community confirms the SID ranges: **2000000–2099999 = ET Open (BSD)**, and the forked Snort-GPL signatures (2100000–2103999 / original ≤3464) are **GPL** — https://community.emergingthreats.net/t/licensing-of-third-party-rules/2396 and https://community.emergingthreats.net/t/signature-id-allocation-ranges/491 . Some third-party feeds embedded in ET Open (e.g. 3coresec, ciarmy) are "part of ET Open for these purposes" per ET — same thread.
- The **paid** product is **ET Pro**; ET Open is the free tier — https://www.proofpoint.com/us/resources/white-papers/proofpoint-etpro-subscription-overview . So C1 (open-source-only) is satisfiable.

**Update tool — verified.** `suricata-update` is the **official** rule manager, **bundled with Suricata since 4.1**, and its **default source is ET Open**: `sudo suricata-update` downloads into `/var/lib/suricata/rules/suricata.rules` — https://docs.suricata.io/en/suricata-8.0.7/rule-management/suricata-update.html . Disable/enable via `disable.conf`/`enable.conf` (same page) — this is how Gilgamesh will implement "rule subset / sensitivity presets" without a CLI for the user.

**Data needed:** the EVE `alert` object + `src/dest ip/port`, `proto`, `app_proto`, `ether.src_mac/dest_mac`, timestamp. State: rule version (to show "rules out of date" in System health), per-signature enable/disable config rendered from the DB (D-005).

**Home-network false-positive sources:** ET Open is tuned for perimeters/enterprise; home FPs come from policy/rule categories (e.g. P2P, games, "potentially unwanted"), IoT protocols it flags, and CDN/QUIC/DoH traffic. **Mitigation:** ship a conservative default rule subset (drop `emerging-malware`/`emerging-exploit_kit`-style high-volume categories is **not** suggested — instead start with a curated enable/disable set and let the UI toggle categories). Exclusions live in `disable.conf`.

**Proposed default thresholds (tunable):** none for the signatures themselves; use per-category default severities and the pipeline's dedup/cooldown. For noisy categories start at `threshold: type limit, track by_src, seconds 3600, count 1` (a pattern used inside ET itself, e.g. `botcc.rules` uses `threshold: type limit, track by_src, seconds 3600, count 1` — https://rules.emergingthreats.net/open/suricata-7.0.3/rules/botcc.rules ).

**Verdict: MVP-fit.** Verified open-source licence + first-party updater. The open item is **Suricata-8 rule-format compatibility** (the public ET Open tree currently publishes `suricata-5.0` and `suricata-7.0.3` directories; `suricata-update` resolves the correct source for the installed engine) — verify in doc 03.

---

# Later items (v1.1+) — shorter treatment

## 7. IPv6 rogue Router Advertisement / NDP spoofing

- **Suricata: partial.** It has an `icmpv6.hdr` sticky buffer and `ip_proto:58` (ICMPv6) — https://docs.suricata.io/en/suricata-8.0.7/rules/header-keywords.html — so you can *match* RA (ICMPv6 type 134) via an `icmpv6.hdr` content match, but Suricata has no RA-awareness and (per fact #1) no L2/NDP trust table. Correlating "RA from a MAC that is not the known router" is Gilgamesh's job. **UNVERIFIED:** whether every NDP packet reaches the Pi in bridge mode (NS/NA are multicast; solicited-node multicast is typically flooded, but confirm capture).
- **Scapy: yes.** `scapy.layers.inet6` provides `ICMPv6ND_RA` (and NS/NA) — https://scapy.readthedocs.io/en/latest/api/scapy.layers.inet6.html . Maintain the known router(s): `(link-local source, MAC, prefix, lifetime)`; alert on a new source MAC advertising a prefix or on a router lifetime/`M`/`O` flag change.
- **RA Guard** is the canonical *switch* mitigation (block RAs on non-router ports) — RFC 6105 — https://www.rfc-editor.org/info/rfc6105/ ; it is **not** available on the Pi's L2 bridge and would require host firewalling (`nft`/`ebtables`), which conflicts with "detect only". Protocols: NDP = RFC 4861 — https://www.rfc-editor.org/info/rfc4861/ ; SLAAC = RFC 4862.
- **FP:** the UK home router legitimately sends RAs; mesh/APs may relay them; multiple routers (failover) legitimately advertise; ISP CPE firmware changes its RA behaviour. **Verdict: needs-care** (v1.1).

## 8. MAC flooding / CAM-table overflow

- **Suricata: no.** No CAM awareness, no signature; it cannot see a switch's forwarding table.
- **Scapy: partial/heuristic.** On a transparent bridge, a successful CAM overflow upstream causes **unknown-unicast flooding**, so the Pi suddenly sees traffic addressed to MACs it never learned on the local segment. Heuristic signals: (a) a burst of **many distinct new source MACs** in a short window; (b) a sudden rise in frames whose destination MAC is not in the segment's known-MAC set; (c) the bridge FDB filling/thrashing.
- **FP:** Wi-Fi roaming, MAC-randomising clients, virtualisation, network storms from a loop (STP), and legitimate broadcast bursts all increase "new MACs". **Verdict: fragile** (v1.1); low confidence — package as heuristic, not an attack claim.

## 9. ICMP redirect abuse

- **Suricata: partial (easy rule, weak signal).** `alert icmp any any -> any any (msg:"ICMP redirect"; itype:5; icode:0; …)` — `itype`/`icode` and type 5 "Redirect" with codes 0–3 are documented — https://docs.suricata.io/en/suricata-8.0.7/rules/header-keywords.html (ICMP types/codes tables). The hard part is *abuse*: a redirect is normal if it comes from the real gateway, malicious if from elsewhere or pointing to an attacker. Correlate source IP/MAC against the gateway.
- **Scapy: yes.** Dissect ICMP and read redirect from the embedded original-packet header; verify the sender is the configured gateway.
- **FP:** legit redirects from the router (rare on home nets), VPN/OSPF-free environments (some VPN stacks emit redirects), enterprise-style routes. RFC 792 defines the ICMP Redirect. **Verdict: fragile** (v1.1); alert only on redirects *not* from the gateway.

## 10. DNS tunnelling heuristics

- **Suricata: partial.** Suricata 8 added an **`entropy`** keyword (Shannon entropy, 0.0–8.0, with operator) — https://suricata.io/2025/07/08/suricata-8-0-0-released/ and https://docs.suricata.io/en/latest/rules/payload-keywords.html (entropy); combined with `dns.query` it can flag high-entropy/high-volume TXT/A queries. Suricata staff have published a DNS-tunnelling workflow using Suricata 8 — https://forum.suricata.io/t/suricata-webinar-apr-23-dns-did-it-with-suricata-8-and-peter-manev/6260 .
- **Scapy: partial.** Heuristics on `dns.query` label count/length, subdomain entropy, query rate, bytes-per-second, and high TXT/NULL/`ANY` usage; requires baseline.
- **FP:** CDN/DNSSEC-long names, SPF/DKIM/DMARC TXT, service discovery (mDNS/LLMNR), IoT telemetry with GUIDs, DoH (hides the query entirely), and legit DNS-based C2-detection tricks. **Verdict: fragile** (v1.1); ship as low-severity heuristic with a tunable entropy/length backstop. **UNVERIFIED:** recommended entropy cut-off (propose `>= 4.0` on the query name after removing the known zone suffix, tunable; must be calibrated against the home's own traffic).

## 11. Beaconing / unusual outbound connections

- **Suricata: no built-in.** It emits `flow` events (start/end/bytes/packets, `pkts_toserver/toclient`) — https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html (§15.1.2.15) — and TLS/`ja3`/`ja4` fingerprints (needs enabling: `app-layer.protocols.tls.ja3-fingerprints`) — same doc §15.1.2.9. Beaconing detection is a *post-processing* analysis, not a rule.
- **Scapy / EVE analysis: partial.** Detect regular inter-arrival times to the same destination (low jitter), consistent small payloads, repeated connection durations, and periodic DNS lookups; score and threshold.
- **FP:** NTP, OCSP/CRL, telemetry, weather/news apps, push-notification keepalives, smart-home polling, backup jobs, cloud sync — all beacon. Needs long windows and allowlists. **Verdict: fragile** (v1.1+); realistically needs weeks of baseline before it is trustworthy.

---

## Sources

Suricata (official):
- Rules format / protocol field / no ARP protocol: https://docs.suricata.io/en/suricata-8.0.7/rules/intro.html
- Rule keyword index (no ARP/ethernet page; DHCP/DNS/mDNS pages): https://docs.suricata.io/en/suricata-8.0.7/rules/index.html
- IP/header keywords (`icmpv6.hdr`, `itype`, `icode`, ICMP type 5): https://docs.suricata.io/en/suricata-8.0.7/rules/header-keywords.html
- DHCP keywords: https://docs.suricata.io/en/suricata-8.0.7/rules/dhcp-keywords.html
- DNS keywords: https://docs.suricata.io/en/suricata-8.0.7/rules/dns-keywords.html
- mDNS keywords: https://docs.suricata.io/en/suricata-8.0.7/rules/mdns-keywords.html
- Thresholding (`threshold`, `detection_filter`): https://docs.suricata.io/en/suricata-8.0.7/rules/thresholding.html
- Global thresholds / `rate_filter` / `suppress`: https://docs.suricata.io/en/suricata-8.0.7/configuration/global-thresholds.html
- EVE JSON format (ARP §15.1.2.25, DHCP §15.1.2.24, DNS §15.1.2.6, Alert §15.1.2.2, Flow §15.1.2.15): https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html
- EVE output config (`- arp: enabled: no`, `- dns:`, `- dhcp:`): https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-output.html
- 8.0 DNS logging changes: https://docs.suricata.io/en/suricata-8.0.7/upgrade/8.0-dns-logging-changes.html
- Rule management with suricata-update: https://docs.suricata.io/en/suricata-8.0.7/rule-management/suricata-update.html
- Suricata 8.0.0 release notes (ARP decoder+logger; mDNS; entropy): https://suricata.io/2025/07/08/suricata-8-0-0-released/
- `latest`/9.0.0-dev header keywords showing `ether.hdr` (NOT in 8.0.7): https://docs.suricata.io/en/latest/rules/header-keywords.html
- Payload keywords / `entropy`: https://docs.suricata.io/en/latest/rules/payload-keywords.html

Emerging Threats Open (ruleset + licence):
- Rule tree index (files, sizes, licence files): https://rules.emergingthreats.net/open/suricata-7.0.3/rules/
- BSD-License.txt (3-clause BSD): https://rules.emergingthreats.net/open/suricata-7.0.3/rules/BSD-License.txt
- Rule-file header carrying the BSD block: https://rules.emergingthreats.net/open/suricata-7.0.3/rules/botcc.rules
- ET community on SID ranges / licences: https://community.emergingthreats.net/t/licensing-of-third-party-rules/2396 and https://community.emergingthreats.net/t/signature-id-allocation-ranges/491
- ET Pro (paid tier) overview: https://www.proofpoint.com/us/resources/white-papers/proofpoint-etpro-subscription-overview

Scapy (official):
- Main docs / `sniff` usage: https://scapy.readthedocs.io/en/latest/usage.html
- ARP monitor example + BPF usage: https://scapy.readthedocs.io/en/latest/extending.html
- ARP layer (`ARPingResult`, `conf.manufdb`): https://scapy.readthedocs.io/en/latest/api/scapy.layers.l2.html
- DHCP/BOOTP layer: https://scapy.readthedocs.io/en/latest/api/scapy.layers.dhcp.html
- DNS layer (`DNS`,`DNSQR`,`DNSRR`): https://scapy.readthedocs.io/en/latest/api/scapy.layers.dns.html
- IPv6/NDP layer (`ICMPv6ND_RA`): https://scapy.readthedocs.io/en/latest/api/scapy.layers.inet6.html

Primary: arpwatch & RFCs:
- arpwatch(8) man page (LBNL 4th Berkeley Distribution): https://manpages.debian.org/bookworm/arpwatch/arpwatch.8.en.html
- RFC 5227 (IPv4 Address Conflict Detection; ARP Announcement/Probe — gratuitous ARP): https://www.rfc-editor.org/rfc/rfc5227.html
- RFC 2131 (DHCP; server 67 / client 68): https://www.rfc-editor.org/rfc/rfc2131.html
- RFC 2132 (DHCP options): https://www.rfc-editor.org/rfc/rfc2132.html
- RFC 1035 (DNS): https://www.rfc-editor.org/rfc/rfc1035.html
- RFC 6762 (Multicast DNS): https://www.rfc-editor.org/rfc/rfc6762.html
- RFC 4861 (Neighbor Discovery for IPv6): https://www.rfc-editor.org/rfc/rfc4861.html
- RFC 4862 (IPv6 Stateless Address Autoconfiguration): https://www.rfc-editor.org/rfc/rfc4862.html
- RFC 6105 (IPv6 Router Advertisement Guard): https://www.rfc-editor.org/info/rfc6105/
- RFC 792 (ICMP; Redirect type 5): https://www.rfc-editor.org/rfc/rfc792.html

---

## Open questions / UNVERIFIED

1. **`ether.hdr` / ARP keywords in Suricata 8.0.7.** Confirmed absent from 8.0.7 docs; present in `latest`/9.0.0-dev. Need to confirm whether any 8.0.x addendum backports an ARP/ethernet keyword. Until then: **design ARP detection without Suricata rules.**
2. **Does Suricata flag an unmatched DNS response as an anomaly** (like it does `UNABLE_TO_MATCH_RESPONSE_TO_REQUEST` for HTTP)? Test with a crafted spoofed reply before relying on it.
3. **Exact EVE config block for ARP logging** (placement inside the `types:` list, and whether VLAN/source-interface info is attached) — verify by running `suricata -T` on the target box.
4. **ET Open ↔ Suricata 8 rule-format compatibility** and the exact `suricata-update` source name/URL for the 8.x engine (public tree shows `suricata-7.0.3`/`suricata-5.0`). Belongs to doc 03.
5. **Scapy per-packet throughput ceiling on the Pi 4** (packets/s before drops) — not established here; needed to size doc 04's capture design (threads vs process, BPF, `store=False`).
6. **IPv6 in bridge mode:** are all NDP (NS/NA) messages captured, or only broadcast/multicast-flooded ones? Affects item 7.
7. **DHCPv6** coverage (ports 546/547) — not researched; decide scope.
8. **arpwatch flip-flop numeric window** — not stated in the man page (it is a source constant); do not quote a number until read from the arpwatch source.
9. **Locally-administered/randomised MAC bit check** wording (IEEE 802-2014 / EUI-48) — verify before implementing the "likely randomised device" label.
10. **DNS-tunnelling entropy cut-off** and **beaconing jitter thresholds** — no vendor defaults exist; must be calibrated on Gilgamesh's own home traffic before shipping (currently *proposed*, not verified).
11. **Suricata minimum/realistic RAM on a 4 GB Pi 4 with ET Open** — belongs to doc 03/04.

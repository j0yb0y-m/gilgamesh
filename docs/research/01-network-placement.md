# 01 — Network Placement

**Scope:** where to put the Pi so it can see traffic (Mode A inline L2 bridge vs Mode B passive mirror port); what each mode can and cannot see; fail-open behaviour under power loss; which network stack configures the bridge on current Raspberry Pi OS; which interface Suricata/Scapy capture on; NIC offloads that corrupt IDS accuracy; and the real bandwidth ceiling of a USB 3 Gigabit adapter on a Pi 4.

**Rule for this file:** every non-obvious claim is cited to an **official** source (kernel.org, manpages.debian.org, NetworkManager/RHEL, Suricata, Raspberry Pi, Cisco, Fortinet, IETF). Vendor-forum/blog measurements are used **only** for throughput, are explicitly labelled **approximate / lower confidence**, and never for configuration syntax. Anything I could not confirm is marked `UNVERIFIED` and repeated in [Open questions](#open-questions--unverified). Configuration keys and interface names are copied from the cited docs, never invented.

**Related decisions:** D-003 (Mode A is the v1 default). Cross-refs: `docs/research/04-architecture.md` (capture tier, `br0` assumption), `docs/research/03-tooling-and-versions.md` (Suricata 8.x, RPi OS Trixie).

> Status tags: **VERIFIED** = read from an official source on 2026-10-14 · **UNVERIFIED** = could not confirm · **AMBIGUOUS** = sources disagree. Numbers marked *(approx.)* come from measurements, not vendor specs.

---

## 1. Why a passively-plugged Pi sees almost nothing

A Pi that is merely plugged into a spare port on an ordinary (unmanaged) switch is a **host on one port**, not a "see everything" tap. On a switched Ethernet segment the switch builds a MAC-address table and forwards each frame only to the port that owns the destination MAC.

- **Unicast is delivered to one port only.** A switch forwards a unicast frame out only the single port on which the destination MAC was last learned. A monitor on any other port never receives it. [1]
- **Unknown-destination unicast is flooded** to all *other* ports until the MAC is learned — the classic "flooding" behaviour. [2] This is why a passive Pi sees a brief burst of traffic for unicast destinations whose MAC it/others have not yet learned, then goes quiet.
- **ARP replies are unicast.** In RFC 826 the *request* is broadcast (to `ff:ff:ff:ff:ff:ff`), but the *reply* is normally sent as a **unicast** frame to the requester's MAC. [3] So on a switched LAN a passive Pi does **not** see the ARP replies between other hosts — only the broadcast requests. This alone breaks passive ARP-poisoning detection.
- **Broadcast and multicast are flooded to every port** (subject to IGMP/multicast snooping), so a passive Pi *does* see ARP requests, DHCP Discover/Offer traffic where broadcast, mDNS/SSDP, IPv6 multicast and similar. [1][2]

**Conclusion (the premise of D-003):** a passive port sees only (a) broadcast, (b) multicast, (c) frames flooded because the destination MAC is unknown, and (d) unicast addressed to the Pi itself. It sees **almost none** of the ordinary unicast LAN↔Internet and LAN↔LAN traffic. To see traffic you must either **put the Pi in the path** (Mode A, §2) or **make the switch copy traffic to it** (Mode B, §9).

**Sources:** [1][2][3].

---

## 2. Mode A — transparent inline L2 bridge (v1 default)

### 2.1 Topology and the "transparent" idea

The Pi sits **physically between** the upstream router/modem and the downstream network:

```
   ISP modem/router            Raspberry Pi 4B                 Home LAN
   ┌─────────────┐        ┌──────────────────────┐        ┌──────────────┐
   │  LAN port   ├──eth0──┤  Linux bridge  br0    ├──eth1──┤ switch / AP  │
   │ (uplink)    │        │  (kernel netdev)      │        │ + clients    │
   └─────────────┘        │  mgmt IP on br0       │        └──────────────┘
                          └──────────────────────┘
```

- `eth0` (onboard Gigabit) faces the **upstream router**; `eth1` (USB 3 Gigabit) faces the **home LAN**. Both are enslaved to a single Linux bridge `br0`.
- A **Linux bridge is a software L2 switch implemented as a kernel network device**; it connects slave ports at layer 2 and forwards frames between them. [4]
- "Transparent" means the bridge has **no IP address of its own on the data path** and does not modify frames — it behaves like an unmanaged switch, so the router still hands out DHCP and does NAT. The Pi is *not* a router (see §10).

### 2.2 Management IP

- The bridge `br0` gets **one management IP** (DHCP or static) so the web UI and SSH are reachable. This is what the NetworkManager example does: the bridge is created, an IP method is chosen on the bridge, and the slave ports are plain L2 members. [5][7]
- **Member ports (`eth0`, `eth1`) must NOT have their own IP address / DHCP client.** In the NetworkManager recipe the port profiles are created as `type ethernet ... controller <bridge>` with no IP method — the IP lives on the bridge. [5] Putting an IP on a slave port is a misconfiguration (dual-homing), not a supported bridge topology.

### 2.3 Recommended 2-port bridge: STP off

- The **kernel** bridge has STP **disabled by default** (`IFLA_BR_STP_STATE` defaults to `0`) — the kernel bridge doc is explicit that STP is off unless enabled. [4]
- **NetworkManager** turns STP **on by default** for bridges ("By default, STP is enabled") — so if you build the bridge with `nmcli` you must **explicitly turn it off**: `bridge.stp no`. [5][6]
- **Why off:** with exactly two ports there is no loop to protect against, and STP would keep a port in blocking/listening/learning before forwarding. Note the kernel `forward_delay` (a bridge parameter documented in `ip-link(8)`, default 900 jiffies = 15 s via the `bridge` tool's view of the kernel default `forward_delay`). [12] With STP off the bridge forwards without STP state-machine convergence. Leaving STP *on* (NetworkManager's default) risks a start-up stall and is pointless here.

> **Recommended approach for the recommended topology (2 ports, NetworkManager):** create `br0`, add `eth0` and `eth1` as controller ports, put the management IP on `br0`, and set `bridge.stp no`.

### 2.4 Exact `nmcli` commands (NetworkManager — the RPi OS default, see §5)

From NetworkManager's own `nmcli-examples(7)` "Adding a bridge and two port profiles" (Example 10) [5], adapted to `br0`/`eth0`/`eth1`:

```sh
# 1. Create the bridge. No IP here yet; STP disabled per §2.3.
nmcli con add type bridge con-name br0 ifname br0
nmcli con modify br0 bridge.stp no

# 2. Attach the two NICs as ports (slaves). No IP method on the ports.
nmcli con add type ethernet con-name br0-port-eth0 ifname eth0 controller br0
nmcli con add type ethernet con-name br0-port-eth1 ifname eth1 controller br0

# 3. Give br0 the management address (DHCP shown; static also supported).
nmcli con modify br0 ipv4.method auto        # or: ipv4.addresses 192.168.1.2/24 ipv4.gateway ... ipv4.method manual
nmcli con up br0
```

`nmcli` writes the connection to `/etc/NetworkManager/system-connections/` in keyfile format. [5][7] The exact `controller` keyword (replacing the older `master`) is what current `nmcli`/`nmcli-examples(7)` documents. [5]

> **Key naming caution:** `bridge.stp` is a NetworkManager *bridge setting property* (verified in the nmcli/RHEL bridge docs [5][6]). Do not confuse it with `bridge.mcast-snooping` or the kernel `STP_STATE` attribute name used by `ip`/`bridge` [12][13]. Names differ per tool; copy them from the tool's own doc.

### 2.5 Alternative: `systemd-networkd`

If a user runs `systemd-networkd` instead, the bridge is defined by a `.netdev` unit plus a `.network` unit under `/etc/systemd/network/`:

```ini
# /etc/systemd/network/10-br0.netdev
[NetDev]
Name=br0
Kind=bridge

[Bridge]
STP=no
```

```ini
# /etc/systemd/network/10-br0.network  — management IP on the bridge
[Match]
Name=br0

[Network]
DHCP=yes

# /etc/systemd/network/10-br0-port-eth0.network — bind eth0 to the bridge
[Match]
Name=eth0

[Network]
Bridge=br0

# /etc/systemd/network/10-br0-port-eth1.network — bind eth1 to the bridge
[Match]
Name=eth1

[Network]
Bridge=br0
```

`[NetDev] Kind=bridge` and the `[Bridge] STP=` boolean are documented in `systemd.netdev(5)`; port binding via `Bridge=br0` in `systemd.network(5)`. [8][9] The default for `STP=` in `systemd.netdev(5)` is **`yes`** *(verify on target — see Open questions)*; set it explicitly.

### 2.6 Alternative: `ifupdown` (classic `/etc/network/interfaces`)

`bridge-utils` documents the classic syntax in `bridge-utils-interfaces(5)`: [10]

```ini
# /etc/network/interfaces
auto br0
iface br0 inet dhcp
    bridge_ports eth0 eth1
    # bridge_stp off   # see note below
```

Rules from that man page: the ports must **not** have their own `iface` stanzas, and `bridge_ports` lists the enslaved interfaces. [10] The `ifupdown2` variant (different suite) instead uses `bridge-ports` and `bridge-stp` (`interfaces(5)` for ifupdown2). [11]

> **Caveat:** `bridge-utils`/`ifupdown` may not be installed on a NetworkManager-based Raspberry Pi OS image (see §5). This stanza is documented for completeness, not as the default path.

### 2.7 Raw `ip`/`bridge` tooling (for scripts and verification)

`ip-link(8)` documents `ip link add name br0 type bridge [stp_state STP_STATE]` and the bridge parameters (`forward_delay`, `ageing_time`, `mcast_snooping`, …); `bridge(8)` shows/sets per-port state (`bridge link show`, port `state`, `learning`, `flood`, `mcast_flood`). [12][13]

```sh
ip link add name br0 type bridge stp_state 0
ip link set eth0 master br0
ip link set eth1 master br0
ip link set br0 up
bridge link show          # confirm each port is in "forwarding"
```

**Note:** `ip`/`bridge` changes are **not persistent** across reboot by themselves — persistence comes from NetworkManager/systemd-networkd/ifupdown (§5). Use `ip`/`bridge` for verification and diagnostics, not as the persistent configuration.

**Sources:** [4][5][6][7][8][9][10][11][12][13].

---

## 3. What Mode A CANNOT see (blindness list)

This is the honest limits section. Mode A sees **only** frames whose path crosses the Pi.

| # | Not visible | Why | Consequence for detection |
|---|---|---|---|
| B1 | **LAN↔LAN traffic that stays inside a downstream switch** | Two hosts on the same access switch talk port-to-port; the frame never reaches the Pi's uplink port. Same as §1. [1][2] | ARP poisoning, scans and lateral movement **between two clients on the same switch** are invisible. |
| B2 | **Wi-Fi client-to-client traffic that stays inside the AP** | Bridged within the AP and never forwarded upstream. Same switching logic. | Sibling Wi-Fi devices attacking each other are invisible. |
| B3 | **Traffic on VLANs the bridge does not carry** | The bridge forwards only VLANs present on its ports; tagged VLANs your ports aren't members of don't cross. | Inter-VLAN traffic and isolated IoT/guest VLANs may be missed unless the bridge ports are trunks that carry them. |
| B4 | **Anything in front of the insertion point** | If the Pi is placed *below* the router, modem↔router traffic is out of path; if placed at one uplink, other uplinks are out of path. | Placement determines coverage; document where the Pi sits. |
| B5 | **Encrypted payloads** | TLS/QUIC/DoH/DoT are opaque. | Content-based detection (DNS spoofing inside DoH, TLS SNI is partly visible, exfil content) is limited to metadata/behaviour. This is a payload limit, not a placement limit — it applies to Mode A and Mode B equally. |
| B6 | **Traffic on the Pi itself / loopback** | `lo` and host-local traffic don't traverse `br0`. | Not a detection target by design. |
| B7 | **Traffic while the bridge is down** | During power loss / boot / config teardown the path is broken (see §4). | Gap in coverage; events during the gap are lost. |
| B8 | **Frames dropped by the NIC/driver before the bridge** | CRC/PHY errors and overruns are dropped below the bridge. | Frame-level errors are not visible as IDS input (arguably fine — you can't analyse a corrupt frame). |

**Honest summary:** Mode A buys visibility of **all traffic that crosses the Pi's position** — LAN↔Internet, plus broadcast/multicast ARP/DHCP/IPv6-NDP — but it is *not* a whole-LAN tap. "Sees everything on the home network" is **false**; the correct claim is "sees everything that crosses the link it is inserted into."

**Sources:** [1][2].

---

## 4. Power loss and fail-open behaviour (plain talk, no overpromising)

Two very different failures must be separated: **a userspace process dies** vs **the Pi loses power / the kernel or bridge goes away**.

### 4.1 What genuinely works: userspace crash = fail-open

The forwarding decision is made by the **kernel bridge datapath** (`br0`), not by Gilgamesh, not by Suricata. [4] Therefore:

- If **Suricata crashes**, if **the gilgamesh sensor process crashes**, or if the **web app dies**, the kernel keeps forwarding frames between `eth0` and `eth1`. The user's network keeps working. **Silent monitoring stops**, but connectivity does not. This is the desired "detect-only, never degrade" property (constraint in the brief).
- **Caveat:** this holds only while the bridge device and its ports stay configured and up. If a network daemon (NetworkManager / systemd-networkd) **tears the bridge down** (service restart, bad config, `nmcli con down br0`), forwarding stops and the link is down. The failure mode is the *network stack*, not the sensor process.

### 4.2 What does NOT work: power loss / kernel failure = outage

- With two **ordinary** NICs (onboard + a normal USB adapter) there is **no hardware bypass**. If the Pi loses power, hibernates, kernel-panics, or `br0` is deleted, **no traffic passes** — the home network is cut off until the Pi is back and the bridge is up. **Software cannot fix this**, because the forwarding engine itself is gone.
- A **watchdog** (systemd `WatchdogSec=`, or the hardware watchdog) restarts a *hung process/service*. It does **nothing** for a power failure, a dead kernel, or a dead NIC — by definition it cannot forward packets without the CPU running.

### 4.3 Real mitigations (ranked, honest about trade-offs)

| Mitigation | What it actually fixes | What it does not |
|---|---|---|
| **Hardware bypass / fail-to-wire NIC or module** | On power loss the module uses relays to physically short the two ports, so the link keeps passing (fail-open). Commercial **built-in fail-open bypass** exists (FortiDDoS documents a copper bypass requiring matched link speeds [30]); **fail-to-wire** on power loss/reboot is a documented feature on some appliances (FortiWeb [31]). | This is hardware, *not* free software. Cost, availability for a Pi 4, and 1 Gbps ratings must be checked. **UNVERIFIED**: a specific open/retail Pi-compatible 1 Gbps fail-to-wire module. |
| **UPS (battery) on the Pi** | Keeps the Pi (and thus the bridge) alive through short power blips and lets it shut down cleanly. | Longer outages still cut the link unless the UPS outlasts them; adds cost/bulk. |
| **Accept the outage, minimise it** | Honest default for v1: if the Pi is down, the network is down; use a watchdog + auto-restart + fast boot to make the window small. | It is a real outage; the user must understand an inline box is a single point of failure. |
| **Place the Pi so an outage is tolerable** | e.g. inline only the segment you can afford to drop. | Reduces coverage. |
| **Dual/redundant paths** | Redundancy to survive link failure. | Not a Mode A property; significant complexity; out of scope for v1. |

**Bottom line:** Mode A is **fail-open for *software* failure and fail-closed (outage) for *hardware/power* failure** unless you add a hardware bypass. That is the truthful statement; any claim that "the Pi is transparent even if it dies" is **false** for standard hardware.

**Sources:** [4][30][31].

---

## 5. Which tool configures the bridge on current Raspberry Pi OS Lite?

**Answer: NetworkManager.** Current official Raspberry Pi configuration documentation uses NetworkManager and `nmcli`, refers to per-connection files under `/etc/NetworkManager/system-connections/`, and the "Network Manager" GUI; it does **not** instruct users to use `dhcpcd`. [7]

- **Default / recommended path:** NetworkManager → `nmcli` (recipe in §2.4). Verified against RPi docs [7] and NetworkManager's own examples [5].
- **Also documented (for other Debian installs / user preference):** `systemd-networkd` (§2.5) [8][9] and `ifupdown` (§2.6) [10][11].
- **Do not** assume `dhcpcd`/`ifupdown` is the active manager on a Trixie-based RPi OS image; check at build time with:

```sh
nmcli -v                     # NetworkManager present?
systemctl status NetworkManager systemd-networkd   # which is active?
```

> **`UNVERIFIED` (target image):** whether `bridge-utils` (needed for the `bridge_ports` ifupdown method in §2.6) is installed by default on the current RPi OS Lite image — it commonly is **not** on NetworkManager-based images. Confirm on the target before relying on §2.6.

**Recommendation:** configure `br0` with **NetworkManager/`nmcli`**, with `bridge.stp no`, because that is the tool current Raspberry Pi OS actually ships and documents. [5][6][7]

**Sources:** [5][6][7][8][9][10][11].

---

## 6. Which interface should Suricata / Scapy capture on? (and the duplicate-packet question)

### 6.1 Suricata's own guidance for inline/bridge deployments

- Suricata's AF_PACKET capture runs on **any Linux network device**; the config shape is `af-packet: - interface: eth0`. [14] A **bridge device (`br0`) is a valid netdev**, so `interface: br0` is legitimate.
- Suricata documents an inline IPS mode built on a **bridge/`tap`**: `copy-mode: tap` = "**no drop**" mode where "Suricata acts as a bridge"; `copy-mode: ips` honours drop verdicts. [16] Gilgamesh is **detect-only**, so the conceptual mode is `tap` (no drops).
- Suricata's tap/bridge recipe assumes **two dedicated interfaces, equal MTU, and distinct `cluster-id`s**, and warns that **GRO/LRO/TSO cause drops** in this mode. [16]

### 6.2 The duplication question

When a frame crosses the bridge, it enters on one member port and leaves on the other. The practical capture rule:

- **Capture on the bridge device `br0`, once.** That gives a single vantage point for the whole path and avoids double-counting.
- The Wireshark Ethernet capture doc notes that a NIC driver **also delivers copies of *transmitted* packets** to the capture path, and that for a **two-NIC transparent bridge "running Wireshark on just one of the NICs is enough to capture all the traffic"** — i.e. you do not need to sniff both members. [1]
- Sniffing **both** `eth0` and `eth1` (two capture instances) is what would risk seeing each frame **twice** (once on ingress, once on egress) and inflating counts/alerts. **Recommended: one capture instance on `br0`.**
- **`UNVERIFIED`:** the exact per-packet accounting when `AF_PACKET` is bound to `br0` versus to the slave ports on the target kernel (whether a single frame is delivered once or twice, and to which socket when bound to a member port). The Wireshark statement above supports "one interface is enough" but is a Wireshark-wiki source, not a kernel spec. **Confirm on the target kernel with a lab count before fixing the capture topology.**

### 6.3 Recommendation

| Component | Capture interface | Rationale |
|---|---|---|
| **Suricata (Sensor A)** | `interface: br0` (single AF_PACKET interface) | One vantage point for the whole bridged path; a netdev is all AF_PACKET needs [14]; avoids double count. |
| **Scapy (Sensor B)** | `sniff(iface="br0", ...)` | Same vantage point; `br0` is a normal netdev to libpcap/AF_PACKET. |
| **Do NOT** | bind separate captures to `eth0` **and** `eth1` | Risk of duplicate frames and inflated alert counts; run both engines on `br0`. |
| **Never** | capture on `lo` or on a management-only path | No data-path traffic. |

**Cluster IDs / symmetric hashing:** AF_PACKET's `cluster-type` defaults to `cluster_flow` (a symmetric 5-tuple hash), which Suricata recommends for performance; RSS queues should be **1**. [15] If both engines attach to `br0`, that is fine — they are independent AF_PACKET sockets, not a single cluster.

**Sources:** [1][14][15][16][17].

---

## 7. NIC offloads that hurt IDS accuracy (and how to disable them persistently)

### 7.1 What the offloads are

From the kernel's segmentation-offload documentation [18]:

| Offload | Meaning | Why it matters to an IDS |
|---|---|---|
| **TSO** (TCP Segmentation Offload) | NIC splits a large "super-frame" into MTU-sized segments in hardware. | The IDS may see an oversized/never-on-the-wire frame, or miss the real segment boundaries. |
| **GSO / UFO / USO** | Software (generic) segmentation equivalents. | Same class of problem; GSO is the software complement of TSO. |
| **GRO** (Generic Receive Offload) | Kernel **coalesces** received packets into larger ones before handing them up. | The sniffer sees **merged** packets that never existed on the wire → signature mismatch. |
| **LRO** (Large Receive Offload) | NIC-hardware coalescing of received packets. | Same as GRO but in hardware; Suricata says it must be off. |
| **Checksum offload** | NIC computes/validates L3/L4 checksums. | On capture, checksums may be reported as "not computed"/wrong, causing false "bad checksum" verdicts — but Suricata's guidance differs by capture mode (below). |

### 7.2 What Suricata officially requires

From Suricata's packet-capture performance page [15]:

- **LRO/GRO must be disabled** — coalesced packets break the engine's view of the wire.
- **Checksum offload** handling differs by capture method:
  - **AF_PACKET / PF_RING → checksum offload may stay ENABLED.**
  - **PCAP / NETMAP → checksum offload must be DISABLED.**
  Gilgamesh uses **AF_PACKET**, so checksum offload can remain on per Suricata's own guidance — but GRO/LRO must be off.
- **RSS queues should be set to 1.** [15]
- Suricata's `suricata.yaml` reference notes that **DPDK disables all offloads by default**, while **other capture interfaces (including AF_PACKET) rely on the user to configure the NIC**. [17] So it is on Gilgamesh to turn GRO/LRO off.

### 7.3 How to disable them

Runtime (via `ethtool(8)`, which documents `gro`, `lro`, `tso`, `gso on|off`) [19]:

```sh
ethtool -K eth0 gro off lro off
ethtool -K eth1 gro off lro off
ethtool -k eth0            # verify current feature state
```

Persistence options:

1. **NetworkManager** connection property (current RHEL docs document per-connection `ethtool.feature-*` via `nmcli con modify`) [20]:
   ```sh
   nmcli con modify br0-port-eth0 ethtool.feature-gro off ethtool.feature-lro off
   nmcli con modify br0-port-eth1 ethtool.feature-gro off ethtool.feature-lro off
   ```
2. **systemd oneshot unit** that runs the `ethtool -K` lines after the interfaces are up.

> **`UNVERIFIED` (target hardware):** whether the specific USB 3 NIC / driver exposes settable `gro`/`lro`/`tso` at all — some drivers report these as fixed/unsupported. Check with `ethtool -k` on the target; if a feature is `[fixed]`, it cannot be changed and its behaviour must be assessed.

**Sources:** [15][17][18][19][20].

---

## 8. USB 3 Gigabit adapter on a Pi 4 — can it sustain ~1 Gbps?

**Short answer:** roughly **line-rate in one direction** with a good chipset (**RTL8153**), *not* a guaranteed simultaneous full-duplex 1 Gbps, and the whole USB complex shares one bus and one power budget. Figures below are **measurements (approx.)**, not vendor guarantees.

### 8.1 Pi 4 USB / NIC hardware (official)

- Pi 4B specs: **2× USB 3.0 + 2× USB 2.0** ports and **Gigabit Ethernet** onboard. [21]
- Datasheet: "2× USB2 and 2× USB3 type-A sockets"; "Downstream USB current limited to approximately **1.1 A in aggregate over the four sockets**"; operating temperature **0–50 °C ambient**. [22]
- Power supply: **5.1 V / 3.0 A USB-C** (≈15 W); official guidance caps total USB peripheral draw around **1.2 A**. [25]
- All four USB-A ports hang off **one VIA VL805 PCIe-to-USB3 (xHCI) controller on a single PCIe x1 lane** (≈4 Gbps theoretical before overhead); the two USB 2.0 ports share **480 Mbit/s**; all four sockets share the current budget. [32][22]

**Which port:** use a **blue USB 3.0 port** (the lower-current, higher-bandwidth pair). Because both blue ports sit on the **same** xHCI controller and the single PCIe lane, adding *other* high-bandwidth USB devices (SSD, another NIC) competes for the same ~4 Gbps and the same ~1.1 A. [32]

### 8.2 Chipset caveats

| Chipset | Support in Pi kernel | Observed throughput *(approx.)* | Notes |
|---|---|---|---|
| **Realtek RTL8153 / RTL8152** | `CONFIG_USB_RTL8152=m` in `bcm2711_defconfig` — supported out of the box [26] | **~930–950 Mbit/s** send/receive in community measurements [28] | The better-behaved choice; closest to line rate. |
| **ASIX AX88179 / AX88180 family** | `CONFIG_USB_NET_AX88179_178A=m` — supported out of the box [26] | **~830 Mbit/s** send in measurements; suboptimal IRQ handling reported [28] | A documented **disconnect/reconnect bug** exists in the kernel bugzilla (bug 212731) and community guides [33]. |

- Onboard `eth0` itself measures **~930–942 Mbit/s** in community benchmarks *(approx.)* [27].
- **Thermals:** the SoC **begins throttling at 80 °C and clamps at 85 °C**; Pi 4 soft limit **80 °C**, hard limit **85 °C** (official frequency-management doc and Pi thermal whitepaper). [23][24] Under heavy synthetic load the Pi 4 SoC reached **72.1 °C at 60 s** in Raspberry Pi's own test. [24] Sustained full-rate bridging with no cooling can therefore approach the throttle window — **use a heatsink/fan and keep ambient below 50 °C** [22].

### 8.3 Verdict (honest)

- **One direction:** a **RTL8153** USB 3 adapter should approach **~1 Gbps line rate** *(approx.)*; AX88179 is lower and buggier. [28][33]
- **Simultaneous full-duplex 1 Gbps through the bridge:** **do not promise it.** The USB xHCI/PCIe share, the SoC's bridging CPU cost, and the shared power/thermal budget all bound real aggregate throughput. Bidirectional "2 Gbps total" is **not** a realistic expectation on a Pi 4. `UNVERIFIED` as a guaranteed figure — **measure on the target**.
- **Practical rule:** prefer a **RTL8153-based** adapter on a **blue (USB 3.0)** port; add cooling; do not co-locate a high-draw USB SSD on the same controller if you need full NIC bandwidth.

> **Confidence note:** the throughput numbers in §8.2 are **community/vendor-blog measurements** (pidramble, tomcore, Jiri Brejcha), **not** Raspberry Pi or Realtek datasheet guarantees. Treat them as ballpark and re-measure on the actual unit.

**Sources:** [21][22][23][24][25][26][27][28][32][33].

---

## 9. Mode B — passive mirror port (SPAN) when appropriate

### 9.1 When Mode B is the right choice

- The user already has a **managed switch that supports port mirroring (SPAN)** and does **not** want an inline single point of failure (Mode A §4).
- The user is willing to accept that a mirror port sees only **what is mirrored to it** (see limits below).

### 9.2 What SPAN is (official description)

Cisco's SPAN documentation: SPAN (Switched Port Analyzer) **copies** traffic from one or more **source** ports/VLANs to a dedicated **destination (monitor) port**, so an attached analyser sees a copy **without affecting the switching of the original traffic**. [29]

### 9.3 Requirements and limits

| Item | Requirement / limit | Source |
|---|---|---|
| Switch capability | A managed switch with SPAN/mirroring; unmanaged switches cannot do this | [29] |
| Destination port | Should be **dedicated** to the analyser (don't also use it for normal traffic) | [29] |
| **Speed match** | The **monitor port must be at least as fast as** the monitored port, or packets are dropped — mirroring a faster link to a slower port loses traffic | [1] |
| Oversubscription | Mirroring **many** busy ports to one monitor port can exceed its capacity → loss | [1] |
| Frame fidelity | Monitor ports may **drop malformed frames, strip VLAN tags, alter timing, or duplicate** packets — the copy is not byte-identical to the wire | [1] |
| Coverage | You see only the mirrored sources; if you mirror the **uplink**, you see LAN↔WAN; if you mirror **all ports**, you see internal traffic too — at the cost of oversubscription | [29] |

### 9.4 Mode A vs Mode B (quick comparison)

| | **Mode A — inline bridge** | **Mode B — SPAN** |
|---|---|---|
| Insertion | Physically in the path (`eth0`+`eth1`→`br0`) | Plug into a mirror port (one NIC) |
| Sees | All traffic crossing the Pi's position + broadcast/multicast | Only mirrored sources |
| Fail-open | **Software**: yes; **Power**: outage unless hardware bypass | Yes — SPAN is passive by design [29] |
| Needs | Two NICs (onboard + USB) | A **managed** switch with SPAN |
| Best for | Users without a managed switch (v1 default) | Users with a managed switch who want zero inline risk |

**Recommendation:** keep **Mode A as the v1 default** (no managed switch required; D-003) and support **Mode B** as an option for managed-switch owners. Both feed the **same** single capture interface (in Mode B that is `eth0` itself, or the single NIC attached to the monitor port).

**Sources:** [1][29].

---

## 10. Out of scope for v1 — full router mode (NAT + DHCP)

Acting as the **home router** (routing between WAN and LAN, **NAT**, running a **DHCP server**, firewall/NAT rules) is **explicitly out of scope for v1** and recorded as **future work only** (D-003). [See `docs/DECISIONS.md` D-003.]

Reasons:
- It **changes the product**: a router *degrades/blocks* traffic and owns the network's address allocation, violating the brief's "detect and alert only; never degrade the connection."
- It is a **much larger** scope (NAT, DHCP, firewall, failover) and a **much larger** attack surface on a 4 GB Pi.
- Mode A already achieves full LAN↔WAN visibility **without** becoming the router: the bridge is transparent and the existing router keeps doing NAT/DHCP. [4]

If revisited later, it would be a **separate mode**, not a change to Mode A.

**Sources:** [4]; `docs/DECISIONS.md` D-003.

---

## Sources

1. Wireshark Wiki — CaptureSetup/Ethernet (switch unicast delivery, flooding of unknown/broadcast/multicast, NIC delivers TX copies to capture, "one NIC is enough" for a 2-NIC bridge, monitor-port speed/fidelity caveats) — https://wiki.wireshark.org/CaptureSetup/Ethernet
2. Cisco — Catalyst 9200 port-based traffic control (unknown-destination unicast flooding) — https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-14/configuration_guide/sec/b_1714_sec_9200_cg/configuring_port_based_traffic_control.html
3. RFC 826 — An Ethernet Address Resolution Protocol (broadcast request, unicast reply) — https://www.rfc-editor.org/rfc/rfc826
4. Linux kernel — Networking / Bridge — https://www.kernel.org/doc/html/latest/networking/bridge.html
5. NetworkManager — `nmcli-examples(7)` (Example 10: add a bridge and two port profiles; `controller`, `bridge.stp`) — https://networkmanager.dev/docs/api/latest/nmcli-examples.html
6. Red Hat — Configuring and managing networking: configuring a network bridge with NetworkManager (STP enabled by default) — https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/configuring-a-network-bridge_configuring-and-managing-networking
7. Raspberry Pi — Configuration (NetworkManager, `nmcli`, `/etc/NetworkManager/system-connections`, Network Manager GUI) — https://www.raspberrypi.com/documentation/computers/configuration.html
8. `systemd.netdev(5)` — `[NetDev] Kind=bridge`, `[Bridge] STP=` — https://manpages.debian.org/trixie/systemd/systemd.netdev.5.en.html
9. `systemd.network(5)` — port binding via `Bridge=` — https://manpages.debian.org/bookworm/systemd/systemd.network.5.en.html
10. `bridge-utils-interfaces(5)` — `bridge_ports` in `/etc/network/interfaces` — https://manpages.debian.org/testing/bridge-utils/bridge-utils-interfaces.5.en.html
11. ifupdown2 `interfaces(5)` — `bridge-ports` / `bridge-stp` — https://manpages.debian.org/bookworm/ifupdown2/interfaces.5.en.html
12. `ip-link(8)` — `ip link add ... type bridge`, bridge parameters — https://man7.org/linux/man-pages/man8/ip-link.8.html
13. `bridge(8)` — `bridge link show`, port `state`, `learning`, `flood` — https://man7.org/linux/man-pages/man8/bridge.8.html
14. Suricata — AF_PACKET capture (`af-packet: - interface: eth0`) — https://docs.suricata.io/en/latest/capture-hardware/af-packet.html
15. Suricata — Packet capture performance (LRO/GRO off; checksum offload on for AF_PACKET/PF_RING, off for PCAP/NETMAP; RSS = 1; `cluster-type`) — https://docs.suricata.io/en/latest/performance/packet-capture.html
16. Suricata — Setting up IPS/inline for Linux (`copy-mode: tap` = no drop, acts as bridge; two interfaces, equal MTU, distinct `cluster-id`; GRO/LRO/TSO cause drops) — https://docs.suricata.io/en/latest/ips/setting-up-ipsinline-for-linux.html
17. Suricata — `suricata.yaml` reference (DPDK disables offloads; other capture methods rely on the user) — https://docs.suricata.io/en/latest/configuration/suricata-yaml.html
18. Linux kernel — Segmentation offloads (TSO/UFO/USO/GSO/GRO) — https://www.kernel.org/doc/html/latest/networking/segmentation-offloads.html
19. `ethtool(8)` — `gro`, `lro`, `tso`, `gso on|off` — https://man7.org/linux/man-pages/man8/ethtool.8.html
20. Red Hat — Configuring ethtool settings in NetworkManager connection profiles (`ethtool.feature-*`) — https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/network_troubleshooting_and_performance_tuning/configuring-ethtool-settings-in-networkmanager-connection-profiles
21. Raspberry Pi 4 Model B specifications (2× USB 3.0, 2× USB 2.0, Gigabit Ethernet) — https://www.raspberrypi.com/products/raspberry-pi-4-model-b/specifications
22. Raspberry Pi 4 datasheet RP-008341-DS-1 (USB2/USB3 sockets, ~1.1 A aggregate USB current, 0–50 °C ambient) — https://pip-assets.raspberrypi.com/categories/545-raspberry-pi-4-model-b/documents/RP-008341-DS-1-raspberry-pi-4-datasheet.pdf
23. Raspberry Pi documentation — frequency management (throttle limit 85 °C; Arm 80→85 °C) — https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/raspberry-pi/frequency-management.adoc
24. Raspberry Pi whitepaper RP-010139-WP-1 — thermal performance (Pi 4 soft 80 °C / hard 85 °C); Raspberry Pi News "Thermal testing Raspberry Pi 4" (72.1 °C at 60 s) — https://pip-assets.raspberrypi.com/categories/685-app-notes-guides-whitepapers/documents/RP-010139-WP-1-Use-case-specific%20thermal%20performance%20of%20Raspberry%20Pi%20SBCs.pdf · https://www.raspberrypi.com/news/thermal-testing-raspberry-pi-4/
25. Raspberry Pi documentation — power supplies (5.1 V / 3.0 A; USB peripheral budget) — https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/computers/raspberry-pi/power-supplies.adoc
26. Raspberry Pi linux — `arch/arm64/configs/bcm2711_defconfig` (`CONFIG_BRIDGE=m`, `CONFIG_USB_RTL8152=m`, `CONFIG_USB_NET_AX88179_178A=m`) — https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm64/configs/bcm2711_defconfig
27. pidramble — networking benchmarks (onboard eth0 ~930–942 Mbit/s) *(approx.)* — https://www.pidramble.com/wiki/benchmarks/networking
28. TomCore — Raspberry Pi 4B USB network performance (AX88179 ~834 Mbit/s; RTL8153a ~949/933 Mbit/s) *(approx.)* — https://tomcore.io/docs/articles/RaspberryPI/raspberry-pi-4b-usb-network-performance
29. Cisco — SPAN session / port mirroring (copies traffic to a dedicated destination port; does not affect source switching) — https://www.cisco.com/c/en/us/td/docs/routers/nfvis/config/3-11-1/nfvis-config-guide-3-11-1/span-session-port-mirroring.pdf
30. Fortinet — FortiDDoS built-in fail-open bypass (copper; matching link speeds) — https://docs.fortinet.com/document/fortiddos-f/8.0.0/handbook/880924/built-in-fail-open-bypass
31. Fortinet — FortiWeb fail-to-wire for power loss/reboots — https://docs.fortinet.com/document/fortiweb/8.0.5/administration-guide/33485/fail-to-wire-for-power-loss-reboots
32. Raspberry Pi — CM4 IO USB3 app note RP-008175-DS (USB3 via PCIe/xHCI; shared bus) — https://pip.raspberrypi.com/documents/RP-008175-DS-cm4iousb3-appnote.pdf
33. Linux kernel Bugzilla #212731 (AX88179 disconnect/reconnect) — https://bugzilla.kernel.org/show_bug.cgi?id=212731

---

## Open questions / UNVERIFIED

1. **`UNVERIFIED`: exact duplicate-packet semantics** when `AF_PACKET` is bound to `br0` vs to the slave ports `eth0`/`eth1` on the target kernel. The Wireshark wiki supports "one interface is enough" for a 2-NIC bridge [1], but this is not a kernel spec. **Test on the target** (count frames with `tcpdump` on `br0` vs `eth0`/`eth1`) before fixing the capture topology.
2. **`UNVERIFIED`: whether the specific USB 3 NIC/driver exposes settable `gro`/`lro`/`tso`** (`ethtool -k` may report `[fixed]`). Verify on the target; if fixed, assess its behaviour.
3. **`UNVERIFIED`: `systemd.netdev(5)` default for `STP=`** on the target's systemd version — set it **explicitly** in any case. (NetworkManager's default is documented as enabled [6]; the kernel default is disabled [4].)
4. **`UNVERIFIED`: `bridge-utils` presence on the current RPi OS Lite image** — the §2.6 ifupdown recipe assumes it; it may be absent on a NetworkManager image. Confirm on the target.
5. **`UNVERIFIED`: a specific Pi-4-compatible 1 Gbps hardware bypass / fail-to-wire module** (open or retail). Commercial fail-open exists on appliances [30][31]; a Pi form factor is not confirmed.
6. **`UNVERIFIED`: sustained bidirectional throughput** through the bridge on a Pi 4 with a given adapter — the measurement-based numbers (RTL8153 ~930–950 Mbit/s one-way) are `approx.`; real full-duplex aggregate must be measured on the unit.
7. **`UNVERIFIED`: whether the target image boots with the bridge already up before DHCP/network is available** (boot-time coverage gap) — confirm and document the actual window.
8. **`UNVERIFIED`: `nmcli` token spelling across versions** (`controller` vs legacy `master`; `bridge.stp` vs any renamed property). Confirm against the `nmcli` version actually installed on the target.
9. **`UNVERIFIED`: interaction of the bridge with multicast snooping** (kernel doc notes multicast snooping is enabled by default [4]) — confirm it does not suppress detection-relevant multicast on the target.

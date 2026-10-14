# 07 — Deployment (install script, systemd units, offline install, updates)

**Phase 1 research note — no application code.** This document designs how a
*non-expert* user gets Gilgamesh running on a Raspberry Pi 4 (4 GB), how it is
kept up to date, and how it survives an SD card. It is infrastructure only.

Cross-references:

- **doc 01 (`01-network-placement.md`)** owns everything about the bridge
  (`br0`), capture interfaces, NIC offload, fail-open, and the USB3 adapter.
  This document only *consumes* those decisions (interface names, which process
  captures, the management IP).
- **doc 04 (`04-architecture.md`)** owns the storage/SD-wear policy, the
  SQLite/WAL schema, retention numbers, RAM/CPU budgets, and privilege
  separation. This document only *implements* those choices in units and
  scripts.

---

## 0. Scope, constraints, and hard design rules

Constraints in force (from `PROMPT.md`):

| ID  | Constraint applied here |
| --- | ----------------------- |
| C2  | **Web-UI only.** No CLI/TUI/desktop/mobile app for the user. systemd units and the install script are *not* user interfaces. |
| C4  | **`uv` only.** No `pip`, no `uv pip`, no hand-made venvs. |
| C5  | **No Node.js on the Pi.** Built CSS is committed. |
| C6  | **Native install, no Docker.** systemd is the process supervisor. |
| C7  | Everything must stay stable in 4 GB RAM. |

### 0.1 Design rule — install is infrastructure, the wizard is the UI

> **The install script must never ask the user a question and must never create
> the administrator account, choose the network interface/mode, or configure an
> alert channel.** Those three things (and everything else user-facing) happen
> **only** in the web first-run wizard (see §6). The installer's only job is to
> put files on disk, create service accounts, and start units.

Consequence for the installer: it takes no interactive input, runs to
completion unattended, is safe to re-run, and leaves the system in a
"not yet configured" state that the web app detects.

---

## 1. Install script design

**Artifact:** `deploy/install.sh` (one script). `#!/usr/bin/env bash`, `set -euo pipefail`.

### 1.1 Idempotency contract

Every step must be safe to run twice. The pattern is **check → act**, never
"assume absent":

| Step | Idempotent check | Action if missing |
| --- | --- | --- |
| Create service groups/users | `getent group gilgamesh` / `getent passwd gilgamesh` | `systemd-sysusers /usr/lib/sysusers.d/gilgamesh.conf` |
| Create directories | `install -d` (no-op if present) | same |
| Install OS packages | `dpkg -s <pkg>` (or just `apt-get install`, which is itself idempotent) | `apt-get install -y --no-install-recommends` |
| Install units | compare installed file to source (checksum) | `install -m 0644` |
| Enable/start units | `systemctl is-enabled` / `is-active` | `systemctl enable --now` |
| Reload systemd | always safe | `systemctl daemon-reload` |
| Python env | `uv sync --frozen` (converges) | same |
| Bootstrap secrets | test for existing `/etc/gilgamesh/*.env` | generate once with a CSPRNG |
| Database | never touched by the installer | app migrates on start |

Rules:

- **Never overwrite user data.** The installer must not touch
  `/var/lib/gilgamesh/*.sqlite3`, `/etc/gilgamesh/*.env`, or the DB.
- **Never clobber local edits.** Only write files owned by the package layout
  (`/usr/lib/systemd/system/*.service`, `/usr/lib/sysusers.d/*.conf`,
  `/usr/lib/tmpfiles.d/*.conf`). Config the admin may edit goes under `/etc/`.
- **Non-interactive apt:** export `DEBIAN_FRONTEND=noninteractive` and pass
  `-y --no-install-recommends`.
- **Fail loudly and stop** (`set -e`). Partial installs are recoverable by
  re-running.
- Log a copy of stderr to `/var/log/gilgamesh-install.log` for the (rare)
  support case.

### 1.2 Preflight checks (abort with a clear message)

- `uname -m` is `aarch64`.
- `/etc/os-release` shows `VERSION_CODENAME=trixie` (Raspberry Pi OS Lite
  64-bit is a port of Debian 13 "trixie", kernel 6.18 — see Sources).
- Running as root (`id -u` is 0).
- Enough free space on `/` (ruleset + Python env + DB growth head-room; number
  owned by doc 03/04).
- The interfaces named by doc 01 exist (`ip link show`), otherwise warn and
  continue — the wizard re-checks at configure time.
- `uv` is present at a fixed path or is installed from the bundled copy (§2).

### 1.3 Service accounts and directories

Accounts are declarative via **`systemd-sysusers`** (idempotent, re-runnable,
uses `/etc/passwd`/`/etc/group` directly). Format verified in `sysusers.d(5)`:
`u name ID GECOS home shell`, where the ID field may be `-` for **automatic
UID/GID allocation** (the recommended value), and an `m user group` line adds a
user to a group. The account type may be `u!` to create a **fully locked**
account — also recommended, since service accounts should not be able to log
in. The file is idempotent by design: "systemd-sysusers will do nothing if the
specified users or groups already exist or the users are members of specified
groups".

`/usr/lib/sysusers.d/gilgamesh.conf`:

```
# Type Name              ID  GECOS                                 Home                       Shell
u! gilgamesh            -   "Gilgamesh web/API service"           /var/lib/gilgamesh         /usr/sbin/nologin
u! gilgamesh-sensor     -   "Gilgamesh packet-capture service"    /var/lib/gilgamesh-sensor  /usr/sbin/nologin
m  gilgamesh-sensor     gilgamesh
```

A `u` line implicitly creates a group of the same name, so this yields two
login-disabled service accounts plus the groups `gilgamesh` and
`gilgamesh-sensor`. The `m` line puts the sensor into the **shared `gilgamesh`
group** — that group is how the two separately-sandboxed processes get access to
the single object they must share (the hand-off socket; see §3.2).

**Directories.** Private per-unit state/log/cache/runtime directories are created
declaratively by the units themselves (`StateDirectory=`, `LogsDirectory=`,
`CacheDirectory=`, `RuntimeDirectory=`, verified in `systemd.exec(5)`), so the
installer only needs `install -d` for the code+config locations
(`/opt/gilgamesh`, `/etc/gilgamesh`).

The **one shared directory** — `/run/gilgamesh`, which holds the sensor→web Unix
socket — is deliberately *not* created via either unit's `RuntimeDirectory=`.
Two units declaring the same `RuntimeDirectory=` would both claim ownership of it
and it would be removed when the first declarer stops (`RuntimeDirectory=`
directories are removed on stop unless `RuntimeDirectoryPreserve=` is set,
verified). Instead a `tmpfiles.d` fragment creates it at boot, with a lifetime
independent of any service — the documented use case for `tmpfiles.d` ("files
whose lifetime is independent of any service"):

`/usr/lib/tmpfiles.d/gilgamesh.conf`:

```
# Type Path               Mode User       Group      Age Argument
d      /run/gilgamesh      0770 gilgamesh  gilgamesh  -   -
```

`0770` gives the owner (`gilgamesh`) and the shared group full access while
excluding everyone else; `/run` is tmpfs, so the directory is recreated empty on
every boot. (Format `d path mode user group age argument` verified in
`tmpfiles.d(5)`.)

### 1.4 Skeleton (illustrative, not final code)

```bash
#!/usr/bin/env bash
set -euo pipefail
readonly SRC="$(cd "$(dirname "$0")/.." && pwd)"   # repo root
[[ "$(uname -m)" == aarch64 ]] || { echo "aarch64 only"; exit 1; }
[[ "$(id -u)" == 0 ]] || { echo "run as root"; exit 1; }

MODE="${1:---online}"        # --online | --offline
# 1. accounts (declarative, idempotent)
install -m 0644 "$SRC/packaging/sysusers/gilgamesh.conf" /usr/lib/sysusers.d/
systemd-sysusers
# 2. OS packages
if [[ "$MODE" == "--offline" ]]; then
  # local .debs; bundle must be dependency-complete (invocation to be verified in build)
  apt-get install -y --no-install-recommends ./vendor/debs/*.deb
else
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      suricata suricata-update libcap2-bin logrotate ca-certificates
fi
# 3. code
install -d -m 0755 /opt/gilgamesh /etc/gilgamesh
cp -a "$SRC/app/." /opt/gilgamesh/            # idempotent for drift (see §7)
# 4. Python env (uv only)
if [[ "$MODE" == "--offline" ]]; then
  uv sync --frozen --offline --no-index --find-links vendor/wheels/
else
  uv sync --frozen
fi
# 5. bootstrap secrets (only if missing)
[[ -f /etc/gilgamesh/gilgamesh.env ]] || write_env_once
# 6. units + declarative filesystem snippets
install -m 0644 "$SRC/packaging/systemd/"*.service /usr/lib/systemd/system/
install -m 0644 "$SRC/packaging/systemd/"*.timer   /usr/lib/systemd/system/
install -m 0644 "$SRC/packaging/tmpfiles/gilgamesh.conf" /usr/lib/tmpfiles.d/
install -m 0644 "$SRC/packaging/journald/gilgamesh.conf" /etc/systemd/journald.conf.d/
install -m 0644 "$SRC/packaging/logrotate/gilgamesh"     /etc/logrotate.d/
systemd-tmpfiles --create /usr/lib/tmpfiles.d/gilgamesh.conf   # create /run/gilgamesh now
systemctl daemon-reload
systemctl enable --now gilgamesh-web.service gilgamesh-sensor.service
systemctl enable --now gilgamesh-rules-update.timer
echo "Gilgamesh installed. Complete setup in the web UI (see /etc/gilgamesh/README)."
```

`systemctl daemon-reload` and `systemctl enable --now` are verified
subcommands (`systemctl(1)`, trixie). `systemd-sysusers` and the
`u … -` line format are verified (`sysusers.d(5)`, trixie), as is
`systemd-tmpfiles --create <configfile>` (`systemd-tmpfiles(8)`: a path argument
makes it use that file directly).

---

## 2. Offline install

Goal: install **and update** on a home LAN with **no internet**, using only
artifacts carried on-site (USB stick / LAN host).

There are **four** artifact classes; each is handled separately.

### 2.1 Debian packages

Offline bundle: `vendor/debs/` containing the `.deb` files and all their
dependencies. `apt-get install ./file.deb` resolves dependencies from the
local install set; the bundle must therefore be **dependency-complete**.

For the target (Debian 13 trixie, arm64), the Suricata package depends on a
large set (verified from the `1:8.0.7-1~bpo13+1` arm64 control data):
`libpcap0.8t64`, `libnetfilter-queue1`, `libnfnetlink0`, `libbpf1`, `libxdp1`,
`libcap-ng0`, `libyaml-0-2`, `libmagic1t64`, `libhiredis1.1.0`,
`libhwloc15`, `libnuma1`, the DPDK `librte-*25` libraries, etc. Also include
`suricata-update`, `libcap2-bin`, `logrotate`, `ca-certificates`.

**Version reality check (important — affects D-002):**

| Suite | `suricata` | `suricata-update` |
| --- | --- | --- |
| `trixie` (stable) | `1:7.0.10-1+deb13u4` | `1.3.4-1+deb13u1` |
| `trixie-backports` | `1:8.0.7-1~bpo13+1` | `1.3.8-1~bpo13+1` |

So `apt install suricata` on stock Raspberry Pi OS Lite (trixie **stable**)
gives **Suricata 7.0.10**, not 8.x. To honour D-002 (Suricata 8.x) you must
either enable `trixie-backports` (`deb … trixie-backports main`, architecture
`arm64` is published) or ship/build 8.0.7 yourself. **This must be decided in
doc 03 before the installer is written.** See Open questions.

### 2.2 Python dependencies (wheelhouse + uv cache)

`uv sync` reads the universal `uv.lock`. Install offline with:

```
uv sync --frozen --offline --no-index --find-links vendor/wheels/
```

Verified flag semantics (`uv` CLI reference):

- `--frozen` — "Sync without updating the `uv.lock` file"; uses lockfile as
  source of truth and errors if it is missing.
- `--offline` — "Disable network access … uv will only use locally cached data
  and locally available files."
- `--no-index` — "Ignore the registry index (e.g., PyPI), instead relying on
  direct URL dependencies and those provided via `--find-links`."
- `--find-links` — local directory of wheels.

**Populating the wheelhouse is the open problem.** `uv` has **no `download`
subcommand** (the pip-compatibility surface is only `compile`, `sync`,
`install`, `uninstall`, `freeze`, `list`, `show`, `tree`, `check`), and C4
forbids `pip`/`uv pip`. Two candidate methods:

1. **Same-arch seeding (recommended, simplest to trust).** On an
   internet-connected aarch64 machine (a Pi, or an aarch64 VM), run
   `uv sync --frozen` against the project. That populates the uv cache and/or
   the local link directory with aarch64 wheels; copy it to the bundle. Then
   `--offline` install works on the Pi with no network.
2. **Cross-arch seeding with `--python-platform`** (verified to exist on
   `uv sync`/`uv run`): run `uv sync --frozen --python-platform
   aarch64-unknown-linux-gnu` on an x86_64 build host so uv selects
   *target-compatible* wheels. The man page warns the *installed* distributions
   may be incompatible with the *current* platform (intended for advanced use).
   Whether the resulting cache/link tree is a faithful aarch64 wheelhouse is
   **UNVERIFIED** — must be built and tested.

`uv export --format requirements.txt` (verified) can emit a requirements file
from the lock for review/audit, but it does not itself download wheels.

### 2.3 Python interpreter

`uv` "managed" interpreters are downloaded from the Astral
`python-build-standalone` project at install time. For an air-gapped Pi you
either (a) pre-install the managed interpreter while online and ship the
uv Python directory, or (b) use the OS Python with `--no-managed-python`
(= `python-preference = only-system`), verified options. `--no-python-downloads`
disables all automatic interpreter downloads (verified). Which OS Python
trixie ships, and its exact version, is owned by **doc 03**.

### 2.4 Rules

The Emerging Threats Open ruleset is fetched by `suricata-update`. Offline, the
bundled ruleset must be applied from a local source. `suricata-update`'s exact
offline/`--local` invocation is **UNVERIFIED** here (owned by doc 02/03); the
bundle will carry a signed rules tarball plus its checksum and the installer
will place it where the rules-update unit reads it (§4).

### 2.5 Bundle layout and integrity

```
vendor/
  debs/            # dependency-complete .deb set (arm64)
  wheels/          # aarch64 wheels (uv --find-links target)
  uv-python/       # optional: pre-seeded uv-managed interpreter
  rules/           # ET Open tarball + signature
  manifest.sha256  # checksums of everything above
  manifest.sha256.asc  # detached GPG signature of the manifest
```

The installer verifies `manifest.sha256` (and its signature) before installing
anything. No network access is attempted in `--offline` mode.

---

## 3. systemd unit templates

**Suricata is *not* our unit — the distro ships it.** `suricata.service` is
confirmed present in the trixie arm64 package index under `/usr/lib/systemd/system/`.
We therefore use a **drop-in**, never a conflicting full unit.

### 3.1 `gilgamesh-web.service` (unprivileged; no capture)

```ini
[Unit]
Description=Gilgamesh web UI and API
After=network-online.target gilgamesh-sensor.service
Wants=network-online.target

[Service]
Type=simple
User=gilgamesh
Group=gilgamesh
WorkingDirectory=/opt/gilgamesh
EnvironmentFile=/etc/gilgamesh/gilgamesh.env
ExecStart=/usr/local/bin/uv run --no-sync gilgamesh-web
Restart=on-failure
RestartSec=5s
StateDirectory=gilgamesh
LogsDirectory=gilgamesh
CacheDirectory=gilgamesh
# NB: no RuntimeDirectory= here. The shared /run/gilgamesh hand-off socket dir is
# created by tmpfiles.d (see §1.3), so it is not tied to this unit's lifetime.

# --- hardening (all directives below verified in systemd.exec(5), v257) ---
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ReadWritePaths=/var/lib/gilgamesh /var/log/gilgamesh /run/gilgamesh
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes          # see caveat below
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
```

- `uv run --no-sync` (verified) implies `--frozen` and does not touch the
  environment at start-up — good for a service. Alternatively point `ExecStart`
  at the console-script in the uv-created `.venv` (still uv-managed).
- `MemoryDenyWriteExecute=yes` is safe for CPython but **breaks any dependency
  that generates code at runtime** (JIT). Confirm no such dependency exists
  (doc 03) or drop the line. **UNVERIFIED for the final dependency set.**
- `ProtectSystem=strict` + explicit `ReadWritePaths=` is the recommended
  combination; `StateDirectory=`/`LogsDirectory=`/`CacheDirectory=` also carve
  themselves out of `ProtectSystem=` automatically (verified).
- **Write scope vs. the wizard.** Under `ProtectSystem=strict` this unit can
  write only `/var/lib/gilgamesh`, `/var/log/gilgamesh` and `/run/gilgamesh`.
  The first-run wizard must therefore **not** be assumed to write `/etc/…`
  directly: either derived config is rendered under `StateDirectory=`
  (`/var/lib/gilgamesh/…`, and the consuming units/Suricata are pointed at it —
  doc 03), or a narrowly-scoped root helper applies files under `/etc`. The
  wizard's "reload the affected units" step needs the same helper: a sandboxed,
  unprivileged service cannot talk to the privileged service manager. **Mechanism
  = doc 04 (privilege separation); UNVERIFIED here.**

### 3.2 `gilgamesh-sensor.service` (capture; minimal capabilities)

```ini
[Unit]
Description=Gilgamesh packet-capture sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=gilgamesh-sensor
Group=gilgamesh-sensor
SupplementaryGroups=gilgamesh
WorkingDirectory=/opt/gilgamesh
EnvironmentFile=/etc/gilgamesh/gilgamesh.env
ExecStart=/usr/local/bin/uv run --no-sync gilgamesh-sensor
Restart=on-failure
RestartSec=5s
StateDirectory=gilgamesh-sensor
LogsDirectory=gilgamesh-sensor
RuntimeDirectory=gilgamesh-sensor

# capabilities: raw capture, no root
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes

ProtectSystem=strict
# own state/log dirs are auto-carved by StateDirectory=/LogsDirectory=; the only
# path we must add back explicitly is the shared socket dir created by tmpfiles.d.
ReadWritePaths=/run/gilgamesh
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET

[Install]
WantedBy=multi-user.target
```

- `AmbientCapabilities=` is documented as "useful if you want to execute a
  process as a non-privileged user but still want to give it some
  capabilities" (verified). This is the modern replacement for `setcap` on the
  interpreter binary — **prefer ambient caps**; if `setcap(8)` is used instead,
  its synopsis is `setcap [-q] [-n <rootuid>] [-v] {capabilities|-|-r} filename …`
  (verified).
- The **exact** minimal capability set (`CAP_NET_RAW` alone vs.
  `+CAP_NET_ADMIN`) depends on doc 01 (promiscuous mode, interface up/down,
  AF_PACKET vs. libpcap). Marked in Open questions.
- `AF_PACKET` is deliberately allowed **only** here (the man page calls it
  "exotic and sensitive" and recommends limiting it).
- **Directory model (reconciled).** This unit writes to exactly three places:
  its private `/var/lib/gilgamesh-sensor` (`StateDirectory=`), its private
  `/var/log/gilgamesh-sensor` (`LogsDirectory=`), and the shared
  `/run/gilgamesh` (`ReadWritePaths=`). The first two are carved out of
  `ProtectSystem=strict` automatically; `/run/gilgamesh` is *not*, so it is the
  only explicit `ReadWritePaths=` entry here. The sensor joins the same
  `gilgamesh` group as the web unit (`SupplementaryGroups=`, also inherited from
  the `m` line in `sysusers.d`), which is what lets an unprivileged, sandboxed
  process place the hand-off object where the web unit can reach it.
- **Socket vs. shared DB is doc 04's call.** This document fixes only the
  *systemd-level* facts (group, path, modes, capabilities). Whether the two
  processes hand off over an `AF_UNIX` socket in `/run/gilgamesh`, or share the
  SQLite file directly (and the socket/file modes that implies), is the
  privilege-separation decision owned by doc 04 — **UNVERIFIED here**.

### 3.3 Suricata hardening drop-in

Path: `/etc/systemd/system/suricata.service.d/10-gilgamesh.conf`. Overriding via
drop-in means we inherit the vendor unit's `Type=notify`, `ExecStart`,
`ExecReload`, `PIDFile`, and `Restart=on-failure` (extracted from the shipped
`suricata.service`; see Sources) and only *add* hardening.

```ini
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
# /etc/suricata stays read-only (ProtectSystem= does not affect *read* access).
ReadWritePaths=/var/lib/suricata /var/log/suricata /var/run/suricata
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET AF_NETLINK
```

Because the shipped unit already sets `ProtectSystem=full` and
`ProtectHome=true`, this drop-in tightens further. **Caveat:** Suricata may need
capabilities and syscalls beyond `@system-service` (privilege dropping, BPF/XDP,
AF_NETLINK route lookups). The exact safe set must be validated by running with
the drop-in and inspecting `systemd-analyze security suricata.service` plus the
journal. **UNVERIFIED** (do not ship as-is without a boot test).
`MemoryDenyWriteExecute=` is intentionally omitted for Suricata (hyperscan/JIT
risk).

### 3.4 `gilgamesh-rules-update.service` + `.timer`

Service (oneshot) runs the updater and reloads rules; timer triggers it daily
(§4). Timer directives `OnCalendar=`, `Persistent=`, `RandomizedDelaySec=`,
`AccuracySec=`, `Unit=` are all verified in `systemd.timer(5)` (trixie).

```ini
# gilgamesh-rules-update.service
[Unit]
Description=Update Gilgamesh/Suricata rules and reload

[Service]
Type=oneshot
User=gilgamesh-sensor
Group=gilgamesh-sensor
ExecStart=/usr/local/bin/uv run --no-sync gilgamesh-rules-update
```

```ini
# gilgamesh-rules-update.timer
[Unit]
Description=Daily Gilgamesh rules update

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h
AccuracySec=1min

[Install]
WantedBy=timers.target
```

- `Persistent=true` catches up if the Pi was off (verified: stores last
  trigger time on disk and triggers immediately if a run was missed).
- `RandomizedDelaySec=1h` avoids a fixed thundering herd at 00:00.
- Do **not** set `RandomizedDelaySec` and expect exact timing; default
  `AccuracySec` is already relaxed. `FixedRandomDelay=` exists if you need a
  stable per-host delay (verified).

---

## 4. Rules update

- Engine: Suricata (version per §2.1 decision). Signature reload does **not**
  require a restart.
- Database of rules: `/var/lib/suricata/rules/` with the rendered
  `suricata.r`; Suricata config keys `default-rule-path` and
  `rule-files:` are owned by doc 03.
- Reload mechanism (verified, Suricata docs): the unix socket
  (`unix-command: enabled: yes`) driven by `suricatasc -c reload-rules`; the
  Debian unit's `ExecReload` is exactly
  `suricatasc -c reload-rules ; kill -HUP $MAINPID`, and its `ExecStop` is
  `suricatasc -c shutdown`.
- **Config is rendered from the DB** (D-005): the app writes the rule-enable
  set / thresholds to disk, then triggers the reload. The rules-update unit
  calls back into the app (`gilgamesh-rules-update`) rather than poking
  Suricata directly, so policy stays in one place.
- Scheduling: daily timer (§3.4), `Persistent=true` for laptops-turned-appliance
  power cycles.
- Failure handling: if `suricata-update` cannot reach its source (offline LAN),
  **keep the last good ruleset** — never leave Suricata with an empty/partial
  rule file. Exact atomicity of `suricata-update` output is **UNVERIFIED**;
  design assumes "download to a staging dir, validate, swap".
- Log rotation of `/var/log/suricata/*.json` is handled by the distro
  (below).

---

## 5. Log rotation and disk budget

Gilgamesh produces three log streams. Each has its own bounding mechanism.

### 5.1 journald (unit stdout/stderr)

All unit output goes to the journal. Bound it globally with a drop-in at
`/etc/systemd/journald.conf.d/gilgamesh.conf` (drop-in precedence verified in
`journald.conf(5)`). Relevant options (all verified):

```ini
[Journal]
Storage=persistent
SystemMaxUse=100M
SystemMaxFileSize=16M
MaxRetentionSec=14day
```

- `SystemMaxUse=` "control[s] how much disk space the journal may use up at
  most" and defaults to 10 % of the filesystem (capped 4 G) — on a small SD
  card that is too much; set it explicitly.
- `SystemMaxFileSize=` defaults to `SystemMaxUse=`/8 (capped 128 M); setting it
  controls rotation granularity.
- `Storage=volatile` keeps the journal in RAM (`/run`, tmpfs) and writes
  **nothing** to the SD card — the strongest anti-wear option, at the cost of
  losing logs on reboot. **Policy decision belongs to doc 04.**
- `journalctl --vacuum-*` can enforce limits manually if needed.

### 5.2 Suricata logs (`/var/log/suricata/`)

The Debian package already ships `/etc/logrotate.d/suricata` (verified contents
from the package):

```
/var/log/suricata/*.log
/var/log/suricata/*.json
{
	rotate 14
	missingok
	compress
	create
	sharedscripts
	postrotate
		/usr/bin/kill -HUP `cat /var/run/suricata/suricata.pid 2>/dev/null` 2>/dev/null || true
	endscript
}
```

`logrotate` directives (`rotate`, `missingok`, `compress`, `create`,
`sharedscripts`, `postrotate`) are documented in `logrotate(8)`. We may ship an
`/etc/logrotate.d/gilgamesh-suricata` override to tune retention (size- or
time-based) once doc 04 fixes the budget. Prefer a **size cap** in addition to
time (`maxsize`) so a burst cannot fill the card.

### 5.3 Gilgamesh app logs (`/var/log/gilgamesh/`)

`LogsDirectory=gilgamesh` gives the web unit `/var/log/gilgamesh`. Ship
`/etc/logrotate.d/gilgamesh`:

```
/var/log/gilgamesh/*.log {
	daily
	rotate 14
	maxsize 32M
	compress
	missingok
	notifempty
	copytruncate
}
```

(`copytruncate` avoids needing to signal the process; `maxsize` bounds a burst;
both documented in `logrotate(8)`.)

### 5.4 SD-card wear (implement doc 04's policy here)

Mechanisms available to the units/installer, with the trade-off noted:

- **`noatime`** mount option on the root `ext4` filesystem (verified in
  `mount(8)`): removes the largest source of hidden writes. Add to `/etc/fstab`
  (format and `systemctl daemon-reload` requirement verified in `fstab(5)`).
  Consider `commit=60` to batch metadata writes (documented in `mount(8)`).
- **tmpfs for runtime data:** `RuntimeDirectory=` already lives on `/run`
  (tmpfs). Anything transient (pid files, sockets) belongs there.
- **journald** either bounded (`SystemMaxUse=`) or `Storage=volatile` (§5.1).
- **SQLite/WAL** checkpointing and retention are doc 04's; the deployment view
  is only "WAL files live in `StateDirectory=` and are bounded by the app".
- Optionally move DB + logs to a USB SSD and keep only the OS on SD (doc 04).

Retention **numbers** above are placeholders pending doc 04.

---

## 6. First run vs. install

**Install time** (unattended, no questions):

1. Install packages, code, Python env, units, accounts, directories.
2. Generate **non-user-facing** bootstrap secrets once (session-signing key,
   CSRF secret) into `/etc/gilgamesh/gilgamesh.env` with `0600` root-only
   permissions, using a CSPRNG. (These are not the user's credentials.)
3. Start `gilgamesh-web` and `gilgamesh-sensor`. The sensor may idle until
   interfaces are chosen; the web app must **not** depend on them yet.
4. Leave the system in a **"unconfigured"** state.

**First run** (the web wizard — the only UI, C2):

- The app checks whether an admin exists. If not, *every* route redirects to the
  wizard; no other page is reachable and **there is no default account**.
- The wizard is the *only* place these happen:
  1. **Create the admin account** (username + password; password hashed with
     Argon2/bcrypt — doc 06).
  2. **Choose interfaces and mode** (bridge vs. SPAN; names/IPs from doc 01).
  3. **Choose alert channel(s)** (Discord / Telegram / email) + test message.
  4. Optional: retention, HTTPS, quiet hours.
- Wizard output is written to the SQLite DB (source of truth, D-005). Derived
  artifacts (env files, rendered Suricata config) are written either under the
  app's state directory or, for paths that must live under `/etc/…`, applied by
  a narrowly-scoped root helper — the web service is sandboxed and cannot write
  `/etc` (see §3.1). The same helper reloads the affected units
  (`systemctl reload`/`restart`) without a reboot. **Helper mechanism = doc 04;
  UNVERIFIED here.**

**Discovery (how the non-expert finds the page) — must not be a CLI:**

- The management address comes from doc 01 (a static IP on the bridge's
  management side). The install script prints that URL (it may *display* a URL;
  it must not *ask questions*).
- Optional convenience: mDNS (`gilgamesh.local`) via the distro's avahi daemon
  — open source, but an extra always-on service to harden; **mark as optional
  and UNVERIFIED** (doc 01/04 decide). Do not depend on it.

**Explicitly forbidden in the installer:** creating users, setting passwords,
choosing interfaces, configuring alerts, asking any prompt, or shipping a CLI
subcommand for any of the above.

---

## 7. Update path

Three independent update tracks. None requires a reboot.

### 7.1 Application code + Python deps

```
cd /opt/gilgamesh
git fetch --tags && git checkout <tag>      # or unpack the new offline bundle
uv sync --frozen                            # online
#   or, offline:
uv sync --frozen --offline --no-index --find-links vendor/wheels/
systemctl restart gilgamesh-web.service gilgamesh-sensor.service
```

- `uv sync --frozen` (verified) never re-locks: the shipped `uv.lock` is the
  contract. This is what makes "don't install from memory" enforceable.
- DB migrations run at service start, forward-only, owned by the app (D-005).
- `daemon-reload` is only needed when unit files change.

### 7.2 Rules (independent of code)

Handled entirely by `gilgamesh-rules-update.timer` (§4). A rules update can
ship without a code update and vice versa.

### 7.3 OS / engine packages

- Online: `apt-get update && apt-get full-upgrade`.
- Offline: replace `vendor/debs/` and re-run `install.sh --offline`.
- **Pin the engine version.** If using trixie-backports for Suricata 8.x, add an
  apt pin (or always install from the offline bundle) so a stray `apt upgrade`
  does not silently downgrade to 7.0.10. (Pin mechanism = `apt_preferences(5)`,
  to be verified in doc 03.)

### 7.4 Rollback

- Keep `/opt/gilgamesh` a git checkout: roll back with
  `git checkout <previous-tag> && uv sync --frozen && systemctl restart …`.
- Keep the previous offline bundle and the previous ruleset; the app never
  destroys the DB, and migrations are forward-only (so rollback across a
  migration is limited — documented risk).

### 7.5 What stays manual (and why)

Nothing user-facing. Updating the OS/engine and applying an offline bundle are
*operator* actions on the appliance, not user configuration, and are outside
the "web UI only" rule (they are infrastructure operations, like the installer).

---

## Sources

Platform / OS:

- Raspberry Pi OS downloads (Lite 64-bit = Debian 13 trixie, kernel 6.18,
  2026-10-06): https://www.raspberrypi.com/software/operating-systems/

Debian package facts (arm64, trixie):

- Package index used to derive versions and file lists:
  `https://deb.debian.org/debian/dists/trixie/main/binary-arm64/Packages.gz`
  and `https://deb.debian.org/debian/dists/trixie-backports/main/binary-arm64/Packages.xz`
- `Contents-arm64` used to confirm `/usr/lib/systemd/system/suricata.service`
  and other files:
  `https://deb.debian.org/debian/dists/trixie/main/Contents-arm64.gz`
- Suricata binary package used for unit/logrotate/control extraction:
  `https://deb.debian.org/debian/pool/main/s/suricata/suricata_8.0.7-1~bpo13+1_arm64.deb`

systemd (Debian trixie, systemd 257.13-1~deb13u1):

- `systemd.exec(5)`: https://manpages.debian.org/trixie/systemd/systemd.exec.5.en.html
- `systemd.service(5)`: https://manpages.debian.org/trixie/systemd/systemd.service.5.en.html
- `systemd.timer(5)`: https://manpages.debian.org/trixie/systemd/systemd.timer.5.en.html
- `systemd.resource-control(5)`: https://manpages.debian.org/trixie/systemd/systemd.resource-control.5.en.html
- `journald.conf(5)`: https://manpages.debian.org/trixie/systemd/journald.conf.5.en.html
- `sysusers.d(5)`: https://manpages.debian.org/trixie/systemd/sysusers.d.5.en.html
- `tmpfiles.d(5)`: https://manpages.debian.org/trixie/systemd/tmpfiles.d.5.en.html
- `systemd-tmpfiles(8)`: https://manpages.debian.org/trixie/systemd/systemd-tmpfiles.8.en.html
- `systemctl(1)`: https://manpages.debian.org/trixie/systemd/systemctl.1.en.html

Other tooling:

- `setcap(8)` (libcap2-bin 1:2.75-10+deb13u1+b3):
  https://manpages.debian.org/trixie/libcap2-bin/setcap.8.en.html
- `capabilities(7)`: https://manpages.debian.org/trixie/manpages/capabilities.7.en.html
- `logrotate(8)` (3.22.0-1):
  https://manpages.debian.org/trixie/logrotate/logrotate.8.en.html
- `fstab(5)` (util-linux 2.41.5):
  https://manpages.debian.org/trixie/mount/fstab.5.en.html
- `mount(8)` (util-linux 2.41.5, `noatime`/`commit=`):
  https://manpages.debian.org/trixie/mount/mount.8.en.html

uv:

- CLI reference (flags `--frozen`, `--offline`, `--no-index`, `--find-links`,
  `--python-platform`, `--no-managed-python`, `--no-python-downloads`,
  `uv run --no-sync`, `uv export`): https://docs.astral.sh/uv/reference/cli/
- Python versions (managed vs. system, `uv python install`, distributions):
  https://docs.astral.sh/uv/concepts/python-versions/
- Locking and syncing: https://docs.astral.sh/uv/concepts/projects/sync/

Suricata:

- `suricata-update` rule management:
  https://docs.suricata.io/en/latest/rule-management/suricata-update.html
- Unix socket (`reload-rules`): https://docs.suricata.io/en/latest/unix-socket.html

---

## Open questions / UNVERIFIED

1. **Suricata version source (blocks §2.1, D-002).** trixie **stable** ships
   `suricata 1:7.0.10`; `8.0.7-1~bpo13+1` is only in `trixie-backports`. Decide:
   enable backports, ship an offline 8.x bundle, or accept 7.0.10. Needs doc 03.
2. **Cross-arch wheelhouse.** Whether `uv sync --python-platform
   aarch64-unknown-linux-gnu` on x86_64 produces a complete, correct aarch64
   wheelhouse/cache is **UNVERIFIED**. Same-arch seeding is the safe default.
3. **`uv` offline interpreter.** Exact procedure to ship a uv-managed Python for
   `--offline` (directory layout, `UV_PYTHON_INSTALL_DIR`) is **UNVERIFIED**;
   fallback is OS `python3` via `--no-managed-python`.
4. **`suricata-update` offline mode.** Whether it supports installing from a
   local/offline source (`--local`/tarball) and whether its output swap is
   atomic is **UNVERIFIED** (doc 02/03).
5. **Suricata hardening drop-in safety.** The exact safe `SystemCallFilter=`,
   `RestrictAddressFamilies=` (AF_NETLINK?), and capability set — and whether
   `MemoryDenyWriteExecute=` is possible (hyperscan/JIT) — are **UNVERIFIED**
   until Suricata boots under the drop-in.
6. **App `MemoryDenyWriteExecute=yes`** is unsafe if any Python dependency
   JITs; final dependency set is doc 03.
7. **Capture capability set** (`CAP_NET_RAW` alone vs. `+CAP_NET_ADMIN`) depends
   on doc 01 (promiscuous mode, AF_PACKET vs. libpcap).
8. **mDNS discovery** (`gilgamesh.local` via avahi) is proposed but
   **UNVERIFIED**; whether to ship it (and its hardening) is a doc 01/04 call.
9. **`uv` binary location for system units.** Fixed path
   (`/usr/local/bin/uv`) and the standalone-installer `UV_INSTALL_DIR`/`--path`
   behavior are **UNVERIFIED** (doc 03).
10. **apt pinning** mechanism to prevent a downgrade from 8.x → 7.0.10
     (`apt_preferences(5)`) is **UNVERIFIED**.
11. **Retention numbers** (journald `SystemMaxUse`, logrotate `rotate`/`maxsize`,
     `Storage=volatile` vs `persistent`) are placeholders pending doc 04.
12. **`openssl`/CSPRNG** availability on Raspberry Pi OS Lite for bootstrap
     secret generation is assumed, not verified.
13. **Wizard write path + unit reload.** How the sandboxed web service persists
    derived config that must live under `/etc/…` and reloads units (root helper
    vs. state-dir rendering) is **UNVERIFIED** and belongs to doc 04
    (privilege separation); see §3.1 and §6.

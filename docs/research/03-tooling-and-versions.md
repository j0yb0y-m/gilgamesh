# 03 — Tooling, Versions, Licences & aarch64 Availability

**Research date:** 2026-10-14 (all versions are "current" as of this date).
**Target:** Raspberry Pi 4B, 4 GB, ARM64/aarch64, Raspberry Pi OS Lite 64-bit, Python + FastAPI, `uv` only.
**Method:** every version and licence below was read from an official source on 2026-10-14 — PyPI JSON API, the project repo/GitHub API, `sources.debian.org`, `deb.debian.org`, `raspberrypi.com`, `suricata.io`, `docs.suricata.io`, `rules.emergingthreats.net`. Source URLs are cited per row and collected in **## Sources**. Nothing here is written from memory.

> Status tags: **VERIFIED** = read from an official source today · **UNVERIFIED** = could not confirm · **AMBIGUOUS** = sources disagree.

---

## 1. Target OS matrix

| Item | Value | Source |
| --- | --- | --- |
| OS | **Raspberry Pi OS Lite (64-bit)** — "A port of Debian Trixie with no desktop environment" | raspberrypi.com/software/operating-systems |
| Current image | `2026-10-06-raspios-trixie-arm64-lite.img.xz` (`raspios_lite_arm64-2026-10-06`) | same |
| Release date | **6 October 2026** | same |
| Architecture | 64-bit (aarch64/arm64) | same |
| Debian base codename | **Debian 13, codename `trixie`** | same |
| Kernel | **6.18** | same |
| System Python | **3.13.5** (`python3-defaults 3.13.5-1`, Debian trixie) | sources.debian.org/api/src/python3-defaults |
| glibc (Debian 13) | **2.41** (`glibc 2.41-12+deb13u4`) | sources.debian.org/api/src/glibc |
| Bundled SQLite (Debian) | **3.46.1** (`sqlite3 3.46.1-7+deb13u2`); Python's `sqlite3` uses the distro lib | sources.debian.org/api/src/sqlite3 |
| Is the Debian base current stable? | **Yes.** Debian's current `stable` is **version 13 `trixie`** (13.0 on 2025-08-09; latest point release **13.7 on 2026-09-12**). Supported to **2028-08-09** + LTS to **2030-06-30**. `forky` is testing, `sid` unstable. | debian.org/releases |
| Legacy alternative (rejected as primary) | Raspberry Pi OS **(Legacy)** = Debian 12 `bookworm`, kernel 6.12 | raspberrypi.com/software/operating-systems |

**Conclusion:** the OS is on the **current** Debian stable line (trixie), not testing or an EOL base. Python **3.13.5** is the system interpreter.

**Platform-firmware caveat (licence, not version):** Raspberry Pi OS boots via Broadcom VideoCore firmware blobs (`start*.elf`, `fixup*.dat`, kernel modules) that are **proprietary/non-free** and shipped under a Raspberry Pi licence, not an SPDX open-source licence. The *userland* is open Debian. This is a property of the hardware platform (Pi 4), unavoidable regardless of which Pi OS/Kali image is used. Recorded here so the "open source only" constraint (C1) is honest about the platform layer. **UNVERIFIED** which exact blob files ship in `2026-10-06` (blob names/sizes not enumerated here).

---

## 2. Tooling table

Legend for "Install path": `uv` = added to the project with `uv add`; `apt` = Debian package; `vendored` = static asset copied into the repo; `build-time` = used on the dev machine, artifact committed.

### 2.1 Sensor / engine layer

| Tool | Purpose | Current version | SPDX licence | Source | aarch64 / Debian availability | Install path |
| --- | --- | --- | --- | --- | --- | --- |
| **Suricata** | Signature IDS engine, EVE JSON output | **8.0.7** (released 2026-09-15; 8.x is the supported branch, 7.0.x **EOL since 2026-07-07**) | `GPL-2.0-only` | github.com/OISF/suricata (LICENSE); suricata.io/download; docs.suricata.io/en/suricata-8.0.7 | **apt package for arm64 exists**: Debian **trixie-backports** = `1:8.0.7-1~bpo13+1` (arm64 confirmed: `suricata_8.0.7-1~bpo13+1_arm64.deb`). Trixie itself only has `1:7.0.10-1+deb13u4`. Also in `forky`/`sid` = `1:8.0.7-1`. **No source build needed.** | `apt` (enable `trixie-backports`), run under systemd |
| **suricata-update** | Rule manager (fetches ET Open, writes `suricata.rules`, `--reload`/SIGHUP reload) | **1.3.8** (Debian trixie-backports); upstream GitHub latest **1.3.6**; PyPI shows **1.3.3** (desynced — use the distro package) | `GPL-2.0-only` | github.com/OISF/suricata-update; sources.debian.org/api/src/suricata-update | **apt package for arm64 exists**: `suricata-update_1.3.8-1~bpo13+1_arm64.deb` (trixie-backports); trixie itself = `1.3.4-1+deb13u1` | `apt` (trixie-backports). **Packaged — do not also `uv add` it** (avoids a second copy) |
| **ET Open ruleset** | Free signature feed for Suricata | Rolling (feed rebuilt 2026-10-13; latest Suricata build dir = **`suricata-7.0.3`**, plus `suricata-5.0`) | **AMBIGUOUS**: shipped `BSD-License.txt` is a **BSD-3-Clause**-style licence; the OISF index labels it **`MIT`** | rules.emergingthreats.net/open/ ; .../open/suricata-7.0.3/BSD-License.txt ; openinfosecfoundation.org/rules/index.yaml | N/A (data feed, not a binary). Free, **no oinkcode, no subscription**. | fetched by `suricata-update` into `/var/lib/suricata/rules` |
| **ET Pro ruleset** | *(rejected)* subscriber feed | — | **Commercial** (index); requires paid `oinkcode` | rules.emergingthreats.net/PRO_download_instructions.html ; .../index.yaml (`license: Commercial`) | N/A | **Do not use** — violates C1 |
| **Scapy** | Custom L2/L3 detectors (ARP, DNS, DHCP, scan/flood) | **2.8.0** | **`GPL-2.0-only`** | pypi.org/project/scapy ; github.com/secdev/scapy | **Pure Python** (`py3-none-any` + sdist) → aarch64-OK, no compiler. Uses raw `AF_PACKET` sockets on Linux by default; **libpcap optional** (`libpcap 1.10.5-2` in trixie) if you force `conf.use_pcap=True`. | `uv` (`uv add scapy`) |
| `libpcap` *(optional)* | Only needed if Scapy is configured to use pcap; also a Suricata build dep (not needed with the apt package) | **1.10.5-2** (trixie) | `BSD-3-Clause` | sources.debian.org/api/src/libpcap | `apt` package `libpcap0.8` (arm64) | `apt` — only if required |

**ET Open fetch mechanism (VERIFIED):** `suricata-update` defaults to `DEFAULT_ETOPEN_URL = "https://rules.emergingthreats.net/open/suricata-%(__version__)s/emerging.rules.tar.gz"` and the source index `https://www.openinfosecfoundation.org/rules/index.yaml` (`et/open` entry, no parameters required). No account needed.

### 2.2 Runtime & Python stack

| Tool | Purpose | Current version | SPDX licence | Source | aarch64 / wheel status | Install path |
| --- | --- | --- | --- | --- | --- | --- |
| **uv** | The only Python package/project manager (C4) | **0.13.0** (2026-10-09) | `MIT OR Apache-2.0` | docs.astral.sh/uv ; github.com/astral-sh/uv | Prebuilt **`uv-aarch64-unknown-linux-gnu.tar.gz`** + `...-musl` in release assets; install script resolves aarch64 | installer / tarball (see §2.5) |
| **FastAPI** | Web framework | **0.143.0** | `MIT` | pypi.org/pypi/fastapi ; github.com/fastapi/fastapi | pure Python | `uv` |
| **Starlette** | ASGI framework under FastAPI | **1.8.0** | `BSD-3-Clause` | pypi.org/pypi/starlette | pure Python. **Requires Python ≥3.11** (trixie 3.13.5 OK). Note: `1.8.0` is a new **1.x** line; FastAPI 0.143.0 pins `starlette>=0.46.0`, so 1.8.0 satisfies it. | `uv` (transitive) |
| **Uvicorn** | ASGI server | **0.54.0** | `BSD-3-Clause` | pypi.org/pypi/uvicorn | pure Python core; the `[standard]` extra pulls compiled extras (all have aarch64 wheels — see §3) | `uv` |
| **Pydantic** | Data models / validation (v2) | **2.14.1** | `MIT` | pypi.org/pypi/pydantic | pure Python, depends on `pydantic-core` (compiled — aarch64 wheel ✅) | `uv` |
| `pydantic-core` | Rust validation core | **2.50.1** (pinned by pydantic 2.14.1) | `MIT` | pypi.org/pypi/pydantic-core | **manylinux_2_17_aarch64** wheel ✅ (no Rust toolchain needed) | `uv` (transitive) |
| **Jinja2** | Server-side HTML templates | **3.1.6** | `BSD-3-Clause` | pypi.org/pypi/jinja2 | pure Python | `uv` |
| **python-multipart** | Form/multipart parsing for FastAPI | **0.0.32** | `Apache-2.0` | pypi.org/pypi/python-multipart | pure Python | `uv` |
| **itsdangerous** | Signed cookies/tokens (sessions) | **2.2.0** | `BSD-3-Clause` | pypi.org/pypi/itsdangerous | pure Python | `uv` |
| **argon2-cffi** | Argon2 password hashing | **25.1.0** | `MIT` | pypi.org/pypi/argon2-cffi | pure Python wrapper; binds `argon2-cffi-bindings` (compiled — aarch64 wheel ✅) | `uv` |
| `argon2-cffi-bindings` | cffi bindings to libargon2 | **26.1.0** | `MIT` | pypi.org/pypi/argon2-cffi-bindings | **manylinux_2_26/2_28_aarch64** abi3 wheel ✅ | `uv` (transitive) |
| **pwdlib** | Modern password-hash façade (Argon2/bcrypt) | **0.3.1** | `MIT` | pypi.org/pypi/pwdlib | pure Python | `uv` |
| **passlib** | *(alternative)* password hashing | **1.7.4** | `BSD` (SPDX clause count **UNVERIFIED**) | pypi.org/pypi/passlib | pure Python | **Not recommended** — last release 2020-10-08, effectively unmaintained; prefer `pwdlib` or `argon2-cffi` directly |
| **httpx** | Async HTTP for Discord webhooks / Telegram Bot API | **0.28.1** | `BSD-3-Clause` | pypi.org/pypi/httpx | pure Python | `uv` |
| **aiosmtplib** | Async SMTP for email alerts | **5.1.3** | `MIT` | pypi.org/pypi/aiosmtplib | pure Python | `uv` |
| `sqlite3` | Storage (WAL mode, C7-optional) | **stdlib** (Debian SQLite 3.46.1) | Python stdlib under `PSF-2.0`; SQLite engine itself **Public Domain** | sqlite.org/copyright ; sources.debian.org/api/src/sqlite3 | stdlib — always present | none (import) |

> **New hard transitive (watch at lock time):** FastAPI **0.143.0** now lists `opentelemetry-api>=1.44.0` and `typing-inspection>=0.4.2` and `annotated-doc>=0.0.2` as **non-optional** deps (not just under `[standard]`). All three are pure Python (`opentelemetry-api` 1.45.1 `Apache-2.0`; `typing-inspection` 0.4.4 `MIT`; `annotated-doc` 0.0.5 `MIT`). Discord/Telegram/SMTP need **no vendor SDK** — plain HTTPS/SMTP via `httpx`/`aiosmtplib`.

### 2.3 Front-end (vendored; no Node.js — C5)

| Tool | Purpose | Current version | SPDX licence | Source | aarch64 / build | Install path |
| --- | --- | --- | --- | --- | --- | --- |
| **htmx** | Server-driven UI (C3) | **4.0.0** (2026-08-28) · latest 2.x = **2.0.11** | **`0BSD`** (Zero-Clause BSD; GitHub reports "NOASSERTION", the LICENSE file is 0BSD) | github.com/bigskysoftware/htmx | static JS, no arch concern | `vendored` |
| **Alpine.js** | Small client-side state (C3) | **3.17.4** (2026-09-21) | `MIT` | github.com/alpinejs/alpine | static JS. **CSP build exists** (`packages/csp`, `@alpinejs/csp`) if the app sets a strict CSP | `vendored` |
| **Tailwind CSS** | Styling (C3/C5) | **4.3.3** (2026-07-16) | `MIT` | github.com/tailwindlabs/tailwindcss | **`tailwindcss-linux-arm64` standalone binary published** in the v4.3.3 release (109.9 MB; plus `-musl` variant) | `build-time` (dev machine or Pi), commit built CSS |

> Tailwind **v4 is CSS-first** (`@import "tailwindcss"` + `@theme`), **not** the v3 `tailwind.config.js` + `@tailwind` directives. Pick v4 syntax and do not mix (PROMPT §4 pitfall).
> **htmx is the one moving target:** the PROMPT assumed htmx 2.x, but **4.0.0** shipped 2026-08-28 (fetch-based rewrite, morphing swaps). Recommendation: pin **htmx 2.0.11** (mature, best-documented, huge ecosystem) and treat 4.0.0 as an evaluate-later upgrade. Flagged as a decision, not a blocker.

### 2.4 Debian packaging summary (the important one)

| Need | Trixie (default) | Trixie-backports | Recommendation |
| --- | --- | --- | --- |
| Suricata | `1:7.0.10-1+deb13u4` (**EOL 7.x** — don't use) | `1:8.0.7-1~bpo13+1` ✅ | `apt install -t trixie-backports suricata` |
| suricata-update | `1.3.4-1+deb13u1` | `1.3.8-1~bpo13+1` ✅ | `apt install -t trixie-backports suricata-update` |
| libpcap | `1.10.5-2` ✅ | — | only if Scapy is configured to use pcap |

**Bottom line: no compilation on the Pi.** Suricata 8.x and `suricata-update` install as prebuilt arm64 `.deb`s from `trixie-backports`. *(Caveat: confirm on the actual Pi that Raspberry Pi OS's apt configuration can reach `trixie-backports` — see Open questions.)*

### 2.5 `uv` install on aarch64 (VERIFIED)

- Official install doc: `https://docs.astral.sh/uv/getting-started/installation/`.
- Script URL: `https://astral.sh/uv/install.sh` → **HTTP 200, redirects to `https://releases.astral.sh/installers/uv/latest/uv-installer.sh`** (script header: *"Licensed under the MIT license"*).
- The script contains explicit aarch64 handling: `uv-aarch64-unknown-linux-gnu.tar.gz` (glibc) and `uv-aarch64-unknown-linux-musl.tar.gz`.
- Release assets for **0.13.0** include `uv-aarch64-unknown-linux-gnu.tar.gz` (+`.sha256`) and `...-musl.tar.gz` (+`.sha256`); PyPI also ships `uv-0.13.0-py3-none-manylinux_2_28_aarch64.whl`.
- **Preferred path on the Pi (offline-first, avoids `curl | sh` which AGENTS.md flags):** download the `uv-aarch64-unknown-linux-gnu.tar.gz` + its `.sha256`, verify the hash, extract to `/usr/local/bin`. Keep the script method as the documented fallback.

---

## 3. aarch64 wheel audit

Rule of thumb: a `manylinux*_aarch64`/`abi3` wheel means **no compiler on the Pi**; a `py3-none-any` wheel means **pure Python**; an sdist-only package would need a toolchain. Every compiled dependency below **ships an aarch64 wheel**, so nothing needs Rust or a C toolchain on the Pi.

| Package | Version | aarch64 wheel? | Pure Python? | Build toolchain needed on Pi? |
| --- | --- | --- | --- | --- |
| pydantic-core | 2.50.1 | ✅ `manylinux_2_17_aarch64` (cp310–cp315) | no | **No** (prebuilt) |
| argon2-cffi-bindings | 26.1.0 | ✅ `manylinux_2_26/2_28_aarch64` (cp310-abi3) | no | **No** (prebuilt) |
| uvloop *(uvicorn[standard])* | 0.23.0 | ✅ `manylinux2014_aarch64/…2_28_aarch64` | no | **No** (prebuilt) |
| httptools *(uvicorn[standard])* | 0.9.0 | ✅ `manylinux2014_aarch64/…2_28_aarch64` | no | **No** (prebuilt) |
| watchfiles *(dev --reload)* | 1.3.0 | ✅ `manylinux_2_17_aarch64` (abi3) | no (Rust, prebuilt) | **No** (prebuilt) |
| websockets | 17.2 | ✅ `manylinux2014_aarch64` **and** `py3-none-any` | yes (also pure wheel) | **No** |
| **uv** (self) | 0.13.0 | ✅ `manylinux_2_28_aarch64` wheel + aarch64 static binaries | no (Rust, prebuilt) | **No** (prebuilt) |
| pydantic | 2.14.1 | — | ✅ `py3-none-any` | no |
| fastapi | 0.143.0 | — | ✅ | no |
| starlette | 1.8.0 | — | ✅ | no |
| uvicorn | 0.54.0 | — | ✅ | no |
| jinja2 | 3.1.6 | — | ✅ | no |
| python-multipart | 0.0.32 | — | ✅ | no |
| itsdangerous | 2.2.0 | — | ✅ | no |
| argon2-cffi | 25.1.0 | — | ✅ (wrapper) | no |
| pwdlib | 0.3.1 | — | ✅ | no |
| httpx | 0.28.1 | — | ✅ | no |
| httpcore | 1.0.9 | — | ✅ | no |
| aiosmtplib | 5.1.3 | — | ✅ | no |
| scapy | 2.8.0 | — | ✅ | no |
| anyio | 4.15.1 | — | ✅ | no |
| h11 | 0.16.0 | — | ✅ | no |
| sniffio | 1.3.1 | — | ✅ | no |
| annotated-types | 0.8.0 | — | ✅ | no |
| typing-extensions | 4.16.0 | — | ✅ | no |
| typing-inspection | 0.4.4 | — | ✅ | no |
| annotated-doc | 0.0.5 | — | ✅ | no |
| opentelemetry-api | 1.45.1 | — | ✅ | no |
| idna | 3.20 | — | ✅ | no |
| certifi | 2026.7.22 | — | ✅ | no |
| h2 *(httpx[http2], optional)* | 4.4.1 | — | ✅ | no |
| click | 8.5.0 | — | ✅ | no |
| python-dotenv | 1.2.4 | — | ✅ | no |

**Highest glibc requirement seen: `manylinux_2_28` (glibc ≥ 2.28).** Debian 13 trixie ships **glibc 2.41**, so all wheels install cleanly — no sdist fallback, no compiling on the Pi.

**Flags:** none require a Rust/C toolchain on the device. The only compiled components (pydantic-core, argon2-cffi-bindings, uvloop, httptools, watchfiles, uv) all publish aarch64 wheels — **verify at lock time** that `uv.lock` resolves those aarch64 wheels and does not silently pick an sdist.

---

## 4. Python version choice

- **What the stack supports today:** FastAPI **0.143.0** supports Python **3.10–3.14** (`requires_python >=3.10`; classifiers list 3.10→3.14). Pydantic 2.14.1 requires **≥3.10** (`pydantic-core` publishes cp310–cp315 wheels). **Starlette 1.8.0 requires ≥3.11.** The effective floor for this project is therefore **Python 3.11+**; the comfortable target is **3.13**.
- **What the OS ships:** Raspberry Pi OS Lite 64-bit (trixie) = **Python 3.13.5**. This satisfies every dependency.
- **Recommendation: use the OS Python 3.13 via `uv`** (`uv venv --python 3.13` / `uv sync`), **not** `uv python install`.
  - Reason: offline-first (C-later goal) — the system interpreter is already on the box; no managed-download needed.
  - `uv python install` fetches Astral-managed **python-build-standalone** builds. Those are licensed **`MPL-2.0`** (the build tooling), bundling CPython (`PSF-2.0`) — open, but an extra download and a licence to record. Keep it as a fallback only if the system Python is unsuitable.
  - Debian's system Python is **PEP 668 "externally managed"**; `uv` sidesteps this by creating its own venv (`.venv/`), so no `--break-system-packages` ever.
- **Do not mix** a `uv`-managed interpreter with distro `python3-*` apt packages inside the venv.

---

## 5. Licence risk notes

1. **Scapy is `GPL-2.0-only` and is imported *in-process* — the real copyleft exposure.**
   Gilgamesh's own code imports Scapy as a library, so a *distributed* Gilgamesh is arguably a combined/derivative work of Scapy and would have to be distributed under GPLv2-compatible terms. This differs from Suricata (below), which runs as a **separate process**.
   - Aggravating factor: **`python-multipart` is `Apache-2.0`**, and Apache-2.0 is **commonly treated as incompatible with GPL-2.0-only**. A single distributed work combining GPL-2.0-only (Scapy) with Apache-2.0 (python-multipart) therefore has a licence-compatibility problem to resolve. *(This is a flag for a maintainer/legal review — not a legal opinion.)*
   - Options: (a) license Gilgamesh as **GPL-2.0-or-later / GPL-3.0** (GPLv3 can absorb Apache-2.0) and keep Scapy; (b) **drop Scapy** for capture and use stdlib raw `AF_PACKET` sockets + permissively-licensed parsers (e.g. `dnspython` `ISC` for DNS, `dpkt` for L2/L3) — removes the copyleft entirely; (c) decide Gilgamesh is internal-only and never distributed (obligations don't trigger). **Recommendation: prefer (b) or (a); decide before publishing a GitHub repo.**
2. **Suricata is `GPL-2.0-only`, but process-isolated → manageable.**
   Gilgamesh runs Suricata as a separate binary and reads its EVE JSON — no linking. So Gilgamesh's own licence is not forced to GPL. *But* if you ship a **prebuilt image bundling Suricata**, you must satisfy GPLv2 for the Suricata parts (ship/point to its source + licence). Installing via Debian `apt` leaves that compliance to Debian.
3. **ET Open licence is `AMBIGUOUS`.**
   The ruleset's own `BSD-License.txt` is **BSD-3-Clause-style** ("Copyright (c) 2003-2026, Emerging Threats"), while the OISF `index.yaml` records `license: MIT`. Both are permissive, non-copyleft, and free — **no distribution problem** — but the exact SPDX id is legally unclear. Record it as "BSD-3-Clause-style / index says MIT" and cite both. **ET Pro is `Commercial` and oinkcode-gated — excluded by C1.**
4. **`passlib` is unmaintained** (last release 2020-10-08, `BSD`). Prefer **`pwdlib` (`MIT`, maintained)** or `argon2-cffi` directly. Avoids relying on a dead dependency in a security product.
5. **Raspberry Pi OS contains proprietary firmware blobs** (VideoCore boot firmware). The platform is not 100% open source, even though the userland is. Unavoidable on Pi 4; recorded for honesty under C1.
6. **Permissive, no concerns:** uv (`MIT OR Apache-2.0`), FastAPI/`pydantic`/`pydantic-core`/`argon2-cffi`/`argon2-cffi-bindings`/`pwdlib`/`aiosmtplib`/Alpine/Tailwind (`MIT`), Starlette/Uvicorn/Jinja2/itsdangerous/httpx (`BSD-3-Clause`), `aiosmtplib` (`MIT`), htmx (`0BSD`), `dnspython` (`ISC`), `email-validator` (`Unlicense`), Python itself (`PSF-2.0`), SQLite (`Public Domain`).

---

## Sources

All URLs read 2026-10-14.

- Raspberry Pi OS downloads (OS matrix, image name, Debian base, kernel, release date): https://www.raspberrypi.com/software/operating-systems/
- Debian releases / current stable: https://www.debian.org/releases/ and https://www.debian.org/releases/stable/
- Debian trixie Python: https://sources.debian.org/api/src/python3-defaults/ (3.13.5-1)
- Debian trixie glibc: https://sources.debian.org/api/src/glibc/ (2.41-12+deb13u4)
- Debian trixie SQLite: https://sources.debian.org/api/src/sqlite3/ (3.46.1-7+deb13u2)
- Debian suricata versions: https://sources.debian.org/api/src/suricata/ (trixie 7.0.10; trixie-backports 8.0.7)
- Debian suricata-update versions: https://sources.debian.org/api/src/suricata-update/ (trixie 1.3.4; trixie-backports 1.3.8)
- Debian libpcap versions: https://sources.debian.org/api/src/libpcap/ (trixie 1.10.5-2)
- Debian arm64 .deb confirmation: http://deb.debian.org/debian/pool/main/s/suricata/ and http://deb.debian.org/debian/pool/main/s/suricata-update/
- Suricata releases / EOL: https://api.github.com/repos/OISF/suricata/releases ; https://suricata.io/download/ ; https://suricata.io/our-story/eol-policy/ ; https://docs.suricata.io/en/suricata-8.0.7/
- Suricata licence: https://github.com/OISF/suricata/blob/main/LICENSE
- suricata-update licence/releases/source logic: https://github.com/OISF/suricata-update ; https://raw.githubusercontent.com/OISF/suricata-update/master/suricata/update/sources.py
- ET rules index + licences: https://www.openinfosecfoundation.org/rules/index.yaml
- ET Open instructions + feed + licence: https://rules.emergingthreats.net/OPEN_download_instructions.html ; https://rules.emergingthreats.net/open/ ; https://rules.emergingthreats.net/open/suricata-7.0.3/BSD-License.txt
- ET Pro (subscriber, excluded): https://rules.emergingthreats.net/PRO_download_instructions.html
- PyPI JSON API (versions, licences, wheels): https://pypi.org/pypi/<package>/json for fastapi, starlette, uvicorn, pydantic, pydantic-core, jinja2, python-multipart, itsdangerous, argon2-cffi, argon2-cffi-bindings, pwdlib, passlib, httpx, httpcore, aiosmtplib, scapy, uv, uvloop, httptools, watchfiles, websockets, h11, anyio, sniffio, annotated-types, typing-extensions, typing-inspection, annotated-doc, opentelemetry-api, idna, certifi, h2, click, python-dotenv, dnspython, email-validator
- uv install/version: https://docs.astral.sh/uv/getting-started/installation/ ; https://astral.sh/uv/install.sh ; https://api.github.com/repos/astral-sh/uv/releases/tags/0.13.0
- python-build-standalone licence: https://github.com/astral-sh/python-build-standalone/blob/main/LICENSE
- htmx: https://github.com/bigskysoftware/htmx/releases ; https://raw.githubusercontent.com/bigskysoftware/htmx/master/LICENSE ; https://four.htmx.org/announcements/2026-08-28-htmx-4.0.0-is-released
- Alpine.js: https://github.com/alpinejs/alpine/releases ; LICENSE (MIT); CSP package dir
- Tailwind CSS: https://github.com/tailwindlabs/tailwindcss/releases/tag/v4.3.3 (asset `tailwindcss-linux-arm64`) ; LICENSE (MIT)

## Open questions / UNVERIFIED

| # | Item | Why it matters | How to close it |
| --- | --- | --- | --- |
| 1 | **ET Open feed's newest Suricata build dir is `suricata-7.0.3`** (no `suricata-8.0` dir on 2026-10-13). Does Suricata 8.0.7 consume it cleanly, and which dir does `suricata-update` pick for an 8.x engine? | Signature coverage on the chosen engine | Run `suricata-update` on the Pi with Suricata 8.0.7 and inspect the resolved source URL + rule load warnings. |
| 2 | **ET Open exact SPDX id** — index says `MIT`, shipped file is BSD-3-Clause-style | Licence recording under C1 | Pick one, cite both sources, note the discrepancy. |
| 3 | **Can Raspberry Pi OS trixie apt reach `trixie-backports`?** (needed to get Suricata 8.0.7 + suricata-update 1.3.8) | Determines apt vs source build | `apt-cache policy suricata` after enabling backports on the actual Pi image. |
| 4 | **Scapy `GPL-2.0-only` + `python-multipart` `Apache-2.0` compatibility** if Gilgamesh is distributed | Affects the project's own licence / whether Scapy stays | Decide: (a) GPL-2.0-or-later project, (b) replace Scapy with stdlib raw sockets, or (c) internal-only. Review before publishing a repo. |
| 5 | **htmx major: 2.0.11 vs 4.0.0** | 4.0.0 is <2 months old (major rewrite) | Default to 2.0.11; re-evaluate 4.0.0 later. |
| 6 | **`uv python install` / python-build-standalone `MPL-2.0`** if a managed interpreter is used | Offline plan + extra licence | Prefer OS Python 3.13; only use managed builds if required. |
| 7 | **Exact `passlib` BSD clause count** | Licence record completeness | Read passlib's LICENSE (or just drop passlib for `pwdlib`). |
| 8 | **Which proprietary firmware blobs ship in `2026-10-06-raspios-trixie-arm64-lite.img.xz`** | Honesty about the platform under C1 | Enumerate `/boot/firmware` on the flashed image. |
| 9 | **Offline `uv sync` viability** (populate wheel cache on a networked dev machine, install on an air-gapped Pi) | C-later offline-first goal | `uv sync --offline` test in doc 07 (deployment). |

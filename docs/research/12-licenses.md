# 12 — Licences of every component (C1)

**Rule (C1):** every dependency, tool, and rule set must be open source. Its SPDX id and
source URL are recorded here **before** it is added. No proprietary, paid, or
freemium-gated component.

**Project licence:** Gilgamesh is **GPL-2.0-or-later** (user decision D-020). Chosen so the
in-process use of Scapy (`GPL-2.0-only`) is unambiguously compatible, matching Suricata's
GPLv2. We deliberately **do not** depend on `python-multipart` (`Apache-2.0`) — the app
accepts URL-encoded form bodies only, so the combined work stays cleanly GPL-2.0-only-compatible.

**Last verified:** 2026-10-14 · **Status of versions:** `V` = verified this phase, `P` = provisional (pin at add time).

## A. Gilgamesh's own dependencies (Python — added with `uv add`)

| Component | Version | SPDX | Source URL | OSS |
|---|---|---|---|---|
| Python | 3.13.x (pinned) | PSF-2.0 | https://docs.python.org/3/license.html | yes |
| FastAPI | 0.143.0 `V` | MIT | https://github.com/fastapi/fastapi | yes |
| Starlette | 1.8.0 `V` | BSD-3-Clause | https://github.com/encode/starlette | yes |
| Uvicorn | 0.54.0 `V` | BSD-3-Clause | https://github.com/encode/uvicorn | yes |
| Pydantic | 2.14.1 `V` | MIT | https://github.com/pydantic/pydantic | yes |
| pydantic-settings | (pin at add) `P` | MIT | https://github.com/pydantic/pydantic-settings | yes |
| Jinja2 | 3.1.6 `V` | BSD-3-Clause | https://github.com/pallets/jinja | yes |
| Scapy | 2.8.0 `V` | **GPL-2.0-only** | https://github.com/secdev/scapy | yes |
| argon2-cffi | 25.1.0 `V` | MIT | https://github.com/hynek/argon2-cffi | yes |
| itsdangerous | (pin at add) `P` | BSD-3-Clause | https://github.com/pallets/itsdangerous | yes |
| limits | 5.8.0 `V` | MIT | https://github.com/alisaifee/limits | yes |
| httpx | (pin at add) `P` | BSD-3-Clause | https://github.com/encode/httpx | yes |
| aiosmtplib | (pin at add) `P` | MIT | https://github.com/cole/aiosmtplib | yes |
| email-validator | (pin at add) `P` | CC0-1.0 | https://github.com/JoshData/python-email-validator | yes |
| pytest | (pin at add) `P` | MIT | https://github.com/pytest-dev/pytest | yes |
| pytest-asyncio | (pin at add) `P` | Apache-2.0 | https://github.com/pytest-dev/pytest-asyncio | yes |
| ruff | (pin at add) `P` | MIT | https://github.com/astral-sh/ruff | yes |
| pyright | (pin at add) `P` | MIT | https://github.com/microsoft/pyright | yes |
| playwright | 1.64.0 `V` (2026-10-18) | Apache-2.0 | https://github.com/microsoft/playwright-python | yes |
| pytest-playwright | 0.10.0 `V` (2026-10-18) | Apache-2.0 | https://github.com/microsoft/playwright-pytest | yes |
| python-slugify | 9.1.3 `V` (2026-10-18, transitive of pytest-playwright) | MIT | https://github.com/un33k/python-slugify | yes |
| pyee | 15.0.0 `V` (2026-10-18, transitive of playwright) | MIT | https://github.com/jfhbrook/pyee | yes |
| text-unidecode | 1.3 `V` (2026-10-18, transitive of python-slugify) | Artistic-1.0 OR GPL-2.0-or-later (dual) | https://github.com/kmike/text-unidecode/ | yes |

> `pytest-asyncio` is Apache-2.0 — used only as a **dev/test** tool, never shipped in the
> distributed combined work, so it does not affect the project licence.

## B. System tools & external engines (not linked)

| Component | Version | SPDX | Source URL | OSS |
|---|---|---|---|---|
| Suricata (separate process) | 8.0.7 `V` | GPL-2.0-only | https://github.com/OISF/suricata | yes |
| suricata-update | 1.3.8 `V` | GPL-2.0-only | https://github.com/OISF/suricata-update | yes |
| Emerging Threats **Open** rules | feed `suricata-7.0.3` build `V` | MIT (per `index.yaml`) **and** BSD-3-Clause-style (`BSD-License.txt`) — ambiguous, both permissive | https://rules.emergingthreats.net/open/ | yes (Open only; ET **Pro** excluded) |
| SQLite | OS-provided | Public domain | https://sqlite.org/copyright.html | yes |
| systemd | OS-provided | LGPL-2.1-or-later | https://github.com/systemd/systemd | yes |
| NetworkManager (`nmcli`) | OS-provided | GPL-2.0-or-later / LGPL-2.1-or-later | https://gitlab.freedesktop.org/NetworkManager/NetworkManager | yes |
| uv | 0.12+ | MIT OR Apache-2.0 | https://github.com/astral-sh/uv | yes |
| Raspberry Pi OS Lite 64-bit | image 2026-10-06 | Debian platform (DFSG); Pi firmware blobs are proprietary-but-redistributable | https://www.raspberrypi.com/software/ | platform note |

## C. Vendored frontend assets (offline-first, C5)

| Component | Version | SPDX | Source URL | OSS |
|---|---|---|---|---|
| htmx | 2.0.11 (pinned, D-009) | 0BSD | https://github.com/bigskysoftware/htmx | yes |
| Alpine.js | 3.17.4 (CSP build) | MIT | https://github.com/alpinejs/alpine | yes |
| Tailwind CSS (standalone CLI; built CSS committed) | 4.3.3 | MIT | https://github.com/tailwindlabs/tailwindcss | yes |
| Lucide icons (inline SVG subset, static markup) | 1.59.0 `V` (2026-10-19) | ISC | https://github.com/lucide-icons/lucide | yes |
| Lucide icons — Feather-derived subset | 1.59.0 `V` (2026-10-19) | MIT | https://github.com/lucide-icons/lucide (upstream icons © 2013–present Cole Bemis, Feather) | yes |

> Lucide's `LICENSE` (fetched 2026-10-19) is ISC, but a named subset of icons is derivative of
> the Feather project and is MIT (© Cole Bemis). Both rows are recorded here because icons we
> inline (search, log-out, chevron-*, check, x, trash-*, alert-triangle, …) fall in the
> Feather-derived list. Both licences are permissive; GPL-2.0-or-later is compatible with
> either. Icons are taken from the official tag `1.59.0` (release zip
> `lucide-icons-1.59.0.zip`, digests published on the release) and committed as static inline
> SVG in `src/gilgamesh/web/templates/_icons.html` — no runtime dependency, no CDN (C5).


## D. Explicitly excluded (C1)

| Component | Why excluded |
|---|---|
| Emerging Threats **Pro** rule set | freemium/subscriber-gated |
| `htmx-ext-sse` | licence unverified (no detected licence file) → we ship our own ~10-line `EventSource` glue |
| Node.js / npm toolchain on the device | C6 |
| `python-multipart` | Apache-2.0; avoids GPL-2.0-only linkage tension (not needed: URL-encoded forms only) |
| `passlib` | unmaintained; superseded by `argon2-cffi` |
| Google Chrome (E2E test browser) | proprietary, but only *driven* by Playwright on the developer's machine via `--browser-channel chrome`; never installed by the project, never shipped, never runs on the Pi |

## E. UNVERIFIED

- Exact licence file for `email-validator` (declared CC0-1.0 on PyPI; confirm at add time).
- Wheels for every dependency on aarch64 — audited in `03-tooling-and-versions.md` §3; re-verify per add.

## F. Project artwork

| Asset | Author | Licence | Note |
|---|---|---|---|
| Logo (`docs/images/gilgamesh-mark.svg`, `gilgamesh-logo.png`, `static/favicon.svg`) | original work drawn for this project | GPL-2.0-or-later (same as the project) | hand-authored SVG; the wordmark PNG was rendered from the same geometry. Lucide (`_icons.html`) was already recorded above for the UI icons; the emblem itself is original, not an icon reuse. |

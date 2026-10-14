# 05 — Web and Stack (FastAPI · Pydantic v2 · Jinja2 · htmx · Alpine · Tailwind)

**Status:** researched · **Date:** 2026-10-14 · **Phase:** 1 (research only — no application code)
**Scope:** server-driven UI stack for Gilgamesh on Raspberry Pi 4 (4 GB), Debian 64-bit, offline-first, no Node.js on the device.

**Frozen versions verified on 2026-10-14** (see [Sources](#sources) for citations):

| Component | Version | SPDX licence | How verified |
|---|---|---|---|
| FastAPI | **0.143.0** | MIT | PyPI JSON `info.version`; `requires_dist: pydantic>=2.9.0, starlette>=0.46.0` |
| Starlette (transitive) | 0.46.0+ | BSD-3-Clause | FastAPI dependency; GitHub API licence |
| Uvicorn (transitive) | — | BSD-3-Clause | GitHub API licence |
| Pydantic | **2.14.1** | MIT | PyPI JSON `info.version` |
| Jinja2 | **3.1.6** | BSD-3-Clause | PyPI JSON `info.version` |
| htmx | **2.0.11** | 0BSD | npm registry `license`; repo `LICENSE` = "Zero-Clause BSD" |
| htmx-ext-sse (optional) | 2.2.4 | **UNVERIFIED** | npm has no `license` field; repo has no detected licence — see [Open questions](#open-questions--unverified) |
| Alpine.js | **3.17.4** | MIT | npm registry `license` |
| @alpinejs/csp (CSP build) | **3.17.4** | MIT | npm registry `license` |
| Tailwind CSS | **4.3.3** | MIT | GitHub API licence; latest release tag `v4.3.3` |
| sse-starlette (optional, not needed) | 3.5.0 | BSD-3-Clause | PyPI JSON `license_expression`; GitHub API licence |

**One-line stack decision:** FastAPI `lifespan` + Pydantic v2 + Jinja2 3.1 + **htmx 2.0.11 (vendored)** + **Alpine 3 CSP build (vendored)** + **Tailwind 4.3.3 built with the official `tailwindcss-linux-arm64` standalone binary and the built CSS committed**; live dashboard via FastAPI's native SSE (`fastapi.sse`), which makes `sse-starlette` unnecessary.

---

## 1. FastAPI current version + app lifecycle

- **Current version:** FastAPI **0.143.0** (PyPI, 2026-10-14). Requires Python ≥ 3.10.
- **Recommended lifecycle = `lifespan` async context manager.** The FastAPI docs page is titled *"Lifespan Events"*, placed under the **Advanced User Guide**, and it explicitly marks the old event hooks as *"Alternative Events (deprecated)"*. The warning reads, verbatim:

  > *"The recommended way to handle the startup and shutdown is using the `lifespan` parameter of the `FastAPI` app as described above. If you provide a `lifespan` parameter, `startup` and `shutdown` event handlers will no longer be called. It's all `lifespan` or all events, not both."*

  And later:

  > *"Because of that, it's now recommended to instead use the `lifespan` as explained above."*

- **Documented shape** (the docs' `@asynccontextmanager` + `yield` example, RST → Python):

```python
from contextlib import asynccontextmanager

from fastapi import FastAPI


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- startup: acquire shared resources (DB engine, sensor socket, task pool) ---
    ...
    yield
    # --- shutdown: release them ---
    ...


app = FastAPI(lifespan=lifespan)
```

- **Deprecation status of `@app.on_event`:** the docs label the whole `startup`/`shutdown` section as **deprecated** and steer users to `lifespan`. `on_event` still exists but is the deprecated path. Under the hood this maps to the ASGI **Lifespan Protocol**; Starlette documents an extended `lifespan` *state* mechanism (useful to stash the DB/pool object on `app.state`).
- **Caveat (documented):** lifespan events run **only for the main application, not for mounted sub-applications**.

**Gilgamesh implication:** open the SQLite (WAL) connection/engine, start/stop the background sensor-consumer task, and load notifier config in one `lifespan`. Do **not** use `@app.on_event`.

---

## 2. Pydantic v2

- **What FastAPI expects:** FastAPI 0.143.0 declares `pydantic>=2.9.0`, i.e. **Pydantic v2**. Current release is **2.14.1** (MIT). FastAPI itself ships a dedicated how-to, *"Migrate from Pydantic v1 to Pydantic v2."*
- Pydantic's own **Migration Guide** states: *"Pydantic V2 is now the current production release of Pydantic."* V1 is still importable via the `pydantic.v1` namespace for legacy code; **do not mix V1 and V2 models** (the migration guide says mixing is unsupported).

**Key v2 API changes that matter for us** (all from the official Migration Guide):

| Pydantic v1 | Pydantic v2 (current) | Notes |
|---|---|---|
| `BaseModel.dict()` | **`model_dump()`** | v1 name is deprecated, emits `DeprecationWarning` |
| `BaseModel.json()` | **`model_dump_json()`** | output is compacted (no spaces like `json.dumps`) |
| `parse_obj()` | **`model_validate()`** | loads Python data |
| `parse_raw()` | **`model_validate_json()`** | `parse_raw`/`parse_file` deprecated |
| `BaseModel.Config` class | **`model_config = ConfigDict(...)`** | `Config` is deprecated |
| `orm_mode = True` | **`from_attributes=True`** in `model_config` | replaces `from_orm()` |
| `@validator` | **`@field_validator`** | no `each_item`; use `Annotated` per item |
| `@root_validator` | **`@model_validator`** | signatures changed |
| `@validate_arguments` | **`@validate_call`** | renamed |
| `allow_mutation` (config) | **`frozen`** | inverted meaning |
| `regex=` (Field) | **`pattern=`** | `min_items`/`max_items` → `min_length`/`max_length` |
| `schema_extra` | **`json_schema_extra`** | |
| `parse_obj_as` / `schema_of` | **`TypeAdapter(...)`** | removed/deprecated elsewhere |
| `BaseSettings` (in `pydantic`) | **`pydantic_settings.BaseSettings`** | separate `pydantic-settings` package |

- **Behaviour change to watch:** a field typed `Optional[str]` with **no default** is **required** (may be `None`), and does **not** default to `None` — a breaking change from v1. Also `Field(union_mode="smart")` is the new default.
- **Patterns use Rust `regex`** (no look-around/back-references) for linear-time safety on untrusted input — a plus for a security product. `email-validator>=2` required.

**Gilgamesh implication:** the normalized event model (Decisions D-004) should be a v2 `BaseModel` with `model_config = ConfigDict(from_attributes=True)`, use `field_validator`/`model_validator`, and serialize with `model_dump()` / `model_dump_json()`. Input validation on every threshold/rule field uses `Annotated[..., Field(...)]` constraints.

---

## 3. Jinja2 templating

- **Current version:** Jinja2 **3.1.6** (PyPI, 2026-10-14). FastAPI's `standard` extra pins `jinja2>=3.1.5`.
- **Mounting (FastAPI docs, "Templates"):** FastAPI re-exports Starlette's templating. Create one reusable `Jinja2Templates` and mount static files:

```python
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


@app.get("/items/{id}", response_class=HTMLResponse)
async def read_item(request: Request, id: str):
    return templates.TemplateResponse(
        request=request, name="item.html", context={"id": id}
    )
```

  **Important signature note (from the docs):** *"Before FastAPI 0.108.0, Starlette 0.29.0, the `name` was the first parameter."* On current versions, pass **`request=` and `name=` as keywords** (the `request` is no longer part of the `context` dict). `url_for('static', path=...)` works inside templates.
- **Sharing partials with htmx:** Jinja has first-class composition — `{% extends "base.html" %}`, `{% block %}`, and `{% include "partials/foo.html" %}` (Jinja Template Designer docs). htmx expects **HTML fragments**, and the server distinguishes a full-page load from an htmx request. The documented htmx mechanism is the request header **`HX-Request: true`** (also `HX-Target`, `HX-Trigger`) plus `hx-boost` for progressive enhancement. Pattern:

```
templates/
  base.html              # skeleton with {% block content %}
  pages/dashboard.html   # {% extends "base.html" %}{% block content %}{% include "partials/alert_feed.html" %}{% endblock %}
  partials/alert_feed.html   # rendered alone for htmx swaps
```

  Server side: one route returns `base.html` when `HX-Request` is absent (full navigation) and only `partials/...` when present. Keep the fragment markup in a `partials/` file so both paths render identical HTML (no duplication). htmx can also pick a sub-tree from a full response with `hx-select`, but the server-side partial approach is simpler and cheaper on the Pi.
- **Jinja2 `{% include %}` context note:** included templates inherit the current context by default; imports (`{% import %}`/`{% from %}`) are cached and do **not** get the current context unless `with context` is used.

---

## 4. htmx

- **Current version: htmx 2.0.11** (npm `htmx.org@2.0.11`, licence **0BSD**). The docs site ships 2.0.11 in its CDN snippets. htmx 1.x is still maintained (supports IE11) but **2.x is current**.
- **Module files (2.x):** `dist/htmx.esm.js`, `dist/htmx.amd.js`, `dist/htmx.cjs.js`; `dist/htmx.js` remains browser-loadable; `dist/htmx.min.js` is the browser build for `<script src=...>`.

### 4.1 htmx 1.x → 2.x differences that matter (official migration guide)

- **Extensions have been removed from core** and are distributed separately. In particular the **SSE extension must be upgraded to its 2.x version** (`htmx-ext-sse`, currently 2.2.4). The legacy built-in `hx-sse` / `hx-ws` attributes are gone — you now use `hx-ext="sse"` + `sse-connect="..."` + `sse-swap="..."`.
- **`hx-on` changed syntax:** the old `hx-on="event: code"` bundle must become per-attribute **`hx-on:<event-name>="..."`** using **kebab-case** event names (HTML attributes are case-insensitive), e.g. `hx-on:htmx:before-request="..."`.
- **Changed defaults:**
  - scrolling is **no longer `smooth`** — revert with `htmx.config.scrollBehavior = 'smooth'` if the old feel is wanted;
  - **`DELETE` now sends a form-encoded body** by default (the migration guide calls the spec-driven URL-params form "a little crazy"); revert with `htmx.config.methodsThatUseUrlParams = ["get"]` if needed;
  - **`htmx.config.selfRequestsOnly` defaults to `true`** — cross-origin requests require setting it to `false` (leave it `true` for us; our UI is same-origin).
- **`htmx.makeFragment()` always returns a `DocumentFragment`** (extension authors).
- Internal extension API `selectAndSwap` was replaced by `swap`.
- **IE is no longer supported in 2.0** (irrelevant for us, but it's a defining 2.x break).
- Newer 2.x additions useful to us: **`<hx-partial hx-target="...">`** server-sent multi-target swap commands, and View Transitions support (`htmx.config.globalViewTransitions`, `transition:true` in `hx-swap`). Treat these as optional polish.

### 4.2 Vendoring htmx locally (offline + CSP)

- **Vendor a single file.** Download `htmx.min.js` (2.0.11) once on the dev machine and commit it to `static/vendor/htmx.min.js`; load it with `<script src="/static/vendor/htmx.min.js" defer></script>`. The docs explicitly endorse "Download a copy … add it to the appropriate directory in your project." Do **not** use the CDN in production (docs link to "why not JavaScript CDN"); we are offline-first.
- **Integrity/hash:** the CDN snippets publish Subresource Integrity hashes. Once vendored and served same-origin, SRI is optional; if kept, pin the exact file and hash (a self-hosted file can still carry `integrity`, but it adds churn on upgrades).
- **CSP:** htmx core does **not** require `unsafe-eval` for normal usage. htmx exposes `htmx.config.allowEval` which *"can be set to `false` to disable all features of htmx that rely on eval"* — specifically **event filters**, **`hx-on:`**, **`hx-vals` with the `js:` prefix**, and **`hx-headers` with the `js:` prefix**. For a hard CSP with no `unsafe-eval`, set `allowEval = false` and avoid those four features (or re-implement them with your own event-listener JavaScript). htmx also documents CSP via `<meta http-equiv="Content-Security-Policy" content="default-src 'self';">` and `htmx.config.selfRequestsOnly`.
- **CSRF (documented):** htmx supports automatic CSRF-token headers via `hx-headers` on `<html>`/`<body>` (e.g. `hx-headers='{"X-CSRF-TOKEN": "..."}'`), and warns `hx-boost` does not replace `<html>`/`<body>`. Pair with the same-origin session cookie (`SameSite`). (Deeper CSRF design → doc 06.)

---

## 5. Alpine.js

- **Current version: Alpine.js 3.17.4** (npm `alpinejs`, MIT). The CSP build is a **separate package, `@alpinejs/csp`, also 3.17.4 (MIT)** — it is a full Alpine replacement, not a plugin.
- **Install shape (docs):** include from a `<script>` tag (with `defer`) or `npm install alpinejs` + `import Alpine from 'alpinejs'; Alpine.start();`. `Alpine.start()` must be called **once per page**.
- **CSP-friendly build — when it is required (official CSP page):** the **default** Alpine build parses inline expressions from attributes such as `x-on:click="..."` using `new Function` declarations, which **violate a strict `Content-Security-Policy` that omits `'unsafe-eval'`**. The docs state Alpine *"offers an alternate build that doesn't violate `unsafe-eval` and supports most of Alpine's inline expression syntax."*

  → **Rule for Gilgamesh:** if (as a security product should) we serve a strict CSP **without** `'unsafe-eval'`, we **must** ship the **`@alpinejs/csp`** build. If we deliberately allow `'unsafe-eval'`, the default build works — we do **not** want that.

- **CSP-build limitations (documented) — supported vs not:**
  - ✅ object/array literals, arithmetic/comparison/ternary, simple method calls (`items.push('c')`), `x-model`, assignments like `count++`.
  - ❌ property assignment (`user.name = 'John'`), arrow functions, destructuring, template literals, spread; ❌ global objects/functions (`console`, `window`, `document`, `Math`, `JSON`, `parseInt`); ❌ `x-html` / HTML injection.
  - Guidance: **extract complex logic into `Alpine.data('componentName', () => ({...}))`** and reference simple values in markup. The docs show exactly this for a `userManager` component with a `get hasActiveAdmins()` getter.
  - The CSP example header the docs recommend is `Content-Security-Policy: default-src 'self'; script-src 'nonce-[random]' 'strict-dynamic';` (drop `'unsafe-eval'`).

- **Scope discipline (C3):** Alpine is for **small local UI state only** — dropdowns, tabs, modals, form toggles, mobile nav. No application data fetching and no app state in Alpine (data lives server-side, delivered by htmx).

---

## 6. Tailwind CSS standalone CLI

- **Current major: Tailwind CSS v4 (latest release `v4.3.3`, 2026-07-16, MIT).** v4 is a **different setup from v3** — mixing the two is the exact pitfall called out in PROMPT §4.

### 6.1 v3 vs v4 (do NOT mix) — official Upgrade Guide

| | v3.x | **v4.x (chosen)** |
|---|---|---|
| Entry CSS | `@tailwind base; @tailwind components; @tailwind utilities;` | **`@import "tailwindcss";`** (single import; the `@tailwind` directives are **removed**) |
| Config | `tailwind.config.js` + `content: [...]` | **CSS-first** `@theme { --color-… }`, `@source`, `@utility`, `@custom-variant`; a JS config is **no longer auto-detected** (load explicitly with `@config "…"` if ever needed) |
| CLI package | `tailwindcss` was the PostCSS plugin | CLI lives in **`@tailwindcss/cli`**; PostCSS plugin in `@tailwindcss/postcss`; Vite plugin `@tailwindcss/vite` |
| Browser target | older browsers | **Safari 16.4+, Chrome 111+, Firefox 128+** (uses `@property`, `color-mix()`) |
| Custom classes | `@layer utilities/components` hijacked | native cascade layers; use **`@utility`** |
| Opacity/scale renames | `bg-opacity-*`, `shadow`, `rounded`, `ring` | `bg-black/50`; `shadow-sm`, `rounded-sm`; `ring` → **`ring-3`**; `outline-none` → **`outline-hidden`** |
| Theme fn | `theme(colors.x)` | prefer `var(--color-x)` |
| Preprocessors | Sass/Less allowed | **Sass/Less/Stylus not supported** |

> **Warning (explicit):** do **not** keep a `tailwind.config.js` `content` array alongside `@import "tailwindcss"` and expect it to work, and do **not** copy v3 `@tailwind base/components/utilities` directives into a v4 file. Pick v4 syntax throughout. If a snippet or tutorial uses `@tailwind …` or `module.exports = { content: … }`, it is v3 — ignore it.

### 6.2 The standalone CLI story (no Node.js)

- The docs' Tailwind CLI page states: *"The CLI is also available as a **standalone executable** if you want to use it without installing Node.js"*, linking to the releases page. The standalone binary **is** the v4 CLI (same flags), built from the v4 release.
- **linux-arm64 assets are published.** From the GitHub release API for **`v4.3.3`**, the published assets include:
  - **`tailwindcss-linux-arm64`** (glibc) — `https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.3/tailwindcss-linux-arm64` (sha256 `55fd0b241214eff3de1e8ee4f22796662f2d2e7a49bcfca7477cfd0bac398195`)
  - **`tailwindcss-linux-arm64-musl`** (musl) — for Alpine-style userlands
  - plus `tailwindcss-linux-x64`, `tailwindcss-macos-arm64`, `tailwindcss-macos-x64`, `tailwindcss-windows-x64.exe`, and `sha256sums.txt`.
  - Raspberry Pi OS 64-bit (Debian glibc) → use **`tailwindcss-linux-arm64`**.
- **CLI flags (verified in the official v4 CLI source `packages/@tailwindcss-cli/src/commands/build/index.ts`):** `-i/--input`, `-o/--output`, `-w/--watch`, `-m/--minify`, `--optimize` (optimize without minify), `--poll[=ms]` (watch without FS events), `--cwd`, `--map`, `--silent`, `-h/--help`.

**Documented v4 setup, adapted to the standalone binary:**

```bash
# On a linux-arm64 machine (Pi or arm64 dev box), once:
curl -fsSLO https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.3/tailwindcss-linux-arm64
chmod +x tailwindcss-linux-arm64        # install as e.g. ./tools/tailwindcss
```
```css
/* static/css/app.css  (committed source) */
@import "tailwindcss";
@source "../../templates";   /* scan Jinja templates for class names */
```
```bash
# One-off build; output is committed:
./tailwindcss-linux-arm64 -i static/css/app.css -o static/css/app.css -m
# Dev loop:
./tailwindcss-linux-arm64 -i static/css/app.css -o static/css/app.css --watch
```

**Recommended workflow (offline-first, C5):** build the CSS **on the dev machine** (x64 arm64 or x64 — asset `tailwindcss-linux-x64` / `macos-arm64` as appropriate), **commit `static/css/app.build.css`**, and never run Tailwind on the Pi at all. If desired, also commit the arm64 binary path in `.gitignore` and document the one-time download; the important artefact is the **built CSS**, which needs no toolchain at runtime. `@source` (not a JS `content` array) is the v4 way to point the scanner at the templates.

> **UNVERIFIED:** the exact standalone-binary `--help` text on the arm64 asset was not executed here. Flags were verified from the v4 CLI **source**; confirm with `./tailwindcss-linux-arm64 --help` at build time.

---

## 7. Live updates on the dashboard

**Recommendation: Server-Sent Events (SSE) using FastAPI's native support.**

- **`StreamingResponse` (baseline).** FastAPI's *"Custom Response — HTML, Stream, File, others"* page documents `StreamingResponse` (from Starlette) for streaming bodies, e.g. wrapping a sync/async generator. It is the generic primitive; SSE is a specific content type on top of it.
- **Native SSE (current, preferred).** FastAPI now documents SSE as a *first-class* feature: use `yield` in the path operation and set `response_class=EventSourceResponse`, importing from **`fastapi.sse`**:

```python
from collections.abc import AsyncIterable
from fastapi import FastAPI
from fastapi.sse import EventSourceResponse, ServerSentEvent

app = FastAPI()

@app.get("/alerts/stream", response_class=EventSourceResponse)
async def stream_alerts() -> AsyncIterable[ServerSentEvent]:
    yield ServerSentEvent(comment="alert feed")
    async for event in alert_source():
        yield ServerSentEvent(data=event, event="alert", id=str(event.id))
```

  Documented behaviour: `data` is always JSON-encoded (declare the return type — e.g. `AsyncIterable[Item]` — and FastAPI uses Pydantic to validate/serialize, with Rust-side speed); `raw_data` sends non-JSON text; `data`/`raw_data` are mutually exclusive; **`Last-Event-ID` resume is supported** via a `Header()` parameter; SSE works over `POST` too. FastAPI automatically sends **a `ping` comment every 15 s** keep-alive, sets **`Cache-Control: no-cache`**, and sets **`X-Accel-Buffering: no`** (plus `Content-Type: text/event-stream`).
- **Version note:** *"Added in FastAPI 0.135.0."* We are on **0.143.0**, so this is available.
- **Is `sse-starlette` needed?** **No.** For FastAPI ≥ 0.135.0 the built-in `fastapi.sse.EventSourceResponse` / `ServerSentEvent` covers it. `sse-starlette` remains a legitimate, permissively licensed (**BSD-3-Clause**, 3.5.0) third-party alternative and is what FastAPI historically used/pointed to, but adding it now would duplicate functionality. Keep it only if we later need a Starlette-only (non-FastAPI) server.
- **Client side (htmx vs raw `EventSource`):**
  - Option A — the official **htmx SSE extension** (`htmx-ext-sse` 2.2.4): `hx-ext="sse"`, `sse-connect="/alerts/stream"`, `sse-swap="alert"`. It is documented, adds automatic reconnection with exponential backoff, and swaps server-sent HTML fragments directly into the DOM. **However, its licence could not be verified (no `license` field on npm; the extensions repo has no detected licence file)** — this conflicts with hard constraint **C1** (record the licence of every dependency) and is flagged in [Open questions](#open-questions--unverified).
  - Option B — **a tiny native `EventSource` snippet we own** (~10–15 lines) that listens on `/alerts/stream` and, on each message, re-issues an htmx request or swaps HTML. No third-party code, no licence ambiguity, fully controllable under a strict CSP (load it with a nonce). **Preferred** until the extension's licence is confirmed.
- **SSE vs polling-with-htmx on a Pi 4 (4 GB):**

  | | SSE (native) | htmx polling (`hx-trigger="every Ns"`) |
  |---|---|---|
  | Bandwidth | one long-lived HTTP/1.1 connection; only event bytes | one request+response per interval **per open tab**, even when nothing changed |
  | Server CPU | push when an event occurs; 1 `ping`/15 s idle | re-render + template + DB query every interval |
  | Latency | near-instant | up to `N` seconds |
  | Complexity | server async generator + event bus; connection lifecycle per client | trivial; just a trigger |
  | Fits Pi | good (few clients: a home UI has 1–3 tabs) | fine at low frequency, wasteful at high frequency |
  | htmx model | htmx SSE extension or a few lines of `EventSource` | pure htmx, no extension |
  | Failure mode | needs reconnect logic (browser auto-reconnects; `Last-Event-ID` resumes) | self-healing by nature |

  **Decision:** use **SSE with a fast dashboard feed**, and keep **htmx polling** for things that are naturally coarse or where a live socket is unnecessary (e.g. "system health" every 5–10 s, "ruleset version"). This keeps one long connection instead of a request storm, which matters on a 4 GB Pi and on battery-powered clients. (Also documented: SSE is uni-directional; we never need server→client pushback, so that's fine.)

---

## 8. Static asset + offline strategy

**Principles:** everything is served same-origin from `/static`; **no CDN, no Node.js, no network at runtime**. Third-party JS/CSS/fonts are downloaded **once on the dev machine** and **committed**. Hash-pin and record the upstream URL + licence for each vendored file.

**Proposed layout** (`StaticFiles(directory="…/static")` mounted at `/static`):

```
gilgamesh/
├── pyproject.toml
├── uv.lock
├── tools/
│   └── tailwindcss-linux-x64            # dev-only binary (gitignored), builds arm64-compatible CSS
├── src/gilgamesh/
│   ├── web/
│   │   ├── app.py                       # FastAPI(lifespan=...), mount StaticFiles, Jinja2Templates
│   │   ├── templates/
│   │   │   ├── base.html                # <script defer src="/static/vendor/..."> , Tailwind <link>
│   │   │   ├── pages/                   # full pages (extend base)
│   │   │   └── partials/                # htmx fragments (also used via {% include %})
│   │   └── static/
│   │       ├── vendor/                  # committed, licence + version recorded
│   │       │   ├── htmx.min.js          # htmx 2.0.11 (0BSD)
│   │       │   ├── alpine-csp.min.js    # @alpinejs/csp 3.17.4 (MIT)
│   │       │   ├── app-live.js          # our EventSource glue (no third-party licence)
│   │       │   ├── VENDOR.md            # name · version · SPDX · source URL · sha256 of each file
│   │       │   └── htmx-ext-sse.min.js  # OPTIONAL — omit until licence is verified
│   │       ├── css/
│   │       │   ├── app.css              # Tailwind v4 source (@import "tailwindcss"; @source ...)
│   │       │   └── app.build.css        # BUILT output, committed, served
│   │       └── fonts/                   # optional self-hosted .woff2 (prefer none — see below)
│   └── ...
└── ...
```

- **htmx:** vendor `htmx.min.js` 2.0.11 (0BSD). Load `<script src="/static/vendor/htmx.min.js" defer>` before body scripting. Set `htmx.config.allowEval = false` when using a strict CSP.
- **Alpine:** vendor the **CSP build** `@alpinejs/csp` 3.17.4 as `alpine-csp.min.js` (MIT), load with `defer`. Because the CSP build forbids complex inline expressions, keep components in a separate `app-live.js`/`app-alpine.js` using `Alpine.data(...)`/`Alpine.start()`.
- **Tailwind output:** vendor only the **built CSS** `app.build.css` (committed). The Tailwind **source** `app.css` and the dev binary are not needed at runtime. Use v4 `@source "../../templates";` so template classes are scanned. Consider `-m` (minify) for the production artefact.
- **Fonts (offline, no CDN):** simplest and lightest for a Pi appliance is a **system font stack** (`font-sans` default / CSS `system-ui, -apple-system, "Segoe UI", Roboto, …`) — **zero bytes**, no FOUT, no licensing. If we want a specific typeface, self-host **WOFF2** files in `static/fonts/` (e.g. an OFL-licensed face such as Inter), download once on the dev machine, commit, and `@font-face` them; do **not** use Google Fonts / any CDN. (Licence + asset choice → doc 03.)
- **CSP & offline:** a strict policy such as `default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self' 'nonce-…'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'` works with everything above, because all assets are same-origin. `connect-src 'self'` also permits the SSE `EventSource` to `/alerts/stream`. Avoid `'unsafe-eval'` (hence the Alpine CSP build and `htmx.config.allowEval = false`).
- **Progressive enhancement:** use `hx-boost` on navigation so links/forms still work without JS, and make partial updates additive on top of full-page rendering.
- **Reproducibility:** record in `static/vendor/VENDOR.md` for each file: name, exact version, SPDX licence, source URL, sha256 — this satisfies C1 and the "record the licence of each dependency" rule.

---

## Sources

Official docs / registries, all accessed **2026-10-14**:

- FastAPI — Lifespan Events: https://fastapi.tiangolo.com/advanced/events/
- FastAPI — Templates: https://fastapi.tiangolo.com/advanced/templates/ · Reference Templating: https://fastapi.tiangolo.com/reference/templating/
- FastAPI — Server-Sent Events (SSE): https://fastapi.tiangolo.com/tutorial/server-sent-events/ · Reference SSE: https://fastapi.tiangolo.com/reference/sse/
- FastAPI — Custom Response (StreamingResponse): https://fastapi.tiangolo.com/advanced/custom-response/
- FastAPI — Migrate from Pydantic v1 to v2: https://fastapi.tiangolo.com/how-to/migrate-from-pydantic-v1-to-pydantic-v2/
- FastAPI — Static Files: https://fastapi.tiangolo.com/tutorial/static-files/
- FastAPI — Release Notes / versions: https://fastapi.tiangolo.com/release-notes/ · PyPI JSON: https://pypi.org/pypi/fastapi/json
- Pydantic — Migration Guide: https://docs.pydantic.dev/latest/migration/ · PyPI JSON: https://pypi.org/pypi/pydantic/json
- Jinja2 — Template Designer (inheritance/include): https://jinja.palletsprojects.com/en/stable/templates/#template-inheritance · PyPI JSON: https://pypi.org/pypi/Jinja2/json
- htmx — Documentation: https://htmx.org/docs/ · 1.x→2.x Migration Guide: https://htmx.org/migration-guide-htmx-1/ · SSE extension: https://htmx.org/extensions/sse/ · npm: https://registry.npmjs.org/htmx.org/latest
- Alpine.js — Installation: https://alpinejs.dev/essentials/installation · CSP build: https://alpinejs.dev/advanced/csp · npm: https://registry.npmjs.org/alpinejs/latest and https://registry.npmjs.org/@alpinejs/csp/latest
- Tailwind CSS — Installation / Tailwind CLI: https://tailwindcss.com/docs/installation/tailwind-cli · Upgrade guide (v3→v4): https://tailwindcss.com/docs/upgrade-guide · Releases: https://github.com/tailwindlabs/tailwindcss/releases · CLI source: https://github.com/tailwindlabs/tailwindcss/blob/main/packages/@tailwindcss-cli/src/commands/build/index.ts
- sse-starlette (optional) — PyPI JSON: https://pypi.org/pypi/sse-starlette/json · repo: https://github.com/sysid/sse-starlette
- Licence checks via GitHub REST API `license.spdx_id` for: fastapi/fastapi (MIT), pydantic/pydantic (MIT), pallets/jinja (BSD-3-Clause), encode/starlette (BSD-3-Clause), encode/uvicorn (BSD-3-Clause), tailwindlabs/tailwindcss (MIT), alpinejs/alpine (MIT).

## Open questions / UNVERIFIED

1. **`htmx-ext-sse` licence — UNVERIFIED.** npm `htmx-ext-sse@2.2.4` carries **no `license` field**, and `bigskysoftware/htmx-extensions` has **no detected licence file** (GitHub API `license: null`; `LICENSE` 404). This violates C1 as-is. **Action:** either (a) don't use the extension and ship a ~10-line native `EventSource` script we own (preferred), or (b) confirm the licence with the maintainers before vendoring.
2. **Standalone arm64 binary `--help` on-device** — flags were verified from the v4 CLI **source**, not by executing the downloaded arm64 asset. Confirm with `./tailwindcss-linux-arm64 --help` before wiring the build.
3. **Tailwind v4 browser support on the target tablet/phone** — v4 requires Safari 16.4+/Chrome 111+/Firefox 128+. Confirm the admin's browser is new enough; if not, the alternative is v3.4 with the standalone binary (v3 has a *different* setup). Not expected to be an issue in 2026.
4. **Alpine CSP build completeness** — the CSP build explicitly does **not** support globals, `x-html`, arrow functions, destructuring, or template literals. Confirm our planned small components (dropdowns/modals/tabs) need none of those; if any do, restructure into `Alpine.data()`.
5. **SSE behind a reverse proxy / HTTPS** — FastAPI sets `X-Accel-Buffering: no` and a 15 s ping, but if we later front the app with a proxy, verify its buffering/timeout settings. (No proxy planned for v1; self-signed HTTPS → doc 06.)
6. **Multiple open tabs / SSE connection count** — Uvicorn worker model and max concurrent SSE connections per worker were not researched here; validate with an N-tab load note during doc 04 (architecture) / doc 07 (deployment). If workers > 1, an in-process event bus will not reach all SSE clients — plan for a single worker or a shared broadcast (e.g. SQLite poll or a small broker).
7. **htmx `<hx-partial>` and View Transitions** — documented as 2.x features but relatively new; treat as optional polish, verify behaviour in the pinned 2.0.11 build before relying on them.
8. **Exact Alpine/Tailwind/htmx asset sha256 values** — to be recorded in `static/vendor/VENDOR.md` at vendoring time (not captured here).

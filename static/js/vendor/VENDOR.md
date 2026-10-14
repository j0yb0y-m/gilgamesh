# Vendored frontend assets

Offline-first (constraint C5): every asset is served from this machine. There are **no CDN
links and no external fonts** anywhere in the templates, so the appliance works with the
internet disconnected.

Versions verified against the npm registry on 2026-10-14. Rebuilding or upgrading an
asset means updating the version, re-downloading, and re-recording the hash below.

| File | Package | Version | Licence (SPDX) | SHA-256 |
|---|---|---|---|---|
| `htmx.min.js` | `htmx.org` | 2.0.11 | `0BSD` | `d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717` |
| `alpine-csp.min.js` | `@alpinejs/csp` | 3.17.4 | `MIT` | `0d18d7f8d7910e2e0212f0f056b12f50bebc3abb7d88d2f7c7cb4c336fe4519a` |

## Why Alpine's **CSP** build

The Content-Security-Policy header Gilgamesh sends deliberately omits `unsafe-eval`
(no inline event handlers, no `new Function`). Alpine's default build *requires*
`unsafe-eval`, because it parses expression strings. The separate `@alpinejs/csp` package
removes that requirement at the cost of forbidding inline JavaScript expressions — so
component code uses `Alpine.data()` and plain attribute bindings rather than
`x-on:click="doThing(1)"`.

## Why htmx 2.0.11 and not 4.0.0

`htmx.org@4.0.0` is published under the `next` dist-tag; `latest` is still 2.0.11. A
fetch-based rewrite released in August 2026 is the wrong risk for an appliance that is
hard to debug remotely. Re-evaluate before v1.1.

## Why no `htmx-ext-sse`

Its licence is not declared in the npm metadata and no licence file was detected, which
fails C1 (open source only). The SSE client is instead ~15 lines of our own JavaScript in
`static/js/app.js`.

## Tailwind CSS

Tailwind is a **build-time** tool, not a runtime asset. The v4.3.3 standalone CLI builds
`static/css/app.css` from `static/css/input.css` on a development machine; the generated
CSS is committed so the Raspberry Pi never needs Node.js (constraint C6). The CLI binary is
deliberately **not** committed.

Source: `static/css/input.css` · licence `MIT` · https://github.com/tailwindlabs/tailwindcss

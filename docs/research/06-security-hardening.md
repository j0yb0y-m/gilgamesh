# 06 — Security Hardening (Gilgamesh web UI + configuration surface)

**Session:** Phase 1 — Research & Plan (Markdown only)
**Date:** 2026-10-14
**Scope of this file:** the security of *Gilgamesh itself* (PROMPT §3.3 item 8). It does **not** cover the detection engines' internals (docs 02/03) or the deployment mechanics (doc 07).
**Rule for this file:** every non-obvious claim has a source in `## Sources`. Anything I could not confirm is marked **UNVERIFIED** and repeated in `## Open questions / UNVERIFIED`.

> **Currency note (2026-10-14).** Several assumptions in `PROMPT.md` are out of date and are corrected here:
> - **htmx:** `PROMPT.md` §4 says "htmx 1.x and 2.x differ". The current situation is 1.x (legacy) → **2.x (current, documented as latest)** → **4.0.0 released 2026-08-28 but not yet the npm `latest` tag** (npm `latest` = 2.0.11, npm `next` = 4.0.0). [S13][S36]
> - **Starlette** is now **1.8.0** and already ships `RequestBodyLimitMiddleware`, which directly addresses request-size DoS (see §7). [S9]
> - **bcrypt** is now **Apache-2.0** (not the older dual BSD/Beerware wording); `bcrypt` 5.0.0.
> - **pwdlib** (the Argon2/bcrypt wrapper) is still **Beta** (0.3.1), so it is optional, not a required dependency.

---

## 1. Password hashing

### Verified facts

- **Algorithm choice.** OWASP's Password Storage Cheat Sheet puts **Argon2id first** ("If Argon2id is available, use it"), then scrypt, then bcrypt, then PBKDF2. It publishes minimum parameter sets, e.g. the low-memory profile **m=47104 KiB (46 MiB), t=1, p=1**, and an even smaller **m=19456 KiB (19 MiB), t=2, p=1**; it also lists m=12288/t=3, m=9216/t=4, m=7168/t=5. [S1]
- **`argon2-cffi` 25.1.0** (MIT, pure-Python wheel `py3-none-any`) provides the high-level `argon2.PasswordHasher`. [S2][S4]
  - Signature: `PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16, encoding='utf-8', type=Type.ID)`. [S2]
  - Defaults come from `argon2.profiles.RFC_9106_LOW_MEMORY` (**64 MiB**, t=3, p=4, Argon2id). [S2][S3]
  - `hash(password)` returns an encoded string; `verify(hash, password)` raises `VerifyMismatchError` (a subclass of `VerificationError`) on mismatch and `InvalidHashError` if the stored hash is malformed; `check_needs_rehash(hash)` returns whether the stored hash used older parameters. [S2]
  - `verify()` is **not** constant-time-safe by contract: "It is assumed that the caller is in full control of the hash." Never pass an attacker-chosen string as `hash` in a way that changes control flow. [S2]
  - The low-level `argon2.low_level` API is explicitly for advanced/non-password use; do not use it for passwords. [S2]
- **aarch64 wheels.** `argon2-cffi` itself is pure Python; the native part is `argon2-cffi-bindings` **26.1.0** (MIT), which publishes `cp310-abi3-manylinux_2_26_aarch64.manylinux_2_28_aarch64` (an abi3 wheel that covers CPython ≥ 3.10) plus cp314/cp315 aarch64 wheels. So a 64-bit Raspberry Pi OS build (glibc ≥ 2.26) installs a prebuilt wheel. [S4][S5]
- **Benchmarking tool.** argon2-cffi ships a CLI: `python -m argon2 --profile RFC_9106_LOW_MEMORY` reports per-verification time on the actual machine. [S2][S3]
- **Alternative** `bcrypt` 5.0.0 (Apache-2.0) has `cp38-abi3-manylinux...aarch64` wheels; OWASP requires work factor ≥ 10 and notes bcrypt truncates at **72 bytes**. [S1][S6]
- **Wrapper** `pwdlib` 0.3.1 (MIT, released 2026-08-12, **Development Status: Beta**) wraps Argon2/bcrypt behind one interface. Optional convenience, not required. [S7]

### Recommendation for Gilgamesh

- **Use Argon2id via `argon2-cffi` 25.1.0** (MIT). It is the OWASP-first choice, pure Python + an aarch64 wheel, and is maintained. Record SPDX `MIT` for `argon2-cffi` and `argon2-cffi-bindings` in doc 03.
- Construct **one module-level `PasswordHasher`** and reuse it (constructing per-request re-validates parameters every time). [S2]
- Start from the argon2-cffi default profile (**t=3, m=64 MiB, p=4**) and **confirm the exact parameters by running `python -m argon2 --profile RFC_9106_LOW_MEMORY` on the Pi 4** during build; store the chosen parameters as constants so `check_needs_rehash()` can detect drift later. [S2][S3]
  - Memory budget: 64 MiB per *concurrent* verification. With login rate limiting (§4) and a single admin, this is fine on 4 GB; if the memory budget in doc 04 is tight, fall back to the OWASP 19 MiB/t=2/p=1 profile. `p=4` buys little on a 4-core Pi under a single login — benchmark and prefer `p=2` if it changes nothing. *(Exact final numbers → PROVISIONAL, benchmark in build.)*
- On successful login: call `check_needs_rehash(stored)`; if `True`, re-hash the cleartext and update the row (the only moment the cleartext is available). [S2]
- Map exceptions explicitly: `except VerifyMismatchError: ...` (wrong password) and `except InvalidHashError: ...` (corrupt row) — never a bare `except`. [S2]
- **Interaction with §4:** Argon2 is deliberately CPU/memory-expensive, so the login endpoint is a DoS target. Rate-limit and cap concurrency *before* hashing; do not run unbounded parallel verifications.

### Do not

- Do not store passwords in the SQLite DB as anything other than the encoded argon2 string. Never log them, never put them in the session cookie, never compare with `==`.
- Do not use raw SHA-256/MD5/PBKDF2 for passwords; do not use `argon2.low_level` for passwords. [S2]

---

## 2. Session management

### Verified facts

- Starlette ships **`SessionMiddleware`**: signed *cookie-based* sessions; "information is readable but not modifiable"; the cookie is always set `HttpOnly`; it is backed by `itsdangerous.TimestampSigner`. [S9][S10]
  - Signature: `SessionMiddleware(app, secret_key, session_cookie="session", max_age=14*24*60*60, path="/", same_site="lax", https_only=False, domain=None, partitioned=False)`. Data is read/written via the `request.session` dict. [S9]
  - `max_age` is a single absolute expiry; `same_site` defaults to `"lax"`; `https_only=True` adds the `Secure` attribute. [S9]
  - Changes to nested values are not auto-tracked — reassign the top-level key. [S9]
- **`itsdangerous` is not a hard Starlette dependency.** It is only pulled in by the `full` extra, so it must be added explicitly when using `SessionMiddleware`. [S9][S11]
- OWASP Session Management requires: `Secure` + `HttpOnly` (+ `SameSite`), ≥ 64 bits of entropy in the session ID, **renew the session ID on privilege change** (login) to stop fixation, and enforce **both idle and absolute timeouts**. [S8]
- OWASP explicitly recommends logging out / invalidating all sessions after a password change. [S8]

### Recommendation for Gilgamesh

- Add **`itsdangerous`** (2.2.0, [S11]) to the dependency list explicitly (it is a Starlette `full`-extra dep only). [S9]
- Use a **server-side session record**, not a fat signed cookie:
  - The cookie carries only an **opaque, random `sid`** (`secrets.token_urlsafe(32)`, ≥ 64 bits entropy [S8]) signed by `SessionMiddleware`.
  - A SQLite `sessions` table stores `sid, user_id, created_at, last_seen_at, expires_at, user_agent, ip`. This gives **revocability** (logout, "log out everywhere", change-password invalidation) and both **idle** and **absolute** timeouts, which a pure signed cookie cannot do. [S8]
- Configure `SessionMiddleware` with `secret_key` = ≥ 32 random bytes from `secrets`/`os.urandom`, `session_cookie="gilgamesh_session"`, `same_site="lax"`, `path="/"`, and **`https_only=True` when TLS is enabled** (§5). [S9]
- Session ID rotation: on login, discard the pre-auth session and issue a fresh `sid`; after password change, delete all `sessions` rows for that user. [S8]
- Timeouts: pick an idle timeout (e.g. 30 min) and an absolute cap (e.g. 12 h); the cookie `max_age` should be ≥ the absolute cap and the DB row enforces the finer policy. *(Exact values → PROVISIONAL, doc 04.)*
- Set `X-Content-Type-Options: nosniff` and a `Referrer-Policy` globally (§ cross-cutting headers), and rely on `SameSite=Lax` only as *defense in depth* — it is **not** a CSRF control on its own (§3). [S8][S12]

### Do not

- Do not store secrets, roles, or anything confidential *inside* the signed cookie: it is signed, **not encrypted**, so the user can read it. Keep the payload to the opaque `sid`. [S9]
- Do not rely on `max_age` alone; OWASP requires an idle timeout too. [S8]

---

## 3. CSRF for htmx

### Verified facts

- OWASP CSRF Cheat Sheet: **stateful applications should use the Synchronizer Token pattern**; stateless ones the **Signed Double-Submit Cookie**; AJAX/API endpoints may use a **custom request header**. Token must be unique per session, secret, and unpredictable; it must **not** be sent in a cookie for the synchronizer pattern, and must not leak into logs or URLs. [S12]
- A browser cannot set a *custom* request header on a cross-site "simple" form POST without triggering CORS preflight, which is why the custom-header approach works — but `.NET`-style built-ins aside, OWASP still recommends combining it with tokens. [S12]
- **htmx** supports `hx-headers`, a JSON object whose headers are added to every request and are **inherited** by descendant elements — the canonical place is `<body hx-headers='{"X-CSRF-Token": "..."}'>`. It also processes hidden inputs in forms. [S13][S14]
- htmx's request headers (`HX-Request`, `HX-Target`, …) are informational; do not treat `HX-Request` as a CSRF control by itself. [S13]

### Recommendation for Gilgamesh

- The app is stateful (cookie session) → **Synchronizer Token pattern**. [S12]
  1. Generate a random per-session CSRF token (`secrets.token_urlsafe(32)`) and store it **server-side** (in the `sessions` row or derived by HMAC from the `sid` + server `secret_key`).
  2. Render it into every page as `<meta name="csrf-token" content="…">` and set `<body hx-headers='{"X-CSRF-Token": "…"}'>`. [S13][S14]
  3. Also include a hidden `<input name="csrf_token">` in every real `<form>` (covers non-htmx submissions and progressive enhancement). [S12]
  4. On the server, validate the submitted token against the session for **every unsafe method (POST/PUT/PATCH/DELETE)** and reject with `403` on mismatch, using `hmac.compare_digest` (constant time). [S12]
- **Defense in depth** (implement at least one, per OWASP): [S12]
  - Keep `SameSite=Lax` on the session cookie. [S9][S12]
  - **Fetch Metadata**: reject unsafe methods where `Sec-Fetch-Site: cross-site`; allow `same-origin`/`none`; treat `same-site` conservatively. Because old browsers omit `Sec-Fetch-*`, always keep the Origin/Referer **fallback** (OWASP calls this fallback mandatory). [S12]
  - Origin/Referer check for unsafe methods.
- The custom-header requirement (`X-CSRF-Token`) complements the token: cross-site form posts cannot set it. [S12]
- Include a CSRF token on the **login form** too (login CSRF is a real case); the pre-login token can be stored in a short-lived signed cookie or a pre-session. [S12]
- Because htmx swaps fragments, make sure every rendered fragment that contains a form carries the token (inherit `hx-headers` on `<body>` so fragments need no extra work). [S13][S14]

### Do not

- Do not use the **Naive Double-Submit Cookie** (cookie-vs-parameter match): OWASP now marks it **DISCOURAGED** because it is bypassable by cookie injection (subdomain takeover, plaintext HTTP, non-`__Host-` cookies). If going stateless, use the *Signed* variant with session-bound HMAC. [S12]
- Do not use GET for state-changing actions. [S12]
- Do not rely on `SameSite` alone. [S12]
- Do not put the CSRF token in a cookie for the synchronizer pattern. [S12]

---

## 4. Login rate limiting & brute-force resistance

### Verified facts

- Two libraries are candidates:
  - **`slowapi` 0.1.10** (MIT, pure Python, released 2026-06-13): a Starlette/FastAPI port of flask-limiter. Usage is declarative: `@limiter.limit("5/minute")` on an endpoint that **must** accept `request: Request`. Backends: memory / Redis / Memcached (via `limits`). Websocket endpoints are unsupported. [S17]
  - **`limits` 5.8.0** (MIT, requires Python ≥ 3.10) is the real engine slowapi wraps: `storage.MemoryStorage()/RedisStorage()/MemcachedStorage()`, `strategies.FixedWindowRateLimiter/MovingWindowRateLimiter/SlidingWindowCounterRateLimiter`, `parse("5/minute")`, and `limiter.hit(rate, namespace, key)` returning `True`/`False`. An async API lives under `limits.aio`. [S18]
- **`slowapi`'s release cadence is slow** (0.1.9 → 2024-02, 0.1.10 → 2026-06). This is a maintenance risk to record in doc 03. [S17]
- OWASP Credential Stuffing Prevention recommends, among others: multi-dimensional rate limiting, account lockout/backoff, and CAPTCHA/second factor for repeated failures. [S15]
- OWASP Denial of Service recommends rate limiting plus early input validation (reject oversized/short-lived work before doing expensive processing). [S16]

### Recommendation for Gilgamesh

- **Layer three limits**, because the threats differ:
  1. **Per-account lockout with persistence** — a small SQLite table `login_attempts(identifier, window_start, fail_count, locked_until)`. On failure, increment; after N failures, lock with exponential backoff. Persist across restarts (defeats restart-resets-the-counter). *(N/backoff → PROVISIONAL; e.g. 5 failures → 15-min backoff doubling.)* [S15]
  2. **Per-IP request throttling at the HTTP layer** — use **`limits` directly with `MemoryStorage`** (`MovingWindowRateLimiter`), keyed by client IP, e.g. `20/minute`, applied to the login route. Use `limits` rather than `slowapi` so we depend on the maintained engine and avoid the thin wrapper; if the team prefers decorators, `slowapi` is acceptable but record the cadence risk. [S17][S18]
  3. **Global concurrency cap on hashing** — a semaphore around Argon2 verification so an attacker cannot spawn many simultaneous 64 MiB hashes and OOM the Pi. [S16]
- Run **a single Uvicorn worker** so `MemoryStorage` is coherent; if multiple workers are ever used, the limits backend must become shared. *(Note for doc 07.)* [S18]
- Timing / enumeration: always run *one* Argon2 verification, using a fixed dummy hash when the username is unknown, so response timing does not reveal account existence; never say "user not found" vs "wrong password". [S1][S15]
- Add a small constant delay/jitter on failures. [S15]
- Log failures (redacted — no passwords) and, because Gilgamesh is a NIDS, **raise a local alert after repeated failed logins** (nice, on-brand). [S15]
- Login must still pass through the CSRF check (§3) and the request-body size limit (§7). [S12][S16]

### Do not

- Do not implement limiting as an in-memory dict keyed by IP without persistence and without cap — it is trivially bypassed and can be a memory-exhaustion vector. [S16]
- Do not reveal whether the username exists. [S15]

---

## 5. Transport security & optional self-signed HTTPS

### Verified facts

- Uvicorn serves TLS directly from these options (confirmed in the 0.54.0 config/source): `--ssl-keyfile`, `--ssl-certfile`, `--ssl-keyfile-password`, `--ssl-ca-certs`, `--ssl-ciphers`, and `--host`/`--port`. *(cit.: Uvicorn repo — `uvicorn/main.py`, `uvicorn/config.py`; the docs site was unreachable from this workstation. [S19b])*
- OWASP HSTS Cheat Sheet: send `Strict-Transport-Security: max-age=…; includeSubDomains` **only once HTTPS is reliable**, and note that **HSTS removes the browser's ability to click through an invalid-certificate warning** — a serious foot-gun with a self-signed certificate. [S20]
- `secure`/`Secure` cookies only work over HTTPS; `HTTPSRedirectMiddleware` exists to force the scheme; `TrustedHostMiddleware` defends against Host-header attacks. [S9]
- `mkcert` (BSD-3-Clause) can create a locally-trusted CA so the browser shows no warning. [S21]

### Recommendation for Gilgamesh

- **Bind by default to the management interface only**, never `0.0.0.0`/`::`: `uvicorn ... --host <mgmt-ip> --port 8443`. This is the single most valuable transport control on a home appliance. [S19b]
- **HTTPS is optional in v1 but recommended.** When enabled, serve with Uvicorn:
  `--ssl-keyfile <key.pem> --ssl-certfile <cert.pem>` (add `--ssl-keyfile-password` if the key is encrypted). [S19b]
- **Certificate options, in order of user-friendliness:**
  1. **Local CA + server certificate** generated on the Pi (openssl, or `mkcert`-style). The user imports the CA once → no browser warning. Best UX, and the only case where HSTS is safe. [S21]
  2. **Plain self-signed certificate** (openssl `req -x509` / Python `cryptography`), SAN must include the management **IP** (e.g. `IP:192.168.x.x`) and/or hostname (`gilgamesh.local`); the user must click through the warning each time until the cert changes.
- **HSTS policy:**
  - With a trusted local CA → send `Strict-Transport-Security: max-age=63072000; includeSubDomains` (and consider `preload` **only** after confirming the cert is stable; preload is effectively irreversible for the domain). [S20]
  - With a plain self-signed cert → **do not send HSTS**, or a future invalid cert will lock the user out of their own device. [S20]
- **Cookie `Secure`:** set `SessionMiddleware(https_only=True)` **only** when TLS is on; otherwise the cookie is never sent. If the user runs HTTP, leave `https_only=False` and depend on the mgmt-interface-only bind. [S9]
- Enable `HTTPSRedirectMiddleware` only when TLS is permanently on. Add `TrustedHostMiddleware` with the known management IP/hostname. [S9]
- Generate/rotate the cert at first-run setup and expose it in Settings; keep the private key `0600` owned by the service user (§6). [S22]
- Prefer Python-ssl defaults (TLS 1.2+) and avoid legacy ciphers; only set `--ssl-ciphers` if a concrete need appears. *(Exact `--ssl-version` deprecation status in Uvicorn 0.54.0 → UNVERIFIED.)* [S19b]

### Do not

- Do not bind the UI to all interfaces. [S19b]
- Do not enable HSTS with a self-signed certificate. [S20]
- Do not put a private key or cert passphrase in the repo, in `argv` history, or in logs. [S22]

---

## 6. Secrets at rest

### Verified facts

- OWASP Secrets Management says to: centralize and standardize secret handling, apply least privilege, **rotate**, enable **logging/accounting/detection** of secret access and misuse, and avoid secrets in logs/URLs. [S22]
- On a single appliance with no KMS/vault, the pragmatic controls are **file permissions + a dedicated service user + log redaction**; full vaults (Vault, cloud KMS) are out of scope for a 4 GB Pi. [S22]

### Secret inventory for Gilgamesh

Session signing key, TLS private key (+ passphrase), Discord webhook URL, Telegram bot token, SMTP password, and any DB encryption key.

### Recommendation for Gilgamesh

- **File-based secrets, not code and not git:**
  - `/etc/gilgamesh/secrets.env` (or `secrets.json`) owned `root:gilgamesh`, mode **`0640`** (or `0600`), holding `SESSION_SECRET`, TLS key passphrase, etc.
  - Provide a committed **`.env.example`** with names only; **`.gitignore`** `.env`, `*.pem`, `*.key`, `secrets.env`. [S22]
  - Load at startup via environment; never `print()`/log the values. [S22]
- **Notifier credentials** (webhook URL, bot token, SMTP password): store in the SQLite DB but protect with file perms and a `0700` data dir. If encryption at rest is wanted, encrypt with `cryptography` **Fernet** using a key file (`0600`, dedicated user) — and document honestly that this only defends against *casual* disk access, because the key sits next to the ciphertext. *(This is the correct threat-model framing; do not oversell it.)* [S22]
- **Logging redaction is mandatory:** add a logging filter that redacts/omits any key whose name matches `password|secret|token|passphrase|webhook|authorization`; scrub webhook URLs and bot tokens before they enter any log or event record. A NIDS logs a lot — one leaked token in a stored event is a real risk. [S22]
- **File/dir permissions:** data dir `0700`; SQLite DB `0600`; key files `0600`; all owned by the dedicated unprivileged service user (D-006). Set the systemd unit `UMask=0077` and `ProtectSystem=strict` + explicit `ReadWritePaths=` so the web tier cannot write outside its data dir. *(Exact systemd directive names verified in doc 04.)* [S22]
- **Rotation:** `secret_key` regeneration must be a supported action (it invalidates all sessions — acceptable); notifier tokens re-enterable; TLS cert regenerable. Log a security event on rotation. [S22]
- **Never** put secrets in URLs or query strings. Note the one unavoidable case — Discord webhooks *are* URLs — so treat the webhook URL as a secret and redact it in logs. [S22]

---

## 7. Input validation

### Verified facts

- OWASP Input Validation: **allowlist** over denylist; validate both **syntax** (shape) and **semantics** (meaning); use anchored matching (`re.fullmatch`); consider Unicode normalization; validate filenames *after* decoding; limit lengths. [S23]
- Pydantic v2 is the validation layer (FastAPI's expected major — see doc 05). Constrained types use `Annotated` + `Field`: `Annotated[int, Field(ge=0, le=65535)]`; string constraints via `Annotated[str, StringConstraints(...)]`; `Literal[...]` for enums; `field_validator`/`model_validator` for cross-field logic; `ConfigDict` for model-level settings such as `extra="forbid"` and `validate_assignment=True`. [S24][S25]
- Starlette ships **`RequestBodyLimitMiddleware(max_body_size=…)`**, which returns `413 Content Too Large`, checks `Content-Length` early, and counts actual body bytes (so an understated header cannot bypass it). [S9]
- OWASP Query Parameterization requires parameterized queries / prepared statements; never build SQL by concatenation. [S30]
- OWASP File Upload: generate filenames server-side, cap length, validate after decoding, reject risky characters such as `:`. [S37]
- FastAPI can disable its auto docs (`docs_url=None`, `redoc_url=None`) on the `FastAPI(...)` constructor. [S38]

### Recommendation for Gilgamesh

- **Every** form/JSON field goes through a Pydantic v2 model with `ConfigDict(extra="forbid")` (reject unknown fields — stops mass-assignment). [S24]
- Use semantic types, not loose strings: [S23]
  - IP/CIDR → `ipaddress.ip_address` / `ip_network` in a `field_validator` (reject host bits set, reject non-canonical input).
  - MAC → anchored regex via `re.fullmatch`.
  - Interface name → must be in the live OS interface list (allowlist), not free text.
  - Severity / event type / channel type → `Literal[...]` / `Enum`.
  - Thresholds → bounded ints/flow with `Field(ge=…, le=…)`; sensitivity presets → enum, not raw numbers.
  - Names/labels → `StringConstraints(max_length=…, strip_whitespace=True)`.
- **Request-size cap:** install `RequestBodyLimitMiddleware` (e.g. `max_body_size=1 MiB`) to bound the parse cost for every request. [S9]
- **SQLite:** parameterized queries only (`?` placeholders); never f-string SQL. [S30]
- **Templates:** keep Jinja2 autoescaping on (the default for `Jinja2Templates`), and never mark user data `|safe`. (XSS defeats CSRF tokens.) [S12]
- **Disable API docs in production:** `FastAPI(docs_url=None, redoc_url=None)` — no reason to expose `/docs`, `/redoc`, `/openapi.json` on an appliance. [S38]
- **Errors:** run with `debug=False`; return generic messages; log details server-side only.
- **Uploads:** v1 has no custom-rule upload; if added later, follow OWASP File Upload (server-generated names, size/type limits, validate after decode). [S37]
- Validate **semantics** too (e.g. a "DNS server" field must be a usable IP; a retention value must be within the allowed range; a Discord URL must be an actual Discord webhook host). [S23]

### Do not

- Do not denylist ("block `<script>`") — allowlist. [S23]
- Do not trust `Content-Length` from the client as the size limit; rely on the middleware that counts real bytes. [S9]
- Do not echo raw validation input back into the response unescaped. [S12]

---

## 8. Detection-configuration attack surface

Gilgamesh lets a user edit thresholds, allowlists, and rule toggles, and then **renders** engine config from the DB (D-005). Three abuse classes must be closed.

### 8a. ReDoS (catastrophic backtracking in user-supplied regex)

**Verified facts**

- OWASP/CWE-1333 "Evil Regex" examples: `(a+)+$`, `([a-zA-Z]+)*$`, `(a|aa)+$`, `(a|a?)+$` — nested quantifiers over overlapping alternations cause exponential backtracking. Mitigations: avoid nested quantifiers/backreferences, **bound input length**, and apply a **timeout/backtracking limit**. [S26][S27]
- **Python's stdlib `re` has no timeout**: verified on this workstation's Python 3.14.8 — `re.compile` signature is `(pattern, flags=0)`, no timeout parameter. [S28b]
- The third-party **`regex`** package (2026.9.29, `Apache-2.0 AND CNRI-Python`) does support a `timeout` argument on its match functions. [S28]

**Recommendation**

- **v1 should not accept free-form user regex at all.** Express allowlists/suppressions structurally: exact IP, CIDR (`ipaddress.ip_network`), MAC, IP↔MAC binding, port range, enum event type. This removes the ReDoS surface entirely. [S23][S26]
- If regex is ever added (v1.1+), then *all* of: [S26][S27][S28]
  - bound pattern length (e.g. ≤ 256 chars) and **bound candidate string length**,
  - run matching through the `regex` module with an explicit `timeout=`,
  - anchor with `fullmatch`, and
  - reject patterns with nested quantifiers where feasible (best-effort heuristic only — not a guarantee).
- Never run user regex inside the hot packet path or the asyncio event loop without a timeout.

### 8b. Resource exhaustion via configuration values

**Verified facts**

- OWASP DoS: bound the resources a single request/input can allocate, limit request size, and rate-limit expensive actions. [S16]

**Recommendation**

- Impose hard caps, enforced in the Pydantic models (§7): max allowlist entries, max simultaneous built-in rules, max device-inventory rows, bounded retention days/rows, bounded thresholds, bounded page sizes. [S16]
- **"Update rules"/"Apply config" actions are expensive** (Suricata reload, rule download): rate-limit them and run them off the request path (background task) so a user (or a stolen session) cannot spin the Pi. [S16]
- Bound Suricata's memory footprint by controlling the enabled rule subset (doc 02/03) — enabling the full ET Open set on 4 GB is itself a self-DoS. [S16]
- Validate the **ruleset source** (HTTPS only, expected host, checksum/signature where the upstream offers one) before it is installed. [S34]

### 8c. Rule / config injection into generated Suricata files

**Verified facts**

- Suricata rules are line-oriented with `action proto … ;` structure; any generated variable or rule text is parsed by Suricata and can, if malformed, be rejected or (if it injects `;`/newlines) alter the ruleset. *(Suricata rule syntax is owned by doc 03; version-specific quoting detail → UNVERIFIED.)* [S39]
- OWASP OS Command Injection Defense: avoid building commands from input, allowlist arguments, use `--`, never interpolate into a shell. [S29]

**Recommendation**

- **Do not let users author raw rule text in v1.** Only *(a)* toggle a fixed catalogue of built-in rules and *(b)* set typed, bounded parameters (IP/CIDR/enum/int). This is the only robust fix for injection. [S23]
- When rendering any value into a Suricata config/rule file:
  - validate it to a **strict type** first (IP→`ipaddress`, enum→allowed set, int→bounds), so what reaches the template is already safe by construction; [S23]
  - reject `\r`, `\n`, `;`, `"`, `\`, and NUL in any string that lands in a rule; [S23]
  - write to a **fixed, non-user-controlled path**, atomically (temp file + `os.replace`). [S23]
- **Never invoke shell strings.** Reload/update via `subprocess.run([...], check=True, shell=False)` with a fixed argv and validated arguments only (e.g. interface names checked against the OS list). [S29]
- Validate **before** reload; if validation fails, do not reload — keep the last known-good config (fail safe, consistent with "never degrade the connection"). [S16]

---

## 9. Dependency / supply-chain hygiene

### Verified facts

- **`uv.lock` should be committed** and kept in sync; the lockfile is universal and retains/records artifact hashes. `uv sync --locked` / `--frozen` prevent silent resolution changes, and `uv lock --check` reports drift. `uv sync` **terminates if a malware advisory is found** for a locked package. `uvx` is an alias for `uv tool run` (for one-off audit tools). (C4 forbids `uv pip`, so use the native commands.) [S31][S32]
- **`pip-audit` 2.10.1** (Apache-2.0, requires Python ≥ 3.10) audits an environment/lockfile for known vulnerabilities. [S33]
- OWASP Vulnerable Dependency Management: inventory dependencies, monitor advisories, and patch on a cadence. [S34]
- aarch64/pure-Python status of the security deps chosen here: `argon2-cffi` (pure Python) + `argon2-cffi-bindings` (abi3 aarch64 wheel), `bcrypt` (abi3 aarch64 wheel), `itsdangerous`/`limits`/`slowapi`/`pwdlib` (pure Python). [S4][S5][S6][S7][S11][S17][S18]

### Recommendation for Gilgamesh

- Commit **`pyproject.toml`**, **`uv.lock`**, and **`.python-version`**; install with **`uv sync --locked`** in the idempotent install path (doc 07) so builds are reproducible. [S31][S32]
- Audit in CI/pre-release and on a **systemd timer** on the Pi: **`uvx pip-audit`** against the project; fail the build (or raise a Gilgamesh alert) on findings. [S33][S34]
- **Pin and vendor the front-end assets** (htmx, Alpine, the Tailwind standalone CLI output): no runtime CDN (offline-first, C5), record the exact version, and verify the integrity hash where the vendor publishes one (htmx's CDN snippets include SRI hashes). [S13][S36]
- **Licence gate (C1):** every added dep must have its SPDX id recorded in doc 03; everything proposed here is permissive (MIT / Apache-2.0 / BSD). [S34]
- Treat the **ET Open ruleset** as part of the supply chain: download over TLS, verify checksum/signature where offered, and pin the version. [S34]
- Keep the dependency count minimal (C7): the security stack in this doc adds `argon2-cffi` (+bindings), `itsdangerous`, and `limits` — no Redis, no Vault, no CORS middleware. [S18][S22]

---

## Cross-cutting: HTTP security headers

Send these on every response (small ASGI middleware or a Starlette wrapper): [S35]
- `Content-Security-Policy` (the app is local; strict CSP also matters for Alpine's CSP build — doc 05). [S35]
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `X-Frame-Options: DENY` (or CSP `frame-ancestors 'none'`) — anti-clickjacking. [S35]
- `Strict-Transport-Security` **only** per §5. [S20]

---

## Proposed decision-log entries (to paste into `docs/DECISIONS.md`; not written there — this session may only touch this file)

| # | Decision | Reason | Alternative rejected | Status |
|---|----------|--------|----------------------|--------|
| D-0xx | Password hashing = **Argon2id via `argon2-cffi` 25.1.0** (MIT), defaults t=3/m=64 MiB/p=4, rehash on login | OWASP-first choice; aarch64 wheel via `argon2-cffi-bindings`; MIT | bcrypt 5.0.0 (fine, but Argon2id stronger); PBKDF2 (weakest) | PROVISIONAL (benchmark params on Pi) |
| D-0xx | Sessions = **opaque `sid` in Starlette `SessionMiddleware` signed cookie + server-side `sessions` table** | Gives revocability + idle & absolute timeouts (OWASP), avoids storing data client-side | Fat signed cookie only (no revoke/idle timeout) | PROVISIONAL |
| D-0xx | CSRF = **Synchronizer Token** sent on every htmx request via `<body hx-headers>` + hidden form field; Fetch-Metadata/Origin as depth | App is stateful + cookie-authenticated; OWASP-recommended pattern | Naive double-submit (DISCOURAGED by OWASP) | PROVISIONAL |
| D-0xx | Rate limiting = **persisted per-account lockout (SQLite) + per-IP throttling via `limits` (MemoryStorage) + hashing concurrency cap** | Different threats need different counters; persist across restart; avoid slowapi wrapper risk | slowapi-only; in-memory dict | PROVISIONAL |
| D-0xx | Transport = **bind to management interface only**; optional self-signed TLS via Uvicorn `--ssl-certfile/--ssl-keyfile`; HSTS only with a trusted local CA | Self-signed + HSTS can lock users out; mgmt-only bind is the key control | HSTS on self-signed; bind 0.0.0.0 | PROVISIONAL |
| D-0xx | Secrets = **file-based (`/etc/gilgamesh/secrets.env`, 0640 root:gilgamesh) + DB perms + log redaction**; Fernet only if encryption-at-rest requested | No KMS on the Pi; perms + dedicated user are the real controls | Full vault (Vault/cloud KMS) — overkill, extra RAM | PROVISIONAL |
| D-0xx | Detection config = **structured allowlists only, no user regex in v1**; typed/bounded params; no raw rule authoring; fixed render path + atomic write; no shell | Removes ReDoS, injection, and resource-exhaustion surfaces | Free-text regex/rules (ReDoS + injection) | PROVISIONAL |

---

## Sources

- [S1] OWASP Password Storage Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- [S2] argon2-cffi API Reference (25.1.0) — https://argon2-cffi.readthedocs.io/en/stable/api.html
- [S3] argon2-cffi "Choosing Parameters" — https://argon2-cffi.readthedocs.io/en/stable/parameters.html
- [S4] PyPI `argon2-cffi` — https://pypi.org/project/argon2-cffi/
- [S5] PyPI `argon2-cffi-bindings` — https://pypi.org/project/argon2-cffi-bindings/
- [S6] PyPI `bcrypt` — https://pypi.org/project/bcrypt/
- [S7] PyPI `pwdlib` — https://pypi.org/project/pwdlib/
- [S8] OWASP Session Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- [S9] Starlette Middleware documentation (SessionMiddleware, RequestBodyLimitMiddleware, HTTPSRedirectMiddleware, TrustedHostMiddleware, CORS) — https://github.com/encode/starlette/blob/master/docs/middleware.md (site https://www.starlette.io/middleware/ was unreachable from this workstation)
- [S10] Starlette `SessionMiddleware` source — https://github.com/encode/starlette/blob/master/starlette/middleware/sessions.py
- [S11] PyPI `itsdangerous` — https://pypi.org/project/itsdangerous/
- [S12] OWASP Cross-Site Request Forgery Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- [S13] htmx documentation (Security, request headers) — https://htmx.org/docs/
- [S14] htmx `hx-headers` attribute — https://htmx.org/attributes/hx-headers/
- [S15] OWASP Credential Stuffing Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html
- [S16] OWASP Denial of Service Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
- [S17] `slowapi` README (GitHub) — https://github.com/laurentS/slowapi
- [S18] `limits` Quickstart (5.8.0) — https://limits.readthedocs.io/en/stable/quickstart.html
- [S19b] Uvicorn TLS/config options (`--ssl-keyfile`, `--ssl-certfile`, `--host`, `--port`, …) — https://github.com/encode/uvicorn (verified in `uvicorn/main.py` / `uvicorn/config.py`; https://www.uvicorn.org/settings/ was unreachable from this workstation)
- [S20] OWASP HTTP Strict Transport Security Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
- [S21] `mkcert` (BSD-3-Clause) — https://github.com/FiloSottile/mkcert
- [S22] OWASP Secrets Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- [S23] OWASP Input Validation Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- [S24] Pydantic v2 — Model configuration (`ConfigDict`, `extra='forbid'`) — https://docs.pydantic.dev/latest/concepts/config/
- [S25] Pydantic v2 — Validators (`field_validator`, `Annotated`, `StringConstraints`, `Field`) — https://docs.pydantic.dev/latest/concepts/validators/
- [S26] OWASP "Regular expression Denial of Service — ReDoS" — https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- [S27] CWE-1333 (Inefficient Regular Expression Complexity) — https://cwe.mitre.org/data/definitions/1333.html
- [S28] PyPI `regex` (Apache-2.0 AND CNRI-Python; `timeout` support) — https://pypi.org/project/regex/
- [S28b] Local check: Python 3.14.8 `re` has no timeout (`inspect.signature(re.compile) == (pattern, flags=0)`)
- [S29] OWASP OS Command Injection Defense Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- [S30] OWASP Query Parameterization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
- [S31] uv — project layout / lockfile — https://docs.astral.sh/uv/concepts/projects/layout/
- [S32] uv — `uv sync` (`--locked`/`--frozen`, malware advisory abort) — https://docs.astral.sh/uv/concepts/projects/sync/
- [S33] PyPI `pip-audit` — https://pypi.org/project/pip-audit/
- [S34] OWASP Vulnerable Dependency Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html
- [S35] OWASP HTTP Headers Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- [S36] htmx releases (GitHub tags; npm `latest`=2.0.11, `next`=4.0.0) — https://github.com/bigskysoftware/htmx/releases
- [S37] OWASP File Upload Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- [S38] FastAPI application reference (`docs_url`/`redoc_url`) — https://fastapi.tiangolo.com/reference/fastapi/
- [S39] Suricata rules documentation (version owned by doc 03) — https://docs.suricata.io/en/latest/rules/intro.html

All versions/URLs checked 2026-10-14.

---

## Open questions / UNVERIFIED

1. **UNVERIFIED — Argon2 parameters on the Pi.** The final `time_cost`/`memory_cost`/`parallelism` must be chosen by running `python -m argon2 --profile RFC_9106_LOW_MEMORY` on the actual Pi 4 and fitting doc 04's RAM budget. [S2][S3]
2. **UNVERIFIED — Uvicorn `--ssl-version` status.** Whether `--ssl-version` is deprecated in Uvicorn 0.54.0 (and the recommended replacement) was not confirmed; default Python ssl settings were assumed. [S19b]
3. **UNVERIFIED — exact TLS flags/behaviour under Uvicorn 0.54.0** beyond the option names (they were verified in source, but the end-to-end HTTPS smoke test is a build task).
4. **UNVERIFIED — Suricata rule-syntax escaping.** The precise set of characters that must be escaped/rejected when rendering values into Suricata rules (and the exact syntax for the Suricata 8.x version) is owned by doc 03. The recommendation here (no raw rule authoring; typed params only) stands regardless. [S39]
5. **UNVERIFIED — whether FastAPI/Starlette raise any additional body-size/JSON-depth limits** beyond `RequestBodyLimitMiddleware`; deep-JSON and zip-bomb style inputs should be tested in build. [S9]
6. **OPEN — session idle/absolute timeout values, lockout thresholds/backoff, and global hashing concurrency cap** (numbers are policy; propose in doc 04, confirm with the user).
7. **OPEN — encryption-at-rest decision.** Whether notifier credentials are stored plaintext-in-DB (permission-protected) or Fernet-encrypted; this is a threat-model tradeoff to lock in doc 04.
8. **OPEN — htmx version** is 2.0.11 (npm `latest`) vs 4.0.0 (released, npm `next`). Recommend vendoring 2.0.11 (what htmx.org currently documents) unless doc 05 finds a concrete reason to adopt 4.x; `PROMPT.md`'s "1.x vs 2.x" note is outdated. [S13][S36]
9. **OPEN — should we add `slowapi` at all**, given its slow cadence, or rely on `limits` directly? (Doc 03 should record the maintenance assessment.)

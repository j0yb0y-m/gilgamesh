"""ASGI middleware that cannot live behind the ``@app.middleware("http")`` decorator.

**Why these are wrappers.** Starlette builds its stack as
``ServerErrorMiddleware`` → user middleware → ``ExceptionMiddleware`` → router, so a
``BaseHTTPMiddleware`` never sees the response the framework synthesises for an
unhandled exception. Attaching these wrappers *around* the finished application is the
only way the security headers are guaranteed on every response, including that one.

* :class:`SecurityHeadersMiddleware` attaches the fixed header set (and ``no-store`` on
  HTML) to every response.
* :class:`BodySizeLimitMiddleware` refuses an oversized request before the framework
  reads it into memory. A declared ``Content-Length`` is checked up front; a streamed
  body is counted as it arrives and raises :class:`RequestTooLarge`, which the app
  converts to a ``413`` with a normal exception handler.
"""

from __future__ import annotations

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)


class RequestTooLarge(Exception):
    """A streamed request body exceeded the configured ceiling."""


class SecurityHeadersMiddleware:
    """Attach the security headers to every HTTP response, without exception."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Content-Security-Policy"] = CSP
                content_type = headers.get("content-type", "")
                if content_type.startswith("text/html"):
                    # An authenticated page renders the inventory and alert evidence;
                    # a shared or kiosk browser must not replay it from cache.
                    headers["Cache-Control"] = "no-store"
                elif scope["path"].startswith("/static/"):
                    # The vendored CSS/JS keep their file names across upgrades, so a
                    # cached copy outlives the code that shipped it: after `install.sh`
                    # the owner's browser would keep executing the *previous* app.js.
                    # Starlette serves these with an ETag and Last-Modified, so
                    # "revalidate, every time" costs a 304 and never serves stale code.
                    headers["Cache-Control"] = "no-cache"
            await send(message)

        await self._app(scope, receive, send_with_headers)


class BodySizeLimitMiddleware:
    """Reject request bodies larger than ``max_bytes`` before they are buffered."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self._app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        declared = Headers(scope=scope).get("content-length")
        if declared is not None:
            try:
                declared_bytes = int(declared)
            except ValueError:
                declared_bytes = None
            if declared_bytes is not None and declared_bytes > self._max_bytes:
                await self._reject(scope, receive, send)
                return

        total = 0

        async def counted_receive() -> Message:
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self._max_bytes:
                    # Raised inside the app so the registered handler can answer 413.
                    raise RequestTooLarge
            return message

        await self._app(scope, counted_receive, send)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send) -> None:
        response = PlainTextResponse("Request body too large", status_code=413)
        await response(scope, receive, send)

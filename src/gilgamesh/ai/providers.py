"""Provider adapters for optional AI explanations.

Only two wire formats exist: the OpenAI-compatible chat-completions shape (which
covers OpenAI, Gemini's compatibility endpoint, Groq, Mistral, OpenRouter, Ollama,
and llama.cpp) and Anthropic's native messages API. Requests are small and
non-streaming; ``httpx`` is already a runtime dependency, so this adds none.

Every failure becomes a short :class:`ProviderError` that never contains the API
key, the prompt, or the provider's response body.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, cast
from urllib.parse import urlsplit

import httpx

from gilgamesh.ai.settings import AiSettings

#: Hard cap on a provider response body. Explanations are a few kilobytes; anything
#: larger is either a mistake or an attempt to exhaust memory.
MAX_RESPONSE_BYTES = 64 * 1024

Resolver = Callable[[str], Sequence[str]]


class ProviderError(RuntimeError):
    """A provider request failed. The message is safe to show the owner."""


class AiConfigError(ValueError):
    """The AI configuration is unusable. The message is safe to show the owner."""


@dataclass(frozen=True, slots=True)
class ExplanationRequest:
    """One explanation request, independent of the provider's wire format."""

    system_prompt: str
    user_prompt: str
    max_tokens: int
    timeout_s: float
    context: Mapping[str, object] = field(default_factory=dict[str, object])


@dataclass(frozen=True, slots=True)
class ExplanationResult:
    """A provider's answer plus the metadata the UI and cache record."""

    text: str
    provider: str
    model: str
    latency_ms: int
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class ProviderProbe:
    """The outcome of the Settings page's "Test connection" button."""

    model: str
    latency_ms: int


class ExplanationProvider(Protocol):
    """Anything that can turn an :class:`ExplanationRequest` into text."""

    async def explain(self, request: ExplanationRequest) -> ExplanationResult: ...


class OpenAICompatibleProvider:
    """``POST {base_url}/chat/completions`` with a bearer token when one exists."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        model: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        retry_delay: float = 0.5,
        provider_name: str = "openai",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.provider = provider_name
        self._transport = transport
        self._retry_delay = retry_delay

    async def explain(self, request: ExplanationRequest) -> ExplanationResult:
        """Send one chat-completion request and parse the first choice."""
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body: dict[str, object] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
            "max_tokens": request.max_tokens,
            "temperature": 0,
        }
        payload, latency_ms = await _post_json(
            url=f"{self.base_url}/chat/completions",
            headers=headers,
            body=body,
            timeout_s=request.timeout_s,
            transport=self._transport,
            retry_delay=self._retry_delay,
        )
        return ExplanationResult(
            text=_openai_text(payload),
            provider=self.provider,
            model=self.model,
            latency_ms=latency_ms,
            prompt_tokens=_int_field(payload.get("usage"), "prompt_tokens"),
            completion_tokens=_int_field(payload.get("usage"), "completion_tokens"),
        )


class AnthropicProvider:
    """``POST {base_url}/messages`` with Anthropic's native headers."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        model: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        retry_delay: float = 0.5,
        provider_name: str = "anthropic",
    ) -> None:
        if not api_key or not api_key.strip():
            raise AiConfigError("an API key is required for Anthropic")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key.strip()
        self.model = model
        self.provider = provider_name
        self._transport = transport
        self._retry_delay = retry_delay

    async def explain(self, request: ExplanationRequest) -> ExplanationResult:
        """Send one messages request and parse the first text block."""
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        body: dict[str, object] = {
            "model": self.model,
            "max_tokens": request.max_tokens,
            "system": request.system_prompt,
            "messages": [{"role": "user", "content": request.user_prompt}],
            "temperature": 0,
        }
        payload, latency_ms = await _post_json(
            url=f"{self.base_url}/messages",
            headers=headers,
            body=body,
            timeout_s=request.timeout_s,
            transport=self._transport,
            retry_delay=self._retry_delay,
        )
        usage = payload.get("usage")
        return ExplanationResult(
            text=_anthropic_text(payload),
            provider=self.provider,
            model=self.model,
            latency_ms=latency_ms,
            prompt_tokens=_int_field(usage, "input_tokens"),
            completion_tokens=_int_field(usage, "output_tokens"),
        )


def validate_base_url(
    url: str,
    *,
    local_provider: bool,
    resolver: Resolver | None = None,
) -> str:
    """Validate a provider base URL and return it without a trailing slash.

    Public providers must use HTTPS and resolve only to global addresses. A local
    provider may use HTTP, but every resolved address must be loopback or private.
    Link-local/metadata addresses, userinfo, queries, and fragments are always
    rejected.
    """
    try:
        parts = urlsplit(url.strip())
        _ = parts.port
    except ValueError as exc:
        raise AiConfigError("base URL is not valid") from exc

    if parts.scheme not in {"http", "https"}:
        raise AiConfigError("base URL must start with http:// or https://")
    if not parts.hostname:
        raise AiConfigError("base URL must include a host")
    if parts.username is not None or parts.password is not None:
        raise AiConfigError("base URL must not include a username or password")
    if parts.query or parts.fragment:
        raise AiConfigError("base URL must not include a query or fragment")
    if parts.scheme == "http" and not local_provider:
        raise AiConfigError("plain HTTP is only allowed for a local provider")

    host = parts.hostname
    literal = _literal_address(host)
    if literal is not None:
        _check_address(literal, local_provider=local_provider)
    else:
        try:
            addresses = resolver(host) if resolver is not None else _default_resolver(host)
        except OSError as exc:
            raise AiConfigError("base URL host did not resolve") from exc
        if not addresses:
            raise AiConfigError("base URL host did not resolve")
        for address in addresses:
            _check_address(address, local_provider=local_provider)

    return url.strip().rstrip("/")


def build_provider(
    settings: AiSettings,
    api_key: str | None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ExplanationProvider:
    """Build the adapter the saved settings describe."""
    url = validate_base_url(settings.base_url, local_provider=settings.local_provider)
    key = api_key.strip() if api_key else None
    if key is None and not settings.local_provider:
        raise AiConfigError("an API key is required for this provider")
    if settings.kind == "anthropic":
        return AnthropicProvider(
            url,
            key,
            settings.model,
            transport=transport,
            provider_name=settings.preset,
        )
    return OpenAICompatibleProvider(
        url,
        key,
        settings.model,
        transport=transport,
        provider_name=settings.preset,
    )


async def probe_provider(
    settings: AiSettings,
    api_key: str | None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ProviderProbe:
    """Send a minimal prompt and report the model and round-trip latency."""
    provider = build_provider(settings, api_key, transport=transport)
    request = ExplanationRequest(
        system_prompt="You are a connectivity check.",
        user_prompt="Reply with the single word OK.",
        max_tokens=100,
        timeout_s=settings.timeout_s,
    )
    result = await provider.explain(request)
    return ProviderProbe(model=result.model, latency_ms=result.latency_ms)


async def _post_json(
    *,
    url: str,
    headers: Mapping[str, str],
    body: Mapping[str, object],
    timeout_s: float,
    transport: httpx.AsyncBaseTransport | None,
    retry_delay: float,
) -> tuple[dict[str, object], int]:
    """POST JSON, retry once on 429/5xx, and cap the response body."""
    started = time.monotonic()
    for attempt in range(2):
        try:
            async with (
                httpx.AsyncClient(
                    timeout=httpx.Timeout(timeout_s),
                    follow_redirects=False,
                    transport=transport,
                ) as client,
                client.stream("POST", url, headers=dict(headers), json=dict(body)) as response,
            ):
                status_code = response.status_code
                if status_code == 429 or status_code >= 500:
                    if attempt == 0:
                        await asyncio.sleep(retry_delay)
                        continue
                    raise ProviderError(_status_error(status_code))
                if 300 <= status_code < 400:
                    raise ProviderError("provider redirected the request")
                if status_code >= 400:
                    raise ProviderError(_status_error(status_code))
                raw = await _read_limited(response)
        except httpx.TimeoutException as exc:
            raise ProviderError("provider timed out") from exc
        except httpx.HTTPError as exc:
            raise ProviderError("provider request failed") from exc

        return _decode(raw), int((time.monotonic() - started) * 1000)
    raise ProviderError("provider error")


async def _read_limited(response: httpx.Response, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    """Read a streamed response, refusing anything over ``limit`` bytes."""
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > limit:
            raise ProviderError("response too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _decode(raw: bytes) -> dict[str, object]:
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        raise ProviderError("invalid response") from exc
    if not isinstance(payload, dict):
        raise ProviderError("invalid response")
    return cast(dict[str, object], payload)


def _openai_text(payload: Mapping[str, object]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderError("invalid response")
    first = cast("object", choices[0])
    if not isinstance(first, dict):
        raise ProviderError("invalid response")
    message = cast("dict[str, object]", first).get("message")
    if not isinstance(message, dict):
        raise ProviderError("invalid response")
    typed_message = cast("dict[str, object]", message)
    content = typed_message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ProviderError("invalid response")
    return content.strip()


def _anthropic_text(payload: Mapping[str, object]) -> str:
    content = payload.get("content")
    if not isinstance(content, list):
        raise ProviderError("invalid response")
    for raw_block in cast("list[object]", content):
        if not isinstance(raw_block, dict):
            continue
        block = cast("dict[str, object]", raw_block)
        if block.get("type") == "text":
            text = block.get("text")
            if isinstance(text, str) and text.strip():
                return text.strip()
    raise ProviderError("invalid response")


def _int_field(mapping: object, key: str) -> int | None:
    if not isinstance(mapping, dict):
        return None
    value = cast("dict[str, object]", mapping).get(key)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _status_error(status_code: int) -> str:
    if status_code in {401, 403}:
        return "authentication failed"
    if status_code == 429:
        return "rate limited"
    if status_code >= 500:
        return "provider error"
    return f"provider rejected the request (HTTP {status_code})"


def _literal_address(host: str) -> str | None:
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return None
    return host.split("%", 1)[0]


def _check_address(value: str, *, local_provider: bool) -> None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise AiConfigError("base URL host did not resolve") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_link_local or address.is_multicast or address.is_unspecified:
        raise AiConfigError("base URL host is not allowed")
    if local_provider:
        if not (address.is_loopback or address.is_private):
            raise AiConfigError("a local provider must resolve to a private or loopback address")
    elif not address.is_global:
        raise AiConfigError("base URL host must be a public address")


def _default_resolver(host: str) -> Sequence[str]:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0]).split("%", 1)[0]
        if address not in addresses:
            addresses.append(address)
    return addresses


__all__ = [
    "MAX_RESPONSE_BYTES",
    "AiConfigError",
    "AnthropicProvider",
    "ExplanationProvider",
    "ExplanationRequest",
    "ExplanationResult",
    "OpenAICompatibleProvider",
    "ProviderError",
    "ProviderProbe",
    "build_provider",
    "probe_provider",
    "validate_base_url",
]

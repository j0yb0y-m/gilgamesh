"""Provider adapters: request shape, safe errors, retries, and URL policy.

The adapters are the only code that talks to a third party. These tests pin the
contract: the key goes only in the provider's own header, redirects are never
followed, retries happen only for 429/5xx, responses are capped, and every failure
maps to a short message that cannot contain the key or the prompt.
"""

from __future__ import annotations

import json

import httpx
import pytest

from gilgamesh.ai.providers import (
    AiConfigError,
    AnthropicProvider,
    ExplanationRequest,
    OpenAICompatibleProvider,
    ProviderError,
    build_provider,
    probe_provider,
    validate_base_url,
)
from gilgamesh.ai.settings import AiSettings

KEY = "sk-test-secret-key"


def request(**overrides: object) -> ExplanationRequest:
    values: dict[str, object] = {
        "system_prompt": "system",
        "user_prompt": "user",
        "context": {"signal": "volume_spike"},
        "max_tokens": 200,
        "timeout_s": 5.0,
    }
    values.update(overrides)
    return ExplanationRequest(**values)  # type: ignore[arg-type]


def openai_body(text: str = "ok") -> dict[str, object]:
    return {
        "choices": [{"message": {"content": text}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2},
    }


async def test_openai_compatible_success_sends_key_and_parses_content() -> None:
    seen: dict[str, object] = {}

    def handler(incoming: httpx.Request) -> httpx.Response:
        seen["auth"] = incoming.headers.get("authorization")
        seen["body"] = json.loads(incoming.content)
        return httpx.Response(200, json=openai_body())

    provider = OpenAICompatibleProvider(
        "https://api.example/v1",
        KEY,
        "m",
        transport=httpx.MockTransport(handler),
    )

    result = await provider.explain(request())

    assert result.text == "ok"
    assert result.provider == "openai"
    assert result.model == "m"
    assert result.latency_ms >= 0
    assert (result.prompt_tokens, result.completion_tokens) == (10, 2)
    assert seen["auth"] == f"Bearer {KEY}"
    body = seen["body"]
    assert isinstance(body, dict)
    assert body["model"] == "m"
    assert body["temperature"] == 0
    assert body["max_tokens"] == 200
    assert body["messages"] == [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]


async def test_openai_compatible_omits_authorization_without_a_key() -> None:
    seen: dict[str, str | None] = {}

    def handler(incoming: httpx.Request) -> httpx.Response:
        seen["auth"] = incoming.headers.get("authorization")
        return httpx.Response(200, json=openai_body())

    provider = OpenAICompatibleProvider(
        "http://127.0.0.1:11434/v1",
        None,
        "llama3.2",
        transport=httpx.MockTransport(handler),
    )

    result = await provider.explain(request())

    assert result.text == "ok"
    assert seen["auth"] is None


async def test_anthropic_success_uses_native_headers_and_text_block() -> None:
    seen: dict[str, object] = {}

    def handler(incoming: httpx.Request) -> httpx.Response:
        seen["key"] = incoming.headers.get("x-api-key")
        seen["version"] = incoming.headers.get("anthropic-version")
        seen["body"] = json.loads(incoming.content)
        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "thinking", "thinking": "hidden"},
                    {"type": "text", "text": "ok"},
                ],
                "usage": {"input_tokens": 7, "output_tokens": 3},
            },
        )

    provider = AnthropicProvider(
        "https://api.example/v1",
        KEY,
        "claude",
        transport=httpx.MockTransport(handler),
    )

    result = await provider.explain(request())

    assert result.text == "ok"
    assert result.provider == "anthropic"
    assert (result.prompt_tokens, result.completion_tokens) == (7, 3)
    assert seen["key"] == KEY
    assert seen["version"] == "2023-06-01"
    body = seen["body"]
    assert isinstance(body, dict)
    assert body["system"] == "system"
    assert body["messages"] == [{"role": "user", "content": "user"}]


def test_anthropic_requires_a_key() -> None:
    with pytest.raises(AiConfigError):
        AnthropicProvider("https://api.example/v1", None, "claude")
    with pytest.raises(AiConfigError):
        AnthropicProvider("https://api.example/v1", "", "claude")


async def test_401_is_not_retried_and_the_key_never_appears() -> None:
    calls = 0

    def handler(incoming: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(401, json={"error": "bad key"})

    provider = OpenAICompatibleProvider(
        "https://api.example/v1",
        KEY,
        "m",
        transport=httpx.MockTransport(handler),
        retry_delay=0,
    )

    with pytest.raises(ProviderError) as caught:
        await provider.explain(request())

    assert calls == 1
    assert "authentication failed" in str(caught.value)
    assert KEY not in str(caught.value)


async def test_429_is_retried_once_then_reported_as_rate_limited() -> None:
    calls = 0

    def handler(incoming: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, json={"error": "slow down"})

    provider = OpenAICompatibleProvider(
        "https://api.example/v1",
        KEY,
        "m",
        transport=httpx.MockTransport(handler),
        retry_delay=0,
    )

    with pytest.raises(ProviderError, match="rate limited"):
        await provider.explain(request())

    assert calls == 2


async def test_5xx_is_retried_once_and_can_recover() -> None:
    calls = 0

    def handler(incoming: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(500, json={"error": "boom"})
        return httpx.Response(200, json=openai_body())

    provider = OpenAICompatibleProvider(
        "https://api.example/v1",
        KEY,
        "m",
        transport=httpx.MockTransport(handler),
        retry_delay=0,
    )

    result = await provider.explain(request())

    assert result.text == "ok"
    assert calls == 2


async def test_other_4xx_is_not_retried() -> None:
    calls = 0

    def handler(incoming: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(400, json={"error": "bad request"})

    provider = OpenAICompatibleProvider(
        "https://api.example/v1",
        KEY,
        "m",
        transport=httpx.MockTransport(handler),
        retry_delay=0,
    )

    with pytest.raises(ProviderError, match="HTTP 400"):
        await provider.explain(request())

    assert calls == 1


async def test_redirects_are_not_followed() -> None:
    calls = 0

    def handler(incoming: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(302, headers={"location": "https://elsewhere.test/"})

    provider = OpenAICompatibleProvider(
        "https://api.example/v1",
        KEY,
        "m",
        transport=httpx.MockTransport(handler),
        retry_delay=0,
    )

    with pytest.raises(ProviderError, match="redirect"):
        await provider.explain(request())

    assert calls == 1


async def test_timeout_becomes_a_safe_provider_error() -> None:
    def handler(incoming: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=incoming)

    provider = OpenAICompatibleProvider(
        "https://api.example/v1",
        KEY,
        "m",
        transport=httpx.MockTransport(handler),
        retry_delay=0,
    )

    with pytest.raises(ProviderError, match="timed out"):
        await provider.explain(request())


async def test_malformed_json_and_empty_text_are_invalid_responses() -> None:
    def malformed(incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    provider = OpenAICompatibleProvider(
        "https://api.example/v1",
        KEY,
        "m",
        transport=httpx.MockTransport(malformed),
    )
    with pytest.raises(ProviderError, match="invalid response"):
        await provider.explain(request())

    def empty(incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=openai_body(""))

    provider = OpenAICompatibleProvider(
        "https://api.example/v1",
        KEY,
        "m",
        transport=httpx.MockTransport(empty),
    )
    with pytest.raises(ProviderError, match="invalid response"):
        await provider.explain(request())


async def test_response_body_is_capped_at_64_kib() -> None:
    def handler(incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (64 * 1024 + 1))

    provider = OpenAICompatibleProvider(
        "https://api.example/v1",
        KEY,
        "m",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(ProviderError, match="response too large"):
        await provider.explain(request())


def test_url_validation_blocks_public_http_metadata_and_userinfo() -> None:
    with pytest.raises(AiConfigError):
        validate_base_url("http://api.example/v1", local_provider=False)
    with pytest.raises(AiConfigError):
        validate_base_url("https://169.254.169.254/v1", local_provider=True)
    with pytest.raises(AiConfigError):
        validate_base_url("https://user:pass@api.example/v1", local_provider=False)
    with pytest.raises(AiConfigError):
        validate_base_url("https://api.example/v1?x=1", local_provider=False)
    with pytest.raises(AiConfigError):
        validate_base_url("https://api.example/v1#frag", local_provider=False)
    with pytest.raises(AiConfigError):
        validate_base_url("ftp://api.example/v1", local_provider=False)
    with pytest.raises(AiConfigError):
        validate_base_url("https:///v1", local_provider=False)
    with pytest.raises(AiConfigError):
        validate_base_url("https://api.example:99999/v1", local_provider=False)
    assert validate_base_url("http://127.0.0.1:11434/v1", local_provider=True).startswith("http://")


def test_url_validation_uses_the_resolver_for_hostnames() -> None:
    def public(host: str) -> list[str]:
        return ["93.184.216.34"]

    def loopback(host: str) -> list[str]:
        return ["127.0.0.1"]

    assert (
        validate_base_url("https://api.example/v1", local_provider=False, resolver=public)
        == "https://api.example/v1"
    )

    with pytest.raises(AiConfigError):
        validate_base_url("https://api.example/v1", local_provider=False, resolver=loopback)

    with pytest.raises(AiConfigError):
        validate_base_url("https://api.example/v1", local_provider=True, resolver=public)


def test_url_validation_allows_private_addresses_only_for_local_providers() -> None:
    assert (
        validate_base_url("http://192.168.1.10:8080/v1", local_provider=True)
        == "http://192.168.1.10:8080/v1"
    )
    with pytest.raises(AiConfigError):
        validate_base_url("http://192.168.1.10:8080/v1", local_provider=False)


def test_build_provider_selects_the_adapter_and_requires_a_key() -> None:
    local = AiSettings(
        preset="ollama",
        kind="openai",
        base_url="http://127.0.0.1:11434/v1",
        model="llama3.2",
        local_provider=True,
    )
    provider = build_provider(local, None)
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.model == "llama3.2"

    anthropic = AiSettings(
        preset="anthropic",
        kind="anthropic",
        base_url="https://127.0.0.1/v1",
        model="claude",
        local_provider=True,
    )
    assert isinstance(build_provider(anthropic, KEY), AnthropicProvider)

    remote = AiSettings(
        preset="custom",
        kind="openai",
        base_url="https://93.184.216.34/v1",
        model="m",
        local_provider=False,
    )
    with pytest.raises(AiConfigError, match="API key"):
        build_provider(remote, None)


async def test_probe_returns_model_and_latency_without_the_key() -> None:
    seen: dict[str, object] = {}

    def handler(incoming: httpx.Request) -> httpx.Response:
        seen["auth"] = incoming.headers.get("authorization")
        seen["body"] = json.loads(incoming.content)
        return httpx.Response(200, json=openai_body("OK"))

    settings = AiSettings(
        preset="openai",
        kind="openai",
        base_url="https://127.0.0.1/v1",
        model="gpt-test",
        local_provider=True,
        timeout_s=5,
    )

    probe = await probe_provider(settings, KEY, transport=httpx.MockTransport(handler))

    assert probe.model == "gpt-test"
    assert probe.latency_ms >= 0
    assert KEY not in str(probe)
    assert seen["auth"] == f"Bearer {KEY}"
    body = seen["body"]
    assert isinstance(body, dict)
    assert body["max_tokens"] == 100

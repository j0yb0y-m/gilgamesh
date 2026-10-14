"""Email (SMTP) notifications.

Sending uses ``aiosmtplib``. Two connection modes matter and both are configurable:

* **STARTTLS on port 587** — the usual choice for a submission relay. The connection
  starts in plaintext and is upgraded, so the server certificate must be validated.
* **Implicit TLS (SMTPS) on port 465** — the session is encrypted from the first byte.

Certificate verification is left on deliberately. Disabling it to "make self-signed
servers work" is how credentials get captured by whoever is on the path; a self-signed
relay should be trusted by the operating system instead.

The password is a secret: it is never logged, never included in an error message, and is
written only by the web UI.
"""

from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage

from gilgamesh.models import Event
from gilgamesh.notifiers.base import (
    ChannelConfig,
    ChannelKind,
    DeliveryResult,
    NotificationChannel,
    format_event_message,
    redact_secrets,
)

DEFAULT_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class EmailMessageParts:
    """The rendered message, before any transport."""

    subject: str
    body: str


def build_email_message(sender: str, recipients: list[str], event: Event) -> EmailMessageParts:
    """Build the subject and body for ``event``."""
    subject = f"[Gilgamesh] {event.severity.value.upper()} — {event.type.value}"
    return EmailMessageParts(subject=subject, body=format_event_message(event))


def _as_email_message(parts: EmailMessageParts, sender: str, recipients: list[str]) -> EmailMessage:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = parts.subject
    message.set_content(parts.body)
    return message


class EmailChannel(NotificationChannel):
    """Sends alerts as plain-text email over SMTP."""

    kind = ChannelKind.EMAIL

    async def _send(self, event: Event) -> DeliveryResult:
        config = self._config
        if not config.smtp_host or not config.sender or not config.recipients:
            return DeliveryResult(
                ok=False, error="SMTP host, sender, or recipients not configured", permanent=True
            )

        parts = build_email_message(config.sender, list(config.recipients), event)
        message = _as_email_message(parts, config.sender, list(config.recipients))

        if self._transport is not None:
            result = await self._transport(message)
        else:
            result = await self._send_smtp(config, message)
        return result

    async def _send_smtp(self, config: ChannelConfig, message: EmailMessage) -> DeliveryResult:
        """Deliver over SMTP, upgrading with STARTTLS where the server supports it."""
        import aiosmtplib

        try:
            await aiosmtplib.send(
                message,
                hostname=config.smtp_host,
                port=config.smtp_port,
                username=config.smtp_username,
                password=config.smtp_password,
                # start_tls upgrades an established connection (port 587); use_tls
                # wraps it from the first byte (SMTPS, port 465).
                start_tls=config.smtp_start_tls,
                use_tls=config.smtp_use_tls,
                # Certificate validation stays on: disabling it "to make a self-signed
                # relay work" is how credentials get captured in transit.
                validate_certs=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            return DeliveryResult(ok=False, error=redact_secrets(str(exc), config.secrets))
        return DeliveryResult(ok=True, status_code=250)

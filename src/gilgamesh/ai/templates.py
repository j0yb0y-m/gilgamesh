"""Deterministic explanations for every event type.

The template is the product's floor: it works with no provider, no key, no
network, and no model. It says what the detector saw, why that pattern can
matter, and what the owner can check, using only the facts already present in
the redacted context.

Text is plain, with three sections and no markdown tables or code. Every value
interpolated from the context is passed through :func:`redact_text` again, so a
directly constructed context cannot leak an identifier the settings hid.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import cast

from gilgamesh.ai.context import ExplanationContext, redact_text
from gilgamesh.ai.providers import ExplanationRequest, ExplanationResult
from gilgamesh.models import EventType

_HOSTNAME_KEYS = frozenset({"hostname", "device_label", "label"})

_ARP_REASONS = {
    "gateway_mac_changed": "The gateway's hardware address changed",
    "ip_mac_conflict": "One IP address was claimed by two hardware addresses",
    "ethernet_source_mismatch": "The Ethernet sender and the ARP sender disagreed",
    "unsolicited_arp_reply": "An unsolicited ARP reply claimed an address",
    "gratuitous_arp_flood": "A burst of gratuitous ARP announcements was seen",
}

_DNS_REASONS = {
    "untrusted_resolver": "A DNS answer came from a resolver that is not on the trusted list",
    "response_without_matching_query": "A DNS response arrived without a matching request",
    "conflicting_answers": "Two DNS responses gave conflicting answers",
}

_DHCP_REASONS = {
    "rogue_dhcp_server": "A DHCP server other than the trusted one answered",
    "dhcp_config_drift": "The trusted DHCP server's settings changed",
    "dhcp_starvation": "Many DHCP requests arrived in a short window",
}

_SCAN_REASONS = {
    "vertical_port_scan": "One device tried many ports on a single host",
    "horizontal_port_scan": "One device tried the same port on many hosts",
}

_BEHAVIOUR_WHY = (
    "The behaviour baseline records what is normal for this device at this time "
    "of day. A departure can be a backup, an update, a video call, or a new app, "
    "or it can be data theft, command-and-control traffic, or malware. The signal "
    "is a reason to look, not proof of an attack."
)

_BEHAVIOUR_CHECK = (
    "Compare the timing with what the device was doing. Check for backups, "
    "updates, streaming, or a new app. If the activity is unexplained, review the "
    "device for malware and watch whether it continues."
)


class TemplateProvider:
    """The always-available provider used when AI is off or failing."""

    name = "template"
    model = ""

    async def explain(self, request: ExplanationRequest) -> ExplanationResult:
        """Render the deterministic explanation for the request's context."""
        context = ExplanationContext.model_validate(request.context)
        return ExplanationResult(
            text=template_explanation(context),
            provider=self.name,
            model=self.model,
            latency_ms=0,
        )


def template_explanation(context: ExplanationContext) -> str:
    """Return the three-section explanation for ``context``."""
    builder = _BUILDERS.get(context.event_type, _generic)
    what, why, check = builder(context)
    return _sections(what, why, check)


def _arp(context: ExplanationContext) -> tuple[str, str, str]:
    reason = _mapped_reason(context, _ARP_REASONS, "ARP activity looked inconsistent")
    evidence: list[str] = []
    count = _int_fact(context, "count")
    if count:
        evidence.append(_times(count))
    window = _window(context)
    if window:
        evidence.append(window)
    suffix = f" ({', '.join(evidence)})" if evidence else ""
    what = f"{reason}{suffix}. A false ARP mapping can redirect local traffic."
    why = (
        "ARP is how devices on the same network find each other's hardware "
        "address. A forged mapping can send traffic through an attacker, enabling "
        "interception or disruption. Proxy ARP, router failover, and virtual "
        "machines can produce similar patterns."
    )
    check = (
        "Confirm the gateway's hardware address on the router's admin page. Check "
        "whether a device was replaced or a virtual machine started. If the mapping "
        "is unexpected, disconnect the suspected device and restart the router."
    )
    return what, why, check


def _dns(context: ExplanationContext) -> tuple[str, str, str]:
    reason = _mapped_reason(context, _DNS_REASONS, "DNS answers looked manipulated")
    reasons = _list_fact(context, "all_reasons")
    detail = f" ({reasons})" if reasons else ""
    ttl = _int_fact(context, "min_ttl")
    ttl_text = f" The smallest TTL was {ttl} seconds." if ttl is not None else ""
    what = f"{reason}{detail}.{ttl_text} A forged answer can point a name at the wrong server."
    why = (
        "DNS decides which server a name points to. A forged answer can send you "
        "to a look-alike login page or silently block a service. Captive portals, "
        "local filters, and misconfigured resolvers can look similar."
    )
    check = (
        "Compare the answer with a trusted resolver such as your router or a "
        "public DNS service. Check the router's DNS settings. Avoid entering "
        "credentials on the affected name until the answer is confirmed."
    )
    return what, why, check


def _dhcp(context: ExplanationContext) -> tuple[str, str, str]:
    reason = _mapped_reason(context, _DHCP_REASONS, "DHCP activity was unexpected")
    details: list[str] = []
    message_type = _fact_text(context, "message_type")
    if message_type:
        details.append(f"message type {message_type}")
    changed = _list_fact(context, "changed")
    if changed:
        details.append(f"changed settings: {changed}")
    suffix = f" ({'; '.join(details)})" if details else ""
    what = f"{reason}{suffix}. DHCP can redirect a device's gateway and DNS settings."
    why = (
        "DHCP tells devices which gateway and DNS servers to use. A rogue server "
        "can redirect traffic through an attacker. A second router, a repeater, or "
        "a misconfigured device can produce the same pattern."
    )
    check = (
        "Find the device offering DHCP and confirm the router is the only DHCP "
        "server. Compare the gateway and DNS settings with what you expect. If a "
        "rogue server is present, disconnect it and renew the affected devices' "
        "leases."
    )
    return what, why, check


def _port_scan(context: ExplanationContext) -> tuple[str, str, str]:
    reason = _mapped_reason(context, _SCAN_REASONS, "One device probed many ports or hosts")
    evidence: list[str] = []
    distinct_ports = _int_fact(context, "distinct_ports")
    if distinct_ports:
        evidence.append(f"{distinct_ports} ports")
    distinct_hosts = _int_fact(context, "distinct_hosts")
    if distinct_hosts:
        evidence.append(f"{distinct_hosts} hosts")
    ports = _list_fact(context, "ports")
    if ports:
        evidence.append(f"sample ports {ports}")
    suffix = f" ({', '.join(evidence)})" if evidence else ""
    what = f"{reason}{suffix}. This is the shape of a port scan."
    why = (
        "Port scans map which services are reachable. They are often "
        "reconnaissance before an attack, but vulnerability scanners, backup "
        "tools, and misconfigured apps also probe many ports."
    )
    check = (
        "Identify the source device and whether it is running a scanner or new "
        "software. Check the target hosts for unexpected open services. If the "
        "source is unknown, isolate it from the network and review it."
    )
    return what, why, check


def _syn_flood(context: ExplanationContext) -> tuple[str, str, str]:
    count = _int_fact(context, "syn_count")
    threshold = _int_fact(context, "threshold")
    target = _fact_text(context, "target")
    what = "A large number of connection attempts (SYNs) arrived"
    if count:
        what += f" — {count:,} in the window"
    if target:
        what += f", aimed at {target}"
    what += "."
    if threshold:
        what += f" The detector's threshold is {threshold:,}."
    why = (
        "A SYN flood can exhaust a service's connection table so legitimate "
        "clients cannot connect. A busy client, a load test, or a broken app can "
        "also produce a burst."
    )
    check = (
        "Check whether the target service is still responding. Identify the source "
        "device and whether it is expected to make that many connections. If not, "
        "isolate the source and review it."
    )
    return what, why, check


def _new_device(context: ExplanationContext) -> tuple[str, str, str]:
    what = f"{_device_phrase(context)} was seen on the network for the first time."
    if _bool_fact(context, "randomised"):
        what += " It uses a randomised hardware address, which is common on phones and laptops."
    if _bool_fact(context, "trusted"):
        what += " It is marked as trusted."
    why = (
        "New devices are normal after a purchase, a guest visit, or a phone "
        "reconnecting. An unknown device can also be an intruder or a neighbour "
        "using the Wi-Fi. Randomised addresses make the same phone look new more "
        "often."
    )
    check = (
        "Identify the device from its label, vendor, or the router's client list. "
        "If you do not recognise it, change the Wi-Fi password and review the "
        "router's connected devices."
    )
    return what, why, check


def _suricata(context: ExplanationContext) -> tuple[str, str, str]:
    signature = _fact_text(context, "signature") or "A Suricata signature matched"
    category = _fact_text(context, "category")
    signature_id = _int_fact(context, "signature_id")
    action = _fact_text(context, "action")
    what = f'Suricata raised "{signature}"'
    if category:
        what += f" in the {category} category"
    if signature_id is not None:
        what += f" (signature id {signature_id})"
    if action:
        what += f"; the configured action was {action}"
    what += "."
    why = (
        "Suricata signatures describe traffic patterns that are known to be "
        "suspicious. Some are precise attack indicators; others are broad and "
        "produce false positives on ordinary software."
    )
    check = (
        "Read the signature name and category. Identify the devices involved from "
        "the alert evidence. Confirm whether the traffic was expected. If it is a "
        "false positive, consider disabling that signature after review."
    )
    return what, why, check


def _behaviour(context: ExplanationContext) -> tuple[str, str, str]:
    signal = _fact_text(context, "signal") or "unknown"
    if signal == "volume_spike":
        return _volume_spike(context)
    if signal == "new_destinations":
        return _new_destinations(context)
    if signal == "beaconing":
        return _beaconing(context)
    return _generic_behaviour(context, signal.replace("_", " "))


def _volume_spike(context: ExplanationContext) -> tuple[str, str, str]:
    observed = _int_fact(context, "observed_bytes")
    baseline = _int_fact(context, "baseline_mean_bytes")
    ratio = _float_fact(context, "ratio")
    direction = _fact_text(context, "direction") or "transferred"
    verb = {"out": "uploaded", "in": "downloaded"}.get(direction, "transferred")
    what = "A device "
    if observed is not None:
        what += f"{verb} {_bytes(observed)}"
    else:
        what += f"{verb} an unusual amount of data"
    if baseline is not None:
        what += f", compared with a normal of about {_bytes(baseline)}"
    if ratio is not None:
        what += f" (about {ratio:.1f} times its normal)"
    window = _window(context)
    what += f" {window}." if window else " in one 15-minute window."
    return what, _BEHAVIOUR_WHY, _BEHAVIOUR_CHECK


def _new_destinations(context: ExplanationContext) -> tuple[str, str, str]:
    count = _int_fact(context, "new_destinations")
    threshold = _float_fact(context, "threshold")
    what = "A device contacted "
    what += f"{count} destinations" if count else "many destinations"
    what += " it had not used before"
    if threshold is not None:
        what += f", above its usual threshold of about {threshold:.1f}"
    window = _window(context)
    what += f" {window}." if window else " in one 15-minute window."
    return what, _BEHAVIOUR_WHY, _BEHAVIOUR_CHECK


def _beaconing(context: ExplanationContext) -> tuple[str, str, str]:
    connections = _int_fact(context, "connections")
    interval = _float_fact(context, "mean_interval_s")
    cov = _float_fact(context, "cov")
    total = _int_fact(context, "total_bytes")
    what = "A device connected to the same external address "
    what += f"{connections} times" if connections else "repeatedly"
    if interval is not None:
        what += f" at an average interval of {interval:.1f} seconds"
    if cov is not None:
        what += f" (interval consistency {cov:.2f})"
    window = _window(context)
    what += f" {window}." if window else " in one 15-minute window."
    if total is not None:
        what += f" It transferred {_bytes(total)} in total."
    return what, _BEHAVIOUR_WHY, _BEHAVIOUR_CHECK


def _generic_behaviour(context: ExplanationContext, signal: str) -> tuple[str, str, str]:
    z_score = _float_fact(context, "z_score")
    what = f"A device's activity departed from its learned baseline (signal: {signal})."
    if z_score is not None:
        what += f" The departure scored {z_score:.1f} standard deviations from normal."
    return what, _BEHAVIOUR_WHY, _BEHAVIOUR_CHECK


def _test(context: ExplanationContext) -> tuple[str, str, str]:
    del context
    what = (
        "Nothing to explain: this is a test event generated by Gilgamesh to check "
        "the alert pipeline."
    )
    why = "It does not describe real network activity, so no action is required."
    check = (
        "Confirm the pipeline is working, then dismiss the event. If test events "
        "appear unexpectedly, check who triggered the test."
    )
    return what, why, check


def _generic(context: ExplanationContext) -> tuple[str, str, str]:
    del context
    what = "An event was recorded."
    why = (
        "The event type is not recognised by this template, so the evidence should "
        "be reviewed directly."
    )
    check = "Open the alert detail and review the evidence before acting."
    return what, why, check


_BUILDERS: dict[EventType, Callable[[ExplanationContext], tuple[str, str, str]]] = {
    EventType.ARP_SPOOF: _arp,
    EventType.DNS_SPOOF: _dns,
    EventType.DHCP_ROGUE: _dhcp,
    EventType.PORT_SCAN: _port_scan,
    EventType.SYN_FLOOD: _syn_flood,
    EventType.NEW_DEVICE: _new_device,
    EventType.SURICATA_ALERT: _suricata,
    EventType.BEHAVIOUR_ANOMALY: _behaviour,
    EventType.TEST: _test,
}


def _sections(what: str, why: str, check: str) -> str:
    return f"What happened\n{what}\n\nWhy it matters\n{why}\n\nWhat to check\n{check}"


def _mapped_reason(context: ExplanationContext, mapping: Mapping[str, str], fallback: str) -> str:
    raw = context.facts.get("reason")
    if not isinstance(raw, str) or not raw:
        return fallback
    if raw in mapping:
        return mapping[raw]
    return redact_text(raw.replace("_", " "), context.redaction)


def _fact_text(context: ExplanationContext, key: str) -> str | None:
    value = context.facts.get(key)
    if value is None:
        return None
    if context.redaction.redact_hostname and key in _HOSTNAME_KEYS:
        return "[redacted hostname]"
    text = redact_text(str(value), context.redaction).strip()
    return text or None


def _list_fact(context: ExplanationContext, key: str) -> str | None:
    value = context.facts.get(key)
    if not isinstance(value, list):
        return None
    items: list[str] = []
    for item in cast("list[object]", value)[:10]:
        text = redact_text(str(item), context.redaction).strip()
        if text:
            items.append(text)
    return ", ".join(items) or None


def _int_fact(context: ExplanationContext, key: str) -> int | None:
    value = context.facts.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return int(value)
    return None


def _float_fact(context: ExplanationContext, key: str) -> float | None:
    value = context.facts.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        number = float(value)
        return number if math.isfinite(number) else None
    return None


def _bool_fact(context: ExplanationContext, key: str) -> bool:
    value = context.facts.get(key)
    return value if isinstance(value, bool) else False


def _device_phrase(context: ExplanationContext) -> str:
    label = context.device.label if context.device else None
    if label and not context.redaction.redact_hostname:
        safe = redact_text(label, context.redaction).strip()
        if safe:
            return f"Device {safe}"
    return "A device"


def _window(context: ExplanationContext) -> str:
    seconds = _int_fact(context, "window_seconds")
    if seconds:
        return f"within {seconds} seconds"
    end = _fact_text(context, "window_end")
    if end:
        moment = _moment(end)
        return f"in the 15 minutes ending {moment}" if moment else "in one 15-minute window"
    return ""


def _moment(value: str) -> str | None:
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _bytes(value: int) -> str:
    return f"{value:,} bytes"


def _times(count: int) -> str:
    return "once" if count == 1 else f"{count} times"


__all__ = ["TemplateProvider", "template_explanation"]

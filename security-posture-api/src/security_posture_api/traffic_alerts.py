"""Helpers for public-site traffic logging and optional email alerts."""

from __future__ import annotations

import logging
import smtplib
from collections.abc import Mapping
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

from security_posture_api.settings import AppSettings

if TYPE_CHECKING:
    from security_posture_api.public_network_enrichment import PublicNetworkEnrichment
    from security_posture_api.public_traffic_metrics import (
        PublicTrafficMetricsSummary,
    )


class PublicTrafficEvent(BaseModel):
    """Public-safe traffic event posted by the simulation site."""

    model_config = ConfigDict(str_strip_whitespace=True)

    event_type: Literal["health_probe", "page_view", "simulation_started"]
    route: str = Field(min_length=1, max_length=120)
    session_id: str = Field(min_length=1, max_length=120)
    site_mode: Literal["security", "simulation"] = "simulation"
    page_title: str | None = Field(default=None, max_length=160)
    referrer: str | None = Field(default=None, max_length=500)


class PublicTrafficAlert(BaseModel):
    """Server-side view of a public traffic event with request metadata."""

    client_ip: str | None = None
    event: PublicTrafficEvent
    received_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    user_agent: str | None = None


def _get_header_value(headers: Mapping[str, str], *names: str) -> str | None:
    for name in names:
        for header_name, header_value in headers.items():
            if header_name.lower() == name.lower() and header_value.strip():
                return header_value.strip()
    return None


def extract_client_ip(headers: Mapping[str, str]) -> str | None:
    """Return the best-effort client IP from trusted forwarding headers."""

    forwarded_for = _get_header_value(
        headers,
        "X-Forwarded-For",
        "X-Azure-ClientIP",
        "X-Client-IP",
    )
    if not forwarded_for:
        return None

    first_hop = forwarded_for.split(",", maxsplit=1)[0].strip()
    if not first_hop:
        return None

    return _strip_port_suffix(first_hop)


def _strip_port_suffix(address: str) -> str:
    """Drop a trailing ``:port`` suffix appended by Azure's edge layer.

    Azure App Service / Front Door append the source port to ``X-Forwarded-For``
    as ``<ip>:<port>`` for IPv4 and ``[<ip>]:<port>`` for IPv6. Provider-backed
    enrichment APIs (ipapi.is, ipqualityscore) reject the IP+port form, so the
    port is stripped here at the single extraction site.
    """

    if address.startswith("["):
        closing_bracket = address.find("]")
        if closing_bracket != -1:
            return address[1:closing_bracket]
        return address

    if "." in address and address.count(":") == 1:
        return address.rsplit(":", maxsplit=1)[0]

    return address


def mask_client_ip(client_ip: str | None) -> str | None:
    """Return a redacted client IP suitable for logs and long-lived history."""

    if client_ip is None:
        return None

    normalized_ip = client_ip.strip()
    if not normalized_ip:
        return None

    octets = normalized_ip.split(".")
    if len(octets) == 4:
        return ".".join((*octets[:3], "x"))

    if ":" in normalized_ip:
        hextets = [segment for segment in normalized_ip.split(":") if segment]
        if hextets:
            visible_segments = hextets[: min(3, len(hextets))]
            return f"{':'.join(visible_segments)}:*"

    return "*"


def build_public_traffic_alert(
    event: PublicTrafficEvent,
    headers: Mapping[str, str],
) -> PublicTrafficAlert:
    """Build the logged alert payload from the request headers and event body."""

    return PublicTrafficAlert(
        client_ip=extract_client_ip(headers),
        event=event,
        user_agent=_get_header_value(headers, "User-Agent"),
    )


def public_traffic_alerts_configured(settings: AppSettings) -> bool:
    """Return whether SMTP-backed public traffic alerts are configured."""

    if not settings.public_traffic_alerts_enabled:
        return False

    return all(
        (
            settings.public_alert_recipient_email,
            settings.smtp_host,
            settings.smtp_sender_email,
        )
    )


def public_traffic_event_triggers_alert_email(event: PublicTrafficEvent) -> bool:
    """Return whether the event should send an SMTP-backed alert email."""

    return event.event_type != "health_probe"


_BOT_KEYWORDS: tuple[str, ...] = (
    "bot",
    "crawler",
    "spider",
    "slurp",
    "facebookexternalhit",
    "headlesschrome",
)


def _looks_like_bot(user_agent: str) -> bool:
    lowered = user_agent.lower()
    return any(token in lowered for token in _BOT_KEYWORDS)


def summarize_user_agent(user_agent: str | None) -> str:
    """Return a short, human-readable description of a user agent string.

    Examples: ``"Firefox 150 on Windows"``, ``"Googlebot"``, ``"Unknown client"``.
    """

    if not user_agent:
        return "Unknown client"

    lowered = user_agent.lower()

    bot_labels = {
        "googlebot": "Googlebot",
        "bingbot": "Bingbot",
        "applebot": "Applebot",
        "yandexbot": "YandexBot",
        "duckduckbot": "DuckDuckBot",
        "baiduspider": "Baiduspider",
        "ahrefsbot": "AhrefsBot",
        "semrushbot": "SemrushBot",
        "mj12bot": "MJ12bot",
        "petalbot": "PetalBot",
        "facebookexternalhit": "Facebook crawler",
    }
    for needle, label in bot_labels.items():
        if needle in lowered:
            return label

    if "edg/" in lowered:
        browser = "Edge"
    elif "firefox/" in lowered:
        browser = "Firefox"
    elif "chrome/" in lowered and "chromium" not in lowered:
        browser = "Chrome"
    elif "safari/" in lowered and "chrome" not in lowered:
        browser = "Safari"
    else:
        browser = "Browser"

    if "windows" in lowered:
        platform = "Windows"
    elif "mac os x" in lowered or "macintosh" in lowered:
        platform = "macOS"
    elif "android" in lowered:
        platform = "Android"
    elif "iphone" in lowered or "ipad" in lowered or "ios" in lowered:
        platform = "iOS"
    elif "linux" in lowered:
        platform = "Linux"
    else:
        platform = "Unknown OS"

    return f"{browser} on {platform}"


def _ip_matches_prefix(client_ip: str, prefix: str) -> bool:
    normalized_prefix = prefix.strip()
    if not normalized_prefix:
        return False
    return client_ip.startswith(normalized_prefix)


def public_traffic_alert_should_send(
    alert: PublicTrafficAlert,
    settings: AppSettings,
    *,
    enrichment: "PublicNetworkEnrichment | None" = None,
) -> bool:
    """Return whether the alert passes self-traffic and bot suppression filters.

    When ``public_alert_allowed_user_agent_substrings`` is non-empty the function
    flips into allow-list mode: only events whose user-agent contains at least
    one of the configured substrings are sent, and every other event is
    suppressed regardless of the deny lists.

    When ``enrichment`` is provided and ``public_alert_suppress_datacenter_traffic``
    is enabled, the alert is also suppressed if ipapi.is reports the source IP
    as a datacenter / VPN / proxy / Tor exit / hosting path. When
    ``public_alert_suppress_no_referrer_deep_links`` is enabled, page_view
    events that arrive with no referrer on a non-landing route are suppressed
    too — that pattern is overwhelmingly scripted traffic rather than a real
    visitor (real users either land on ``home`` or arrive with a referrer).
    """

    client_ip = (alert.client_ip or "").strip()
    if client_ip:
        for prefix in settings.public_alert_ignored_ip_prefixes:
            if _ip_matches_prefix(client_ip, prefix):
                return False

    user_agent = (alert.user_agent or "").strip()
    lowered_agent = user_agent.lower()

    allow_list = tuple(
        substring.strip().lower()
        for substring in settings.public_alert_allowed_user_agent_substrings
        if substring and substring.strip()
    )
    if allow_list:
        if not lowered_agent:
            return False
        return any(substring in lowered_agent for substring in allow_list)

    if user_agent:
        for substring in settings.public_alert_ignored_user_agent_substrings:
            normalized = substring.strip().lower()
            if normalized and normalized in lowered_agent:
                return False

    if (
        settings.public_alert_suppress_datacenter_traffic
        and enrichment is not None
        and _enrichment_indicates_automated_source(enrichment)
    ):
        return False

    if settings.public_alert_suppress_no_referrer_deep_links and _is_no_referrer_deep_link(
        alert.event, settings
    ):
        return False

    return True


_AUTOMATED_VPN_PROXY_KEYWORDS = (
    "tor",
    "vpn",
    "proxy",
    "datacenter",
    "data center",
    "hosting",
)


def _enrichment_indicates_automated_source(
    enrichment: "PublicNetworkEnrichment",
) -> bool:
    """Return True when ipapi.is signals a non-residential / automated source."""

    if enrichment.hosting_provider:
        return True

    vpn_proxy_status = (enrichment.vpn_proxy_status or "").lower()
    if vpn_proxy_status:
        return any(keyword in vpn_proxy_status for keyword in _AUTOMATED_VPN_PROXY_KEYWORDS)

    return False


def _is_no_referrer_deep_link(
    event: PublicTrafficEvent,
    settings: AppSettings,
) -> bool:
    """Return True for page_views that look like scripted deep-link hits.

    A real visitor either lands on the configured landing routes (typically
    ``home`` / ``/``) or arrives from another page and carries a referrer.
    A page_view on a deep route with an empty referrer is almost always a
    headless browser, scraper, or uptime probe.
    """

    if event.event_type != "page_view":
        return False

    referrer = (event.referrer or "").strip()
    if referrer:
        return False

    landing_routes = {
        candidate.strip().lower()
        for candidate in settings.public_alert_landing_routes
        if candidate is not None
    }
    normalized_route = event.route.strip().lower()
    return normalized_route not in landing_routes


def build_public_traffic_alert_email(
    alert: PublicTrafficAlert,
    settings: AppSettings,
    *,
    enrichment: "PublicNetworkEnrichment | None" = None,
) -> EmailMessage:
    """Build the optional SMTP email for a public traffic event.

    When ``enrichment`` is provided, ASN / network owner / hosting provider /
    reputation summary are appended to the body so the recipient can tell at a
    glance whether the visitor was a residential ISP, a cloud crawler, or a
    pen-test scanner without having to look up the IP.
    """

    message = EmailMessage()
    message["From"] = settings.smtp_sender_email
    message["To"] = settings.public_alert_recipient_email
    message["Subject"] = (
        f"[DOCINT] Public site traffic: {alert.event.event_type} {alert.event.route}"
    )

    body_lines = [
        "Hybrid Document Intelligence public-site traffic detected.",
        f"Environment: {settings.environment_name}",
        f"Event type: {alert.event.event_type}",
        f"Route: {alert.event.route}",
        f"Site mode: {alert.event.site_mode}",
        f"Page title: {alert.event.page_title or 'n/a'}",
        f"Session id: {alert.event.session_id}",
        f"Referrer: {alert.event.referrer or 'n/a'}",
        f"Client summary: {summarize_user_agent(alert.user_agent)}",
        f"Likely bot: {'yes' if alert.user_agent and _looks_like_bot(alert.user_agent) else 'no'}",
        f"User agent: {alert.user_agent or 'n/a'}",
        f"Client IP (masked): {mask_client_ip(alert.client_ip) or 'n/a'}",
    ]
    if enrichment is not None:
        if enrichment.network_asn:
            body_lines.append(f"Network ASN: {enrichment.network_asn}")
        if enrichment.network_owner:
            body_lines.append(f"Network owner: {enrichment.network_owner}")
        if enrichment.hosting_provider:
            body_lines.append(f"Hosting provider: {enrichment.hosting_provider}")
        if enrichment.approximate_location:
            body_lines.append(f"Approximate location: {enrichment.approximate_location}")
        if enrichment.reputation_summary:
            body_lines.append(f"Reputation: {enrichment.reputation_summary}")
        if enrichment.vpn_proxy_status:
            body_lines.append(f"VPN/proxy status: {enrichment.vpn_proxy_status}")
    body_lines.append(f"Received UTC: {alert.received_at_utc.isoformat()}")

    message.set_content("\n".join(body_lines))
    return message


def _safe_lookup_alert_enrichment(
    alert: PublicTrafficAlert,
    settings: AppSettings,
) -> "PublicNetworkEnrichment | None":
    """Best-effort provider-backed enrichment for a passing traffic alert.

    Failures are swallowed (and logged) because alert delivery must never block
    on a third-party feed. Returns ``None`` whenever enrichment is disabled,
    unconfigured, missing a client IP, or the provider raises.
    """

    if not (alert.client_ip or "").strip():
        return None

    try:
        from security_posture_api.public_network_enrichment import (
            build_public_network_enrichment_provider,
        )

        provider = build_public_network_enrichment_provider(settings)
        if provider is None:
            return None
        return provider.enrich(alert.client_ip or "")
    except Exception as enrichment_error:  # noqa: BLE001 — never block alert send
        logging.warning(
            "Public traffic alert enrichment failed: %s", enrichment_error
        )
        return None


def _record_suppressed_alert(
    alert: PublicTrafficAlert,
    settings: AppSettings,
    *,
    suppression_reason: str,
) -> None:
    """Persist a sanitized suppressed-alert row so the cadence card can count it.

    Failures are swallowed and logged because suppression accounting must never
    fail an inbound traffic event.
    """

    try:
        from security_posture_api.public_traffic_metrics import (
            PublicSuppressedAlertHistoryRecord,
            persist_public_suppressed_alert_record,
        )

        record = PublicSuppressedAlertHistoryRecord(
            event_type=alert.event.event_type,
            route=alert.event.route,
            site_mode=alert.event.site_mode,
            suppression_reason=suppression_reason,
        )
        persist_public_suppressed_alert_record(record, settings)
    except Exception:  # noqa: BLE001 — never block alert ingestion
        logging.exception("Unable to persist sanitized suppressed-alert record.")


def send_public_traffic_alert(
    alert: PublicTrafficAlert,
    settings: AppSettings,
) -> bool:
    """Send an SMTP email for the supplied public traffic event when enabled."""

    if not public_traffic_event_triggers_alert_email(alert.event):
        logging.info(
            "Public traffic event %s is a health probe; skipping email alert",
            alert.event.event_type,
        )
        return False

    enrichment = _safe_lookup_alert_enrichment(alert, settings)

    if not public_traffic_alert_should_send(alert, settings, enrichment=enrichment):
        logging.info(
            "Public traffic event suppressed by ignore filters (ip=%s, ua=%s)",
            mask_client_ip(alert.client_ip) or "n/a",
            summarize_user_agent(alert.user_agent),
        )
        _record_suppressed_alert(alert, settings, suppression_reason="ignore_filters")
        return False

    if not public_traffic_alerts_configured(settings):
        logging.info("Public traffic alert email is not configured; skipping email")
        return False

    message = build_public_traffic_alert_email(alert, settings, enrichment=enrichment)
    smtp_host = settings.smtp_host
    if smtp_host is None:
        raise ValueError("smtp_host is required when traffic alerts are enabled")

    with smtplib.SMTP(smtp_host, settings.smtp_port, timeout=10) as client:
        if settings.smtp_use_tls:
            client.starttls()
        if settings.smtp_username:
            client.login(
                settings.smtp_username,
                settings.smtp_password or "",
            )
        client.send_message(message)

    return True


def build_public_traffic_daily_digest_email(
    summary: "PublicTrafficMetricsSummary",
    settings: AppSettings,
) -> EmailMessage:
    """Build the daily public-traffic digest email from a sanitized summary.

    Pure: takes a fully-built `PublicTrafficMetricsSummary` and returns the
    `EmailMessage`. The summary itself is composed in
    `public_traffic_metrics.build_public_traffic_metrics_summary`.
    """

    message = EmailMessage()
    message["From"] = settings.smtp_sender_email
    message["To"] = settings.public_alert_recipient_email
    message["Subject"] = (
        f"[DOCINT] Public site daily digest "
        f"({summary.environment_name}): {summary.total_events} events / "
        f"{summary.unique_sessions} sessions"
    )

    def _format_counts(label: str, counts: object) -> list[str]:
        if not counts:
            return [f"{label}: none"]
        items = ", ".join(f"{c.label}={c.count}" for c in counts)  # type: ignore[union-attr]
        return [f"{label}: {items}"]

    body_lines: list[str] = [
        "Hybrid Document Intelligence public-site daily digest.",
        f"Environment: {summary.environment_name}",
        f"Generated UTC: {summary.generated_at_utc.isoformat()}",
        f"Collection window: {summary.collection_window}",
        f"Total events: {summary.total_events}",
        f"Unique sessions: {summary.unique_sessions}",
        f"Current status: {summary.current_status}",
    ]
    if summary.availability_percentage is not None:
        body_lines.append(
            f"Availability: {summary.availability_percentage:.2f}% "
            f"({summary.availability_window})"
        )
    if summary.last_event_at_utc is not None:
        body_lines.append(f"Last event UTC: {summary.last_event_at_utc.isoformat()}")
    body_lines.extend(_format_counts("Routes", summary.route_counts))
    body_lines.extend(_format_counts("Site modes", summary.site_mode_counts))
    body_lines.extend(_format_counts("Geography", summary.geography_counts))
    if summary.recent_health_checks:
        body_lines.append("Recent health checks:")
        for check in summary.recent_health_checks:
            body_lines.append(
                f"  - {check.checked_at_utc.isoformat()} "
                f"ok={check.overall_ok} {check.note}"
            )

    message.set_content("\n".join(body_lines))
    return message


def send_public_traffic_daily_digest(settings: AppSettings) -> bool:
    """Build the current public-traffic summary and send the daily digest email.

    Returns ``True`` when the digest is sent. The digest is skipped (with a
    log line) when the digest flag is disabled, SMTP is not configured, or the
    summary contains zero events for the retention window.
    """

    if not settings.public_traffic_daily_digest_enabled:
        logging.info("Public traffic daily digest disabled by feature flag.")
        return False

    if not public_traffic_alerts_configured(settings):
        logging.info(
            "Public traffic daily digest skipped: SMTP/recipient not configured."
        )
        return False

    from security_posture_api.public_traffic_metrics import (
        build_public_traffic_metrics_summary,
    )

    summary = build_public_traffic_metrics_summary(settings)
    if summary.total_events == 0 and not summary.recent_health_checks:
        logging.info("Public traffic daily digest skipped: no events in window.")
        return False

    message = build_public_traffic_daily_digest_email(summary, settings)
    smtp_host = settings.smtp_host
    if smtp_host is None:
        raise ValueError("smtp_host is required when traffic alerts are enabled")

    with smtplib.SMTP(smtp_host, settings.smtp_port, timeout=10) as client:
        if settings.smtp_use_tls:
            client.starttls()
        if settings.smtp_username:
            client.login(
                settings.smtp_username,
                settings.smtp_password or "",
            )
        client.send_message(message)

    return True
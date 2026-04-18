"""Helpers for public-site traffic logging and optional email alerts."""

from __future__ import annotations

import logging
import smtplib
from collections.abc import Mapping
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from security_posture_api.settings import AppSettings


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

    return forwarded_for.split(",", maxsplit=1)[0].strip() or None


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


def build_public_traffic_alert_email(
    alert: PublicTrafficAlert,
    settings: AppSettings,
) -> EmailMessage:
    """Build the optional SMTP email for a public traffic event."""

    message = EmailMessage()
    message["From"] = settings.smtp_sender_email
    message["To"] = settings.public_alert_recipient_email
    message["Subject"] = (
        f"[DOCINT] Public site traffic: {alert.event.event_type} {alert.event.route}"
    )
    message.set_content(
        "\n".join(
            [
                "Hybrid Document Intelligence public-site traffic detected.",
                f"Environment: {settings.environment_name}",
                f"Event type: {alert.event.event_type}",
                f"Route: {alert.event.route}",
                f"Site mode: {alert.event.site_mode}",
                f"Page title: {alert.event.page_title or 'n/a'}",
                f"Session id: {alert.event.session_id}",
                f"Referrer: {alert.event.referrer or 'n/a'}",
                f"User agent: {alert.user_agent or 'n/a'}",
                f"Client IP (masked): {mask_client_ip(alert.client_ip) or 'n/a'}",
                f"Received UTC: {alert.received_at_utc.isoformat()}",
            ]
        )
    )
    return message


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

    if not public_traffic_alerts_configured(settings):
        logging.info("Public traffic alert email is not configured; skipping email")
        return False

    message = build_public_traffic_alert_email(alert, settings)
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
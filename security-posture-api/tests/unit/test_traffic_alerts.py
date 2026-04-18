"""Unit tests for public traffic alert helpers."""

from __future__ import annotations

from security_posture_api.settings import AppSettings
from security_posture_api.traffic_alerts import (
    PublicTrafficEvent,
    build_public_traffic_alert,
    build_public_traffic_alert_email,
    extract_client_ip,
    mask_client_ip,
    public_traffic_event_triggers_alert_email,
    public_traffic_alerts_configured,
)


def test_extract_client_ip_prefers_forwarded_for_header() -> None:
    """The first forwarded IP should be used when multiple proxies are present."""
    headers = {"X-Forwarded-For": "203.0.113.10, 10.10.10.10"}

    assert extract_client_ip(headers) == "203.0.113.10"


def test_build_public_traffic_alert_includes_request_metadata() -> None:
    """Request metadata should be copied into the server-side traffic alert."""
    event = PublicTrafficEvent(
        event_type="page_view",
        route="review",
        session_id="session-123",
        site_mode="simulation",
    )

    alert = build_public_traffic_alert(
        event,
        {
            "User-Agent": "pytest-agent",
            "X-Azure-ClientIP": "198.51.100.22",
        },
    )

    assert alert.client_ip == "198.51.100.22"
    assert alert.user_agent == "pytest-agent"
    assert alert.event.route == "review"


def test_mask_client_ip_redacts_last_segment() -> None:
    """Long-lived alerting paths should mask the raw client IP."""

    assert mask_client_ip("198.51.100.11") == "198.51.100.x"


def test_public_traffic_alerts_configured_requires_minimum_smtp_fields() -> None:
    """SMTP alerting should stay disabled until the required values are present."""
    incomplete_settings = AppSettings(
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
    )
    configured_settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
    )

    assert public_traffic_alerts_configured(incomplete_settings) is False
    assert public_traffic_alerts_configured(configured_settings) is True


def test_build_public_traffic_alert_email_includes_event_context() -> None:
    """Alert email content should include the environment and event details."""
    event = PublicTrafficEvent(
        event_type="simulation_started",
        route="intake",
        session_id="session-789",
        page_title="Public Simulation",
        referrer="https://contoso.example/hr",
        site_mode="simulation",
    )
    alert = build_public_traffic_alert(
        event,
        {
            "User-Agent": "pytest-agent",
            "X-Forwarded-For": "198.51.100.11",
        },
    )
    settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
    )

    message = build_public_traffic_alert_email(alert, settings)

    assert message["From"] == "docint@example.com"
    assert message["To"] == "alerts@example.com"
    assert (
        message["Subject"]
        == "[DOCINT] Public site traffic: simulation_started intake"
    )
    assert "Environment: test" in message.get_content()
    assert "Route: intake" in message.get_content()
    assert "Client IP (masked): 198.51.100.x" in message.get_content()


def test_public_traffic_event_triggers_alert_email_skips_health_probes() -> None:
    """Continuous health probes should not generate SMTP traffic alerts."""

    assert public_traffic_event_triggers_alert_email(
        PublicTrafficEvent(
            event_type="simulation_started",
            route="intake",
            session_id="session-1",
            site_mode="simulation",
        )
    ) is True
    assert public_traffic_event_triggers_alert_email(
        PublicTrafficEvent(
            event_type="health_probe",
            route="security-monitor",
            session_id="probe-1",
            site_mode="simulation",
        )
    ) is False
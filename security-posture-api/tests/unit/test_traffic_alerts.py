"""Unit tests for public traffic alert helpers."""

from __future__ import annotations

from security_posture_api.settings import AppSettings
from security_posture_api.traffic_alerts import (
    PublicTrafficEvent,
    build_public_traffic_alert,
    build_public_traffic_alert_email,
    extract_client_ip,
    mask_client_ip,
    public_traffic_alert_should_send,
    public_traffic_event_triggers_alert_email,
    public_traffic_alerts_configured,
    summarize_user_agent,
)


def test_extract_client_ip_prefers_forwarded_for_header() -> None:
    """The first forwarded IP should be used when multiple proxies are present."""
    headers = {"X-Forwarded-For": "203.0.113.10, 10.10.10.10"}

    assert extract_client_ip(headers) == "203.0.113.10"


def test_extract_client_ip_strips_ipv4_port_suffix() -> None:
    """Azure's edge appends ``:port`` to IPv4 forwarded IPs; that must not leak."""
    headers = {"X-Forwarded-For": "75.242.252.169:59498"}

    assert extract_client_ip(headers) == "75.242.252.169"


def test_extract_client_ip_strips_bracketed_ipv6_port_suffix() -> None:
    """IPv6 forwarded IPs use the ``[ip]:port`` shape; the brackets and port go."""
    headers = {"X-Forwarded-For": "[2001:db8::1]:443, 10.0.0.1"}

    assert extract_client_ip(headers) == "2001:db8::1"


def test_extract_client_ip_preserves_bare_ipv6() -> None:
    """A bare IPv6 (no port suffix) must round-trip unchanged."""
    headers = {"X-Forwarded-For": "2001:db8::1"}

    assert extract_client_ip(headers) == "2001:db8::1"


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


def _sample_event() -> PublicTrafficEvent:
    return PublicTrafficEvent(
        event_type="page_view",
        route="landing",
        session_id="session-xyz",
        site_mode="simulation",
    )


def test_summarize_user_agent_recognizes_googlebot() -> None:
    """Googlebot user agents should be summarized as a known crawler."""

    user_agent = (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    )

    assert summarize_user_agent(user_agent) == "Googlebot"


def test_summarize_user_agent_parses_firefox_on_windows() -> None:
    """Browser + OS combinations should yield a short readable label."""

    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0"

    assert summarize_user_agent(user_agent) == "Firefox on Windows"


def test_public_traffic_alert_should_send_filters_self_ip_prefix() -> None:
    """Self-traffic from a configured IP prefix should be suppressed."""
    settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
        public_alert_ignored_ip_prefixes=("75.242.252.",),
    )
    alert = build_public_traffic_alert(
        _sample_event(),
        {"X-Forwarded-For": "75.242.252.10", "User-Agent": "Firefox/150.0"},
    )

    assert public_traffic_alert_should_send(alert, settings) is False


def test_public_traffic_alert_should_send_filters_googlebot_user_agent() -> None:
    """Default ignored UA list should suppress Googlebot crawls."""
    settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
    )
    alert = build_public_traffic_alert(
        _sample_event(),
        {
            "X-Forwarded-For": "66.249.66.1",
            "User-Agent": (
                "Mozilla/5.0 (compatible; Googlebot/2.1; "
                "+http://www.google.com/bot.html)"
            ),
        },
    )

    assert public_traffic_alert_should_send(alert, settings) is False


def test_public_traffic_alert_should_send_allows_real_visitor() -> None:
    """Genuine visitor traffic should still pass the filters."""
    settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
        public_alert_ignored_ip_prefixes=("75.242.252.",),
    )
    alert = build_public_traffic_alert(
        _sample_event(),
        {
            "X-Forwarded-For": "203.0.113.55",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
            ),
        },
    )

    assert public_traffic_alert_should_send(alert, settings) is True


def test_public_traffic_alert_should_send_allow_list_blocks_unknown_ua() -> None:
    """Allow-list mode should suppress events whose UA does not match an allowed substring."""
    settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
        public_alert_allowed_user_agent_substrings=("firefox", "safari"),
    )
    alert = build_public_traffic_alert(
        _sample_event(),
        {"X-Forwarded-For": "203.0.113.10", "User-Agent": "curl/8.4.0"},
    )

    assert public_traffic_alert_should_send(alert, settings) is False


def test_public_traffic_alert_should_send_allow_list_passes_matching_ua() -> None:
    """Allow-list mode should still send events whose UA matches an allowed substring."""
    settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
        public_alert_allowed_user_agent_substrings=("firefox",),
    )
    alert = build_public_traffic_alert(
        _sample_event(),
        {
            "X-Forwarded-For": "203.0.113.55",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) "
                "Gecko/20100101 Firefox/150.0"
            ),
        },
    )

    assert public_traffic_alert_should_send(alert, settings) is True


def test_build_public_traffic_alert_email_includes_client_summary_line() -> None:
    """Email body should include the parsed client summary and bot flag."""
    alert = build_public_traffic_alert(
        _sample_event(),
        {
            "X-Forwarded-For": "203.0.113.55",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) "
                "Gecko/20100101 Firefox/150.0"
            ),
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
    body = message.get_content()

    assert "Client summary: Firefox on Windows" in body
    assert "Likely bot: no" in body


def test_build_public_traffic_alert_email_includes_enrichment_lines() -> None:
    """Email body should append ASN / owner / hosting / reputation when supplied."""
    from security_posture_api.public_network_enrichment import PublicNetworkEnrichment

    alert = build_public_traffic_alert(
        _sample_event(),
        {
            "X-Forwarded-For": "203.0.113.55",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) "
                "Gecko/20100101 Firefox/150.0"
            ),
        },
    )
    settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
    )
    enrichment = PublicNetworkEnrichment(
        approximate_location="US / WA",
        hosting_provider="Cloud Provider",
        network_asn="AS15169",
        network_owner="Example ISP",
        reputation_summary="Low observed abuse risk",
        vpn_proxy_status="No proxy or VPN signal returned.",
    )

    message = build_public_traffic_alert_email(alert, settings, enrichment=enrichment)
    body = message.get_content()

    assert "Network ASN: AS15169" in body
    assert "Network owner: Example ISP" in body
    assert "Hosting provider: Cloud Provider" in body
    assert "Approximate location: US / WA" in body
    assert "Reputation: Low observed abuse risk" in body
    assert "VPN/proxy status: No proxy or VPN signal returned." in body


def test_send_public_traffic_daily_digest_disabled_returns_false() -> None:
    """When the digest flag is off the helper returns False without sending."""
    from security_posture_api.traffic_alerts import send_public_traffic_daily_digest
    settings = AppSettings(public_traffic_daily_digest_enabled=False)
    assert send_public_traffic_daily_digest(settings) is False


def test_build_public_traffic_daily_digest_email_renders_summary() -> None:
    """The digest body should include totals, route counts, and status."""
    from datetime import UTC, datetime
    from security_posture_api.public_traffic_metrics import (
        PublicMetricCount,
        PublicTrafficMetricsSummary,
    )
    from security_posture_api.traffic_alerts import build_public_traffic_daily_digest_email

    summary = PublicTrafficMetricsSummary(
        availability_percentage=99.9,
        availability_source="durable",
        availability_window="last 24h",
        collection_mode="durable",
        collection_window="Last 24 hours",
        current_status="healthy",
        environment_name="prod",
        generated_at_utc=datetime(2026, 4, 23, 13, 30, tzinfo=UTC),
        last_event_at_utc=datetime(2026, 4, 23, 12, 0, tzinfo=UTC),
        recent_activity_window="last 30 minutes",
        route_counts=(PublicMetricCount(label="security", count=12),),
        site_mode_counts=(PublicMetricCount(label="security", count=12),),
        geography_counts=(PublicMetricCount(label="US / WA", count=10),),
        total_events=12,
        traffic_cadence_window="last 24 hourly buckets",
        unique_sessions=4,
    )
    settings = AppSettings(
        environment_name="prod",
        public_alert_recipient_email="alerts@example.com",
        smtp_sender_email="docint@example.com",
    )

    message = build_public_traffic_daily_digest_email(summary, settings)
    body = message.get_content()

    assert "Total events: 12" in body
    assert "Unique sessions: 4" in body
    assert "Routes: security=12" in body
    assert "Geography: US / WA=10" in body
    assert "Availability: 99.90%" in body


def test_should_send_suppresses_datacenter_traffic_via_enrichment() -> None:
    """ipapi.is hosting/datacenter signals should suppress the alert by default."""
    from security_posture_api.public_network_enrichment import PublicNetworkEnrichment

    settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
    )
    alert = build_public_traffic_alert(
        _sample_event(),
        {
            "X-Forwarded-For": "203.0.113.10",
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) HeadlessChrome/139.0.0.0 Safari/537.36"
            ),
        },
    )
    enrichment = PublicNetworkEnrichment(
        hosting_provider="DigitalOcean",
        network_asn="AS14061",
        network_owner="DigitalOcean LLC",
        vpn_proxy_status="DigitalOcean hosting path observed by ipapi.is.",
    )

    assert public_traffic_alert_should_send(alert, settings, enrichment=enrichment) is False


def test_should_send_suppresses_vpn_proxy_traffic_via_enrichment() -> None:
    """VPN / proxy / Tor signals on the enrichment payload should suppress."""
    from security_posture_api.public_network_enrichment import PublicNetworkEnrichment

    settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
    )
    alert = build_public_traffic_alert(
        _sample_event(),
        {
            "X-Forwarded-For": "203.0.113.10",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
            ),
        },
    )
    enrichment = PublicNetworkEnrichment(
        vpn_proxy_status="VPN exit node detected by ipapi.is (Mullvad).",
    )

    assert public_traffic_alert_should_send(alert, settings, enrichment=enrichment) is False


def test_should_send_passes_residential_enrichment() -> None:
    """Residential ISP enrichment with no proxy signal should not suppress."""
    from security_posture_api.public_network_enrichment import PublicNetworkEnrichment

    settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
    )
    alert = build_public_traffic_alert(
        _sample_event(),
        {
            "X-Forwarded-For": "75.242.252.169",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
            ),
        },
    )
    enrichment = PublicNetworkEnrichment(
        network_asn="AS6167",
        network_owner="Verizon Business",
    )

    assert public_traffic_alert_should_send(alert, settings, enrichment=enrichment) is True


def test_should_send_suppresses_no_referrer_deep_link_page_view() -> None:
    """A page_view on a deep route with no referrer is almost always a bot."""
    settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
    )
    deep_link_event = PublicTrafficEvent(
        event_type="page_view",
        route="cost",
        session_id="session-deep",
        site_mode="simulation",
        referrer=None,
    )
    alert = build_public_traffic_alert(
        deep_link_event,
        {
            "X-Forwarded-For": "75.242.252.169",
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
            ),
        },
    )

    assert public_traffic_alert_should_send(alert, settings) is False


def test_should_send_passes_landing_route_without_referrer() -> None:
    """A no-referrer hit to the configured landing route is a real direct visit."""
    settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
    )
    landing_event = PublicTrafficEvent(
        event_type="page_view",
        route="home",
        session_id="session-direct",
        site_mode="simulation",
        referrer=None,
    )
    alert = build_public_traffic_alert(
        landing_event,
        {
            "X-Forwarded-For": "75.242.252.169",
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
            ),
        },
    )

    assert public_traffic_alert_should_send(alert, settings) is True


def test_should_send_passes_deep_link_with_referrer() -> None:
    """A deep route with a referrer is normal in-app navigation; do not suppress."""
    settings = AppSettings(
        environment_name="test",
        public_traffic_alerts_enabled=True,
        public_alert_recipient_email="alerts@example.com",
        smtp_host="smtp.example.com",
        smtp_sender_email="docint@example.com",
    )
    referred_event = PublicTrafficEvent(
        event_type="page_view",
        route="cost",
        session_id="session-nav",
        site_mode="simulation",
        referrer="https://func-doc-test-nwigok.azurewebsites.net/",
    )
    alert = build_public_traffic_alert(
        referred_event,
        {
            "X-Forwarded-For": "75.242.252.169",
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
            ),
        },
    )

    assert public_traffic_alert_should_send(alert, settings) is True


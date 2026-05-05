"""Unit tests for public request-context helpers."""

from __future__ import annotations

from security_posture_api.public_network_enrichment import PublicNetworkEnrichment
from security_posture_api.public_request_context import build_public_request_context


class _StubEnrichmentProvider:
    provider_name = "IPQualityScore"

    def enrich(self, client_ip: str) -> PublicNetworkEnrichment | None:
        if client_ip != "203.0.113.77":
            return None

        return PublicNetworkEnrichment(
            hosting_provider="Azure Front Door",
            network_asn="AS8075",
            network_owner="Microsoft Corporation",
            reputation_summary="Low observed abuse risk · fraud score 12/100",
            vpn_proxy_status=(
                "Data Center/Web Hosting/Transit path observed by IPQualityScore."
            ),
        )


def test_build_public_request_context_prefers_forwarded_headers() -> None:
    """The public request context should surface trusted forwarded metadata."""

    request_context = build_public_request_context(
        {
            "X-ARR-LOG-ID": "abcdef1234567890fedcba",
            "X-Forwarded-For": "203.0.113.77, 10.0.0.4",
            "X-Forwarded-Host": "ryancodes.security.online",
            "X-Forwarded-Proto": "https",
            "X-Geo-Country": "US",
            "X-Geo-Region": "Ohio",
            "X-SSL-Protocol": "TLSv1.3",
        },
        "http://localhost/api/public-request-context",
    )

    assert request_context.client_ip == "203.0.113.77"
    assert request_context.approximate_location == "US / Ohio"
    assert request_context.forwarded_host == "ryancodes.security.online"
    assert request_context.forwarded_proto == "https"
    assert request_context.transport_security == "HTTPS only"
    assert request_context.tls_protocol == "TLSv1.3"
    assert request_context.request_id == "req-abcdef123456"
    assert request_context.enrichment_provider_name is None
    assert request_context.enrichment_status == (
        "No provider-backed network enrichment feed is configured on this host."
    )
    assert request_context.public_network_enrichment_enabled is True
    assert request_context.public_security_globe_enabled is True


def test_build_public_request_context_falls_back_when_edge_headers_are_missing(
    monkeypatch,
) -> None:
    """The public request context should stay explicit when edge hints are absent."""

    monkeypatch.setenv("REGION_NAME", "eastus2")

    request_context = build_public_request_context(
        {"Host": "func-doc-test.azurewebsites.net"},
        "http://localhost/api/public-request-context",
    )

    assert request_context.client_ip is None
    assert request_context.approximate_location == (
        "Unavailable until coarse edge geolocation headers are configured."
    )
    assert request_context.edge_region == "Host region: eastus2"
    assert request_context.forwarded_host == "func-doc-test.azurewebsites.net"
    assert request_context.forwarded_proto == "http"
    assert request_context.transport_security == "HTTP or local development path"
    assert request_context.tls_protocol == "HTTP"
    assert request_context.request_id.startswith("req-")
    assert request_context.enrichment_provider_name is None
    assert request_context.public_network_enrichment_enabled is True
    assert request_context.public_security_globe_enabled is True


def test_build_public_request_context_includes_provider_backed_enrichment() -> None:
    """Provider-backed enrichment should surface bounded network fields."""

    request_context = build_public_request_context(
        {
            "X-Forwarded-For": "203.0.113.77, 10.0.0.4",
            "X-Forwarded-Proto": "https",
            "X-Geo-Country": "US",
            "X-Geo-Region": "Ohio",
        },
        "http://localhost/api/public-request-context",
        enrichment_provider=_StubEnrichmentProvider(),
    )

    assert request_context.client_ip == "203.0.113.77"
    assert request_context.enrichment_provider_name == "IPQualityScore"
    assert request_context.enrichment_status == (
        "Provider-backed network signals loaded from IPQualityScore."
    )
    assert request_context.network_asn == "AS8075"
    assert request_context.network_owner == "Microsoft Corporation"
    assert request_context.hosting_provider == "Azure Front Door"
    assert request_context.public_network_enrichment_enabled is True
    assert request_context.public_security_globe_enabled is True
    assert request_context.vpn_proxy_status == (
        "Data Center/Web Hosting/Transit path observed by IPQualityScore."
    )
    assert request_context.reputation_summary == (
        "Low observed abuse risk · fraud score 12/100"
    )


def test_build_public_request_context_uses_provider_location_when_edge_headers_are_missing() -> None:
    """Provider-backed coarse location should fill the gap when edge geo headers are absent."""

    class _ProviderLocationStub:
        provider_name = "ipapi.is"

        def enrich(self, client_ip: str) -> PublicNetworkEnrichment | None:
            if client_ip != "203.0.113.77":
                return None

            return PublicNetworkEnrichment(
                approximate_location="US / Ohio",
                network_asn="AS6167",
                network_owner="Verizon Business",
                reputation_summary="Provider-backed abuse exposure 0 (Very Low) according to ipapi.is.",
            )

    request_context = build_public_request_context(
        {
            "Host": "func-doc-test.azurewebsites.net",
            "X-Forwarded-For": "203.0.113.77, 10.0.0.4",
            "X-Forwarded-Proto": "https",
        },
        "http://localhost/api/public-request-context",
        enrichment_provider=_ProviderLocationStub(),
    )

    assert request_context.approximate_location == "US / Ohio"
    assert request_context.enrichment_provider_name == "ipapi.is"
    assert request_context.enrichment_status == (
        "Provider-backed network signals loaded from ipapi.is."
    )
    assert request_context.network_asn == "AS6167"
    assert request_context.network_owner == "Verizon Business"


def test_build_public_request_context_skips_provider_when_feature_flag_disabled() -> None:
    """The rollout flag should hide provider-backed enrichment without calling the provider."""

    provider_calls = 0

    class _CountingProvider:
        provider_name = "IPQualityScore"

        def enrich(self, client_ip: str) -> PublicNetworkEnrichment | None:
            nonlocal provider_calls
            provider_calls += 1
            del client_ip
            return None

    request_context = build_public_request_context(
        {
            "X-Forwarded-For": "203.0.113.77, 10.0.0.4",
            "X-Forwarded-Proto": "https",
        },
        "http://localhost/api/public-request-context",
        enrichment_provider=_CountingProvider(),
        enrichment_enabled=False,
        security_globe_enabled=False,
    )

    assert provider_calls == 0
    assert request_context.enrichment_provider_name is None
    assert request_context.enrichment_status == (
        "Provider-backed network enrichment is disabled by feature flag."
    )
    assert request_context.public_network_enrichment_enabled is False
    assert request_context.public_security_globe_enabled is False
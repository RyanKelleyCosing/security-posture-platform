"""Unit tests for public request-context helpers."""

from __future__ import annotations

from security_posture_api.public_request_context import build_public_request_context


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
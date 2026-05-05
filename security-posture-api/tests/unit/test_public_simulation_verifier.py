"""Unit tests for public simulation verification helpers."""

from __future__ import annotations

import json
from email.message import EmailMessage
from types import TracebackType
from urllib.request import Request

from pytest import MonkeyPatch

from security_posture_api.utils import public_simulation_verifier


class FakeSiteResponse:
    """Minimal response stub for public site availability tests."""

    def __init__(self, status: int, content_type: str, body: str = "") -> None:
        self.status = status
        self.headers = EmailMessage()
        self.headers["Content-Type"] = content_type
        self._body = body.encode("utf-8")

    def __enter__(self) -> FakeSiteResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback

    def read(self) -> bytes:
        return self._body


def test_summarize_public_alert_settings_reports_ready_configuration() -> None:
    """Alert readiness should require the enable flag and all required values."""
    summary = public_simulation_verifier.summarize_public_alert_settings(
        {
            "DOCINT_PUBLIC_TRAFFIC_ALERTS_ENABLED": "true",
            "DOCINT_PUBLIC_ALERT_RECIPIENT_EMAIL": "alerts@example.com",
            "DOCINT_SMTP_HOST": "smtp.example.com",
            "DOCINT_SMTP_SENDER_EMAIL": "docint@example.com",
        }
    )

    assert summary.alerts_enabled is True
    assert summary.email_ready is True
    assert summary.missing_required_settings == ()


def test_summarize_public_alert_settings_reports_missing_values() -> None:
    """Missing SMTP values should keep email readiness false."""
    summary = public_simulation_verifier.summarize_public_alert_settings(
        {
            "DOCINT_PUBLIC_TRAFFIC_ALERTS_ENABLED": "true",
            "DOCINT_PUBLIC_ALERT_RECIPIENT_EMAIL": "alerts@example.com",
            "DOCINT_SMTP_HOST": "__REPLACE_WITH_SMTP_HOST__",
        }
    )

    assert summary.alerts_enabled is True
    assert summary.email_ready is False
    assert summary.missing_required_settings == (
        "DOCINT_SMTP_HOST",
        "DOCINT_SMTP_SENDER_EMAIL",
    )


def test_fetch_public_site_check_returns_reachability_details(
    monkeypatch: MonkeyPatch,
) -> None:
    """Public site checks should capture URL, status, and content type."""
    captured: dict[str, object] = {}

    def fake_urlopen(request: Request, timeout: int = 30) -> FakeSiteResponse:
        del timeout
        captured["method"] = request.get_method()
        captured["url"] = request.full_url
        return FakeSiteResponse(200, "text/html; charset=utf-8")

    monkeypatch.setattr(public_simulation_verifier, "urlopen", fake_urlopen)

    site_check = public_simulation_verifier.fetch_public_site_check(
        "https://contoso.z22.web.core.windows.net/"
    )

    assert captured == {
        "method": "GET",
        "url": "https://contoso.z22.web.core.windows.net",
    }
    assert site_check.is_reachable is True
    assert site_check.status_code == 200
    assert site_check.content_type == "text/html"


def test_load_azure_function_app_settings_parses_cli_json(
    monkeypatch: MonkeyPatch,
) -> None:
    """Azure CLI app settings output should flatten into a name/value mapping."""

    def fake_run_azure_cli_text(az_executable: str, args: list[str]) -> str:
        del az_executable, args
        return json.dumps(
            [
                {"name": "DOCINT_PUBLIC_TRAFFIC_ALERTS_ENABLED", "value": "true"},
                {"name": "DOCINT_SMTP_HOST", "value": "smtp.example.com"},
            ]
        )

    monkeypatch.setattr(
        public_simulation_verifier,
        "run_azure_cli_text",
        fake_run_azure_cli_text,
    )
    monkeypatch.setattr(
        public_simulation_verifier,
        "resolve_function_app_name",
        lambda az_executable, resource_group_name, function_app_name: "func-doc-test",
    )

    settings = public_simulation_verifier.load_azure_function_app_settings(
        "az",
        "rg-doc-intel-dev",
        "",
    )

    assert settings == {
        "DOCINT_PUBLIC_TRAFFIC_ALERTS_ENABLED": "true",
        "DOCINT_SMTP_HOST": "smtp.example.com",
    }


def test_resolve_public_cost_endpoint_normalizes_function_base_url() -> None:
    """Public cost endpoints should append the expected path to the Functions base URL."""

    endpoint = public_simulation_verifier.resolve_public_cost_endpoint(
        "https://func-doc-test-nwigok.azurewebsites.net/api/",
        "summary",
    )

    assert endpoint == "https://func-doc-test-nwigok.azurewebsites.net/api/public-cost-summary"


def test_resolve_public_request_context_endpoint_normalizes_function_base_url() -> None:
    """Request-context endpoints should append the expected path to the Functions base URL."""

    endpoint = public_simulation_verifier.resolve_public_request_context_endpoint(
        "https://func-doc-test-nwigok.azurewebsites.net/api/"
    )

    assert endpoint == (
        "https://func-doc-test-nwigok.azurewebsites.net/api/public-request-context"
    )


def test_fetch_public_cost_summary_parses_json_payload(
    monkeypatch: MonkeyPatch,
) -> None:
    """Public cost summary fetches should decode the retained JSON payload."""

    def fake_urlopen(request: Request, timeout: int = 30) -> FakeSiteResponse:
        del timeout
        assert request.full_url.endswith("/public-cost-summary")
        return FakeSiteResponse(
            200,
            "application/json; charset=utf-8",
            body=json.dumps(
                {
                    "history_row_count": 3,
                    "history_source": "Retained public cost history",
                    "month_to_date_cost": 184.5,
                }
            ),
        )

    monkeypatch.setattr(public_simulation_verifier, "urlopen", fake_urlopen)

    summary = public_simulation_verifier.fetch_public_cost_summary(
        "https://func-doc-test-nwigok.azurewebsites.net/api"
    )

    assert summary.status_code == 200
    assert summary.content_type == "application/json"
    assert summary.payload["history_row_count"] == 3
    assert summary.payload["month_to_date_cost"] == 184.5


def test_fetch_public_request_context_includes_verification_headers(
    monkeypatch: MonkeyPatch,
) -> None:
    """Request-context fetches should carry the forwarded headers used for verification."""

    captured: dict[str, str | None] = {}

    def fake_urlopen(request: Request, timeout: int = 30) -> FakeSiteResponse:
        del timeout
        captured["forwarded_for"] = request.get_header("X-forwarded-for")
        captured["user_agent"] = request.get_header("User-agent")
        return FakeSiteResponse(
            200,
            "application/json; charset=utf-8",
            body=json.dumps(
                {
                    "approximate_location": "US / Ohio",
                    "client_ip": "203.0.113.10",
                    "edge_region": "Host region: eastus2",
                    "enrichment_provider_name": None,
                    "enrichment_status": "No provider-backed network enrichment feed is configured on this host.",
                    "forwarded_host": "func-doc-test-nwigok.azurewebsites.net",
                    "forwarded_proto": "https",
                    "hosting_provider": None,
                    "network_asn": None,
                    "network_owner": None,
                    "public_network_enrichment_enabled": True,
                    "public_security_globe_enabled": True,
                    "reputation_summary": None,
                    "request_id": "req-demo-1234",
                    "request_timestamp_utc": "2026-04-20T17:16:33Z",
                    "tls_protocol": "TLSv1.3",
                    "transport_security": "HTTPS only",
                    "vpn_proxy_status": None,
                }
            ),
        )

    monkeypatch.setattr(public_simulation_verifier, "urlopen", fake_urlopen)

    response = public_simulation_verifier.fetch_public_request_context(
        "https://func-doc-test-nwigok.azurewebsites.net/api",
        headers={
            "User-Agent": "docint-public-simulation-verifier/1.0",
            "X-Forwarded-For": "203.0.113.10",
        },
    )

    assert captured == {
        "forwarded_for": "203.0.113.10",
        "user_agent": "docint-public-simulation-verifier/1.0",
    }
    assert response.status_code == 200
    assert response.payload["public_network_enrichment_enabled"] is True


def test_fetch_public_cost_history_returns_csv_text(
    monkeypatch: MonkeyPatch,
) -> None:
    """Public cost history fetches should return the retained CSV export body."""

    def fake_urlopen(request: Request, timeout: int = 30) -> FakeSiteResponse:
        del timeout
        assert request.full_url.endswith("/public-cost-history")
        return FakeSiteResponse(
            200,
            "text/csv; charset=utf-8",
            body=(
                "generated_at,currency,month_to_date_cost\n"
                "2026-04-19T17:16:33Z,USD,184.5\n"
            ),
        )

    monkeypatch.setattr(public_simulation_verifier, "urlopen", fake_urlopen)

    history = public_simulation_verifier.fetch_public_cost_history(
        "https://func-doc-test-nwigok.azurewebsites.net/api"
    )

    assert history.status_code == 200
    assert history.content_type == "text/csv"
    assert "month_to_date_cost" in history.text


def test_public_traffic_response_sent_alert_reads_route_flag() -> None:
    """One-off email verification should rely on the route's alertSent flag."""

    assert (
        public_simulation_verifier.public_traffic_response_sent_alert(
            {"alertSent": True, "status": "accepted"}
        )
        is True
    )
    assert (
        public_simulation_verifier.public_traffic_response_sent_alert(
            {"alertSent": False, "status": "accepted"}
        )
        is False
    )

def test_fetch_public_site_deep_checks_probes_each_spa_route(
    monkeypatch: MonkeyPatch,
) -> None:
    """Each SPA path (/, /security, /cost, /demo) should be probed in path form."""

    captured_urls: list[str] = []

    def fake_urlopen(request: Request, timeout: int = 30) -> FakeSiteResponse:
        del timeout
        captured_urls.append(request.full_url)
        return FakeSiteResponse(200, "text/html; charset=utf-8")

    monkeypatch.setattr(public_simulation_verifier, "urlopen", fake_urlopen)

    checks = public_simulation_verifier.fetch_public_site_deep_checks(
        "https://contoso.example.com/"
    )

    assert captured_urls == [
        "https://contoso.example.com",
        "https://contoso.example.com/security",
        "https://contoso.example.com/cost",
        "https://contoso.example.com/demo",
    ]
    assert all(check.is_reachable for check in checks)
    assert tuple(check.status_code for check in checks) == (200, 200, 200, 200)


def test_resolve_public_openapi_endpoint_appends_docs_path() -> None:
    """OpenAPI endpoint should resolve to /docs/public-openapi.json."""

    url = public_simulation_verifier.resolve_public_openapi_endpoint(
        "https://func-doc-test-nwigok.azurewebsites.net/api"
    )

    assert url == (
        "https://func-doc-test-nwigok.azurewebsites.net/api/docs/public-openapi.json"
    )


def test_fetch_public_openapi_document_returns_parsed_payload(
    monkeypatch: MonkeyPatch,
) -> None:
    """Public OpenAPI fetch should parse JSON and surface the URL it probed."""

    captured: dict[str, object] = {}

    def fake_urlopen(request: Request, timeout: int = 30) -> FakeSiteResponse:
        del timeout
        captured["url"] = request.full_url
        return FakeSiteResponse(
            200,
            "application/json",
            body='{"openapi": "3.1.0", "info": {"title": "Public"}}',
        )

    monkeypatch.setattr(public_simulation_verifier, "urlopen", fake_urlopen)

    response = public_simulation_verifier.fetch_public_openapi_document(
        "https://func-doc-test-nwigok.azurewebsites.net/api"
    )

    assert captured["url"] == (
        "https://func-doc-test-nwigok.azurewebsites.net/api/docs/public-openapi.json"
    )
    assert response.status_code == 200
    assert response.payload["openapi"] == "3.1.0"

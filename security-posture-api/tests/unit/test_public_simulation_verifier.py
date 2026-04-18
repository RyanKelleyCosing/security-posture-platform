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

    def __init__(self, status: int, content_type: str) -> None:
        self.status = status
        self.headers = EmailMessage()
        self.headers["Content-Type"] = content_type

    def __enter__(self) -> FakeSiteResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback


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
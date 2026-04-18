"""Unit tests for the extracted public Azure Functions entrypoint."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType

import azure.functions as func
from pytest import MonkeyPatch

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def load_function_app() -> ModuleType:
    """Load the standalone public Function app module."""

    sys.modules.pop("security_posture_api.public_traffic_metrics", None)
    sys.modules.pop("security_posture_api.settings", None)
    sys.modules.pop("function_app", None)

    module = importlib.import_module("function_app")

    from security_posture_api.settings import get_settings

    get_settings.cache_clear()
    return importlib.reload(module)


def test_function_app_indexes_public_routes() -> None:
    """The extracted app should expose only the public API surface."""

    module = load_function_app()
    function_names = sorted(
        function.get_function_name() for function in module.app.get_functions()
    )

    assert function_names == [
        "capture_public_traffic_event",
        "get_public_metrics_summary",
        "get_public_request_context",
        "health_check",
        "run_public_site_verifier",
    ]


def test_public_traffic_event_returns_accepted_payload(
    monkeypatch: MonkeyPatch,
) -> None:
    """Public traffic events should validate and return an accepted payload."""

    module = load_function_app()

    from security_posture_api import traffic_alerts

    captured: dict[str, str | None] = {}

    def fake_send_public_traffic_alert(alert: object, settings: object) -> bool:
        del settings
        typed_alert = traffic_alerts.PublicTrafficAlert.model_validate(alert)
        captured["client_ip"] = typed_alert.client_ip
        captured["route"] = typed_alert.event.route
        return False

    monkeypatch.setattr(
        traffic_alerts,
        "send_public_traffic_alert",
        fake_send_public_traffic_alert,
    )

    request = func.HttpRequest(
        method="POST",
        url="http://localhost/api/public-traffic-events",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "pytest-agent",
            "X-Forwarded-For": "203.0.113.77, 10.0.0.4",
        },
        params={},
        route_params={},
        body=json.dumps(
            {
                "event_type": "page_view",
                "route": "intake",
                "session_id": "session-1",
                "site_mode": "security",
            }
        ).encode("utf-8"),
    )

    response = module.capture_public_traffic_event(request)
    payload = json.loads(response.get_body().decode("utf-8"))

    assert response.status_code == 202
    assert payload == {"alertSent": False, "status": "accepted"}
    assert captured == {
        "client_ip": "203.0.113.77",
        "route": "intake",
    }


def test_public_request_context_returns_sanitized_payload() -> None:
    """The request-context route should expose only sanitized request data."""

    module = load_function_app()
    request = func.HttpRequest(
        method="GET",
        url="http://localhost/api/public-request-context",
        headers={
            "Host": "func-doc-test.azurewebsites.net",
            "X-ARR-LOG-ID": "abcdef1234567890fedcba",
            "X-Forwarded-For": "203.0.113.55, 10.0.0.4",
            "X-Forwarded-Host": "ryancodes.security.online",
            "X-Forwarded-Proto": "https",
            "X-Geo-Country": "US",
            "X-Geo-Region": "Ohio",
            "X-SSL-Protocol": "TLSv1.3",
        },
        params={},
        route_params={},
        body=b"",
    )

    response = module.get_public_request_context(request)
    payload = json.loads(response.get_body().decode("utf-8"))

    assert response.status_code == 200
    assert payload["client_ip"] == "203.0.113.55"
    assert payload["approximate_location"] == "US / Ohio"
    assert payload["forwarded_host"] == "ryancodes.security.online"
    assert payload["forwarded_proto"] == "https"
    assert payload["transport_security"] == "HTTPS only"
    assert payload["tls_protocol"] == "TLSv1.3"
    assert payload["request_id"] == "req-abcdef123456"
    assert payload["request_timestamp_utc"]


def test_public_metrics_summary_returns_aggregate_payload(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The metrics route should expose aggregate-only public telemetry."""

    monkeypatch.setenv(
        "DOCINT_PUBLIC_TELEMETRY_HISTORY_DIRECTORY",
        str(tmp_path),
    )
    module = load_function_app()

    from security_posture_api import traffic_alerts
    from security_posture_api.public_traffic_metrics import (
        build_public_health_check_record,
        persist_public_health_check_record,
    )

    monkeypatch.setattr(
        traffic_alerts,
        "send_public_traffic_alert",
        lambda alert, settings: False,
    )

    capture_request = func.HttpRequest(
        method="POST",
        url="http://localhost/api/public-traffic-events",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "pytest-agent",
            "X-Forwarded-For": "203.0.113.77, 10.0.0.4",
            "X-Geo-Country": "US",
            "X-Geo-Region": "Ohio",
        },
        params={},
        route_params={},
        body=json.dumps(
            {
                "event_type": "page_view",
                "route": "security",
                "session_id": "session-1",
                "site_mode": "security",
            }
        ).encode("utf-8"),
    )
    module.capture_public_traffic_event(capture_request)
    persist_public_health_check_record(
        build_public_health_check_record(
            {
                "alert_settings": {"email_ready": True},
                "ok": True,
                "public_site": {"is_reachable": True, "status_code": 200},
                "traffic_event": {"ok": True, "status_code": 202},
            }
        ),
        module.get_settings(),
    )

    summary_request = func.HttpRequest(
        method="GET",
        url="http://localhost/api/public-metrics-summary",
        headers={},
        params={},
        route_params={},
        body=b"",
    )

    response = module.get_public_metrics_summary(summary_request)
    payload = json.loads(response.get_body().decode("utf-8"))

    assert response.status_code == 200
    assert payload["availability_percentage"] == 100.0
    assert payload["availability_source"] == "External verification history"
    assert payload["collection_mode"] == "Durable sanitized aggregate history"
    assert payload["current_status"] == "Healthy"
    assert payload["latest_alert_configuration_ready"] is True
    assert payload["latest_monitor_name"] == "public-simulation-verifier"
    assert payload["total_events"] == 1
    assert payload["unique_sessions"] == 1
    assert payload["recent_health_checks"][0]["overall_ok"] is True
    assert payload["route_counts"] == [{"label": "security", "count": 1}]
    assert payload["site_mode_counts"] == [{"label": "security", "count": 1}]
    assert payload["geography_counts"] == [{"label": "US / Ohio", "count": 1}]
    assert payload["last_successful_health_check_at_utc"]
    assert payload["last_event_at_utc"]


def test_health_probe_event_skips_alert_email_and_traffic_counts(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Scheduled health probes should not inflate public traffic counts."""

    monkeypatch.setenv(
        "DOCINT_PUBLIC_TELEMETRY_HISTORY_DIRECTORY",
        str(tmp_path),
    )
    module = load_function_app()

    probe_request = func.HttpRequest(
        method="POST",
        url="http://localhost/api/public-traffic-events",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "pytest-probe",
        },
        params={},
        route_params={},
        body=json.dumps(
            {
                "event_type": "health_probe",
                "route": "security-monitor",
                "session_id": "probe-1",
                "site_mode": "simulation",
            }
        ).encode("utf-8"),
    )

    probe_response = module.capture_public_traffic_event(probe_request)
    probe_payload = json.loads(probe_response.get_body().decode("utf-8"))

    assert probe_response.status_code == 202
    assert probe_payload == {"alertSent": False, "status": "accepted"}

    summary_request = func.HttpRequest(
        method="GET",
        url="http://localhost/api/public-metrics-summary",
        headers={},
        params={},
        route_params={},
        body=b"",
    )

    summary_response = module.get_public_metrics_summary(summary_request)
    summary_payload = json.loads(summary_response.get_body().decode("utf-8"))

    assert summary_response.status_code == 200
    assert summary_payload["total_events"] == 0
    assert summary_payload["unique_sessions"] == 0
    assert summary_payload["route_counts"] == []
    assert summary_payload["site_mode_counts"] == []


def test_public_site_verifier_timer_runs_monitor_helper(
    monkeypatch: MonkeyPatch,
) -> None:
    """The scheduled timer should delegate to the public-site monitor helper."""

    module = load_function_app()

    from security_posture_api import public_site_monitor

    captured: dict[str, object] = {}

    def fake_run_public_site_monitor(settings: object) -> dict[str, object]:
        captured["settings"] = settings
        return {
            "ok": True,
            "public_site": {"is_reachable": True},
            "traffic_event": {"ok": True},
        }

    monkeypatch.setattr(
        public_site_monitor,
        "run_public_site_monitor",
        fake_run_public_site_monitor,
    )

    module.run_public_site_verifier(None)

    assert captured["settings"] == module.get_settings()

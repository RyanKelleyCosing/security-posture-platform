"""Unit tests for the scheduled public-site monitor."""

from __future__ import annotations

from pathlib import Path

from security_posture_api.public_site_monitor import run_public_site_monitor
from security_posture_api.public_traffic_metrics import build_public_traffic_metrics_summary
from security_posture_api.settings import AppSettings
from security_posture_api.utils.public_simulation_verifier import PublicSiteCheck


def test_run_public_site_monitor_persists_health_history(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """The scheduled monitor should persist health history without inflating traffic counts."""
    monkeypatch.setenv("WEBSITE_HOSTNAME", "func-doc-test-nwigok.azurewebsites.net")

    captured: dict[str, object] = {}
    settings = AppSettings.model_validate(
        {
            "environment_name": "test",
            "public_site_url": "https://www.ryancodes.online",
            "public_telemetry_history_directory": tmp_path,
        }
    )

    def fake_send_public_traffic_event(endpoint, payload, headers):
        captured["endpoint"] = endpoint
        captured["payload"] = payload
        captured["headers"] = headers
        return 202, {"alertSent": False, "status": "accepted"}

    results = run_public_site_monitor(
        settings,
        fetch_public_site_check=lambda url: PublicSiteCheck(
            content_type="text/html",
            is_reachable=True,
            status_code=200,
            url=url,
        ),
        monitor_name="pytest-timer-monitor",
        send_public_traffic_event_fn=fake_send_public_traffic_event,
    )
    summary = build_public_traffic_metrics_summary(settings)

    assert results["ok"] is True
    assert captured["endpoint"] == (
        "https://func-doc-test-nwigok.azurewebsites.net/api/public-traffic-events"
    )
    assert captured["payload"]["event_type"] == "health_probe"
    assert captured["payload"]["route"] == "security-monitor"
    assert summary.availability_percentage == 100.0
    assert summary.latest_monitor_name == "pytest-timer-monitor"
    assert summary.total_events == 0
    assert summary.unique_sessions == 0
    assert summary.route_counts == ()
    assert summary.recent_health_checks[0].overall_ok is True
    assert (
        summary.recent_health_checks[0].note
        == "Public site reachable · traffic route accepted"
    )
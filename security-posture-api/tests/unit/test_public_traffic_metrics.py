"""Unit tests for aggregate public traffic metrics helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from security_posture_api.public_traffic_metrics import (
    PublicTrafficMetricsStore,
    build_public_health_check_record,
    build_public_traffic_metrics_summary,
    persist_public_health_check_record,
    record_public_traffic_event_aggregate,
)
from security_posture_api.settings import AppSettings
from security_posture_api.traffic_alerts import PublicTrafficEvent


def test_public_traffic_metrics_store_tracks_aggregate_counts() -> None:
    """Aggregate metrics should count routes, sessions, site modes, and geography."""

    store = PublicTrafficMetricsStore(
        started_at_utc=datetime(2026, 4, 16, 12, 0, tzinfo=UTC)
    )

    store.record_event(
        PublicTrafficEvent(
            event_type="page_view",
            route="security",
            session_id="session-1",
            site_mode="security",
        ),
        {
            "X-Geo-Country": "US",
            "X-Geo-Region": "Ohio",
        },
    )
    store.record_event(
        PublicTrafficEvent(
            event_type="simulation_started",
            route="simulation",
            session_id="session-2",
            site_mode="simulation",
        ),
        {"X-Geo-Country": "CA"},
    )
    store.record_event(
        PublicTrafficEvent(
            event_type="page_view",
            route="security",
            session_id="session-1",
            site_mode="security",
        ),
        {
            "X-Geo-Country": "US",
            "X-Geo-Region": "Ohio",
        },
    )

    summary = store.build_summary("test")

    assert summary.collection_mode == "Process-local aggregate only"
    assert summary.current_status == "Healthy"
    assert summary.environment_name == "test"
    assert summary.total_events == 3
    assert summary.unique_sessions == 2
    assert summary.route_counts[0].label == "security"
    assert summary.route_counts[0].count == 2
    assert summary.site_mode_counts[0].label == "security"
    assert summary.site_mode_counts[0].count == 2
    assert summary.geography_counts[0].label == "US / Ohio"
    assert summary.geography_counts[0].count == 2
    assert summary.last_event_at_utc is not None
    assert summary.current_uptime_seconds >= 0


def test_public_traffic_metrics_store_returns_empty_counts_before_events() -> None:
    """The aggregate summary should stay explicit when no events exist yet."""

    store = PublicTrafficMetricsStore(
        started_at_utc=datetime(2026, 4, 16, 12, 0, tzinfo=UTC)
    )

    summary = store.build_summary("   ")

    assert summary.environment_name == "unknown"
    assert summary.total_events == 0
    assert summary.unique_sessions == 0
    assert summary.route_counts == ()
    assert summary.site_mode_counts == ()
    assert summary.geography_counts == ()
    assert summary.last_event_at_utc is None


def test_build_public_traffic_metrics_summary_reads_local_durable_history(
    tmp_path: Path,
) -> None:
    """Durable local history should back the aggregate summary across cold starts."""

    settings = AppSettings.model_validate(
        {
            "environment_name": "test",
            "public_telemetry_history_directory": tmp_path,
        }
    )

    record_public_traffic_event_aggregate(
        PublicTrafficEvent(
            event_type="page_view",
            route="security",
            session_id="session-1",
            site_mode="security",
        ),
        {
            "X-Geo-Country": "US",
            "X-Geo-Region": "Ohio",
        },
        settings,
    )
    record_public_traffic_event_aggregate(
        PublicTrafficEvent(
            event_type="simulation_started",
            route="simulation",
            session_id="session-2",
            site_mode="simulation",
        ),
        {"X-Geo-Country": "CA"},
        settings,
    )
    persist_public_health_check_record(
        build_public_health_check_record(
            {
                "alert_settings": {"email_ready": True},
                "ok": True,
                "public_site": {"is_reachable": True, "status_code": 200},
                "traffic_event": {"ok": True, "status_code": 202},
            }
        ),
        settings,
    )

    summary = build_public_traffic_metrics_summary(settings)

    assert summary.collection_mode == "Durable sanitized aggregate history"
    assert summary.collection_window.startswith("Rolling 60d durable aggregate history")
    assert summary.availability_percentage == 100.0
    assert summary.availability_source == "External verification history"
    assert summary.current_status == "Healthy"
    assert summary.latest_alert_configuration_ready is True
    assert summary.latest_monitor_name == "public-simulation-verifier"
    assert summary.total_events == 2
    assert summary.unique_sessions == 2
    assert summary.route_counts[0].count == 1
    assert summary.recent_health_checks[0].overall_ok is True
    assert summary.last_successful_health_check_at_utc is not None
    assert (
        tmp_path / "public-security" / "traffic-events"
    ).exists()
    assert (
        tmp_path / "public-security" / "health-checks"
    ).exists()


def test_build_public_health_check_record_extracts_verifier_results() -> None:
    """Verifier output should become one sanitized durable health-check row."""

    record = build_public_health_check_record(
        {
            "alert_settings": {"email_ready": False},
            "ok": False,
            "public_site": {"is_reachable": False, "status_code": 503},
            "traffic_event": {"ok": False, "status_code": 500},
        },
        monitor_name="pytest-monitor",
    )

    assert record.monitor_name == "pytest-monitor"
    assert record.overall_ok is False
    assert record.public_site_ok is False
    assert record.public_site_status_code == 503
    assert record.traffic_event_ok is False
    assert record.traffic_event_status_code == 500
    assert record.alert_ready is False


def test_record_public_traffic_event_aggregate_ignores_health_probes(
    tmp_path: Path,
) -> None:
    """Scheduled health probes should not inflate durable public traffic counts."""

    settings = AppSettings.model_validate(
        {
            "environment_name": "test",
            "public_telemetry_history_directory": tmp_path,
        }
    )

    record_public_traffic_event_aggregate(
        PublicTrafficEvent(
            event_type="health_probe",
            route="security-monitor",
            session_id="probe-1",
            site_mode="simulation",
        ),
        {},
        settings,
    )
    persist_public_health_check_record(
        build_public_health_check_record(
            {
                "alert_settings": {"email_ready": True},
                "ok": True,
                "public_site": {"is_reachable": True, "status_code": 200},
                "traffic_event": {"ok": True, "status_code": 202},
            }
        ),
        settings,
    )

    summary = build_public_traffic_metrics_summary(settings)

    assert summary.total_events == 0
    assert summary.unique_sessions == 0
    assert summary.route_counts == ()
    assert not (tmp_path / "public-security" / "traffic-events").exists()
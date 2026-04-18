"""Scheduled public-site monitoring helpers for the security posture page."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict
from datetime import UTC, datetime
import logging
import os
import secrets

from security_posture_api.public_traffic_metrics import (
    build_public_health_check_record,
    persist_public_health_check_record,
)
from security_posture_api.settings import AppSettings
from security_posture_api.traffic_alerts import public_traffic_alerts_configured
from security_posture_api.utils.public_simulation_verifier import (
    fetch_public_site_check as fetch_public_site_check_impl,
    summarize_public_alert_settings,
)
from security_posture_api.utils.public_traffic_client import (
    build_public_traffic_headers,
    build_public_traffic_payload,
    send_public_traffic_event,
)

_DEFAULT_MONITOR_NAME = "azure-functions-public-site-monitor"
_DEFAULT_MONITOR_ROUTE = "security-monitor"
_DEFAULT_MONITOR_USER_AGENT = "docint-public-site-monitor/1.0"


def _normalize_public_site_url(settings: AppSettings) -> str | None:
    public_site_url = settings.public_site_url
    if public_site_url is None:
        return None

    normalized_public_site_url = public_site_url.strip()
    return normalized_public_site_url or None


def _normalize_function_base_url(settings: AppSettings) -> str | None:
    configured_base_url = settings.function_api_base_url
    if configured_base_url and configured_base_url.strip():
        normalized_base_url = configured_base_url.strip().rstrip("/")
        if normalized_base_url.endswith("/api"):
            return normalized_base_url
        return f"{normalized_base_url}/api"

    website_hostname = os.getenv("WEBSITE_HOSTNAME", "").strip()
    if website_hostname:
        return f"https://{website_hostname}/api"

    return None


def _build_public_alert_settings_payload(settings: AppSettings) -> Mapping[str, str]:
    return {
        "DOCINT_PUBLIC_TRAFFIC_ALERTS_ENABLED": (
            "true" if settings.public_traffic_alerts_enabled else "false"
        ),
        "DOCINT_PUBLIC_ALERT_RECIPIENT_EMAIL": settings.public_alert_recipient_email
        or "",
        "DOCINT_SMTP_HOST": settings.smtp_host or "",
        "DOCINT_SMTP_SENDER_EMAIL": settings.smtp_sender_email or "",
    }


def _build_health_probe_session_id() -> str:
    current_timestamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    return f"health-probe-{current_timestamp}-{secrets.token_hex(4)}"


def run_public_site_monitor(
    settings: AppSettings,
    *,
    fetch_public_site_check: Callable[[str], object] = fetch_public_site_check_impl,
    monitor_name: str = _DEFAULT_MONITOR_NAME,
    send_public_traffic_event_fn: Callable[
        [str, Mapping[str, str], Mapping[str, str]], tuple[int, dict[str, object]]
    ] = send_public_traffic_event,
) -> dict[str, object]:
    """Run the public-site health probe and persist a public-safe health record."""

    results: dict[str, object] = {"ok": True}
    normalized_public_site_url = _normalize_public_site_url(settings)
    normalized_function_base_url = _normalize_function_base_url(settings)

    if normalized_public_site_url:
        try:
            site_check = fetch_public_site_check(normalized_public_site_url)
            results["public_site"] = asdict(site_check)
            results["ok"] = bool(results["ok"]) and bool(site_check.is_reachable)
        except Exception as error:
            logging.exception("Public site availability check failed.")
            results["public_site"] = {
                "error": str(error),
                "is_reachable": False,
                "url": normalized_public_site_url,
            }
            results["ok"] = False
    else:
        logging.warning(
            "DOCINT_PUBLIC_SITE_URL is not configured; skipping external site probe."
        )

    if normalized_function_base_url:
        endpoint = f"{normalized_function_base_url.rstrip('/')}/public-traffic-events"
        payload = build_public_traffic_payload(
            "health_probe",
            _DEFAULT_MONITOR_ROUTE,
            _build_health_probe_session_id(),
            page_title="Security posture availability monitor",
        )
        headers = build_public_traffic_headers(_DEFAULT_MONITOR_USER_AGENT)
        try:
            status_code, response_payload = send_public_traffic_event_fn(
                endpoint,
                payload,
                headers,
            )
            traffic_ok = status_code == 202 and response_payload.get("status") == "accepted"
            results["traffic_event"] = {
                "endpoint": endpoint,
                "headers": headers,
                "payload": payload,
                "response": response_payload,
                "status_code": status_code,
                "ok": traffic_ok,
            }
            results["ok"] = bool(results["ok"]) and traffic_ok
        except Exception as error:
            logging.exception("Public traffic route health probe failed.")
            results["traffic_event"] = {
                "endpoint": endpoint,
                "error": str(error),
                "ok": False,
            }
            results["ok"] = False
    else:
        logging.error(
            "Function App base URL could not be resolved for the health probe."
        )
        results["traffic_event"] = {
            "endpoint": "",
            "error": "Function App base URL is not configured.",
            "ok": False,
        }
        results["ok"] = False

    alert_settings_summary = summarize_public_alert_settings(
        _build_public_alert_settings_payload(settings)
    )
    results["alert_settings"] = asdict(alert_settings_summary)
    results["email_alert"] = {
        "ready": public_traffic_alerts_configured(settings),
        "required": False,
        "sent": False,
    }

    health_check_record = build_public_health_check_record(
        results,
        monitor_name=monitor_name,
    )
    persist_public_health_check_record(health_check_record, settings)
    return results
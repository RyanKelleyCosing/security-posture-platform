"""Azure Functions entrypoints for the extracted public security API."""

from __future__ import annotations

import json
import logging
import sys
from http import HTTPStatus
from pathlib import Path
from typing import Any

APP_ROOT = Path(__file__).resolve().parent
SRC_PATH = APP_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

import azure.functions as func
from pydantic import ValidationError

from security_posture_api.settings import get_settings

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)


def _json_response(
    payload: dict[str, Any],
    status_code: HTTPStatus,
) -> func.HttpResponse:
    return func.HttpResponse(
        body=json.dumps(payload, indent=2, default=str),
        mimetype="application/json",
        status_code=int(status_code),
    )


def _validation_error_response(
    error: ValidationError | ValueError,
) -> func.HttpResponse:
    details: Any
    if isinstance(error, ValidationError):
        details = error.errors(include_url=False)
    else:
        details = str(error)

    return _json_response(
        {"status": "invalid_request", "details": details},
        HTTPStatus.BAD_REQUEST,
    )


@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    del req
    settings = get_settings()

    return _json_response(
        {
            "status": "healthy",
            "service": "security-posture-api",
            "environment": settings.environment_name,
            "publicHealthDigestWindowDays": (
                settings.public_health_digest_window_days
            ),
            "publicTelemetryRetentionDays": (
                settings.public_telemetry_retention_days
            ),
        },
        HTTPStatus.OK,
    )


@app.route(
    route="public-traffic-events",
    methods=["POST"],
    auth_level=func.AuthLevel.ANONYMOUS,
)
def capture_public_traffic_event(req: func.HttpRequest) -> func.HttpResponse:
    from security_posture_api.public_traffic_metrics import (
        record_public_traffic_event_aggregate,
    )
    from security_posture_api.traffic_alerts import (
        PublicTrafficEvent,
        build_public_traffic_alert,
        mask_client_ip,
        send_public_traffic_alert,
    )

    try:
        event = PublicTrafficEvent.model_validate(req.get_json())
    except (ValidationError, ValueError) as error:
        return _validation_error_response(error)

    settings = get_settings()
    alert = build_public_traffic_alert(event, req.headers)
    record_public_traffic_event_aggregate(event, req.headers, settings)
    alert_sent = send_public_traffic_alert(alert, settings)

    logging.info(
        "Captured public traffic event route=%s event=%s site=%s session=%s ip=%s",
        alert.event.route,
        alert.event.event_type,
        alert.event.site_mode,
        alert.event.session_id,
        mask_client_ip(alert.client_ip) or "unknown",
    )

    return _json_response(
        {"alertSent": alert_sent, "status": "accepted"},
        HTTPStatus.ACCEPTED,
    )


@app.route(
    route="public-metrics-summary",
    methods=["GET"],
    auth_level=func.AuthLevel.ANONYMOUS,
)
def get_public_metrics_summary(req: func.HttpRequest) -> func.HttpResponse:
    del req

    from security_posture_api.public_traffic_metrics import (
        build_public_traffic_metrics_summary,
    )

    summary = build_public_traffic_metrics_summary(get_settings())
    logging.info(
        "Built public metrics summary total_events=%s sessions=%s last_event=%s",
        summary.total_events,
        summary.unique_sessions,
        summary.last_event_at_utc or "none",
    )

    return _json_response(summary.model_dump(mode="json"), HTTPStatus.OK)


@app.timer_trigger(
    arg_name="monitor_timer",
    schedule="0 */30 * * * *",
    use_monitor=True,
)
def run_public_site_verifier(monitor_timer: func.TimerRequest) -> None:
    del monitor_timer

    from security_posture_api.public_site_monitor import run_public_site_monitor

    results = run_public_site_monitor(get_settings())
    logging.info(
        "Scheduled public site verifier finished ok=%s public=%s traffic=%s",
        results.get("ok"),
        results.get("public_site"),
        results.get("traffic_event"),
    )


@app.route(
    route="public-request-context",
    methods=["GET"],
    auth_level=func.AuthLevel.ANONYMOUS,
)
def get_public_request_context(req: func.HttpRequest) -> func.HttpResponse:
    from security_posture_api.public_request_context import (
        build_public_request_context,
    )

    request_context = build_public_request_context(req.headers, req.url)
    logging.info(
        "Built public request context request_id=%s secure=%s ip_present=%s",
        request_context.request_id,
        request_context.transport_security,
        request_context.client_ip is not None,
    )

    return _json_response(request_context.model_dump(mode="json"), HTTPStatus.OK)

"""Client helpers for verifying public traffic event ingestion."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal
from urllib.request import Request, urlopen

DEFAULT_LOCAL_FUNCTION_BASE_URL = "http://localhost:7071/api"
PUBLIC_TRAFFIC_EVENT_TYPES = ("health_probe", "page_view", "simulation_started")


def _read_local_settings_payload(local_settings_file: Path) -> dict[str, Any]:
    if not local_settings_file.exists():
        return {}

    payload = json.loads(local_settings_file.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return {}

    return payload


def resolve_public_traffic_endpoint(
    function_base_url: str,
    local_settings_file: Path,
) -> str:
    """Resolve the public traffic event endpoint for local or deployed use."""
    normalized_base_url = function_base_url.strip()
    if normalized_base_url.endswith("/public-traffic-events"):
        return normalized_base_url

    if not normalized_base_url:
        host_payload = _read_local_settings_payload(local_settings_file).get("Host")
        if isinstance(host_payload, dict):
            local_http_port = host_payload.get("LocalHttpPort")
            if local_http_port is not None and str(local_http_port).strip():
                normalized_base_url = (
                    f"http://localhost:{str(local_http_port).strip()}/api"
                )

    if not normalized_base_url:
        normalized_base_url = DEFAULT_LOCAL_FUNCTION_BASE_URL

    return f"{normalized_base_url.rstrip('/')}/public-traffic-events"


def build_public_traffic_payload(
    event_type: Literal["health_probe", "page_view", "simulation_started"],
    route: str,
    session_id: str,
    *,
    page_title: str | None = None,
    referrer: str | None = None,
) -> dict[str, str]:
    """Build the request payload for the anonymous public traffic route."""
    normalized_route = route.strip()
    normalized_session_id = session_id.strip()
    if not normalized_route:
        raise ValueError("route is required")
    if not normalized_session_id:
        raise ValueError("session_id is required")

    payload: dict[str, str] = {
        "event_type": event_type,
        "route": normalized_route,
        "session_id": normalized_session_id,
        "site_mode": "simulation",
    }

    if page_title is not None and page_title.strip():
        payload["page_title"] = page_title.strip()
    if referrer is not None and referrer.strip():
        payload["referrer"] = referrer.strip()

    return payload


def build_public_traffic_headers(
    user_agent: str,
    *,
    forwarded_for: str | None = None,
) -> dict[str, str]:
    """Build HTTP headers for a synthetic public traffic event request."""
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": user_agent.strip(),
    }
    if forwarded_for is not None and forwarded_for.strip():
        headers["X-Forwarded-For"] = forwarded_for.strip()

    return headers


def send_public_traffic_event(
    endpoint: str,
    payload: Mapping[str, str],
    headers: Mapping[str, str],
) -> tuple[int, dict[str, Any]]:
    """POST a public traffic event and return the HTTP status and JSON body."""
    request = Request(
        endpoint,
        data=json.dumps(dict(payload)).encode("utf-8"),
        headers=dict(headers),
        method="POST",
    )
    with urlopen(request, timeout=30) as response:
        response_payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(response_payload, dict):
            raise ValueError(
                "Public traffic event response must be a JSON object."
            )

        normalized_payload = {
            str(key): value for key, value in response_payload.items()
        }
        return response.status, normalized_payload
"""Unit tests for public traffic verification helpers."""

from __future__ import annotations

import json
from pathlib import Path
from types import TracebackType
from urllib.request import Request

from pytest import MonkeyPatch

from security_posture_api.utils import public_traffic_client


class FakeResponse:
    """Minimal HTTP response stub for request helper tests."""

    def __init__(self, status: int, payload: dict[str, object]) -> None:
        self.status = status
        self._payload = payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback

    def read(self) -> bytes:
        """Return the JSON payload as bytes."""
        return json.dumps(self._payload).encode("utf-8")


def test_resolve_public_traffic_endpoint_uses_local_settings_port(
    tmp_path: Path,
) -> None:
    """The helper should respect the local Functions HTTP port override."""
    local_settings_file = tmp_path / "local.settings.json"
    local_settings_file.write_text(
        json.dumps({"Host": {"LocalHttpPort": 7088}}),
        encoding="utf-8",
    )

    endpoint = public_traffic_client.resolve_public_traffic_endpoint(
        "",
        local_settings_file,
    )

    assert endpoint == "http://localhost:7088/api/public-traffic-events"


def test_build_public_traffic_payload_omits_blank_optional_fields() -> None:
    """Blank optional values should not be emitted in the request payload."""
    payload = public_traffic_client.build_public_traffic_payload(
        "simulation_started",
        "processing",
        "session-123",
        page_title="  ",
        referrer=" https://contoso.example/hr ",
    )

    assert payload == {
        "event_type": "simulation_started",
        "route": "processing",
        "referrer": "https://contoso.example/hr",
        "session_id": "session-123",
        "site_mode": "simulation",
    }


def test_build_public_traffic_payload_supports_health_probes() -> None:
    """The helper should allow the probe event used by scheduled verification."""

    payload = public_traffic_client.build_public_traffic_payload(
        "health_probe",
        "security-monitor",
        "probe-session",
    )

    assert payload == {
        "event_type": "health_probe",
        "route": "security-monitor",
        "session_id": "probe-session",
        "site_mode": "simulation",
    }


def test_send_public_traffic_event_posts_json_payload(
    monkeypatch: MonkeyPatch,
) -> None:
    """The request helper should POST JSON and parse the JSON response."""
    captured: dict[str, object] = {}

    def fake_urlopen(request: Request, timeout: int = 30) -> FakeResponse:
        del timeout
        request_body = request.data
        captured["body"] = (
            request_body.decode("utf-8") if isinstance(request_body, bytes) else ""
        )
        captured["headers"] = {
            key.lower(): value for key, value in request.header_items()
        }
        captured["url"] = request.full_url
        return FakeResponse(202, {"alertSent": False, "status": "accepted"})

    monkeypatch.setattr(public_traffic_client, "urlopen", fake_urlopen)

    status_code, response_payload = public_traffic_client.send_public_traffic_event(
        "http://localhost:7071/api/public-traffic-events",
        public_traffic_client.build_public_traffic_payload(
            "page_view",
            "landing",
            "session-abc",
        ),
        public_traffic_client.build_public_traffic_headers(
            "pytest-agent",
            forwarded_for="203.0.113.5",
        ),
    )

    assert status_code == 202
    assert response_payload == {"alertSent": False, "status": "accepted"}
    assert captured["url"] == "http://localhost:7071/api/public-traffic-events"
    assert json.loads(str(captured["body"])) == {
        "event_type": "page_view",
        "route": "landing",
        "session_id": "session-abc",
        "site_mode": "simulation",
    }
    assert captured["headers"] == {
        "accept": "application/json",
        "content-type": "application/json",
        "user-agent": "pytest-agent",
        "x-forwarded-for": "203.0.113.5",
    }
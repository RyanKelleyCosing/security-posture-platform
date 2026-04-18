"""Public-safe request-context helpers for the security posture site."""

from __future__ import annotations

import os
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from security_posture_api.traffic_alerts import extract_client_ip

_COARSE_LOCATION_UNAVAILABLE = (
    "Unavailable until coarse edge geolocation headers are configured."
)
_EDGE_REGION_UNAVAILABLE = "Unavailable until edge or proxy region headers exist."
_REQUEST_HOST_UNAVAILABLE = "Not exposed by the current public edge path."
_HOST_REGION_ENV_VARS = ("REGION_NAME", "WEBSITE_REGION", "WEBSITE_REGION_NAME")


class PublicRequestContext(BaseModel):
    """Sanitized request metadata returned to the public transparency panel."""

    model_config = ConfigDict(str_strip_whitespace=True)

    approximate_location: str = Field(min_length=1, max_length=160)
    client_ip: str | None = None
    edge_region: str = Field(min_length=1, max_length=160)
    forwarded_host: str = Field(min_length=1, max_length=160)
    forwarded_proto: str = Field(min_length=1, max_length=16)
    request_id: str = Field(min_length=1, max_length=32)
    request_timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tls_protocol: str = Field(min_length=1, max_length=40)
    transport_security: str = Field(min_length=1, max_length=32)


def _get_header_value(headers: Mapping[str, str], *names: str) -> str | None:
    for name in names:
        for header_name, header_value in headers.items():
            if header_name.lower() == name.lower() and header_value.strip():
                return header_value.strip()

    return None


def _build_approximate_location(headers: Mapping[str, str]) -> str:
    country = _get_header_value(
        headers,
        "CF-IPCountry",
        "X-AppEngine-Country",
        "X-Country-Code",
        "X-Geo-Country",
    )
    region = _get_header_value(
        headers,
        "X-AppEngine-Region",
        "X-Geo-Region",
    )
    location_parts = tuple(
        value
        for value in (country, region)
        if value and value.upper() not in {"T1", "XX", "UNKNOWN"}
    )
    if location_parts:
        return " / ".join(dict.fromkeys(location_parts))

    return _COARSE_LOCATION_UNAVAILABLE


def _build_edge_region(headers: Mapping[str, str]) -> str:
    edge_region = _get_header_value(
        headers,
        "X-Azure-Edge-Region",
        "X-Edge-Region",
        "X-AppEngine-Region",
    )
    if edge_region:
        return edge_region

    for env_name in _HOST_REGION_ENV_VARS:
        host_region = os.getenv(env_name, "").strip()
        if host_region:
            return f"Host region: {host_region}"

    return _EDGE_REGION_UNAVAILABLE


def _build_forwarded_host(headers: Mapping[str, str]) -> str:
    return (
        _get_header_value(headers, "X-Forwarded-Host", "Host")
        or _REQUEST_HOST_UNAVAILABLE
    )


def _build_forwarded_proto(headers: Mapping[str, str], request_url: str) -> str:
    forwarded_proto = _get_header_value(
        headers,
        "X-Forwarded-Proto",
        "X-AppService-Proto",
    )
    if forwarded_proto:
        return forwarded_proto.lower()

    return "https" if request_url.lower().startswith("https://") else "http"


def _build_transport_security(
    headers: Mapping[str, str],
    forwarded_proto: str,
) -> str:
    if forwarded_proto == "https" or _get_header_value(headers, "X-ARR-SSL"):
        return "HTTPS only"

    return "HTTP or local development path"


def _build_tls_protocol(headers: Mapping[str, str], forwarded_proto: str) -> str:
    tls_protocol = _get_header_value(
        headers,
        "X-Forwarded-TlsVersion",
        "X-SSL-Protocol",
        "X-Tls-Version",
    )
    if tls_protocol:
        return tls_protocol

    return "HTTPS" if forwarded_proto == "https" else "HTTP"


def _build_request_id(headers: Mapping[str, str]) -> str:
    traceparent = _get_header_value(headers, "traceparent")
    if traceparent:
        trace_parts = traceparent.split("-")
        if len(trace_parts) >= 2 and trace_parts[1]:
            return f"req-{trace_parts[1][:12].lower()}"

    for header_name in ("X-ARR-LOG-ID", "X-Request-Id", "X-Correlation-Id"):
        header_value = _get_header_value(headers, header_name)
        if header_value:
            normalized_value = "".join(
                character for character in header_value.lower() if character.isalnum()
            )
            if normalized_value:
                return f"req-{normalized_value[:12]}"

    return f"req-{secrets.token_hex(6)}"


def build_public_request_context(
    headers: Mapping[str, str],
    request_url: str,
) -> PublicRequestContext:
    """Build the sanitized request context returned to the public site."""

    forwarded_proto = _build_forwarded_proto(headers, request_url)
    return PublicRequestContext(
        approximate_location=_build_approximate_location(headers),
        client_ip=extract_client_ip(headers),
        edge_region=_build_edge_region(headers),
        forwarded_host=_build_forwarded_host(headers),
        forwarded_proto=forwarded_proto,
        request_id=_build_request_id(headers),
        tls_protocol=_build_tls_protocol(headers, forwarded_proto),
        transport_security=_build_transport_security(headers, forwarded_proto),
    )
"""Durable sanitized aggregate public telemetry helpers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
import hashlib
import json
import logging
import os
from pathlib import Path
from threading import Lock
from typing import Any, TypeVar

from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.storage.blob import BlobClient, BlobServiceClient
from pydantic import BaseModel, ConfigDict, Field

from security_posture_api.settings import AppSettings
from security_posture_api.traffic_alerts import PublicTrafficEvent

_DURABLE_COLLECTION_MODE = "Durable sanitized aggregate history"
_PROCESS_LOCAL_COLLECTION_MODE = "Process-local aggregate only"
_DURABLE_COLLECTION_WINDOW_TEMPLATE = (
    "Rolling {retention_days}d durable aggregate history with hashed session "
    "dedupe and sanitized geography buckets."
)
_PROCESS_LOCAL_COLLECTION_WINDOW = (
    "Counts reflect the current worker lifetime. Durable sanitized history "
    "takes over once the configured storage container has at least one event."
)
_EXTERNAL_AVAILABILITY_SOURCE = "External verification history"
_PROCESS_LOCAL_AVAILABILITY_SOURCE = "Process-local fallback"
_MONITORED_AVAILABILITY_WINDOW_TEMPLATE = "Last {window_days}d monitored checks"
_PROCESS_LOCAL_TRAFFIC_CADENCE_WINDOW = (
    "Current worker hourly buckets ending at the latest observed public event. "
    "Buckets reset on cold start until durable sanitized history is added."
)
_DURABLE_TRAFFIC_CADENCE_WINDOW = (
    "Last 12 hourly buckets ending at the latest retained public event."
)
_SHORT_LIVED_RECENT_ACTIVITY_WINDOW = (
    "Short-lived in-memory recent-session feed only. It resets on cold start and is not written to durable history."
)
_DURABLE_RECENT_ACTIVITY_WINDOW_TEMPLATE = (
    "Most recent {max_items} sanitized public events from the rolling durable "
    "history. Session labels are derived from the hashed session identifier."
)
_UNSPECIFIED_GEOGRAPHY = "Unspecified edge geography"
_HEALTHY_STATUS = "Healthy"
_DEGRADED_STATUS = "Degraded"
_AWAITING_MONITORED_HISTORY_STATUS = "Awaiting monitored history"
_PUBLIC_SECURITY_PREFIX = "public-security"
_RECENT_ACTIVITY_MAX_ITEMS = 6
_TRAFFIC_CADENCE_WINDOW_HOURS = 12
_DEFAULT_PUBLIC_TELEMETRY_HISTORY_DIRECTORY = Path("outputs") / "public-site-telemetry"


class PublicMetricCount(BaseModel):
    """One aggregate label and count pair returned by the public metrics API."""

    model_config = ConfigDict(str_strip_whitespace=True)

    label: str = Field(min_length=1, max_length=160)
    count: int = Field(ge=0)


class PublicHealthCheckDigestItem(BaseModel):
    """One recent monitored health-check entry for the public site."""

    model_config = ConfigDict(str_strip_whitespace=True)

    checked_at_utc: datetime
    note: str = Field(min_length=1, max_length=240)
    overall_ok: bool


class PublicRecentActivityItem(BaseModel):
    """One short-lived recent visitor activity entry for the public dashboard."""

    model_config = ConfigDict(str_strip_whitespace=True)

    geography_bucket: str = Field(min_length=1, max_length=160)
    recorded_at_utc: datetime
    route: str = Field(min_length=1, max_length=120)
    session_label: str = Field(min_length=1, max_length=24)
    site_mode: str = Field(min_length=1, max_length=32)


class PublicTrafficCadencePoint(BaseModel):
    """One hourly public traffic cadence bucket for the security dashboard."""

    model_config = ConfigDict(str_strip_whitespace=True)

    bucket_started_at_utc: datetime
    count: int = Field(ge=0)
    label: str = Field(min_length=1, max_length=40)


class PublicTrafficMetricsSummary(BaseModel):
    """Sanitized aggregate public metrics for the security posture site."""

    model_config = ConfigDict(str_strip_whitespace=True)

    availability_percentage: float | None = Field(default=None, ge=0.0, le=100.0)
    availability_source: str = Field(min_length=1, max_length=120)
    availability_window: str = Field(min_length=1, max_length=160)
    collection_mode: str = Field(min_length=1, max_length=80)
    collection_window: str = Field(min_length=1, max_length=240)
    current_status: str = Field(min_length=1, max_length=48)
    current_uptime_seconds: int | None = Field(default=None, ge=0)
    environment_name: str = Field(min_length=1, max_length=64)
    generated_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    geography_counts: tuple[PublicMetricCount, ...] = ()
    last_event_at_utc: datetime | None = None
    latest_alert_configuration_ready: bool | None = None
    latest_monitor_name: str | None = None
    last_successful_health_check_at_utc: datetime | None = None
    process_started_at_utc: datetime | None = None
    recent_activity: tuple[PublicRecentActivityItem, ...] = ()
    recent_activity_window: str = Field(min_length=1, max_length=200)
    recent_health_checks: tuple[PublicHealthCheckDigestItem, ...] = ()
    route_counts: tuple[PublicMetricCount, ...] = ()
    site_mode_counts: tuple[PublicMetricCount, ...] = ()
    suppressed_alert_count: int = Field(default=0, ge=0)
    suppressed_alert_window: str = Field(
        default="Counts sanitized alert suppressions persisted across the retention window.",
        min_length=1,
        max_length=200,
    )
    total_events: int = Field(ge=0)
    traffic_cadence: tuple[PublicTrafficCadencePoint, ...] = ()
    traffic_cadence_window: str = Field(min_length=1, max_length=160)
    unique_sessions: int = Field(ge=0)


class PublicTrafficHistoryRecord(BaseModel):
    """One sanitized public traffic event row written to durable history."""

    model_config = ConfigDict(str_strip_whitespace=True)

    event_type: str = Field(min_length=1, max_length=40)
    geography_bucket: str = Field(min_length=1, max_length=160)
    recorded_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    route: str = Field(min_length=1, max_length=120)
    session_hash: str = Field(min_length=64, max_length=64)
    site_mode: str = Field(min_length=1, max_length=32)


class PublicSuppressedAlertHistoryRecord(BaseModel):
    """One sanitized suppressed-alert row written to durable history.

    Persists only the public-safe shape of an alert that the SMTP suppression
    filters short-circuited, so the cadence card can show the count without
    leaking the visitor IP, raw user-agent, or any session identifier.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    event_type: str = Field(min_length=1, max_length=40)
    recorded_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    route: str = Field(min_length=1, max_length=120)
    site_mode: str = Field(min_length=1, max_length=32)
    suppression_reason: str = Field(min_length=1, max_length=64)


class PublicHealthCheckRecord(BaseModel):
    """One sanitized monitored health-check row written to durable history."""

    model_config = ConfigDict(str_strip_whitespace=True)

    alert_ready: bool | None = None
    checked_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    monitor_name: str = Field(
        default="public-simulation-verifier",
        min_length=1,
        max_length=80,
    )
    overall_ok: bool
    public_site_ok: bool | None = None
    public_site_status_code: int | None = Field(default=None, ge=100, le=599)
    traffic_event_ok: bool
    traffic_event_status_code: int | None = Field(default=None, ge=100, le=599)


@dataclass(frozen=True)
class _TrafficAggregate:
    geography_counts: tuple[PublicMetricCount, ...]
    last_event_at_utc: datetime | None
    route_counts: tuple[PublicMetricCount, ...]
    site_mode_counts: tuple[PublicMetricCount, ...]
    total_events: int
    traffic_cadence: tuple[PublicTrafficCadencePoint, ...]
    unique_sessions: int


@dataclass(frozen=True)
class _HealthAggregate:
    availability_percentage: float | None
    current_status: str
    latest_alert_configuration_ready: bool | None
    latest_monitor_name: str | None
    last_successful_health_check_at_utc: datetime | None
    recent_health_checks: tuple[PublicHealthCheckDigestItem, ...]


@dataclass(frozen=True)
class _LiveTelemetryDetail:
    recent_activity: tuple[PublicRecentActivityItem, ...]
    recent_activity_window: str


_ModelType = TypeVar("_ModelType", bound=BaseModel)


def _get_header_value(headers: Mapping[str, str], *names: str) -> str | None:
    for name in names:
        for header_name, header_value in headers.items():
            if header_name.lower() == name.lower() and header_value.strip():
                return header_value.strip()

    return None


def _build_geography_bucket(headers: Mapping[str, str]) -> str:
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

    return _UNSPECIFIED_GEOGRAPHY


def _build_metric_counts(
    counter: Counter[str],
    *,
    max_items: int = 3,
) -> tuple[PublicMetricCount, ...]:
    if not counter:
        return ()

    sorted_counts = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    return tuple(
        PublicMetricCount(label=label, count=count)
        for label, count in sorted_counts[:max_items]
    )


def _normalize_hour_bucket(timestamp: datetime) -> datetime:
    normalized_timestamp = timestamp.astimezone(UTC)
    return normalized_timestamp.replace(minute=0, second=0, microsecond=0)


def _format_hour_bucket_label(hour_bucket: datetime) -> str:
    return hour_bucket.strftime("%b %d %H:%M UTC")


def _build_traffic_cadence_points(
    hourly_counts: Mapping[datetime, int],
) -> tuple[PublicTrafficCadencePoint, ...]:
    if not hourly_counts:
        return ()

    latest_bucket = max(hourly_counts)
    cadence_buckets = tuple(
        latest_bucket - timedelta(hours=offset)
        for offset in reversed(range(_TRAFFIC_CADENCE_WINDOW_HOURS))
    )
    return tuple(
        PublicTrafficCadencePoint(
            bucket_started_at_utc=hour_bucket,
            count=hourly_counts.get(hour_bucket, 0),
            label=_format_hour_bucket_label(hour_bucket),
        )
        for hour_bucket in cadence_buckets
    )


def _hash_session_id(session_id: str) -> str:
    return hashlib.sha256(session_id.strip().encode("utf-8")).hexdigest()


def _build_session_label(session_id: str) -> str:
    return f"session-{_hash_session_id(session_id)[:8]}"


def _normalize_environment_name(environment_name: str) -> str:
    normalized_environment_name = environment_name.strip()
    return normalized_environment_name or "unknown"


def _resolve_storage_connection_string(settings: AppSettings) -> str | None:
    configured_connection_string = settings.storage_connection_string
    if configured_connection_string:
        return configured_connection_string

    fallback_connection_string = os.getenv("AzureWebJobsStorage", "").strip()
    return fallback_connection_string or None


def _build_history_relative_name(prefix: str, history_day: date) -> str:
    return f"{_PUBLIC_SECURITY_PREFIX}/{prefix}/{history_day.isoformat()}.ndjson"


def _build_local_history_path(base_directory: Path, relative_name: str) -> Path:
    return base_directory / Path(relative_name)


def _serialize_json_line(payload: Mapping[str, Any]) -> bytes:
    serialized_payload = json.dumps(
        dict(payload),
        default=str,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"{serialized_payload}\n".encode("utf-8")


def _append_json_line_to_local_file(file_path: Path, payload: Mapping[str, Any]) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("ab") as history_file:
        history_file.write(_serialize_json_line(payload))


def _append_json_line_to_blob(
    connection_string: str,
    container_name: str,
    blob_name: str,
    payload: Mapping[str, Any],
) -> None:
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.get_container_client(container_name)
    try:
        container_client.create_container()
    except ResourceExistsError:
        pass

    blob_client = BlobClient.from_connection_string(
        conn_str=connection_string,
        container_name=container_name,
        blob_name=blob_name,
    )
    try:
        blob_client.create_append_blob()
    except ResourceExistsError:
        pass

    blob_client.append_block(_serialize_json_line(payload))


def _append_history_record(
    settings: AppSettings,
    *,
    history_prefix: str,
    history_day: date,
    payload: Mapping[str, Any],
) -> None:
    relative_name = _build_history_relative_name(history_prefix, history_day)
    if _prefer_local_public_telemetry_history(settings):
        _append_json_line_to_local_file(
            _build_local_history_path(
                settings.public_telemetry_history_directory,
                relative_name,
            ),
            payload,
        )
        return

    connection_string = _resolve_storage_connection_string(settings)
    if connection_string:
        _append_json_line_to_blob(
            connection_string,
            settings.public_telemetry_history_container_name,
            relative_name,
            payload,
        )
        return

    _append_json_line_to_local_file(
        _build_local_history_path(
            settings.public_telemetry_history_directory,
            relative_name,
        ),
        payload,
    )


def _read_json_lines_from_text(payload_text: str) -> tuple[dict[str, Any], ...]:
    parsed_payloads: list[dict[str, Any]] = []
    for line in payload_text.splitlines():
        stripped_line = line.strip()
        if not stripped_line:
            continue

        parsed_line = json.loads(stripped_line)
        if isinstance(parsed_line, dict):
            parsed_payloads.append(parsed_line)

    return tuple(parsed_payloads)


def _read_json_lines_from_blob(
    connection_string: str,
    container_name: str,
    blob_name: str,
) -> tuple[dict[str, Any], ...]:
    blob_client = BlobClient.from_connection_string(
        conn_str=connection_string,
        container_name=container_name,
        blob_name=blob_name,
    )
    try:
        payload_bytes = blob_client.download_blob().readall()
    except ResourceNotFoundError:
        return ()

    return _read_json_lines_from_text(payload_bytes.decode("utf-8"))


def _read_json_lines_from_local_file(file_path: Path) -> tuple[dict[str, Any], ...]:
    if not file_path.exists():
        return ()

    return _read_json_lines_from_text(file_path.read_text(encoding="utf-8"))


def _build_retained_days(retention_days: int) -> tuple[date, ...]:
    today_utc = datetime.now(UTC).date()
    return tuple(today_utc - timedelta(days=offset) for offset in range(retention_days))


def _load_history_models(
    settings: AppSettings,
    *,
    history_prefix: str,
    history_days: tuple[date, ...],
    model_type: type[_ModelType],
) -> tuple[_ModelType, ...]:
    loaded_models: list[_ModelType] = []
    connection_string = None
    if not _prefer_local_public_telemetry_history(settings):
        connection_string = _resolve_storage_connection_string(settings)

    for history_day in history_days:
        relative_name = _build_history_relative_name(history_prefix, history_day)
        if connection_string:
            payloads = _read_json_lines_from_blob(
                connection_string,
                settings.public_telemetry_history_container_name,
                relative_name,
            )
        else:
            payloads = _read_json_lines_from_local_file(
                _build_local_history_path(
                    settings.public_telemetry_history_directory,
                    relative_name,
                )
            )

        for payload in payloads:
            loaded_models.append(model_type.model_validate(payload))

    return tuple(loaded_models)


def _prefer_local_public_telemetry_history(settings: AppSettings) -> bool:
    return (
        settings.public_telemetry_history_directory
        != _DEFAULT_PUBLIC_TELEMETRY_HISTORY_DIRECTORY
    )


def _build_public_traffic_history_record(
    event: PublicTrafficEvent,
    headers: Mapping[str, str],
) -> PublicTrafficHistoryRecord:
    return PublicTrafficHistoryRecord(
        event_type=event.event_type,
        geography_bucket=_build_geography_bucket(headers),
        route=event.route,
        session_hash=_hash_session_id(event.session_id),
        site_mode=event.site_mode,
    )


def _build_recent_activity_item(
    event: PublicTrafficEvent,
    headers: Mapping[str, str],
    *,
    recorded_at_utc: datetime,
) -> PublicRecentActivityItem:
    return PublicRecentActivityItem(
        geography_bucket=_build_geography_bucket(headers),
        recorded_at_utc=recorded_at_utc,
        route=event.route,
        session_label=_build_session_label(event.session_id),
        site_mode=event.site_mode,
    )


def _build_health_check_note(record: PublicHealthCheckRecord) -> str:
    if record.public_site_ok is True:
        public_site_note = "Public site reachable"
    elif record.public_site_ok is False:
        public_site_note = "Public site unavailable"
    else:
        public_site_note = "Public site not checked"

    traffic_event_note = (
        "traffic route accepted" if record.traffic_event_ok else "traffic route failed"
    )
    return f"{public_site_note} · {traffic_event_note}"


def _build_current_status_from_health_records(
    health_records: tuple[PublicHealthCheckRecord, ...],
) -> str:
    if not health_records:
        return _AWAITING_MONITORED_HISTORY_STATUS

    latest_record = max(health_records, key=lambda record: record.checked_at_utc)
    return _HEALTHY_STATUS if latest_record.overall_ok else _DEGRADED_STATUS


def _aggregate_traffic_history(
    traffic_records: tuple[PublicTrafficHistoryRecord, ...],
) -> _TrafficAggregate:
    geography_counts: Counter[str] = Counter()
    hourly_counts: Counter[datetime] = Counter()
    route_counts: Counter[str] = Counter()
    session_hashes: set[str] = set()
    site_mode_counts: Counter[str] = Counter()
    last_event_at_utc: datetime | None = None

    for record in traffic_records:
        geography_counts[record.geography_bucket] += 1
        hourly_counts[_normalize_hour_bucket(record.recorded_at_utc)] += 1
        route_counts[record.route] += 1
        session_hashes.add(record.session_hash)
        site_mode_counts[record.site_mode] += 1
        if last_event_at_utc is None or record.recorded_at_utc > last_event_at_utc:
            last_event_at_utc = record.recorded_at_utc

    return _TrafficAggregate(
        geography_counts=_build_metric_counts(geography_counts),
        last_event_at_utc=last_event_at_utc,
        route_counts=_build_metric_counts(route_counts),
        site_mode_counts=_build_metric_counts(site_mode_counts),
        total_events=len(traffic_records),
        traffic_cadence=_build_traffic_cadence_points(hourly_counts),
        unique_sessions=len(session_hashes),
    )


def _build_recent_activity_from_history(
    traffic_records: tuple[PublicTrafficHistoryRecord, ...],
    *,
    max_items: int,
) -> tuple[PublicRecentActivityItem, ...]:
    """Reconstruct the recent-activity feed from durable sanitized history.

    Falls back to the durable `PublicTrafficHistoryRecord` rows when the live
    in-memory store is empty (typical immediately after a cold start). The
    short hashed-session prefix is reused as the human-readable session label
    so the panel matches the in-memory format.
    """

    if not traffic_records:
        return ()

    most_recent = sorted(
        traffic_records,
        key=lambda record: record.recorded_at_utc,
        reverse=True,
    )[:max_items]
    return tuple(
        PublicRecentActivityItem(
            geography_bucket=record.geography_bucket,
            recorded_at_utc=record.recorded_at_utc,
            route=record.route,
            session_label=f"session-{record.session_hash[:8]}",
            site_mode=record.site_mode,
        )
        for record in most_recent
    )


def _aggregate_health_history(
    health_records: tuple[PublicHealthCheckRecord, ...],
    *,
    max_checks: int,
) -> _HealthAggregate:
    if not health_records:
        return _HealthAggregate(
            availability_percentage=None,
            current_status=_AWAITING_MONITORED_HISTORY_STATUS,
            latest_alert_configuration_ready=None,
            latest_monitor_name=None,
            last_successful_health_check_at_utc=None,
            recent_health_checks=(),
        )

    ordered_records = tuple(
        sorted(health_records, key=lambda record: record.checked_at_utc, reverse=True)
    )
    latest_record = ordered_records[0]
    successful_check_count = sum(record.overall_ok for record in ordered_records)
    last_successful_health_check_at_utc = next(
        (
            record.checked_at_utc
            for record in ordered_records
            if record.overall_ok
        ),
        None,
    )
    recent_health_checks = tuple(
        PublicHealthCheckDigestItem(
            checked_at_utc=record.checked_at_utc,
            note=_build_health_check_note(record),
            overall_ok=record.overall_ok,
        )
        for record in ordered_records[:max_checks]
    )
    return _HealthAggregate(
        availability_percentage=round(
            (successful_check_count / len(ordered_records)) * 100,
            1,
        ),
        current_status=_build_current_status_from_health_records(ordered_records),
        latest_alert_configuration_ready=latest_record.alert_ready,
        latest_monitor_name=latest_record.monitor_name,
        last_successful_health_check_at_utc=last_successful_health_check_at_utc,
        recent_health_checks=recent_health_checks,
    )


class PublicTrafficMetricsStore:
    """Process-local aggregate counter store for public traffic events."""

    def __init__(self, *, started_at_utc: datetime | None = None) -> None:
        self._started_at_utc = started_at_utc or datetime.now(UTC)
        self._lock = Lock()
        self._geography_counts: Counter[str] = Counter()
        self._hourly_counts: Counter[datetime] = Counter()
        self._last_event_at_utc: datetime | None = None
        self._recent_activity: list[PublicRecentActivityItem] = []
        self._route_counts: Counter[str] = Counter()
        self._session_ids: set[str] = set()
        self._site_mode_counts: Counter[str] = Counter()
        self._total_events = 0

    def record_event(
        self,
        event: PublicTrafficEvent,
        headers: Mapping[str, str],
    ) -> None:
        """Record one public traffic event into aggregate-only counters."""

        geography_bucket = _build_geography_bucket(headers)
        recorded_at_utc = datetime.now(UTC)
        recent_activity_item = _build_recent_activity_item(
            event,
            headers,
            recorded_at_utc=recorded_at_utc,
        )
        with self._lock:
            self._geography_counts[geography_bucket] += 1
            self._hourly_counts[_normalize_hour_bucket(recorded_at_utc)] += 1
            self._last_event_at_utc = recorded_at_utc
            self._recent_activity.insert(0, recent_activity_item)
            if len(self._recent_activity) > _RECENT_ACTIVITY_MAX_ITEMS:
                self._recent_activity = self._recent_activity[:_RECENT_ACTIVITY_MAX_ITEMS]
            self._route_counts[event.route] += 1
            self._session_ids.add(event.session_id)
            self._site_mode_counts[event.site_mode] += 1
            self._total_events += 1

    def build_live_detail_snapshot(self) -> _LiveTelemetryDetail:
        """Build the short-lived session-detail overlay for the public dashboard."""

        with self._lock:
            recent_activity = tuple(self._recent_activity)

        return _LiveTelemetryDetail(
            recent_activity=recent_activity,
            recent_activity_window=_SHORT_LIVED_RECENT_ACTIVITY_WINDOW,
        )

    def build_summary(self, environment_name: str) -> PublicTrafficMetricsSummary:
        """Build the current process-local aggregate summary snapshot."""

        generated_at_utc = datetime.now(UTC)
        normalized_environment_name = _normalize_environment_name(environment_name)
        with self._lock:
            geography_counts = _build_metric_counts(self._geography_counts)
            hourly_counts = Counter(self._hourly_counts)
            last_event_at_utc = self._last_event_at_utc
            recent_activity = tuple(self._recent_activity)
            route_counts = _build_metric_counts(self._route_counts)
            site_mode_counts = _build_metric_counts(self._site_mode_counts)
            total_events = self._total_events
            unique_sessions = len(self._session_ids)

        current_status = (
            _HEALTHY_STATUS if total_events > 0 else _AWAITING_MONITORED_HISTORY_STATUS
        )
        return PublicTrafficMetricsSummary(
            availability_percentage=None,
            availability_source=_PROCESS_LOCAL_AVAILABILITY_SOURCE,
            availability_window="Worker lifetime",
            collection_mode=_PROCESS_LOCAL_COLLECTION_MODE,
            collection_window=_PROCESS_LOCAL_COLLECTION_WINDOW,
            current_status=current_status,
            current_uptime_seconds=max(
                int((generated_at_utc - self._started_at_utc).total_seconds()),
                0,
            ),
            environment_name=normalized_environment_name,
            generated_at_utc=generated_at_utc,
            geography_counts=geography_counts,
            last_event_at_utc=last_event_at_utc,
            latest_alert_configuration_ready=None,
            latest_monitor_name=None,
            process_started_at_utc=self._started_at_utc,
            recent_activity=recent_activity,
            recent_activity_window=_SHORT_LIVED_RECENT_ACTIVITY_WINDOW,
            route_counts=route_counts,
            site_mode_counts=site_mode_counts,
            total_events=total_events,
            traffic_cadence=_build_traffic_cadence_points(hourly_counts),
            traffic_cadence_window=_PROCESS_LOCAL_TRAFFIC_CADENCE_WINDOW,
            unique_sessions=unique_sessions,
        )


_DEFAULT_PUBLIC_TRAFFIC_METRICS_STORE = PublicTrafficMetricsStore()


def build_public_health_check_record(
    verification_results: Mapping[str, object],
    *,
    monitor_name: str = "public-simulation-verifier",
) -> PublicHealthCheckRecord:
    """Build a sanitized monitored health-check record from verifier output."""

    public_site_payload = verification_results.get("public_site")
    traffic_event_payload = verification_results.get("traffic_event")
    alert_settings_payload = verification_results.get("alert_settings")

    public_site_ok: bool | None = None
    public_site_status_code: int | None = None
    if isinstance(public_site_payload, Mapping):
        is_reachable = public_site_payload.get("is_reachable")
        if isinstance(is_reachable, bool):
            public_site_ok = is_reachable
        public_site_status = public_site_payload.get("status_code")
        if isinstance(public_site_status, int):
            public_site_status_code = public_site_status

    traffic_event_ok = False
    traffic_event_status_code: int | None = None
    if isinstance(traffic_event_payload, Mapping):
        traffic_event_ok_value = traffic_event_payload.get("ok")
        if isinstance(traffic_event_ok_value, bool):
            traffic_event_ok = traffic_event_ok_value
        traffic_event_status = traffic_event_payload.get("status_code")
        if isinstance(traffic_event_status, int):
            traffic_event_status_code = traffic_event_status

    alert_ready: bool | None = None
    if isinstance(alert_settings_payload, Mapping):
        alert_ready_value = alert_settings_payload.get("email_ready")
        if isinstance(alert_ready_value, bool):
            alert_ready = alert_ready_value

    overall_ok_value = verification_results.get("ok")
    overall_ok = overall_ok_value if isinstance(overall_ok_value, bool) else traffic_event_ok
    return PublicHealthCheckRecord(
        alert_ready=alert_ready,
        monitor_name=monitor_name,
        overall_ok=overall_ok,
        public_site_ok=public_site_ok,
        public_site_status_code=public_site_status_code,
        traffic_event_ok=traffic_event_ok,
        traffic_event_status_code=traffic_event_status_code,
    )


def persist_public_health_check_record(
    record: PublicHealthCheckRecord,
    settings: AppSettings,
) -> None:
    """Persist one sanitized monitored health-check record."""

    _append_history_record(
        settings,
        history_prefix="health-checks",
        history_day=record.checked_at_utc.date(),
        payload=record.model_dump(mode="json"),
    )


def persist_public_suppressed_alert_record(
    record: PublicSuppressedAlertHistoryRecord,
    settings: AppSettings,
) -> None:
    """Persist one sanitized suppressed-alert record for the cadence card."""

    _append_history_record(
        settings,
        history_prefix="suppressed-alerts",
        history_day=record.recorded_at_utc.date(),
        payload=record.model_dump(mode="json"),
    )


def record_public_traffic_event_aggregate(
    event: PublicTrafficEvent,
    headers: Mapping[str, str],
    settings: AppSettings | None = None,
) -> None:
    """Record one public traffic event into aggregate metrics and durable history."""

    if event.event_type == "health_probe":
        return

    _DEFAULT_PUBLIC_TRAFFIC_METRICS_STORE.record_event(event, headers)
    if settings is None:
        return

    history_record = _build_public_traffic_history_record(event, headers)
    try:
        _append_history_record(
            settings,
            history_prefix="traffic-events",
            history_day=history_record.recorded_at_utc.date(),
            payload=history_record.model_dump(mode="json"),
        )
    except Exception:
        logging.exception("Unable to persist sanitized public traffic history.")


def _build_durable_public_traffic_metrics_summary(
    settings: AppSettings,
) -> PublicTrafficMetricsSummary:
    traffic_history_days = _build_retained_days(settings.public_telemetry_retention_days)
    health_history_days = _build_retained_days(
        min(
            settings.public_telemetry_retention_days,
            settings.public_health_digest_window_days,
        )
    )
    traffic_records = _load_history_models(
        settings,
        history_prefix="traffic-events",
        history_days=traffic_history_days,
        model_type=PublicTrafficHistoryRecord,
    )
    health_records = _load_history_models(
        settings,
        history_prefix="health-checks",
        history_days=health_history_days,
        model_type=PublicHealthCheckRecord,
    )
    suppressed_alert_records = _load_history_models(
        settings,
        history_prefix="suppressed-alerts",
        history_days=traffic_history_days,
        model_type=PublicSuppressedAlertHistoryRecord,
    )

    traffic_aggregate = _aggregate_traffic_history(traffic_records)
    health_aggregate = _aggregate_health_history(
        health_records,
        max_checks=settings.public_health_digest_max_checks,
    )
    durable_recent_activity = _build_recent_activity_from_history(
        traffic_records,
        max_items=_RECENT_ACTIVITY_MAX_ITEMS,
    )
    durable_recent_activity_window = (
        _DURABLE_RECENT_ACTIVITY_WINDOW_TEMPLATE.format(
            max_items=_RECENT_ACTIVITY_MAX_ITEMS,
        )
        if durable_recent_activity
        else _SHORT_LIVED_RECENT_ACTIVITY_WINDOW
    )
    return PublicTrafficMetricsSummary(
        availability_percentage=health_aggregate.availability_percentage,
        availability_source=_EXTERNAL_AVAILABILITY_SOURCE,
        availability_window=_MONITORED_AVAILABILITY_WINDOW_TEMPLATE.format(
            window_days=min(
                settings.public_telemetry_retention_days,
                settings.public_health_digest_window_days,
            )
        ),
        collection_mode=_DURABLE_COLLECTION_MODE,
        collection_window=_DURABLE_COLLECTION_WINDOW_TEMPLATE.format(
            retention_days=settings.public_telemetry_retention_days,
        ),
        current_status=health_aggregate.current_status,
        environment_name=_normalize_environment_name(settings.environment_name),
        geography_counts=traffic_aggregate.geography_counts,
        last_event_at_utc=traffic_aggregate.last_event_at_utc,
        latest_alert_configuration_ready=health_aggregate.latest_alert_configuration_ready,
        latest_monitor_name=health_aggregate.latest_monitor_name,
        last_successful_health_check_at_utc=(
            health_aggregate.last_successful_health_check_at_utc
        ),
        recent_activity=durable_recent_activity,
        recent_activity_window=durable_recent_activity_window,
        recent_health_checks=health_aggregate.recent_health_checks,
        route_counts=traffic_aggregate.route_counts,
        site_mode_counts=traffic_aggregate.site_mode_counts,
        suppressed_alert_count=len(suppressed_alert_records),
        total_events=traffic_aggregate.total_events,
        traffic_cadence=traffic_aggregate.traffic_cadence,
        traffic_cadence_window=_DURABLE_TRAFFIC_CADENCE_WINDOW,
        unique_sessions=traffic_aggregate.unique_sessions,
    )


def build_public_traffic_metrics_summary(
    settings: AppSettings,
) -> PublicTrafficMetricsSummary:
    """Build the current public aggregate summary using durable history when present."""

    durable_summary = _build_durable_public_traffic_metrics_summary(settings)
    live_detail = _DEFAULT_PUBLIC_TRAFFIC_METRICS_STORE.build_live_detail_snapshot()
    if durable_summary.total_events > 0 or durable_summary.recent_health_checks:
        if live_detail.recent_activity:
            return durable_summary.model_copy(
                update={
                    "recent_activity": live_detail.recent_activity,
                    "recent_activity_window": live_detail.recent_activity_window,
                }
            )
        return durable_summary

    return _DEFAULT_PUBLIC_TRAFFIC_METRICS_STORE.build_summary(settings.environment_name)
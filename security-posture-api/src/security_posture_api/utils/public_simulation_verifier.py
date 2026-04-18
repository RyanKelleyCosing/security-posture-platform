"""Helpers for verifying the public simulation deployment and alert settings."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from urllib.request import Request, urlopen

PUBLIC_ALERT_REQUIRED_SETTINGS = (
    "DOCINT_PUBLIC_ALERT_RECIPIENT_EMAIL",
    "DOCINT_SMTP_HOST",
    "DOCINT_SMTP_SENDER_EMAIL",
)


@dataclass(frozen=True)
class PublicAlertSettingsSummary:
    """Status summary for the public traffic email configuration."""

    alerts_enabled: bool
    configured_required_settings: tuple[str, ...]
    email_ready: bool
    missing_required_settings: tuple[str, ...]


@dataclass(frozen=True)
class PublicSiteCheck:
    """Availability summary for the public simulation site."""

    content_type: str
    is_reachable: bool
    status_code: int
    url: str


def _is_unset_value(value: str | None) -> bool:
    if value is None:
        return True

    normalized_value = value.strip()
    return not normalized_value or normalized_value.startswith("__REPLACE_")


def parse_bool_setting(value: str | None) -> bool:
    """Parse common environment-style truthy values."""
    if value is None:
        return False

    return value.strip().lower() in {"1", "true", "yes", "on"}


def summarize_public_alert_settings(
    values: Mapping[str, str],
) -> PublicAlertSettingsSummary:
    """Summarize whether the public traffic email settings are actually ready."""
    alerts_enabled = parse_bool_setting(
        values.get("DOCINT_PUBLIC_TRAFFIC_ALERTS_ENABLED")
    )
    configured_required_settings = tuple(
        setting_name
        for setting_name in PUBLIC_ALERT_REQUIRED_SETTINGS
        if not _is_unset_value(values.get(setting_name))
    )
    missing_required_settings = tuple(
        setting_name
        for setting_name in PUBLIC_ALERT_REQUIRED_SETTINGS
        if _is_unset_value(values.get(setting_name))
    )

    return PublicAlertSettingsSummary(
        alerts_enabled=alerts_enabled,
        configured_required_settings=configured_required_settings,
        email_ready=alerts_enabled and not missing_required_settings,
        missing_required_settings=missing_required_settings,
    )


def public_traffic_response_sent_alert(response_payload: Mapping[str, object]) -> bool:
    """Return whether the traffic route reported a successful SMTP alert send."""

    alert_sent = response_payload.get("alertSent")
    return isinstance(alert_sent, bool) and alert_sent


def normalize_public_site_url(public_site_url: str) -> str:
    """Return a normalized public site URL with an explicit scheme."""
    normalized_url = public_site_url.strip().rstrip("/")
    if not normalized_url:
        raise ValueError("public_site_url is required")
    if not normalized_url.startswith(("http://", "https://")):
        raise ValueError("public_site_url must start with http:// or https://")

    return normalized_url


def fetch_public_site_check(public_site_url: str) -> PublicSiteCheck:
    """Fetch the public site and return its basic availability details."""
    normalized_url = normalize_public_site_url(public_site_url)
    request = Request(
        normalized_url,
        headers={"Accept": "text/html,application/xhtml+xml"},
        method="GET",
    )
    with urlopen(request, timeout=30) as response:
        return PublicSiteCheck(
            content_type=response.headers.get_content_type(),
            is_reachable=response.status == 200,
            status_code=response.status,
            url=normalized_url,
        )


def resolve_azure_cli_executable() -> str:
    """Return the Azure CLI executable path."""
    for command_name in ("az", "az.cmd"):
        resolved_path = which(command_name)
        if resolved_path:
            return resolved_path

    for candidate_path in (
        Path("C:/Program Files/Microsoft SDKs/Azure/CLI2/wbin/az.cmd"),
        Path("C:/Program Files (x86)/Microsoft SDKs/Azure/CLI2/wbin/az.cmd"),
    ):
        if candidate_path.exists():
            return str(candidate_path)

    raise RuntimeError("Azure CLI is required to resolve Azure deployment settings.")


def run_azure_cli_text(az_executable: str, args: list[str]) -> str:
    """Run an Azure CLI command and return stripped text output."""
    try:
        result = subprocess.run(
            [az_executable, *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        details = error.stderr.strip() or error.stdout.strip() or str(error)
        raise RuntimeError(details) from error

    return result.stdout.strip()


def resolve_function_app_name(
    az_executable: str,
    resource_group_name: str,
    function_app_name: str,
) -> str:
    """Resolve the Function App name from an explicit value or the resource group."""
    if function_app_name.strip():
        return function_app_name.strip()

    resolved_name = run_azure_cli_text(
        az_executable,
        [
            "functionapp",
            "list",
            "--resource-group",
            resource_group_name,
            "--query",
            "[0].name",
            "--output",
            "tsv",
        ],
    )
    if not resolved_name:
        raise RuntimeError("Could not resolve a Function App name.")

    return resolved_name


def resolve_function_base_url(
    az_executable: str,
    resource_group_name: str,
    function_app_name: str,
) -> str:
    """Resolve the deployed Functions base URL including the API prefix."""
    resolved_function_app_name = resolve_function_app_name(
        az_executable,
        resource_group_name,
        function_app_name,
    )
    host_name = run_azure_cli_text(
        az_executable,
        [
            "functionapp",
            "show",
            "--resource-group",
            resource_group_name,
            "--name",
            resolved_function_app_name,
            "--query",
            "properties.defaultHostName",
            "--output",
            "tsv",
        ],
    )
    if not host_name:
        raise RuntimeError("Could not resolve the deployed Function App host name.")

    return f"https://{host_name}/api"


def load_azure_function_app_settings(
    az_executable: str,
    resource_group_name: str,
    function_app_name: str,
) -> dict[str, str]:
    """Load Function App settings into a simple name/value mapping."""
    resolved_function_app_name = resolve_function_app_name(
        az_executable,
        resource_group_name,
        function_app_name,
    )
    output_text = run_azure_cli_text(
        az_executable,
        [
            "functionapp",
            "config",
            "appsettings",
            "list",
            "--resource-group",
            resource_group_name,
            "--name",
            resolved_function_app_name,
            "--output",
            "json",
        ],
    )
    payload = json.loads(output_text)
    if not isinstance(payload, list):
        raise RuntimeError("Expected Azure CLI app settings output to be a JSON list.")

    settings: dict[str, str] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        value = item.get("value")
        if isinstance(name, str) and value is not None:
            settings[name] = str(value)

    return settings
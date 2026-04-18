"""Verify the public simulation deployment, traffic endpoint, and alert readiness."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict
from pathlib import Path
from urllib.error import HTTPError, URLError

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from security_posture_api.verification_settings import (  # noqa: E402
    load_local_values,
    resolve_storage_connection_string,
)
from security_posture_api.public_traffic_metrics import (  # noqa: E402
    build_public_health_check_record,
    persist_public_health_check_record,
)
from security_posture_api.settings import AppSettings  # noqa: E402
from security_posture_api.utils.public_simulation_verifier import (  # noqa: E402
    fetch_public_site_check,
    load_azure_function_app_settings,
    public_traffic_response_sent_alert,
    resolve_azure_cli_executable,
    resolve_function_base_url,
    summarize_public_alert_settings,
)
from security_posture_api.utils.public_traffic_client import (  # noqa: E402
    PUBLIC_TRAFFIC_EVENT_TYPES,
    build_public_traffic_headers,
    build_public_traffic_payload,
    resolve_public_traffic_endpoint,
    send_public_traffic_event,
)

DEFAULT_USER_AGENT = "docint-public-simulation-verifier/1.0"


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for public simulation deployment verification."""
    parser = argparse.ArgumentParser(
        description=(
            "Verify the public simulation site, the anonymous traffic route, and "
            "whether email alert settings are ready."
        ),
    )
    parser.add_argument(
        "--public-site-url",
        default="",
        help="Optional deployed public simulation site URL to check for reachability.",
    )
    parser.add_argument(
        "--function-base-url",
        default="",
        help=(
            "Optional Functions base URL, including /api when applicable. "
            "When this is omitted, the script can resolve it from Azure CLI "
            "or local.settings.json."
        ),
    )
    parser.add_argument(
        "--local-settings-file",
        type=Path,
        default=Path("local.settings.json"),
        help="Optional local.settings.json file used for local verification.",
    )
    parser.add_argument(
        "--settings-source",
        choices=("none", "local", "azure"),
        default="none",
        help="Where to read alert settings from for readiness checks.",
    )
    parser.add_argument(
        "--resource-group-name",
        default="rg-doc-intel-dev",
        help="Azure resource group used to resolve deployed Function App settings.",
    )
    parser.add_argument(
        "--function-app-name",
        default="",
        help="Optional Function App name override for Azure settings checks.",
    )
    parser.add_argument(
        "--event-type",
        choices=PUBLIC_TRAFFIC_EVENT_TYPES,
        default="simulation_started",
        help="Traffic event type to submit during verification.",
    )
    parser.add_argument(
        "--route",
        default="intake",
        help="Simulation route label to submit during verification.",
    )
    parser.add_argument(
        "--page-title",
        default="Hybrid Document Intelligence Public Simulation",
        help="Optional page title to include in the synthetic traffic event.",
    )
    parser.add_argument(
        "--session-id",
        default="simulation-verification-session",
        help="Session identifier for the synthetic traffic event.",
    )
    parser.add_argument(
        "--forwarded-for",
        default="203.0.113.10",
        help="Optional X-Forwarded-For value for alert and logging verification.",
    )
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="User-Agent header for the synthetic traffic event.",
    )
    parser.add_argument(
        "--require-alert-ready",
        action="store_true",
        help="Fail verification when alert settings are not fully configured.",
    )
    parser.add_argument(
        "--require-alert-sent",
        action="store_true",
        help=(
            "Fail verification when the traffic route responds without actually "
            "sending an SMTP alert email. Use this only for one-off delivery checks, "
            "not for the scheduled health probe."
        ),
    )
    parser.add_argument(
        "--monitor-name",
        default="public-simulation-verifier",
        help="Monitor label persisted into the public-safe health history.",
    )
    parser.add_argument(
        "--persist-public-history",
        action="store_true",
        help=(
            "Persist a sanitized monitored health-check record so the public "
            "security summary can show availability history."
        ),
    )
    parser.add_argument(
        "--storage-account-name",
        default="",
        help="Optional storage account name override for public history persistence.",
    )
    parser.add_argument(
        "--storage-connection-string",
        default="",
        help="Optional storage connection string override for public history persistence.",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=None,
        help="Optional JSON output file path for the verification result.",
    )
    return parser.parse_args()


def load_alert_settings(args: argparse.Namespace) -> dict[str, str] | None:
    """Load alert settings from the requested source."""
    if args.settings_source == "none":
        return None

    if args.settings_source == "local":
        return load_local_values(args.local_settings_file)

    az_executable = resolve_azure_cli_executable()
    return load_azure_function_app_settings(
        az_executable,
        args.resource_group_name,
        args.function_app_name,
    )


def resolve_function_base_url_for_verification(args: argparse.Namespace) -> str:
    """Resolve the Functions base URL from CLI input, Azure, or local settings."""
    function_base_url = str(args.function_base_url)
    if function_base_url.strip():
        return function_base_url.strip()

    if args.settings_source == "azure":
        az_executable = resolve_azure_cli_executable()
        return resolve_function_base_url(
            az_executable,
            args.resource_group_name,
            args.function_app_name,
        )

    return ""


def _build_public_history_settings(args: argparse.Namespace) -> AppSettings:
    """Build the public history persistence settings for verifier runs."""

    local_values = load_local_values(args.local_settings_file)
    resolved_storage_connection_string: str | None = None
    try:
        stripped_connection_string = args.storage_connection_string.strip()
        resolved_storage_connection_string, _ = resolve_storage_connection_string(
            args.resource_group_name,
            local_values,
            storage_account_name=args.storage_account_name,
            storage_connection_string=stripped_connection_string or None,
        )
    except RuntimeError:
        logging.warning(
            "Unable to resolve Azure storage for public history persistence; "
            "falling back to the local history directory."
        )

    return AppSettings.model_validate(
        {
            "environment_name": local_values.get("DOCINT_ENVIRONMENT_NAME", "dev"),
            "storage_connection_string": resolved_storage_connection_string,
        }
    )


def main() -> int:
    """Run the requested public simulation verification checks."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = parse_args()

    results: dict[str, object] = {"ok": True}

    if args.public_site_url.strip():
        site_check = fetch_public_site_check(args.public_site_url)
        results["public_site"] = asdict(site_check)
        results["ok"] = bool(results["ok"]) and site_check.is_reachable

    function_base_url = resolve_function_base_url_for_verification(args)
    endpoint = resolve_public_traffic_endpoint(
        function_base_url,
        args.local_settings_file,
    )
    payload = build_public_traffic_payload(
        args.event_type,
        args.route,
        args.session_id,
        page_title=args.page_title,
    )
    headers = build_public_traffic_headers(
        args.user_agent,
        forwarded_for=args.forwarded_for,
    )

    try:
        status_code, response_payload = send_public_traffic_event(
            endpoint,
            payload,
            headers,
        )
    except (HTTPError, URLError, ValueError) as error:
        logging.error("Traffic event verification failed: %s", error)
        return 1

    traffic_ok = status_code == 202 and response_payload.get("status") == "accepted"
    alert_sent = public_traffic_response_sent_alert(response_payload)
    results["traffic_event"] = {
        "endpoint": endpoint,
        "headers": headers,
        "payload": payload,
        "response": response_payload,
        "status_code": status_code,
        "ok": traffic_ok,
    }
    results["ok"] = bool(results["ok"]) and traffic_ok
    results["email_alert"] = {
        "required": bool(args.require_alert_sent),
        "sent": alert_sent,
    }
    if args.require_alert_sent:
        results["ok"] = bool(results["ok"]) and alert_sent

    alert_settings = load_alert_settings(args)
    if alert_settings is not None:
        alert_summary = summarize_public_alert_settings(alert_settings)
        results["alert_settings"] = asdict(alert_summary)
        if args.require_alert_ready:
            results["ok"] = bool(results["ok"]) and alert_summary.email_ready

    if args.persist_public_history:
        history_settings = _build_public_history_settings(args)
        health_check_record = build_public_health_check_record(
            results,
            monitor_name=args.monitor_name,
        )
        persist_public_health_check_record(health_check_record, history_settings)
        results["public_history"] = {
            "persisted": True,
            "storage_mode": (
                "blob"
                if history_settings.storage_connection_string
                else "local"
            ),
        }

    if args.output_file is not None:
        args.output_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
        logging.info(
            "Wrote public simulation verification output to %s",
            args.output_file,
        )

    logging.info("%s", json.dumps(results, indent=2))
    return 0 if bool(results["ok"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
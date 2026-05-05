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
    fetch_public_cost_history,
    fetch_public_cost_latest,
    fetch_public_request_context,
    fetch_public_cost_summary,
    fetch_public_site_check,
    load_azure_function_app_settings,
    normalize_public_site_url,
    parse_bool_setting,
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
            "Verify the public simulation site, the anonymous request-context and "
            "traffic routes, and whether email alert settings are ready."
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
        "--verify-public-cost",
        action="store_true",
        help=(
            "Verify the public cost summary, latest JSON export, CSV history export, "
            "and optional /cost site route."
        ),
    )
    parser.add_argument(
        "--require-azure-cost-history",
        action="store_true",
        help=(
            "Fail verification unless the public cost summary reports retained "
            "durable history instead of the bundled repo snapshot."
        ),
    )
    parser.add_argument(
        "--minimum-cost-history-rows",
        type=int,
        default=1,
        help="Minimum retained history rows expected from the public cost summary and CSV export.",
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


def _is_non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def public_network_enrichment_provider_is_configured(
    provider_name: str,
    provider_key: str,
) -> bool:
    """Return whether the current provider configuration should produce enrichment."""

    if provider_name in {"", "none"}:
        return False

    if provider_name in {"ipqualityscore", "ipqs"}:
        return bool(provider_key)

    return True


def build_public_request_context_headers(args: argparse.Namespace) -> dict[str, str]:
    """Build HTTP headers for request-context verification."""

    headers = {
        "Accept": "application/json",
        "User-Agent": args.user_agent,
        "X-Forwarded-Proto": "https",
    }
    if args.forwarded_for.strip():
        headers["X-Forwarded-For"] = args.forwarded_for.strip()

    return headers


def public_request_context_payload_is_valid(payload: dict[str, object]) -> bool:
    """Return whether a request-context payload includes the expected public fields."""

    required_string_fields = (
        "approximate_location",
        "edge_region",
        "enrichment_status",
        "forwarded_host",
        "forwarded_proto",
        "request_id",
        "request_timestamp_utc",
        "tls_protocol",
        "transport_security",
    )
    return all(_is_non_empty_string(payload.get(field_name)) for field_name in required_string_fields) and isinstance(
        payload.get("public_network_enrichment_enabled"),
        bool,
    ) and isinstance(payload.get("public_security_globe_enabled"), bool)


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
    loaded_settings = load_alert_settings(args)

    if args.public_site_url.strip():
        site_check = fetch_public_site_check(args.public_site_url)
        results["public_site"] = asdict(site_check)
        results["ok"] = bool(results["ok"]) and site_check.is_reachable

    function_base_url = resolve_function_base_url_for_verification(args)
    request_context_headers = build_public_request_context_headers(args)

    try:
        request_context_response = fetch_public_request_context(
            function_base_url,
            headers=request_context_headers,
        )
    except (HTTPError, URLError, ValueError) as error:
        logging.error("Public request-context verification failed: %s", error)
        results["public_request_context"] = {
            "error": str(error),
            "ok": False,
        }
        results["ok"] = False
    else:
        request_context_payload = request_context_response.payload
        flags_match = True
        expected_provider_configured: bool | None = None

        if loaded_settings is not None:
            expected_enrichment_enabled = parse_bool_setting(
                loaded_settings.get("DOCINT_PUBLIC_NETWORK_ENRICHMENT_ENABLED")
            )
            expected_globe_enabled = parse_bool_setting(
                loaded_settings.get("DOCINT_PUBLIC_SECURITY_GLOBE_ENABLED")
            )
            configured_provider_name = (
                loaded_settings.get("DOCINT_PUBLIC_NETWORK_ENRICHMENT_PROVIDER", "")
                .strip()
                .lower()
            )
            configured_provider_key = loaded_settings.get(
                "DOCINT_PUBLIC_NETWORK_ENRICHMENT_API_KEY",
                "",
            ).strip()
            flags_match = (
                request_context_payload.get("public_network_enrichment_enabled")
                is expected_enrichment_enabled
                and request_context_payload.get("public_security_globe_enabled")
                is expected_globe_enabled
            )
            expected_provider_configured = (
                expected_enrichment_enabled
                and public_network_enrichment_provider_is_configured(
                    configured_provider_name,
                    configured_provider_key,
                )
            )

        provider_check_ok = True
        if expected_provider_configured:
            provider_name = request_context_payload.get("enrichment_provider_name")
            provider_check_ok = _is_non_empty_string(provider_name)

        public_request_context_ok = (
            request_context_response.status_code == 200
            and public_request_context_payload_is_valid(request_context_payload)
            and flags_match
            and provider_check_ok
        )
        results["public_request_context"] = {
            "endpoint": request_context_response.url,
            "headers": request_context_headers,
            "response": request_context_payload,
            "status_code": request_context_response.status_code,
            "ok": public_request_context_ok,
            "flags_match": flags_match,
            "provider_check": {
                "configured": expected_provider_configured,
                "ok": provider_check_ok,
            },
        }
        results["ok"] = bool(results["ok"]) and public_request_context_ok

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

    if args.verify_public_cost:
        if not function_base_url:
            results["public_cost"] = {
                "error": (
                    "Public cost verification requires --function-base-url or "
                    "--settings-source azure."
                ),
                "ok": False,
            }
            results["ok"] = False
        else:
            try:
                summary_response = fetch_public_cost_summary(function_base_url)
                latest_response = fetch_public_cost_latest(function_base_url)
                history_response = fetch_public_cost_history(function_base_url)
            except (HTTPError, URLError, ValueError) as error:
                logging.error("Public cost verification failed: %s", error)
                results["public_cost"] = {
                    "error": str(error),
                    "ok": False,
                }
                results["ok"] = False
            else:
                summary_payload = summary_response.payload
                latest_payload = latest_response.payload
                history_source = summary_payload.get("history_source")
                history_row_count = summary_payload.get("history_row_count")
                month_to_date_cost = summary_payload.get("month_to_date_cost")
                latest_cost_summary = latest_payload.get("costSummary")
                csv_lines = [
                    line for line in history_response.text.splitlines() if line.strip()
                ]
                history_csv_row_count = max(len(csv_lines) - 1, 0)

                summary_has_required_fields = (
                    isinstance(history_source, str)
                    and isinstance(history_row_count, int)
                    and isinstance(month_to_date_cost, int | float)
                )
                latest_has_cost_summary = isinstance(latest_cost_summary, dict)
                has_minimum_history_rows = (
                    isinstance(history_row_count, int)
                    and history_row_count >= args.minimum_cost_history_rows
                    and history_csv_row_count >= args.minimum_cost_history_rows
                )
                uses_azure_cost_history = isinstance(history_source, str) and (
                    history_source == "Retained public cost history"
                    or history_source.startswith("Azure Blob cost history")
                )

                route_check: dict[str, object] | None = None
                route_ok = True
                if args.public_site_url.strip():
                    normalized_public_site_url = normalize_public_site_url(
                        args.public_site_url
                    )
                    route_check = asdict(
                        fetch_public_site_check(
                            f"{normalized_public_site_url}/#/cost"
                        )
                    )
                    route_ok = bool(route_check.get("is_reachable"))

                public_cost_ok = (
                    summary_has_required_fields
                    and latest_has_cost_summary
                    and has_minimum_history_rows
                    and route_ok
                    and (
                        not args.require_azure_cost_history
                        or uses_azure_cost_history
                    )
                )

                results["public_cost"] = {
                    "cost_route": route_check,
                    "csv_export": {
                        "content_type": history_response.content_type,
                        "ok": history_csv_row_count >= args.minimum_cost_history_rows,
                        "row_count": history_csv_row_count,
                        "status_code": history_response.status_code,
                        "url": history_response.url,
                    },
                    "latest_json": {
                        "content_type": latest_response.content_type,
                        "has_cost_summary": latest_has_cost_summary,
                        "ok": latest_has_cost_summary,
                        "status_code": latest_response.status_code,
                        "url": latest_response.url,
                    },
                    "ok": public_cost_ok,
                    "summary": {
                        "history_row_count": history_row_count,
                        "history_source": history_source,
                        "month_to_date_cost": month_to_date_cost,
                        "ok": summary_has_required_fields,
                        "status_code": summary_response.status_code,
                        "url": summary_response.url,
                        "uses_azure_cost_history": uses_azure_cost_history,
                    },
                }
                results["ok"] = bool(results["ok"]) and public_cost_ok

    if loaded_settings is not None:
        alert_summary = summarize_public_alert_settings(loaded_settings)
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
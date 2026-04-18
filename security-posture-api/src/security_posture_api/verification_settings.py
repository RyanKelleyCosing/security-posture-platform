"""Helper functions for local settings and storage resolution in verifier flows."""

from __future__ import annotations

import json
from pathlib import Path

from security_posture_api.utils.public_simulation_verifier import (
    resolve_azure_cli_executable,
    run_azure_cli_text,
)


def load_local_values(local_settings_file: Path) -> dict[str, str]:
    """Load the Values section from a local.settings.json file."""

    if not local_settings_file.exists():
        return {}

    payload = json.loads(local_settings_file.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return {}

    values = payload.get("Values")
    if not isinstance(values, dict):
        return {}

    return {
        str(key): str(value)
        for key, value in values.items()
        if value is not None
    }


def _is_placeholder_value(value: str | None) -> bool:
    if value is None:
        return True

    normalized_value = value.strip()
    return not normalized_value or normalized_value.startswith("__REPLACE_")


def resolve_storage_connection_string(
    azure_resource_group_name: str,
    local_values: dict[str, str],
    *,
    storage_account_name: str = "",
    storage_connection_string: str | None = None,
) -> tuple[str, str | None]:
    """Resolve the storage connection string from local settings or Azure CLI."""

    resolved_connection_string = (
        storage_connection_string
        or local_values.get("DOCINT_STORAGE_CONNECTION_STRING")
        or local_values.get("AzureWebJobsStorage")
    )
    if resolved_connection_string and not _is_placeholder_value(
        resolved_connection_string
    ):
        normalized_account_name = storage_account_name.strip() or None
        return resolved_connection_string.strip(), normalized_account_name

    az_executable = resolve_azure_cli_executable()
    normalized_account_name = storage_account_name.strip()
    if not normalized_account_name:
        normalized_account_name = run_azure_cli_text(
            az_executable,
            [
                "resource",
                "list",
                "--resource-group",
                azure_resource_group_name,
                "--resource-type",
                "Microsoft.Storage/storageAccounts",
                "--query",
                "[0].name",
                "--output",
                "tsv",
            ],
        )

    if not normalized_account_name:
        raise RuntimeError("Could not resolve a storage account name.")

    connection_string = run_azure_cli_text(
        az_executable,
        [
            "storage",
            "account",
            "show-connection-string",
            "--resource-group",
            azure_resource_group_name,
            "--name",
            normalized_account_name,
            "--query",
            "connectionString",
            "--output",
            "tsv",
        ],
    )
    if not connection_string:
        raise RuntimeError("Could not resolve a storage connection string.")

    return connection_string, normalized_account_name

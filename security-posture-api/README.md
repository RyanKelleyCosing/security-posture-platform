# Ryan Security Posture API

This directory is the extracted public-safe backend slice for the security
posture site.

It is intended for public demonstration only. The private repo remains the
live operational source of truth.

It keeps the anonymous request-context route, aggregate metrics route,
scheduled monitor, SMTP-backed public alerts, and verifier helpers in a
standalone Azure Functions package without dragging the private operator
shell, protected workflow routes, or tenant-specific infrastructure wiring.

## Source Of Truth

The extraction plan is derived from the private repo boundary manifest.
Machine-specific paths, local settings, and secrets are intentionally excluded
from this public package.

Rebuild this package from the repo root with:

```powershell
python scripts/extract_public_security_api_package.py
```

## Runtime Files

- `scripts/verify_public_simulation_stack.py`
- `src/security_posture_api/public_request_context.py`
- `src/security_posture_api/public_site_monitor.py`
- `src/security_posture_api/public_traffic_metrics.py`
- `src/security_posture_api/traffic_alerts.py`
- `src/security_posture_api/utils/public_simulation_verifier.py`
- `src/security_posture_api/utils/public_traffic_client.py`

## Validation Companions

- `tests/unit/test_public_request_context.py`
- `tests/unit/test_public_simulation_verifier.py`
- `tests/unit/test_public_site_monitor.py`
- `tests/unit/test_public_traffic_client.py`
- `tests/unit/test_public_traffic_metrics.py`
- `tests/unit/test_traffic_alerts.py`

## Environment Variables

- `DOCINT_ENVIRONMENT_NAME`: public environment label surfaced in summaries.
- `DOCINT_FUNCTION_API_BASE_URL`: explicit base URL used by the monitor when
  the Functions host is not inferable from `WEBSITE_HOSTNAME`.
- `DOCINT_PUBLIC_SITE_URL`: deployed public site URL used by the external
  reachability probe.
- `DOCINT_PUBLIC_TRAFFIC_ALERTS_ENABLED`: enables SMTP-backed alert sends for
  non-health-probe events.
- `DOCINT_PUBLIC_ALERT_RECIPIENT_EMAIL`: target inbox for optional traffic
  alerts.
- `DOCINT_PUBLIC_TELEMETRY_HISTORY_*`: storage and retention settings for the
  sanitized aggregate history.
- `DOCINT_STORAGE_CONNECTION_STRING` or `AzureWebJobsStorage`: durable history
  storage connection string.
- `DOCINT_SMTP_*`: SMTP relay settings for optional alert sends.

## Local Validation

```powershell
pip install -r requirements.txt
pip install -e .[dev]
pytest tests/unit
func start
```

For a full public-surface check after the API package is running, use:

```powershell
python scripts/verify_public_simulation_stack.py --settings-source local
```

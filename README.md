# Security Posture Platform

This repository is the public-safe demonstration surface for the Ryan security
posture experience.

It keeps the extracted frontend site package and the matching standalone
Azure Functions API package together without the private operator shell,
private review routes, tenant-specific deployment scripts, or secret-bearing
environment files.

It is intended for public demonstration only. The private
`hybrid-document-intelligence-platform` repo remains the live operational
source of truth.

## Included Packages

- `public-derivatives/security-posture-site` -> `security-posture-site/`
- `public-derivatives/security-posture-api` -> `security-posture-api/`

## Validation

```powershell
Set-Location security-posture-site
npm install
npm test
npm run build

Set-Location ..\security-posture-api
pip install -r requirements.txt
pip install -e .[dev]
pytest tests/unit
```

## Refresh From The Private Repo

From the private repo root, rebuild the demonstration export with:

```powershell
python scripts/extract_public_security_site_package.py
python scripts/extract_public_security_api_package.py
python scripts/build_public_security_posture_subtree.py
python scripts/export_public_security_posture_repo.py
```

## CI

A standalone-repo validation workflow is included at
`.github/workflows/validate.yml` so the public repository validates both
packages and fails fast if machine-specific paths or secret-bearing content
leak into the export.

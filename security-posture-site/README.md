# Ryan Security Posture Site

This directory is the first real public derivative package extracted from the
private `hybrid-document-intelligence-platform` repo.

It is intended for public demonstration only. The private repo remains the
live operational source of truth.

It keeps the employer-facing `#/security` experience in a standalone Vite app,
while the private operator shell, live deployment wiring, SMTP provisioning,
and backend-only routes stay in the private operational codebase.

## Source Of Truth

The extraction plan is derived from the private repo boundary manifest.
Machine-specific paths, local settings, and secrets are intentionally excluded
from this public package.

Rebuild this package from the repo root with:

```powershell
python scripts/extract_public_security_site_package.py
```

## Included Package Files

- `docs/ryancodes-security-online-concept.md`
- `src/api/publicTrafficApi.ts`
- `src/components/SecurityPostureSite.test.tsx`
- `src/components/SecurityPostureSite.tsx`
- `src/data/securitySiteContent.ts`

## Environment Variables

- `VITE_PUBLIC_TRAFFIC_API_BASE_URL`: optional base URL for the public-safe
  request-context and aggregate telemetry APIs.
- `VITE_PUBLIC_GITHUB_URL`: optional GitHub profile or repo link.
- `VITE_PUBLIC_LINKEDIN_URL`: optional LinkedIn profile link.

## Validation

```powershell
npm install
npm test
npm run build
```

# ryancodes.security.online Concept

## Goal

Create an employer-facing security posture site under `ryancodes.security.online`
that explains the public stack, zero-trust stance, defense-in-depth controls,
and privacy boundaries in a way that a hiring manager or technical reviewer can
understand in a few minutes.

The site should feel like a transparent security briefing rather than a generic
portfolio page.

## Audience

- Hiring managers who need a fast, plain-language explanation of the security posture.
- Technical interviewers who want to see concrete control choices and tradeoffs.
- Curious visitors who want to understand what telemetry is collected and why.

## Non-Goals

- Do not expose production secrets, internal hostnames, or subscription-specific identifiers.
- Do not publish raw logs, live vulnerability findings, or sensitive event payloads.
- Do not couple the site to the private operator platform or any production data plane.

## Core Message

The site should communicate four ideas quickly:

1. Public demos are intentionally separated from private operational systems.
2. Security choices are deliberate: zero trust, least privilege, strong boundaries, and minimal retention.
3. Telemetry is visible and understandable to the visitor instead of hidden behind vague privacy statements.
4. The site proves engineering judgment through clear controls, not through fear language or security theater.

## Recommended Experience

### 1. Landing Section

The landing view should answer these questions immediately:

- What is this site?
- What stack is public?
- What is intentionally not public?
- What privacy rules govern visitor telemetry?

Suggested headline:

`Security posture for the public-facing Ryan Codes stack`

Suggested supporting copy:

`This site explains how the public demo surface is isolated, what telemetry is visible to the visitor, and which controls are in place to keep the experience transparent without exposing private operational systems.`

### 2. Control Summary

Use short cards or rows for the main security pillars:

- Identity: least privilege, OIDC where possible, no embedded secrets in browser code.
- Network: CDN or edge front door, HTTPS-only, WAF, origin isolation.
- Secrets: no secrets committed, no secrets shipped to the browser, managed identity or secret store for backend needs.
- Monitoring: sanitized telemetry, aggregate health signals, explicit retention limits.
- Delivery: validated CI/CD, environment separation, production changes through reviewed automation.

### 3. Public-Safe Architecture View

Show a simple diagram or schematic for:

- Static front-end
- Edge or CDN layer
- Minimal request-context API
- Sanitized telemetry pipeline
- Separate private operational platform

The diagram should make the boundary obvious: the public security site can talk
about the private platform, but it must not share its secrets, data stores, or
administrative control plane.

### 4. Transparency Panel

This is the differentiator. It should show the visitor a sanitized view of the
current request context in real time.

Recommended fields:

- Current public IP as seen by the edge or request-context API
- Approximate location at country or region level, and city only when confidence is reasonable
- Browser and platform derived from the user agent
- Request timestamp in UTC
- TLS status and protocol version when available
- Edge location or proxy region when available
- Session request ID for support or debugging

## Privacy Rules For The Transparency Panel

The transparency feature must stay public-safe and privacy-conscious.

Recommended rules:

- Show the visitor's current IP on screen, but do not persist raw IP longer than operationally necessary.
- If IP retention is needed for abuse prevention, store a salted hash plus a short TTL rather than the raw value.
- Keep approximate geolocation coarse by default. Country or region is enough for most visitors.
- Do not use third-party marketing trackers.
- Do not drop non-essential cookies.
- Keep raw request context out of long-lived analytics tables.
- Persist only aggregate counters for trend views, such as request counts by day or region bucket.
- State the retention window in plain language on the page.

Suggested retention posture:

- Raw request-context payload: memory only or less than 24 hours
- Hashed abuse-prevention key: 24 to 72 hours
- Aggregate public metrics: 30 to 90 days
- No permanent storage of full raw IP and user-agent pairs

## Recommended Technical Shape

### Front End

- Static site hosted on Azure Storage static website or Azure Static Web Apps
- Fronted by Azure Front Door for HTTPS, WAF, custom domain, and edge headers
- Separate domain and resource group from the private operational platform

### Request-Context API

- Minimal Azure Function or edge-compatible endpoint
- Returns only the sanitized request details needed by the transparency panel
- No access to private platform credentials or internal APIs
- No write path required except optional aggregate telemetry

### Telemetry Pipeline

- Application Insights or Log Analytics only if IP masking and retention settings are explicitly reviewed
- Prefer aggregate custom metrics over raw request event storage
- If a daily digest or public health view is added later, build it from sanitized aggregates only

### Identity And Access

- Use separate identities for deployment, telemetry query, and any backend maintenance
- Prefer GitHub OIDC or managed identity over long-lived secrets
- Keep contributor access narrow and time-bound

## Public Content Model

The site should include these sections:

1. Security posture summary
2. Public architecture and trust boundaries
3. Telemetry transparency and privacy rules
4. Public stack controls
5. Deployment and change-management approach
6. Frequently asked questions

Good FAQ examples:

- `Can this site see my IP address?`
- `How long is request data retained?`
- `Does this site use tracking cookies?`
- `Is this connected to the private operator platform?`
- `What security controls are implemented at the edge?`

## Suggested Visual Direction

Avoid a generic dark security aesthetic.

Use a clean, editorial layout with:

- Clear hierarchy
- Short paragraphs
- Architecture panels instead of buzzword-heavy hero copy
- Strong emphasis on boundary lines and retention policies
- Visible plain-language labels such as `Public`, `Private`, `Sanitized`, and `Not Stored`

## Implementation Guardrails

- Keep the domain public-facing but operationally isolated.
- Do not co-host it inside the private admin experience.
- Treat all telemetry shown on the page as public content.
- Review every field in the transparency response as if it will be screenshotted and shared.
- Prefer omission over over-sharing when confidence is low.

## Delivery Plan

### Phase 1

- Publish the static concept site with posture sections and trust-boundary diagrams.
- Add a static privacy and telemetry statement.

### Phase 2

- Add the live transparency panel backed by a minimal request-context API.
- Keep retention short and avoid raw telemetry persistence.

### Phase 3

- Add sanitized aggregate metrics such as daily request volume and coarse geography using a durable append-only history path rather than worker-only memory.
- Track monitored availability through externally recorded health checks so the site can show recent uptime history without exposing raw operational telemetry.
- Keep the health digest aggregate-only: recent pass or fail checks, availability percentage, and last-success timestamps are enough.

## Success Criteria

- A hiring manager can understand the site's security posture in under three minutes.
- A technical reviewer can see the separation between public and private systems immediately.
- The transparency panel is informative without becoming invasive.
- No production secret, tenant identifier, or raw operational payload is exposed.
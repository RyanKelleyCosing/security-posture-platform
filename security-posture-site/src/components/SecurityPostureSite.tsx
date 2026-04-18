import { useEffect, useMemo, useState } from "react";

import {
  fetchPublicRequestContext,
  fetchPublicTrafficMetricsSummary,
  getPublicTrafficSessionId,
  recordPublicTrafficEvent,
  type PublicHealthCheckDigestItem,
  type PublicMetricCount,
  type PublicRequestContextPayload,
  type PublicTrafficMetricsSummary,
} from "../api/publicTrafficApi";
import {
  securityArchitectureCards,
  securityBoundaryRules,
  securityControlCards,
  securityFaqItems,
  securityHeroHighlights,
  securityRetentionWindows,
} from "../data/securitySiteContent";

type BrowserContextSnapshot = {
  browser: string;
  capturedAtUtc: string;
  language: string;
  platform: string;
  route: string;
  secureContext: string;
  timeZone: string;
};

type PublicApiLoadState = "error" | "idle" | "loading" | "ready" | "unavailable";

const defaultGithubUrl = "https://github.com/RyanKelleyCosing";
const homeHash = "#/";
const walkthroughHash = "#/simulation";

function detectBrowser(userAgent: string): string {
  if (userAgent.includes("Edg/")) {
    return "Microsoft Edge";
  }

  if (userAgent.includes("Chrome/")) {
    return "Google Chrome";
  }

  if (userAgent.includes("Firefox/")) {
    return "Mozilla Firefox";
  }

  if (userAgent.includes("Safari/") && !userAgent.includes("Chrome/")) {
    return "Safari";
  }

  return "Browser detected from user agent";
}

function detectPlatform(userAgent: string): string {
  if (userAgent.includes("Windows")) {
    return "Windows";
  }

  if (userAgent.includes("Mac OS X")) {
    return "macOS";
  }

  if (userAgent.includes("Linux")) {
    return "Linux";
  }

  if (userAgent.includes("Android")) {
    return "Android";
  }

  if (userAgent.includes("iPhone") || userAgent.includes("iPad")) {
    return "iOS";
  }

  return "Platform inferred in browser";
}

function buildBrowserContextSnapshot(): BrowserContextSnapshot {
  const userAgent = navigator.userAgent || "";
  const route = `${window.location.pathname}${window.location.hash}`;

  return {
    browser: detectBrowser(userAgent),
    capturedAtUtc: new Date().toISOString(),
    language: navigator.language || "Unknown",
    platform: detectPlatform(userAgent),
    route,
    secureContext: window.isSecureContext ? "Secure context" : "Not secure",
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone || "Unknown",
  };
}

function formatCountLabel(
  value: number,
  singularLabel: string,
  pluralLabel: string,
): string {
  return `${value} ${value === 1 ? singularLabel : pluralLabel}`;
}

function formatAggregateCounts(
  items: ReadonlyArray<PublicMetricCount>,
  fallbackValue: string,
): string {
  if (items.length === 0) {
    return fallbackValue;
  }

  return items.map((item) => `${item.label} (${item.count})`).join(" · ");
}

function formatAvailabilityMetric(summary: PublicTrafficMetricsSummary | null): string {
  if (!summary) {
    return "Awaiting monitored history";
  }

  if (summary.availability_percentage == null) {
    return summary.current_status;
  }

  return `${summary.current_status} · ${summary.availability_percentage.toFixed(1)}%`;
}

function formatRecentHealthChecks(
  items: ReadonlyArray<PublicHealthCheckDigestItem>,
  fallbackValue: string,
): string {
  if (items.length === 0) {
    return fallbackValue;
  }

  return items
    .map((item) => `${item.checked_at_utc} · ${item.overall_ok ? "Healthy" : "Degraded"} · ${item.note}`)
    .join(" | ");
}

function formatRelativeAgeLabel(totalMinutes: number): string {
  if (totalMinutes <= 0) {
    return "just now";
  }

  if (totalMinutes < 60) {
    return formatCountLabel(totalMinutes, "minute", "minutes") + " ago";
  }

  const totalHours = Math.round(totalMinutes / 60);
  if (totalHours < 48) {
    return formatCountLabel(totalHours, "hour", "hours") + " ago";
  }

  const totalDays = Math.round(totalHours / 24);
  return formatCountLabel(totalDays, "day", "days") + " ago";
}

function formatMonitorFreshness(summary: PublicTrafficMetricsSummary | null): string {
  const latestCheckAtUtc =
    summary?.recent_health_checks[0]?.checked_at_utc ||
    summary?.last_successful_health_check_at_utc;

  if (!latestCheckAtUtc) {
    return "No external health checks have been recorded yet.";
  }

  const checkedAt = new Date(latestCheckAtUtc);
  if (Number.isNaN(checkedAt.valueOf())) {
    return "Latest health-check timestamp is unavailable.";
  }

  const elapsedMinutes = Math.max(
    0,
    Math.round((Date.now() - checkedAt.valueOf()) / 60000),
  );
  const freshnessLabel =
    elapsedMinutes <= 45 ? "Current" : elapsedMinutes <= 90 ? "Delayed" : "Stale";

  return `${freshnessLabel} · checked ${formatRelativeAgeLabel(elapsedMinutes)}`;
}

function formatAlertReadiness(summary: PublicTrafficMetricsSummary | null): string {
  if (!summary || summary.latest_alert_configuration_ready == null) {
    return "Unknown until a persisted external verifier run reports SMTP readiness.";
  }

  return summary.latest_alert_configuration_ready
    ? "Ready for explicit alert-delivery checks"
    : "SMTP configuration incomplete";
}

export function SecurityPostureSite() {
  const [trafficSessionId] = useState(() => getPublicTrafficSessionId());
  const [browserContext, setBrowserContext] = useState(() =>
    buildBrowserContextSnapshot(),
  );
  const [requestContext, setRequestContext] = useState<PublicRequestContextPayload | null>(null);
  const [metricsSummary, setMetricsSummary] = useState<PublicTrafficMetricsSummary | null>(null);
  const [metricsLoadState, setMetricsLoadState] = useState<PublicApiLoadState>("idle");
  const [requestContextLoadState, setRequestContextLoadState] = useState<PublicApiLoadState>("idle");
  const [publicApiReloadToken, setPublicApiReloadToken] = useState(0);

  const githubUrl =
    import.meta.env.VITE_PUBLIC_GITHUB_URL?.trim() || defaultGithubUrl;
  const linkedinUrl = import.meta.env.VITE_PUBLIC_LINKEDIN_URL?.trim() || "";

  const browserSignals = useMemo(
    () => [
      {
        label: "Browser",
        note: "Client-derived now",
        value: browserContext.browser,
      },
      {
        label: "Platform",
        note: "Client-derived now",
        value: browserContext.platform,
      },
      {
        label: "Language",
        note: "Client-derived now",
        value: browserContext.language,
      },
      {
        label: "Time zone",
        note: "Client-derived now",
        value: browserContext.timeZone,
      },
      {
        label: "Route",
        note: "Client-derived now",
        value: browserContext.route,
      },
      {
        label: "Security context",
        note: "Client-derived now",
        value: browserContext.secureContext,
      },
    ],
    [browserContext],
  );

  const requestSignalNote =
    requestContextLoadState === "ready"
      ? "Server-derived now"
      : requestContextLoadState === "loading"
        ? "Loading isolated API"
        : "Request-context API fallback";

  const requestSignals = useMemo(
    () => [
      {
        label: "Public IP",
        note: requestSignalNote,
        value:
          requestContext?.client_ip ||
          "Available only while the live request-context API is connected.",
      },
      {
        label: "Approximate location",
        note: requestSignalNote,
        value:
          requestContext?.approximate_location ||
          "Unavailable until coarse edge geolocation headers are configured.",
      },
      {
        label: "Request timestamp",
        note: requestSignalNote,
        value: requestContext?.request_timestamp_utc || browserContext.capturedAtUtc,
      },
      {
        label: "Forwarded host",
        note: requestSignalNote,
        value: requestContext?.forwarded_host || "Not exposed in this build.",
      },
      {
        label: "TLS and edge region",
        note: requestSignalNote,
        value: requestContext
          ? `${requestContext.transport_security} · ${requestContext.tls_protocol} · ${requestContext.edge_region}`
          : "Expose only sanitized transport metadata that helps explain the request path.",
      },
      {
        label: "Support request ID",
        note: requestSignalNote,
        value:
          requestContext?.request_id ||
          "Generated only when the live request-context API responds.",
      },
    ],
    [browserContext.capturedAtUtc, requestContext, requestSignalNote],
  );

  const aggregateSignalNote =
    metricsLoadState === "ready"
      ? "Server-derived aggregate"
      : metricsLoadState === "loading"
        ? "Loading isolated API"
        : "Aggregate metrics fallback";

  const headlineMetrics = useMemo(
    () => [
      {
        detail: metricsSummary
          ? `${metricsSummary.collection_mode}. ${metricsSummary.collection_window}`
          : "Aggregate counts appear once the isolated public API base URL is connected.",
        label: "Aggregate traffic",
        value: metricsSummary
          ? formatCountLabel(metricsSummary.total_events, "public event", "public events")
          : "Aggregate summary pending",
      },
      {
        detail: metricsSummary
          ? `Observed across ${formatCountLabel(metricsSummary.unique_sessions, "session", "sessions")} in the retained aggregate history window.`
          : "Session totals appear once the aggregate summary route is connected.",
        label: "Observed sessions",
        value: metricsSummary
          ? formatCountLabel(metricsSummary.unique_sessions, "session", "sessions")
          : "Session counts pending",
      },
      {
        detail: metricsSummary
          ? `${metricsSummary.availability_source} · ${metricsSummary.availability_window}`
          : "Availability history appears once monitored health checks are persisted.",
        label: "Availability history",
        value: formatAvailabilityMetric(metricsSummary),
      },
    ],
    [metricsSummary],
  );

  const aggregateSignals = useMemo(
    () => [
      {
        label: "Collection mode",
        note: aggregateSignalNote,
        value:
          metricsSummary?.collection_mode ||
          "Process-local aggregate metrics appear when the isolated API is connected.",
      },
      {
        label: "Collection window",
        note: aggregateSignalNote,
        value:
          metricsSummary?.collection_window ||
          "Counts reset on cold start until durable sanitized history is added.",
      },
      {
        label: "Top routes",
        note: aggregateSignalNote,
        value: formatAggregateCounts(
          metricsSummary?.route_counts || [],
          "No public route counts have been recorded yet.",
        ),
      },
      {
        label: "Site modes",
        note: aggregateSignalNote,
        value: formatAggregateCounts(
          metricsSummary?.site_mode_counts || [],
          "No site mode counts have been recorded yet.",
        ),
      },
      {
        label: "Coarse geography",
        note: aggregateSignalNote,
        value: formatAggregateCounts(
          metricsSummary?.geography_counts || [],
          "Coarse geography buckets appear only after sanitized public events are recorded.",
        ),
      },
      {
        label: "Availability source",
        note: aggregateSignalNote,
        value: metricsSummary
          ? `${metricsSummary.availability_source} · ${metricsSummary.availability_window}`
          : "Monitored health history appears once external verification writes are available.",
      },
      {
        label: "Monitor freshness",
        note: aggregateSignalNote,
        value: formatMonitorFreshness(metricsSummary),
      },
      {
        label: "Probe cadence",
        note: aggregateSignalNote,
        value:
          "30-minute external availability probes via the deployed timer monitor, with an optional GitHub workflow companion.",
      },
      {
        label: "Monitor source",
        note: aggregateSignalNote,
        value:
          metricsSummary?.latest_monitor_name ||
          "Awaiting the first persisted external monitor run.",
      },
      {
        label: "Alert relay readiness",
        note: aggregateSignalNote,
        value: formatAlertReadiness(metricsSummary),
      },
      {
        label: "Recent health checks",
        note: aggregateSignalNote,
        value: formatRecentHealthChecks(
          metricsSummary?.recent_health_checks || [],
          "No monitored health checks have been recorded yet.",
        ),
      },
      {
        label: "Last successful health check",
        note: aggregateSignalNote,
        value:
          metricsSummary?.last_successful_health_check_at_utc ||
          "Waiting for the first successful monitored check.",
      },
      {
        label: "Last public event",
        note: aggregateSignalNote,
        value:
          metricsSummary?.last_event_at_utc ||
          "No public events have been aggregated in durable history yet.",
      },
    ],
    [aggregateSignalNote, metricsSummary],
  );

  const requestContextStatusMessage = useMemo(() => {
    if (requestContextLoadState === "ready") {
      return "Live request context is loaded from the isolated public API.";
    }

    if (requestContextLoadState === "loading") {
      return "Loading live request context from the isolated public API.";
    }

    if (requestContextLoadState === "error") {
      return "The request-context API did not respond. Browser-derived signals still render above.";
    }

    if (requestContextLoadState === "unavailable") {
      return "This build is not connected to a public API base URL yet, so the server-side panel is showing safe fallback values.";
    }

    return "The isolated request-context API is ready to populate this panel when connected.";
  }, [requestContextLoadState]);

  const metricsStatusMessage = useMemo(() => {
    if (metricsLoadState === "ready") {
      return "Live aggregate public metrics and monitored availability history are loaded from the isolated public API.";
    }

    if (metricsLoadState === "loading") {
      return "Loading aggregate public metrics from the isolated public API.";
    }

    if (metricsLoadState === "error") {
      return "The aggregate metrics API did not respond. Static posture and live request context still render above.";
    }

    if (metricsLoadState === "unavailable") {
      return "This build is not connected to a public API base URL yet, so the aggregate telemetry panel is showing safe fallback values.";
    }

    return "The aggregate-only metrics and monitored availability API is ready to populate this panel when connected.";
  }, [metricsLoadState]);

  const profileLinks = [
    {
      href: githubUrl,
      label: "GitHub",
      note: "Source repos and implementation details.",
    },
    ...(linkedinUrl
      ? [
          {
            href: linkedinUrl,
            label: "LinkedIn",
            note: "Profile, experience, and role history.",
          },
        ]
      : []),
  ];

  useEffect(() => {
    void recordPublicTrafficEvent({
      event_type: "page_view",
      page_title: "Security posture site",
      referrer: document.referrer || undefined,
      route: "security",
      session_id: trafficSessionId,
      site_mode: "security",
    });
  }, [trafficSessionId]);

  useEffect(() => {
    let isCancelled = false;

    const loadPublicApiState = async () => {
      setMetricsLoadState("loading");
      setRequestContextLoadState("loading");

      const [requestContextResult, metricsSummaryResult] = await Promise.allSettled([
        fetchPublicRequestContext(),
        fetchPublicTrafficMetricsSummary(),
      ]);

      if (isCancelled) {
        return;
      }

      if (requestContextResult.status === "fulfilled") {
        if (requestContextResult.value === null) {
          setRequestContext(null);
          setRequestContextLoadState("unavailable");
        } else {
          setRequestContext(requestContextResult.value);
          setRequestContextLoadState("ready");
        }
      } else {
        console.warn(
          "Unable to load public request context.",
          requestContextResult.reason,
        );
        setRequestContext(null);
        setRequestContextLoadState("error");
      }

      if (metricsSummaryResult.status === "fulfilled") {
        if (metricsSummaryResult.value === null) {
          setMetricsSummary(null);
          setMetricsLoadState("unavailable");
        } else {
          setMetricsSummary(metricsSummaryResult.value);
          setMetricsLoadState("ready");
        }
      } else {
        console.warn(
          "Unable to load aggregate public metrics.",
          metricsSummaryResult.reason,
        );
        setMetricsSummary(null);
        setMetricsLoadState("error");
      }
    };

    void loadPublicApiState();

    return () => {
      isCancelled = true;
    };
  }, [publicApiReloadToken]);

  return (
    <div className="app-shell security-shell">
      <header className="hero hero-wide security-hero">
        <div className="security-hero-copy">
          <p className="eyebrow">Public-facing security posture</p>
          <h1>Security posture for the Ryan Codes public stack.</h1>
          <p className="hero-copy security-hero-text">
            This prototype turns the security concept into a browsable public surface.
            It explains the trust boundary between the public demo stack and the
            private operator platform, shows what telemetry is intentionally visible,
            and makes the retention rules explicit instead of implied.
          </p>
          <div className="hero-actions">
            <a className="button-link" href={homeHash}>
              Back to public landing
            </a>
            <a className="button-link secondary-link" href={walkthroughHash}>
              Open workflow walkthrough
            </a>
          </div>
          <ul className="chip-list public-chip-list" aria-label="security posture highlights">
            {securityHeroHighlights.map((item) => (
              <li className="reason-chip" key={item}>
                {item}
              </li>
            ))}
          </ul>
        </div>

        <div className="hero-panel security-status-panel">
          <span>Why this exists</span>
          <strong>Transparent controls without exposing private systems</strong>
          <div className="security-status-grid">
            <div className="workspace-subcard">
              <small>Public</small>
              <strong>Architecture, controls, retention rules</strong>
              <span>Readable by hiring managers and technical reviewers.</span>
            </div>
            <div className="workspace-subcard">
              <small>Sanitized</small>
              <strong>Request context and aggregate health</strong>
              <span>Only the fields the visitor can safely see on screen.</span>
            </div>
            <div className="workspace-subcard">
              <small>Private</small>
              <strong>Operator systems and secrets stay separate</strong>
              <span>No tenant IDs, admin endpoints, or secret-bearing paths.</span>
            </div>
          </div>
          <div className="profile-link-list">
            {profileLinks.map((link) => (
              <a
                className="profile-link-card"
                href={link.href}
                key={link.label}
                rel="noreferrer"
                target="_blank"
              >
                <strong>{link.label}</strong>
                <p>{link.note}</p>
              </a>
            ))}
          </div>
        </div>
      </header>

      <section className="metrics-grid" aria-label="security posture metrics">
        {headlineMetrics.map((metric) => (
          <article className="metric-card" key={metric.label}>
            <span>{metric.label}</span>
            <strong>{metric.value}</strong>
            <p className="metric-detail">{metric.detail}</p>
          </article>
        ))}
      </section>

      <section className="queue-column section-stack security-section" aria-labelledby="security-architecture-heading">
        <div className="section-heading">
          <h2 id="security-architecture-heading">Public-safe architecture view</h2>
          <p>
            The static site, edge, request-context API, and private operator plane each
            serve a different role. The important part is the separation, not the buzzwords.
          </p>
        </div>
        <div className="showcase-grid security-architecture-grid">
          {securityArchitectureCards.map((card) => (
            <article className="surface-card section-stack security-architecture-card" key={card.title}>
              <p className="queue-card-label">{card.eyebrow}</p>
              <h3>{card.title}</h3>
              <p className="mini-card-copy">{card.copy}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="workbench-layout security-grid" aria-label="security details">
        <div className="queue-column simulation-main public-main section-stack">
          <div className="section-heading">
            <h2>Control summary</h2>
            <p>
              The point is to show engineering judgment clearly: who gets access,
              what is exposed, what is retained, and what never crosses the public boundary.
            </p>
          </div>
          <div className="showcase-grid security-control-grid">
            {securityControlCards.map((card) => (
              <article className="surface-card section-stack" key={card.title}>
                <p className="queue-card-label">{card.eyebrow}</p>
                <h3>{card.title}</h3>
                <p className="mini-card-copy">{card.copy}</p>
              </article>
            ))}
          </div>

          <div className="surface-card section-stack security-transparency-panel">
            <div className="section-heading-row">
              <div className="section-heading">
                <h2>Transparency panel prototype</h2>
                <p>
                  This phase shows the browser-derived fields now and the live server-derived
                  fields returned by the isolated request-context API whenever the public API
                  base URL is connected.
                </p>
              </div>
              <button
                className="secondary-button"
                onClick={() => {
                  setBrowserContext(buildBrowserContextSnapshot());
                  setPublicApiReloadToken((currentValue) => currentValue + 1);
                }}
                type="button"
              >
                Refresh live snapshot
              </button>
            </div>

            <div className="security-transparency-grid">
              <article className="workspace-card section-stack">
                <p className="queue-card-label">Visible in browser now</p>
                <div className="workspace-field-list">
                  {browserSignals.map((signal) => (
                    <div className="workspace-field-row" key={signal.label}>
                      <small>{signal.note}</small>
                      <strong>{signal.label}</strong>
                      <span>{signal.value}</span>
                    </div>
                  ))}
                </div>
              </article>

              <article className="workspace-card section-stack">
                <p className="queue-card-label">Live request-context API</p>
                <p className="workspace-caption">{requestContextStatusMessage}</p>
                <div className="workspace-field-list">
                  {requestSignals.map((signal) => (
                    <div className="workspace-field-row" key={signal.label}>
                      <small>{signal.note}</small>
                      <strong>{signal.label}</strong>
                      <span>{signal.value}</span>
                    </div>
                  ))}
                </div>
              </article>
            </div>
          </div>

          <div className="showcase-grid security-boundary-grid">
            {securityBoundaryRules.map((rule) => (
              <article className="surface-card section-stack" key={rule.title}>
                <h3>{rule.title}</h3>
                <div className="security-rule-row">
                  <p className="queue-card-label">Allowed</p>
                  <p className="mini-card-copy">{rule.allow}</p>
                </div>
                <div className="security-rule-row">
                  <p className="queue-card-label">Blocked</p>
                  <p className="mini-card-copy">{rule.block}</p>
                </div>
              </article>
            ))}
          </div>
        </div>

        <aside className="operations-panel simulation-aside public-aside section-stack">
          <div className="section-heading">
            <h2>Privacy posture</h2>
            <p>
              The security site should make collection limits obvious, not bury them in a policy footer.
            </p>
          </div>
          <ul className="operations-list compact-rule-list">
            <li>No third-party marketing trackers.</li>
            <li>No non-essential cookies in the public security surface.</li>
            <li>No permanent storage of raw IP and browser pairs.</li>
            <li>Aggregate telemetry only after fields have been sanitized.</li>
            <li>Every displayed field is treated as public content by default.</li>
          </ul>

          <article className="workspace-card section-stack">
            <p className="queue-card-label">Sanitized aggregate public metrics</p>
            <p className="workspace-caption">{metricsStatusMessage}</p>
            <div className="workspace-field-list">
              {aggregateSignals.map((signal) => (
                <div className="workspace-field-row" key={signal.label}>
                  <small>{signal.note}</small>
                  <strong>{signal.label}</strong>
                  <span>{signal.value}</span>
                </div>
              ))}
            </div>
          </article>

          <div className="section-heading">
            <h2>Retention windows</h2>
          </div>
          <div className="timeline-list">
            {securityRetentionWindows.map((item, index) => (
              <article className="timeline-card" key={item.title}>
                <div className="timeline-marker" data-state={index === 0 ? "active" : "complete"} />
                <div>
                  <p className="queue-card-label">{item.window}</p>
                  <h3>{item.title}</h3>
                  <p className="mini-card-copy">{item.copy}</p>
                </div>
              </article>
            ))}
          </div>
        </aside>
      </section>

      <section className="queue-column section-stack security-section" aria-labelledby="security-faq-heading">
        <div className="section-heading">
          <h2 id="security-faq-heading">Frequently asked questions</h2>
          <p>
            The answers stay intentionally direct so a hiring manager or reviewer can understand the posture quickly.
          </p>
        </div>
        <div className="showcase-grid security-faq-grid">
          {securityFaqItems.map((item) => (
            <article className="surface-card section-stack" key={item.question}>
              <h3>{item.question}</h3>
              <p className="mini-card-copy">{item.answer}</p>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
import { useEffect, useMemo, useState } from "react";

import { DEMO_PATH, HOME_PATH, navigateToAppPath } from "../appRoutes";
import {
  fetchPublicHealth,
  fetchPublicRequestContext,
  fetchPublicSecurityCveFeed,
  fetchPublicSecurityMsrcFeed,
  fetchPublicTrafficMetricsSummary,
  getPublicTrafficSessionId,
  recordPublicTrafficEvent,
  type PublicHealthCheckDigestItem,
  type PublicHealthStatus,
  type PublicMetricCount,
  type PublicRecentActivityItem,
  type PublicRequestContextPayload,
  type PublicSecurityCveFeed,
  type PublicSecurityMsrcFeed,
  type PublicTrafficCadencePoint,
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
import {
  nistCsf2,
  nistSp80053Highlights,
  owaspTop10,
} from "../data/securityStandards";
import {
  formatAlertReadiness,
  formatCountLabel,
  formatMonitorFreshness,
  formatProviderFieldValue,
  formatRelativeAgeFromIso,
  formatRelativeAgeLabel,
  formatSlugLabel,
  formatUtcDateTimeLabel,
} from "./securityPostureFormatters";
import { getFeatureFlag } from "../featureFlags";
import { PublicSiteLayout } from "./PublicSiteLayout";
import { SecurityTelemetryGlobe } from "./SecurityTelemetryGlobe";
import {
  SectionHeading,
  StatusBadge,
  SurfaceBarRow,
  SurfaceCard,
  SurfaceColumnChart,
  SurfaceDrawer,
  SurfaceMetricCard,
  SurfacePanel,
  SurfaceTable,
  SurfaceTableFrame,
  SurfaceTimelineItem,
  type StatusBadgeTone,
} from "./SurfacePrimitives";

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

function formatLoadStateLabel(loadState: PublicApiLoadState): string {
  return `${loadState.charAt(0).toUpperCase()}${loadState.slice(1)}`;
}

function getLoadStateTone(loadState: PublicApiLoadState): StatusBadgeTone {
  switch (loadState) {
    case "ready":
      return "success";
    case "loading":
      return "accent";
    case "unavailable":
      return "warning";
    case "error":
      return "danger";
    case "idle":
    default:
      return "neutral";
  }
}

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

function formatAggregateCounts(
  items: ReadonlyArray<PublicMetricCount>,
  fallbackValue: string,
): string {
  if (items.length === 0) {
    return fallbackValue;
  }

  return items.map((item) => `${item.label} (${item.count})`).join(" · ");
}

function getMetricCountColumnHeight(
  items: ReadonlyArray<PublicMetricCount>,
  count: number,
) {
  const maxCount = Math.max(...items.map((item) => item.count), 0);
  if (maxCount <= 0) {
    return 0;
  }

  return Math.max(18, Math.round((count / maxCount) * 100));
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

function formatRouteLabel(route: string): string {
  switch (route) {
    case "home":
      return "Overview";
    case "simulation":
    case "demo":
      return "Demo";
    default:
      return formatSlugLabel(route);
  }
}

function formatSiteModeLabel(siteMode: string): string {
  return siteMode === "security" ? "Security surface" : "Demo surface";
}

function getCadenceFillWidth(
  items: ReadonlyArray<PublicTrafficCadencePoint>,
  count: number,
) {
  const maxCount = Math.max(...items.map((item) => item.count), 0);
  if (maxCount <= 0) {
    return 0;
  }

  return Math.max(14, Math.round((count / maxCount) * 100));
}

function buildTrafficCadenceCsvHref(
  items: ReadonlyArray<PublicTrafficCadencePoint>,
): string {
  const escape = (value: string) => `"${value.replace(/"/g, '""')}"`;
  const header = "bucket_started_at_utc,label,count";
  const rows = items.map(
    (item) => `${escape(item.bucket_started_at_utc)},${escape(item.label)},${item.count}`,
  );
  const csv = [header, ...rows].join("\n");
  return `data:text/csv;charset=utf-8,${encodeURIComponent(csv)}`;
}

function buildRecentActivityCsvHref(
  items: ReadonlyArray<PublicRecentActivityItem>,
): string {
  const escape = (value: string) => `"${value.replace(/"/g, '""')}"`;
  const header = "recorded_at_utc,route,site_mode,geography_bucket,session_label";
  const rows = items.map(
    (item) =>
      `${escape(item.recorded_at_utc)},${escape(item.route)},${escape(item.site_mode)},${escape(item.geography_bucket)},${escape(item.session_label)}`,
  );
  const csv = [header, ...rows].join("\n");
  return `data:text/csv;charset=utf-8,${encodeURIComponent(csv)}`;
}

function getRecentActivityTone(siteMode: string): StatusBadgeTone {
  return siteMode === "security" ? "accent" : "warning";
}

function getHealthCheckTone(overallOk: boolean): StatusBadgeTone {
  return overallOk ? "success" : "danger";
}

function getHealthCheckMarkerState(
  item: PublicHealthCheckDigestItem,
  index: number,
): "active" | "complete" | "queued" {
  if (!item.overall_ok) {
    return "queued";
  }

  return index === 0 ? "active" : "complete";
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
  const [freshnessTickMs, setFreshnessTickMs] = useState(() => Date.now());
  const [healthStatus, setHealthStatus] = useState<PublicHealthStatus | null>(null);
  const [cveFeed, setCveFeed] = useState<PublicSecurityCveFeed | null>(null);
  const [cveFeedLoadState, setCveFeedLoadState] = useState<PublicApiLoadState>("idle");
  const [msrcFeed, setMsrcFeed] = useState<PublicSecurityMsrcFeed | null>(null);
  const [msrcFeedLoadState, setMsrcFeedLoadState] = useState<PublicApiLoadState>("idle");

  useEffect(() => {
    let isCancelled = false;

    const probeHealth = async () => {
      const nextStatus = await fetchPublicHealth();
      if (!isCancelled) {
        setHealthStatus(nextStatus);
      }
    };

    void probeHealth();

    const rawPollMs = Number.parseInt(
      import.meta.env.VITE_PUBLIC_HEALTH_POLL_MS_SECURITY
        ?? import.meta.env.VITE_PUBLIC_HEALTH_POLL_MS
        ?? "",
      10,
    );
    const pollMs = Number.isFinite(rawPollMs) && rawPollMs > 0 ? rawPollMs : 60_000;
    const intervalId = window.setInterval(probeHealth, pollMs);

    return () => {
      isCancelled = true;
      window.clearInterval(intervalId);
    };
  }, []);

  useEffect(() => {
    const generatedAt = metricsSummary?.generated_at_utc;
    if (!generatedAt) {
      return;
    }

    const intervalId = window.setInterval(() => {
      setFreshnessTickMs(Date.now());
    }, 15_000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [metricsSummary?.generated_at_utc]);

  const globeFreshnessLabel = useMemo(() => {
    const generatedAt = metricsSummary?.generated_at_utc;
    if (!generatedAt) {
      return null;
    }

    const parsedValue = new Date(generatedAt);
    if (Number.isNaN(parsedValue.valueOf())) {
      return null;
    }

    const elapsedMinutes = Math.max(
      0,
      Math.round((freshnessTickMs - parsedValue.valueOf()) / 60_000),
    );
    return `Updated ${formatRelativeAgeLabel(elapsedMinutes)}`;
  }, [freshnessTickMs, metricsSummary?.generated_at_utc]);

  const linkedinUrl = import.meta.env.VITE_PUBLIC_LINKEDIN_URL?.trim() || "";
  const securityEnrichmentEnabled =
    requestContext?.public_network_enrichment_enabled ??
    getFeatureFlag("publicSecurityEnrichmentEnabled");
  const securityGlobeEnabled =
    requestContext?.public_security_globe_enabled ??
    getFeatureFlag("publicSecurityGlobeEnabled");
  const liveVisitorTraceDescription = securityEnrichmentEnabled
    ? "Current visitor trace stays telemetry-first: browser-derived route and fingerprint context, live request metadata from the isolated API, and an explicit statement about which enrichment still remains intentionally unavailable."
    : "Current visitor trace stays telemetry-first: browser-derived route and fingerprint context, live request metadata from the isolated API, and an explicit statement about what remains outside the public boundary."

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

  const requestSignals = useMemo(() => {
    const hasAnyProviderSignal = Boolean(
      requestContext?.network_asn ||
        requestContext?.network_owner ||
        requestContext?.hosting_provider ||
        requestContext?.vpn_proxy_status ||
        requestContext?.reputation_summary,
    );    const providerSignals =
      securityEnrichmentEnabled && hasAnyProviderSignal
        ? [
          {
            label: "Network ASN",
            note: requestSignalNote,
            value: formatProviderFieldValue(requestContext?.network_asn, requestContext),
          },
          {
            label: "Network owner",
            note: requestSignalNote,
            value: formatProviderFieldValue(requestContext?.network_owner, requestContext),
          },
          {
            label: "Hosting or transit provider",
            note: requestSignalNote,
            value: formatProviderFieldValue(requestContext?.hosting_provider, requestContext),
          },
          {
            label: "VPN / proxy hint",
            note: requestSignalNote,
            value: formatProviderFieldValue(requestContext?.vpn_proxy_status, requestContext),
          },
          {
            label: "Reputation summary",
            note: requestSignalNote,
            value: formatProviderFieldValue(requestContext?.reputation_summary, requestContext),
          },
        ]
      : [];

    return [
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
          "Unavailable until the Function App is configured with the DOCINT_PUBLIC_NETWORK_ENRICHMENT_PROVIDER and DOCINT_PUBLIC_NETWORK_ENRICHMENT_API_KEY app settings (then redeployed).",
      },
      ...providerSignals,
      {
        label: "Forwarded host",
        note: requestSignalNote,
        value: requestContext?.forwarded_host || "Not exposed in this build.",
      },
      {
        label: "Forwarded protocol",
        note: requestSignalNote,
        value: requestContext?.forwarded_proto || "Unavailable until edge headers are present.",
      },
      {
        label: "Edge region",
        note: requestSignalNote,
        value:
          requestContext?.edge_region ||
          "Expose only sanitized edge hints that help explain the request path.",
      },
      {
        label: "Transport security",
        note: requestSignalNote,
        value:
          requestContext?.transport_security ||
          "Transport classification appears when the request-context API responds.",
      },
      {
        label: "TLS hint",
        note: requestSignalNote,
        value:
          requestContext?.tls_protocol ||
          "TLS detail appears when the request-context API responds.",
      },
      {
        label: "Request timestamp",
        note: requestSignalNote,
        value: requestContext?.request_timestamp_utc || browserContext.capturedAtUtc,
      },
      {
        label: "Support request ID",
        note: requestSignalNote,
        value:
          requestContext?.request_id ||
          "Generated only when the live request-context API responds.",
      },
    ];
  }, [
    browserContext.capturedAtUtc,
    requestContext,
    requestSignalNote,
    securityEnrichmentEnabled,
  ]);

  const currentVisitorBoundarySignals = useMemo(() => {
    const providerSignals = securityEnrichmentEnabled
      ? [
          {
            label: "Provider source",
            note: requestSignalNote,
            value:
              requestContext?.enrichment_provider_name ||
              "No provider-backed enrichment feed is configured on this host.",
          },
          {
            label: "Provider-backed enrichment",
            note: requestSignalNote,
            value:
              requestContext?.enrichment_status ||
              "Provider-backed enrichment appears only when the isolated request-context API is connected.",
          },
        ]
      : [];

    return [
      {
        label: "Edge path",
        note: requestSignalNote,
        value: requestContext
          ? `${requestContext.forwarded_proto.toUpperCase()} · ${requestContext.forwarded_host} · ${requestContext.edge_region}`
          : "Edge path stays public-safe and appears once the live request-context API responds.",
      },
      {
        label: "Browser fingerprint summary",
        note: "Client-derived now",
        value: `${browserContext.browser} · ${browserContext.platform} · ${browserContext.language} · ${browserContext.timeZone}`,
      },
      {
        label: "Route trail",
        note: "Client-derived now",
        value: browserContext.route,
      },
      ...providerSignals,
      {
        label: "Retention class",
        note: "Safety boundary",
        value:
          "Current visitor trace stays short-lived; only sanitized aggregate counts and monitor history persist beyond the session.",
      },
      {
        label: "Short-lived feed scope",
        note: "Worker-local only",
        value:
          metricsSummary?.recent_activity_window ||
          "Recent-session feed appears when the public metrics route is connected.",
      },
    ];
  }, [
    browserContext.browser,
    browserContext.language,
    browserContext.platform,
    browserContext.route,
    browserContext.timeZone,
    metricsSummary?.recent_activity_window,
    requestContext,
    requestSignalNote,
    securityEnrichmentEnabled,
  ]);

  const aggregateSignalNote =
    metricsLoadState === "ready"
      ? "Server-derived aggregate"
      : metricsLoadState === "loading"
        ? "Loading isolated API"
        : "Aggregate metrics fallback";

  const headlineMetrics = useMemo(
    () => {
      const topRoute = metricsSummary?.route_counts[0] ?? null;
      const latestEventAtUtc = metricsSummary?.last_event_at_utc ?? null;

      return [
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
        {
          detail: topRoute
            ? `${formatCountLabel(topRoute.count, "event", "events")} retained on this route.`
            : "Route leaders appear after sanitized public events are retained.",
          label: "Top route",
          value: topRoute ? formatRouteLabel(topRoute.label) : "Route mix pending",
        },
        {
          detail: latestEventAtUtc
            ? `Received ${formatUtcDateTimeLabel(latestEventAtUtc)} UTC in sanitized history.`
            : "Waiting for the first retained public event timestamp.",
          label: "Latest event",
          value: latestEventAtUtc
            ? formatRelativeAgeFromIso(latestEventAtUtc)
            : "No event yet",
        },
      ];
    },
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

  const recentActivityFeed = metricsSummary?.recent_activity || [];
  const trafficCadence = metricsSummary?.traffic_cadence || [];
  const uptimeHistory = metricsSummary?.recent_health_checks || [];

  const trafficDistributionGroups = useMemo(
    () => [
      {
        description:
          "Which public routes are actually receiving traffic inside the retained aggregate window.",
        emptyState:
          "Route distributions appear after the first sanitized public events are retained.",
        items: metricsSummary?.route_counts || [],
        title: "Route mix",
        tone: "accent" as const,
      },
      {
        description:
          "How the retained event history splits between informational, demo, and security-facing site modes.",
        emptyState:
          "Site-mode buckets appear after the isolated public API records retained events.",
        items: metricsSummary?.site_mode_counts || [],
        title: "Site mode mix",
        tone: "warning" as const,
      },
      {
        description:
          "Coarse geography buckets remain intentionally broad, but they are still easier to scan as a retained distribution.",
        emptyState:
          "Geography buckets appear once sanitized public events have been retained.",
        items: metricsSummary?.geography_counts || [],
        title: "Geography mix",
        tone: "success" as const,
      },
    ],
    [metricsSummary],
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

  const profileLinks = linkedinUrl
    ? [
        {
          href: linkedinUrl,
          label: "LinkedIn",
          note: "Profile, experience, and role history.",
        },
      ]
    : [];

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

  useEffect(() => {
    let isCancelled = false;

    const loadSecurityFeeds = async () => {
      setCveFeedLoadState("loading");
      setMsrcFeedLoadState("loading");

      const [cveResult, msrcResult] = await Promise.allSettled([
        fetchPublicSecurityCveFeed(),
        fetchPublicSecurityMsrcFeed(),
      ]);

      if (isCancelled) {
        return;
      }

      if (cveResult.status === "fulfilled") {
        if (cveResult.value === null) {
          setCveFeed(null);
          setCveFeedLoadState("unavailable");
        } else {
          setCveFeed(cveResult.value);
          setCveFeedLoadState("ready");
        }
      } else {
        console.warn("Unable to load public CVE feed.", cveResult.reason);
        setCveFeed(null);
        setCveFeedLoadState("error");
      }

      if (msrcResult.status === "fulfilled") {
        if (msrcResult.value === null) {
          setMsrcFeed(null);
          setMsrcFeedLoadState("unavailable");
        } else {
          setMsrcFeed(msrcResult.value);
          setMsrcFeedLoadState("ready");
        }
      } else {
        console.warn("Unable to load public MSRC feed.", msrcResult.reason);
        setMsrcFeed(null);
        setMsrcFeedLoadState("error");
      }
    };

    void loadSecurityFeeds();

    return () => {
      isCancelled = true;
    };
  }, [publicApiReloadToken]);

  return (
    <PublicSiteLayout activeRoute="security" className="security-shell">
      <header className="hero hero-wide security-hero">
        <div className="security-hero-copy">
          <p className="eyebrow">Public-facing security posture</p>
          <h1>Security posture for the Ryan Codes public stack.</h1>
          {healthStatus ? (
            <p
              aria-live="polite"
              className={`landing-live-status landing-live-status-${healthStatus.status}`}
            >
              <span aria-hidden="true" className="landing-live-status-dot" />
              {healthStatus.status === "online"
                ? `Public API online · ${healthStatus.latencyMs ?? "?"} ms`
                : healthStatus.status === "degraded"
                  ? "Public API degraded · retrying"
                  : "Public API unreachable · retrying"}
            </p>
          ) : null}
          <p className="hero-copy security-hero-text">
            This prototype turns the security concept into a browsable public surface.
            It explains the trust boundary between the public demo stack and the
            private operator platform, shows what telemetry is intentionally visible,
            and now separates short-lived visitor trace detail from durable sanitized
            aggregate history instead of collapsing everything into one summary.
          </p>
          <div className="hero-actions">
            <a
              className="button-link"
              href={HOME_PATH}
              onClick={(event) => {
                event.preventDefault();
                navigateToAppPath(HOME_PATH);
              }}
            >
              Back to public landing
            </a>
            <a
              className="button-link secondary-link"
              href={DEMO_PATH}
              onClick={(event) => {
                event.preventDefault();
                navigateToAppPath(DEMO_PATH);
              }}
            >
              Open workflow walkthrough
            </a>
            <a
              className="button-link secondary-link security-hero-source"
              href="https://github.com/RyanKelleyCosing"
              rel="noreferrer"
              target="_blank"
            >
              Source & architecture on GitHub ↗
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
            <SurfaceCard as="div" className="workspace-subcard">
              <StatusBadge tone="accent">Public</StatusBadge>
              <strong>Architecture, controls, retention rules</strong>
              <span>Readable by hiring managers and technical reviewers.</span>
            </SurfaceCard>
            <SurfaceCard as="div" className="workspace-subcard">
              <StatusBadge tone="success">Sanitized</StatusBadge>
              <strong>Request context and aggregate health</strong>
              <span>Only the fields the visitor can safely see on screen.</span>
            </SurfaceCard>
            <SurfaceCard as="div" className="workspace-subcard">
              <StatusBadge tone="neutral">Private</StatusBadge>
              <strong>Operator systems and secrets stay separate</strong>
              <span>No tenant IDs, admin endpoints, or secret-bearing paths.</span>
            </SurfaceCard>
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

      <section className="metrics-grid security-metrics-grid" aria-label="security posture metrics">
        {headlineMetrics.map((metric) => (
          <SurfaceMetricCard
            as="article"
            className="metric-card"
            detail={metric.detail}
            eyebrow={metric.label}
            key={metric.label}
            value={metric.value}
          />
        ))}
      </section>

      <section className="workbench-layout security-grid" aria-label="security details">
        <div className="queue-column simulation-main public-main section-stack">
          <SurfacePanel className="security-transparency-panel" id="security-transparency">
            <SectionHeading
              actions={
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
              }
              description={liveVisitorTraceDescription}
              title="Live visitor trace"
            />
            <div className="security-transparency-grid">
              <SurfaceCard>
                <div className="mini-card-header">
                  <p className="queue-card-label">Live request context</p>
                  <StatusBadge tone={getLoadStateTone(requestContextLoadState)}>
                    {formatLoadStateLabel(requestContextLoadState)}
                  </StatusBadge>
                </div>
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
                {securityEnrichmentEnabled &&
                (requestContext?.network_asn ||
                  requestContext?.network_owner ||
                  requestContext?.hosting_provider ||
                  requestContext?.vpn_proxy_status ||
                  requestContext?.reputation_summary) ? (
                  <p className="workspace-caption security-provider-attribution">
                    Provider signals (ASN, hosting, VPN/proxy, reputation) sourced from{" "}
                    <a
                      href="https://www.ipqualityscore.com/"
                      rel="noreferrer"
                      target="_blank"
                    >
                      {requestContext?.enrichment_provider_name || "IPQualityScore"}
                    </a>
                    .
                  </p>
                ) : null}
              </SurfaceCard>

              <SurfaceCard>
                <div className="mini-card-header">
                  <p className="queue-card-label">Browser and route fingerprint</p>
                  <StatusBadge tone="neutral">Browser snapshot</StatusBadge>
                </div>
                <div className="workspace-field-list">
                  {browserSignals.map((signal) => (
                    <div className="workspace-field-row" key={signal.label}>
                      <small>{signal.note}</small>
                      <strong>{signal.label}</strong>
                      <span>{signal.value}</span>
                    </div>
                  ))}
                </div>
              </SurfaceCard>

              <SurfaceCard>
                <div className="mini-card-header">
                  <p className="queue-card-label">
                    {securityEnrichmentEnabled
                      ? "Boundary and enrichment posture"
                      : "Boundary posture"}
                  </p>
                  <StatusBadge tone={securityEnrichmentEnabled ? "warning" : "neutral"}>
                    {securityEnrichmentEnabled ? "Bounded enrichment" : "Public boundary"}
                  </StatusBadge>
                </div>
                <div className="workspace-field-list">
                  {currentVisitorBoundarySignals.map((signal) => (
                    <div className="workspace-field-row" key={signal.label}>
                      <small>{signal.note}</small>
                      <strong>{signal.label}</strong>
                      <span>{signal.value}</span>
                    </div>
                  ))}
                </div>
              </SurfaceCard>
            </div>
          </SurfacePanel>

          <SurfacePanel id="security-cadence">
            <SectionHeading
              description="Short-lived recent-session detail stays worker-local while route mix, hourly cadence, and monitored uptime can remain durable once they have been reduced into sanitized aggregate history."
              title="Recent activity and cadence"
            />
            <div className="security-watch-grid">
              <SurfaceCard className="security-watch-card">
                <div className="mini-card-header">
                  <p className="queue-card-label">Recent public activity</p>
                  <div className="security-globe-card-badges">
                    <StatusBadge tone="accent">Short-lived feed</StatusBadge>
                    {recentActivityFeed.length > 0 ? (
                      <a
                        className="button-link secondary-link security-cadence-export-link"
                        download="public-security-recent-activity.csv"
                        href={buildRecentActivityCsvHref(recentActivityFeed)}
                      >
                        Export activity CSV
                      </a>
                    ) : null}
                  </div>
                </div>
                <p className="workspace-caption">
                  {metricsSummary?.recent_activity_window ||
                    "Recent-session activity appears only while the current worker lifetime still holds it in memory."}
                </p>
                {recentActivityFeed.length > 0 ? (
                  <SurfaceTableFrame className="security-recent-activity-table-frame">
                    <SurfaceTable className="security-recent-activity-table">
                      <thead>
                        <tr>
                          <th scope="col">When</th>
                          <th scope="col">Route</th>
                          <th scope="col">Mode</th>
                          <th scope="col">Geography</th>
                          <th scope="col">Session</th>
                        </tr>
                      </thead>
                      <tbody>
                        {recentActivityFeed.map((item, index) => (
                          <tr
                            data-active={index === 0 ? "true" : "false"}
                            key={`${item.recorded_at_utc}:${item.session_label}:${item.route}:${index}`}
                          >
                            <td>
                              <strong>{formatUtcDateTimeLabel(item.recorded_at_utc)}</strong>
                              <small>{formatRelativeAgeFromIso(item.recorded_at_utc)}</small>
                            </td>
                            <td>{formatRouteLabel(item.route)}</td>
                            <td>
                              <StatusBadge tone={getRecentActivityTone(item.site_mode)}>
                                {formatSiteModeLabel(item.site_mode)}
                              </StatusBadge>
                            </td>
                            <td>{item.geography_bucket}</td>
                            <td>{item.session_label}</td>
                          </tr>
                        ))}
                      </tbody>
                    </SurfaceTable>
                  </SurfaceTableFrame>
                ) : (
                  <p className="workspace-copy">
                    No short-lived visitor activity is available in the current worker lifetime yet.
                  </p>
                )}
              </SurfaceCard>

              <SurfaceCard className="security-watch-card">
                <div className="mini-card-header">
                  <p className="queue-card-label">Traffic cadence</p>
                  <div className="security-globe-card-badges">
                    {globeFreshnessLabel ? (
                      <StatusBadge tone="neutral" className="security-globe-freshness">
                        {globeFreshnessLabel}
                      </StatusBadge>
                    ) : null}
                    <StatusBadge tone={getLoadStateTone(metricsLoadState)}>
                      {formatLoadStateLabel(metricsLoadState)}
                    </StatusBadge>
                    {trafficCadence.length > 0 ? (
                      <a
                        className="button-link secondary-link security-cadence-export-link"
                        download="public-security-traffic-cadence.csv"
                        href={buildTrafficCadenceCsvHref(trafficCadence)}
                      >
                        Export CSV
                      </a>
                    ) : null}
                  </div>
                </div>
                <p className="workspace-caption">
                  {metricsSummary?.traffic_cadence_window ||
                    "Hourly cadence appears once aggregate public telemetry is available."}
                </p>
                {trafficCadence.length > 0 ? (
                  <div className="section-stack security-bar-list">
                    {trafficCadence.map((point) => (
                      <SurfaceBarRow
                        detail={`${formatCountLabel(point.count, "event", "events")} in this UTC hour bucket.`}
                        key={`${point.bucket_started_at_utc}:${point.label}`}
                        label={point.label}
                        progress={getCadenceFillWidth(trafficCadence, point.count)}
                        value={String(point.count)}
                      />
                    ))}
                  </div>
                ) : (
                  <p className="workspace-copy">
                    Hourly cadence becomes visible after the first sanitized public events are aggregated.
                  </p>
                )}
              </SurfaceCard>

              <SurfaceCard className="security-watch-card">
                <div className="mini-card-header">
                  <p className="queue-card-label">Monitored uptime history</p>
                  <StatusBadge tone={getLoadStateTone(metricsLoadState)}>
                    {formatLoadStateLabel(metricsLoadState)}
                  </StatusBadge>
                </div>
                <p className="workspace-caption">
                  {metricsSummary
                    ? `${formatAvailabilityMetric(metricsSummary)} · ${metricsSummary.availability_window}`
                    : "Monitor history appears after the first external health checks are retained."}
                </p>
                {uptimeHistory.length > 0 ? (
                  <SurfaceColumnChart
                    aria-label="Monitored uptime history"
                    items={uptimeHistory.map((item, index) => ({
                      detail: item.note,
                      height: item.overall_ok ? 100 : 40,
                      id: `${item.checked_at_utc}:${index}`,
                      label: formatUtcDateTimeLabel(item.checked_at_utc),
                      tone: item.overall_ok ? "success" : "danger",
                      value: item.overall_ok ? "Healthy" : "Degraded",
                    }))}
                  />
                ) : (
                  <p className="workspace-copy">
                    No monitored uptime history has been recorded yet.
                  </p>
                )}
              </SurfaceCard>
              <SurfaceCard className="security-watch-card">
                <div className="mini-card-header">
                  <p className="queue-card-label">Suppressed alert count</p>
                  <StatusBadge tone={getLoadStateTone(metricsLoadState)}>
                    {formatLoadStateLabel(metricsLoadState)}
                  </StatusBadge>
                </div>
                <p className="workspace-caption">
                  {metricsSummary?.suppressed_alert_window ||
                    "Counts sanitized alert suppressions persisted across the retention window."}
                </p>
                <p className="security-suppressed-alert-count">
                  {metricsSummary
                    ? formatCountLabel(
                        metricsSummary.suppressed_alert_count,
                        "suppression",
                        "suppressions",
                      )
                    : "Awaiting durable history"}
                </p>
                <p className="workspace-copy">
                  Each suppression is a public-safe row containing only event
                  type, route, site mode, and the suppression reason. The raw
                  client IP and user-agent are dropped before persistence so the
                  count surfaces noise without exposing visitor identity.
                </p>
              </SurfaceCard>
            </div>
          </SurfacePanel>

          {securityGlobeEnabled ? (
            <SurfacePanel>
              <SectionHeading
                description="The globe uses only coarse geography labels that are already safe to render publicly. It centers the current view and retained aggregate buckets without exposing raw coordinates or exact addresses."
                title="Geography globe layer"
              />
              <div className="security-globe-grid">
                <SurfaceCard className="security-globe-card">
                  <div className="mini-card-header">
                    <p className="queue-card-label">Coarse geography globe</p>
                    <div className="security-globe-card-badges">
                      {globeFreshnessLabel ? (
                        <StatusBadge tone="neutral" className="security-globe-freshness">
                          {globeFreshnessLabel}
                        </StatusBadge>
                      ) : null}
                      <StatusBadge tone={getLoadStateTone(metricsLoadState)}>
                        {formatLoadStateLabel(metricsLoadState)}
                      </StatusBadge>
                    </div>
                  </div>
                  <p className="workspace-caption">
                    {metricsSummary?.geography_counts.length
                      ? "Retained geography buckets, recent activity, and the current viewer location are layered together on a single public-safe globe."
                      : "The globe activates once retained or short-lived geography signals are available."}
                  </p>
                  {requestContext?.approximate_location ? (
                    <p
                      className="security-globe-viewer-pill"
                      aria-label="Your approximate location"
                    >
                      <span className="security-globe-viewer-pill-label">
                        Your approximate location
                      </span>
                      <span className="security-globe-viewer-pill-value">
                        {requestContext.approximate_location}
                      </span>
                    </p>
                  ) : null}
                  <SecurityTelemetryGlobe
                    aggregateCounts={metricsSummary?.geography_counts || []}
                    currentLocation={requestContext?.approximate_location || null}
                    recentActivity={recentActivityFeed}
                    viewerTimezone={browserContext.timeZone}
                  />
                  <details className="security-globe-why">
                    <summary>Why only coarse locations?</summary>
                    <p>
                      The globe plots only country or region centers from the public-safe
                      labels already shown elsewhere on the page. Raw IP addresses, exact
                      coordinates, device identifiers, and household-level geolocation never
                      reach the public surface. Approximate buckets keep the geography cue
                      legible without turning this into raw visitor tracking.
                    </p>
                  </details>
                </SurfaceCard>

                <SurfaceCard>
                  <div className="mini-card-header">
                    <p className="queue-card-label">Globe layer notes</p>
                    <StatusBadge tone="success">Public-safe</StatusBadge>
                  </div>
                  <div className="workspace-field-list">
                    <div className="workspace-field-row">
                      <small>Current viewer</small>
                      <strong>Request context anchor</strong>
                      <span>
                        {requestContext?.approximate_location ||
                          "Waiting for coarse current-viewer location from the request-context API."}
                      </span>
                    </div>
                    <div className="workspace-field-row">
                      <small>Retained geography</small>
                      <strong>Aggregate bucket count</strong>
                      <span>
                        {metricsSummary
                          ? formatCountLabel(
                              metricsSummary.geography_counts.length,
                              "bucket",
                              "buckets",
                            )
                          : "Aggregate geography buckets appear once the metrics API responds."}
                      </span>
                    </div>
                    <div className="workspace-field-row">
                      <small>Privacy boundary</small>
                      <strong>No raw coordinates or street-level precision</strong>
                      <span>
                        The globe resolves country and region centers only, so it stays explanatory instead of becoming precise tracking.
                      </span>
                    </div>
                  </div>
                </SurfaceCard>
              </div>
            </SurfacePanel>
          ) : null}

          <SurfacePanel>
            <SectionHeading
              description="The aggregate summary is still available as key-value telemetry, but these retained shapes make traffic mix easier to read at a glance."
              title="Aggregate traffic mix"
            />
            <div className="security-chart-grid">
              {trafficDistributionGroups.map((group) => (
                <SurfaceCard className="surface-chart-card security-chart-card" key={group.title}>
                  <div className="mini-card-header">
                    <p className="queue-card-label">{group.title}</p>
                    <StatusBadge tone={getLoadStateTone(metricsLoadState)}>
                      {formatLoadStateLabel(metricsLoadState)}
                    </StatusBadge>
                  </div>
                  <p className="workspace-copy">{group.description}</p>
                  {group.items.length > 0 ? (
                    <SurfaceColumnChart
                      items={group.items.map((item) => ({
                        detail: formatCountLabel(item.count, "event", "events"),
                        height: getMetricCountColumnHeight(group.items, item.count),
                        id: `${group.title}:${item.label}`,
                        label: item.label,
                        tone: group.tone,
                        value: item.count,
                      }))}
                    />
                  ) : (
                    <p className="workspace-copy">{group.emptyState}</p>
                  )}
                </SurfaceCard>
              ))}
            </div>
          </SurfacePanel>

          <SurfacePanel>
            <SectionHeading
              description="The point is to show engineering judgment clearly: who gets access, what is exposed, what is retained, and what never crosses the public boundary."
              title="Control summary"
            />
            <div className="showcase-grid security-control-grid">
              {securityControlCards.map((card) => (
                <SurfaceCard key={card.title}>
                  <p className="queue-card-label">{card.eyebrow}</p>
                  <h3>{card.title}</h3>
                  <p className="mini-card-copy">{card.copy}</p>
                </SurfaceCard>
              ))}
            </div>
          </SurfacePanel>

          <SurfacePanel>
            <SectionHeading
              description="These cards make the public boundary explicit: what the route can show, and what still belongs only in the protected operator plane."
              title="Public boundary rules"
            />
            <div className="showcase-grid security-boundary-grid">
              {securityBoundaryRules.map((rule) => (
                <SurfaceCard key={rule.title}>
                  <h3>{rule.title}</h3>
                  <div className="security-rule-row">
                    <p className="queue-card-label">Allowed</p>
                    <p className="mini-card-copy">{rule.allow}</p>
                  </div>
                  <div className="security-rule-row">
                    <p className="queue-card-label">Blocked</p>
                    <p className="mini-card-copy">{rule.block}</p>
                  </div>
                </SurfaceCard>
              ))}
            </div>
          </SurfacePanel>
        </div>

        <SurfaceDrawer as="aside" className="operations-panel simulation-aside public-aside">
          <SectionHeading
            description="The security site should make collection limits obvious, not bury them in a policy footer."
            title="Privacy posture"
          />
          <ul className="operations-list compact-rule-list">
            <li>No third-party marketing trackers.</li>
            <li>No non-essential cookies in the public security surface.</li>
            <li>No permanent storage of raw IP and browser pairs.</li>
            <li>Short-lived recent-session detail stays in memory and resets on cold start.</li>
            <li>Aggregate telemetry only after fields have been sanitized.</li>
            <li>Every displayed field is treated as public content by default.</li>
          </ul>

          <SurfaceCard>
            <div className="mini-card-header">
              <p className="queue-card-label">Sanitized aggregate public metrics</p>
              <StatusBadge tone={getLoadStateTone(metricsLoadState)}>
                {formatLoadStateLabel(metricsLoadState)}
              </StatusBadge>
            </div>
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
          </SurfaceCard>

          <SectionHeading title="Retention windows" />
          <div className="timeline-list">
            {securityRetentionWindows.map((item, index) => (
              <SurfaceTimelineItem
                description={item.copy}
                eyebrow={item.window}
                key={item.title}
                markerState={index === 0 ? "active" : "complete"}
                title={item.title}
              />
            ))}
          </div>
        </SurfaceDrawer>
      </section>

      <SurfacePanel
        aria-labelledby="security-feeds-heading"
        className="queue-column security-section"
        id="security-feeds"
      >
        <SectionHeading
          description="Live signals from the National Vulnerability Database (NVD) and Microsoft Security Response Center (MSRC). Each feed is fetched server-side, sanitized, and cached so the public site stays informational and never relays unfiltered third-party payloads."
          title={<span id="security-feeds-heading">Public security signal feeds</span>}
        />
        <div className="security-feeds-grid">
          <SurfaceCard className="security-feed-card">
            <div className="security-feed-card-header">
              <p className="queue-card-label">NVD CVE feed</p>
              <StatusBadge tone={getLoadStateTone(cveFeedLoadState)}>{formatLoadStateLabel(cveFeedLoadState)}</StatusBadge>
            </div>
            <h3>Recent CVEs across the public stack</h3>
            <p className="mini-card-copy">
              {cveFeed
                ? `${cveFeed.collection_mode} · keywords: ${cveFeed.keyword_terms.join(", ") || "none"}`
                : "Awaiting the isolated CVE API."}
            </p>
            {cveFeed && cveFeed.items.length > 0 ? (
              <ul className="security-feed-list">
                {cveFeed.items.slice(0, 5).map((item) => (
                  <li className="security-feed-item" key={item.cve_id}>
                    <div className="security-feed-item-header">
                      <strong>{item.cve_id}</strong>
                      {item.severity ? (
                        <span className="security-feed-item-meta">
                          {item.severity}
                          {item.cvss_score != null ? ` · ${item.cvss_score.toFixed(1)}` : ""}
                        </span>
                      ) : null}
                    </div>
                    <p>{item.summary}</p>
                    {item.reference_url ? (
                      <a
                        className="security-feed-item-link"
                        href={item.reference_url}
                        rel="noreferrer noopener"
                        target="_blank"
                      >
                        Reference ↗
                      </a>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mini-card-copy">No CVE entries are available right now.</p>
            )}
          </SurfaceCard>

          <SurfaceCard className="security-feed-card">
            <div className="security-feed-card-header">
              <p className="queue-card-label">MSRC release index</p>
              <StatusBadge tone={getLoadStateTone(msrcFeedLoadState)}>{formatLoadStateLabel(msrcFeedLoadState)}</StatusBadge>
            </div>
            <h3>Latest Microsoft security release rollups</h3>
            <p className="mini-card-copy">
              {msrcFeed
                ? msrcFeed.collection_mode
                : "Awaiting the isolated MSRC release index API."}
            </p>
            {msrcFeed && msrcFeed.items.length > 0 ? (
              <ul className="security-feed-list">
                {msrcFeed.items.slice(0, 5).map((item) => (
                  <li className="security-feed-item" key={item.msrc_id}>
                    <div className="security-feed-item-header">
                      <strong>{item.alias || item.msrc_id}</strong>
                      {item.initial_release_utc ? (
                        <span className="security-feed-item-meta">
                          {formatUtcDateTimeLabel(item.initial_release_utc)}
                        </span>
                      ) : null}
                    </div>
                    {item.document_title ? <p>{item.document_title}</p> : null}
                    {item.cvrf_url ? (
                      <a
                        className="security-feed-item-link"
                        href={item.cvrf_url}
                        rel="noreferrer noopener"
                        target="_blank"
                      >
                        CVRF document ↗
                      </a>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mini-card-copy">No MSRC releases are available right now.</p>
            )}
          </SurfaceCard>
        </div>
      </SurfacePanel>

      <SurfacePanel
        aria-labelledby="security-architecture-heading"
        className="queue-column security-section"
        id="security-architecture"
      >
        <SectionHeading
          description="The static site, edge, request-context API, and private operator plane each serve a different role. The important part is the separation, not the buzzwords."
          title={<span id="security-architecture-heading">Public-safe architecture view</span>}
        />
        <div className="showcase-grid security-architecture-grid">
          {securityArchitectureCards.map((card) => (
            <SurfaceCard className="security-architecture-card" key={card.title}>
              <p className="queue-card-label">{card.eyebrow}</p>
              <h3>{card.title}</h3>
              <p className="mini-card-copy">{card.copy}</p>
            </SurfaceCard>
          ))}
        </div>
      </SurfacePanel>

      <SurfacePanel
        aria-labelledby="security-standards-heading"
        className="queue-column security-section"
        id="security-standards"
      >
        <SectionHeading
          description="Each platform control below is a real layer this stack already enforces; the standards (OWASP Top 10 2021, NIST CSF 2.0, NIST SP 800-53 Rev.5) are pinned at build time so the mapping never drifts silently."
          title={
            <span id="security-standards-heading">
              Controls mapped to recognised security standards
            </span>
          }
        />

        <div className="security-standards-block">
          <h3 className="security-standards-subhead">OWASP Top 10 (2021)</h3>
          <div className="showcase-grid security-standards-grid">
            {owaspTop10.map((entry) => (
              <SurfaceCard key={entry.id}>
                <p className="queue-card-label">{entry.id}</p>
                <h4>{entry.category}</h4>
                <p className="mini-card-copy">{entry.platformControl}</p>
              </SurfaceCard>
            ))}
          </div>
        </div>

        <div className="security-standards-block">
          <h3 className="security-standards-subhead">NIST Cybersecurity Framework 2.0</h3>
          <div className="showcase-grid security-standards-grid security-standards-grid-csf">
            {nistCsf2.map((entry) => (
              <SurfaceCard key={entry.function}>
                <p className="queue-card-label">{entry.function}</p>
                <h4>{entry.outcome}</h4>
                <p className="mini-card-copy">{entry.platformControl}</p>
              </SurfaceCard>
            ))}
          </div>
        </div>

        <div className="security-standards-block">
          <h3 className="security-standards-subhead">NIST SP 800-53 Rev.5 (spot-check)</h3>
          <div className="showcase-grid security-standards-grid">
            {nistSp80053Highlights.map((entry) => (
              <SurfaceCard key={entry.id}>
                <p className="queue-card-label">{entry.id}</p>
                <h4>{entry.title}</h4>
                <p className="mini-card-copy">{entry.platformControl}</p>
              </SurfaceCard>
            ))}
          </div>
        </div>
      </SurfacePanel>

      <SurfacePanel
        aria-labelledby="security-faq-heading"
        className="queue-column security-section"
        id="security-faq"
      >
        <SectionHeading
          description="The answers stay intentionally direct so a hiring manager or reviewer can understand the posture quickly."
          title={<span id="security-faq-heading">Frequently asked questions</span>}
        />
        <div className="showcase-grid security-faq-grid">
          {securityFaqItems.map((item) => (
            <SurfaceCard key={item.question}>
              <h3>{item.question}</h3>
              <p className="mini-card-copy">{item.answer}</p>
            </SurfaceCard>
          ))}
        </div>
      </SurfacePanel>
    </PublicSiteLayout>
  );
}
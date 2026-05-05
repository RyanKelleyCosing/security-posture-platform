export type PublicTrafficEventType = "page_view" | "simulation_started";

export type PublicTrafficEventPayload = {
  event_type: PublicTrafficEventType;
  page_title?: string;
  referrer?: string;
  route: string;
  session_id: string;
  site_mode: "security" | "simulation";
};

export type PublicRequestContextPayload = {
  approximate_location: string;
  client_ip: string | null;
  edge_region: string;
  enrichment_provider_name: string | null;
  enrichment_status: string;
  forwarded_host: string;
  forwarded_proto: string;
  hosting_provider: string | null;
  network_asn: string | null;
  network_owner: string | null;
  public_network_enrichment_enabled: boolean;
  public_security_globe_enabled: boolean;
  reputation_summary: string | null;
  request_id: string;
  request_timestamp_utc: string;
  tls_protocol: string;
  transport_security: string;
  vpn_proxy_status: string | null;
};

export type PublicMetricCount = {
  count: number;
  label: string;
};

export type PublicHealthCheckDigestItem = {
  checked_at_utc: string;
  note: string;
  overall_ok: boolean;
};

export type PublicRecentActivityItem = {
  geography_bucket: string;
  recorded_at_utc: string;
  route: string;
  session_label: string;
  site_mode: string;
};

export type PublicTrafficCadencePoint = {
  bucket_started_at_utc: string;
  count: number;
  label: string;
};

export type PublicTrafficMetricsSummary = {
  availability_percentage: number | null;
  availability_source: string;
  availability_window: string;
  collection_mode: string;
  collection_window: string;
  current_status: string;
  current_uptime_seconds: number | null;
  environment_name: string;
  generated_at_utc: string;
  geography_counts: PublicMetricCount[];
  last_event_at_utc: string | null;
  latest_alert_configuration_ready: boolean | null;
  latest_monitor_name: string | null;
  last_successful_health_check_at_utc: string | null;
  process_started_at_utc: string | null;
  recent_activity: PublicRecentActivityItem[];
  recent_activity_window: string;
  recent_health_checks: PublicHealthCheckDigestItem[];
  route_counts: PublicMetricCount[];
  site_mode_counts: PublicMetricCount[];
  suppressed_alert_count: number;
  suppressed_alert_window: string;
  total_events: number;
  traffic_cadence: PublicTrafficCadencePoint[];
  traffic_cadence_window: string;
  unique_sessions: number;
};

const publicTrafficApiBaseUrl =
  import.meta.env.VITE_PUBLIC_TRAFFIC_API_BASE_URL?.replace(/\/$/, "") || "";

function createFallbackSessionId() {
  return `simulation-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

export function getPublicTrafficSessionId(): string {
  const storageKey = "docint-public-traffic-session-id";
  const existingValue = window.sessionStorage.getItem(storageKey);
  if (existingValue) {
    return existingValue;
  }

  const nextValue = globalThis.crypto?.randomUUID() || createFallbackSessionId();
  window.sessionStorage.setItem(storageKey, nextValue);
  return nextValue;
}

export async function recordPublicTrafficEvent(
  payload: PublicTrafficEventPayload,
): Promise<void> {
  if (!publicTrafficApiBaseUrl) {
    return;
  }

  try {
    await fetch(`${publicTrafficApiBaseUrl}/public-traffic-events`, {
      body: JSON.stringify(payload),
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      keepalive: true,
      method: "POST",
    });
  } catch (error) {
    console.warn("Unable to record public traffic event.", error);
  }
}

export async function fetchPublicRequestContext(): Promise<PublicRequestContextPayload | null> {
  if (!publicTrafficApiBaseUrl) {
    return null;
  }

  const response = await fetch(`${publicTrafficApiBaseUrl}/public-request-context`, {
    cache: "no-store",
    headers: {
      Accept: "application/json",
    },
    method: "GET",
  });

  if (!response.ok) {
    throw new Error(`Public request context failed with status ${response.status}`);
  }

  const payload = (await response.json()) as Partial<PublicRequestContextPayload>;
  if (!payload || typeof payload !== "object") {
    throw new Error("Public request context response must be a JSON object.");
  }

  return payload as PublicRequestContextPayload;
}

export async function fetchPublicTrafficMetricsSummary(): Promise<PublicTrafficMetricsSummary | null> {
  if (!publicTrafficApiBaseUrl) {
    return null;
  }

  const response = await fetch(`${publicTrafficApiBaseUrl}/public-metrics-summary`, {
    cache: "no-store",
    headers: {
      Accept: "application/json",
    },
    method: "GET",
  });

  if (!response.ok) {
    throw new Error(`Public metrics summary failed with status ${response.status}`);
  }

  const payload = (await response.json()) as Partial<PublicTrafficMetricsSummary>;
  if (!payload || typeof payload !== "object") {
    throw new Error("Public metrics summary response must be a JSON object.");
  }

  return payload as PublicTrafficMetricsSummary;
}

export type PublicHealthStatus = {
  ok: boolean;
  status: "online" | "degraded" | "offline";
  latencyMs: number | null;
  checkedAtUtc: string;
};

export async function fetchPublicHealth(): Promise<PublicHealthStatus> {
  const checkedAtUtc = new Date().toISOString();
  if (!publicTrafficApiBaseUrl) {
    return {
      checkedAtUtc,
      latencyMs: null,
      ok: false,
      status: "offline",
    };
  }

  const startedAt = performance.now();
  try {
    const response = await fetch(`${publicTrafficApiBaseUrl}/health`, {
      cache: "no-store",
      headers: { Accept: "application/json" },
      method: "GET",
    });
    const latencyMs = Math.max(1, Math.round(performance.now() - startedAt));
    if (!response.ok) {
      return { checkedAtUtc, latencyMs, ok: false, status: "degraded" };
    }

    return { checkedAtUtc, latencyMs, ok: true, status: "online" };
  } catch {
    return { checkedAtUtc, latencyMs: null, ok: false, status: "offline" };
  }
}

export type PublicSecurityCveItem = {
  cve_id: string;
  cvss_score: number | null;
  last_modified_utc: string | null;
  published_utc: string | null;
  reference_url: string | null;
  severity: string | null;
  summary: string;
};

export type PublicSecurityCveFeed = {
  collection_mode: string;
  generated_at_utc: string;
  items: PublicSecurityCveItem[];
  keyword_terms: string[];
  source: string;
  total_count: number;
};

export type PublicSecurityMsrcItem = {
  alias: string | null;
  cvrf_url: string | null;
  document_title: string | null;
  initial_release_utc: string | null;
  msrc_id: string;
};

export type PublicSecurityMsrcFeed = {
  collection_mode: string;
  generated_at_utc: string;
  items: PublicSecurityMsrcItem[];
  source: string;
  total_count: number;
};

export async function fetchPublicSecurityCveFeed(): Promise<PublicSecurityCveFeed | null> {
  if (!publicTrafficApiBaseUrl) {
    return null;
  }

  const response = await fetch(`${publicTrafficApiBaseUrl}/security/cves`, {
    cache: "no-store",
    headers: { Accept: "application/json" },
    method: "GET",
  });

  if (!response.ok) {
    throw new Error(`Public CVE feed failed with status ${response.status}`);
  }

  const payload = (await response.json()) as Partial<PublicSecurityCveFeed>;
  if (!payload || typeof payload !== "object") {
    throw new Error("Public CVE feed response must be a JSON object.");
  }

  return payload as PublicSecurityCveFeed;
}

export async function fetchPublicSecurityMsrcFeed(): Promise<PublicSecurityMsrcFeed | null> {
  if (!publicTrafficApiBaseUrl) {
    return null;
  }

  const response = await fetch(`${publicTrafficApiBaseUrl}/security/msrc-latest`, {
    cache: "no-store",
    headers: { Accept: "application/json" },
    method: "GET",
  });

  if (!response.ok) {
    throw new Error(`Public MSRC feed failed with status ${response.status}`);
  }

  const payload = (await response.json()) as Partial<PublicSecurityMsrcFeed>;
  if (!payload || typeof payload !== "object") {
    throw new Error("Public MSRC feed response must be a JSON object.");
  }

  return payload as PublicSecurityMsrcFeed;
}
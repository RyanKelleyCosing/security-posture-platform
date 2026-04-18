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
  forwarded_host: string;
  forwarded_proto: string;
  request_id: string;
  request_timestamp_utc: string;
  tls_protocol: string;
  transport_security: string;
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
  recent_health_checks: PublicHealthCheckDigestItem[];
  route_counts: PublicMetricCount[];
  site_mode_counts: PublicMetricCount[];
  total_events: number;
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
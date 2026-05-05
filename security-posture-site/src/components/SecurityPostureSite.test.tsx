import { render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SecurityPostureSite } from "./SecurityPostureSite";

const {
  fetchPublicRequestContextMock,
  fetchPublicSecurityCveFeedMock,
  fetchPublicSecurityMsrcFeedMock,
  fetchPublicTrafficMetricsSummaryMock,
} = vi.hoisted(() => ({
  fetchPublicRequestContextMock: vi.fn(),
  fetchPublicSecurityCveFeedMock: vi.fn(),
  fetchPublicSecurityMsrcFeedMock: vi.fn(),
  fetchPublicTrafficMetricsSummaryMock: vi.fn(),
}));

const defaultRequestContext = {
  approximate_location: "US / Ohio",
  client_ip: "203.0.113.77",
  edge_region: "Host region: eastus2",
  enrichment_provider_name: "IPQualityScore",
  enrichment_status:
    "Provider-backed network signals loaded from IPQualityScore.",
  forwarded_host: "ryancodes.security.online",
  forwarded_proto: "https",
  hosting_provider: "Azure Front Door",
  network_asn: "AS8075",
  network_owner: "Microsoft Corporation",
  public_network_enrichment_enabled: true,
  public_security_globe_enabled: true,
  reputation_summary: "Low observed abuse risk · fraud score 12/100",
  request_id: "req-demo-1234",
  request_timestamp_utc: "2026-04-16T12:15:00Z",
  tls_protocol: "TLSv1.3",
  transport_security: "HTTPS only",
  vpn_proxy_status:
    "Data Center/Web Hosting/Transit path observed by IPQualityScore.",
};

const defaultMetricsSummary = {
  availability_percentage: 100,
  availability_source: "External verification history",
  availability_window: "Last 7d monitored checks",
  collection_mode: "Durable sanitized aggregate history",
  collection_window:
    "Rolling 60d durable aggregate history with hashed session dedupe and sanitized geography buckets.",
  current_status: "Healthy",
  current_uptime_seconds: null,
  environment_name: "test",
  generated_at_utc: "2026-04-16T12:16:00Z",
  geography_counts: [{ count: 7, label: "US / Ohio" }],
  last_event_at_utc: "2026-04-16T12:15:00Z",
  latest_alert_configuration_ready: true,
  latest_monitor_name: "github-actions-public-site-monitor",
  last_successful_health_check_at_utc: "2026-04-16T12:15:30Z",
  process_started_at_utc: null,
  recent_activity: [
    {
      geography_bucket: "US / Ohio",
      recorded_at_utc: "2026-04-16T12:18:00Z",
      route: "security",
      session_label: "session-1a2b3c4d",
      site_mode: "security",
    },
    {
      geography_bucket: "CA",
      recorded_at_utc: "2026-04-16T12:13:00Z",
      route: "demo",
      session_label: "session-5f6e7d8c",
      site_mode: "simulation",
    },
  ],
  recent_activity_window:
    "Short-lived in-memory recent-session feed only. It resets on cold start and is not written to durable history.",
  recent_health_checks: [
    {
      checked_at_utc: "2026-04-16T12:15:30Z",
      note: "Public site reachable · traffic route accepted",
      overall_ok: true,
    },
  ],
  route_counts: [{ count: 7, label: "security" }],
  site_mode_counts: [{ count: 7, label: "security" }],
  suppressed_alert_count: 4,
  suppressed_alert_window:
    "Counts sanitized alert suppressions persisted across the retention window.",
  total_events: 7,
  traffic_cadence: [
    {
      bucket_started_at_utc: "2026-04-16T11:00:00Z",
      count: 2,
      label: "Apr 16 11:00 UTC",
    },
    {
      bucket_started_at_utc: "2026-04-16T12:00:00Z",
      count: 5,
      label: "Apr 16 12:00 UTC",
    },
  ],
  traffic_cadence_window:
    "Last 12 hourly buckets ending at the latest retained public event.",
  unique_sessions: 3,
};

vi.mock("../api/publicTrafficApi", () => ({
  fetchPublicHealth: vi.fn(async () => ({ status: "online", latencyMs: 42 })),
  fetchPublicRequestContext: fetchPublicRequestContextMock,
  fetchPublicSecurityCveFeed: fetchPublicSecurityCveFeedMock,
  fetchPublicSecurityMsrcFeed: fetchPublicSecurityMsrcFeedMock,
  fetchPublicTrafficMetricsSummary: fetchPublicTrafficMetricsSummaryMock,
  getPublicTrafficSessionId: () => "security-session-test",
  recordPublicTrafficEvent: vi.fn(),
}));

describe("SecurityPostureSite", () => {
  beforeEach(() => {
    vi.spyOn(Date, "now").mockReturnValue(
      new Date("2026-04-16T12:20:00Z").valueOf(),
    );
    fetchPublicRequestContextMock.mockReset();
    fetchPublicTrafficMetricsSummaryMock.mockReset();
    fetchPublicSecurityCveFeedMock.mockReset();
    fetchPublicSecurityMsrcFeedMock.mockReset();
    fetchPublicRequestContextMock.mockResolvedValue(defaultRequestContext);
    fetchPublicTrafficMetricsSummaryMock.mockResolvedValue(defaultMetricsSummary);
    fetchPublicSecurityCveFeedMock.mockResolvedValue({
      collection_mode: "NVD CVE keyword search (1h cache)",
      generated_at_utc: "2026-04-24T10:00:00Z",
      items: [
        {
          cve_id: "CVE-2026-1234",
          cvss_score: 8.5,
          last_modified_utc: "2026-04-23T10:00:00Z",
          published_utc: "2026-04-22T10:00:00Z",
          reference_url: "https://example.test/cve-2026-1234",
          severity: "HIGH",
          summary: "Example sanitized CVE summary used in tests.",
        },
      ],
      keyword_terms: ["python"],
      source: "https://services.nvd.nist.gov/rest/json/cves/2.0",
      total_count: 1,
    });
    fetchPublicSecurityMsrcFeedMock.mockResolvedValue({
      collection_mode: "MSRC CVRF release index (6h cache)",
      generated_at_utc: "2026-04-24T10:00:00Z",
      items: [
        {
          alias: "2026-Apr",
          cvrf_url: "https://example.test/cvrf/2026-apr",
          document_title: "April 2026 Security Updates",
          initial_release_utc: "2026-04-08T08:00:00Z",
          msrc_id: "2026-Apr",
        },
      ],
      source: "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
      total_count: 1,
    });
    window.location.hash = "#/security";
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  it("renders the public security posture summary and live transparency panel", async () => {
    render(<SecurityPostureSite />);

    expect(
      screen.getByRole("heading", {
        name: /Security posture for the Ryan Codes public stack/i,
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /Live visitor trace/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /Recent activity and cadence/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: /Geography globe layer/i }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(/Live request context is loaded from the isolated public API/i),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(/Live aggregate public metrics and monitored availability history are loaded from the isolated public API/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/203\.0\.113\.77/i)).toBeInTheDocument();
    expect(screen.getByText(/AS8075/i)).toBeInTheDocument();
    expect(screen.getByText(/Microsoft Corporation/i)).toBeInTheDocument();
    expect(screen.getByText(/Azure Front Door/i)).toBeInTheDocument();
    expect(screen.getByText(/req-demo-1234/i)).toBeInTheDocument();
    expect(screen.getByText(/session-1a2b3c4d/i)).toBeInTheDocument();
    expect(screen.getByText(/Apr 16 12:00 UTC/i)).toBeInTheDocument();
    expect(screen.getByText(/7 public events/i)).toBeInTheDocument();
    expect(screen.getByText(/^Top route$/i)).toBeInTheDocument();
    expect(screen.getByText(/7 events retained on this route/i)).toBeInTheDocument();
    expect(screen.getByText(/^Latest event$/i)).toBeInTheDocument();
    expect(screen.getByText(/^5 minutes ago$/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Aggregate traffic mix/i })).toBeInTheDocument();
    expect(screen.getByText(/^Route mix$/i)).toBeInTheDocument();
    expect(screen.getByText(/^Site mode mix$/i)).toBeInTheDocument();
    expect(screen.getByText(/^Geography mix$/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Healthy · 100\.0%/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Durable sanitized aggregate history/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Current · checked 5 minutes ago/i)).toBeInTheDocument();
    expect(
      screen.getByText(/30-minute external availability probes via the deployed timer monitor/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/github-actions-public-site-monitor/i)).toBeInTheDocument();
    expect(screen.getByText(/Ready for explicit alert-delivery checks/i)).toBeInTheDocument();
    expect(
      screen.getAllByText(/Public site reachable · traffic route accepted/i).length,
    ).toBeGreaterThan(0);
    expect(screen.getAllByText(/No third-party marketing trackers/i).length).toBeGreaterThan(0);
    expect(
      screen.getByText(/Provider-backed network signals loaded from IPQualityScore/i),
    ).toBeInTheDocument();
    const providerAttributionLink = screen.getByRole("link", { name: /IPQualityScore/i });
    expect(providerAttributionLink).toHaveAttribute(
      "href",
      "https://www.ipqualityscore.com/",
    );
  });

  it("renders the suppressed alert count from the durable summary on the cadence card", async () => {
    render(<SecurityPostureSite />);

    expect(
      await screen.findByText(/Suppressed alert count/i),
    ).toBeInTheDocument();
    expect(await screen.findByText(/4 suppressions/i)).toBeInTheDocument();
  });

  it("exposes a CSV export link with cadence buckets on the traffic cadence card", async () => {
    render(<SecurityPostureSite />);

    const exportLink = await screen.findByRole("link", { name: /Export CSV/i });

    expect(exportLink).toHaveAttribute(
      "download",
      "public-security-traffic-cadence.csv",
    );

    const href = exportLink.getAttribute("href") ?? "";
    expect(href.startsWith("data:text/csv;charset=utf-8,")).toBe(true);

    const decoded = decodeURIComponent(
      href.slice("data:text/csv;charset=utf-8,".length),
    );
    expect(decoded.split("\n")[0]).toBe("bucket_started_at_utc,label,count");
    expect(decoded).toContain("Apr 16 11:00 UTC");
    expect(decoded).toContain(",2");
    expect(decoded).toContain(",5");
  });

  it("renders the recent public activity dense table and exposes an activity CSV export link", async () => {
    render(<SecurityPostureSite />);

    const sessionCell = await screen.findByText("session-1a2b3c4d");
    const row = sessionCell.closest("tr");
    expect(row).not.toBeNull();
    expect(row?.querySelector("td")?.textContent).toMatch(/Apr 16, 2026, 12:18 PM/i);
    expect(within(row as HTMLElement).getByText("US / Ohio")).toBeInTheDocument();

    const exportLink = await screen.findByRole("link", {
      name: /Export activity CSV/i,
    });
    expect(exportLink).toHaveAttribute(
      "download",
      "public-security-recent-activity.csv",
    );
    const href = exportLink.getAttribute("href") ?? "";
    expect(href.startsWith("data:text/csv;charset=utf-8,")).toBe(true);
    const decoded = decodeURIComponent(
      href.slice("data:text/csv;charset=utf-8,".length),
    );
    expect(decoded.split("\n")[0]).toBe(
      "recorded_at_utc,route,site_mode,geography_bucket,session_label",
    );
    expect(decoded).toContain("session-1a2b3c4d");
    expect(decoded).toContain("session-5f6e7d8c");
  });

  it("renders a Your approximate location pill above the geography globe", async () => {
    render(<SecurityPostureSite />);

    const pill = await screen.findByLabelText("Your approximate location");
    expect(pill).toBeInTheDocument();
    expect(pill.textContent).toMatch(/Your approximate location/i);
    expect(pill.textContent).toMatch(/US \/ Ohio/);
  });

  it("mounts cleanly when the URL hash points at an unknown deep-link section", async () => {
    window.location.hash = "#/security#bogus-section-that-does-not-exist";

    render(<SecurityPostureSite />);

    expect(
      await screen.findByRole("heading", {
        name: /Security posture for the Ryan Codes public stack/i,
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", {
        name: /Public security signal feeds/i,
      }),
    ).toBeInTheDocument();
  });

  it("renders the public security signal feeds card with NVD CVE and MSRC entries", async () => {
    render(<SecurityPostureSite />);

    expect(
      await screen.findByRole("heading", {
        name: /Public security signal feeds/i,
      }),
    ).toBeInTheDocument();
    expect(await screen.findByText(/CVE-2026-1234/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Example sanitized CVE summary used in tests/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/2026-Apr/i)).toBeInTheDocument();
    expect(
      screen.getByText(/April 2026 Security Updates/i),
    ).toBeInTheDocument();
    const cveLink = screen.getByRole("link", { name: /Reference/i });
    expect(cveLink).toHaveAttribute("href", "https://example.test/cve-2026-1234");
    expect(cveLink).toHaveAttribute("target", "_blank");
    const msrcLink = screen.getByRole("link", { name: /CVRF document/i });
    expect(msrcLink).toHaveAttribute("href", "https://example.test/cvrf/2026-apr");
  });


  it("hides enrichment and globe panels when the rollout flags are disabled", async () => {
    fetchPublicRequestContextMock.mockResolvedValue({
      ...defaultRequestContext,
      enrichment_provider_name: null,
      enrichment_status: "Provider-backed network enrichment is disabled by feature flag.",
      hosting_provider: null,
      network_asn: null,
      network_owner: null,
      public_network_enrichment_enabled: false,
      public_security_globe_enabled: false,
      reputation_summary: null,
      vpn_proxy_status: null,
    });

    render(<SecurityPostureSite />);

    expect(
      await screen.findByText(/Live request context is loaded from the isolated public API/i),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: /Geography globe layer/i }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/AS8075/i)).not.toBeInTheDocument();
    expect(
      screen.queryByText(/Provider-backed network signals loaded from IPQualityScore/i),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Boundary posture/i)).toBeInTheDocument();
  });
});
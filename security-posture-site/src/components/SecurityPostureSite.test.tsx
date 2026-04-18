import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SecurityPostureSite } from "./SecurityPostureSite";

vi.mock("../api/publicTrafficApi", () => ({
  fetchPublicRequestContext: vi.fn(async () => ({
    approximate_location: "US / Ohio",
    client_ip: "203.0.113.77",
    edge_region: "Host region: eastus2",
    forwarded_host: "ryancodes.security.online",
    forwarded_proto: "https",
    request_id: "req-demo-1234",
    request_timestamp_utc: "2026-04-16T12:15:00Z",
    tls_protocol: "TLSv1.3",
    transport_security: "HTTPS only",
  })),
  fetchPublicTrafficMetricsSummary: vi.fn(async () => ({
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
    recent_health_checks: [
      {
        checked_at_utc: "2026-04-16T12:15:30Z",
        note: "Public site reachable · traffic route accepted",
        overall_ok: true,
      },
    ],
    route_counts: [{ count: 7, label: "security" }],
    site_mode_counts: [{ count: 7, label: "security" }],
    total_events: 7,
    unique_sessions: 3,
  })),
  getPublicTrafficSessionId: () => "security-session-test",
  recordPublicTrafficEvent: vi.fn(),
}));

describe("SecurityPostureSite", () => {
  beforeEach(() => {
    vi.spyOn(Date, "now").mockReturnValue(
      new Date("2026-04-16T12:20:00Z").valueOf(),
    );
    window.location.hash = "#/security";
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the public security posture summary and live transparency panel", async () => {
    render(<SecurityPostureSite />);

    expect(
      screen.getByRole("heading", {
        name: /Security posture for the Ryan Codes public stack/i,
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Transparency panel prototype/i)).toBeInTheDocument();
    expect(
      await screen.findByText(/Live request context is loaded from the isolated public API/i),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(/Live aggregate public metrics and monitored availability history are loaded from the isolated public API/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/203\.0\.113\.77/i)).toBeInTheDocument();
    expect(screen.getByText(/req-demo-1234/i)).toBeInTheDocument();
    expect(screen.getByText(/7 public events/i)).toBeInTheDocument();
    expect(screen.getByText(/Healthy · 100\.0%/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Durable sanitized aggregate history/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Current · checked 5 minutes ago/i)).toBeInTheDocument();
    expect(
      screen.getByText(/30-minute external availability probes via the deployed timer monitor/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/github-actions-public-site-monitor/i)).toBeInTheDocument();
    expect(screen.getByText(/Ready for explicit alert-delivery checks/i)).toBeInTheDocument();
    expect(screen.getByText(/Public site reachable · traffic route accepted/i)).toBeInTheDocument();
    expect(screen.getAllByText(/No third-party marketing trackers/i).length).toBeGreaterThan(0);
  });
});
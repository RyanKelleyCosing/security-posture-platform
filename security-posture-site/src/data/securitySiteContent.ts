export type SecurityContentCard = {
  copy: string;
  eyebrow: string;
  title: string;
};

export type SecurityBoundaryRule = {
  allow: string;
  block: string;
  title: string;
};

export type SecurityRetentionWindow = {
  copy: string;
  title: string;
  window: string;
};

export type SecurityFaqItem = {
  answer: string;
  question: string;
};

export const securityHeroHighlights = [
  "Zero trust by default",
  "Public-safe telemetry only",
  "Separate private operator plane",
];

export const securityControlCards: SecurityContentCard[] = [
  {
    copy:
      "GitHub OIDC, reviewed automation, and narrowly scoped identities keep deployment access short-lived and explicit.",
    eyebrow: "Identity",
    title: "Short-lived access instead of ambient trust",
  },
  {
    copy:
      "Edge termination, HTTPS-only delivery, and origin isolation keep the public site separate from private admin and data-plane systems.",
    eyebrow: "Network",
    title: "A public site with a hard boundary",
  },
  {
    copy:
      "The browser never receives private credentials, and the prototype treats every field in the transparency panel as if it will be screenshotted.",
    eyebrow: "Secrets",
    title: "No secret material in the public surface",
  },
  {
    copy:
      "Telemetry is intentionally coarse, clearly explained, and bounded by short retention windows instead of vague blanket collection.",
    eyebrow: "Telemetry",
    title: "Visible signals with explicit privacy limits",
  },
];

export const securityArchitectureCards: SecurityContentCard[] = [
  {
    copy:
      "A static front-end explains the public stack, trust boundaries, and privacy commitments in plain language.",
    eyebrow: "Public",
    title: "Static posture site",
  },
  {
    copy:
      "An edge or CDN layer provides HTTPS, WAF policy, custom domain routing, and the request headers needed for transparent session context.",
    eyebrow: "Sanitized",
    title: "Edge and trust-boundary layer",
  },
  {
    copy:
      "A minimal request-context API returns only the fields shown to the visitor and stays isolated from private operator credentials.",
    eyebrow: "Phase 2",
    title: "Request-context API",
  },
  {
    copy:
      "The private operational platform remains separate, with different identities, different resources, and no direct coupling to this public site.",
    eyebrow: "Private",
    title: "Operator platform boundary",
  },
];

export const securityBoundaryRules: SecurityBoundaryRule[] = [
  {
    allow: "Architecture summaries, control choices, coarse request context, and aggregate health indicators.",
    block:
      "Tenant identifiers, private admin endpoints, secret-bearing configuration, and operator payloads.",
    title: "What the public site may show",
  },
  {
    allow:
      "The current request's public IP on screen, coarse geography when confidence is high, and a short-lived support request ID.",
    block:
      "Permanent storage of full raw IP and browser pairs or detailed user tracking histories.",
    title: "What the transparency panel may show",
  },
  {
    allow:
      "Aggregate counts such as daily request volume, coarse region totals, and uptime or health summaries.",
    block:
      "Long-lived raw request logs exported into public analytics views.",
    title: "What may persist beyond the session",
  },
];

export const securityRetentionWindows: SecurityRetentionWindow[] = [
  {
    copy:
      "Used only for transparency rendering and short operational troubleshooting, not as a marketing analytics feed.",
    title: "Raw request context",
    window: "Memory only to <24h",
  },
  {
    copy:
      "Only needed when abuse prevention requires a stable signal without keeping the raw address itself.",
    title: "Salted abuse-prevention hash",
    window: "24h to 72h",
  },
  {
    copy:
      "Public-safe metrics such as request totals, coarse geography buckets, and uptime summaries can live longer because they are aggregated.",
    title: "Aggregate public metrics",
    window: "30d to 90d",
  },
];

export const securityFaqItems: SecurityFaqItem[] = [
  {
    answer:
      "Yes, the live transparency panel is designed to show the current public IP that the edge or request-context API sees, but the architecture is intentionally biased against long-lived raw IP retention.",
    question: "Can this site see my IP address?",
  },
  {
    answer:
      "The phase 1 prototype is static. Phase 2 adds a minimal request-context API that returns only the visitor-facing fields shown on the page.",
    question: "Is the transparency panel live yet?",
  },
  {
    answer:
      "No. The public security site is meant to describe and demonstrate the boundary, not to share the private operator surface itself.",
    question: "Is this connected directly to the private operator platform?",
  },
  {
    answer:
      "The design assumes no non-essential cookies, no third-party marketing trackers, and no silent collection of raw request telemetry for indefinite storage.",
    question: "Does this site use tracking cookies?",
  },
];
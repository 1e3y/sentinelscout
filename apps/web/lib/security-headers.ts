/**
 * Browser security defaults for the Scout web app.
 *
 * Clerk CSP exceptions:
 * - script-src / worker-src: Clerk JS bundles and challenge workers
 * - connect-src: Clerk Frontend API + our API origin
 * - frame-src / child-src: Clerk hosted components / bot challenges
 * - img-src: Clerk avatars (img.clerk.com)
 * - style-src 'unsafe-inline': required by Clerk component styling
 */
const apiBase =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export const contentSecurityPolicy = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://*.clerk.accounts.dev https://*.clerk.com https://clerk.com",
  "worker-src 'self' blob: https://*.clerk.accounts.dev https://*.clerk.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https://img.clerk.com https://*.clerk.com https://*.clerk.accounts.dev",
  "font-src 'self' data:",
  `connect-src 'self' ${apiBase} https://*.clerk.accounts.dev https://*.clerk.com https://api.clerk.com`,
  "frame-src 'self' https://*.clerk.accounts.dev https://*.clerk.com",
  "child-src 'self' https://*.clerk.accounts.dev https://*.clerk.com",
].join("; ");

export const SECURITY_HEADERS: { key: string; value: string }[] = [
  {
    key: "Content-Security-Policy",
    value: contentSecurityPolicy,
  },
  {
    key: "X-Content-Type-Options",
    value: "nosniff",
  },
  {
    key: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
  },
  {
    key: "X-Frame-Options",
    value: "DENY",
  },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
  },
];

export const REQUIRED_SECURITY_HEADER_NAMES = [
  "Content-Security-Policy",
  "X-Content-Type-Options",
  "Referrer-Policy",
  "X-Frame-Options",
] as const;

# v23 integration map

The v23 source candidate integrates the adaptive service into the Express server. The repository review branch keeps this small integration contract separate from the private-owner application source.

1. Import `adaptiveSecurityService` in `server.ts`.
2. Disable Express `X-Powered-By`.
3. Validate `TRUST_PROXY_HOPS` as an integer from 0 to 5 and set Express trust proxy to the exact known trusted-proxy chain only. Default is 0; never trust arbitrary user-supplied forwarded headers.
4. Install `app.use(adaptiveSecurityService.middleware())` before body parsing and all API routes.
5. Keep `express.json({ limit: '1mb', strict: true })` after adaptive middleware.
6. In `verifyOwnerAuthorization`, any rejected protected-route authorization where `recordFailure !== false` must call `adaptiveSecurityService.recordOwnerAuthentication(clientIp, false, req.path)`. Prefer a route template for audit targets, never log `req.originalUrl`, query strings, bearer tokens, download nonces, cookies, or raw client IP addresses.
7. The owner-only `GET /api/security/posture` route must require a verified owner session and return only the bounded posture snapshot.
8. The owner sign-in endpoint's response-finish hook records failed authentication; do not duplicate this hook for routes already counted by `verifyOwnerAuthorization`.
9. Exempt `/api/health` from the normal API request budget so monitoring cannot consume a user's allowance. Keep it available during source quarantine.
10. Repeated TRACE/TRACK/CONNECT attempts count as probe-risk signals and are classified as `METHOD_BLOCKED`.
11. Include `test/adaptive_security_layer_check.mjs` and the static auth/audit privacy assertions in `npm run security:check`.

## Required tests

- BASELINE → GUARDED → CONTAINMENT → QUARANTINE thresholds.
- One quarantined fingerprint must not change another client's layer.
- 25,000 repeated probe/auth/API-flood signals must not grow per-client timestamp arrays or event history without bound.
- 1,000 health checks must not consume normal API budget.
- Repeated dangerous HTTP methods must escalate the source.
- Audit entries must not include raw IPs, request query tokens, or unbounded user-controlled paths.

The adaptive state is process-local. Multi-replica production requires a shared atomic store or a trusted managed edge rate limiter with consistent identity and proxy semantics. This app-level control is not a WAF, DDoS shield, intrusion-prevention certification, or guarantee of being unhackable.

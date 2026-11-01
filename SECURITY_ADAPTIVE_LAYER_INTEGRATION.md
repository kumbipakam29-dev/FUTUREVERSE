# v23 integration map

The v23 source candidate integrates the adaptive service and CSRF guard into the Express app. The repository review branch keeps the small security primitives and integration contract separate from the complete application source archive.

1. Import `adaptiveSecurityService` and `evaluateOwnerCookieMutationOrigin` in `server.ts`.
2. Disable Express `X-Powered-By`.
3. Validate `TRUST_PROXY_HOPS` as an integer from 0 to 5 and set Express trust proxy to the exact known trusted-proxy chain only. Default is 0; never trust arbitrary forwarded headers.
4. In production, require `APP_URL` to be a valid canonical HTTPS URL; startup fails closed otherwise.
5. Install adaptive middleware, then the owner-cookie CSRF guard, before body parsing and all API routes. Keep `express.json({ limit: '1mb', strict: true })` after both.
6. For unsafe methods, the CSRF guard checks only ambient `fv_owner_token` cookies. Exact Origin must equal APP_URL's origin; cross-site Fetch Metadata is rejected. Bearer/custom-header clients are not ambient-cookie clients and are not checked by this guard.
7. In `verifyOwnerAuthorization`, failed protected-route authorization feeds the adaptive risk counter; audit events must never retain request query strings, bearer tokens, download nonces, cookies or raw client IPs.
8. The owner-only `GET /api/security/posture` route requires a verified owner session.
9. One-time ZIP download nonces are accepted only from `X-Owner-Download-Nonce` on GET/HEAD; never accept them from URL query strings. Return a nonce-free download URL and set no-store on the nonce response.
10. Production CSP begins as `Content-Security-Policy-Report-Only` using inventoried app, Google Fonts, Unsplash avatar, and YAGYX RPC/explorer origins. Review browser violations before enforcement.
11. Include both `test/adaptive_security_layer_check.mjs` and `test/csrf_origin_guard_check.mjs` in `npm run security:check`.

## Regression requirements

- BASELINE → GUARDED → CONTAINMENT → QUARANTINE with per-source isolation.
- 25,000 repeated probe/auth/API-flood signals cannot grow per-client timestamp arrays or event history without bound.
- 1,000 health checks do not consume normal API quota.
- Dangerous HTTP methods escalate probe risk.
- Exact same-origin cookie mutation passes; cross-origin, cross-site, missing-Origin and production-without-APP_URL fail closed.
- Download nonces do not appear in browser URLs.

Adaptive client state is process-local. Multi-replica production requires a shared atomic store or trusted managed edge rate-limiting with verified proxy semantics. App middleware is not a WAF, DDoS service, or guarantee of being unhackable.


## v24 recovery test

Run `node test/adaptive_quarantine_recovery_check.mjs` in the project workspace after the v24 source patch is synced. The test uses a controlled clock and verifies quarantine expiry, bounded recovery, stale counter reset, return to BASELINE, and re-escalation on fresh signals.

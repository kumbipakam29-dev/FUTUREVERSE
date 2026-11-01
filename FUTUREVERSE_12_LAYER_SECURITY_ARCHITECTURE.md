# FUTUREVERSE — 12-Layer Security Architecture (v23 owner-review candidate)

**Status: owner-review candidate. Not a security certification.**

Security layers remain stacked and active together. Adaptive posture changes friction for a suspicious source; it never mutates code, rotates secrets, disables the platform, or lets AI change policy.

| # | Layer | v23 status | Control / remaining work |
|---:|---|---|---|
| 1 | Edge perimeter | Deployment prerequisite | Managed CDN/WAF, bot controls and DDoS protection must sit before the application. |
| 2 | Secure transport | Partial | Production emits HSTS for requests Express recognizes as HTTPS. TLS certificates, edge termination and TLS policy must be configured and verified by the operator. |
| 3 | Trusted ingress | Implemented, not live-verified | TRUST_PROXY_HOPS is validated (0–5), default 0. Configure only the actual trusted proxy chain. |
| 4 | HTTP/browser hardening | Partial | X-Powered-By disabled; nosniff, frame denial, referrer, permissions, COOP, API no-store and production CSP-Report-Only headers. Review browser violations, then test an enforced CSP. |
| 5 | Request/input boundary | Candidate implemented | Strict JSON ≤1 MiB; common secret/config probes get generic 404; TRACE/TRACK/CONNECT rejected; limits on sensitive routes. |
| 6 | Authentication | Partial | Three distinct server-side owner secrets, minimum 32 characters, timing-safe digest comparison, generic failures. MFA/passkeys are not implemented. |
| 7 | Session/nonce protection | Candidate implemented | Random owner-session and one-time download credentials stored only as SHA-256 digests; HttpOnly/SameSite cookie; Secure in production; bounded credential maps. Download nonce is a header, not URL parameter. |
| 8 | Authorization/Zero Trust | Partial | Protected owner actions require an active session and role checks. Complete route-by-route authorization review remains. |
| 9 | Adaptive threat detection | Candidate implemented, process-local | BASELINE → GUARDED → CONTAINMENT → QUARANTINE using repeated probe, failed-auth and rate-abuse signals; HMAC pseudonymous source keys and bounded telemetry. |
| 10 | Quotas/anti-abuse | Partial | Per-route/source rate limiter with 20,000-entry cap; adaptive per-client API budgets. Multi-replica needs shared atomic state or managed edge limiter; add account/session signals without attacker-triggerable account lockout. |
| 11 | Data integrity/audit | Partial | Bounded audit state, source ZIP checksums and private runtime exclusion. External immutable logs, backups/restore drills, key rotation and dedicated secret scanning remain outstanding. |
| 12 | Incident response/recovery | Partial | Per-source 15-minute quarantine; health endpoint stays available; no global lockout. Alert delivery, forensic retention, operator runbooks and tested disaster recovery remain outstanding. |

## Adaptive policy

| Layer | API budget | Signal threshold | Effect |
|---|---:|---|---|
| BASELINE | 180/minute/source | No risk signal | Normal bounded API budget |
| GUARDED | 90/minute/source | 3 auth failures, 2 probes, or 2 rate-limit signals | Tighten source budget |
| CONTAINMENT | 30/minute/source | 6 auth failures, 5 probes, or 4 rate-limit signals | Strict source-specific budget |
| QUARANTINE | 0/minute/source | 10 auth failures, 8 probes, or 8 rate-limit signals | 15-minute API quarantine; health remains available |

Thresholds are immutable at runtime. Client input and AI agents cannot weaken them. Quarantine is per source, not global. IP controls can affect NAT-shared users and do not solve distributed attacks.

## Additional browser/session controls

- Mutating requests that carry the ambient owner session cookie require exact Origin equality with APP_URL; cross-site Fetch Metadata is rejected.
- Production startup refuses missing, placeholder, non-HTTPS or credential-bearing APP_URL values.
- Bearer/custom-header clients are not treated as ambient-cookie clients by the CSRF guard.
- Single-use download nonce is sent in X-Owner-Download-Nonce, not URL query.
- CSP begins in report-only mode with current first-party and inventoried external origins; do not enforce until browser violations are reviewed.

## Required before production

- Set repository Private and remove/rotate exposed artifacts if identity privacy is required.
- Managed WAF/CDN/DDoS, TLS, origin restrictions and exact trusted-proxy configuration.
- Shared atomic adaptive/rate-limit storage across replicas.
- MFA/passkeys, route authorization audit, CSRF/browser end-to-end verification.
- CSP violation review then enforced CSP.
- Secret manager, key rotation/revocation, immutable external audit storage and backup restore exercises.
- Dependency/SBOM/secret scanning, reproducible build, semantic typecheck, live HTTP/proxy, multi-replica and load testing.
- Independent penetration test with remediation evidence.

No system is honestly non-hackable. The target is prevent, detect, contain, recover and continuously verify.


## v24 quarantine recovery layer

After the 15-minute QUARANTINE expires, a source enters a five-minute RECOVERY probation at 60 API requests/minute. Stale trigger counters are cleared at that transition to prevent immediate re-quarantine from old events. New signals continue to escalate normally. A clean recovery period returns the source to BASELINE. Regression test: `test/adaptive_quarantine_recovery_check.mjs`.

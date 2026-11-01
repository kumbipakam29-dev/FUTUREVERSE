# FUTUREVERSE Adaptive Defense-in-Depth — v23 candidate

## Purpose

A deterministic, per-client adaptive shield raises defensive friction when a source shows repeated probing, owner-authentication failures, or API rate abuse. This is not an "unhackable" guarantee.

## Hard-coded policy

| Layer | API budget | Escalation threshold | Effect |
|---|---:|---|---|
| BASELINE | 180/min | No current risk signals | Baseline headers and request budget |
| GUARDED | 90/min | 3 owner-auth failures, 2 probes, or 2 rate-limit signals | Tighter source-specific budget |
| CONTAINMENT | 30/min | 6 auth failures, 5 probes, or 4 rate-limit signals | Strict source-specific budget |
| QUARANTINE | 0/min | 10 auth failures, 8 probes, or 8 rate-limit signals | API requests from that source receive 429 for 15 minutes; health remains available |

Policy is immutable at runtime. Client-supplied data and AI agents cannot weaken thresholds. A successful login clears failed-login signals only; it cannot immediately clear a quarantine.

## Integrated controls

1. Baseline headers: nosniff, frame denial, referrer policy, permissions policy, same-origin opener policy, and production HSTS only for HTTPS requests.
2. Request boundary: strict JSON parsing with a 1 MiB limit, dangerous HTTP method rejection, and generic 404 for common probe paths.
3. Adaptive source-specific request limits: BASELINE → GUARDED → CONTAINMENT → QUARANTINE.
4. Existing controls remain: 5 owner-auth attempts per 15 minutes, active owner sessions for protected routes, payment and export fail-closed guards. Failed protected-route authorization also feeds the adaptive source risk counter.
5. Owner-only observability: `GET /api/security/posture` returns aggregate layer counts and recent privacy-filtered events.

## Safety and limits

- Escalation is per pseudonymous client fingerprint, not global; one attacker cannot lock out all users.
- Event records omit raw IPs, request bodies, credentials, cookies, query strings, and resource IDs. Client fingerprints use a process-ephemeral HMAC salt.
- State and event buffers are bounded. Per-client rolling timestamp arrays are capped at saturation thresholds (181 API samples, 10 auth failures, 8 probes, 8 rate-limit events), preventing request floods from growing timestamp storage without bound.
- No autonomous code, route, secret, owner-record, or policy mutation is allowed.
- The `/api/health` monitoring route is excluded from the normal per-client API budget so monitoring cannot exhaust user quotas. Repeated TRACE/TRACK/CONNECT attempts count as source probe signals. State is process-local and resets on restart. Multi-replica deployment needs shared atomic rate-limit storage and consistent trusted proxy configuration.
- This app-level layer does not replace a WAF/CDN, DDoS controls, host/container isolation, MFA/passkeys, database authorization, external immutable logs, backups, patching, dependency scanning, or independent penetration testing.
- Verify proxy/HSTS behaviour and browser CSP separately. Full build, semantic typecheck, live HTTP/browser CSRF integration, proxy integration, multi-process tests, load tests, dependency audit, and external security review are still required.

No system should be marketed as impossible to hack. The goal is layered prevention, detection, containment, recovery, and evidence.

## v24 shared-state candidate

A separate `RedisAdaptiveSecurityStore` adapter defines a multi-replica path using one atomic Lua EVAL. It uses Redis TIME, stable per-source HMAC identifiers from a 32+ byte private secret, and six keys with one Redis Cluster hash tag. The async middleware fails closed with 503 when Redis is unavailable; it never falls back to per-process memory. This adapter is not wired into the complete application server yet. See `docs/SHARED_ADAPTIVE_SECURITY_STORE.md` for provisioning, integration and tests.

A successful login does not clear failed-auth signals from the same IP because multiple legitimate users may share a NAT. Signals expire naturally after the fixed window. NAT collateral risk remains; production should combine source limits with authenticated account/session and edge controls, without attacker-triggerable account lockout.

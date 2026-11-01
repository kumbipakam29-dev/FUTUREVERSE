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
4. Existing controls remain: 5 owner-auth attempts per 15 minutes, active owner sessions for protected routes, payment and export fail-closed guards.
5. Owner-only observability: `GET /api/security/posture` returns aggregate layer counts and recent privacy-filtered events.

## Safety and limits

- Escalation is per pseudonymous client fingerprint, not global; one attacker cannot lock out all users.
- Event records omit raw IPs, request bodies, credentials, cookies, query strings, and resource IDs. Client fingerprints use a process-ephemeral HMAC salt.
- State and event buffers are bounded. Per-client rolling timestamp arrays are capped at saturation thresholds (181 API samples, 10 auth failures, 8 probes, 8 rate-limit events), preventing request floods from growing timestamp storage without bound.
- No autonomous code, route, secret, owner-record, or policy mutation is allowed.
- State is process-local and resets on restart. Multi-replica deployment needs shared atomic rate-limit storage and consistent trusted proxy configuration.
- This app-level layer does not replace a WAF/CDN, DDoS controls, host/container isolation, MFA/passkeys, database authorization, external immutable logs, backups, patching, dependency scanning, or independent penetration testing.
- Verify proxy/HSTS behaviour and browser CSP separately. Full build, semantic typecheck, HTTP integration behind the real proxy, multi-process tests, load tests, dependency audit, and external security review are still required.

No system should be marketed as impossible to hack. The goal is layered prevention, detection, containment, recovery, and evidence.

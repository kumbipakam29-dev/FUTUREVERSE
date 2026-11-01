# FUTUREVERSE Security Operations Runbook

**Applies to:** v23 adaptive defense and owner-cookie CSRF guard candidate.
**Status:** Operational guidance for review; not a substitute for a staffed security function.

## 1. What the application can do today

- Escalate a source fingerprint through BASELINE → GUARDED → CONTAINMENT → QUARANTINE.
- Quarantine a source for 15 minutes after repeated suspicious signals.
- Keep /api/health available during source quarantine.
- Reject common secret/config probing paths and TRACE/TRACK/CONNECT methods.
- Emit owner-only, privacy-filtered posture telemetry.
- Reject unsafe owner-cookie mutations when Origin is missing, cross-origin, or Fetch Metadata says cross-site.

The adaptive state is in-memory and per Node.js process. It resets at restart and does not coordinate replicas. Do not treat its posture endpoint as a fleet-wide security dashboard.

## 2. Before responding to an incident

1. Verify whether the signal is repeated malicious traffic, a scanner, a monitoring service, or a shared NAT/proxy.
2. Confirm client IP semantics at the trusted edge. Only use forwarded headers from configured proxies; never copy arbitrary X-Forwarded-For values from a client report.
3. Record the time window, affected route class, layer counts, and relevant request IDs in the approved incident system. Do not put cookies, bearer tokens, owner secrets, download nonces, raw request bodies, or private source archives in public tickets.
4. Check the source's current layer through owner-authorized posture telemetry, if available. If the source shares a corporate/mobile carrier NAT, assess collateral impact before escalating edge-level blocks.

## 3. Response by severity

### GUARDED
- Confirm which signal caused escalation.
- Review API request rate and owner-auth failure patterns.
- Keep normal service available; do not rotate keys solely because a low-confidence probe occurred.

### CONTAINMENT
- Review whether the same source is probing multiple route classes.
- Confirm route-specific authentication/rate limits are working.
- If evidence supports malicious activity, add a temporary rule at the managed CDN/WAF or trusted edge. Scope it narrowly and record owner approval.

### QUARANTINE
- The application applies a 15-minute per-source API restriction, except health checks.
- Check for shared-NAT false positives before applying wider blocks.
- Preserve in-memory posture evidence before any restart; process restart clears the adaptive counters and pseudonymous fingerprint salt.
- Do not restart the server merely to clear a quarantine. Let the bounded quarantine expire, or use a separately reviewed operator recovery procedure if one is implemented.
- For volumetric/DDoS events, engage the hosting provider/CDN/ISP. Application middleware cannot absorb network saturation upstream.

## 4. Credential/session compromise

If there is credible evidence of owner credential compromise:
1. Suspend affected privileged operations at the identity/edge layer.
2. Revoke active owner sessions and one-time download nonces using the approved operator workflow.
3. Rotate the relevant owner secret through private deployment configuration/secret manager; never commit it to Git.
4. Review authority audit metadata and deployment logs in a restricted channel.
5. Restore access only after the owner identity is re-verified and affected credentials are rotated.

The current v23 candidate does not provide MFA/passkeys, a shared distributed session store, or an externally immutable audit ledger. Those remain production blockers.

## 5. Recovery and validation

- Confirm the offending traffic has stopped.
- Verify the API health endpoint and core user journeys.
- Re-run adaptive and CSRF primitive tests.
- Review CSP report-only violations before enforcing a policy.
- Verify reverse-proxy hop count and HTTPS/HSTS behavior in the actual deployment.
- Record root cause, remediation, recovery point, and follow-up actions.

## 6. Required production dependencies

- Managed WAF/CDN and DDoS protection.
- Shared atomic rate-limit/quarantine state across replicas.
- MFA/passkeys for privileged identities.
- External immutable audit storage and tested backup/restore.
- Alert delivery and on-call ownership.
- Dependency/SBOM/secret scanning, full build/typecheck, real HTTP/proxy tests, load tests, and independent penetration testing.

**Never describe the service as non-hackable.** Report measured controls, detected incidents, tested recovery, and known limitations.

 
## Redis capacity / fingerprint-secret operations

- Use a dedicated Redis deployment with TLS, ACLs, private ingress, memory alerts and failover tests.
- Set a memory ceiling with `maxmemory-policy noeviction`; eviction can silently remove active quarantine/rate-limit state. A full store should cause explicit 503 responses, paging and edge mitigation—not a weaker local fallback.
- Monitor total keys, memory, keyspace growth by prefix, latency, rejected writes and connection backlog. Per-source bounded counters do not prevent high-cardinality source-IP key creation.
- Mitigate volumetric/high-cardinality floods at CDN/WAF/edge before requests reach the app.
- Rotate the shared HMAC fingerprint secret only with a coordinated plan: a new secret maps every client to different keys and can make existing quarantine state invisible. Preserve old key mapping until active windows expire or temporarily enforce equivalent edge controls.


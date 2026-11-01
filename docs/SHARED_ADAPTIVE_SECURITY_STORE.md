# FUTUREVERSE Shared Adaptive Security Store — v24 candidate

**Status: implementation candidate; not activated in the production application.**

## Problem this addresses
The v23 adaptive shield keeps request and risk counters in a process-local Map and uses a process-random HMAC salt. With multiple Node.js replicas, the same client can land on different instances and appear as separate sources. Restart also clears current state.

## What this candidate adds
- `RedisAdaptiveSecurityStore`: an ioredis-compatible `EVAL` adapter; the host app owns Redis client creation and lifecycle.
- Stable HMAC fingerprints from `ADAPTIVE_SECURITY_FINGERPRINT_SECRET` (minimum 32 bytes). Every replica must use the same private secret.
- One atomic Redis Lua operation for request admission, failed-auth/probe/rate counters and quarantine.
- All six Redis keys use a common `{fingerprint}` hash tag, so one operation remains in one Redis Cluster slot.
- Redis `TIME` is authoritative across app instances, avoiding application-host clock skew.
- Bounded per-source event list (250) with one-day TTL; no raw IP, cookies, credentials, query strings or request bodies.
- Health checks do not consume the normal request budget and stay available while a source is quarantined.
- Successful login does not erase failed-auth signals from other users sharing the same IP/NAT; signals age out naturally.
- Redis errors propagate and middleware returns 503. Shared mode never silently falls back to process-local counters.
- Async Express middleware can replace the local-only adaptive middleware after the complete server source is available.

## Integration contract
1. Provision private Redis/Redis Cluster with TLS, ACL credentials, network restrictions, monitoring and capacity limits.
2. Provision one random `ADAPTIVE_SECURITY_FINGERPRINT_SECRET` of at least 32 bytes and inject the same value into every replica using private configuration. Never commit it.
3. Create and PING the Redis client at startup. Fail startup if shared mode is configured but Redis is unavailable.
4. Use a client implementing `eval(script, numberOfKeys, ...keysAndArgs)` (ioredis-compatible interface).
5. Replace old local adaptive middleware with `store.middleware()` before body parsing/API routes; do not install both request-budget middlewares.
6. Set `TRUST_PROXY_HOPS` to the exact trusted proxy chain; never trust arbitrary client-supplied forwarded headers.
7. Treat `SECURITY_STORE_UNAVAILABLE` as a readiness/alert condition. Do not fall back to local counters.
8. Preserve owner auth, route authorization, CSRF, payments and export guards.

Example shape (Redis client package intentionally is not added as a runtime dependency here):
```ts
const sharedStore = new RedisAdaptiveSecurityStore({
  redis: redisClient, // host-managed ioredis-compatible client
  fingerprintSecret: process.env.ADAPTIVE_SECURITY_FINGERPRINT_SECRET || '',
});
await redisClient.ping();
app.use(sharedStore.middleware());
```

## Policy
| Layer | API budget | Trigger | Effect |
|---|---:|---|---|
| BASELINE | 180/minute/source | no active risk signal | normal budget |
| GUARDED | 90/minute/source | 3 auth failures, 2 probes, or 2 rate-limit signals | stricter budget |
| CONTAINMENT | 30/minute/source | 6 auth failures, 5 probes, or 4 rate-limit signals | strict source budget |
| QUARANTINE | 0/minute/source | 10 auth failures, 8 probes, or 8 rate-limit signals | 15-minute source quarantine; health stays available |

Successful login does not clear source failures because another user behind the same NAT may have caused them.

## Testing and claims
- Contract tests validate replica-independent fingerprints, shared Redis Cluster slots, response validation and fail-closed propagation.
- With `FV_TEST_REDIS=1`, GitHub Actions uses a real Redis server and `redis-cli` to exercise the Lua script across two independent store instances: cross-instance escalation, quarantine persistence, health availability, client isolation and shared rate budget.
- A normal mock-only run does not prove Redis Lua behaviour.
- The adapter is not yet wired into the complete app server in this source-only PR overlay. The complete application source tree is not present in GitHub main.
- Global posture aggregation is not included; event lists are per source and need a separate privacy-safe metrics pipeline.

Redis becomes a critical dependency. Monitor latency, capacity, failover and availability. This does not replace WAF/CDN, DDoS controls, MFA, route authorization, patching, host isolation, backup/restore, dependency scanning or independent penetration testing. No system is non-hackable.

 
## Redis operational safety requirements

- Run this store on a dedicated/private Redis deployment with TLS, ACLs, firewall/network controls, capacity alerts and tested failover.
- Configure a deliberate memory ceiling and `maxmemory-policy noeviction`. Do **not** use an eviction policy that can silently remove active rate-limit or quarantine keys. On write-capacity exhaustion, the adapter fails closed with 503; page the operator and scale/mitigate at the edge.
- Apply connection, command-timeout and client-side queue limits in the host Redis client. Avoid unbounded pending requests when Redis is slow.
- A stream of many distinct source IPs can still create high-cardinality keys; per-source caps do not bound total Redis cardinality. Put volumetric and IP-cardinality controls at the CDN/WAF/edge, and monitor key count, memory, rejected writes and latency.
- Fingerprint-secret rotation changes every source key. Rotating it immediately invalidates access to existing rate-limit/quarantine state. Coordinate rotation with edge mitigation or a migration that preserves old fingerprints until active state expires; do not rotate as routine housekeeping.
- Use a conservative key prefix per environment (for example separate staging and production namespaces). Never share a namespace across unrelated apps or environments.


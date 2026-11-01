# FUTUREVERSE Shared High-Risk Action Approvals — v24 candidate

**Status: shared storage primitive and tests; not wired to the complete app runtime.**

## Contract
- A caller may issue an approval only after the application has verified an active owner session and the `APPROVE_HIGH_RISK_ACTIONS` permission.
- Approval binds one actor ID, one exact tool name and a SHA-256 hash of canonicalized JSON arguments.
- Argument keys are sorted recursively; cyclic values, functions, non-finite numbers, class instances, symbols and oversized payloads are rejected.
- Bearer token is 32 random bytes encoded base64url. Only its SHA-256 digest is used as the Redis key; the raw token is never stored.
- Redis Lua sets the record with a 120-second TTL, then atomically verifies and deletes it on exact consumption.
- Wrong actor, tool or arguments return `BINDING_MISMATCH` and do not consume the valid approval.
- Correct consumption returns `CONSUMED`; replay or expiry returns `NOT_FOUND_OR_EXPIRED`.
- Redis errors propagate; callers must fail closed and must not fall back to local approvals.

## Integration rule
The store is not an authorization endpoint. The host application must create the verified owner context from server-side session/permission checks only. Never construct that context from client-supplied JSON or expose the issue function as a public route. Consume the token immediately before executing the exact high-risk action; do not place it in URLs, logs or analytics.

## Limits
This does not implement MFA/passkeys or replace the existing tool approval guard. It is a multi-replica storage adapter. The complete app source and actual high-risk tool callsites are not in the GitHub repository source tree yet, so full runtime integration is outstanding. Production requires Redis TLS/ACL/private network, audit alerting, action-level authorization review and real HTTP tests.

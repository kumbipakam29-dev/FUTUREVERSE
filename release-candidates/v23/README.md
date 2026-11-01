# FUTUREVERSE v23 Adaptive Security Candidate

## Review status

**Draft / NOT PRODUCTION READY.** This branch contains the reviewable adaptive defense service, targeted tests, and integration/design notes. The complete application ZIP is a local artifact and is not attached to this GitHub PR.

## Adaptive defense

The policy is code-owned and immutable at runtime:
- BASELINE: 180 API requests/minute per source.
- GUARDED: 90/minute after repeated auth/probe/rate-limit signals.
- CONTAINMENT: 30/minute at higher thresholds.
- QUARANTINE: 0 API requests/minute for 15 minutes after severe repeated signals; health remains available.

Escalation is per pseudonymous source fingerprint, not global. This application middleware is not a WAF and cannot guarantee an unhackable service.

## Local candidate verification

- `npm run security:check`: PASS (13 security/regression gates).
- Full application test suite: 82/82 PASS using a disposable Node 22 TypeScript-loader harness because the standard `tsx` executable was unavailable. A no-network test stub covered an SDK constructor not exercised by this suite; this is not a live provider test.
- v22→v23 source patch: applied successfully to a clean local v22 extraction; key output files matched.
- ZIP integrity: PASS, 188 entries, 11,131,291 bytes.
- SHA-256: `e32e0f976f16a6f4fbedd4d68b56047e47f3f65f49e3e1b640c0781484c3624d`.

## Outstanding

Dependency installation failed because npm registry DNS returned EAI_AGAIN. Build is blocked by missing Vite; semantic typecheck is blocked by missing `vite/client` types. No live provider, payment/RPC, HTTP/proxy, multi-replica, load, deployment or independent penetration tests were performed.

## Critical privacy warning

The source ZIP still contains owner names and one owner contact email in server-side code/constants. Do not publish it as a public release until those identifiers are moved into private deployment configuration or their owners explicitly approve public disclosure. The public UI asset scan passing does not make the source package identity-private.

See the PR description for the complete verification limitations and production security requirements.

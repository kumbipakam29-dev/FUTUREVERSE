# FUTUREVERSE v23 Adaptive Security Candidate

**Review status: DRAFT / NOT PRODUCTION READY.**

- Hard-coded adaptive source-specific layers: BASELINE → GUARDED → CONTAINMENT → QUARANTINE.
- Per-source escalation, baseline security headers, strict JSON parser limit, common probe-path handling, dangerous HTTP method rejection, owner-only posture telemetry.
- Session and one-time nonce hashes at rest; bounded session, nonce, audit, adaptive-client, event and route-rate-limit state.
- Additional DoS hardening: per-client rolling API/auth/probe/rate-limit timestamp arrays are capped at saturation thresholds; regression test exercises 25,000 repeated probe/auth/API requests.
- Local checks: `npm run security:check` PASS (13 gates), including the adaptive flood regression. Full application suite previously passed 82/82 via isolated Node 22 TS-loader harness.
- ZIP: 189 entries, 11,135,225 bytes. SHA-256: `8c550055eb99ee6d7d69d0af951a0f825084f18dd5c6ea890ccd42680486ceea`.

**Not verified:** dependency install (npm DNS EAI_AGAIN), build (Vite missing), semantic typecheck (vite/client missing), live provider, HTTP/proxy/TLS/WAF, multi-replica shared state, load/deployment, live YAGYX RPC/payment and independent penetration test.

**Privacy warning:** server source/docs still contain owner names and one owner contact email. Do not publish the source ZIP publicly until moved to private deployment configuration or explicitly approved. No system can be promised non-hackable. See PR #2 for production prerequisites and complete limitations.

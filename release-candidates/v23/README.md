# FUTUREVERSE v23 Adaptive Security — Owner Review Candidate

**Release stance: NOT PRODUCTION READY. Do not publish this source archive publicly.**

## Added security controls

- Immutable adaptive source-level policy: BASELINE → GUARDED → CONTAINMENT → QUARANTINE.
- Per-client pseudonymous HMAC fingerprints; bounded client/event/timestamp buffers; bounded LRU-style route limiter.
- Repeated probe paths, TRACE/TRACK/CONNECT attempts, protected-route authentication failures and API abuse feed the adaptive risk score.
- Source-specific containment; one attacker does not trigger a platform-wide lockout. Health checks do not consume the standard API budget.
- Security headers and production Content-Security-Policy-Report-Only, with no `unsafe-eval`.
- Owner-cookie mutations use exact same-origin Origin validation. Production startup requires a canonical HTTPS APP_URL.
- One-time archive download nonce is accepted via `X-Owner-Download-Nonce`, not URL query; browser export sends it as a header.
- Owner session and download nonce material is stored as SHA-256 digests; bounded sessions, nonces and audit logs.
- Owner-only security posture endpoint.

## Verification

- `npm run security:check`: **PASS** — 13 included security/regression gates: release ZIP/privacy, auth smoke, CSRF Origin guard, adaptive escalation/flood bounds, compute-route hardening, public UI identity scan, AI provider/task routing, scheduler, backup checksums and production gates.
- Full functional test suite: **82/82 PASS** using isolated Node 22 TypeScript-loader harness. The ordinary `tsx` command is absent. A no-network Google SDK constructor stub was used; live provider inference was not tested.
- Release archive: 191 entries; 11,139,771 bytes; ZIP integrity PASS.
- SHA-256: `dcbbac572b7d47100e518ef1bf00bccd3b02b821667304a2b920619406bf9cde`.

## Blocked / not verified

- `npm run build`: blocked because Vite is not installed.
- `npm run lint`: blocked because `vite/client` types are unavailable; semantic TypeScript check outstanding.
- Dependency install previously failed with npm registry DNS `EAI_AGAIN`; no dependency lockfile update.
- No live HTTP/browser CSRF test, TLS/reverse-proxy test, WAF/CDN/DDoS setup, multi-replica shared state, load/deployment test, live provider/payment/RPC test, or independent penetration test.
- Adaptive and route-limiter state is process-local. Production multi-replica deployments need a shared atomic store or trusted edge rate limiter.

## Critical privacy finding

The application source contains owner names and one owner contact email in server-side identity/authorization constants. The public UI asset scan passing does not make this source archive identity-private. Do not upload/publish the archive until these references are moved to private deployment configuration or the owners explicitly approve publication. The existing repository is public and contains older ZIPs; change repository visibility to Private and review prior public artifacts/links manually.

## GitHub review status

- Branch is based on main SHA `9772932c21c683eb28609e53405c6cdcc41cca23`.
- Main is unchanged; PR #2 remains draft/unmerged.
- This review branch contains the adaptive service, CSRF primitive, targeted tests and design/integration docs. It does not contain the complete application source tree or the 11 MB owner-review archive.
- Main branch protection and required CI checks are not enabled; configure them in GitHub settings.

No software should be called non-hackable. The objective is layered prevention, detection, containment, recovery and independently verified assurance.

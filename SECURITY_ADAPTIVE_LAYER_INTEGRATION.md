# v23 integration map

The v23 candidate archive contains the integrated implementation. These are the integration points for source review:

1. Add `src/server/adaptiveSecurityService.ts` from this branch to the application source.
2. Import it in `server.ts`:
   `import { adaptiveSecurityService } from './src/server/adaptiveSecurityService.ts';`
3. Configure `TRUST_PROXY_HOPS` before middleware. It must be an integer from 0 to 5 and must match the actual trusted reverse-proxy chain. Invalid values fail startup.
4. Install `app.use(adaptiveSecurityService.middleware())` before `express.json({ limit: '1mb', strict: true })` and before all API routes.
5. After the `verifyOwnerAuthorization` helper is declared, add `GET /api/security/posture`; it must require a verified owner session and return only `adaptiveSecurityService.getPosture()`.
6. Include `test/adaptive_security_layer_check.mjs` in `npm run security:check` and run the full security check.
7. Keep production deployment blocked until full build/typecheck, real proxy HTTP integration, multi-replica rate-limit storage, dependency review, load test, and independent security review pass.

The integration is source code, not a managed WAF. It intentionally does not mutate or rotate server code during an attack.

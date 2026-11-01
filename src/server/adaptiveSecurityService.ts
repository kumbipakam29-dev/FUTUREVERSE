import crypto from 'crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

/**
 * Adaptive, defense-in-depth guard for the FUTUREVERSE Express application.
 *
 * Important boundaries:
 * - Escalation is per client fingerprint, never a global self-lockout.
 * - The policy table is code-owned and cannot be changed by request input or AI agents.
 * - Quarantine applies to API calls from the suspicious client; the health probe remains available.
 * - State is process-local. Multi-replica deployments MUST add a shared rate-limit/event store
 *   at the edge before claiming fleet-wide enforcement.
 */

export type SecurityLayer = 'BASELINE' | 'GUARDED' | 'CONTAINMENT' | 'QUARANTINE';
type SecurityEventType = 'PROBE_PATH' | 'OWNER_AUTH_FAILURE' | 'RATE_LIMIT' | 'METHOD_BLOCKED';

interface ClientState {
  apiRequests: number[];
  authFailures: number[];
  probes: number[];
  rateLimitEvents: number[];
  quarantineUntil: number;
  lastSeen: number;
}

interface SecurityEvent {
  timestamp: string;
  client: string;
  type: SecurityEventType;
  layer: SecurityLayer;
  route: string;
}

const WINDOW_MS = 60_000;
const AUTH_WINDOW_MS = 15 * 60_000;
const QUARANTINE_MS = 15 * 60_000;
const MAX_CLIENTS = 20_000;
const MAX_EVENTS = 250;

/** Hard-coded defensive policy. No runtime API or AI agent can weaken these defaults. */
export const SECURITY_LAYER_POLICY: Readonly<Record<SecurityLayer, {
  maxApiRequestsPerMinute: number;
  description: string;
}>> = Object.freeze({
  BASELINE: Object.freeze({ maxApiRequestsPerMinute: 180, description: 'Normal API budget with all baseline controls active.' }),
  GUARDED: Object.freeze({ maxApiRequestsPerMinute: 90, description: 'Reduced API budget after suspicious activity.' }),
  CONTAINMENT: Object.freeze({ maxApiRequestsPerMinute: 30, description: 'Strict API budget while the source is contained.' }),
  QUARANTINE: Object.freeze({ maxApiRequestsPerMinute: 0, description: 'API calls denied for the quarantined source, except health checks.' }),
});

const PROBE_PATH_PATTERNS = [
  /(^|\/)\.env(?:\.|\/|$)/i,
  /(^|\/)\.git(?:\/|$)/i,
  /(^|\/)wp-admin(?:\/|$)/i,
  /(^|\/)wp-login\.php(?:\/|$)/i,
  /(^|\/)phpmyadmin(?:\/|$)/i,
  /(^|\/)actuator(?:\/|$)/i,
  /(^|\/)server-status(?:\/|$)/i,
  /(^|\/)\.well-known\/..*?(?:env|config)/i,
  /%2e%2e|\.\.\\|%252e%252e/i,
];

function keepRecent(values: number[], now: number, windowMs: number): number[] {
  let first = 0;
  while (first < values.length && now - values[first] > windowMs) first++;
  if (first > 0) values.splice(0, first);
  return values;
}

/** Cap timestamp samples at saturation so request floods cannot grow memory without bound. */
function pushRecentBounded(values: number[], timestamp: number, maxEntries: number): void {
  values.push(timestamp);
  if (values.length > maxEntries) values.splice(0, values.length - maxEntries);
}

function safeRoute(pathname: string): string {
  // Keep only coarse route classes. Resource IDs and user-controlled path fragments are not logged.
  if (pathname === '/api/export/owner-authenticate') return pathname;
  if (pathname === '/api/health') return pathname;
  if (pathname.startsWith('/api/')) return '/api/*';
  return '/non-api/*';
}

export class AdaptiveSecurityService {
  private readonly processSalt = crypto.randomBytes(32);
  private readonly clients = new Map<string, ClientState>();
  private readonly events: SecurityEvent[] = [];
  private operations = 0;

  private fingerprint(address: string): string {
    return crypto.createHmac('sha256', this.processSalt).update(address || 'unknown').digest('hex').slice(0, 16);
  }

  private stateFor(address: string): { key: string; state: ClientState } {
    const key = this.fingerprint(address);
    const now = Date.now();
    let state = this.clients.get(key);
    if (!state) {
      state = { apiRequests: [], authFailures: [], probes: [], rateLimitEvents: [], quarantineUntil: 0, lastSeen: now };
      this.clients.set(key, state);
    }
    state.lastSeen = now;
    this.clients.delete(key);
    this.clients.set(key, state);
    this.cleanup(now);
    return { key, state };
  }

  private cleanup(now: number): void {
    this.operations++;
    if (this.operations % 128 !== 0 && this.clients.size <= MAX_CLIENTS) return;
    for (const [key, state] of this.clients) {
      const expired = now - state.lastSeen > 30 * 60_000 && state.quarantineUntil <= now;
      if (expired) this.clients.delete(key);
    }
    while (this.clients.size > MAX_CLIENTS) {
      const oldest = this.clients.keys().next().value as string | undefined;
      if (!oldest) break;
      this.clients.delete(oldest);
    }
  }

  private layerForState(state: ClientState, now: number): SecurityLayer {
    keepRecent(state.apiRequests, now, WINDOW_MS);
    keepRecent(state.authFailures, now, AUTH_WINDOW_MS);
    keepRecent(state.probes, now, WINDOW_MS);
    keepRecent(state.rateLimitEvents, now, 5 * WINDOW_MS);

    if (state.quarantineUntil > now) return 'QUARANTINE';
    if (state.authFailures.length >= 10 || state.probes.length >= 8 || state.rateLimitEvents.length >= 8) {
      state.quarantineUntil = now + QUARANTINE_MS;
      return 'QUARANTINE';
    }
    if (state.authFailures.length >= 6 || state.probes.length >= 5 || state.rateLimitEvents.length >= 4) return 'CONTAINMENT';
    if (state.authFailures.length >= 3 || state.probes.length >= 2 || state.rateLimitEvents.length >= 2) return 'GUARDED';
    return 'BASELINE';
  }

  private appendEvent(key: string, type: SecurityEventType, layer: SecurityLayer, route: string): void {
    this.events.unshift({ timestamp: new Date().toISOString(), client: key, type, layer, route: safeRoute(route) });
    if (this.events.length > MAX_EVENTS) this.events.length = MAX_EVENTS;
  }

  public recordOwnerAuthentication(address: string, successful: boolean, route = '/api/export/owner-authenticate'): void {
    const { key, state } = this.stateFor(address);
    const now = Date.now();
    if (successful) {
      state.authFailures.length = 0;
      return;
    }
    pushRecentBounded(state.authFailures, now, 10);
    const layer = this.layerForState(state, now);
    this.appendEvent(key, 'OWNER_AUTH_FAILURE', layer, route);
  }

  public recordProbe(address: string, route: string): SecurityLayer {
    const { key, state } = this.stateFor(address);
    const now = Date.now();
    pushRecentBounded(state.probes, now, 8);
    const layer = this.layerForState(state, now);
    this.appendEvent(key, 'PROBE_PATH', layer, route);
    return layer;
  }

  /** Dangerous method probes share the probe-risk counter and retain their own event type. */
  public recordMethodBlocked(address: string, route: string): SecurityLayer {
    const { key, state } = this.stateFor(address);
    const now = Date.now();
    pushRecentBounded(state.probes, now, 8);
    const layer = this.layerForState(state, now);
    this.appendEvent(key, 'METHOD_BLOCKED', layer, route);
    return layer;
  }

  public getLayerForAddress(address: string): SecurityLayer {
    const { state } = this.stateFor(address);
    return this.layerForState(state, Date.now());
  }

  public getPosture(): {
    policy: typeof SECURITY_LAYER_POLICY;
    trackedClients: number;
    layers: Record<SecurityLayer, number>;
    activeQuarantines: number;
    recentEvents: SecurityEvent[];
  } {
    const now = Date.now();
    const layers: Record<SecurityLayer, number> = { BASELINE: 0, GUARDED: 0, CONTAINMENT: 0, QUARANTINE: 0 };
    let activeQuarantines = 0;
    for (const state of this.clients.values()) {
      const layer = this.layerForState(state, now);
      layers[layer]++;
      if (layer === 'QUARANTINE') activeQuarantines++;
    }
    return { policy: SECURITY_LAYER_POLICY, trackedClients: this.clients.size, layers, activeQuarantines, recentEvents: this.events.slice(0, 50) };
  }

  public middleware(): RequestHandler {
    return (req: Request, res: Response, next: NextFunction) => {
      const address = req.ip || req.socket.remoteAddress || 'unknown';
      const { key, state } = this.stateFor(address);
      const now = Date.now();
      const pathname = req.path || '/';
      const isApi = pathname.startsWith('/api/');

      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Referrer-Policy', 'no-referrer');
      res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
      res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
      // Begin with report-only CSP. Review browser violations before enforcement.
      if (process.env.NODE_ENV === 'production') {
        res.setHeader('Content-Security-Policy-Report-Only', [
          "default-src 'self'",
          "base-uri 'self'",
          "object-src 'none'",
          "frame-ancestors 'none'",
          "form-action 'self'",
          "script-src 'self'",
          "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
          "font-src 'self' https://fonts.gstatic.com data:",
          "img-src 'self' data: blob: https://images.unsplash.com",
          "connect-src 'self' https://rpc.yagyx.network https://explorer.yagyx.network",
          "worker-src 'self' blob:",
          "frame-src 'none'",
        ].join('; '));
      }
      if (isApi) res.setHeader('Cache-Control', 'no-store');
      if (process.env.NODE_ENV === 'production' && req.secure) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000');
      }

      if (['TRACE', 'TRACK', 'CONNECT'].includes(req.method.toUpperCase())) {
        this.recordMethodBlocked(address, pathname);
        return res.status(405).json({ error: 'HTTP method not allowed.' });
      }

      if (PROBE_PATH_PATTERNS.some((pattern) => pattern.test(pathname))) {
        this.recordProbe(address, pathname);
        return res.status(404).json({ error: 'Not found.' });
      }

      // Keep health checks independent from client API budgets so monitoring cannot
      // exhaust an otherwise legitimate user's request allowance.
      if (isApi && pathname !== '/api/health') {
        pushRecentBounded(state.apiRequests, now, SECURITY_LAYER_POLICY.BASELINE.maxApiRequestsPerMinute + 1);
        keepRecent(state.apiRequests, now, WINDOW_MS);
        const layer = this.layerForState(state, now);
        if (layer === 'QUARANTINE' && pathname !== '/api/health') {
          res.setHeader('Retry-After', String(Math.max(1, Math.ceil((state.quarantineUntil - now) / 1000))));
          return res.status(429).json({ error: 'Request temporarily restricted by adaptive security controls.', code: 'SECURITY_QUARANTINE' });
        }
        const maxRequests = SECURITY_LAYER_POLICY[layer].maxApiRequestsPerMinute;
        if (pathname !== '/api/health' && state.apiRequests.length > maxRequests) {
          pushRecentBounded(state.rateLimitEvents, now, 8);
          const escalatedLayer = this.layerForState(state, now);
          this.appendEvent(key, 'RATE_LIMIT', escalatedLayer, pathname);
          res.setHeader('Retry-After', '60');
          return res.status(429).json({ error: 'API request budget exceeded. Please retry later.', code: 'ADAPTIVE_RATE_LIMIT' });
        }
      }

      if (pathname === '/api/export/owner-authenticate' && req.method.toUpperCase() === 'POST') {
        res.once('finish', () => {
          if (res.statusCode === 401 || res.statusCode === 403 || res.statusCode === 429) this.recordOwnerAuthentication(address, false);
          else if (res.statusCode >= 200 && res.statusCode < 300) this.recordOwnerAuthentication(address, true);
        });
      }
      next();
    };
  }
}

export const adaptiveSecurityService = new AdaptiveSecurityService();

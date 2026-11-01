import crypto from 'crypto';
import { isIP } from 'net';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

/** ioredis-compatible EVAL surface. The host application owns client creation and lifecycle. */
export interface RedisEvalClient {
  eval(script: string, numberOfKeys: number, ...keysAndArgs: Array<string | number>): Promise<unknown>;
}

export type SharedSecurityAction = 'REQUEST' | 'AUTH_FAILURE' | 'AUTH_SUCCESS' | 'PROBE' | 'METHOD_BLOCKED';
export type SharedSecurityLayer = 'BASELINE' | 'GUARDED' | 'CONTAINMENT' | 'QUARANTINE';

export interface SharedSecurityDecision {
  layer: SharedSecurityLayer;
  requestCount: number;
  authFailures: number;
  probes: number;
  rateLimitSignals: number;
  retryAfterMs: number;
  allowed: boolean;
  reason: 'OK' | 'RATE_LIMIT' | 'QUARANTINE';
}

export interface SharedAdaptiveSecurityOptions {
  redis: RedisEvalClient;
  /** Must be the same private random secret on every replica; never commit it to source control. */
  fingerprintSecret: string;
  namespace?: string;
  requestId?: () => string;
}

const DEFAULT_NAMESPACE = 'futureverse:adaptive-security:v1';
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

/**
 * One atomic Redis Lua operation for request admission and risk-signal updates.
 * All six keys share the same Redis Cluster hash-tag: {fingerprint}.
 * Sliding-window ZSET counters and quarantine are updated in one EVAL operation.
 */
export const SHARED_ADAPTIVE_SECURITY_LUA = String.raw`
local requestsKey = KEYS[1]
local authKey = KEYS[2]
local probesKey = KEYS[3]
local rateKey = KEYS[4]
local quarantineKey = KEYS[5]
local eventsKey = KEYS[6]

local action = ARGV[1]
local member = ARGV[2]
local fingerprint = ARGV[3]
local isHealth = ARGV[4] == '1'
local redisTime = redis.call('TIME')
local now = tonumber(redisTime[1]) * 1000 + math.floor(tonumber(redisTime[2]) / 1000)

local function prune(key, window)
  redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
  redis.call('PEXPIRE', key, math.max(window * 2, 60000))
end

prune(requestsKey, 60000)
prune(authKey, 900000)
prune(probesKey, 60000)
prune(rateKey, 300000)

local function addSignal(key, window)
  redis.call('ZADD', key, now, member)
  redis.call('PEXPIRE', key, math.max(window * 2, 60000))
end

if action == 'REQUEST' then
  if not isHealth then addSignal(requestsKey, 60000) end
elseif action == 'AUTH_FAILURE' then
  addSignal(authKey, 900000)
elseif action == 'AUTH_SUCCESS' then
  -- A successful login must not erase failures recorded by other users behind the same NAT/IP.
  -- Failed-auth signals age out naturally through the 15-minute sliding window.
elseif action == 'PROBE' or action == 'METHOD_BLOCKED' then
  addSignal(probesKey, 60000)
end

local requestCount = redis.call('ZCARD', requestsKey)
local authCount = redis.call('ZCARD', authKey)
local probeCount = redis.call('ZCARD', probesKey)
local rateCount = redis.call('ZCARD', rateKey)
local quarantineUntil = tonumber(redis.call('GET', quarantineKey) or '0')
local wasQuarantined = quarantineUntil > now

local function resolveLayer()
  if quarantineUntil > now then return 'QUARANTINE' end
  if authCount >= 10 or probeCount >= 8 or rateCount >= 8 then
    quarantineUntil = now + 900000
    redis.call('SET', quarantineKey, tostring(quarantineUntil), 'PX', 900000)
    return 'QUARANTINE'
  end
  if authCount >= 6 or probeCount >= 5 or rateCount >= 4 then return 'CONTAINMENT' end
  if authCount >= 3 or probeCount >= 2 or rateCount >= 2 then return 'GUARDED' end
  return 'BASELINE'
end

local layer = resolveLayer()
local allowed = 1
local reason = 'OK'
local retryAfter = 0

if action == 'REQUEST' and not isHealth then
  if layer == 'QUARANTINE' then
    allowed = 0
    reason = 'QUARANTINE'
    retryAfter = math.max(1, quarantineUntil - now)
  else
    local limit = 180
    if layer == 'GUARDED' then limit = 90 end
    if layer == 'CONTAINMENT' then limit = 30 end
    if requestCount > limit then
      addSignal(rateKey, 300000)
      rateCount = redis.call('ZCARD', rateKey)
      layer = resolveLayer()
      allowed = 0
      reason = layer == 'QUARANTINE' and 'QUARANTINE' or 'RATE_LIMIT'
      retryAfter = layer == 'QUARANTINE' and math.max(1, quarantineUntil - now) or 60000
    end
  end
end

if action ~= 'REQUEST' then
  redis.call('LPUSH', eventsKey, tostring(now) .. '|' .. fingerprint .. '|' .. action .. '|' .. layer)
  redis.call('LTRIM', eventsKey, 0, 249)
  redis.call('PEXPIRE', eventsKey, 86400000)
elseif not allowed then
  local eventType = reason == 'QUARANTINE' and 'QUARANTINE_BLOCK' or 'RATE_LIMIT'
  redis.call('LPUSH', eventsKey, tostring(now) .. '|' .. fingerprint .. '|' .. eventType .. '|' .. layer)
  redis.call('LTRIM', eventsKey, 0, 249)
  redis.call('PEXPIRE', eventsKey, 86400000)
end

if not wasQuarantined and layer == 'QUARANTINE' then
  redis.call('LPUSH', eventsKey, tostring(now) .. '|' .. fingerprint .. '|LAYER_ESCALATED|QUARANTINE')
  redis.call('LTRIM', eventsKey, 0, 249)
  redis.call('PEXPIRE', eventsKey, 86400000)
end

return { layer, requestCount, authCount, probeCount, rateCount, retryAfter, allowed, reason }
`;

function parseDecision(raw: unknown): SharedSecurityDecision {
  if (!Array.isArray(raw) || raw.length < 8) throw new Error('SHARED_SECURITY_STORE_INVALID_RESPONSE');
  const [layerRaw, requestsRaw, authRaw, probesRaw, ratesRaw, retryRaw, allowedRaw, reasonRaw] = raw;
  const validLayers: SharedSecurityLayer[] = ['BASELINE', 'GUARDED', 'CONTAINMENT', 'QUARANTINE'];
  const layer = String(layerRaw) as SharedSecurityLayer;
  if (!validLayers.includes(layer)) throw new Error('SHARED_SECURITY_STORE_INVALID_LAYER');
  const reason = String(reasonRaw) as SharedSecurityDecision['reason'];
  const allowedNumber = Number(allowedRaw);
  if (!['OK', 'RATE_LIMIT', 'QUARANTINE'].includes(reason)) throw new Error('SHARED_SECURITY_STORE_INVALID_REASON');
  if (![0, 1].includes(allowedNumber)) throw new Error('SHARED_SECURITY_STORE_INVALID_ALLOWED_FLAG');
  const numeric = [requestsRaw, authRaw, probesRaw, ratesRaw, retryRaw].map(Number);
  if (numeric.some((value) => !Number.isSafeInteger(value) || value < 0)) throw new Error('SHARED_SECURITY_STORE_INVALID_COUNTER');
  return {
    layer,
    requestCount: numeric[0],
    authFailures: numeric[1],
    probes: numeric[2],
    rateLimitSignals: numeric[3],
    retryAfterMs: numeric[4],
    allowed: allowedNumber === 1,
    reason,
  };
}

export function createSharedClientFingerprint(address: string, secret: string): string {
  if (typeof secret !== 'string' || Buffer.byteLength(secret, 'utf8') < 32) {
    throw new Error('ADAPTIVE_SECURITY_FINGERPRINT_SECRET_MUST_BE_AT_LEAST_32_BYTES');
  }
  const normalized = typeof address === 'string' ? address.trim() : '';
  if (!normalized || normalized.toLowerCase() === 'unknown' || isIP(normalized) === 0) {
    throw new Error('ADAPTIVE_SECURITY_CLIENT_IP_UNAVAILABLE_OR_INVALID');
  }
  return crypto.createHmac('sha256', secret).update(normalized).digest('hex').slice(0, 32);
}

/**
 * Shared multi-replica state adapter.
 * IMPORTANT: callers must fail closed (503) if Redis is unavailable; never silently fall back
 * to a process-local map when shared mode is configured.
 */
export class RedisAdaptiveSecurityStore {
  private readonly redis: RedisEvalClient;
  private readonly secret: string;
  private readonly namespace: string;
  private readonly requestId: () => string;

  constructor(options: SharedAdaptiveSecurityOptions) {
    if (!options?.redis || typeof options.redis.eval !== 'function') throw new Error('ADAPTIVE_SECURITY_REDIS_CLIENT_REQUIRED');
    if (typeof options.namespace === 'string' && !/^[a-zA-Z0-9:_-]{1,64}$/.test(options.namespace)) throw new Error('ADAPTIVE_SECURITY_NAMESPACE_INVALID');
    // Validate the secret and its stable fingerprint contract at construction time.
    createSharedClientFingerprint('127.0.0.1', options.fingerprintSecret);
    this.redis = options.redis;
    this.secret = options.fingerprintSecret;
    this.namespace = options.namespace || DEFAULT_NAMESPACE;
    this.requestId = options.requestId || crypto.randomUUID;
  }

  private async execute(address: string, action: SharedSecurityAction, isHealth = false): Promise<SharedSecurityDecision> {
    const fingerprint = createSharedClientFingerprint(address, this.secret);
    const tag = `{${fingerprint}}`;
    const root = `${this.namespace}:${tag}`;
    const keys = [
      `${root}:requests`,
      `${root}:auth`,
      `${root}:probes`,
      `${root}:rate`,
      `${root}:quarantine`,
      `${root}:events`,
    ];
    // EVAL is atomic in Redis. All keys use one cluster hash slot.
    const result = await this.redis.eval(
      SHARED_ADAPTIVE_SECURITY_LUA,
      keys.length,
      ...keys,
      action,
      this.requestId(),
      fingerprint,
      isHealth ? 1 : 0,
    );
    return parseDecision(result);
  }

  public evaluateRequest(address: string, isHealth = false): Promise<SharedSecurityDecision> {
    return this.execute(address, 'REQUEST', isHealth);
  }

  public recordOwnerAuthentication(address: string, successful: boolean): Promise<SharedSecurityDecision> {
    return this.execute(address, successful ? 'AUTH_SUCCESS' : 'AUTH_FAILURE');
  }

  public recordProbe(address: string): Promise<SharedSecurityDecision> {
    return this.execute(address, 'PROBE');
  }

  public recordMethodBlocked(address: string): Promise<SharedSecurityDecision> {
    return this.execute(address, 'METHOD_BLOCKED');
  }

  /**
   * Drop-in asynchronous Express middleware for distributed deployments.
   * Redis errors return 503; this never silently falls back to local counters.
   */
  public middleware(): RequestHandler {
    return (req: Request, res: Response, next: NextFunction) => {
      const address = req.ip || req.socket.remoteAddress || '';
      const pathname = req.path || '/';
      const isApi = pathname.startsWith('/api/');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Referrer-Policy', 'no-referrer');
      res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
      res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
      if (isApi) res.setHeader('Cache-Control', 'no-store');
      if (process.env.NODE_ENV === 'production' && req.secure) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000');
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
          "connect-src 'self' https://rpc.yagyx.network  https://explorer.yagyx.network",
          "worker-src 'self' blob:",
          "frame-src 'none'",
        ].join('; '));
      }

      void (async () => {
        if (['TRACE', 'TRACK', 'CONNECT'].includes(req.method.toUpperCase())) {
          await this.recordMethodBlocked(address);
          res.status(405).json({ error: 'HTTP method not allowed.' });
          return;
        }
        if (PROBE_PATH_PATTERNS.some((pattern) => pattern.test(pathname))) {
          await this.recordProbe(address);
          res.status(404).json({ error: 'Not found.' });
          return;
        }
        if (isApi) {
          const decision = await this.evaluateRequest(address, pathname === '/api/health');
          if (!ecision.allowed) {
            res.setHeader('Retry-After', String(Math.max(1, Math.ceil(decision.retryAfterMs / 1000))));
            res.status(429).json( {
              error: decision.reason === 'QUARANTINE' ? 'Request temporarily restricted by adaptive security controls.' : 'API request budget exceeded. Please retry later.',
              code: decision.reason === 'QUARANTINE' ? 'SECURITY_QUARANTINE' : 'ADAPTIVE_RATE_LIMIT',
              layer: decision.layer,
            });
            return;
          }
        }
        if (pathname === '/api/export/owner-authenticate' && req.method.toUpperCase() === 'POST') {
          res.once('finish', () => {
            const successful = res.statusCode >= 200 && res.statusCode < 300;
            if (successful || res.statusCode === 401 || res.statusCode === 403 || res.statusCode === 429) {
              void this.recordOwnerAuthentication(address, successful).catch(() => {
                // Do not leak connection details or auth context. Redis health monitoring must alert separately.
              });
            }
          });
        }
        next();
      })().catch(() => {
        if (res.headersSent) return;
        res.setHeader('Retry-After', '5');
        res.status(503).json({ error: 'Security controls are temporarily unavailable.', code: 'SECURITY_STORE_UNAVAILABLE' });
      });
    };
  }
}

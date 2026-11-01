import crypto from 'crypto';
import type { RedisEvalClient } from './sharedAdaptiveSecurityStore.ts';

export const HIGH_RISK_APPROVAL_TTL_MS = 120_000;
export const HIGH_RISK_APPROVAL_PERMISSION = 'APPROVE_HIGH_RISK_ACTIONS';
const DEFAULT_NAMESPACE = 'futureverse:high-risk-approval:v1';
const MAX_ARGUMENT_BYTES = 65_536;

export interface VerifiedOwnerApprovalContext {
  ownerSessionVerified: true;
  permissions: readonly string[];
  actorId: string;
}

export interface HighRiskApprovalOptions {
  redis: RedisEvalClient;
  namespace?: string;
  tokenFactory?: () => string;
}

export interface IssuedHighRiskApproval {
  token: string;
  expiresInSeconds: 120;
}

export type HighRiskApprovalConsumption = 'CONSUMED' | 'NOT_FOUND_OR_EXPIRED' | 'BINDING_MISMATCH';

/**
 * Redis Lua issue script: create a 120-second approval record only if the nonce digest is unused.
 * The raw bearer token is never stored in Redis.
 */
export const HIGH_RISK_APPROVAL_ISSUE_LUA = [
  "if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end",
  "redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])",
  'return 1',
].join('\n');

/**
 * Redis Lua consume script: actor, tool and canonical argument hash must all match.
 * A mismatch leaves the approval intact for the legitimate exact action; a match deletes atomically.
 */
export const HIGH_RISK_APPROVAL_CONSUME_LUA = [
  "local raw = redis.call('GET', KEYS[1])",
  'if not raw then return 0 end',
  'local payload = cjson.decode(raw)',
  'if payload.actorId ~= ARGV[1] then return -1 end',
  'if payload.toolName ~= ARGV[2] then return -1 end',
  'if payload.argumentHash ~= ARGV[3] then return -1 end',
  "redis.call('DEL', KEYS[1])",
  'return 1',
].join('\n');

function canonicalJson(value: unknown, seen = new Set<object>()): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('APPROVAL_ARGUMENT_NUMBER_INVALID');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error('APPROVAL_ARGUMENT_CYCLE_DETECTED');
    seen.add(value);
    const result = '[' + value.map((item) => canonicalJson(item, seen)).join(',') + ']';
    seen.delete(value);
    return result;
  }
  if (typeof value === 'object') {
    const objectValue = value as Record<string, unknown>;
    const prototype = Object.getPrototypeOf(objectValue);
    if (prototype !== Object.prototype && prototype !== null) throw new Error('APPROVAL_ARGUMENT_OBJECT_TYPE_INVALID');
    if (seen.has(objectValue)) throw new Error('APPROVAL_ARGUMENT_CYCLE_DETECTED');
    if (Object.getOwnPropertySymbols(objectValue).length > 0) throw new Error('APPROVAL_ARGUMENT_SYMBOL_KEY_INVALID');
    seen.add(objectValue);
    const keys = Object.keys(objectValue).sort();
    const result = '{' + keys.map((key) => JSON.stringify(key) + ':' + canonicalJson(objectValue[key], seen)).join(',') + '}';
    seen.delete(objectValue);
    return result;
  }
  throw new Error('APPROVAL_ARGUMENT_TYPE_INVALID');
}

export function hashHighRiskArguments(args: unknown): string {
  const canonical = canonicalJson(args);
  if (Buffer.byteLength(canonical, 'utf8') > MAX_ARGUMENT_BYTES) throw new Error('APPROVAL_ARGUMENTS_TOO_LARGE');
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

function validateActorId(actorId: string): void {
  if (typeof actorId !== 'string' || !/^[a-zA-Z0-9_.:@-]{1,160}$/.test(actorId)) {
    throw new Error('APPROVAL_ACTOR_ID_INVALID');
  }
}

function validateToolName(toolName: string): void {
  if (typeof toolName !== 'string' || !/^[a-zA-Z0-9_.:-]{1,128}$/.test(toolName)) {
    throw new Error('APPROVAL_TOOL_NAME_INVALID');
  }
}

function tokenDigest(token: string): string {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('APPROVAL_TOKEN_INVALID');
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

function canonicalNamespace(namespace: string | undefined): string {
  const value = namespace || DEFAULT_NAMESPACE;
  if (!/^[a-zA-Z0-9:_-]{1,64}$/.test(value)) throw new Error('APPROVAL_NAMESPACE_INVALID');
  return value;
}

export class RedisHighRiskApprovalStore {
  private readonly redis: RedisEvalClient;
  private readonly namespace: string;
  private readonly tokenFactory: () => string;

  constructor(options: HighRiskApprovalOptions) {
    if (!options?.redis || typeof options.redis.eval !== 'function') throw new Error('APPROVAL_REDIS_CLIENT_REQUIRED');
    this.redis = options.redis;
    this.namespace = canonicalNamespace(options.namespace);
    this.tokenFactory = options.tokenFactory || (() => crypto.randomBytes(32).toString('base64url'));
  }

  /**
   * Call only after the application has verified the active owner session and permission.
   * This class is a storage primitive, not an HTTP authorization endpoint.
   */
  public async issueApproval(
    authority: VerifiedOwnerApprovalContext,
    toolName: string,
    args: unknown,
  ): Promise<IssuedHighRiskApproval> {
    if (!authority || authority.ownerSessionVerified !== true) throw new Error('APPROVAL_VERIFIED_OWNER_SESSION_REQUIRED');
    if (!Array.isArray(authority.permissions) || !authority.permissions.includes(HIGH_RISK_APPROVAL_PERMISSION)) {
      throw new Error('APPROVAL_PERMISSION_REQUIRED');
    }
    validateActorId(authority.actorId);
    validateToolName(toolName);
    const argumentHash = hashHighRiskArguments(args);
    const token = this.tokenFactory();
    const digest = tokenDigest(token);
    const key = this.namespace + ':' + digest;
    const payload = JSON.stringify({ actorId: authority.actorId, toolName, argumentHash });
    const result = Number(await this.redis.eval(HIGH_RISK_APPROVAL_ISSUE_LUA, 1, key, payload, HIGH_RISK_APPROVAL_TTL_MS));
    if (result !== 1) throw new Error('APPROVAL_NONCE_COLLISION_OR_STORE_REJECTED');
    return { token, expiresInSeconds: 120 };
  }

  /**
   * Exact actor/tool/arguments binding. Correct consumption deletes the nonce atomically;
   * mismatches do not burn another legitimate action's approval.
   */
  public async consumeApproval(
    token: string,
    actorId: string,
    toolName: string,
    args: unknown,
  ): Promise<HighRiskApprovalConsumption> {
    validateActorId(actorId);
    validateToolName(toolName);
    const digest = tokenDigest(token);
    const argumentHash = hashHighRiskArguments(args);
    const result = Number(await this.redis.eval(
      HIGH_RISK_APPROVAL_CONSUME_LUA,
      1,
      this.namespace + ':' + digest,
      actorId,
      toolName,
      argumentHash,
    ));
    if (result === 1) return 'CONSUMED';
    if (result === -1) return 'BINDING_MISMATCH';
    if (result === 0) return 'NOT_FOUND_OR_EXPIRED';
    throw new Error('APPROVAL_STORE_INVALID_RESPONSE');
  }
}

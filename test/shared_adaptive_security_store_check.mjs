import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'fv-shared-security-'));
try {
  const sourcePath = path.join(root, 'src/server/sharedAdaptiveSecurityStore.ts');
  const source = fs.readFileSync(sourcePath, 'utf8');
  const compiled = ts.transpileModule(source, {
    fileName: sourcePath,
    reportDiagnostics: true,
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, verbatimModuleSyntax: false },
  });
  const syntaxErrors = (compiled.diagnostics || []).filter((item) => item.category === ts.DiagnosticCategory.Error);
  assert.equal(syntaxErrors.length, 0, 'shared store TypeScript must transpile');
  const modulePath = path.join(temp, 'sharedAdaptiveSecurityStore.mjs');
  fs.writeFileSync(modulePath, compiled.outputText, 'utf8');
  const {
    RedisAdaptiveSecurityStore,
    SHARED_ADAPTIVE_SECURITY_LUA,
    createSharedClientFingerprint,
  } = await import(pathToFileURL(modulePath).href);

  const secret = 'test-only-shared-adaptive-secret-32-bytes-minimum';
  let counter = 0;
  const calls = [];
  const fakeRedis = {
    async eval(script, numberOfKeys, ...keysAndArgs) {
      calls.push({ script, numberOfKeys, keysAndArgs });
      const action = String(keysAndArgs[numberOfKeys]);
      if (action === 'AUTH_FAILURE') return ['GUARDED', 0, 3, 0, 0, 0, 1, 'OK'];
      if (action === 'AUTH_SUCCESS') return ['GUARDED', 0, 3, 0, 0, 0, 1, 'OK'];
      if (action === 'PROBE' || action === 'METHOD_BLOCKED') return ['GUARDED', 0, 0, 2, 0, 0, 1, 'OK'];
      if (action === 'REQUEST' && String(keysAndArgs[numberOfKeys + 3]) === '1') return ['QUARANTINE', 0, 10, 8, 8, 500_000, 1, 'OK'];
      if (action === 'REQUEST') return ['BASELINE', 1, 0, 0, 0, 0, 1, 'OK'];
      throw new Error('unexpected test action');
    },
  };
  const options = {
    redis: fakeRedis,
    fingerprintSecret: secret,
    requestId: () => `request-${++counter}`,
  };
  const replicaA = new RedisAdaptiveSecurityStore(options);
  const replicaB = new RedisAdaptiveSecurityStore(options);

  const fingerprintA = createSharedClientFingerprint('198.51.100.12', secret);
  const fingerprintB = createSharedClientFingerprint('198.51.100.12', secret);
  assert.equal(fingerprintA, fingerprintB, 'same private secret and client IP must produce the same replica-independent fingerprint');
  assert.notEqual(fingerprintA, createSharedClientFingerprint('198.51.100.12', `${secret}-rotated`), 'secret rotation must change the fingerprint');
  assert.throws(() => new RedisAdaptiveSecurityStore({ ...options, fingerprintSecret: 'short' }), /AT_LEAST_32_BYTES/);
  assert.throws(() => createSharedClientFingerprint('unknown', secret), /IP_UNAVAILABLE/);
  assert.throws(() => createSharedClientFingerprint('not-an-ip', secret), /IP_UNAVAILABLE/);

  const first = await replicaA.evaluateRequest('198.51.100.12');
  const second = await replicaB.evaluateRequest('198.51.100.12');
  assert.equal(first.layer, 'BASELINE');
  assert.equal(first.allowed, true);
  assert.equal(second.layer, 'BASELINE');
  assert.equal(calls.length, 2);
  const firstCall = calls[0];
  const secondCall = calls[1];
  assert.equal(firstCall.numberOfKeys, 6);
  assert.deepEqual(firstCall.keysAndArgs.slice(0, 6), secondCall.keysAndArgs.slice(0, 6), 'both replicas must address identical Redis keys');
  const keyTags = firstCall.keysAndArgs.slice(0, 6).map((key) => String(key).match(/\{([^}]+)\}/)?.[1]);
  assert.ok(keyTags.every((tag) => tag === fingerprintA), 'all keys must share a Redis Cluster hash slot');
  assert.match(firstCall.script, /redis\.call\('TIME'\)/, 'Redis server time must be authoritative across replicas');
  assert.match(firstCall.script, /ZREMRANGEBYSCORE/);
  assert.match(firstCall.script, /ZADD/);
  assert.match(firstCall.script, /ZCARD', key\) < maxEntries/, 'per-client counter ZSETs must stop growing after their risk threshold is saturated');
  assert.match(firstCall.script, /redis\.call\('SET', quarantineKey[\s\S]*'PX', 900000\)/);
  assert.match(firstCall.script, /redis\.call\('LTRIM', eventsKey, 0, 249\)/);

  const failedLogin = await replicaA.recordOwnerAuthentication('198.51.100.12', false);
  assert.equal(failedLogin.layer, 'GUARDED');
  const successfulLogin = await replicaB.recordOwnerAuthentication('198.51.100.12', true);
  assert.equal(successfulLogin.layer, 'GUARDED', 'one successful login must not erase failures from other users on a shared IP');
  assert.equal(successfulLogin.authFailures, 3);
  const probe = await replicaB.recordProbe('198.51.100.12');
  assert.equal(probe.probes, 2);
  const method = await replicaA.recordMethodBlocked('198.51.100.12');
  assert.equal(method.layer, 'GUARDED');
  const health = await replicaA.evaluateRequest('198.51.100.12', true);
  assert.equal(health.allowed, true, 'health requests must not be blocked by the normal request budget');
  assert.equal(health.layer, 'QUARANTINE', 'health probe reports but does not bypass or clear quarantine state');

  const brokenRedis = { eval: async () => { throw new Error('redis unavailable'); } };
  const failClosed = new RedisAdaptiveSecurityStore({ ...options, redis: brokenRedis });
  await assert.rejects(() => failClosed.evaluateRequest('198.51.100.12'), /redis unavailable/, 'store errors must propagate; caller must fail closed rather than silently use local counters');
  const malformedRedis = { eval: async () => ['UNKNOWN', 0, 0, 0, 0, 0, 1, 'OK'] };
  const malformed = new RedisAdaptiveSecurityStore({ ...options, redis: malformedRedis });
  await assert.rejects(() => malformed.evaluateRequest('198.51.100.12'), /INVALID_LAYER/);

  const middlewareRedis = {
    async eval(_script, numberOfKeys, ...keysAndArgs) {
      const action = String(keysAndArgs[numberOfKeys]);
      if (action === 'PROBE' || action === 'METHOD_BLOCKED') return ['GUARDED', 0, 0, 2, 0, 0, 1, 'OK'];
      if (middlewareRedis.mode === 'quarantine') return ['QUARANTINE', 0, 0, 0, 0, 300_000, 0, 'QUARANTINE'];
      return ['BASELINE', 1, 0, 0, 0, 0, 1, 'OK'];
    },
    mode: 'allow',
  };
  const middlewareStore = new RedisAdaptiveSecurityStore({ ...options, redis: middlewareRedis });
  const makeResponse = () => ({
    headers: {}, statusCode: 200, body: undefined, headersSent: false, finishHandler: undefined,
    setHeader(name, value) { this.headers[name] = value; return this; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; this.headersSent = true; return this; },
    once(event, callback) { if (event === 'finish') this.finishHandler = callback; return this; },
  });
  const runMiddleware = async (request) => {
    const response = makeResponse();
    let nextCalled = false;
    middlewareStore.middleware()(request, response, () => { nextCalled = true; });
    await new Promise((resolve) => setImmediate(resolve));
    return { response, nextCalled };
  };
  const allowedRequest = await runMiddleware({ ip: '198.51.100.31', socket: { remoteAddress: '198.51.100.31' }, path: '/api/test', method: 'GET', secure: false });
  assert.equal(allowedRequest.nextCalled, true, 'allowed request must reach the application');
  assert.equal(allowedRequest.response.headers['Cache-Control'], 'no-store');
  middlewareRedis.mode = 'quarantine';
  const blockedRequest = await runMiddleware({ ip: '198.51.100.32', socket: { remoteAddress: '198.51.100.32' }, path: '/api/test', method: 'GET', secure: false });
  assert.equal(blockedRequest.nextCalled, false, 'quarantined request must not reach the application');
  assert.equal(blockedRequest.response.statusCode, 429);
  assert.equal(blockedRequest.response.body.code, 'SECURITY_QUARANTINE');
  assert.equal(blockedRequest.response.headers['Retry-After'], '300');
  middlewareRedis.mode = 'allow';
  const failedStore = new RedisAdaptiveSecurityStore({ ...options, redis: brokenRedis });
  const unavailableResponse = makeResponse();
  let unavailableNextCalled = false;
  failedStore.middleware()({ ip: '198.51.100.33', socket: { remoteAddress: '198.51.100.33' }, path: '/api/test', method: 'GET', secure: false }, unavailableResponse, () => { unavailableNextCalled = true; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(unavailableNextCalled, false, 'Redis outage must not fail open to the application');
  assert.equal(unavailableResponse.statusCode, 503);
  assert.equal(unavailableResponse.body.code, 'SECURITY_STORE_UNAVAILABLE');

  console.log('SHARED_ADAPTIVE_SECURITY_STORE_CHECK==PASS (26 contract assertions + middleware fail-closed assertions)');

  if (process.env.FV_TEST_REDIS === '1') {
    const port = process.env.REDIS_PORT || '6389';
    const redisCli = (...args) => execFileSync('redis-cli', ['-h', '127.0.0.1', '-p', port, '--raw', ...args.map(String)], { encoding: 'utf8' }).trim();
    assert.equal(redisCli('PING'), 'PONG', 'real Redis service must be reachable for integration tests');
    redisCli('FLUSHDB');
    const realRedis = {
      async eval(script, numberOfKeys, ...keysAndArgs) {
        const output = execFileSync('redis-cli', ['-h', '127.0.0.1', '-p', port, '--raw', 'EVAL', script, String(numberOfKeys), ...keysAndArgs.map(String)], { encoding: 'utf8', maxBuffer: 2 * 1024 * 1024 });
        return output.trimEnd().split(/\r?\n/);
      },
    };
    const sharedOptions = { redis: realRedis, fingerprintSecret: 'real-redis-test-shared-secret-32-bytes-minimum', namespace: `fv:test:${process.pid}` };
    const serverOne = new RedisAdaptiveSecurityStore(sharedOptions);
    const serverTwo = new RedisAdaptiveSecurityStore(sharedOptions);

    const sharedAuthAddress = '198.51.100.20';
    for (let i = 0; i < 3; i++) await serverOne.recordOwnerAuthentication(sharedAuthAddress, false);
    const crossReplica = await serverTwo.evaluateRequest(sharedAuthAddress);
    assert.equal(crossReplica.layer, 'GUARDED', 'auth failures recorded by one replica must escalate the other replica');
    assert.equal(crossReplica.allowed, true, 'guarded layer still admits a low-volume request');

    const quarantinedAddress = '198.51.100.21';
    for (let i = 0; i < 10; i++) await serverOne.recordOwnerAuthentication(quarantinedAddress, false);
    await serverTwo.recordOwnerAuthentication(quarantinedAddress, true);
    const quarantined = await serverTwo.evaluateRequest(quarantinedAddress);
    assert.equal(quarantined.layer, 'QUARANTINE', 'quarantine state must be shared across replicas');
    assert.equal(quarantined.allowed, false, 'successful login must not clear an active quarantine');
    const healthWhileQuarantined = await serverTwo.evaluateRequest(quarantinedAddress, true);
    assert.equal(healthWhileQuarantined.allowed, true, 'health checks remain available during shared quarantine');
    assert.equal(healthWhileQuarantined.layer, 'QUARANTINE', 'health checks must not clear quarantine');

    const unaffected = await serverTwo.evaluateRequest('203.0.113.99');
    assert.equal(unaffected.layer, 'BASELINE', 'one quarantined source must not affect other users');
    assert.equal(unaffected.allowed, true);

    const rateAddress = '198.51.100.22';
    let lastDecision;
    for (let i = 0; i < 181; i++) {
      lastDecision = i % 2 === 0 ? await serverOne.evaluateRequest(rateAddress) : await serverTwo.evaluateRequest(rateAddress);
    }
    assert.equal(lastDecision.layer, 'BASELINE');
    assert.equal(lastDecision.allowed, false, 'request budget must be shared atomically between replicas');
    assert.equal(lastDecision.reason, 'RATE_LIMIT');
    const boundedIp = '198.51.100.23';
    for (let i = 0; i < 400; i++) await serverOne.evaluateRequest(boundedIp);
    const boundedFingerprint = createSharedClientFingerprint(boundedIp, sharedOptions.fingerprintSecret);
    const boundedRoot = `fv:test:${process.pid}:{${boundedFingerprint}}`;
    assert.equal(Number(redisCli('ZCARD', boundedRoot + ':requests')), 181, 'request counter must saturate at baseline threshold + 1 even during continued quarantine traffic');
    assert.ok(Number(redisCli('ZCARD', boundedRoot + ':rate')) <= 8, 'rate-limit signal storage must be capped at the quarantine threshold');
    assert.ok(Number(redisCli('LLEN', boundedRoot + ':events')) <= 250, 'per-client event list must remain bounded');
    const boundedAuthIp = '198.51.100.24';
    for (let i = 0; i < 30; i++) await serverOne.recordOwnerAuthentication(boundedAuthIp, false);
    const boundedAuthFp = createSharedClientFingerprint(boundedAuthIp, sharedOptions.fingerprintSecret);
    assert.equal(Number(redisCli('ZCARD', `fv:test:${process.pid}:{${boundedAuthFp}}:auth`)), 10, 'auth failure storage must saturate at quarantine threshold');
    const boundedProbeIp = '198.51.100.25';
    for (let i = 0; i < 30; i++) await serverOne.recordProbe(boundedProbeIp);
    const boundedProbeFp = createSharedClientFingerprint(boundedProbeIp, sharedOptions.fingerprintSecret);
    assert.equal(Number(redisCli('ZCARD', `fv:test:${process.pid}:{${boundedProbeFp}}:probes`)), 8, 'probe storage must saturate at quarantine threshold');
    console.log('REAL_REDIS_LUA_INTEGRATION=PASS (18 assertions across two independent store instances + bounded flood counters)');
  } else {
    console.log('REAL_REDIS_LUA_INTEGRATION=SKIPPED (set FV_TEST_REDIS=1 with an isolated Redis server)');
  }
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'fv-high-risk-approval-'));
try {
  const sourcePath = path.join(root, 'src/server/sharedHighRiskApprovalStore.ts');
  const source = fs.readFileSync(sourcePath, 'utf8');
  const compiled = ts.transpileModule(source, {
    fileName: sourcePath,
    reportDiagnostics: true,
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, verbatimModuleSyntax: false },
  });
  const errors = (compiled.diagnostics || []).filter((item) => item.category === ts.DiagnosticCategory.Error);
  assert.equal(errors.length, 0, 'approval store TypeScript must transpile');
  const modulePath = path.join(temp, 'sharedHighRiskApprovalStore.mjs');
  fs.writeFileSync(modulePath, compiled.outputText, 'utf8');
  const {
    RedisHighRiskApprovalStore,
    HIGH_RISK_APPROVAL_ISSUE_LUA,
    HIGH_RISK_APPROVAL_CONSUME_LUA,
    hashHighRiskArguments,
  } = await import(pathToFileURL(modulePath).href);

  const authority = { ownerSessionVerified: true, permissions: ['APPROVE_HIGH_RISK_ACTIONS'], actorId: 'owner-verified-01' };
  const args = { destination: 'approved-channel', content: 'Reviewed announcement', options: { visibility: 'public', pinned: false } };
  let tokenCounter = 0;
  const records = new Map();
  const calls = [];
  const fakeRedis = {
    async eval(script, numberOfKeys, ...argsIn) {
      calls.push({ script, numberOfKeys, argsIn });
      const key = String(argsIn[0]);
      if (script === HIGH_RISK_APPROVAL_ISSUE_LUA) {
        if (records.has(key)) return 0;
        records.set(key, JSON.parse(String(argsIn[1])));
        return 1;
      }
      if (script === HIGH_RISK_APPROVAL_CONSUME_LUA) {
        const record = records.get(key);
        if (!record) return 0;
        if (record.actorId !== String(argsIn[1]) || record.toolName !== String(argsIn[2]) || record.argumentHash !== String(argsIn[3])) return -1;
        records.delete(key);
        return 1;
      }
      throw new Error('unknown approval script');
    },
  };
  const options = { redis: fakeRedis, namespace: 'fv:approval:test', tokenFactory: () => 'A'.repeat(42) + String(++tokenCounter) };
  const replicaA = new RedisHighRiskApprovalStore(options);
  const replicaB = new RedisHighRiskApprovalStore(options);

  await assert.rejects(() => replicaA.issueApproval({ ownerSessionVerified: false, permissions: [], actorId: 'owner-verified-01' }, 'publish.post', args), /VERIFIED_OWNER_SESSION_REQUIRED/);
  await assert.rejects(() => replicaA.issueApproval({ ownerSessionVerified: true, permissions: [], actorId: 'owner-verified-01' }, 'publish.post', args), /PERMISSION_REQUIRED/);
  assert.equal(hashHighRiskArguments({ a: 1, b: { y: 2, x: 3 } }), hashHighRiskArguments({ b: { x: 3, y: 2 }, a: 1 }), 'argument hash must be independent of object insertion order');
  assert.throws(() => hashHighRiskArguments({ value: Number.NaN }), /NUMBER_INVALID/);
  const cyclic = {}; cyclic.self = cyclic;
  assert.throws(() => hashHighRiskArguments(cyclic), /CYCLE_DETECTED/);

  const issued = await replicaA.issueApproval(authority, 'publish.post', args);
  assert.equal(issued.expiresInSeconds, 120);
  assert.match(issued.token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(records.size, 1);
  const storedValue = [...records.values()][0];
  assert.equal(storedValue.actorId, authority.actorId);
  assert.equal(storedValue.toolName, 'publish.post');
  assert.equal(storedValue.argumentHash, hashHighRiskArguments(args));
  assert.equal(JSON.stringify(storedValue).includes(issued.token), false, 'raw bearer token must not be stored in Redis');
  assert.match(calls[0].script, /'PX', ARGV\[2\]/, 'issue script must apply an expiry');
  assert.match(calls[1]?.script || HIGH_RISK_APPROVAL_CONSUME_LUA, /redis\.call\('DEL', KEYS\[1\]\)/, 'consume script must atomically delete on success');

  assert.equal(await replicaB.consumeApproval(issued.token, 'other-owner', 'publish.post', args), 'BINDING_MISMATCH');
  assert.equal(await replicaB.consumeApproval(issued.token, authority.actorId, 'publish.post', { ...args, content: 'Changed content' }), 'BINDING_MISMATCH');
  assert.equal(await replicaB.consumeApproval(issued.token, authority.actorId, 'delete.account', args), 'BINDING_MISMATCH');
  assert.equal(records.size, 1, 'binding mismatch must not consume the approval');
  assert.equal(await replicaB.consumeApproval(issued.token, authority.actorId, 'publish.post', { options: { pinned: false, visibility: 'public' }, content: 'Reviewed announcement', destination: 'approved-channel' }), 'CONSUMED', 'different replicas and equivalent canonical argument ordering must consume the same approval');
  assert.equal(records.size, 0);
  assert.equal(await replicaA.consumeApproval(issued.token, authority.actorId, 'publish.post', args), 'NOT_FOUND_OR_EXPIRED', 'approval replay must fail');

  const broken = new RedisHighRiskApprovalStore({ ...options, redis: { eval: async () => { throw new Error('redis unavailable'); } } });
  await assert.rejects(() => broken.issueApproval(authority, 'publish.post', args), /redis unavailable/, 'store outages must propagate and must not fall back to local memory');
  console.log('SHARED_HIGH_RISK_APPROVAL_STORE_CHECK=PASS (18 contract assertions)');

  if (process.env.FV_TEST_REDIS === '1') {
    const port = process.env.REDIS_PORT || '6389';
    const redisCli = (...command) => execFileSync('redis-cli', ['-h', '127.0.0.1', '-p', port, '--raw', ...command.map(String)], { encoding: 'utf8' }).trim();
    assert.equal(redisCli('PING'), 'PONG');
    const namespace = 'fv:approval:real:' + process.pid;
    const realRedis = {
      async eval(script, numberOfKeys, ...argsIn) {
        return Number(execFileSync('redis-cli', ['-h', '127.0.0.1', '-p', port, '--raw', 'EVAL', script, String(numberOfKeys), ...argsIn.map(String)], { encoding: 'utf8' }).trim());
      },
    };
    const sharedOptions = { redis: realRedis, namespace };
    const serverOne = new RedisHighRiskApprovalStore(sharedOptions);
    const serverTwo = new RedisHighRiskApprovalStore(sharedOptions);
    const realArgs = { operation: 'publish', target: 'verified-test-target', payload: { text: 'human-approved' } };
    const realAuthority = { ownerSessionVerified: true, permissions: ['APPROVE_HIGH_RISK_ACTIONS'], actorId: 'real-owner-42' };
    const realApproval = await serverOne.issueApproval(realAuthority, 'content.publish', realArgs);
    assert.equal(await serverTwo.consumeApproval(realApproval.token, 'other-owner', 'content.publish', realArgs), 'BINDING_MISMATCH');
    assert.equal(await serverTwo.consumeApproval(realApproval.token, realAuthority.actorId, 'content.publish', { ...realArgs, payload: { text: 'tampered' } }), 'BINDING_MISMATCH');
    assert.equal(await serverTwo.consumeApproval(realApproval.token, realAuthority.actorId, 'content.publish', realArgs), 'CONSUMED', 'approval should be consumed across Redis-backed store instances');
    assert.equal(await serverOne.consumeApproval(realApproval.token, realAuthority.actorId, 'content.publish', realArgs), 'NOT_FOUND_OR_EXPIRED', 'single-use token must reject replay across instances');
    const expiring = await serverOne.issueApproval(realAuthority, 'content.publish', realArgs);
    const digest = (await import('node:crypto')).createHash('sha256').update(expiring.token).digest('hex');
    const redisKey = namespace + ':' + digest;
    const ttl = Number(redisCli('PTTL', redisKey));
    assert.ok(ttl > 0 && ttl <= 120_000, 'Redis must enforce a maximum 120-second approval lifetime');
    redisCli('DEL', redisKey);
    assert.equal(await serverTwo.consumeApproval(expiring.token, realAuthority.actorId, 'content.publish', realArgs), 'NOT_FOUND_OR_EXPIRED');
    console.log('REAL_REDIS_HIGH_RISK_APPROVAL_INTEGRATION=PASS (7 assertions across two store instances)');
  } else {
    console.log('REAL_REDIS_HIGH_RISK_APPROVAL_INTEGRATION=SKIPPED (set FV_TEST_REDIS=1 with an isolated Redis server)');
  }
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}

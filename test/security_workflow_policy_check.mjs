import assert from 'node:assert/strict';
import fs from 'node:fs';

const workflow = fs.readFileSync('.github/workflows/security-primitives.yml', 'utf8');
assert.match(workflow, /permissions:\s+contents:\s+read/, 'workflow must use read-only repository permissions');
assert.match(workflow, /persist-credentials:\s+false/, 'checkout must not persist credentials');
assert.match(workflow, /actions\/checkout@[0-9a-f]{40}/, 'checkout action must be pinned to an immutable SHA');
assert.match(workflow, /actions\/setup-node@[0-9a-f]{40}/, 'setup-node action must be pinned to an immutable SHA');
assert.match(workflow, /typescript@5\.9\.3/, 'test transpiler must be pinned to an exact version');
assert.match(workflow, /node test\/adaptive_security_layer_check\.mjs/, 'adaptive test must run in CI');
assert.match(workflow, /node test\/csrf_origin_guard_check\.mjs/, 'CSRF test must run in CI');
assert.match(workflow, /node test\/shared_adaptive_security_store_check\.mjs/, 'shared-store test must run in CI');
assert.match(workflow, /node test\/shared_high_risk_approval_store_check\.mjs/, 'shared high-risk approval test must run in CI');
assert.match(workflow, /redis-server --port 6389/, 'CI must start an isolated Redis server');
assert.match(workflow, /FV_TEST_REDIS: '1'/, 'CI must enable real Redis integration');
assert.doesNotMatch(workflow, /pull_request_target/, 'untrusted pull-request code must not run in a privileged workflow');
assert.doesNotMatch(workflow, /secrets\./, 'test workflow must not consume repository secrets');
console.log('SECURITY_WORKFLOW_POLICY_CHECK=PASS (14 assertions)');

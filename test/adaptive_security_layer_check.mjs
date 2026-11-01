import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'fv-adaptive-security-'));
try {
  const source = fs.readFileSync(path.join(root, 'src/server/adaptiveSecurityService.ts'), 'utf8');
  const compiled = ts.transpileModule(source, {
    fileName: 'adaptiveSecurityService.ts',
    reportDiagnostics: true,
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, verbatimModuleSyntax: false },
  });
  const errors = (compiled.diagnostics || []).filter((d) => d.category === ts.DiagnosticCategory.Error);
  assert.equal(errors.length, 0, 'adaptive security service must transpile');
  const file = path.join(temp, 'adaptiveSecurityService.mjs');
  fs.writeFileSync(file, compiled.outputText, 'utf8');
  const { AdaptiveSecurityService, SECURITY_LAYER_POLICY } = await import(pathToFileURL(file).href);
  const shield = new AdaptiveSecurityService();

  assert.equal(shield.getLayerForAddress('198.51.100.10'), 'BASELINE');
  shield.recordOwnerAuthentication('198.51.100.10', false);
  shield.recordOwnerAuthentication('198.51.100.10', false);
  assert.equal(shield.getLayerForAddress('198.51.100.10'), 'BASELINE');
  shield.recordOwnerAuthentication('198.51.100.10', false);
  assert.equal(shield.getLayerForAddress('198.51.100.10'), 'GUARDED');
  shield.recordOwnerAuthentication('198.51.100.10', false);
  shield.recordOwnerAuthentication('198.51.100.10', false);
  shield.recordOwnerAuthentication('198.51.100.10', false);
  assert.equal(shield.getLayerForAddress('198.51.100.10'), 'CONTAINMENT');
  shield.recordOwnerAuthentication('198.51.100.10', false);
  shield.recordOwnerAuthentication('198.51.100.10', false);
  shield.recordOwnerAuthentication('198.51.100.10', false);
  shield.recordOwnerAuthentication('198.51.100.10', false);
  assert.equal(shield.getLayerForAddress('198.51.100.10'), 'QUARANTINE');

  assert.equal(shield.getLayerForAddress('203.0.113.40'), 'BASELINE', 'another client must remain unaffected');
  assert.equal(SECURITY_LAYER_POLICY.QUARANTINE.maxApiRequestsPerMinute, 0);
  assert.equal(SECURITY_LAYER_POLICY.BASELINE.maxApiRequestsPerMinute, 180);

  const posture = shield.getPosture();
  assert.equal(posture.trackedClients, 2);
  assert.equal(posture.activeQuarantines, 1);
  assert.ok(posture.recentEvents.length >= 10);
  assert.ok(posture.recentEvents.every((event) => !event.route.includes('?')));
  assert.ok(posture.recentEvents.every((event) => !event.client.includes('198.51.100.10')));

  shield.recordOwnerAuthentication('198.51.100.10', true);
  assert.equal(shield.getLayerForAddress('198.51.100.10'), 'QUARANTINE');

  const probeShield = new AdaptiveSecurityService();
  probeShield.recordProbe('192.0.2.44', '/.env');
  probeShield.recordProbe('192.0.2.44', '/.git/config');
  assert.equal(probeShield.getLayerForAddress('192.0.2.44'), 'GUARDED');

  const middlewareShield = new AdaptiveSecurityService();
  const response = {
    headers: {}, statusCode: 200, body: undefined,
    setHeader(name, value) { this.headers[name] = value; return this; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    once() { return this; },
  };
  let nextCalled = false;
  middlewareShield.middleware()({ ip: '198.51.100.77', socket: { remoteAddress: '198.51.100.77' }, path: '/.env', method: 'GET', secure: false }, response, () => { nextCalled = true; });
  assert.equal(response.statusCode, 404);
  assert.equal(nextCalled, false);
  assert.equal(response.headers['X-Content-Type-Options'], 'nosniff');
  assert.equal(response.headers['X-Frame-Options'], 'DENY');
  assert.equal(response.headers['Referrer-Policy'], 'no-referrer');

  console.log('ADAPTIVE_SECURITY_LAYER_CHECK=PASS');
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}

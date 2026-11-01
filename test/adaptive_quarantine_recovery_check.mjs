import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'fv-quarantine-recovery-'));
const realNow = Date.now;
let fakeNow = 1_800_000_000_000;
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

  Date.now = () => fakeNow;
  const shield = new AdaptiveSecurityService();
  const sourceIp = '198.51.100.200';
  for (let i = 0; i < 10; i++) shield.recordOwnerAuthentication(sourceIp, false);
  assert.equal(shield.getLayerForAddress(sourceIp), 'QUARANTINE', 'threshold should enter quarantine');

  const state = [...shield.clients.values()][0];
  const quarantineUntil = state.quarantineUntil;
  fakeNow = quarantineUntil + 1;
  assert.equal(shield.getLayerForAddress(sourceIp), 'RECOVERY', 'expired quarantine must enter recovery probation');
  assert.equal(state.quarantineUntil, 0, 'expired quarantine timestamp must be cleared');
  assert.equal(state.authFailures.length, 0, 'stale auth failures must be cleared at recovery');
  assert.equal(state.probes.length, 0, 'stale probe signals must be cleared at recovery');
  assert.equal(state.rateLimitEvents.length, 0, 'stale rate-limit signals must be cleared at recovery');
  assert.equal(state.recoveryUntil, fakeNow + 5 * 60_000, 'recovery window must be bounded to five minutes');

  assert.equal(SECURITY_LAYER_POLICY.RECOVERY.maxApiRequestsPerMinute, 60);
  assert.ok(SECURITY_LAYER_POLICY.RECOVERY.maxApiRequestsPerMinute < SECURITY_LAYER_POLICY.BASELINE.maxApiRequestsPerMinute);

  fakeNow += 4 * 60_000;
  assert.equal(shield.getLayerForAddress(sourceIp), 'RECOVERY', 'source remains in probation during recovery window');
  fakeNow += 60_001;
  assert.equal(shield.getLayerForAddress(sourceIp), 'BASELINE', 'source returns to baseline after clean recovery');

  // Fresh signals during probation still escalate; recovery is not a bypass.
  const second = new AdaptiveSecurityService();
  fakeNow += 10;
  for (let i = 0; i < 10; i++) second.recordProbe('203.0.113.200', '/.env');
  assert.equal(second.getLayerForAddress('203.0.113.200'), 'QUARANTINE');

  console.log('ADAPTIVE_QUARANTINE_RECOVERY_CHECK=PASS (12 assertions)');
} finally {
  Date.now = realNow;
  fs.rmSync(temp, { recursive: true, force: true });
}

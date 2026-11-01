import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import ts from 'typescript';
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const source = fs.readFileSync(path.join(root, 'src/server/csrfOriginGuard.ts'), 'utf8');
const compiled = ts.transpileModule(source, { fileName: 'csrfOriginGuard.ts', reportDiagnostics: true, compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, verbatimModuleSyntax: false } });
const errors = (compiled.diagnostics || []).filter((d) => d.category === ts.DiagnosticCategory.Error);
assert.equal(errors.length, 0);
const temp = path.join(os.tmpdir(), `fv-csrf-guard-${process.pid}.mjs`);
fs.writeFileSync(temp, compiled.outputText, 'utf8');
try {
  const { evaluateOwnerCookieMutationOrigin: check } = await import(pathToFileURL(temp).href);
  const base = { cookieHeader: 'fv_owner_token=opaque', configuredAppUrl: 'https://futureverse.example/app', nodeEnv: 'production' };
  assert.equal(check({ ...base, method: 'GET', originHeader: 'https://evil.example' }).allowed, true);
  assert.equal(check({ ...base, method: 'POST', originHeader: 'https://futureverse.example' }).allowed, true);
  assert.equal(check({ ...base, method: 'POST', originHeader: 'https://evil.example' }).reason, 'ORIGIN_MISMATCH');
  assert.equal(check({ ...base, method: 'POST', originHeader: 'https://futureverse.example', fetchSiteHeader: 'cross-site' }).reason, 'CROSS_SITE_FETCH');
  assert.equal(check({ ...base, method: 'POST' }).reason, 'MISSING_ORIGIN');
  assert.equal(check({ ...base, method: 'POST', cookieHeader: '' }).reason, 'NO_OWNER_COOKIE');
  assert.equal(check({ method: 'POST', cookieHeader: 'fv_owner_token=opaque', originHeader: 'https://futureverse.example', nodeEnv: 'production' }).reason, 'APP_ORIGIN_NOT_CONFIGURED');
  assert.equal(check({ ...base, method: 'POST', originHeader: 'null' }).reason, 'MISSING_ORIGIN');
  console.log('CSRF_ORIGIN_GUARD_CHECK=PASS');
} finally { fs.rmSync(temp, { force: true }); }

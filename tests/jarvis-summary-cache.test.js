'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { isTrustedJarvisSummaryRequest, createJarvisSummaryCache } = require('../jarvis-summary-cache');

function response() {
  return {
    statusCode: 200, headers: {}, body: null,
    set(name, value) { this.headers[name] = value; return this; },
    json(body) { this.body = body; return this; }
  };
}

test('only the correctly authenticated JARVIS summary path bypasses global API rate limiting', () => {
  const env = { JARVIS_INTEGRATION_SECRET: 'a-secret-long-enough-for-test' };
  assert.equal(isTrustedJarvisSummaryRequest({ path: '/api/integrations/jarvis/business-summary', headers: { 'x-jarvis-integration-token': env.JARVIS_INTEGRATION_SECRET } }, env), true);
  // Express trims the mounted '/api' prefix in req.path; originalUrl must still match.
  assert.equal(isTrustedJarvisSummaryRequest({ path: '/integrations/jarvis/business-summary', originalUrl: '/api/integrations/jarvis/business-summary?source=test', headers: { 'x-jarvis-integration-token': env.JARVIS_INTEGRATION_SECRET } }, env), true);
  assert.equal(isTrustedJarvisSummaryRequest({ path: '/api/integrations/jarvis/business-summary', headers: {} }, env), false);
  assert.equal(isTrustedJarvisSummaryRequest({ path: '/api/owner/login', headers: { 'x-jarvis-integration-token': env.JARVIS_INTEGRATION_SECRET } }, env), false);
});

test('successful JARVIS summary is cached and repeated reads do not call the database handler', () => {
  let now = 1000;
  const middleware = createJarvisSummaryCache(30_000, () => now);
  let executions = 0;
  const first = response();
  middleware({}, first, () => { executions++; first.json({ status: 'ok', summary: { shops_total: 4 } }); });
  const second = response();
  middleware({}, second, () => { executions++; });
  assert.equal(executions, 1);
  assert.deepEqual(second.body, { status: 'ok', summary: { shops_total: 4 } });
  assert.equal(second.headers['Cache-Control'], 'private, max-age=30');
});

test('failed or non-success summaries are never cached', () => {
  const middleware = createJarvisSummaryCache(30_000, () => 1000);
  const failed = response();
  failed.statusCode = 503;
  middleware({}, failed, () => failed.json({ status: 'unavailable' }));
  let executions = 0;
  const next = response();
  middleware({}, next, () => { executions++; next.json({ status: 'ok', summary: {} }); });
  assert.equal(executions, 1);
});

test('expired cache triggers a fresh summary build', () => {
  let now = 1000;
  const middleware = createJarvisSummaryCache(30_000, () => now);
  const first = response();
  middleware({}, first, () => first.json({ status: 'ok', version: 1 }));
  now += 30_001;
  let executions = 0;
  const next = response();
  middleware({}, next, () => { executions++; next.json({ status: 'ok', version: 2 }); });
  assert.equal(executions, 1);
  assert.equal(next.body.version, 2);
});

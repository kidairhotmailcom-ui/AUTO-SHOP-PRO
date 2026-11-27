'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const {
  isTrustedJarvisSummaryRequest,
  createJarvisSummaryCache,
  createJarvisSummaryDiagnostics
} = require('../jarvis-summary-cache');

function response() {
  const events = new EventEmitter();
  return {
    statusCode: 200,
    headers: {},
    body: null,
    set(name, value) { this.headers[name.toLowerCase()] = value; return this; },
    getHeader(name) { return this.headers[name.toLowerCase()]; },
    status(code) { this.statusCode = code; return this; },
    on: events.on.bind(events),
    emit: events.emit.bind(events),
    json(body) { this.body = body; this.emit('finish'); return this; }
  };
}

test('1. only the correctly authenticated JARVIS summary path bypasses global API rate limiting', () => {
  const env = { JARVIS_INTEGRATION_SECRET: 'a-secret-long-enough-for-test' };
  assert.equal(isTrustedJarvisSummaryRequest({ path: '/api/integrations/jarvis/business-summary', headers: { 'x-jarvis-integration-token': env.JARVIS_INTEGRATION_SECRET } }, env), true);
  assert.equal(isTrustedJarvisSummaryRequest({ path: '/api/owner/login', headers: { 'x-jarvis-integration-token': env.JARVIS_INTEGRATION_SECRET } }, env), false);
});

test('2. Express mounted path and query string are normalized before the bypass check', () => {
  const env = { JARVIS_INTEGRATION_SECRET: 'a-secret-long-enough-for-test' };
  assert.equal(isTrustedJarvisSummaryRequest({
    path: '/integrations/jarvis/business-summary',
    originalUrl: '/api/integrations/jarvis/business-summary?source=test',
    headers: { 'x-jarvis-integration-token': env.JARVIS_INTEGRATION_SECRET }
  }, env), true);
});

test('3. missing, wrong, or unconfigured integration tokens never bypass the global limiter', () => {
  const env = { JARVIS_INTEGRATION_SECRET: 'a-secret-long-enough-for-test' };
  const path = '/api/integrations/jarvis/business-summary';
  assert.equal(isTrustedJarvisSummaryRequest({ path, headers: {} }, env), false);
  assert.equal(isTrustedJarvisSummaryRequest({ path, headers: { 'x-jarvis-integration-token': 'wrong-secret' } }, env), false);
  assert.equal(isTrustedJarvisSummaryRequest({ path, headers: { 'x-jarvis-integration-token': env.JARVIS_INTEGRATION_SECRET } }, {}), false);
});

test('4. successful JARVIS summary is cached and repeated reads do not call the database handler', () => {
  let now = 1000;
  const middleware = createJarvisSummaryCache(30_000, () => now);
  let executions = 0;
  const first = response();
  middleware({}, first, () => { executions++; first.json({ status: 'ok', summary: { shops_total: 4 } }); });
  const second = response();
  middleware({}, second, () => { executions++; });
  assert.equal(executions, 1);
  assert.deepEqual(second.body, { status: 'ok', summary: { shops_total: 4 } });
  assert.equal(second.headers['cache-control'], 'private, max-age=30');
});

test('5. failed or non-success summaries are never cached', () => {
  const middleware = createJarvisSummaryCache(30_000, () => 1000);
  const failed = response();
  failed.status(503);
  middleware({}, failed, () => failed.json({ status: 'unavailable' }));
  let executions = 0;
  const next = response();
  middleware({}, next, () => { executions++; next.json({ status: 'ok', summary: {} }); });
  assert.equal(executions, 1);
});

test('6. expired cache triggers a fresh summary build', () => {
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

test('7. concurrent authenticated misses share one summary build', () => {
  const middleware = createJarvisSummaryCache(30_000, () => 1000);
  let executions = 0;
  let finishFirst;
  const first = response();
  middleware({}, first, () => { executions++; finishFirst = () => first.json({ status: 'ok', summary: { shops_total: 7 } }); });
  const second = response();
  middleware({}, second, () => { executions++; });
  const third = response();
  middleware({}, third, () => { executions++; });
  assert.equal(executions, 1);
  finishFirst();
  assert.deepEqual(second.body, { status: 'ok', summary: { shops_total: 7 } });
  assert.deepEqual(third.body, { status: 'ok', summary: { shops_total: 7 } });
});

test('8. excessive in-flight waiters fail fast without growing memory without bound', () => {
  const middleware = createJarvisSummaryCache(30_000, () => 1000);
  const first = response();
  middleware({}, first, () => {});
  let busy = null;
  for (let i = 0; i < 51; i++) {
    const waiter = response();
    middleware({}, waiter, () => {});
    if (i === 50) busy = waiter;
  }
  assert.equal(busy.statusCode, 503);
  assert.equal(busy.headers['retry-after'], '1');
  assert.equal(busy.body.error, 'JARVIS_SUMMARY_IN_PROGRESS');
});

test('9. diagnostics generate a request id and never log the integration secret', () => {
  const logs = [];
  const middleware = createJarvisSummaryDiagnostics({
    env: { JARVIS_INTEGRATION_SECRET: 'top-secret-never-log-this-value' },
    logger: line => logs.push(line),
    now: () => 1000,
    idFactory: () => 'generated-id-123'
  });
  const req = { method: 'GET', headers: { 'x-jarvis-integration-token': 'top-secret-never-log-this-value' } };
  const res = response();
  let continued = false;
  middleware(req, res, () => { continued = true; });
  assert.equal(continued, true);
  assert.equal(req.jarvisRequestId, 'generated-id-123');
  assert.equal(res.headers['x-request-id'], 'generated-id-123');
  res.status(429).set('Retry-After', '60').set('X-RateLimit-Policy', 'jarvis-summary');
  res.emit('finish');
  assert.equal(logs.length, 2);
  assert.equal(logs.some(line => line.includes('top-secret-never-log-this-value')), false);
  assert.equal(JSON.parse(logs[1].replace('[JARVIS SUMMARY] ', '')).status_code, 429);
  assert.equal(JSON.parse(logs[1].replace('[JARVIS SUMMARY] ', '')).rate_limit_policy, 'jarvis-summary');
});

test('10. diagnostics preserve a safe upstream request id for cross-service correlation', () => {
  const logs = [];
  const middleware = createJarvisSummaryDiagnostics({
    env: { JARVIS_INTEGRATION_SECRET: 'a-secret-long-enough-for-test' },
    logger: line => logs.push(line),
    now: () => 2000,
    idFactory: () => 'unused-generated-id'
  });
  const req = { method: 'GET', headers: { 'x-request-id': 'jarvis-req-456' } };
  const res = response();
  middleware(req, res, () => {});
  assert.equal(req.jarvisRequestId, 'jarvis-req-456');
  assert.equal(res.headers['x-request-id'], 'jarvis-req-456');
});

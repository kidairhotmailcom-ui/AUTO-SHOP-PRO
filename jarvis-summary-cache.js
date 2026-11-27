'use strict';

const crypto = require('node:crypto');

const SUMMARY_PATH = '/api/integrations/jarvis/business-summary';
const MAX_IN_FLIGHT_WAITERS = 50;

function isTrustedJarvisSummaryRequest(req, env = process.env) {
  const requestPath = String(req.originalUrl || req.path || '').split('?')[0];
  if (requestPath !== SUMMARY_PATH && req.path !== SUMMARY_PATH) return false;
  const expected = String(env.JARVIS_INTEGRATION_SECRET || '').trim();
  const provided = String(
    typeof req.get === 'function'
      ? req.get('x-jarvis-integration-token') || ''
      : req.headers?.['x-jarvis-integration-token'] || ''
  ).trim();
  if (!expected || !provided) return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(provided);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function createJarvisSummaryDiagnostics(options = {}) {
  const env = options.env || process.env;
  const logger = options.logger || (line => console.log(line));
  const now = options.now || Date.now;
  const idFactory = options.idFactory || (() => crypto.randomUUID());

  return function jarvisSummaryDiagnostics(req, res, next) {
    const supplied = String(
      typeof req.get === 'function'
        ? req.get('x-request-id') || ''
        : req.headers?.['x-request-id'] || ''
    ).trim();
    const requestId = /^[A-Za-z0-9._:-]{1,100}$/.test(supplied)
      ? supplied
      : idFactory();

    req.jarvisRequestId = requestId;
    res.set('X-Request-ID', requestId);

    const startedAt = now();
    const authHeaderPresent = Boolean(
      typeof req.get === 'function'
        ? req.get('x-jarvis-integration-token')
        : req.headers?.['x-jarvis-integration-token']
    );

    logger('[JARVIS SUMMARY] ' + JSON.stringify({
      event: 'request_received',
      request_id: requestId,
      method: req.method || 'GET',
      path: SUMMARY_PATH,
      auth_header_present: authHeaderPresent,
      integration_secret_configured:
        String(env.JARVIS_INTEGRATION_SECRET || '').trim().length >= 20
    }));

    res.on('finish', () => {
      const retryAfter = typeof res.getHeader === 'function'
        ? res.getHeader('Retry-After') || null
        : null;
      const policy = typeof res.getHeader === 'function'
        ? res.getHeader('X-RateLimit-Policy') || null
        : null;
      logger('[JARVIS SUMMARY] ' + JSON.stringify({
        event: 'response_finished',
        request_id: requestId,
        status_code: res.statusCode,
        retry_after: retryAfter,
        rate_limit_policy: policy,
        duration_ms: Math.max(0, now() - startedAt)
      }));
    });

    next();
  };
}

function createJarvisSummaryCache(ttlMs = 30_000, now = Date.now) {
  let cached = null;
  let inFlight = null;

  return function jarvisSummaryCache(req, res, next) {
    if (cached && now() - cached.at < ttlMs) {
      res.set('Cache-Control', 'private, max-age=30');
      return res.json(cached.body);
    }

    if (inFlight) {
      if (inFlight.waiters.length >= MAX_IN_FLIGHT_WAITERS) {
        res.set('Retry-After', '1');
        return res.status(503).json({
          status: 'busy',
          error: 'JARVIS_SUMMARY_IN_PROGRESS',
          retry_after_seconds: 1
        });
      }
      inFlight.waiters.push(res);
      return;
    }

    const flight = { waiters: [] };
    inFlight = flight;
    const sendJson = res.json.bind(res);

    res.json = body => {
      const statusCode = res.statusCode || 200;
      if (statusCode === 200 && body && body.status === 'ok') {
        cached = { at: now(), body };
        res.set('Cache-Control', 'private, max-age=30');
      }

      const headers = {};
      for (const name of ['Cache-Control', 'Retry-After']) {
        const value = typeof res.getHeader === 'function' ? res.getHeader(name) : null;
        if (value != null) headers[name] = value;
      }

      if (inFlight === flight) inFlight = null;
      const waiters = flight.waiters.splice(0);
      const result = sendJson(body);

      for (const waiter of waiters) {
        waiter.status(statusCode);
        for (const [name, value] of Object.entries(headers)) waiter.set(name, value);
        waiter.json(body);
      }
      return result;
    };

    return next();
  };
}

module.exports = {
  isTrustedJarvisSummaryRequest,
  createJarvisSummaryCache,
  createJarvisSummaryDiagnostics
};

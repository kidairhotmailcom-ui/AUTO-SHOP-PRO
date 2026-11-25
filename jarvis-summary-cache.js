'use strict';

const SUMMARY_PATH = '/api/integrations/jarvis/business-summary';

function isTrustedJarvisSummaryRequest(req, env = process.env) {
  if (req.path !== SUMMARY_PATH) return false;
  const expected = String(env.JARVIS_INTEGRATION_SECRET || '').trim();
  const provided = String(
    typeof req.get === 'function'
      ? req.get('x-jarvis-integration-token') || ''
      : req.headers?.['x-jarvis-integration-token'] || ''
  ).trim();
  if (!expected || !provided) return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(provided);
  return a.length === b.length && require('node:crypto').timingSafeEqual(a, b);
}

function createJarvisSummaryCache(ttlMs = 30_000, now = Date.now) {
  let cached = null;
  return function jarvisSummaryCache(req, res, next) {
    if (cached && now() - cached.at < ttlMs) {
      res.set('Cache-Control', 'private, max-age=30');
      return res.json(cached.body);
    }
    const sendJson = res.json.bind(res);
    res.json = body => {
      if (res.statusCode === 200 && body && body.status === 'ok') {
        cached = { at: now(), body };
        res.set('Cache-Control', 'private, max-age=30');
      }
      return sendJson(body);
    };
    return next();
  };
}

module.exports = { isTrustedJarvisSummaryRequest, createJarvisSummaryCache };

// utils/appBase.js
//
// Canonical frontend base URL for links sent in Discord broadcasts and emails.
// Production never falls back to request Origin/localhost.

function getAppBase(req) {
  const isProd = (process.env.NODE_ENV || '').toLowerCase() === 'production';
  const defaultBase = isProd ? 'https://portal.attlarp.gr' : 'http://localhost:3002';
  const raw = isProd
    ? (process.env.APP_BASE_URL || defaultBase)
    : (process.env.APP_BASE_URL || req?.headers?.origin || defaultBase);
  return String(raw).replace(/\/$/, '');
}

module.exports = { getAppBase };

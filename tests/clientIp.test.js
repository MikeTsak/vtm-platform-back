// tests/clientIp.test.js — the rate limiters key anonymous callers by IP, so the
// IP must not be something the client can pick per request.
const { clientIp } = require('../services/guards');

const req = (headers, ip = '127.0.0.1') => ({ headers, ip });

describe('clientIp', () => {
  it('takes the proxy-appended (rightmost) X-Forwarded-For entry, not the client-supplied first one', () => {
    expect(clientIp(req({ 'x-forwarded-for': '6.6.6.6, 203.0.113.9' }))).toBe('203.0.113.9');
  });

  it('ignores CF-Connecting-IP (there is no Cloudflare in front of the API)', () => {
    expect(clientIp(req({ 'cf-connecting-ip': '6.6.6.6', 'x-forwarded-for': '203.0.113.9' }))).toBe('203.0.113.9');
  });

  it('falls back to X-Real-IP, then the socket address', () => {
    expect(clientIp(req({ 'x-real-ip': '203.0.113.9' }))).toBe('203.0.113.9');
    expect(clientIp(req({}))).toBe('127.0.0.1');
  });
});

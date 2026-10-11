// tests/rateLimit.test.js — the named limiter tiers in services/guards.js.
const { makeLimiter } = require('../services/guards');

const fakeReply = () => {
  const r = { code: 200, headers: {} };
  r.status = (c) => { r.code = c; return r; };
  r.header = (k, v) => { r.headers[k] = v; return r; };
  r.send = (b) => { r.body = b; return r; };
  return r;
};

describe('makeLimiter', () => {
  it('lets max requests through, then answers 429 with Retry-After', async () => {
    const limit = makeLimiter('t', 2, 60_000);
    const req = { headers: {}, ip: '1.2.3.4' };
    for (let i = 0; i < 2; i++) { const r = fakeReply(); await limit(req, r); expect(r.code).toBe(200); }
    const blocked = fakeReply();
    await limit(req, blocked);
    expect(blocked.code).toBe(429);
    expect(Number(blocked.headers['Retry-After'])).toBeGreaterThan(0);
  });

  it('counts signed-in callers by user id, not by shared IP', async () => {
    const limit = makeLimiter('t', 1, 60_000);
    const a = { headers: {}, ip: '9.9.9.9', user: { id: 1 } };
    const b = { headers: {}, ip: '9.9.9.9', user: { id: 2 } };
    await limit(a, fakeReply());
    const rb = fakeReply(); await limit(b, rb);
    expect(rb.code).toBe(200);
    const ra = fakeReply(); await limit(a, ra);
    expect(ra.code).toBe(429);
  });
});

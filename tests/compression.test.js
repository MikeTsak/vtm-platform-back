// tests/compression.test.js — regression guard for the response-compression
// onSend hook (utils/compression.js).
//
// The whole reason this hook is hand-rolled instead of `@fastify/compress` in
// global mode is that ~490 handlers here end with a bare `reply.send(x)` /
// `reply.status(n).json(x)` rather than `return reply.send(x)`. An async
// compression hook turns those into empty 0-byte responses. These tests pin
// that exact interaction: a bare-send async handler must still produce a
// complete, decodable, compressed body.
const zlib = require('zlib');
const fastify = require('fastify');
const { compressionHook } = require('../utils/compression');

let app;

const BIG = {
  rows: Array.from({ length: 400 }, (_, i) => ({
    id: i,
    name: 'Kindred ' + i,
    clan: 'Tremere',
    note: 'lorem ipsum dolor sit amet '.repeat(4),
  })),
};

beforeAll(async () => {
  app = fastify({ logger: false });
  // the reply.json shim the real server adds in app.js
  app.decorateReply('json', function (payload) {
    return this.send(payload);
  });
  app.addHook('onSend', compressionHook);

  // bare send from an async handler — the dominant pattern in routes/*.js
  app.get('/list', async (req, reply) => {
    reply.header('Cache-Control', 'no-store').send({ ok: true, data: BIG });
  });
  // pre-stringified body with a hand-set Content-Length — the dashboard /
  // characters pattern
  app.get('/bootstrap', async (req, reply) => {
    const payload = JSON.stringify({ success: true, data: BIG });
    reply
      .header('Content-Type', 'application/json; charset=utf-8')
      .header('Content-Length', Buffer.byteLength(payload))
      .send(payload);
  });
  // error path through the .json shim
  app.get('/boom', async (req, reply) => {
    reply.status(500).json({ error: 'detail '.repeat(400) });
  });
  app.get('/tiny', async (req, reply) => {
    reply.send({ pong: 1 });
  });
  app.get('/binary', async (req, reply) => {
    reply.type('application/octet-stream').send(Buffer.alloc(8000, 7));
  });

  await app.ready();
});

afterAll(async () => {
  await app.close();
});

function decode(res) {
  const enc = res.headers['content-encoding'];
  if (enc === 'br') return zlib.brotliDecompressSync(res.rawPayload);
  if (enc === 'gzip') return zlib.gunzipSync(res.rawPayload);
  return res.rawPayload;
}

describe('response compression onSend hook', () => {
  it('brotli-compresses a bare-send async JSON response and keeps the body intact', async () => {
    const res = await app.inject({ method: 'GET', url: '/list', headers: { 'accept-encoding': 'br, gzip' } });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-encoding']).toBe('br');
    expect(res.headers['vary']).toMatch(/accept-encoding/i);
    // Content-Length, if present, must describe the bytes actually on the wire.
    if (res.headers['content-length'] != null) {
      expect(Number(res.headers['content-length'])).toBe(res.rawPayload.length);
    }
    expect(res.rawPayload.length).toBeLessThan(6000); // ~40KB uncompressed
    const body = JSON.parse(decode(res).toString());
    expect(body.data.rows).toHaveLength(400);
  });

  it('falls back to gzip when brotli is not offered', async () => {
    const res = await app.inject({ method: 'GET', url: '/list', headers: { 'accept-encoding': 'gzip, deflate' } });
    expect(res.headers['content-encoding']).toBe('gzip');
    expect(JSON.parse(decode(res).toString()).data.rows).toHaveLength(400);
  });

  it('does not compress when the client only accepts identity', async () => {
    const res = await app.inject({ method: 'GET', url: '/list', headers: { 'accept-encoding': 'identity' } });
    expect(res.headers['content-encoding']).toBeUndefined();
    expect(JSON.parse(res.rawPayload.toString()).data.rows).toHaveLength(400);
  });

  it('fixes up a hand-set Content-Length when compressing a pre-stringified body', async () => {
    const res = await app.inject({ method: 'GET', url: '/bootstrap', headers: { 'accept-encoding': 'br' } });
    expect(res.headers['content-encoding']).toBe('br');
    expect(Number(res.headers['content-length'])).toBe(res.rawPayload.length);
    expect(JSON.parse(decode(res).toString()).data.rows).toHaveLength(400);
  });

  it('compresses error responses sent through the .json shim', async () => {
    const res = await app.inject({ method: 'GET', url: '/boom', headers: { 'accept-encoding': 'gzip' } });
    expect(res.statusCode).toBe(500);
    expect(res.headers['content-encoding']).toBe('gzip');
    expect(JSON.parse(decode(res).toString()).error.length).toBeGreaterThan(1000);
  });

  it('leaves small responses uncompressed', async () => {
    const res = await app.inject({ method: 'GET', url: '/tiny', headers: { 'accept-encoding': 'br, gzip' } });
    expect(res.headers['content-encoding']).toBeUndefined();
    expect(JSON.parse(res.rawPayload.toString())).toEqual({ pong: 1 });
  });

  it('leaves non-text (binary) responses uncompressed', async () => {
    const res = await app.inject({ method: 'GET', url: '/binary', headers: { 'accept-encoding': 'br, gzip' } });
    expect(res.headers['content-encoding']).toBeUndefined();
    expect(res.rawPayload.length).toBe(8000);
  });
});

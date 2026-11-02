// A new upload must reach browsers that cached the old avatar redirect.
import { describe, it, expect } from 'vitest';
import Fastify from 'fastify';
import avatars from '../routes/avatars';

async function app(row) {
  const f = Fastify();
  const pool = { query: async () => [[row]] };
  await f.register(avatars, { pool, log: { warn() {}, err() {} }, authRequired: async () => {}, requireAdmin: async () => {} });
  return f;
}

describe('avatar GET caching', () => {
  it('revalidates instead of serving a day-old redirect', async () => {
    const row = { avatar_url: 'https://img.example/a1.webp', avatar_url_thumb: null, avatar: null };
    const f = await app(row);

    const first = await f.inject('/api/users/1/avatar');
    expect(first.statusCode).toBe(302);
    expect(first.headers['cache-control']).toBe('no-cache');
    const etag = first.headers.etag;

    const same = await f.inject({ url: '/api/users/1/avatar', headers: { 'if-none-match': etag } });
    expect(same.statusCode).toBe(304);

    row.avatar_url = 'https://img.example/a2.webp'; // player uploaded a new portrait
    const changed = await f.inject({ url: '/api/users/1/avatar', headers: { 'if-none-match': etag } });
    expect(changed.statusCode).toBe(302);
    expect(changed.headers.location).toBe('https://img.example/a2.webp');
  });
});

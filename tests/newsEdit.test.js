// back/tests/newsEdit.test.js — editing a published article or decree within an
// hour of publishing: the author or an admin may, nobody else, and never after the
// hour. The feed tells each reader only their own deadline (author stays hidden).
const { setupTestDatabase, getTestPool, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser, extractSessionCookie } = require('./setup/helpers');

let pool, app, author, other, admin;

const req = (method, url, who, payload) => app.inject({ method, url, headers: { cookie: who.cookie }, payload });
const insertEntry = async (fields) => (await pool.query('INSERT INTO news_entries SET ?', [{
  type: 'news', title: 'Original', body: '<p>Body</p>', theme: 'ERT', is_private: 0, published_at: new Date(), ...fields,
}]))[0].insertId;

beforeAll(async () => {
  await setupTestDatabase();
  pool = getTestPool();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  author = await registerUser(app, { displayName: 'Author' });
  other = await registerUser(app, { displayName: 'Other' });
  admin = await registerUser(app, { displayName: 'Admin' });
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  admin.cookie = extractSessionCookie(await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } }));
});
afterAll(async () => { if (app) await app.close(); });

describe('editing a published entry', () => {
  it('lets the author edit within the hour, and marks it edited', async () => {
    const id = await insertEntry({ author_id: author.user.id });
    const res = await req('PUT', `/api/news/${id}`, author, { title: 'Fixed title', subtitle: 'New sub', body: '<p>Fixed <script>x</script></p>' });
    expect(res.statusCode).toBe(200);
    const [[row]] = await pool.query('SELECT title, subtitle, body, edited_at FROM news_entries WHERE id=?', [id]);
    expect(row.title).toBe('Fixed title');
    expect(row.subtitle).toBe('New sub');
    expect(row.body).not.toMatch(/script/);
    expect(row.edited_at).not.toBeNull();
  });

  it('refuses other players, and everyone after an hour', async () => {
    const id = await insertEntry({ author_id: author.user.id });
    expect((await req('PUT', `/api/news/${id}`, other, { title: 'x', body: 'y' })).statusCode).toBe(403);
    const old = await insertEntry({ author_id: author.user.id, published_at: new Date(Date.now() - 61 * 60 * 1000) });
    expect((await req('PUT', `/api/news/${old}`, author, { title: 'x', body: 'y' })).statusCode).toBe(403);
    expect((await req('PUT', `/api/news/${old}`, admin, { title: 'x', body: 'y' })).statusCode).toBe(403);
  });

  it('lets an admin edit a decree within the hour, and removes media on request', async () => {
    const id = await insertEntry({ type: 'announcement', author_id: author.user.id, media_url: '/api/media/1' });
    expect((await req('PUT', `/api/news/${id}`, admin, { title: 'Decree', body: 'By order', media_url: null })).statusCode).toBe(200);
    const [[row]] = await pool.query('SELECT media_url FROM news_entries WHERE id=?', [id]);
    expect(row.media_url).toBeNull();
  });

  it('tells only the author (and admins) their deadline in the feed', async () => {
    const id = await insertEntry({ author_id: author.user.id });
    const find = async (who) => JSON.parse((await req('GET', '/api/news', who)).body).items.find((i) => i.id === id);
    expect((await find(author)).editable_until).toBeTruthy();
    expect((await find(admin)).editable_until).toBeTruthy();
    const seen = await find(other);
    expect(seen.editable_until).toBeNull();
    expect(seen.author_id).toBeUndefined();
  });
});

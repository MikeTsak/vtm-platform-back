// back/tests/newsDrafts.test.js
// Tests for server-side news article drafts
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');
const { clearTokenVersionCache } = require('../utils/tokenVersion');

let pool, app, admin, writer, reader;
const json = (res) => JSON.parse(res.body);
const as = (who, method, url, payload) => app.inject({ method, url, headers: { cookie: who.cookie }, payload });

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();

  admin = await registerUser(app, { displayName: 'Admin User' });
  await pool.query("UPDATE users SET role = 'admin' WHERE id = ?", [admin.user.id]);
  clearTokenVersionCache(admin.user.id);

  writer = await registerUser(app, { displayName: 'Writer User' });
  reader = await registerUser(app, { displayName: 'Regular Reader' });

  // Grant writer permission for ERT outlet
  await pool.query('INSERT INTO user_news_permissions (user_id, theme) VALUES (?, ?)', [writer.user.id, 'ERT']);
});

afterAll(async () => {
  await pool.query('DELETE FROM news_article_drafts');
  await app.close();
  await teardownTestDatabase();
});

test('unauthorized users cannot access drafts endpoints', async () => {
  const getRes = await as(reader, 'GET', '/api/news/drafts');
  expect(getRes.statusCode).toBe(403);

  const postRes = await as(reader, 'POST', '/api/news/drafts', { title: 'Unauthorized' });
  expect(postRes.statusCode).toBe(403);
});

test('writer can create, view, update and delete their own draft', async () => {
  // Create draft
  const createRes = await as(writer, 'POST', '/api/news/drafts', {
    title: 'Secret Investigation',
    subtitle: 'Underworld movements',
    body: '<p>Report content</p><script>alert("hack")</script>',
    theme: 'ERT',
    journalist_name: 'Kostas P.',
    discord_prefix: '🔥 Hot news!',
    is_custom_prefix: 1,
    is_private: 0
  });
  expect(createRes.statusCode).toBe(201);
  const draft = json(createRes).draft;
  expect(draft).toBeDefined();
  expect(draft.id).toBeGreaterThan(0);
  expect(draft.title).toBe('Secret Investigation');
  // Body must be sanitized (script tag stripped)
  expect(draft.body).not.toContain('<script>');
  expect(draft.body).toContain('Report content');

  // List drafts as writer
  const listRes = await as(writer, 'GET', '/api/news/drafts');
  expect(listRes.statusCode).toBe(200);
  const list = json(listRes).drafts;
  expect(list.some(d => d.id === draft.id)).toBe(true);

  // Update draft
  const updateRes = await as(writer, 'PUT', `/api/news/drafts/${draft.id}`, {
    title: 'Updated Secret Investigation',
    subtitle: 'Updated subtitle',
    body: '<p>Updated content</p>',
    theme: 'ERT'
  });
  expect(updateRes.statusCode).toBe(200);
  const updated = json(updateRes).draft;
  expect(updated.title).toBe('Updated Secret Investigation');

  // Another writer/reader cannot hijack or delete this draft
  const readerUpdate = await as(reader, 'PUT', `/api/news/drafts/${draft.id}`, { title: 'Hijack' });
  expect(readerUpdate.statusCode).toBe(403);

  // Writer deletes draft
  const delRes = await as(writer, 'DELETE', `/api/news/drafts/${draft.id}`);
  expect(delRes.statusCode).toBe(200);
  expect(json(delRes).success).toBe(true);
});

test('admin can view all drafts and delete any draft', async () => {
  // Writer creates a draft
  const createRes = await as(writer, 'POST', '/api/news/drafts', {
    title: 'Writer Draft for Admin to See',
    body: '<p>Testing admin visibility</p>',
    theme: 'ERT'
  });
  const draftId = json(createRes).draft.id;

  // Admin lists drafts and sees writer's draft
  const adminListRes = await as(admin, 'GET', '/api/news/drafts');
  expect(adminListRes.statusCode).toBe(200);
  const adminDrafts = json(adminListRes).drafts;
  expect(adminDrafts.some(d => d.id === draftId)).toBe(true);

  // Admin can delete writer's draft
  const adminDelRes = await as(admin, 'DELETE', `/api/news/drafts/${draftId}`);
  expect(adminDelRes.statusCode).toBe(200);
});

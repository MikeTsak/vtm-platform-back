// back/tests/newsPublish.test.js
// Tests for publishing private news articles and triggering Discord notifications.

const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');
const discordService = require('../services/discord');

let pool, app, player, admin, privateNewsId;

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();

  player = await registerUser(app, { displayName: 'Player' });
  admin = await registerUser(app, { displayName: 'Admin' });
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);

  const login = await app.inject({
    method: 'POST',
    url: '/api/auth/login',
    payload: { email: admin.email, password: admin.password }
  });
  admin.cookie = login.cookies.map(c => `${c.name}=${c.value}`).join('; ');

  // Create a private news article
  const [insert] = await pool.query(
    "INSERT INTO news_entries (author_id, type, title, subtitle, body, theme, is_private) VALUES (?, 'news', 'Secret Investigation', 'Confidential', 'Detailed leak', 'ERT', 1)",
    [admin.user.id]
  );
  privateNewsId = insert.insertId;

  // Set discord channel and enabled flag
  await pool.query(
    "INSERT INTO app_settings (setting_key, setting_value) VALUES ('discord_enabled', 'true'), ('discord_channel_id', '123456789') ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)"
  );
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

test('publishing private news requires admin authorization', async () => {
  const anonRes = await app.inject({
    method: 'PATCH',
    url: `/api/news/${privateNewsId}/publish`,
    payload: {}
  });
  expect(anonRes.statusCode).toBe(401);

  const playerRes = await app.inject({
    method: 'PATCH',
    url: `/api/news/${privateNewsId}/publish`,
    headers: { cookie: player.cookie },
    payload: {}
  });
  expect(playerRes.statusCode).toBe(403);
});

test('admin can publish private news article and trigger discord broadcast', async () => {
  const sendSpy = vi.spyOn(discordService, 'sendDiscordChannelMessage').mockResolvedValue({ id: 'msg_1' });
  process.env.DISCORD_BOT_TOKEN = 'mock-token';

  const res = await app.inject({
    method: 'PATCH',
    url: `/api/news/${privateNewsId}/publish`,
    headers: { cookie: admin.cookie },
    payload: {
      discord_prefix: '🔥 Hot News Alert! 🔥'
    }
  });

  expect(res.statusCode).toBe(200);
  const data = JSON.parse(res.body);
  expect(data.success).toBe(true);
  expect(data.discordSent).toBe(true);

  // Verify database update
  const [[updated]] = await pool.query('SELECT is_private, published_by, published_at FROM news_entries WHERE id = ?', [privateNewsId]);
  expect(updated.is_private).toBe(0);
  expect(updated.published_by).toBe(admin.user.id);
  expect(updated.published_at).toBeTruthy();

  // Verify discord send was invoked with formatted payload
  expect(sendSpy).toHaveBeenCalled();
  const [channelId, payload] = sendSpy.mock.calls[0];
  expect(channelId).toBe('123456789');
  expect(payload.content).toContain('🔥 Hot News Alert! 🔥');
  expect(payload.content).toContain('Secret Investigation');

  sendSpy.mockRestore();
});

test('publishing an already published article can re-broadcast when discord not skipped', async () => {
  const sendSpy = vi.spyOn(discordService, 'sendDiscordChannelMessage').mockResolvedValue({ id: 'msg_2' });

  const res = await app.inject({
    method: 'PATCH',
    url: `/api/news/${privateNewsId}/publish`,
    headers: { cookie: admin.cookie },
    payload: {
      discord_prefix: '📢 Re-announcement'
    }
  });

  expect(res.statusCode).toBe(200);
  const data = JSON.parse(res.body);
  expect(data.success).toBe(true);
  expect(data.message).toBe('Already published');
  expect(data.discordSent).toBe(true);
  expect(sendSpy).toHaveBeenCalled();

  sendSpy.mockRestore();
});

test('admin can broadcast public news article directly via broadcast endpoint', async () => {
  const sendSpy = vi.spyOn(discordService, 'sendDiscordChannelMessage').mockResolvedValue({ id: 'msg_3' });

  const res = await app.inject({
    method: 'POST',
    url: `/api/news/${privateNewsId}/broadcast`,
    headers: { cookie: admin.cookie },
    payload: {
      discord_prefix: '🚨 Breaking News 🚨'
    }
  });

  expect(res.statusCode).toBe(200);
  const data = JSON.parse(res.body);
  expect(data.success).toBe(true);
  expect(sendSpy).toHaveBeenCalled();

  sendSpy.mockRestore();
});

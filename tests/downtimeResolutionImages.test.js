// tests/downtimeResolutionImages.test.js — Downtime resolution image attachments
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');

let pool, app, player, admin, characterId, downtimeId;
const json = (res) => JSON.parse(res.body);

function makeMultipartImage(filename = 'test_map.png', content = 'fake-image-bytes', contentType = 'image/png') {
  const boundary = '----TestBoundary' + Math.random().toString(36).substring(2);
  const payload = [
    `--${boundary}`,
    `Content-Disposition: form-data; name="file"; filename="${filename}"`,
    `Content-Type: ${contentType}`,
    '',
    content,
    `--${boundary}--`,
    ''
  ].join('\r\n');
  return {
    headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
    payload: Buffer.from(payload),
  };
}

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();

  player = await registerUser(app, { displayName: 'Player One' });
  admin = await registerUser(app, { displayName: 'Storyteller Boss' });
  await pool.query("UPDATE users SET role='admin' WHERE id=?", [admin.user.id]);
  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: admin.email, password: admin.password } });
  admin.cookie = login.cookies.map(c => `${c.name}=${c.value}`).join('; ');

  // Create a character for player
  const [cRes] = await pool.query(
    "INSERT INTO characters (user_id, name, clan, xp) VALUES (?, 'Vlad', 'Brujah', 0)",
    [player.user.id]
  );
  characterId = cRes.insertId;

  // Create a downtime action
  const [dtRes] = await pool.query(
    "INSERT INTO downtimes (character_id, title, body, status, feeding_type) VALUES (?, 'Investigate Catacombs', 'I search the catacombs', 'submitted', 'Alleycat')",
    [characterId]
  );
  downtimeId = dtRes.insertId;
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

test('non-admin is rejected from uploading resolution image', async () => {
  const mp = makeMultipartImage();
  const res = await app.inject({
    method: 'POST',
    url: '/api/admin/downtimes/upload-image',
    headers: { ...mp.headers, cookie: player.cookie },
    payload: mp.payload,
  });
  expect(res.statusCode).toBe(403);
});

test('admin can upload resolution image via Mike PHP handler', async () => {
  const mp = makeMultipartImage('athens_map.png');
  const res = await app.inject({
    method: 'POST',
    url: '/api/admin/downtimes/upload-image',
    headers: { ...mp.headers, cookie: admin.cookie },
    payload: mp.payload,
  });
  expect(res.statusCode).toBe(200);
  const data = json(res);
  expect(data.success).toBe(true);
  expect(data.url).toContain('https://img.miketsak.gr/');
  expect(data.name).toBe('athens_map.png');
});

test('admin can attach resolution image to downtime via patch and player can view it', async () => {
  const attachedImages = [
    { url: 'https://img.miketsak.gr/athens_map.webp', name: 'athens_map.webp' }
  ];

  const patchRes = await app.inject({
    method: 'PATCH',
    url: `/api/admin/downtimes/${downtimeId}`,
    headers: { cookie: admin.cookie },
    payload: {
      status: 'resolved',
      gm_resolution: 'You found ancient markings on the walls.',
      resolution_images: attachedImages,
    },
  });

  expect(patchRes.statusCode).toBe(200);
  const patchData = json(patchRes);
  expect(patchData.downtime.resolution_image_url).toBe('https://img.miketsak.gr/athens_map.webp');
  expect(patchData.downtime.resolution_image_name).toBe('athens_map.webp');
  expect(patchData.downtime.resolution_images).toHaveLength(1);
  expect(patchData.downtime.resolution_images[0].name).toBe('athens_map.webp');

  // Verify admin list returns attached image
  const adminListRes = await app.inject({
    method: 'GET',
    url: '/api/admin/downtimes',
    headers: { cookie: admin.cookie },
  });
  expect(adminListRes.statusCode).toBe(200);
  const adminList = json(adminListRes).downtimes;
  const targetDt = adminList.find(d => d.id === downtimeId);
  expect(targetDt).toBeDefined();
  expect(targetDt.resolution_images).toHaveLength(1);
  expect(targetDt.resolution_images[0].url).toBe('https://img.miketsak.gr/athens_map.webp');

  // Verify player /api/downtimes/mine returns attached image
  const playerMineRes = await app.inject({
    method: 'GET',
    url: '/api/downtimes/mine',
    headers: { cookie: player.cookie },
  });
  expect(playerMineRes.statusCode).toBe(200);
  const playerDts = json(playerMineRes).downtimes;
  const playerTarget = playerDts.find(d => d.id === downtimeId);
  expect(playerTarget).toBeDefined();
  expect(playerTarget.resolution_images).toHaveLength(1);
  expect(playerTarget.resolution_images[0].name).toBe('athens_map.webp');
  expect(playerTarget.resolution_images[0].url).toBe('https://img.miketsak.gr/athens_map.webp');
});

test('admin can attach multiple images and detach them', async () => {
  const multipleImages = [
    { url: 'https://img.miketsak.gr/evidence_1.webp', name: 'evidence_1.webp' },
    { url: 'https://img.miketsak.gr/evidence_2.webp', name: 'evidence_2.webp' },
  ];

  // Update with multiple images
  const patchRes = await app.inject({
    method: 'PATCH',
    url: `/api/admin/downtimes/${downtimeId}`,
    headers: { cookie: admin.cookie },
    payload: {
      resolution_images: multipleImages,
    },
  });

  expect(patchRes.statusCode).toBe(200);
  const data = json(patchRes).downtime;
  expect(data.resolution_images).toHaveLength(2);
  expect(data.resolution_image_url).toBe('https://img.miketsak.gr/evidence_1.webp');
  expect(data.resolution_image_name).toBe('evidence_1.webp');

  // Verify player sees both images
  const playerRes = await app.inject({
    method: 'GET',
    url: '/api/downtimes/mine',
    headers: { cookie: player.cookie },
  });
  const playerDt = json(playerRes).downtimes.find(d => d.id === downtimeId);
  expect(playerDt.resolution_images).toHaveLength(2);
  expect(playerDt.resolution_images[1].name).toBe('evidence_2.webp');

  // Detach all images
  const clearRes = await app.inject({
    method: 'PATCH',
    url: `/api/admin/downtimes/${downtimeId}`,
    headers: { cookie: admin.cookie },
    payload: {
      resolution_images: [],
    },
  });
  expect(clearRes.statusCode).toBe(200);
  const cleared = json(clearRes).downtime;
  expect(cleared.resolution_images).toEqual([]);
  expect(cleared.resolution_image_url).toBeNull();
  expect(cleared.resolution_image_name).toBeNull();
});

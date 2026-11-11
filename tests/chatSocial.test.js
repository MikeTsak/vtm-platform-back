// tests/chatSocial.test.js — SchreckNet blocks (open, DMs only), pin/mute per
// chat, @mentions piercing a mute, and saved messages (migration 0086).
const { setupTestDatabase, teardownTestDatabase, truncateAll } = require('./setup/testDb');
const { buildTestApp } = require('./setup/testApp');
const { registerUser } = require('./setup/helpers');
const { mentionedIds } = require('../utils/chatConversation');

let pool, app, livia, marcus, selene, outsider, admin, groupId;

const call = (who, method, url, payload) => app.inject({ method, url, payload, headers: { cookie: who.cookie } });
const body = (res) => JSON.parse(res.body);
const pushes = () => app.testPushNotifications;
const settle = () => new Promise((r) => setTimeout(r, 150));
const dm = (from, to, text) => call(from, 'POST', '/api/chat/messages', { recipient_id: to.user.id, body: text });
const groupSay = (who, text) => call(who, 'POST', `/api/chat/groups/${groupId}/messages`, { body: text });

async function player(name, role = null) {
  const u = await registerUser(app, { displayName: `${name} Account` });
  await pool.query('INSERT INTO characters (user_id, name, clan, xp, sheet) VALUES (?, ?, ?, 0, ?)',
    [u.user.id, name, 'Toreador', JSON.stringify({ is_active: true })]);
  if (role) {
    await pool.query('UPDATE users SET role = ? WHERE id = ?', [role, u.user.id]);
    const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: u.email, password: u.password } });
    u.cookie = login.cookies.map((c) => `${c.name}=${c.value}`).join('; ');
  }
  return u;
}

beforeAll(async () => {
  pool = await setupTestDatabase();
  await truncateAll();
  app = buildTestApp(pool);
  await app.ready();
  livia = await player('Livia');
  marcus = await player('Marcus');
  selene = await player('Selene');
  outsider = await player('Outsider');
  admin = await player('Storyteller', 'admin');
  groupId = (await pool.query("INSERT INTO chat_groups (name, created_by) VALUES ('The Night Court', ?)", [livia.user.id]))[0].insertId;
  for (const u of [livia, marcus, selene]) {
    await pool.query('INSERT INTO chat_group_members (group_id, user_id) VALUES (?, ?)', [groupId, u.user.id]);
  }
});

afterAll(async () => {
  await app.close();
  await teardownTestDatabase();
});

beforeEach(() => { pushes().length = 0; });

describe('blocking', () => {
  let oldMessageId;

  it('stops DMs both ways and tells each side plainly', async () => {
    oldMessageId = body(await dm(marcus, livia, 'Before the feud')).message.id;
    expect((await call(livia, 'POST', '/api/chat/blocks', { user_id: marcus.user.id })).statusCode).toBe(200);

    const theirs = await dm(marcus, livia, 'Hello?');
    expect(theirs.statusCode).toBe(403);
    expect(body(theirs)).toMatchObject({ error: 'Livia has blocked you.', blocked: 'by_them' });

    const mine = await dm(livia, marcus, 'One last word');
    expect(mine.statusCode).toBe(403);
    expect(body(mine)).toMatchObject({ blocked: 'by_me' });
    expect(body(mine).error).toMatch(/You blocked Marcus/);
  });

  it('each side sees the block in their settings', async () => {
    expect(body(await call(livia, 'GET', '/api/chat/prefs')).blocked).toEqual([marcus.user.id]);
    expect(body(await call(marcus, 'GET', '/api/chat/prefs')).blocked_by).toEqual([livia.user.id]);
  });

  it('no reacting across a block', async () => {
    const res = await call(marcus, 'POST', `/api/chat/messages/${oldMessageId}/reactions`, { table: 'chat_messages', emoji: '❤️' });
    expect(res.statusCode).toBe(403);
  });

  it('Storytellers and yourself cannot be blocked', async () => {
    expect((await call(livia, 'POST', '/api/chat/blocks', { user_id: admin.user.id })).statusCode).toBe(400);
    expect((await call(livia, 'POST', '/api/chat/blocks', { user_id: livia.user.id })).statusCode).toBe(400);
  });

  it('unblocking opens the line again', async () => {
    expect((await call(livia, 'DELETE', `/api/chat/blocks/${marcus.user.id}`)).statusCode).toBe(200);
    expect((await dm(marcus, livia, 'Truce?')).statusCode).toBe(201);
  });
});

describe('reactions need access', () => {
  it('a stranger cannot react to someone else\'s DM', async () => {
    const id = body(await dm(livia, selene, 'Private')).message.id;
    const res = await call(outsider, 'POST', `/api/chat/messages/${id}/reactions`, { table: 'chat_messages', emoji: '❤️' });
    expect(res.statusCode).toBe(403);
  });
});

describe('pin and mute', () => {
  it('pins a chat to the top and takes it off again', async () => {
    const key = `g:${groupId}`;
    const pinned = await call(selene, 'PUT', '/api/chat/prefs', { key, pinned: true });
    expect(pinned.statusCode).toBe(200);
    expect(body(pinned).pinned_at).toBeTruthy();
    expect(body(await call(selene, 'GET', '/api/chat/prefs')).prefs[key].pinned_at).toBeTruthy();

    await call(selene, 'PUT', '/api/chat/prefs', { key, pinned: false });
    expect(body(await call(selene, 'GET', '/api/chat/prefs')).prefs[key]).toBeUndefined();
  });

  it('a muted DM sends no push; other DMs still do', async () => {
    await call(selene, 'PUT', '/api/chat/prefs', { key: `u:${marcus.user.id}`, mute: '1h' });
    await dm(marcus, selene, 'Are you there?');
    await dm(livia, selene, 'Elysium tonight');
    await settle();
    expect(pushes().map((p) => p.userId)).toEqual([selene.user.id]);
    expect(pushes()[0].title).toMatch(/Livia/);
  });

  it('a mention gets through a muted group, and says so', async () => {
    await call(marcus, 'PUT', '/api/chat/prefs', { key: `g:${groupId}`, mute: 'forever' });

    await groupSay(livia, 'Quiet night');
    await settle();
    expect(pushes().map((p) => p.userId)).toEqual([selene.user.id]);

    pushes().length = 0;
    await groupSay(livia, 'A word, @marcus, before dawn');
    await settle();
    const toMarcus = pushes().find((p) => p.userId === marcus.user.id);
    expect(toMarcus.title).toBe('Livia mentioned you in The Night Court');
  });

  it('unmuting brings pushes back, and nonsense is refused', async () => {
    await call(marcus, 'PUT', '/api/chat/prefs', { key: `g:${groupId}`, mute: null });
    await groupSay(livia, 'Everyone listen');
    await settle();
    expect(pushes().map((p) => p.userId).sort()).toEqual([marcus.user.id, selene.user.id].sort());

    expect((await call(marcus, 'PUT', '/api/chat/prefs', { key: `g:${groupId}`, mute: '3 years' })).statusCode).toBe(400);
    expect((await call(marcus, 'PUT', '/api/chat/prefs', { key: 'x:1', pinned: true })).statusCode).toBe(400);
  });
});

describe('saved messages', () => {
  let groupMsgId;

  it('saves a message only its reader can see, and lists it with where it lives', async () => {
    groupMsgId = body(await groupSay(marcus, 'Remember this oath')).message.id;
    const saved = await call(selene, 'POST', `/api/chat/messages/${groupMsgId}/save`, { table: 'chat_group_messages' });
    expect(saved.statusCode).toBe(200);
    const list = body(await call(selene, 'GET', '/api/chat/saved')).saved;
    expect(list[0]).toMatchObject({ id: groupMsgId, kind: 'group', chat_id: groupId, chat_name: 'The Night Court', sender_name: 'Marcus' });

    const notMine = await call(outsider, 'POST', `/api/chat/messages/${groupMsgId}/save`, { table: 'chat_group_messages' });
    expect(notMine.statusCode).toBe(403);
  });

  it('drops out of the list once they leave the group', async () => {
    await pool.query('DELETE FROM chat_group_members WHERE group_id = ? AND user_id = ?', [groupId, selene.user.id]);
    expect(body(await call(selene, 'GET', '/api/chat/saved')).saved).toHaveLength(0);
    await pool.query('INSERT INTO chat_group_members (group_id, user_id) VALUES (?, ?)', [groupId, selene.user.id]);
  });

  it('can be unsaved', async () => {
    await call(selene, 'POST', `/api/chat/messages/${groupMsgId}/save`, { table: 'chat_group_messages', saved: false });
    expect(body(await call(selene, 'GET', '/api/chat/saved')).saved).toHaveLength(0);
  });
});

describe('mention matching', () => {
  const members = [{ user_id: 1, name: 'Ann' }, { user_id: 2, name: 'Anna Petrou' }, { user_id: 3, name: 'Καλυψώ Γραικίνη' }];
  it('needs the whole name, ignores case, reads Greek', () => {
    expect([...mentionedIds('@anna petrou, come', members)]).toEqual([2]);
    expect([...mentionedIds('hi @Ann!', members)]).toEqual([1]);
    expect([...mentionedIds('@Annabel?', members)]).toEqual([]);
    expect([...mentionedIds('Η @καλυψώ γραικίνη ήρθε', members)]).toEqual([3]);
    expect([...mentionedIds('no tags here', members)]).toEqual([]);
  });
});

// utils/chatConversation.js
//
// Shared by routes/chat.js and routes/npcChat.js: the key a conversation's
// shared settings live under, history paging, and a character's public
// court standing (the same data the Court page shows everyone).

// 'u:<low>:<high>' for a DM, 'g:<groupId>' for a group, 'n:<npcId>:<userId>' for an NPC thread.
function convKey(kind, a, b) {
  if (kind === 'user') return `u:${Math.min(a, b)}:${Math.max(a, b)}`;
  if (kind === 'group') return `g:${a}`;
  return `n:${a}:${b}`;
}

async function loadConvSettings(pool, key) {
  const [[row]] = await pool.query('SELECT theme, emoji FROM chat_conversation_settings WHERE conv_key=?', [key]);
  return { theme: row?.theme || null, emoji: row?.emoji || null };
}

// History paging on (created_at, id), the order messages are shown in.
//   ?limit=50            latest page
//   ?before=<id>         the page older than that message (scrolling up)
//   ?from=<id>&before=.. everything from that message up to `before`
//                        (jumping to an old search result / quoted message)
// No params keeps the old behaviour: the latest 500.
async function historyWindow(pool, table, alias, query = {}) {
  const limit = query.from ? 2000 : Math.min(Math.max(Number(query.limit) || 500, 1), 500);
  let sql = '';
  const params = [];
  const position = async (id) => {
    const [[row]] = await pool.query(`SELECT created_at, id FROM ${table} WHERE id=?`, [Number(id)]);
    return row;
  };
  if (query.before) {
    const r = await position(query.before);
    if (r) {
      sql += ` AND (${alias}.created_at < ? OR (${alias}.created_at = ? AND ${alias}.id < ?))`;
      params.push(r.created_at, r.created_at, r.id);
    }
  }
  if (query.from) {
    const r = await position(query.from);
    if (r) {
      sql += ` AND (${alias}.created_at > ? OR (${alias}.created_at = ? AND ${alias}.id >= ?))`;
      params.push(r.created_at, r.created_at, r.id);
    }
  }
  const order = `ORDER BY ${alias}.created_at DESC, ${alias}.id DESC LIMIT ${limit}`;
  const hasMore = (rows) => (query.from ? undefined : rows.length === limit);
  return { sql, params, order, hasMore };
}

// Court title(s) + Status dots, hidden characters excluded.
function courtStanding(row) {
  if (!row || row.is_hidden) return { titles: [], court_status: null };
  let titles = row.titles;
  if (typeof titles === 'string') {
    try { titles = JSON.parse(titles); } catch { titles = []; }
  }
  return {
    titles: Array.isArray(titles) ? titles : [],
    court_status: row.court_status == null ? null : Number(row.court_status),
  };
}

// Size (1-3) of a hold-to-grow conversation emoji. Only honoured on a short,
// text-only message (the emoji itself); anything else stores NULL.
function emojiSize(body, raw) {
  const size = Number(raw);
  const text = typeof body === 'string' ? body.trim() : '';
  return [1, 2, 3].includes(size) && text && text.length <= 32 ? size : null;
}

module.exports = { convKey, loadConvSettings, historyWindow, courtStanding, emojiSize };

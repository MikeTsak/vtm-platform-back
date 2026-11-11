// services/coterieLifecycle.js
//
// What happens to a coterie when members drop out (house rules, user, 2026-11-11):
//   * A character out of play (dead, left the city, exiled; not "missing",
//     who may come back) leaves its coterie at once, and every Background it
//     contributed is taken back. Nothing returns to its sheet.
//   * A coterie under the member floor goes DORMANT for DORMANT_DAYS. Its
//     merits keep working. The rules engine already refuses edits, purchases
//     and contributions below the floor, so adding members is all that's open.
//     The deadline is a Calendar date and is edited there.
//   * Back at the floor before the deadline: active again.
//   * Deadline passed: DISSOLVED, never deleted (a delete cascades the log and
//     the retainers away). Ghouls go to their domitor if still in play, without
//     other members' blood; every other retainer is released. The remaining
//     members are freed and the Domain is given up.
//
// Functions taking `conn` run inside the caller's transaction and return push
// notices; send them with announce() once the caller has committed.

const { MIN_MEMBERS } = require('../utils/coterieRules');
const { parseSheet } = require('../utils/sheet');
const { splitBlood } = require('../utils/ghoulBlood');
const { sendPushNotification } = require('./push');
const { log } = require('../logger');

const DORMANT_DAYS = 60;
const REMIND_DAYS = 7;
const DAY_MS = 24 * 60 * 60 * 1000;
const PAGE = '/court/coteries';

// Characters that have left the story. Flags can be NULL on old rows.
const OUT_OF_PLAY_SQL = '(COALESCE(c.is_deceased, 0) = 1 OR COALESCE(c.is_left, 0) = 1 OR COALESCE(c.is_exiled, 0) = 1)';
const OUT_OF_PLAY_FLAGS = ['is_deceased', 'is_left', 'is_exiled'];
const reasonFor = (c, fallback) =>
  c?.is_deceased ? 'met Final Death' : c?.is_exiled ? 'was exiled' : c?.is_left ? 'left the city' : fallback;

const fmt = (d) => new Date(d).toLocaleDateString('en-GB', { timeZone: 'Europe/Athens', day: 'numeric', month: 'long', year: 'numeric' });

const asList = (v) => {
  if (Array.isArray(v)) return v;
  try {
    const out = JSON.parse(v || '[]');
    return Array.isArray(out) ? out : [];
  } catch {
    return [];
  }
};

function logEvent(conn, coterieId, e) {
  return conn.query(
    `INSERT INTO coterie_xp_log
       (coterie_id, user_id, character_id, kind, target_type, target_key, target_name, from_dots, to_dots, note)
     VALUES (?,?,?,?,?,?,?,?,?,?)`,
    [
      coterieId, e.userId ?? null, e.characterId ?? null, e.kind, e.targetType ?? null, e.targetKey ?? null,
      e.targetName ? String(e.targetName).slice(0, 160) : null, e.fromDots ?? null, e.toDots ?? null,
      e.note ? String(e.note).slice(0, 500) : null,
    ]
  );
}

async function memberUserIds(conn, coterieId) {
  const [rows] = await conn.query('SELECT user_id FROM coterie_members WHERE coterie_id = ?', [coterieId]);
  return rows.map((r) => Number(r.user_id));
}

async function inTransaction(pool, fn) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const out = await fn(conn);
    await conn.commit();
    return out;
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
}

// Fire-and-forget pushes, after the commit. sendPushNotification never throws.
function announce(notices) {
  for (const n of notices || []) {
    if (!n) continue;
    for (const id of n.userIds) sendPushNotification(id, n.title, n.body, { url: PAGE }, 'character');
  }
}

// Takes back every Background dot this character contributed that the coterie
// still holds. The log is the ledger: 'contribute' rows add, 'revoked' rows
// subtract, so nothing is taken twice. Dots the coterie later lost some other
// way are not taken again (never below zero).
async function takeBackDonations(conn, coterieId, charId, name) {
  const [rows] = await conn.query(
    `SELECT target_key, target_name, from_dots, to_dots FROM coterie_xp_log
      WHERE coterie_id = ? AND character_id = ? AND target_type = 'background' AND kind IN ('contribute', 'revoked')`,
    [coterieId, charId]
  );
  const given = new Map();
  for (const r of rows) {
    const g = given.get(r.target_key) || { name: r.target_name, dots: 0 };
    g.dots += (Number(r.to_dots) || 0) - (Number(r.from_dots) || 0);
    given.set(r.target_key, g);
  }
  if (![...given.values()].some((g) => g.dots > 0)) return;

  const [[co]] = await conn.query('SELECT backgrounds_json FROM coteries WHERE id = ? FOR UPDATE', [coterieId]);
  const backgrounds = asList(co.backgrounds_json);
  let taken = 0;
  for (const [key, g] of given) {
    const entry = backgrounds.find((b) => b && b.key === key);
    const before = entry ? Number(entry.dots) || 0 : 0;
    const take = Math.min(g.dots, before);
    if (take <= 0) continue;
    const after = before - take;
    if (after > 0) entry.dots = after;
    else backgrounds.splice(backgrounds.indexOf(entry), 1);
    taken += take;
    await logEvent(conn, coterieId, {
      characterId: charId, kind: 'revoked', targetType: 'background', targetKey: key, targetName: g.name,
      fromDots: before, toDots: after, note: `${name}'s ${take} dot(s) of ${g.name} left with them`,
    });
  }
  if (taken) {
    // Contributions were credited as advancement dots; they leave the same way.
    await conn.query(
      'UPDATE coteries SET backgrounds_json = ?, advancement_dots = GREATEST(0, advancement_dots - ?) WHERE id = ?',
      [JSON.stringify(backgrounds), taken, coterieId]
    );
  }
}

// Puts a coterie to sleep below the floor and wakes it at the floor.
async function syncFloor(conn, coterieId) {
  const [[co]] = await conn.query('SELECT id, name, status FROM coteries WHERE id = ? FOR UPDATE', [coterieId]);
  if (!co || co.status === 'dissolved') return null;
  const ids = await memberUserIds(conn, coterieId);

  if (ids.length < MIN_MEMBERS && co.status === 'active') {
    const until = new Date(Date.now() + DORMANT_DAYS * DAY_MS);
    await conn.query("UPDATE coteries SET status = 'dormant', dormant_since = NOW(), dissolve_at = ? WHERE id = ?", [until, coterieId]);
    await logEvent(conn, coterieId, {
      kind: 'status', targetType: 'dormant',
      note: `Fewer than ${MIN_MEMBERS} members: dormant until ${fmt(until)}. Merits keep working; only new members can be added.`,
    });
    return {
      userIds: ids,
      title: `${co.name} is dormant`,
      body: `It needs ${MIN_MEMBERS} members again by ${fmt(until)}, or the coterie dissolves.`,
    };
  }
  if (ids.length >= MIN_MEMBERS && co.status === 'dormant') {
    await conn.query("UPDATE coteries SET status = 'active', dormant_since = NULL, dissolve_at = NULL WHERE id = ?", [coterieId]);
    await logEvent(conn, coterieId, { kind: 'status', targetType: 'active', note: 'Back to full strength: the coterie is active again.' });
  }
  return null;
}

// Takes an out-of-play character out of every coterie it is in. `userId`
// also catches legacy member rows written before character_id existed.
async function removeFromCoteries(conn, charId, userId, fallbackReason = 'left play') {
  const [[ch]] = await conn.query('SELECT name, is_deceased, is_left, is_exiled FROM characters WHERE id = ?', [charId]);
  const reason = reasonFor(ch, fallbackReason);
  const [rows] = await conn.query(
    `SELECT m.id, m.coterie_id, m.user_id, COALESCE(c.name, m.display_name) AS name
       FROM coterie_members m LEFT JOIN characters c ON c.id = m.character_id
      WHERE m.character_id = ? OR (m.character_id IS NULL AND m.user_id = ?)`,
    [charId, userId ?? null]
  );
  const notices = [];
  for (const m of rows) {
    const name = m.name || ch?.name || 'A character';
    await conn.query('DELETE FROM coterie_members WHERE id = ?', [m.id]);
    await logEvent(conn, m.coterie_id, {
      userId: m.user_id, characterId: charId, kind: 'member_left', targetType: 'member', targetName: name,
      note: `${name} ${reason}`,
    });
    await takeBackDonations(conn, m.coterie_id, charId, name);
    notices.push(await syncFloor(conn, m.coterie_id));
  }
  return notices.filter(Boolean);
}

// The court marked a character dead, gone or exiled.
async function characterLeftPlay(pool, charId) {
  const notices = await inTransaction(pool, async (conn) => {
    const [[c]] = await conn.query('SELECT user_id FROM characters WHERE id = ?', [charId]);
    return c ? removeFromCoteries(conn, charId, c.user_id) : [];
  });
  announce(notices);
}

async function dissolve(conn, coterieId) {
  const [[co]] = await conn.query('SELECT id, name, status FROM coteries WHERE id = ? FOR UPDATE', [coterieId]);
  if (!co || co.status !== 'dormant') return null;

  const [retainers] = await conn.query(
    `SELECT r.id, r.name, r.sheet, r.domitor_character_id, c.name AS domitor_name,
            (c.id IS NOT NULL AND c.user_id IS NOT NULL AND NOT ${OUT_OF_PLAY_SQL}) AS domitor_in_play
       FROM retainers r LEFT JOIN characters c ON c.id = r.domitor_character_id
      WHERE r.coterie_id = ?`,
    [coterieId]
  );
  for (const r of retainers) {
    const sheet = parseSheet(r.sheet);
    let note;
    if (sheet?.isGhoul === true && Number(r.domitor_in_play) === 1) {
      // A personal ghoul is its owner's: character_id, no separate domitor.
      await conn.query(
        'UPDATE retainers SET coterie_id = NULL, character_id = ?, domitor_character_id = NULL, sheet = ? WHERE id = ?',
        [r.domitor_character_id, JSON.stringify(splitBlood(sheet).own), r.id]
      );
      note = `${r.name} went back to ${r.domitor_name}`;
    } else {
      await conn.query('DELETE FROM retainers WHERE id = ?', [r.id]);
      note = `${r.name} was released`;
    }
    await logEvent(conn, coterieId, { kind: 'status', targetType: 'retainer', targetName: r.name, note });
  }

  const [members] = await conn.query(
    `SELECT m.user_id, m.character_id, COALESCE(c.name, m.display_name) AS name
       FROM coterie_members m LEFT JOIN characters c ON c.id = m.character_id
      WHERE m.coterie_id = ?`,
    [coterieId]
  );
  await conn.query('DELETE FROM coterie_members WHERE coterie_id = ?', [coterieId]);
  for (const m of members) {
    await logEvent(conn, coterieId, {
      userId: m.user_id, characterId: m.character_id, kind: 'member_left', targetType: 'member', targetName: m.name,
      note: `${m.name || 'A character'} was freed when the coterie dissolved`,
    });
  }
  await conn.query("UPDATE coteries SET status = 'dissolved', dissolve_at = NOW(), domain_id = NULL WHERE id = ?", [coterieId]);
  await logEvent(conn, coterieId, { kind: 'status', targetType: 'dissolved', note: 'Dissolved: it never got its members back. Its Domain was given up.' });
  return {
    userIds: members.map((m) => Number(m.user_id)),
    title: `${co.name} has dissolved`,
    body: 'Its ghouls went back to their masters and its other retainers were released.',
  };
}

// A Storyteller moves the deadline (admin Calendar). Returns 'ok', 'not_found' or 'not_dormant'.
async function setDeadline(pool, coterieId, when) {
  return inTransaction(pool, async (conn) => {
    const [[co]] = await conn.query('SELECT status FROM coteries WHERE id = ? FOR UPDATE', [coterieId]);
    if (!co) return 'not_found';
    if (co.status !== 'dormant') return 'not_dormant';
    await conn.query('UPDATE coteries SET dissolve_at = ? WHERE id = ?', [when, coterieId]);
    await logEvent(conn, coterieId, { kind: 'status', targetType: 'deadline', note: `A Storyteller moved the deadline to ${fmt(when)}.` });
    return 'ok';
  });
}

// One coterie failing must not stall the rest.
async function each(items, what, fn) {
  let n = 0;
  for (const it of items) {
    try {
      if (await fn(it)) n += 1;
    } catch (e) {
      log.err(`Coterie sweep: ${what} failed`, { id: it.id, message: e.message });
    }
  }
  return n;
}

// The background job: catches what the hooks missed, then runs the clock.
async function sweepCoteries(pool) {
  // Out-of-play characters still listed: marked before this rule, or by a path without the hook.
  const [stale] = await pool.query(
    `SELECT DISTINCT c.id FROM coterie_members m JOIN characters c ON c.id = m.character_id WHERE ${OUT_OF_PLAY_SQL}`
  );
  const removed = await each(stale, 'removing an out-of-play member', async (c) => {
    await characterLeftPlay(pool, c.id);
    return true;
  });

  // Under the floor -> dormant (also coteries that were short before this rule); at it -> active.
  const [open] = await pool.query("SELECT id FROM coteries WHERE status <> 'dissolved'");
  const slept = await each(open, 'checking the member floor', async (co) => {
    const notice = await inTransaction(pool, (conn) => syncFloor(conn, co.id));
    announce([notice]);
    return !!notice;
  });

  // One reminder per dormancy, a week before the deadline.
  const [soon] = await pool.query(
    `SELECT co.id, co.name, co.dissolve_at FROM coteries co
      WHERE co.status = 'dormant' AND co.dissolve_at > NOW() AND co.dissolve_at <= NOW() + INTERVAL ? DAY
        AND NOT EXISTS (SELECT 1 FROM coterie_xp_log l
                         WHERE l.coterie_id = co.id AND l.kind = 'status' AND l.target_type = 'reminder'
                           AND l.created_at >= co.dormant_since)`,
    [REMIND_DAYS]
  );
  const reminded = await each(soon, 'reminding', async (co) => {
    const ids = await inTransaction(pool, async (conn) => {
      await logEvent(conn, co.id, { kind: 'status', targetType: 'reminder', note: `Reminder sent: the coterie dissolves on ${fmt(co.dissolve_at)}.` });
      return memberUserIds(conn, co.id);
    });
    announce([{ userIds: ids, title: `${co.name} dissolves soon`, body: `It needs ${MIN_MEMBERS} members by ${fmt(co.dissolve_at)}, or it dissolves.` }]);
    return true;
  });

  const [due] = await pool.query("SELECT id FROM coteries WHERE status = 'dormant' AND dissolve_at IS NOT NULL AND dissolve_at <= NOW()");
  const dissolved = await each(due, 'dissolving', async (co) => {
    const notice = await inTransaction(pool, (conn) => dissolve(conn, co.id));
    announce([notice]);
    return !!notice;
  });

  return { removed, dormant: slept, reminded, dissolved };
}

module.exports = {
  DORMANT_DAYS, OUT_OF_PLAY_FLAGS,
  removeFromCoteries, syncFloor, characterLeftPlay, setDeadline, sweepCoteries, announce,
};

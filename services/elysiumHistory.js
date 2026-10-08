// services/elysiumHistory.js
//
// Every change to an Elysium invitation leaves a full snapshot in
// elysium_invitation_versions: the words, the design and the guest list
// exactly as stored (so exactly as players were shown it), who did it, and
// in which office. Written by routes/elysium.js (the Keeper) and
// routes/adminMisc.js (a rename from the Calendar); read by the admin history tab.

const pool = require('../db');

const CONTENT = ['name', 'location', 'salutation', 'body', 'dress_code', 'signature', 'design', 'barred'];

const sameContent = (a, b) => CONTENT.every(k => String(a?.[k] ?? '') === String(b?.[k] ?? ''));

// Plain saves that change nothing are not logged; publish / withdraw / re-send always are.
async function recordVersion(eventId, action, actorId, actorOffice) {
  const [[inv]] = await pool.query('SELECT * FROM elysium_invitations WHERE event_id = ?', [eventId]);
  if (!inv) return null;
  if (action === 'save' || action === 'edit' || action === 'calendar_rename') {
    const [[last]] = await pool.query(
      'SELECT * FROM elysium_invitation_versions WHERE event_id = ? ORDER BY id DESC LIMIT 1',
      [eventId]
    );
    if (last && sameContent(last, inv)) return last.id;
  }
  const [r] = await pool.query(
    `INSERT INTO elysium_invitation_versions
       (event_id, action, name, location, salutation, body, dress_code, signature, design, barred, published, actor_id, actor_office)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [eventId, action, inv.name, inv.location, inv.salutation, inv.body, inv.dress_code, inv.signature,
      inv.design, inv.barred, inv.published_at ? 1 : 0, actorId || null, actorOffice || null]
  );
  return r.insertId;
}

module.exports = { recordVersion };

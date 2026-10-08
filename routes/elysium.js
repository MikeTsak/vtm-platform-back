// routes/elysium.js
//
// The Keeper of Elysium's invitation. Each Elysium is a chronicle event
// (events.is_elysium) whose date is owned by the admin Calendar; the Keeper
// names it and writes/designs the invitation. The cycle turns on the day of
// the gathering: from that morning (Athens time) the next Elysium is current.

const { requireCapability, signingOffice } = require('../services/courtOffices');
const { recordVersion } = require('../services/elysiumHistory');

const TEXT_FIELDS = { name: 160, location: 255, salutation: 255, body: 8000, dress_code: 160, signature: 160 };
const DESIGN_SLUGS = ['cardPreset', 'bannerPreset', 'accent', 'ornament', 'font', 'seal'];
const DESIGN_IMAGES = ['cardImage', 'bannerImage'];

const athensDay = (d) => new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Athens' }).format(new Date(d));

const parseJson = (raw, fallback) => {
  if (raw == null) return fallback;
  if (typeof raw === 'object') return raw;
  try { return JSON.parse(raw); } catch { return fallback; }
};

// Only short slugs and plain https image URLs: these end up in CSS url().
function cleanDesign(input) {
  const out = {};
  if (!input || typeof input !== 'object') return out;
  for (const k of DESIGN_SLUGS) {
    if (typeof input[k] === 'string' && /^[a-z0-9-]{1,40}$/.test(input[k])) out[k] = input[k];
  }
  // Language of the card's fixed wording; anything else is dropped (the card falls back to English).
  if (input.lang === 'el' || input.lang === 'en') out.lang = input.lang;
  for (const k of DESIGN_IMAGES) {
    const v = input[k];
    if (typeof v === 'string' && v.length <= 500 && /^https:\/\/[^\s"'()<>\\]+$/.test(v)) out[k] = v;
  }
  return out;
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  async function currentElysium() {
    const [rows] = await pool.query(
      'SELECT id, title, date FROM events WHERE is_elysium = 1 AND date >= NOW() - INTERVAL 2 DAY ORDER BY date ASC LIMIT 5'
    );
    const today = athensDay(new Date());
    return rows.find(e => athensDay(e.date) > today) || null;
  }

  async function loadInvitation(eventId) {
    const [[row]] = await pool.query('SELECT * FROM elysium_invitations WHERE event_id = ?', [eventId]);
    if (!row) return null;
    return { ...row, design: parseJson(row.design, {}), barred: parseJson(row.barred, []) };
  }

  // A fresh cycle starts from the previous invitation's words and design (not its guest list).
  async function draftFor(eventId) {
    const existing = await loadInvitation(eventId);
    if (existing) return existing;
    const [[prev]] = await pool.query('SELECT * FROM elysium_invitations ORDER BY updated_at DESC LIMIT 1');
    return {
      event_id: eventId,
      name: null,
      location: prev?.location ?? null,
      salutation: prev?.salutation ?? null,
      body: prev?.body ?? null,
      dress_code: prev?.dress_code ?? null,
      signature: prev?.signature ?? null,
      design: parseJson(prev?.design, {}),
      barred: [],
      published_at: null,
      is_new: true,
    };
  }

  // What this user is shown for an event: their character, and whether they are invited.
  async function guestView(eventId, userId) {
    const inv = await loadInvitation(eventId);
    const [[character]] = await pool.query(
      'SELECT id, name, clan, is_bloodhunted FROM characters WHERE user_id = ? ORDER BY id ASC LIMIT 1',
      [userId]
    );
    const published = !!inv?.published_at;
    const barred = !!character && (!!character.is_bloodhunted || (inv?.barred || []).includes(character.id));
    return { inv, character, status: !published ? 'pending' : barred ? 'barred' : 'invited' };
  }

  // "Send again" pops the invitation up for everyone without erasing who read it
  // before: a read only counts if the version it saw is the re-send or newer.
  async function lastReannounce(eventId) {
    const [[row]] = await pool.query(
      "SELECT id, created_at FROM elysium_invitation_versions WHERE event_id = ? AND action = 'reannounce' ORDER BY id DESC LIMIT 1",
      [eventId]
    );
    return row || null;
  }

  /* ---------------- Player side ---------------- */

  fastify.get('/api/elysium/current', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      reply.header('Cache-Control', 'no-store');
      const event = await currentElysium();
      if (!event) return reply.send({ event: null });

      const { inv, character, status } = await guestView(event.id, req.user.id);
      const published = status !== 'pending';
      const barred = status === 'barred';
      const [[read]] = await pool.query('SELECT last_version_id FROM elysium_invitation_reads WHERE event_id=? AND user_id=?', [event.id, req.user.id]);
      const resent = await lastReannounce(event.id);

      reply.send({
        event: { id: event.id, date: event.date, name: inv?.name || null },
        status,
        read: !!read && (!resent || (read.last_version_id || 0) >= resent.id),
        character: character ? { name: character.name, clan: character.clan } : null,
        // The barred learn only that they are not welcome, not where the court meets.
        invitation: published && !barred ? {
          name: inv.name, location: inv.location, salutation: inv.salutation, body: inv.body,
          dress_code: inv.dress_code, signature: inv.signature, design: inv.design, published_at: inv.published_at,
        } : (published ? { design: inv.design } : null),
      });
    } catch (e) {
      log.err('Elysium current fetch failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load the Elysium' });
    }
  });

  // Every opening is logged: first time (and which card they were shown), last time, how often.
  fastify.post('/api/elysium/:eventId/read', { preHandler: [authRequired] }, async (req, reply) => {
    const eventId = parseInt(req.params.eventId, 10);
    if (!eventId) return reply.status(400).send({ error: 'Invalid event' });
    const { status } = await guestView(eventId, req.user.id);
    if (status === 'pending') return reply.status(409).send({ error: 'Not published' });
    // The snapshot on their screen: the newest published version.
    const [[shown]] = await pool.query(
      'SELECT MAX(id) AS id FROM elysium_invitation_versions WHERE event_id = ? AND published = 1',
      [eventId]
    );
    await pool.query(
      `INSERT INTO elysium_invitation_reads (event_id, user_id, read_at, last_read_at, open_count, seen_as, first_version_id, last_version_id)
       VALUES (?, ?, NOW(), NOW(), 1, ?, ?, ?)
       ON DUPLICATE KEY UPDATE last_read_at = NOW(), open_count = open_count + 1, last_version_id = VALUES(last_version_id)`,
      [eventId, req.user.id, status, shown?.id || null, shown?.id || null]
    );
    reply.send({ ok: true });
  });

  /* ---------------- Keeper of Elysium ---------------- */

  // The Keeper works on the current Elysium; admins may open any (?eventId=).
  async function resolveEventId(req) {
    if (req.court.isAdmin && req.query?.eventId) return parseInt(req.query.eventId, 10) || null;
    if (req.court.isAdmin && req.params?.eventId) return parseInt(req.params.eventId, 10) || null;
    const ev = await currentElysium();
    if (!ev) return null;
    if (req.params?.eventId && Number(req.params.eventId) !== ev.id) return null;
    return ev.id;
  }

  fastify.get('/api/court-actions/elysium', { preHandler: [authRequired, requireCapability('keeper')] }, async (req, reply) => {
    try {
      const eventId = await resolveEventId(req);
      if (!eventId) return reply.send({ event: null });
      const [[event]] = await pool.query('SELECT id, title, date FROM events WHERE id = ?', [eventId]);
      if (!event) return reply.send({ event: null });
      const invitation = await draftFor(eventId);
      const [guests] = await pool.query(
        `SELECT id, name, clan, is_bloodhunted FROM characters
          WHERE COALESCE(is_deceased,0)=0 AND COALESCE(is_left,0)=0 AND COALESCE(is_hidden,0)=0
          ORDER BY name ASC`
      );
      const [[reads]] = await pool.query('SELECT COUNT(*) AS n FROM elysium_invitation_reads WHERE event_id = ?', [eventId]);
      reply.send({ event, invitation, guests, read_count: reads.n });
    } catch (e) {
      log.err('Keeper invitation fetch failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load the invitation' });
    }
  });

  fastify.put('/api/court-actions/elysium/:eventId', { preHandler: [authRequired, requireCapability('keeper')] }, async (req, reply) => {
    try {
      const eventId = await resolveEventId(req);
      if (!eventId) return reply.status(409).send({ error: 'Only the coming Elysium can be prepared.' });
      const b = req.body || {};
      const vals = {};
      for (const [k, max] of Object.entries(TEXT_FIELDS)) {
        vals[k] = typeof b[k] === 'string' && b[k].trim() ? b[k].trim().slice(0, max) : null;
      }
      const design = JSON.stringify(cleanDesign(b.design));
      const barred = JSON.stringify((Array.isArray(b.barred) ? b.barred : []).map(n => parseInt(n, 10)).filter(Boolean));
      await pool.query(
        `INSERT INTO elysium_invitations (event_id, name, location, salutation, body, dress_code, signature, design, barred, updated_by)
         VALUES (?,?,?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE name=VALUES(name), location=VALUES(location), salutation=VALUES(salutation), body=VALUES(body),
           dress_code=VALUES(dress_code), signature=VALUES(signature), design=VALUES(design), barred=VALUES(barred), updated_by=VALUES(updated_by)`,
        [eventId, vals.name, vals.location, vals.salutation, vals.body, vals.dress_code, vals.signature, design, barred, req.user.id]
      );
      const [[cur]] = await pool.query('SELECT published_at FROM elysium_invitations WHERE event_id = ?', [eventId]);
      await recordVersion(eventId, cur?.published_at ? 'edit' : 'save', req.user.id, signingOffice(req.court, 'keeper'));
      log.adm('Elysium invitation saved', { event_id: eventId, by: req.user.id });
      reply.send({ ok: true, invitation: await loadInvitation(eventId) });
    } catch (e) {
      log.err('Keeper invitation save failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to save the invitation' });
    }
  });

  // publish: true/false. reannounce: true clears who has read it, so it pops up again for everyone.
  fastify.post('/api/court-actions/elysium/:eventId/publish', { preHandler: [authRequired, requireCapability('keeper')] }, async (req, reply) => {
    const eventId = await resolveEventId(req);
    if (!eventId) return reply.status(409).send({ error: 'Only the coming Elysium can be published.' });
    const inv = await loadInvitation(eventId);
    if (!inv) return reply.status(400).send({ error: 'Save the invitation first.' });
    const { publish, reannounce } = req.body || {};
    if (publish === false) {
      await pool.query('UPDATE elysium_invitations SET published_at = NULL WHERE event_id = ?', [eventId]);
    } else {
      await pool.query('UPDATE elysium_invitations SET published_at = COALESCE(published_at, NOW()) WHERE event_id = ?', [eventId]);
    }
    const wasPublished = !!inv.published_at;
    const action = publish === false ? 'withdraw' : reannounce ? 'reannounce' : wasPublished ? 'edit' : 'publish';
    if (publish === false || reannounce || !wasPublished) await recordVersion(eventId, action, req.user.id, signingOffice(req.court, 'keeper'));
    log.adm('Elysium invitation publish state', { event_id: eventId, publish: publish !== false, reannounce: !!reannounce, by: req.user.id });
    reply.send({ ok: true, invitation: await loadInvitation(eventId) });
  });

  /* ---------------- Storytellers: history and audit ---------------- */

  // Every Elysium, past and coming, with how far its invitation got.
  fastify.get('/api/admin/elysium/invitations', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const [rows] = await pool.query(
      `SELECT e.id, e.title, e.date, e.is_elysium, i.name, i.published_at, i.updated_at,
              (SELECT COUNT(*) FROM elysium_invitation_versions v WHERE v.event_id = e.id) AS version_count,
              (SELECT COUNT(*) FROM elysium_invitation_reads r WHERE r.event_id = e.id) AS reader_count
         FROM events e LEFT JOIN elysium_invitations i ON i.event_id = e.id
        WHERE e.is_elysium = 1 OR i.event_id IS NOT NULL
        ORDER BY e.date DESC`
    );
    reply.send({ invitations: rows.map(r => ({ ...r, version_count: Number(r.version_count), reader_count: Number(r.reader_count) })) });
  });

  // One invitation's full record: every version as it was stored, who made each,
  // who opened it (when, how often, which version and which card they saw), and who never did.
  fastify.get('/api/admin/elysium/invitations/:eventId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const eventId = parseInt(req.params.eventId, 10);
      const [[event]] = await pool.query('SELECT id, title, date, is_elysium FROM events WHERE id = ?', [eventId]);
      if (!event) return reply.status(404).send({ error: 'No such event' });

      const [versionRows] = await pool.query(
        `SELECT v.*, u.display_name AS actor_user, COALESCE(c.name, u.display_name) AS actor_name
           FROM elysium_invitation_versions v
           LEFT JOIN users u ON u.id = v.actor_id
           LEFT JOIN characters c ON c.id = (SELECT MIN(id) FROM characters WHERE user_id = v.actor_id)
          WHERE v.event_id = ? ORDER BY v.id ASC`,
        [eventId]
      );
      const versions = versionRows.map(v => ({ ...v, published: !!v.published, design: parseJson(v.design, {}), barred: parseJson(v.barred, []) }));

      const [readRows] = await pool.query(
        `SELECT r.user_id, r.read_at, r.last_read_at, r.open_count, r.seen_as, r.first_version_id AS stored_first, r.last_version_id AS stored_last, u.display_name AS user_name,
                c.id AS character_id, c.name AS character_name, c.clan
           FROM elysium_invitation_reads r
           JOIN users u ON u.id = r.user_id
           LEFT JOIN characters c ON c.id = (SELECT MIN(id) FROM characters WHERE user_id = r.user_id)
          WHERE r.event_id = ? ORDER BY r.read_at ASC`,
        [eventId]
      );
      // Reads logged before 0049 have no stored version: estimate it as the last
      // published snapshot taken by then.
      const shownAt = (t) => {
        let hit = null;
        for (const v of versions) if (v.published && new Date(v.created_at) <= new Date(t)) hit = v.id;
        return hit;
      };
      const reads = readRows.map(({ stored_first, stored_last, ...r }) => ({
        ...r,
        first_version_id: stored_first ?? shownAt(r.read_at),
        last_version_id: stored_last ?? shownAt(r.last_read_at || r.read_at),
      }));

      const readers = new Set(readRows.map(r => r.user_id));
      const [unread] = await pool.query(
        `SELECT c.id AS character_id, c.name AS character_name, c.clan, c.user_id, u.display_name AS user_name
           FROM characters c JOIN users u ON u.id = c.user_id
          WHERE COALESCE(c.is_deceased,0)=0 AND COALESCE(c.is_left,0)=0 AND COALESCE(c.is_hidden,0)=0
          ORDER BY c.name ASC`
      );
      reply.send({
        event,
        invitation: await loadInvitation(eventId),
        versions,
        reads,
        unread: unread.filter(c => !readers.has(c.user_id)),
        last_reannounce: (await lastReannounce(eventId))?.created_at || null,
      });
    } catch (e) {
      log.err('Admin elysium history failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load the invitation history' });
    }
  });
};

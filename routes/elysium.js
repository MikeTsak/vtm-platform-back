// routes/elysium.js
//
// The Keeper of Elysium's invitation. Each Elysium is a chronicle event
// (events.is_elysium) whose date is owned by the admin Calendar; the Keeper
// names it and writes/designs the invitation. The cycle turns on the day of
// the gathering: from that morning (Athens time) the next Elysium is current.

const { requireCapability } = require('../services/courtOffices');

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
  for (const k of DESIGN_IMAGES) {
    const v = input[k];
    if (typeof v === 'string' && v.length <= 500 && /^https:\/\/[^\s"'()<>\\]+$/.test(v)) out[k] = v;
  }
  return out;
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired } = opts;

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

  /* ---------------- Player side ---------------- */

  fastify.get('/api/elysium/current', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      reply.header('Cache-Control', 'no-store');
      const event = await currentElysium();
      if (!event) return reply.send({ event: null });

      const inv = await loadInvitation(event.id);
      const [[character]] = await pool.query(
        'SELECT id, name, clan, is_bloodhunted FROM characters WHERE user_id = ? ORDER BY id ASC LIMIT 1',
        [req.user.id]
      );
      const published = !!inv?.published_at;
      const barred = !!character && (!!character.is_bloodhunted || (inv?.barred || []).includes(character.id));
      const [[read]] = await pool.query('SELECT read_at FROM elysium_invitation_reads WHERE event_id=? AND user_id=?', [event.id, req.user.id]);

      reply.send({
        event: { id: event.id, date: event.date, name: inv?.name || null },
        status: !published ? 'pending' : barred ? 'barred' : 'invited',
        read: !!read,
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

  fastify.post('/api/elysium/:eventId/read', { preHandler: [authRequired] }, async (req, reply) => {
    await pool.query(
      'INSERT IGNORE INTO elysium_invitation_reads (event_id, user_id) VALUES (?, ?)',
      [req.params.eventId, req.user.id]
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
      if (reannounce) await pool.query('DELETE FROM elysium_invitation_reads WHERE event_id = ?', [eventId]);
    }
    log.adm('Elysium invitation publish state', { event_id: eventId, publish: publish !== false, reannounce: !!reannounce, by: req.user.id });
    reply.send({ ok: true, invitation: await loadInvitation(eventId) });
  });
};

// routes/courtActions.js
//
// Court Actions: the per-office powers of court users. Blood Hunts (Prince
// calls or ratifies, Seneschal/Sheriff/Scourge propose), the Sheriff's Wanted
// board, the dangerous-domains ranking and Princely decree pushes. The Keeper's
// Elysium invitation lives in routes/elysium.js. Office rules: services/courtOffices.js.

const { getCourtContext, requireCapability, signingOffice } = require('../services/courtOffices');
const { expireBloodHunts, setBloodhuntFlag, pushEveryone, pushOfficeHolders } = require('../services/bloodHunts');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  const HUNT_SELECT = `
    SELECT h.*,
           COALESCE(cp.name, up.display_name) AS proposed_by_name,
           COALESCE(cr.name, ur.display_name) AS ratified_by_name
      FROM blood_hunts h
      LEFT JOIN users up ON up.id = h.proposed_by
      LEFT JOIN characters cp ON cp.id = (SELECT MIN(id) FROM characters WHERE user_id = h.proposed_by)
      LEFT JOIN users ur ON ur.id = h.ratified_by
      LEFT JOIN characters cr ON cr.id = (SELECT MIN(id) FROM characters WHERE user_id = h.ratified_by)`;

  const parseExpiry = (v) => {
    if (v === undefined) return undefined;
    if (v === null || v === '') return null;
    const d = new Date(v);
    return isNaN(d.getTime()) ? false : d;
  };

  async function activate(hunt, ratifierId) {
    await pool.query(
      "UPDATE blood_hunts SET status='active', ratified_by=?, ratified_at=NOW() WHERE id=?",
      [ratifierId, hunt.id]
    );
    await setBloodhuntFlag(hunt.target_type, hunt.target_id);
    pushEveryone('A Blood Hunt has been called', `The Prince declares ${hunt.target_name} forfeit. Their blood is yours to take.`, '/court/hierarchy');
    log.adm('Blood Hunt activated', { id: hunt.id, target: hunt.target_name, by: ratifierId });
  }

  // GET /api/court-actions/me: who am I in the court, and what may I do.
  fastify.get('/api/court-actions/me', { preHandler: [authRequired] }, async (req, reply) => {
    const ctx = await getCourtContext(req.user);
    reply.send(ctx);
  });

  /* ---------------- Blood Hunts ---------------- */

  // Everyone sees active hunts (the public proclamation); the court also sees
  // pending proposals and the recent history.
  fastify.get('/api/court-actions/blood-hunts', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      await expireBloodHunts();
      const ctx = await getCourtContext(req.user);
      const where = ctx.isCourt
        ? "WHERE h.status IN ('proposed','active') OR h.closed_at > NOW() - INTERVAL 90 DAY OR h.created_at > NOW() - INTERVAL 90 DAY"
        : "WHERE h.status = 'active'";
      const [hunts] = await pool.query(`${HUNT_SELECT} ${where} ORDER BY FIELD(h.status,'proposed','active') DESC, h.created_at DESC`);
      reply.send({ hunts });
    } catch (e) {
      log.err('Blood hunts fetch failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load Blood Hunts' });
    }
  });

  fastify.post('/api/court-actions/blood-hunts', { preHandler: [authRequired] }, async (req, reply) => {
    const ctx = await getCourtContext(req.user);
    if (!ctx.can.callBloodHunt && !ctx.can.proposeBloodHunt) {
      return reply.status(403).send({ error: 'Your office does not grant this power.' });
    }
    const { target_type, target_id, reason } = req.body || {};
    const expires = parseExpiry(req.body?.expires_at);
    const id = parseInt(target_id, 10);
    if (!['player', 'npc'].includes(target_type) || !id) return reply.status(400).send({ error: 'Choose who is to be hunted.' });
    if (!reason || !String(reason).trim()) return reply.status(400).send({ error: 'A Blood Hunt must state its cause.' });
    if (expires === false) return reply.status(400).send({ error: 'Invalid expiry date' });

    try {
      const table = target_type === 'player' ? 'characters' : 'npcs';
      const [[target]] = await pool.query(`SELECT id, name FROM ${table} WHERE id = ?`, [id]);
      if (!target) return reply.status(404).send({ error: 'No such Kindred' });
      const [[dupe]] = await pool.query(
        "SELECT id FROM blood_hunts WHERE target_type=? AND target_id=? AND status IN ('proposed','active') LIMIT 1",
        [target_type, id]
      );
      if (dupe) return reply.status(409).send({ error: `${target.name} is already hunted, or a hunt is awaiting the Prince.` });

      const office = signingOffice(ctx, ctx.can.callBloodHunt ? 'callBloodHunt' : 'proposeBloodHunt');
      const [r] = await pool.query(
        `INSERT INTO blood_hunts (target_type, target_id, target_name, reason, status, proposed_by, proposed_office, expires_at)
         VALUES (?, ?, ?, ?, 'proposed', ?, ?, ?)`,
        [target_type, id, target.name, String(reason).trim().slice(0, 4000), req.user.id, office, expires || null]
      );
      const hunt = { id: r.insertId, target_type, target_id: id, target_name: target.name };
      if (ctx.can.callBloodHunt) {
        await activate(hunt, req.user.id);
      } else {
        pushOfficeHolders(['Prince'], 'A Blood Hunt awaits your word', `The ${office} asks for the blood of ${target.name}.`, '/court/actions');
        log.adm('Blood Hunt proposed', { id: r.insertId, target: target.name, by: req.user.id, office });
      }
      const [[row]] = await pool.query(`${HUNT_SELECT} WHERE h.id = ?`, [r.insertId]);
      reply.status(201).send({ hunt: row });
    } catch (e) {
      log.err('Blood hunt create failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to call the Blood Hunt' });
    }
  });

  fastify.post('/api/court-actions/blood-hunts/:id/ratify', { preHandler: [authRequired, requireCapability('callBloodHunt')] }, async (req, reply) => {
    const [[hunt]] = await pool.query("SELECT * FROM blood_hunts WHERE id=? AND status='proposed'", [req.params.id]);
    if (!hunt) return reply.status(404).send({ error: 'No pending proposal' });
    await activate(hunt, req.user.id);
    reply.send({ ok: true });
  });

  fastify.post('/api/court-actions/blood-hunts/:id/reject', { preHandler: [authRequired, requireCapability('callBloodHunt')] }, async (req, reply) => {
    const [r] = await pool.query(
      "UPDATE blood_hunts SET status='rejected', closed_by=?, closed_at=NOW() WHERE id=? AND status='proposed'",
      [req.user.id, req.params.id]
    );
    if (!r.affectedRows) return reply.status(404).send({ error: 'No pending proposal' });
    reply.send({ ok: true });
  });

  // Any blood-hunt office may lift (or withdraw) a hunt.
  fastify.post('/api/court-actions/blood-hunts/:id/lift', { preHandler: [authRequired] }, async (req, reply) => {
    const ctx = await getCourtContext(req.user);
    if (!ctx.can.callBloodHunt && !ctx.can.proposeBloodHunt) return reply.status(403).send({ error: 'Your office does not grant this power.' });
    const [[hunt]] = await pool.query("SELECT * FROM blood_hunts WHERE id=? AND status IN ('proposed','active')", [req.params.id]);
    if (!hunt) return reply.status(404).send({ error: 'No open hunt' });
    await pool.query("UPDATE blood_hunts SET status='lifted', closed_by=?, closed_at=NOW() WHERE id=?", [req.user.id, hunt.id]);
    if (hunt.status === 'active') {
      await setBloodhuntFlag(hunt.target_type, hunt.target_id);
      pushEveryone('The Blood Hunt is lifted', `${hunt.target_name} is no longer forfeit. Stay your hand.`, '/court/hierarchy');
    }
    log.adm('Blood Hunt lifted', { id: hunt.id, by: req.user.id });
    reply.send({ ok: true });
  });

  // Expiry: the Prince, or the Storytellers from the Calendar.
  fastify.patch('/api/court-actions/blood-hunts/:id', { preHandler: [authRequired] }, async (req, reply) => {
    const ctx = await getCourtContext(req.user);
    if (!ctx.can.callBloodHunt) return reply.status(403).send({ error: 'Your office does not grant this power.' });
    const expires = parseExpiry(req.body?.expires_at);
    if (expires === undefined || expires === false) return reply.status(400).send({ error: 'Invalid expiry date' });
    const [r] = await pool.query(
      "UPDATE blood_hunts SET expires_at=? WHERE id=? AND status IN ('proposed','active')",
      [expires, req.params.id]
    );
    if (!r.affectedRows) return reply.status(404).send({ error: 'No open hunt' });
    await expireBloodHunts();
    reply.send({ ok: true });
  });

  // Admin Calendar: every open hunt with an expiry, plus any open hunt at all.
  fastify.get('/api/admin/blood-hunts', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    await expireBloodHunts();
    const [hunts] = await pool.query(`${HUNT_SELECT} WHERE h.status IN ('proposed','active') ORDER BY h.created_at DESC`);
    reply.send({ hunts });
  });

  /* ---------------- Sheriff's Wanted board ---------------- */

  fastify.get('/api/court-actions/wanted', { preHandler: [authRequired] }, async (req, reply) => {
    const [wanted] = await pool.query(
      `SELECT w.*, COALESCE(c.name, u.display_name) AS posted_by_name
         FROM court_wanted w
         LEFT JOIN users u ON u.id = w.posted_by
         LEFT JOIN characters c ON c.id = (SELECT MIN(id) FROM characters WHERE user_id = w.posted_by)
        WHERE w.closed_at IS NULL
        ORDER BY w.created_at DESC`
    );
    reply.send({ wanted });
  });

  fastify.post('/api/court-actions/wanted', { preHandler: [authRequired, requireCapability('wanted')] }, async (req, reply) => {
    const { target_name, reason } = req.body || {};
    if (!target_name?.trim() || !reason?.trim()) return reply.status(400).send({ error: 'Name and cause are required' });
    await pool.query(
      'INSERT INTO court_wanted (target_name, reason, posted_by, posted_office) VALUES (?, ?, ?, ?)',
      [target_name.trim().slice(0, 255), reason.trim().slice(0, 4000), req.user.id, signingOffice(req.court, 'wanted')]
    );
    reply.status(201).send({ ok: true });
  });

  fastify.post('/api/court-actions/wanted/:id/close', { preHandler: [authRequired, requireCapability('wanted')] }, async (req, reply) => {
    await pool.query('UPDATE court_wanted SET closed_at=NOW(), closed_by=? WHERE id=? AND closed_at IS NULL', [req.user.id, req.params.id]);
    reply.send({ ok: true });
  });

  /* ---------------- Prince / Seneschal ---------------- */

  // The city's most dangerous divisions, worst first: lowest Masquerade safety
  // rating (domain_claims.safety_rating). Unassessed divisions (no rating) are left out: unknown is not dangerous.
  fastify.get('/api/court-actions/dangerous-domains', { preHandler: [authRequired, requireCapability('security')] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(
        `SELECT d.division, d.safety_rating, d.is_abaton, d.claimed_at,
                COALESCE(c.name, n.name, d.owner_name) AS owner_name, COALESCE(c.clan, n.clan) AS owner_clan,
                (d.owner_character_id IS NOT NULL OR d.owner_npc_id IS NOT NULL) AS is_claimed
           FROM domain_claims d
           LEFT JOIN characters c ON c.id = d.owner_character_id
           LEFT JOIN npcs n ON n.id = d.owner_npc_id
          WHERE d.safety_rating IS NOT NULL
          ORDER BY d.safety_rating ASC, d.division ASC`
      );
      reply.send({
        domains: rows.map(r => ({
          ...r,
          is_abaton: !!r.is_abaton,
          is_claimed: !!r.is_claimed,
          owner_name: r.is_claimed ? r.owner_name : null,
        })),
      });
    } catch (e) {
      log.err('Dangerous domains fetch failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load the domains' });
    }
  });

  // Push an already-published announcement to every player. Only its author
  // (a Prince/Seneschal) or an admin, so the push text is always a real decree.
  fastify.post('/api/court-actions/decrees/:newsId/push', { preHandler: [authRequired, requireCapability('decree')] }, async (req, reply) => {
    const [[entry]] = await pool.query("SELECT id, title, author_id FROM news_entries WHERE id=? AND type='announcement'", [req.params.newsId]);
    if (!entry) return reply.status(404).send({ error: 'Decree not found' });
    if (entry.author_id !== req.user.id && !req.court.isAdmin) return reply.status(403).send({ error: 'Not your decree' });
    pushEveryone(`Decree of the ${signingOffice(req.court, 'decree')}`, entry.title, '/court/announcements');
    reply.send({ ok: true });
  });
};

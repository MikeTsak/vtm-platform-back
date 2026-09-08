// routes/domains.js
//
// Domain records and their membership lists.

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  /* -------------------- Domains -------------------- */
  // List domains with members (for players)
  fastify.get('/api/domains', { preHandler: [authRequired] }, async (req, reply) => {
    const [doms] = await pool.query('SELECT * FROM domains ORDER BY name ASC');
    if (!doms.length) {
      log.dom('Domains list (empty)');
      return reply.send({ domains: [] });
    }

    const [rows] = await pool.query(
      `SELECT dm.domain_id, c.name AS char_name, c.clan
     FROM domain_members dm
     JOIN characters c ON c.id=dm.character_id`
    );

    const byDomain = rows.reduce((acc, r) => {
      (acc[r.domain_id] ||= []).push({ name: r.char_name, clan: r.clan });
      return acc;
    }, {});

    const out = doms.map(d => ({ ...d, members: byDomain[d.id] || [] }));
    log.dom('Domains list', { count: out.length });
    reply.send({ domains: out });
  });

  // Admin: manage domains
  fastify.post('/api/admin/domains', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  const { name, description } = req.body;
    if (!name) return reply.status(400).json({ error: 'name required' });
    const [r] = await pool.query('INSERT INTO domains (name, description) VALUES (?,?)', [name, description || null]);
    const [rows] = await pool.query('SELECT * FROM domains WHERE id=?', [r.insertId]);
    log.adm('Domain created', { id: r.insertId, name });
    reply.send({ domain: rows[0] });
  });

  fastify.delete('/api/admin/domains/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    await pool.query('DELETE FROM domains WHERE id=?', [req.params.id]);
    log.adm('Domain deleted', { id: req.params.id });
    reply.send({ ok: true });
  });

  fastify.post('/api/admin/domains/:id/members', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  const { character_id } = req.body;
    if (!character_id) return reply.status(400).json({ error: 'character_id required' });
    await pool.query('INSERT IGNORE INTO domain_members (domain_id, character_id) VALUES (?,?)', [req.params.id, character_id]);
    log.adm('Domain member added', { domain_id: req.params.id, character_id });
    reply.send({ ok: true });
  });

  fastify.delete('/api/admin/domains/:id/members/:character_id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    await pool.query('DELETE FROM domain_members WHERE domain_id=? AND character_id=?', [req.params.id, req.params.character_id]);
    log.adm('Domain member removed', { domain_id: req.params.id, character_id: req.params.character_id });
    reply.send({ ok: true });
  });
};

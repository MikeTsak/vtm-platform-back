// routes/camarilla.js
//
// The Camarilla hierarchy roster — public view and the Storyteller editor.

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  /* --- Camarilla Hierarchy API --- */

  // 1. Fetch combined roster (Admin)
  fastify.get('/api/admin/camarilla/roster', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [players] = await pool.query(
        `SELECT c.id, c.user_id, c.name, c.clan, c.camarilla_titles as titles, c.status, c.image_url, 
              c.is_ex, c.is_deceased, c.is_hidden, c.is_left, c.is_called, c.is_missing, c.is_exiled, c.is_bloodhunted, 
              'player' as type,
              (u.avatar_url IS NOT NULL OR u.avatar_url_thumb IS NOT NULL) as has_avatar
       FROM characters c
       LEFT JOIN users u ON c.user_id = u.id`
      );
      const [npcs] = await pool.query(
        `SELECT n.id, NULL as user_id, n.name, n.clan, n.camarilla_titles as titles, n.status, n.image_url, 
              n.is_ex, n.is_deceased, n.is_hidden, n.is_left, n.is_called, n.is_missing, n.is_exiled, n.is_bloodhunted, 
              'npc' as type,
              (n.avatar_url IS NOT NULL OR n.avatar_url_thumb IS NOT NULL) as has_avatar
       FROM npcs n`
      );

      const format = (list) => list.map(item => ({
        ...item,
        titles: typeof item.titles === 'string' ? JSON.parse(item.titles) : (item.titles || []),
        is_ex: !!item.is_ex,
        is_deceased: !!item.is_deceased,
        is_hidden: !!item.is_hidden,
        has_avatar: Boolean(item.has_avatar)
      }));

      const combined = [...format(players), ...format(npcs)];
      combined.sort((a, b) => (b.status || 0) - (a.status || 0));

      reply.send({ roster: combined });
    } catch (e) {
      log.err('Admin roster fetch failed', { message: e.message });
      reply.status(500).json({ error: e.message });
    }
  });

  // GET: Publicly accessible roster
  fastify.get('/api/camarilla/roster', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [players] = await pool.query(
        `SELECT c.id, c.user_id, c.name, c.clan, c.camarilla_titles as titles, c.status, c.image_url, 
              c.is_ex, c.is_deceased, c.is_hidden, c.is_left, c.is_called, c.is_missing, c.is_exiled, c.is_bloodhunted, 
              'player' as type,
              (u.avatar_url IS NOT NULL OR u.avatar_url_thumb IS NOT NULL) as has_avatar
       FROM characters c
       LEFT JOIN users u ON c.user_id = u.id`
      );
      const [npcs] = await pool.query(
        `SELECT n.id, NULL as user_id, n.name, n.clan, n.camarilla_titles as titles, n.status, n.image_url, 
              n.is_ex, n.is_deceased, n.is_hidden, n.is_left, n.is_called, n.is_missing, n.is_exiled, n.is_bloodhunted, 
              'npc' as type,
              (n.avatar_url IS NOT NULL OR n.avatar_url_thumb IS NOT NULL) as has_avatar
       FROM npcs n`
      );

      const format = (list) => list.map(item => ({
        ...item,
        titles: typeof item.titles === 'string' ? JSON.parse(item.titles) : (item.titles || []),
        is_ex: !!item.is_ex,
        is_deceased: !!item.is_deceased,
        is_hidden: !!item.is_hidden,
        is_left: !!item.is_left,
        is_called: !!item.is_called,
        is_missing: !!item.is_missing,
        is_exiled: !!item.is_exiled,
        is_bloodhunted: !!item.is_bloodhunted,
        has_avatar: Boolean(item.has_avatar)
      }));

      const combined = [...format(players), ...format(npcs)];
      combined.sort((a, b) => (b.status || 0) - (a.status || 0));

      reply.send({ roster: combined });
    } catch (e) {
      log.err('Public roster fetch failed', { message: e.message });
      reply.status(500).json({ error: "Failed to load the Court hierarchy." });
    }
  });

  // GET: Publicly accessible roster
  // DUP: fastify.get('/api/camarilla/roster', { preHandler: [authRequired] }, async (req, reply) => {
  // DUP:   try {
  // DUP:     const [players] = await pool.query(
  // DUP:       "SELECT id, name, clan, camarilla_titles as titles, status, image_url, is_ex, is_deceased, 'player' as type FROM characters"
  // DUP:     );
  // DUP:     const [npcs] = await pool.query(
  // DUP:       "SELECT id, name, clan, camarilla_titles as titles, status, image_url, is_ex, is_deceased, 'npc' as type FROM npcs"
  // DUP:     );
  // DUP: 
  // DUP:     const format = (list) => list.map(item => ({
  // DUP:       ...item,
  // DUP:       titles: typeof item.titles === 'string' ? JSON.parse(item.titles) : (item.titles || []),
  // DUP:       is_ex: !!item.is_ex,
  // DUP:       is_deceased: !!item.is_deceased
  // DUP:     }));
  // DUP: 
  // DUP:     const combined = [...format(players), ...format(npcs)];
  // DUP:     combined.sort((a, b) => (b.status || 0) - (a.status || 0));
  // DUP: 
  // DUP:     reply.send({ roster: combined });
  // DUP:   } catch (e) {
  // DUP:     log.err('Public roster fetch failed', { message: e.message });
  // DUP:     reply.status(500).json({ error: "Failed to load the Court hierarchy." });
  // DUP:   }
  // DUP: });

  /* --- Public Camarilla Hierarchy API --- */

  // GET: Publicly accessible roster for all logged-in users
  // DUP: fastify.get('/api/camarilla/roster', { preHandler: [authRequired] }, async (req, reply) => {
  // DUP:   try {
  // DUP:     // Selects basic info from players and NPCs, including image_url
  // DUP:     const [players] = await pool.query(
  // DUP:       "SELECT id, name, clan, camarilla_titles as titles, status, image_url, 'player' as type FROM characters"
  // DUP:     );
  // DUP:     const [npcs] = await pool.query(
  // DUP:       "SELECT id, name, clan, camarilla_titles as titles, status, image_url, 'npc' as type FROM npcs"
  // DUP:     );
  // DUP: 
  // DUP:     // Format helper to handle JSON strings for titles
  // DUP:     const format = (list) => list.map(item => ({
  // DUP:       ...item,
  // DUP:       titles: typeof item.titles === 'string' ? JSON.parse(item.titles) : (item.titles || [])
  // DUP:     }));
  // DUP: 
  // DUP:     const combined = [...format(players), ...format(npcs)];
  // DUP: 
  // DUP:     // Sort NUMERICALLY by status (highest number first, nulls become 0)
  // DUP:     combined.sort((a, b) => (b.status || 0) - (a.status || 0));
  // DUP: 
  // DUP:     reply.send({ roster: combined });
  // DUP:   } catch (e) {
  // DUP:     log.err('Public roster fetch failed', { message: e.message });
  // DUP:     reply.status(500).json({ error: "Failed to load the Court hierarchy." });
  // DUP:   }
  // DUP: });

  // 2. Update status, titles, image_url, or modifiers
  fastify.patch('/api/admin/camarilla/update', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  const { id, type, field, value } = req.body;
    const table = type === 'player' ? 'characters' : 'npcs';

    let dbField, dbValue;

    if (field === 'titles') {
      dbField = 'camarilla_titles';
      dbValue = JSON.stringify(value);
    } else if (field === 'image_url') {
      dbField = 'image_url';
      dbValue = value;
      // Use a quick array check for all boolean flags
    } else if (['is_ex', 'is_deceased', 'is_hidden', 'is_bloodhunted', 'is_left', 'is_called', 'is_missing', 'is_exiled'].includes(field)) {
      dbField = field;
      dbValue = value ? 1 : 0;
    } else {
      // If it's not any of the above, it's the status slider
      dbField = 'status';
      dbValue = value;
    }

    try {
      await pool.query(`UPDATE ${table} SET ${dbField} = ? WHERE id = ?`, [dbValue, id]);
      log.adm(`Updated Camarilla ${field}`, { type, id, value });
      reply.send({ ok: true });
    } catch (e) {
      log.err('Camarilla update failed', { message: e.message });
      reply.status(500).json({ error: "Database update failed" });
    }
  });
};

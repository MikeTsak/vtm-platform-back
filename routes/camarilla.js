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
      combined.sort((a, b) => {
        const statusDiff = (b.status || 0) - (a.status || 0);
        if (statusDiff !== 0) return statusDiff;
        const clanDiff = (a.clan || '').localeCompare(b.clan || '');
        if (clanDiff !== 0) return clanDiff;
        return (a.name || '').localeCompare(b.name || '');
      });

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
      combined.sort((a, b) => {
        const statusDiff = (b.status || 0) - (a.status || 0);
        if (statusDiff !== 0) return statusDiff;
        const clanDiff = (a.clan || '').localeCompare(b.clan || '');
        if (clanDiff !== 0) return clanDiff;
        return (a.name || '').localeCompare(b.name || '');
      });

      const isHarpy = await isHarpyOrAdmin(req.user);

      reply.send({ roster: combined, is_harpy: isHarpy, can_manage_status: isHarpy });
    } catch (e) {
      log.err('Public roster fetch failed', { message: e.message });
      reply.status(500).json({ error: "Failed to load the Court hierarchy." });
    }
  });

  async function isHarpyOrAdmin(user) {
    if (!user) return false;
    if (user.role === 'admin' || user.role === 'courtuser') return true;
    try {
      const [chars] = await pool.query('SELECT camarilla_titles FROM characters WHERE user_id = ?', [user.id]);
      if (!chars.length) return false;
      const raw = chars[0].camarilla_titles;
      let titles = [];
      if (Array.isArray(raw)) {
        titles = raw;
      } else if (typeof raw === 'string' && raw.trim()) {
        try {
          const parsed = JSON.parse(raw);
          if (Array.isArray(parsed)) titles = parsed;
          else if (typeof parsed === 'string') titles = [parsed];
        } catch {
          titles = raw.split(',').map(s => s.trim()).filter(Boolean);
        }
      }
      return titles.some(t => typeof t === 'string' && t.toLowerCase().includes('harpy'));
    } catch {
      return false;
    }
  }

  // 2. Update status, titles, image_url, or modifiers
  fastify.patch('/api/admin/camarilla/update', { preHandler: [authRequired] }, async (req, reply) => {
    const { id, type, field, value } = req.body || {};
    const isAdminUser = req.user && req.user.role === 'admin';
    const isHarpy = await isHarpyOrAdmin(req.user);

    if (!isAdminUser && !(isHarpy && field === 'status')) {
      return reply.status(403).json({ error: 'Insufficient clearance' });
    }

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
      dbValue = Math.max(0, Math.min(5, parseInt(value, 10) || 0));
    }

    try {
      await pool.query(`UPDATE ${table} SET ${dbField} = ? WHERE id = ?`, [dbValue, id]);
      log.adm(`Updated Camarilla ${field}`, { type, id, value: dbValue, by_user: req.user.id });
      reply.send({ ok: true });
    } catch (e) {
      log.err('Camarilla update failed', { message: e.message });
      reply.status(500).json({ error: "Database update failed" });
    }
  });

  // 3. Dedicated Harpy Status Updater Endpoint
  fastify.patch('/api/camarilla/status', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const allowed = await isHarpyOrAdmin(req.user);
      if (!allowed) {
        log.warn('Status update denied: user is not a Harpy', { user_id: req.user?.id, role: req.user?.role });
        return reply.status(403).json({ error: 'Harpy clearance required' });
      }

      const { id, type, status, delta, value } = req.body || {};
      const numId = parseInt(id, 10);
      if (!numId || (type !== 'player' && type !== 'npc')) {
        return reply.status(400).json({ error: 'Invalid kindred identifier or type' });
      }

      const table = type === 'player' ? 'characters' : 'npcs';

      let targetStatus;
      if (status !== undefined || value !== undefined) {
        const raw = status !== undefined ? status : value;
        targetStatus = parseInt(raw, 10);
        if (Number.isNaN(targetStatus)) {
          return reply.status(400).json({ error: 'Status must be a number' });
        }
      } else if (delta !== undefined) {
        const numDelta = parseInt(delta, 10);
        if (Number.isNaN(numDelta)) {
          return reply.status(400).json({ error: 'Delta must be a number' });
        }
        const [rows] = await pool.query(`SELECT status FROM ${table} WHERE id = ?`, [numId]);
        if (!rows.length) {
          return reply.status(404).json({ error: 'Kindred record not found' });
        }
        const current = rows[0].status ?? 1;
        targetStatus = current + numDelta;
      } else {
        return reply.status(400).json({ error: 'Status or delta required' });
      }

      // Clamp status between 0 and 5
      const clampedStatus = Math.max(0, Math.min(5, targetStatus));

      await pool.query(`UPDATE ${table} SET status = ? WHERE id = ?`, [clampedStatus, numId]);
      log.adm('Camarilla status updated by Harpy', { user_id: req.user.id, target_id: numId, type, status: clampedStatus });

      reply.send({ ok: true, id: numId, type, status: clampedStatus });
    } catch (e) {
      log.err('Status update failed', { message: e.message });
      reply.status(500).json({ error: 'Database update failed' });
    }
  });
};

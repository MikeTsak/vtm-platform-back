// routes/downtimes.js
//
// Downtime actions: player submission and quota, Storyteller resolution, and
// the chronicle-wide downtime configuration.
const { getSetting, setSetting } = require('../utils/settings');
const { startOfMonth, endOfMonth, feedingFromPredator } = require('../services/format');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, broadcastNtfyAlert } = opts;

  /* -------------------- Downtimes -------------------- */
  // My quota this cycle
  fastify.get('/api/downtimes/quota', { preHandler: [authRequired] }, async (req, reply) => {
    const [chars] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
    const ch = chars[0];
    if (!ch) {
      log.dt('Quota check (no character)', { user_id: req.user.id });
      return reply.send({ used: 0, limit: 3 });
    }

    let from = startOfMonth();
    let to = endOfMonth();

    // FIX: Tie the quota to the current cycle (Opening Date) instead of a strict calendar month
    try {
      const openingStr = await getSetting('downtime_opening', null);
      if (openingStr) {
        const parsed = new Date(openingStr);
        if (!isNaN(parsed.getTime())) {
          from = parsed;
          // Give the cycle a generous safe upper bound (e.g., 90 days) until the next opening overrides it
          to = new Date(parsed.getTime() + 90 * 24 * 60 * 60 * 1000);
        }
      }
    } catch (e) { }

    const [rows] = await pool.query(
      'SELECT COUNT(*) AS c FROM downtimes WHERE character_id=? AND created_at >= ? AND created_at < ?',
      [ch.id, from, to]
    );
    log.dt('Quota check', { user_id: req.user.id, used: rows[0].c, limit: 3 });
    reply.send({ used: rows[0].c, limit: 3 });
  });

  // PUT /api/downtimes/:id — Edit a project/downtime submission
  fastify.put('/api/downtimes/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { id } = req.params;
      const { title, body } = req.body;

      // 1. Verify ownership by joining downtimes with characters
      const [rows] = await pool.query(`
      SELECT dt.*, c.user_id 
      FROM downtimes dt 
      JOIN characters c ON dt.character_id = c.id
      WHERE dt.id = ? AND c.user_id = ?
    `, [id, req.user.id]);

      if (rows.length === 0) {
        return reply.status(404).json({ error: 'Submission not found or unauthorized' });
      }

      const submission = rows[0];

      // 2. Only allow edits if status is 'submitted' or 'needs a scene'
      if (submission.status !== 'submitted' && submission.status !== 'needs a scene') {
        return reply.status(400).json({ error: 'You can only edit actions that are not yet approved or resolved.' });
      }

      // 3. Check against the CORRECT global deadline setting
      // Determine if the action being edited is a project based on its current title
      const isProject = submission.title && submission.title.startsWith('[PROJECT]');
      const deadlineKey = isProject ? 'project_deadline' : 'downtime_deadline';

      const deadlineStr = await getSetting(deadlineKey, null);

      // Check if the specific deadline for this type of action has passed
      if (deadlineStr && new Date(deadlineStr) < new Date()) {
        return reply.status(400).json({
          error: `The deadline for ${isProject ? 'project' : 'action'} submissions has passed.`
        });
      }

      // 4. Perform update
      await pool.query(
        'UPDATE downtimes SET title = ?, body = ? WHERE id = ?',
        [title || submission.title, body || submission.body, id]
      );

      reply.send({ success: true, message: 'Action updated successfully' });
    } catch (e) {
      console.error('Failed to update downtime/project:', e);
      reply.status(500).json({ error: 'Internal server error while updating submission' });
    }
  });

  // PATCH /api/downtimes/read-batch - Mark multiple downtimes as read
  fastify.patch('/api/downtimes/read-batch', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { ids } = req.body || {};
      if (!Array.isArray(ids) || ids.length === 0) return reply.send({ success: true });

      // Verify ownership and get data
      const [rows] = await pool.query(
        `SELECT dt.*, c.name as char_name 
       FROM downtimes dt 
       JOIN characters c ON dt.character_id = c.id 
       WHERE dt.id IN (?) AND c.user_id = ? AND dt.is_read = 0`,
        [ids, req.user.id]
      );

      if (rows.length === 0) {
        return reply.send({ success: true });
      }

      const validIds = rows.map(r => r.id);
      await pool.query('UPDATE downtimes SET is_read = 1 WHERE id IN (?)', [validIds]);

      const charName = rows[0].char_name;
      const titles = rows.map(dt => dt.title.replace('[PROJECT] ', ''));

      let msg = `**${charName}** has read their downtime resolution for:\n\n`;
      titles.forEach(t => {
        msg += `> *${t}*\n`;
      });

      broadcastNtfyAlert(msg, {
        title: 'Downtime Read',
        tags: 'eyes,vampire',
        priority: 'default',
        requiresSubscription: 'downtimes'
      }).catch(() => { });

      reply.send({ success: true, updated: validIds.length });
    } catch (e) {
      req.log.error(e);
      reply.status(500).send({ error: 'Failed to mark as read' });
    }
  });

  // List my downtimes
  fastify.get('/api/downtimes/mine', { preHandler: [authRequired] }, async (req, reply) => {
    const [[char]] = await Promise.all([
      pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]),
    ]);
    if (!char?.[0]) {
      log.dt('List mine (no character)', { user_id: req.user.id });
      return reply.send({ downtimes: [] });
    }

    const [rows] = await pool.query(
      'SELECT * FROM downtimes WHERE character_id=? ORDER BY created_at DESC',
      [char[0].id]
    );

    const massReleaseMode = await getSetting('downtime_mass_release_mode', 'false');
    const massReleaseDate = await getSetting('downtime_mass_release_date', null);

    let hideResolutions = false;
    if (massReleaseMode === 'true' && massReleaseDate) {
      const releaseTime = new Date(massReleaseDate).getTime();
      if (!isNaN(releaseTime) && Date.now() < releaseTime) {
        hideResolutions = true;
      }
    }

    if (hideResolutions) {
      rows.forEach(r => {
        r.gm_resolution = null;
        r.gm_notes = null;
      });
    }

    log.dt('List mine', { user_id: req.user.id, count: rows.length });
    reply.send({ downtimes: rows });
  });

  // Create downtime (3 per cycle; auto feeding type)
  fastify.post('/api/downtimes', { preHandler: [authRequired] }, async (req, reply) => {
  const { title, body, feeding_type } = req.body;
    if (!title || !body) {
      log.warn('Downtime create missing fields', { user_id: req.user.id });
      return reply.status(400).json({ error: 'Title and body required' });
    }

    const isProjectSubmission = title.startsWith('[PROJECT]');
    const activePhase = await getSetting('downtime_active_phase', 'standard');

    if (activePhase === 'project' && !isProjectSubmission) {
      return reply.status(400).json({ error: 'Monthly Action submissions are currently closed. Only Long-Term Projects are being accepted.' });
    } else if (activePhase === 'standard' && isProjectSubmission) {
      return reply.status(400).json({ error: 'Long-Term Project submissions are currently closed. Only Monthly Actions are being accepted.' });
    }

    const [chars] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
    const ch = chars[0];
    if (!ch) {
      log.warn('Downtime create without character', { user_id: req.user.id });
      return reply.status(400).json({ error: 'Create a character first' });
    }

    let from = startOfMonth();
    let to = endOfMonth();

    // FIX: Tie the limit check to the current cycle
    try {
      const openingStr = await getSetting('downtime_opening', null);
      if (openingStr) {
        const parsed = new Date(openingStr);
        if (!isNaN(parsed.getTime())) {
          from = parsed;
          to = new Date(parsed.getTime() + 90 * 24 * 60 * 60 * 1000);
        }
      }
    } catch (e) { }

    const [cnt] = await pool.query(
      'SELECT COUNT(*) AS c FROM downtimes WHERE character_id=? AND created_at >= ? AND created_at < ?',
      [ch.id, from, to]
    );
    if (cnt[0].c >= 3) {
      log.warn('Downtime limit reached', { user_id: req.user.id, count: cnt[0].c });
      return reply.status(400).json({ error: 'Downtime limit reached for this cycle (3).' });
    }

    let defaultFeed = feeding_type;
    if (!defaultFeed) {
      let pred = null;
      if (ch.sheet) {
        try {
          const parsed = typeof ch.sheet === 'string' ? JSON.parse(ch.sheet) : ch.sheet;
          pred = parsed?.predatorType || null;
        } catch { }
      }
      defaultFeed = feedingFromPredator(pred);
    }

    const [r] = await pool.query(
      'INSERT INTO downtimes (character_id, title, feeding_type, body) VALUES (?,?,?,?)',
      [ch.id, title, defaultFeed || null, body]
    );
    const [rows] = await pool.query('SELECT * FROM downtimes WHERE id=?', [r.insertId]);
    log.dt('Downtime created', { user_id: req.user.id, downtime_id: r.insertId, feeding_type: defaultFeed || feeding_type || null });
    broadcastNtfyAlert(`**${ch.name} (${ch.id})** submitted a new downtime action:\n\n> *${title}*`, { title: 'Downtime Submitted', tags: 'hourglass_flowing_sand', priority: 'default' });
    reply.send({ downtime: rows[0] });
  });

  fastify.get('/api/admin/downtimes', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const [rows] = await pool.query(
      `SELECT d.*, c.name AS char_name, c.clan, u.display_name AS player_name, u.email
     FROM downtimes d
     JOIN characters c ON c.id=d.character_id
     JOIN users u ON u.id=c.user_id
     ORDER BY d.created_at DESC`
    );
    log.adm('Admin downtimes list', { count: rows.length });
    reply.send({ downtimes: rows });
  });

  fastify.patch('/api/admin/downtimes/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  const { status, gm_notes, gm_resolution } = req.body;
    const allowed = ['submitted', 'approved', 'rejected', 'resolved', 'Needs a Scene', 'Resolved in scene'];
    if (status && !allowed.includes(status)) return reply.status(400).json({ error: 'Bad status' });

    const fields = [];
    const vals = [];

    if (status) { fields.push('status=?'); vals.push(status); }
    if (typeof gm_notes === 'string') { fields.push('gm_notes=?'); vals.push(gm_notes); }
    if (typeof gm_resolution === 'string') { fields.push('gm_resolution=?'); vals.push(gm_resolution); }

    // auto-set resolved_at when marking resolved
    if (status === 'resolved') {
      fields.push('resolved_at=?');
      vals.push(new Date());
    }

    if (!fields.length) return reply.status(400).json({ error: 'Nothing to update' });

    vals.push(req.params.id);
    await pool.query(`UPDATE downtimes SET ${fields.join(', ')} WHERE id=?`, vals);

    const [rows] = await pool.query('SELECT * FROM downtimes WHERE id=?', [req.params.id]);
    log.adm('Downtime updated', { id: req.params.id, fields });
    reply.send({ downtime: rows[0] });
  });

  // GET: public to logged-in users (players need to see dates)
  fastify.get('/api/downtimes/config', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      reply.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');

      const deadline = await getSetting('downtime_deadline', null);
      const opening = await getSetting('downtime_opening', null);
      const projectDeadline = await getSetting('project_deadline', null);
      const activePhase = await getSetting('downtime_active_phase', 'standard'); // <-- NEW
      const massReleaseMode = await getSetting('downtime_mass_release_mode', 'false');
      const massReleaseDate = await getSetting('downtime_mass_release_date', null);

      reply.send({
        downtime_deadline: deadline || null,
        downtime_opening: opening || null,
        project_deadline: projectDeadline || null,
        downtime_active_phase: activePhase, // <-- NEW
        downtime_mass_release_mode: massReleaseMode,
        downtime_mass_release_date: massReleaseDate || null,
      });
    } catch (e) {
      log.err('Fetch downtime config failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch downtime config' });
    }
  });

  // WRITE (admins): save the dates
  fastify.post('/api/admin/downtimes/config', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { downtime_deadline, downtime_opening, project_deadline, downtime_active_phase, downtime_mass_release_mode, downtime_mass_release_date } = req.body || {};

      if (downtime_deadline && isNaN(new Date(downtime_deadline).getTime())) {
        return reply.status(400).json({ error: 'Invalid downtime_deadline date' });
      }
      if (downtime_opening && isNaN(new Date(downtime_opening).getTime())) {
        return reply.status(400).json({ error: 'Invalid downtime_opening date' });
      }
      if (project_deadline && isNaN(new Date(project_deadline).getTime())) {
        return reply.status(400).json({ error: 'Invalid project_deadline date' });
      }
      if (downtime_mass_release_date && isNaN(new Date(downtime_mass_release_date).getTime())) {
        return reply.status(400).json({ error: 'Invalid downtime_mass_release_date date' });
      }

      if (typeof downtime_deadline !== 'undefined') await setSetting('downtime_deadline', downtime_deadline || '');
      if (typeof downtime_opening !== 'undefined') await setSetting('downtime_opening', downtime_opening || '');
      if (typeof project_deadline !== 'undefined') await setSetting('project_deadline', project_deadline || '');
      if (typeof downtime_active_phase !== 'undefined') await setSetting('downtime_active_phase', downtime_active_phase || 'standard'); // <-- NEW
      if (typeof downtime_mass_release_mode !== 'undefined') {
        const oldMassReleaseMode = await getSetting('downtime_mass_release_mode', 'false');
        await setSetting('downtime_mass_release_mode', downtime_mass_release_mode ? 'true' : 'false');

        if (oldMassReleaseMode === 'true' && !downtime_mass_release_mode) {
          const hasNotified = await getSetting('downtime_mass_release_notified', 'false');
          if (hasNotified === 'false') {
            broadcastNtfyAlert('Downtime Resolutions have been released manually to all players!', {
              title: '🦇 Downtimes Released',
              tags: 'loudspeaker,vampire',
              priority: 'default'
            }).catch(() => { });
            await setSetting('downtime_mass_release_notified', 'true');
          }
        }
      }
      if (typeof downtime_mass_release_date !== 'undefined') {
        await setSetting('downtime_mass_release_date', downtime_mass_release_date || '');
        await setSetting('downtime_mass_release_notified', 'false');
      }

      const deadline = await getSetting('downtime_deadline', null);
      const opening = await getSetting('downtime_opening', null);
      const projDeadline = await getSetting('project_deadline', null);
      const phase = await getSetting('downtime_active_phase', 'standard'); // <-- NEW
      const massReleaseMode = await getSetting('downtime_mass_release_mode', 'false');
      const massReleaseDate = await getSetting('downtime_mass_release_date', null);

      reply.send({
        ok: true,
        downtime_deadline: deadline || null,
        downtime_opening: opening || null,
        project_deadline: projDeadline || null,
        downtime_active_phase: phase, // <-- NEW
        downtime_mass_release_mode: massReleaseMode,
        downtime_mass_release_date: massReleaseDate || null
      });
    } catch (e) {
      log.err('Update downtime config failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to update downtime config' });
    }
  });

  // Admin: Clean Resolved/Rejected Downtimes
  fastify.delete('/api/admin/downtimes/resolved', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [result] = await pool.query("DELETE FROM downtimes WHERE status IN ('resolved', 'rejected')");
      log.adm('Cleaned resolved downtimes', { admin_id: req.user.id, affectedRows: result.affectedRows });
      reply.send({ success: true, count: result.affectedRows });
    } catch (e) {
      log.err('Failed to clean downtimes', { error: e.message });
      reply.status(500).json({ success: false, error: 'Internal Server Error' });
    }
  });
};

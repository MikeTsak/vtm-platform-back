// routes/downtimes.js
//
// Downtime actions: player submission and quota, Storyteller resolution, and
// the chronicle-wide downtime configuration.
const { getSetting, setSetting } = require('../utils/settings');
const { startOfMonth, endOfMonth, feedingFromPredator } = require('../services/format');
const { getCycleInfo, resolveCurrentFeedingCycle } = require('../utils/feedingCycle');
const { parseSheet } = require('../utils/sheet');

// Scene ids are `scene_<ms timestamp>_<rand>`: order by the timestamp. Must match the sort of
// allSceneIds in front/src/features/admin/AdminDowntimesTab.jsx so "Scene N" agrees on both sides.
function compareSceneIds(a, b) {
  const key = (id) => Number((/^scene_(\d+)/.exec(String(id)) || [])[1]) || 0;
  return (key(a) - key(b)) || String(a).localeCompare(String(b));
}

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

    // Tie the quota window directly to the current Downtime cycle
    try {
      const cycleInfo = await resolveCurrentFeedingCycle();
      if (cycleInfo?.cycleStart && !isNaN(cycleInfo.cycleStart.getTime())) {
        from = cycleInfo.cycleStart;
        to = cycleInfo.cycleEnd && !isNaN(cycleInfo.cycleEnd.getTime())
          ? cycleInfo.cycleEnd
          : new Date(cycleInfo.cycleStart.getTime() + 90 * 24 * 60 * 60 * 1000);
      }
    } catch (e) {
      try {
        const openingStr = await getSetting('downtime_opening', null);
        if (openingStr) {
          const parsed = new Date(openingStr);
          if (!isNaN(parsed.getTime())) {
            from = parsed;
            to = new Date(parsed.getTime() + 90 * 24 * 60 * 60 * 1000);
          }
        }
      } catch (err) { }
    }

    // If deadline was manually extended beyond to, extend to so quota counts all submissions of this cycle
    try {
      const dlStr = await getSetting('downtime_deadline', null);
      if (dlStr) {
        const dlDate = new Date(dlStr);
        if (!isNaN(dlDate.getTime()) && dlDate > to) {
          to = dlDate;
        }
      }
    } catch (err) { }

    const [rows] = await pool.query(
      "SELECT COUNT(*) AS c FROM downtimes WHERE character_id=? AND created_at >= ? AND created_at <= ? AND status <> 'rejected'",
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

      // 2. Only allow edits if status is 'submitted' or 'needs a scene' (stored as 'Needs a Scene', hence lowercase)
      const editStatus = String(submission.status || '').toLowerCase();
      if (editStatus !== 'submitted' && editStatus !== 'needs a scene') {
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
    const activePhase = await getSetting('downtime_active_phase', 'standard');

    let isMassReleaseActive = false;
    if (massReleaseMode === 'true' && massReleaseDate) {
      const releaseTime = new Date(massReleaseDate).getTime();
      if (!isNaN(releaseTime) && Date.now() < releaseTime) {
        isMassReleaseActive = true;
      }
    }

    let currentCycleStart = null;
    try {
      const cycleInfo = await resolveCurrentFeedingCycle();
      if (cycleInfo?.cycleStart && !isNaN(cycleInfo.cycleStart.getTime())) {
        currentCycleStart = cycleInfo.cycleStart;
      }
    } catch (e) {}

    if (!currentCycleStart) {
      try {
        const openingStr = await getSetting('downtime_opening', null);
        if (openingStr) {
          const parsed = new Date(openingStr);
          if (!isNaN(parsed.getTime())) {
            currentCycleStart = parsed;
          }
        }
      } catch (e) {}
    }

    if (!isMassReleaseActive) {
      const unreleasedIds = rows.filter(r => r.is_released === 0 || r.is_released === false).map(r => r.id);
      if (unreleasedIds.length > 0) {
        pool.query('UPDATE downtimes SET is_released = 1 WHERE id IN (?)', [unreleasedIds]).catch(() => {});
      }
    }

    const sceneIds = [...new Set(rows.map(r => r.scene_id).filter(Boolean))];
    let participantsByScene = {};
    const sceneNumberById = {};
    if (sceneIds.length > 0) {
      // Only actions still in a scene status count: switching one to Approved keeps its scene_id
      // (so it can be moved back), but that character must stop showing up as a scene partner.
      const [participantRows] = await pool.query(
        `SELECT d.id AS downtime_id, d.scene_id, d.character_id, c.user_id, c.name AS char_name, c.clan, u.display_name AS player_name,
                (u.avatar_url IS NOT NULL OR u.avatar_url_thumb IS NOT NULL) AS has_avatar
         FROM downtimes d
         JOIN characters c ON c.id = d.character_id
         JOIN users u ON u.id = c.user_id
         WHERE d.scene_id IN (?) AND LOWER(d.status) IN ('needs a scene', 'resolved in scene')`,
        [sceneIds]
      );
      for (const p of participantRows) {
        if (!participantsByScene[p.scene_id]) {
          participantsByScene[p.scene_id] = [];
        }
        participantsByScene[p.scene_id].push(p);
      }

      // Same "Scene N" numbering as the admin Live Event Scenes board (AdminDowntimesTab allSceneIds):
      // every scene that still holds a scene action, oldest first by the timestamp inside its id.
      const [allScenes] = await pool.query(
        `SELECT DISTINCT d.scene_id
         FROM downtimes d
         JOIN characters c ON c.id = d.character_id
         JOIN users u ON u.id = c.user_id
         WHERE d.scene_id IS NOT NULL AND LOWER(d.status) IN ('needs a scene', 'resolved in scene')`
      );
      allScenes.map(s => s.scene_id).sort(compareSceneIds).forEach((id, i) => { sceneNumberById[id] = i + 1; });
    }

    rows.forEach(r => {
      let pendingRelease = false;

      if (isMassReleaseActive) {
        const alreadyRead = r.is_read === 1 || r.is_read === true;
        const isProject = r.title && r.title.startsWith('[PROJECT]');
        const projectMismatch = isProject && activePhase === 'standard';
        const pastCycle = currentCycleStart && new Date(r.created_at).getTime() < currentCycleStart.getTime();

        if (!alreadyRead && !projectMismatch && !pastCycle) {
          const s = String(r.status || '').toLowerCase();
          const isResolvedOrApproved = ['resolved', 'approved', 'rejected', 'resolved in scene'].includes(s) || s.startsWith('approved');
          if (isResolvedOrApproved || r.gm_resolution) {
            pendingRelease = true;
          }
        }
      }

      r.is_pending_release = pendingRelease;

      if (pendingRelease) {
        r.gm_resolution = null;
        r.gm_notes = null;
      }

      if (r.status && r.status.toLowerCase().startsWith('approved')) {
        r.status = 'approved';
      }

      if (r.scene_id && participantsByScene[r.scene_id]) {
        const others = [];
        const all = [];
        const seenCharIds = new Set();
        for (const p of participantsByScene[r.scene_id]) {
          if (!seenCharIds.has(p.character_id)) {
            seenCharIds.add(p.character_id);
            const item = {
              character_id: p.character_id,
              user_id: p.user_id,
              has_avatar: Boolean(p.has_avatar),
              char_name: p.char_name,
              player_name: p.player_name,
              clan: p.clan,
              is_me: p.character_id === char[0].id,
            };
            all.push(item);
            if (p.character_id !== char[0].id) {
              others.push(item);
            }
          }
        }
        r.scene_participants = others;
        r.scene_all_participants = all;
      } else {
        r.scene_participants = [];
        r.scene_all_participants = [];
      }
      r.scene_number = (r.scene_id && sceneNumberById[r.scene_id]) || null;
    });

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

    if (activePhase === 'closed') {
      return reply.status(400).json({ error: 'Downtime submissions are currently closed.' });
    }

    if (activePhase === 'project' && !isProjectSubmission) {
      return reply.status(400).json({ error: 'Monthly Action submissions are currently closed. Only Long Term Projects are being accepted.' });
    } else if (activePhase === 'standard' && isProjectSubmission) {
      return reply.status(400).json({ error: 'Long Term Project submissions are currently closed. Only Monthly Actions are being accepted.' });
    }

    // Check opening date
    const openingStr = await getSetting('downtime_opening', null);
    if (openingStr) {
      const op = new Date(openingStr);
      if (!isNaN(op.getTime()) && Date.now() < op.getTime()) {
        return reply.status(400).json({ error: 'Downtime submissions have not opened yet.' });
      }
    }

    // Check deadline
    const deadlineKey = isProjectSubmission ? 'project_deadline' : 'downtime_deadline';
    const deadlineStr = await getSetting(deadlineKey, null);
    if (deadlineStr) {
      const dl = new Date(deadlineStr);
      if (!isNaN(dl.getTime()) && Date.now() > dl.getTime()) {
        return reply.status(400).json({
          error: `The deadline for ${isProjectSubmission ? 'project' : 'downtime'} submissions has passed.`
        });
      }
    }

    const [chars] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
    const ch = chars[0];
    if (!ch) {
      log.warn('Downtime create without character', { user_id: req.user.id });
      return reply.status(400).json({ error: 'Create a character first' });
    }

    // Feeding gate: this cycle's hunting roll must be resolved before any
    // downtime action (standard or project) can be submitted.
    const feedingEnabled = (await getSetting('feeding_enabled', 'true')) === 'true';
    let currentCycleInfo = null;
    try {
      currentCycleInfo = await resolveCurrentFeedingCycle();
    } catch (e) { }

    if (feedingEnabled) {
      const cycleIndex = currentCycleInfo?.cycleIndex || 0;
      const [fed] = await pool.query(
        "SELECT id FROM feedings WHERE character_id=? AND cycle_index=? AND status='resolved' LIMIT 1",
        [ch.id, cycleIndex]
      );
      if (!fed.length) {
        return reply.status(400).json({ error: 'You must feed this cycle before submitting downtime actions.' });
      }
    }

    let from = startOfMonth();
    let to = endOfMonth();

    if (currentCycleInfo?.cycleStart && !isNaN(currentCycleInfo.cycleStart.getTime())) {
      from = currentCycleInfo.cycleStart;
      to = currentCycleInfo.cycleEnd && !isNaN(currentCycleInfo.cycleEnd.getTime())
        ? currentCycleInfo.cycleEnd
        : new Date(currentCycleInfo.cycleStart.getTime() + 90 * 24 * 60 * 60 * 1000);
    } else {
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
    }

    // If deadline was manually extended beyond to, extend to so quota counts all submissions of this cycle
    try {
      const dlKey = isProjectSubmission ? 'project_deadline' : 'downtime_deadline';
      const dlStr = await getSetting(dlKey, null);
      if (dlStr) {
        const dlDate = new Date(dlStr);
        if (!isNaN(dlDate.getTime()) && dlDate > to) {
          to = dlDate;
        }
      }
    } catch (e) { }

    const [cnt] = await pool.query(
      "SELECT COUNT(*) AS c FROM downtimes WHERE character_id=? AND created_at >= ? AND created_at <= ? AND status <> 'rejected'",
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
        const parsed = parseSheet(ch.sheet);
        pred = parsed?.predator_type || parsed?.predatorType || null;
      }
      defaultFeed = feedingFromPredator(pred);
    }

    const massReleaseMode = await getSetting('downtime_mass_release_mode', 'false');
    const massReleaseDate = await getSetting('downtime_mass_release_date', null);
    let initialReleased = 1;
    if (massReleaseMode === 'true' && massReleaseDate) {
      const releaseTime = new Date(massReleaseDate).getTime();
      if (!isNaN(releaseTime) && Date.now() < releaseTime) {
        initialReleased = 0;
      }
    }

    const [r] = await pool.query(
      'INSERT INTO downtimes (character_id, title, feeding_type, body, is_released) VALUES (?,?,?,?,?)',
      [ch.id, title, defaultFeed || null, body, initialReleased]
    );
    const [rows] = await pool.query('SELECT * FROM downtimes WHERE id=?', [r.insertId]);
    log.dt('Downtime created', { user_id: req.user.id, downtime_id: r.insertId, feeding_type: defaultFeed || feeding_type || null });
    broadcastNtfyAlert(`**${ch.name} (${ch.id})** submitted a new downtime action:\n\n> *${title}*`, { title: 'Downtime Submitted', tags: 'hourglass_flowing_sand', priority: 'default' });
    reply.send({ downtime: rows[0] });
  });

  fastify.get('/api/admin/downtimes', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const [rows] = await pool.query(
      `SELECT d.*, c.user_id, c.name AS char_name, c.clan, u.display_name AS player_name, u.email,
              (u.avatar_url IS NOT NULL OR u.avatar_url_thumb IS NOT NULL) AS has_avatar
     FROM downtimes d
     JOIN characters c ON c.id=d.character_id
     JOIN users u ON u.id=c.user_id
     ORDER BY d.created_at DESC`
    );
    log.adm('Admin downtimes list', { count: rows.length });
    reply.send({ downtimes: rows });
  });

  fastify.patch('/api/admin/downtimes/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const { status, gm_notes, gm_resolution, scene_id, scene_title } = req.body;
    const allowed = [
      'submitted',
      'approved',
      'Approved: Kikos',
      'Approved: Mike',
      'rejected',
      'resolved',
      'Needs a Scene',
      'Resolved in scene'
    ];
    let normalizedStatus = status;
    if (status) {
      const match = allowed.find(a => a.toLowerCase() === String(status).trim().toLowerCase());
      if (!match) return reply.status(400).json({ error: 'Bad status' });
      normalizedStatus = match;
    }

    const fields = [];
    const vals = [];

    if (normalizedStatus) { fields.push('status=?'); vals.push(normalizedStatus); }
    if (typeof gm_notes === 'string') { fields.push('gm_notes=?'); vals.push(gm_notes); }
    if (typeof gm_resolution === 'string') { fields.push('gm_resolution=?'); vals.push(gm_resolution); }
    if (scene_id !== undefined) { fields.push('scene_id=?'); vals.push(scene_id || null); }
    if (scene_title !== undefined) { fields.push('scene_title=?'); vals.push(scene_title || null); }

    // auto-set resolved_at when marking resolved
    if (status === 'resolved') {
      fields.push('resolved_at=?');
      vals.push(new Date());
    }

    const massReleaseMode = await getSetting('downtime_mass_release_mode', 'false');
    const massReleaseDate = await getSetting('downtime_mass_release_date', null);
    let isMassReleaseActive = false;
    if (massReleaseMode === 'true' && massReleaseDate) {
      const releaseTime = new Date(massReleaseDate).getTime();
      if (!isNaN(releaseTime) && Date.now() < releaseTime) {
        isMassReleaseActive = true;
      }
    }
    if (!isMassReleaseActive) {
      fields.push('is_released=?');
      vals.push(1);
    }

    if (!fields.length) return reply.status(400).json({ error: 'Nothing to update' });

    vals.push(req.params.id);
    await pool.query(`UPDATE downtimes SET ${fields.join(', ')} WHERE id=?`, vals);

    const [rows] = await pool.query('SELECT * FROM downtimes WHERE id=?', [req.params.id]);
    log.adm('Downtime updated', { id: req.params.id, fields });
    reply.send({ downtime: rows[0] });
  });

  // Batch scene update endpoint
  fastify.post('/api/admin/downtimes/scenes/batch', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const { downtime_ids, scene_id, scene_title, status } = req.body || {};
    if (!Array.isArray(downtime_ids) || downtime_ids.length === 0) {
      return reply.status(400).json({ error: 'downtime_ids array required' });
    }

    const fields = [];
    const vals = [];

    if (scene_id !== undefined) {
      fields.push('scene_id=?');
      vals.push(scene_id || null);
    }
    if (scene_title !== undefined) {
      fields.push('scene_title=?');
      vals.push(scene_title || null);
    }
    if (status !== undefined) {
      // Scene batches only move actions between the two scene statuses; anything else goes through PATCH.
      if (!['Needs a Scene', 'Resolved in scene'].includes(status)) {
        return reply.status(400).json({ error: 'Bad status' });
      }
      fields.push('status=?');
      vals.push(status);
    }

    if (!fields.length) return reply.status(400).json({ error: 'Nothing to update' });

    vals.push(downtime_ids);
    await pool.query(`UPDATE downtimes SET ${fields.join(', ')} WHERE id IN (?)`, vals);

    const [rows] = await pool.query('SELECT * FROM downtimes WHERE id IN (?)', [downtime_ids]);
    log.adm('Downtime scenes batch updated', { count: rows.length, scene_id, scene_title });
    reply.send({ downtimes: rows });
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
          await pool.query('UPDATE downtimes SET is_released = 1 WHERE is_released = 0').catch(() => {});
          const hasNotified = await getSetting('downtime_mass_release_notified', 'false');
          if (hasNotified === 'false') {
            broadcastNtfyAlert('Downtime Resolutions have been released manually to all players!', {
              title: '🦇 Downtimes Released',
              tags: 'loudspeaker,vampire',
              priority: 'default'
            }).catch(() => { });
            await setSetting('downtime_mass_release_notified', 'true');
          }
        } else if (oldMassReleaseMode !== 'true' && downtime_mass_release_mode) {
          let start = null;
          try {
            const cycleInfo = await resolveCurrentFeedingCycle();
            if (cycleInfo?.cycleStart) start = cycleInfo.cycleStart;
          } catch (_) {}
          if (!start) {
            const op = await getSetting('downtime_opening', null);
            if (op) start = new Date(op);
          }
          if (start) {
            await pool.query(
              'UPDATE downtimes SET is_released = 0 WHERE created_at >= ? AND is_read = 0 AND title NOT LIKE "[PROJECT]%"',
              [start]
            ).catch(() => {});
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

  // GET /api/admin/downtimes/cycles: Retrieve multiple downtime operation cycles
  fastify.get('/api/admin/downtimes/cycles', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const raw = await getSetting('downtime_cycles_schedule', '[]');
      let cycles = [];
      try { cycles = JSON.parse(raw); } catch (_) {}
      reply.send({ cycles: Array.isArray(cycles) ? cycles : [] });
    } catch (e) {
      log.err('Fetch downtime cycles failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch downtime cycles' });
    }
  });

  // GET /api/admin/downtimes/last-cycle-submitters: characters that submitted a
  // (non-rejected) downtime in the most recently *closed* cycle. Session XP is
  // granted after that cycle is resolved, so the still-open cycle is skipped.
  fastify.get('/api/admin/downtimes/last-cycle-submitters', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      let cycles = [];
      try { cycles = JSON.parse(await getSetting('downtime_cycles_schedule', '[]')); } catch (_) { }
      const todayStr = new Date().toISOString().split('T')[0];
      const last = (Array.isArray(cycles) ? cycles : [])
        .filter(c => c && c.opening_date && c.closing_date && c.closing_date < todayStr)
        .sort((a, b) => b.closing_date.localeCompare(a.closing_date))[0];
      if (!last) return reply.send({ cycle: null, character_ids: [] });

      const [rows] = await pool.query(
        `SELECT DISTINCT character_id FROM downtimes
         WHERE status <> 'rejected' AND created_at >= ? AND created_at <= ?`,
        [new Date(last.opening_date + 'T00:00:00'), new Date(last.closing_date + 'T23:59:59')]
      );
      reply.send({
        cycle: { id: last.id, title: last.title || null, opening_date: last.opening_date, closing_date: last.closing_date },
        character_ids: rows.map(r => r.character_id),
      });
    } catch (e) {
      log.err('Fetch last-cycle downtime submitters failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch downtime submitters' });
    }
  });

  // POST /api/admin/downtimes/cycles: Save multiple downtime operation cycles
  fastify.post('/api/admin/downtimes/cycles', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { cycles, activeCycleId } = req.body || {};
      const validCycles = Array.isArray(cycles) ? cycles : [];
      await setSetting('downtime_cycles_schedule', JSON.stringify(validCycles));

      if (activeCycleId) {
        const found = validCycles.find(c => String(c.id) === String(activeCycleId));
        if (found) {
          if (found.opening_date) await setSetting('downtime_opening', found.opening_date);
          if (found.closing_date) await setSetting('downtime_deadline', found.closing_date);
        }
      }
      reply.send({ ok: true, cycles: validCycles });
    } catch (e) {
      log.err('Save downtime cycles failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to save downtime cycles' });
    }
  });
};


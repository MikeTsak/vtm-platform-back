// routes/hunts.js
//
// The Hunt: Storyteller authoring of hunts and steps, review of submissions,
// and the player-facing group/join/submit flow.
const crypto = require('crypto');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, broadcastNtfyAlert, sendPushNotification } = opts;

  // GET: List all hunts
  fastify.get('/api/admin/hunts', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [hunts] = await pool.query('SELECT * FROM hunts ORDER BY created_at DESC');
      reply.send({ hunts });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch hunts' });
    }
  });

  // POST: Create a new hunt
  fastify.post('/api/admin/hunts', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { title, description } = req.body;
      const [r] = await pool.query('INSERT INTO hunts (title, description) VALUES (?,?)', [title, description]);
      reply.send({ id: r.insertId });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to create hunt' });
    }
  });

  // --- NEW: Move a Step Up or Down ---
  fastify.patch('/api/admin/hunts/:huntId/steps/:stepId/move/:direction', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  const { huntId, stepId, direction } = req.params;
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Get current step
      const [[currentStep]] = await conn.query('SELECT id, step_order FROM hunt_steps WHERE id = ? AND hunt_id = ?', [stepId, huntId]);
      if (!currentStep) throw new Error("Step not found");

      const targetOrder = direction === 'up' ? currentStep.step_order - 1 : currentStep.step_order + 1;

      // Get the step we are swapping with
      const [[swapStep]] = await conn.query('SELECT id, step_order FROM hunt_steps WHERE hunt_id = ? AND step_order = ?', [huntId, targetOrder]);

      if (swapStep) {
        // Swap their orders
        await conn.query('UPDATE hunt_steps SET step_order = ? WHERE id = ?', [targetOrder, currentStep.id]);
        await conn.query('UPDATE hunt_steps SET step_order = ? WHERE id = ?', [currentStep.step_order, swapStep.id]);
      }

      await conn.commit();
      reply.send({ ok: true });
    } catch (e) {
      await conn.rollback();
      reply.status(500).json({ error: 'Failed to reorder steps.' });
    } finally {
      conn.release();
    }
  });

  // --- NEW: Force Advance a Player ---
  fastify.post('/api/admin/hunts/:huntId/progress/:userId/advance', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const huntId = Number(req.params.huntId);
      const userId = Number(req.params.userId);

      const [[progress]] = await pool.query('SELECT * FROM hunt_progress WHERE user_id=? AND hunt_id=?', [userId, huntId]);
      if (!progress || progress.completed) return reply.status(400).json({ error: 'Player is not active or already finished.' });

      const [[currentStep]] = await pool.query('SELECT step_order FROM hunt_steps WHERE id=?', [progress.current_step_id]);
      const [[nextStep]] = await pool.query('SELECT id FROM hunt_steps WHERE hunt_id=? AND step_order > ? ORDER BY step_order ASC LIMIT 1', [huntId, currentStep.step_order]);

      if (nextStep) {
        await pool.query('UPDATE hunt_progress SET current_step_id=? WHERE user_id=? AND hunt_id=?', [nextStep.id, userId, huntId]);
      } else {
        await pool.query('UPDATE hunt_progress SET completed=1 WHERE user_id=? AND hunt_id=?', [userId, huntId]);
      }

      log.adm('Admin forced player advance', { admin_id: req.user.id, target_user: userId, hunt_id: huntId });
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to advance player.' });
    }
  });

  // --- ADMIN: Toggle Hunt Status ---

  // Updated to allow multiple active hunts simultaneously
  fastify.patch('/api/admin/hunts/:id/toggle', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const id = req.params.id;
      // Removed the query that deactivated other hunts to allow multiple activations
      await pool.query('UPDATE hunts SET is_active = NOT is_active WHERE id=?', [id]);
      reply.send({ ok: true });
    } catch (e) {
      log.err('Failed to toggle hunt', { message: e.message });
      reply.status(500).json({ error: 'Failed to toggle hunt' });
    }
  });

  // Edit a step (Fixed to save manual_review flag)
  fastify.put('/api/admin/hunts/:huntId/steps/:stepId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  const { task_type, prompt, target_data } = req.body;
    const tData = typeof target_data === 'string' ? target_data : JSON.stringify(target_data);
    const isManual = ['photo', 'draw', 'audio'].includes(task_type) ? 1 : 0;

    try {
      await pool.query(
        'UPDATE hunt_steps SET task_type=?, prompt=?, target_data=?, manual_review=? WHERE id=?',
        [task_type, prompt, tData, isManual, req.params.stepId]
      );
      reply.send({ success: true });
    } catch (err) { reply.status(500).json({ error: err.message }); }
  });

  // Delete a step
  fastify.delete('/api/admin/hunts/:huntId/steps/:stepId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      await pool.query('DELETE FROM hunt_steps WHERE id=?', [req.params.stepId]);
      reply.send({ success: true });
    } catch (err) { reply.status(500).json({ error: err.message }); }
  });

  // GET: List steps for a specific hunt
  fastify.get('/api/admin/hunts/:id/steps', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [steps] = await pool.query('SELECT * FROM hunt_steps WHERE hunt_id=? ORDER BY step_order ASC', [req.params.id]);
      reply.send({ steps });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch steps' });
    }
  });

  // Get progress of all players for a specific hunt
  fastify.get('/api/admin/hunts/:huntId/progress', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      // Fetch all players who have a progress entry for this hunt
      const [progress] = await pool.query(`
      SELECT 
        u.id as user_id, 
        u.email,
        COALESCE(c.name, 'Unknown Kindred') as character_name,
        hp.completed,
        hs.step_order as current_step
      FROM hunt_progress hp
      JOIN users u ON hp.user_id = u.id
      LEFT JOIN characters c ON u.id = c.user_id
      LEFT JOIN hunt_steps hs ON hp.current_step_id = hs.id
      WHERE hp.hunt_id = ?
    `, [req.params.huntId]);

      // Get total steps to calculate the exact percentage
      const [stepCount] = await pool.query('SELECT COUNT(*) as total FROM hunt_steps WHERE hunt_id = ?', [req.params.huntId]);
      const totalSteps = stepCount[0].total || 1;

      // Format the data for the frontend
      const formattedProgress = progress.map(p => {
        let percent = 0;
        if (p.completed) percent = 100;
        else if (p.current_step > 1) percent = Math.round(((p.current_step - 1) / totalSteps) * 100);

        return {
          ...p,
          percent: percent
        };
      });

      reply.send({ progress: formattedProgress });
    } catch (err) {
      console.error(err);
      reply.status(500).json({ error: err.message });
    }
  });

  // Get pending manual reviews for a chronicle (Fixed query logic)
  fastify.get('/api/admin/hunts/:huntId/reviews', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [reviews] = await pool.query(`
      SELECT 
        s.id as submission_id,
        u.email,
        COALESCE(c.name, 'Unknown Kindred') as character_name,
        hs.step_order,
        hs.prompt,
        hs.task_type,
        s.media_id,
        s.status
      FROM hunt_submissions s
      JOIN users u ON s.user_id = u.id
      LEFT JOIN characters c ON u.id = c.user_id
      JOIN hunt_steps hs ON s.step_id = hs.id
      WHERE hs.hunt_id = ? 
        AND hs.task_type IN ('photo', 'draw', 'audio') 
        AND (s.status = 'pending' OR s.status IS NULL)
    `, [req.params.huntId]);

      reply.send({ reviews });
    } catch (err) { reply.status(500).json({ error: err.message }); }
  });

  // Approve or Reject a submission
  fastify.post('/api/admin/reviews/:submissionId/:action', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  const { submissionId, action } = req.params;
    const newStatus = action === 'approve' ? 'approved' : 'rejected';

    try {
      // 1. Update the submission status
      await pool.query('UPDATE hunt_submissions SET status = ? WHERE id = ?', [newStatus, submissionId]);

      // 2. If the ST rejects it, we punish the player
      if (newStatus === 'rejected') {

        // Find out exactly who submitted this and for what step/hunt
        const [[sub]] = await pool.query(`
        SELECT s.user_id, s.step_id, hs.hunt_id, hs.step_order, hs.prompt
        FROM hunt_submissions s
        JOIN hunt_steps hs ON s.step_id = hs.id
        WHERE s.id = ?
      `, [submissionId]);

        if (sub) {
          // Roll their progress back to the failed step and ensure they are un-marked as completed
          await pool.query(`
          UPDATE hunt_progress 
          SET current_step_id = ?, completed = 0 
          WHERE user_id = ? AND hunt_id = ?
        `, [sub.step_id, sub.user_id, sub.hunt_id]);

          // Send a push notification alerting them of their failure
          const title = "❌ Evidence Rejected";
          const body = `The Court found your submission for Step ${sub.step_order} unacceptable. You must acquire better evidence.`;

          await sendPushNotification(sub.user_id, title, body).catch(() => { });
          log.adm('Evidence rejected & player rolled back', { admin: req.user.id, player: sub.user_id, step: sub.step_order });
        }
      }

      reply.send({ success: true });
    } catch (err) {
      log.err('Review action failed', { error: err.message });
      reply.status(500).json({ error: err.message });
    }
  });

  // POST: Add a new step to a hunt (Fixed to save manual_review flag)
  fastify.post('/api/admin/hunts/:id/steps', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { task_type, prompt, target_data, step_order } = req.body;
      const isManual = ['photo', 'draw', 'audio'].includes(task_type) ? 1 : 0;

      await pool.query(
        'INSERT INTO hunt_steps (hunt_id, step_order, task_type, prompt, target_data, manual_review) VALUES (?,?,?,?,?,?)',
        [req.params.id, step_order, task_type, prompt, JSON.stringify(target_data), isManual]
      );
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to add step' });
    }
  });

  // DELETE: Completely remove a chronicle
  fastify.delete('/api/admin/hunts/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const huntId = req.params.id;

      // 1. Find all Coteries associated with this hunt
      const [groups] = await pool.query('SELECT id FROM hunt_groups WHERE hunt_id=?', [huntId]);
      if (groups.length > 0) {
        const groupIds = groups.map(g => g.id);
        // 2. Delete all members of those coteries
        await pool.query('DELETE FROM hunt_group_members WHERE group_id IN (?)', [groupIds]);
      }

      // 3. Delete the coteries themselves
      await pool.query('DELETE FROM hunt_groups WHERE hunt_id=?', [huntId]);

      // 4. Finally, delete the actual chronicle
      await pool.query('DELETE FROM hunts WHERE id=?', [huntId]);

      reply.send({ ok: true });
    } catch (e) {
      log.err('Failed to delete chronicle', { message: e.message });
      reply.status(500).json({ error: 'Failed to delete chronicle' });
    }
  });
  // --- PLAYER ROUTES ---

  // --- TEAM / COTERIE SYSTEM FOR HUNTS ---

  // POST: Create a team for a hunt
  fastify.post('/api/hunts/:huntId/groups', { preHandler: [authRequired] }, async (req, reply) => {
    const huntId = Number(req.params.huntId);
  const { name } = req.body;
    if (!name || name.trim() === '') return reply.status(400).json({ error: 'Team name is required.' });

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Generate a 6-character random hex invite code
      const inviteCode = crypto.randomBytes(3).toString('hex').toUpperCase();

      // 1. Create the group
      const [gRes] = await conn.query(
        'INSERT INTO hunt_groups (hunt_id, name, invite_code, created_by) VALUES (?, ?, ?, ?)',
        [huntId, name.trim(), inviteCode, req.user.id]
      );

      // 2. Add creator to the group
      await conn.query(
        'INSERT INTO hunt_group_members (group_id, user_id) VALUES (?, ?)',
        [gRes.insertId, req.user.id]
      );

      await conn.commit();
      reply.send({ ok: true, invite_code: inviteCode });
    } catch (e) {
      await conn.rollback();
      log.err('Failed to create hunt group', { error: e.message });
      reply.status(500).json({ error: 'Failed to establish coterie.' });
    } finally {
      conn.release();
    }
  });

  // POST: Join a team via invite code
  fastify.post('/api/hunts/:huntId/groups/join', { preHandler: [authRequired] }, async (req, reply) => {
    const huntId = Number(req.params.huntId);
  const { code } = req.body;
    if (!code) return reply.status(400).json({ error: 'Invite code required.' });

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // 1. Find the group
      const [[group]] = await conn.query('SELECT id FROM hunt_groups WHERE hunt_id = ? AND invite_code = ?', [huntId, code.trim().toUpperCase()]);
      if (!group) {
        await conn.rollback();
        return reply.status(404).json({ error: 'Invalid invite code or chronicle mismatch.' });
      }

      // 2. Add user to the group (IGNORE handles if they are already in it)
      await conn.query('INSERT IGNORE INTO hunt_group_members (group_id, user_id) VALUES (?, ?)', [group.id, req.user.id]);

      // 3. Sync their progress to the group's highest progress
      const [[groupProgress]] = await conn.query(`
      SELECT current_step_id, completed 
      FROM hunt_progress 
      WHERE hunt_id = ? AND user_id IN (SELECT user_id FROM hunt_group_members WHERE group_id = ?)
      ORDER BY completed DESC, current_step_id DESC LIMIT 1
    `, [huntId, group.id]);

      if (groupProgress) {
        await conn.query(
          'UPDATE hunt_progress SET current_step_id = ?, completed = ? WHERE user_id = ? AND hunt_id = ?',
          [groupProgress.current_step_id, groupProgress.completed, req.user.id, huntId]
        );
      }

      await conn.commit();
      reply.send({ ok: true });
    } catch (e) {
      await conn.rollback();
      log.err('Failed to join hunt group', { error: e.message });
      reply.status(500).json({ error: 'Failed to join coterie.' });
    } finally {
      conn.release();
    }
  });

  /* -------------------- Fixed & Enhanced Hunt Player Routes -------------------- */

  // GET: Player's active hunts, current progress, and Coterie info
  fastify.get('/api/hunts/active', { preHandler: [authRequired] }, async (req, reply) => {
    reply.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');

    try {
      const [activeHunts] = await pool.query(
        'SELECT * FROM hunts WHERE is_active = 1 ORDER BY created_at DESC'
      );

      if (activeHunts.length === 0) {
        return reply.send({ activeHunts: [] });
      }

      const huntsWithMetadata = await Promise.all(
        activeHunts.map(async (hunt) => {
          const [[progressRow]] = await pool.query(
            'SELECT * FROM hunt_progress WHERE user_id = ? AND hunt_id = ?',
            [req.user.id, hunt.id]
          );

          const [[winner]] = await pool.query(
            'SELECT id FROM hunt_progress WHERE hunt_id = ? AND completed = 1 LIMIT 1',
            [hunt.id]
          );
          const isGloballyFinished = !!winner;

          const [[competitorCount]] = await pool.query(
            'SELECT COUNT(*) AS c FROM hunt_progress WHERE hunt_id = ? AND user_id != ? AND completed = 0',
            [hunt.id, req.user.id]
          );
          const active_hunters = competitorCount.c;

          const [[firstStep]] = await pool.query(
            'SELECT * FROM hunt_steps WHERE hunt_id = ? ORDER BY step_order ASC LIMIT 1',
            [hunt.id]
          );

          let progress = progressRow || null;
          let currentStep = null;
          let isReady = !!firstStep;

          // No steps yet: still return the hunt so it appears in the player list
          if (!firstStep) {
            return {
              hunt,
              step: {
                id: null,
                step_order: 0,
                prompt: 'This hunt is active, but no steps have been published yet.',
                task_type: 'text'
              },
              team: null,
              progress: {
                percent: 0,
                completed: false,
                isGloballyFinished,
                otherHunters: active_hunters
              },
              isReady: false
            };
          }

          if (!progress) {
            await pool.query(
              'INSERT INTO hunt_progress (user_id, hunt_id, current_step_id) VALUES (?, ?, ?)',
              [req.user.id, hunt.id, firstStep.id]
            );

            progress = {
              user_id: req.user.id,
              hunt_id: hunt.id,
              current_step_id: firstStep.id,
              completed: 0
            };

            currentStep = firstStep;
          } else if (progress.completed) {
            const [[lastStep]] = await pool.query(
              'SELECT * FROM hunt_steps WHERE hunt_id = ? ORDER BY step_order DESC LIMIT 1',
              [hunt.id]
            );
            currentStep = lastStep || firstStep;
          } else {
            const [[step]] = await pool.query(
              'SELECT * FROM hunt_steps WHERE id = ? AND hunt_id = ?',
              [progress.current_step_id, hunt.id]
            );

            if (step) {
              currentStep = step;
            } else {
              // self-heal stale progress when a step was deleted/reordered
              await pool.query(
                'UPDATE hunt_progress SET current_step_id = ? WHERE user_id = ? AND hunt_id = ?',
                [firstStep.id, req.user.id, hunt.id]
              );
              progress.current_step_id = firstStep.id;
              currentStep = firstStep;
            }
          }

          const [[totalSteps]] = await pool.query(
            'SELECT COUNT(*) AS t FROM hunt_steps WHERE hunt_id = ?',
            [hunt.id]
          );

          let percent = 0;
          if (progress?.completed) {
            percent = 100;
          } else if (currentStep?.step_order > 1 && totalSteps.t > 0) {
            percent = Math.round(((currentStep.step_order - 1) / totalSteps.t) * 100);
          }

          let teamData = null;
          const [[myGroup]] = await pool.query(`
          SELECT g.id, g.name, g.invite_code
          FROM hunt_groups g
          JOIN hunt_group_members m ON m.group_id = g.id
          WHERE m.user_id = ? AND g.hunt_id = ?
          LIMIT 1
        `, [req.user.id, hunt.id]);

          if (myGroup) {
            const [members] = await pool.query(`
            SELECT COALESCE(c.name, u.display_name) AS member_name
            FROM hunt_group_members m
            JOIN users u ON m.user_id = u.id
            LEFT JOIN characters c ON c.user_id = u.id
            WHERE m.group_id = ?
          `, [myGroup.id]);

            teamData = {
              name: myGroup.name,
              invite_code: myGroup.invite_code,
              members: members.map(m => m.member_name)
            };
          }

          return {
            hunt,
            step: currentStep,
            team: teamData,
            progress: {
              percent,
              completed: !!progress?.completed,
              isGloballyFinished,
              otherHunters: active_hunters
            },
            isReady
          };
        })
      );

      reply.send({ activeHunts: huntsWithMetadata });
    } catch (e) {
      log.err('Failed to fetch active hunts', { message: e.message });
      reply.status(500).json({ error: 'Failed to sync chronicles' });
    }
  });
  // POST: Submit an answer or evidence for the current step
  fastify.post('/api/hunts/submit', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { step_id, text_answer, lat, lng, media_id } = req.body;

      // 1. Verify step exists and belongs to the user's current progress
      const [[step]] = await pool.query('SELECT * FROM hunt_steps WHERE id=?', [step_id]);
      if (!step) return reply.status(404).json({ error: 'Challenge not found in the archives.' });

      const [[progress]] = await pool.query('SELECT * FROM hunt_progress WHERE user_id=? AND hunt_id=?', [req.user.id, step.hunt_id]);
      if (!progress || progress.current_step_id !== step.id || progress.completed) {
        return reply.status(400).json({ error: 'Invalid submission sequence.' });
      }

      // Safely parse target data
      const target = typeof step.target_data === 'string' ? JSON.parse(step.target_data || '{}') : (step.target_data || {});

      // --- 2. VALIDATION BY TASK TYPE ---
      if (step.task_type === 'text') {
        if (text_answer?.toLowerCase().trim() !== target?.answer?.toLowerCase()) {
          return reply.status(400).json({ error: 'Incorrect answer. The Court expects better.' });
        }
      }
      else if (step.task_type === 'qr') {
        if (text_answer?.trim() !== target?.qr_string) {
          return reply.status(400).json({ error: 'Invalid Sigil scanned.' });
        }
      }
      else if (step.task_type === 'gps') {
        if (!lat || !lng) return reply.status(400).json({ error: 'Missing GPS coordinates.' });

        // Haversine formula to calculate distance in meters
        const R = 6371e3; // Earth radius in metres
        const φ1 = lat * Math.PI / 180;
        const φ2 = target.lat * Math.PI / 180;
        const Δφ = (target.lat - lat) * Math.PI / 180;
        const Δλ = (target.lng - lng) * Math.PI / 180;
        const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
          Math.cos(φ1) * Math.cos(φ2) *
          Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        const distance = R * c;

        const allowedRadius = target.radius_meters || 50; // Default 50m allowance for GPS drift
        if (distance > allowedRadius) {
          return reply.status(400).json({ error: `Location rejected. You are ${Math.round(distance)} meters away from the target.` });
        }
      }
      else if (['photo', 'draw', 'audio'].includes(step.task_type)) {
        if (!media_id) return reply.status(400).json({ error: 'Evidence file required.' });

        // Log the submission into the database for the ST to review later
        await pool.query(
          'INSERT INTO hunt_submissions (user_id, step_id, media_id, status) VALUES (?, ?, ?, ?)',
          [req.user.id, step.id, media_id, 'pending']
        );
        broadcastNtfyAlert(`Player submitted evidence for **Hunt Challenge #${step.id}**.\n\n*Awaiting manual review in the ST panel.*`, { title: 'Hunt Submission', tags: 'mag', priority: 'high' });
      }

      // --- 3. GET NEXT STEP ---
      const [[nextStep]] = await pool.query(
        'SELECT * FROM hunt_steps WHERE hunt_id=? AND step_order > ? ORDER BY step_order ASC LIMIT 1',
        [step.hunt_id, step.step_order]
      );

      // --- 4. ADVANCE THE TEAM / COTERIE ---
      let targetUserIds = [req.user.id]; // Default to solo player

      // Check if the user is in a group for this specific hunt
      const [[myGroup]] = await pool.query(`
      SELECT group_id FROM hunt_group_members 
      WHERE user_id = ? AND group_id IN (SELECT id FROM hunt_groups WHERE hunt_id = ?)
    `, [req.user.id, step.hunt_id]);

      if (myGroup) {
        // Get every user ID in that group
        const [mRows] = await pool.query('SELECT user_id FROM hunt_group_members WHERE group_id = ?', [myGroup.group_id]);
        targetUserIds = mRows.map(r => r.user_id);
      }

      // Update progress for every player in the targetUserIds array
      if (nextStep) {
        await pool.query(
          'UPDATE hunt_progress SET current_step_id=? WHERE hunt_id=? AND user_id IN (?)',
          [nextStep.id, step.hunt_id, targetUserIds]
        );
        reply.send({ success: true, completed: false });
      } else {
        // No more steps: The team has won!
        await pool.query(
          'UPDATE hunt_progress SET completed=1 WHERE hunt_id=? AND user_id IN (?)',
          [step.hunt_id, targetUserIds]
        );
        reply.send({ success: true, completed: true });
      }

    } catch (e) {
      log.err('Submission logic failed', { message: e.message });
      reply.status(500).json({ error: 'Internal server error while verifying submission.' });
    }
  });
};

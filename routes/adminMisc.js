// routes/adminMisc.js
//
// Smaller Storyteller tools that do not warrant a module of their own:
// events, broadcasts, timelines, domain problems, the blood web, audit logs.

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, sendPushNotification, broadcastNtfyAlert } = opts;

  fastify.get('/api/admin/events', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [events] = await pool.query('SELECT * FROM events ORDER BY date ASC');
      reply.send({ events });
    } catch (e) {
      log.err('Admin events fetch failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch events' });
    }
  });

  fastify.post('/api/admin/events', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { title, date_string, description } = req.body;
      await pool.query('INSERT INTO events (title, date, description) VALUES (?, ?, ?)', [title, new Date(date_string), description || null]);
      reply.send({ ok: true });
    } catch (e) {
      log.err('Admin events create failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to create event' });
    }
  });

  fastify.delete('/api/admin/events/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      await pool.query('DELETE FROM events WHERE id=?', [req.params.id]);
      reply.send({ ok: true });
    } catch (e) {
      log.err('Admin events delete failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to delete event' });
    }
  });

  fastify.post('/api/admin/broadcast', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { title, body } = req.body;
      const [users] = await pool.query('SELECT id FROM users');
      let sent = 0;
      for (const u of users) {
        await sendPushNotification(u.id, title, body, {}, 'system');
        sent++;
      }
      log.adm('Global Broadcast Sent', { admin_id: req.user.id, title });
      reply.send({ ok: true, sent_count: sent });
    } catch (e) {
      log.err('Admin broadcast failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to send broadcast' });
    }
  });

  fastify.get('/api/admin/timeline/:charId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const charId = parseInt(req.params.charId, 10);
      const [char] = await pool.query('SELECT name, created_at FROM characters WHERE id=?', [charId]);
      if (!char.length) return reply.status(404).json({ error: 'Character not found' });
      const cname = char[0].name;

      const [xp] = await pool.query('SELECT id, cost, action, target, created_at FROM xp_log WHERE character_id=? ORDER BY created_at DESC LIMIT 500', [charId]);
      const [dice] = await pool.query('SELECT id, pool, successes, hunger, sides, note, created_at FROM dice_rolls WHERE character_id=? ORDER BY created_at DESC LIMIT 500', [charId]);
      const [boons] = await pool.query('SELECT id, from_name, to_name, level, description as details, created_at FROM boons WHERE from_name=? OR to_name=? ORDER BY created_at DESC LIMIT 500', [cname, cname]);
      const [downtimes] = await pool.query('SELECT id, title, status, created_at FROM downtimes WHERE character_id=? ORDER BY created_at DESC LIMIT 500', [charId]);

      const timeline = [];
      timeline.push({ type: 'creation', id: 'creation', timestamp: char[0].created_at, title: 'Character Created', body: 'This character was created in the system.' });
      xp.forEach(x => timeline.push({ type: 'xp', id: x.id, timestamp: x.created_at, delta: -x.cost, reason: `${x.action} ${x.target ? `(${x.target})` : ''}`.trim() }));
      dice.forEach(d => timeline.push({ type: 'dice', id: d.id, timestamp: d.created_at, pool: d.pool, successes: d.successes, hunger: d.hunger, sides: d.sides, note: d.note }));
      downtimes.forEach(dt => timeline.push({ type: 'downtime', id: dt.id, timestamp: dt.created_at, title: dt.title, status: dt.status }));
      boons.forEach(b => {
        const is_debtor = b.from_name === cname;
        timeline.push({ type: 'boon', id: b.id, timestamp: b.created_at, is_debtor, boon_type: b.level, other_name: is_debtor ? b.to_name : b.from_name, details: b.details });
      });

      timeline.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      reply.send({ timeline });
    } catch (e) {
      log.err('Admin timeline failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch timeline' });
    }
  });

  fastify.get('/api/admin/domains-advanced', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [domains] = await pool.query('SELECT division as id, owner_name as name, color, safety_rating FROM domain_claims ORDER BY division ASC');
      const [problems] = await pool.query('SELECT * FROM domain_problems ORDER BY created_at DESC');
      reply.send({ domains, problems });
    } catch (e) {
      console.error('Error fetching advanced domains:', e);
      broadcastNtfyAlert(`API Crash in /api/admin/domains-advanced:\n\n${e.message}`, { title: '🚨 API Error', tags: 'rotating_light,x', priority: 'high', requiresSubscription: 'errors' }).catch(() => { });
      reply.status(500).send({ error: 'Failed to fetch advanced domains', details: e.message, stack: e.stack });
    }
  });

  fastify.post('/api/admin/domains/draw-problems', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [domains] = await pool.query('SELECT division as id FROM domain_claims');
      if (domains.length === 0) return reply.status(400).json({ error: 'No domains exist' });

      const shuffled = domains.sort(() => 0.5 - Math.random());
      const selected = shuffled.slice(0, 3);
      const problemList = [
        // Human / General Problems (-1)
        { text: 'MAT (Riot Police) clash with violent protestors in the streets', penalty: 1 },
        { text: 'Public transport strike causes gridlock and increased police presence', penalty: 1 },
        { text: 'Massive tourist influx floods the night streets, disrupting feeding', penalty: 1 },
        { text: 'New cartel moving highly dangerous synthetic drugs in local clubs', penalty: 1 },
        { text: 'Severe summer heatwave forces mortals to stay out late into the night', penalty: 1 },
        { text: 'Unexpected blackout leaves entire blocks in darkness and panic', penalty: 1 },
        { text: 'Sudden police sweep and checkpoints set up in the area', penalty: 1 },
        { text: 'Major traffic accident blocks key escape routes', penalty: 1 },
        { text: 'Far-right extremist group marching in the streets at night', penalty: 1 },
        { text: 'Organized crime turf war results in public shootings', penalty: 1 },
        { text: 'Large illegal rave draws noise complaints and heavy police attention', penalty: 1 },
        { text: 'Health inspectors cracking down heavily on local night establishments', penalty: 1 },
        { text: 'Sudden influx of homeless camps drawing unwanted municipal sweeps', penalty: 1 },
        { text: 'Flash floods from sudden storm paralyze local infrastructure', penalty: 1 },
        { text: 'Internet/Cellular blackout in the area causes localized panic', penalty: 1 },

        // Occult / Vampire / Supernatural Problems (-2 to -4)
        { text: 'Second Inquisition (Entity) surveillance van spotted monitoring the area', penalty: 3 },
        { text: 'Lupine pack hunting aggressively in the area', penalty: 3 },
        { text: 'Masquerade Breach: Blurry cellphone footage circulating on Greek TikTok', penalty: 3 },
        { text: 'Sabbat infiltrators rumored to be testing the area defenses', penalty: 2 },
        { text: 'Severe Blood Shortage: Local blood banks heavily guarded and mortals staying indoors', penalty: 2 },
        { text: 'Unsanctioned Embrace discovered running wild and terrified', penalty: 2 },
        { text: 'Rogue Ghoul causing a violent scene in a public venue', penalty: 1 },
        { text: 'Hecata necromancers performing highly visible rituals', penalty: 2 },
        { text: 'SI Strike Team heavily armed and raiding a suspected Haven', penalty: 4 },
        { text: 'Tainted Blood: A local mortal drug is making feeding extremely dangerous', penalty: 2 },
        { text: 'Thin-Blood alchemists causing chemical explosions and drawing police', penalty: 2 },
        { text: 'Strange occult graffiti appearing, causing mortal hysteria', penalty: 1 },
        { text: 'A rogue Wraith poltergeist is terrifying locals and making the evening news', penalty: 2 },
        { text: 'Unexplained mortal disappearances attract persistent investigative journalists', penalty: 2 },
        { text: 'Someone is distributing pamphlets exposing local Kindred identities', penalty: 3 },
        { text: 'Feral Gargoyle sighted roosting on a local church', penalty: 2 },
        { text: 'Blood cult of mortals discovered worshipping a mysterious master', penalty: 2 }
      ];

      for (const dom of selected) {
        const prob = problemList[Math.floor(Math.random() * problemList.length)];

        const [[{ unresolvedCount }]] = await pool.query('SELECT COUNT(*) as unresolvedCount FROM domain_problems WHERE domain_id=? AND resolved=0', [dom.id]);
        const totalPenalty = prob.penalty + Number(unresolvedCount);

        await pool.query('INSERT INTO domain_problems (domain_id, problem_text) VALUES (?, ?)', [dom.id, prob.text]);
        await pool.query('UPDATE domain_claims SET safety_rating = GREATEST(safety_rating - ?, 0) WHERE division=?', [totalPenalty, dom.id]);
      }

      await pool.query('INSERT INTO admin_audit_logs (admin_id, action, details) VALUES (?, ?, ?)', [req.user.id, 'DRAW_DOMAIN_PROBLEMS', `Drew monthly problems for ${selected.length} domains.`]);
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to draw problems' });
    }
  });

  fastify.post('/api/admin/domains/custom-problem', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { domain_id, problem_text } = req.body;
      const [[{ unresolvedCount }]] = await pool.query('SELECT COUNT(*) as unresolvedCount FROM domain_problems WHERE domain_id=? AND resolved=0', [domain_id]);
      const penalty = 2 + Number(unresolvedCount);

      await pool.query('INSERT INTO domain_problems (domain_id, problem_text, is_custom) VALUES (?, ?, 1)', [domain_id, problem_text]);
      await pool.query('UPDATE domain_claims SET safety_rating = GREATEST(safety_rating - ?, 0) WHERE division=?', [penalty, domain_id]);
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to add custom problem' });
    }
  });

  fastify.patch('/api/admin/domains/resolve-problem/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      await pool.query('UPDATE domain_problems SET resolved = 1 WHERE id=?', [req.params.id]);
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to resolve problem' });
    }
  });

  fastify.get('/api/admin/blood-web', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [chars] = await pool.query('SELECT c.id, c.name, c.sheet, u.display_name FROM characters c JOIN users u ON c.user_id = u.id WHERE c.is_ex = 0 AND c.is_deceased = 0');
      const web = chars.map(c => {
        let sheet = {};
        try { sheet = typeof c.sheet === 'string' ? JSON.parse(c.sheet) : (c.sheet || {}); } catch (e) { }
        return { id: c.id, name: c.name, player: c.display_name, hunger: Number(sheet.hunger) || 0, bloodPotency: Number(sheet.bloodPotency) || 0 };
      });
      reply.send({ web });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch blood web' });
    }
  });

  fastify.post('/api/admin/blood-web/update', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { id, hunger, bloodPotency } = req.body;
      const [[char]] = await pool.query('SELECT sheet FROM characters WHERE id = ?', [id]);
      if (!char) return reply.status(404).json({ error: 'Character not found' });
      let sheet = {};
      try { sheet = typeof char.sheet === 'string' ? JSON.parse(char.sheet) : (char.sheet || {}); } catch (e) { }
      if (hunger !== undefined) sheet.hunger = Math.max(0, Math.min(5, Number(hunger)));
      if (bloodPotency !== undefined) sheet.bloodPotency = Math.max(0, Math.min(10, Number(bloodPotency)));
      await pool.query('UPDATE characters SET sheet = ? WHERE id = ?', [JSON.stringify(sheet), id]);
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to update character' });
    }
  });

  fastify.post('/api/admin/masquerade-threat', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { level } = req.body;
      await pool.query('INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value=?', ['masquerade_threat_level', String(level), String(level)]);
      await pool.query('INSERT INTO admin_audit_logs (admin_id, action, details) VALUES (?, ?, ?)', [req.user.id, 'SET_MASQUERADE_THREAT', `Threat level set to ${level}`]);
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to update threat level' });
    }
  });

  fastify.get('/api/admin/coteries', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [coteries] = await pool.query('SELECT * FROM coteries');
      // Joins on the recorded character_id rather than user_id: the old join
      // duplicated rows (and picked an arbitrary name) for any user holding
      // more than one character, and dropped members whose character was gone.
      const [members] = await pool.query(
        `SELECT cm.*, COALESCE(c.name, cm.display_name) AS char_name, c.clan
         FROM coterie_members cm
         LEFT JOIN characters c ON c.id = cm.character_id`
      );
      reply.send({ coteries, members });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch coteries' });
    }
  });

  fastify.get('/api/admin/audit-logs', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [logs] = await pool.query('SELECT a.*, u.display_name as admin_name FROM admin_audit_logs a LEFT JOIN users u ON a.admin_id = u.id ORDER BY a.created_at DESC LIMIT 500');
      reply.send({ logs });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch audit logs' });
    }
  });
};

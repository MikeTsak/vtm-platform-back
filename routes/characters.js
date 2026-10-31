const { getSetting } = require('../utils/settings');
const { attachFeeding } = require('../services/ghoulFeeding');
const { checkGhoulGift } = require('../utils/ghoulBlood');
const { withSetOnceDates, RETAINER_DATES } = require('../utils/sheetDates');
const { keepTrackers, ghoulTrackers } = require('../services/ghoulTrackers');
const { DEFAULT_DISABLED_CLANS } = require('../utils/clans');
const { isAdmin, userOwnsCharacter } = require('../services/guards');
const { parseSheet } = require('../utils/sheet');
const { mergePlayerSheetEdit } = require('../utils/playerSheetEdit');
const { retireCharacter } = require('../services/characterRetirement');

async function isClanDisabled(clan) {
  const raw = await getSetting('disabled_clans', JSON.stringify(DEFAULT_DISABLED_CLANS));
  let disabledClans;
  try { disabledClans = JSON.parse(raw); } catch { disabledClans = DEFAULT_DISABLED_CLANS; }
  return disabledClans.includes(clan);
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, moderateLimiter, requireAdmin, validateRetainerSheet, getMimeType, sharp, broadcastNtfyAlert } = opts;

  // A player saving their own sheet: only the narrative and live-session
  // fields are taken from the request (utils/playerSheetEdit.js). Dots,
  // powers and merits change through XP purchases; name and clan through a
  // Storyteller. Storytellers edit freely via /api/characters/user/:id.
  async function updateOwnCharacter(req, reply) {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [[row]] = await conn.query('SELECT id, clan, sheet FROM characters WHERE user_id=? FOR UPDATE', [req.user.id]);
      if (!row) {
        await conn.rollback();
        log.warn('Update character not found', { user_id: req.user.id });
        return reply.status(404).send({ error: 'No character' });
      }
      const incoming = req.body?.sheet;
      if (!incoming || typeof incoming !== 'object') {
        await conn.rollback();
        return reply.status(400).send({ error: 'Nothing to update' });
      }
      // Storytellers are trusted with their own sheet as with everyone else's.
      const next = isAdmin(req.user) ? incoming : mergePlayerSheetEdit(row.sheet, incoming, row.clan);
      await conn.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(next), row.id]);
      await conn.commit();

      const [[ch]] = await pool.query('SELECT * FROM characters WHERE id=?', [row.id]);
      if (ch) ch.sheet = parseSheet(ch.sheet);
      log.char('Character updated', { id: row.id, user_id: req.user.id });
      return reply.send({ character: ch });
    } catch (e) {
      await conn.rollback().catch(() => {});
      throw e;
    } finally {
      conn.release();
    }
  }
  /* -------------------- Characters -------------------- */
  // Get my character (parse sheet if string)
  fastify.get('/api/characters/me', { preHandler: [authRequired] }, async (req, reply) => {
    // Prevent ghost caching
    reply.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');

    const [rows] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
    const ch = rows[0] || null;

    if (ch) ch.sheet = parseSheet(ch.sheet);

    log.char('Fetch my character', { user_id: req.user.id, hasCharacter: !!ch });

    // Manually stringify and set Content-Length to bypass Fastify/Proxy chunking bugs
    const payload = JSON.stringify({ character: ch });

    return reply
      .header('Content-Type', 'application/json; charset=utf-8')
      .header('Content-Length', Buffer.byteLength(payload))
      .send(payload);
  });

  // Update my character (optional)
  fastify.put('/api/characters/me', { preHandler: [authRequired] }, async (req, reply) => {
    return updateOwnCharacter(req, reply);
  });

  /**
   * @swagger
   * /api/characters:
   *   post:
   *     summary: Create a new character
   *     description: Creates a new character for the authenticated user with starting XP of 50
   *     tags: [Characters]
   *     security:
   *       - bearerAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - name
   *               - clan
   *             properties:
   *               name:
   *                 type: string
   *                 description: Character name
   *                 example: Marcus Valerius
   *               clan:
   *                 type: string
   *                 description: Vampire clan
   *                 example: Ventrue
   *               sheet:
   *                 type: object
   *                 description: Character sheet data (optional)
   *                 example: { "strength": 3, "dexterity": 2 }
   *     responses:
   *       200:
   *         description: Character successfully created
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 character:
   *                   $ref: '#/components/schemas/Character'
   *       400:
   *         description: Missing required fields
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/Error'
   *       401:
   *         description: Unauthorized - Missing or invalid token
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/Error'
   *       409:
   *         description: Character already exists for this user
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/Error'
   *       500:
   *         description: Server error
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/Error'
   */
  // Create character (stores sheet JSON and xp=50)
  fastify.post('/api/characters', { preHandler: [authRequired, moderateLimiter] }, async (req, reply) => {
    const { name, clan, sheet } = req.body;
    if (!name || !clan) {
      log.warn('Create character missing fields', { user_id: req.user.id });
      return reply.status(400).send({ error: 'Name and clan are required' });
    }

    if (await isClanDisabled(clan)) {
      log.warn('Create character disabled clan', { user_id: req.user.id, clan });
      return reply.status(400).send({ error: `${clan} is not currently available for character creation` });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      // A character that met Final Death (Storyteller-set is_deceased) is
      // retired here, so the player can start their next one. Any other
      // current character blocks creation.
      const [[current]] = await conn.query('SELECT id, is_deceased FROM characters WHERE user_id=? FOR UPDATE', [req.user.id]);
      if (current && !current.is_deceased) {
        await conn.rollback();
        log.warn('Create character already exists', { user_id: req.user.id });
        return reply.status(409).send({ error: 'Character already exists' });
      }
      if (current) await retireCharacter(conn, current.id);

      let sheetObj = parseSheet(sheet);
      sheetObj.is_active = false;
      delete sheetObj.allow_reset; // only a Storyteller grants re-rolls

      const [r] = await conn.query(
        'INSERT INTO characters (user_id, name, clan, sheet, xp) VALUES (?,?,?,?,?)',
        [req.user.id, name, clan, JSON.stringify(sheetObj), 50]
      );
      await conn.commit();

      const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [r.insertId]);
      const ch = rows[0];
      if (ch) ch.sheet = parseSheet(ch.sheet);
      if (current) log.char('Deceased character retired', { id: current.id, user_id: req.user.id });
      log.char('Character created', { id: r.insertId, user_id: req.user.id, name, clan, xp: ch?.xp });
      broadcastNtfyAlert(`**${name}** (Clan: **${clan}**) was created by ${req.user.display_name} (${req.user.id}).`, { title: 'New Character', tags: 'vampire', priority: 'default' });
      reply.send({ character: ch });
    } catch (e) {
      await conn.rollback().catch(() => {});
      log.err('Failed to create character', e);
      reply.status(500).send({ error: 'Failed to create character' });
    } finally {
      conn.release();
    }
  });

  // Every character this account has played: the current one first, then
  // retired ones, newest retirement first.
  fastify.get('/api/characters/mine', { preHandler: [authRequired] }, async (req, reply) => {
    const [characters] = await pool.query(
      `SELECT id, name, clan, image_url, xp, is_deceased, created_at, retired_at, (user_id IS NOT NULL) AS is_current
         FROM characters WHERE user_id = ? OR retired_user_id = ?
        ORDER BY is_current DESC, retired_at DESC`,
      [req.user.id, req.user.id]
    );
    reply.send({ characters });
  });

  // A retired character's sheet, read-only (nothing writes through this path).
  fastify.get('/api/characters/archive/:id', { preHandler: [authRequired] }, async (req, reply) => {
    const [[ch]] = await pool.query(
      'SELECT * FROM characters WHERE id = ? AND retired_user_id = ?', [req.params.id, req.user.id]
    );
    if (!ch) return reply.status(404).send({ error: 'Character not found' });
    ch.sheet = parseSheet(ch.sheet);
    reply.send({ character: ch });
  });

  /**
   * @swagger
   * /api/characters:
   *   put:
   *     summary: Update character
   *     description: Updates the authenticated user's character information
   *     tags: [Characters]
   *     security:
   *       - bearerAuth: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               name:
   *                 type: string
   *                 description: Character name (optional)
   *                 example: Marcus Valerius
   *               clan:
   *                 type: string
   *                 description: Vampire clan (optional)
   *                 example: Ventrue
   *               sheet:
   *                 type: object
   *                 description: Character sheet data (optional)
   *                 example: { "strength": 4, "dexterity": 3 }
   *     responses:
   *       200:
   *         description: Character successfully updated
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 character:
   *                   $ref: '#/components/schemas/Character'
   *       400:
   *         description: No fields to update
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/Error'
   *       401:
   *         description: Unauthorized - Missing or invalid token
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/Error'
   *       404:
   *         description: Character not found
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/Error'
   *       500:
   *         description: Server error
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/Error'
   */
  // Update my character (optional)
  fastify.put('/api/characters', { preHandler: [authRequired] }, async (req, reply) => {
    return updateOwnCharacter(req, reply);
  });

  // GET a specific character by ID (Admin only — mirrors the PUT below; a
  // player's own sheet is served by /api/characters/me instead)
  fastify.get('/api/characters/user/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [req.params.id]);
      const ch = rows[0] || null;
      if (ch) ch.sheet = parseSheet(ch.sheet);
      log.char('Fetch character by ID', { target_id: req.params.id, hasCharacter: !!ch });
      reply.send({ character: ch });
    } catch (e) {
      log.err('Failed to fetch character by ID', e);
      reply.status(500).send({ error: 'Failed to fetch character' });
    }
  });

  // PUT update a specific character by ID (For Admins)
  fastify.put('/api/characters/user/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const { name, clan, sheet } = req.body;
    const charId = req.params.id;

    const [rows] = await pool.query('SELECT id FROM characters WHERE id=?', [charId]);
    if (!rows.length) {
      return reply.status(404).send({ error: 'No character found' });
    }

    const fields = [], vals = [];
    if (name) { fields.push('name=?'); vals.push(name); }
    if (clan) { fields.push('clan=?'); vals.push(clan); }
    if (sheet !== undefined) { fields.push('sheet=?'); vals.push(sheet ? JSON.stringify(sheet) : null); }

    if (!fields.length) {
      return reply.status(400).send({ error: 'Nothing to update' });
    }

    vals.push(charId);
    await pool.query(`UPDATE characters SET ${fields.join(', ')} WHERE id=?`, vals);

    if (sheet !== undefined) {
      try {
        await pool.query(
          'INSERT INTO character_sheet_versions (character_id, editor_id, sheet, change_summary) VALUES (?, ?, ?, ?)',
          [charId, req.user?.id || null, sheet ? JSON.stringify(sheet) : null, 'Admin character sheet edit']
        );
      } catch (err) {
        // Non-fatal
      }
    }

    const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [charId]);
    const ch = out[0];
    if (ch) ch.sheet = parseSheet(ch.sheet);

    log.char('Character updated by Admin', { id: charId, admin_id: req.user.id });
    reply.send({ character: ch });
  });

  // Inventory lives in routes/inventory.js.


  // ================== Retainers ==================
  // GET a character's retainers (owner or admin)
  fastify.get('/api/characters/:id/retainers', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const charId = Number(req.params.id);
      if (!isAdmin(req.user) && !(await userOwnsCharacter(pool, req.user.id, charId))) {
        return reply.status(403).send({ error: 'Unauthorized' });
      }

      const [rows] = await pool.query('SELECT id, character_id, name, tier, sheet, xp, created_at, is_favorite FROM retainers WHERE character_id=?', [charId]);
      const results = [];
      for (const row of rows) {
        row.sheet = parseSheet(row.sheet);
        results.push({ ...row, trackers: ghoulTrackers(row.sheet || {}) }); // Ensure it's a plain object
      }
      await attachFeeding(pool, results);
        const payload = JSON.stringify(results);
        return reply
          .header('Content-Type', 'application/json; charset=utf-8')
          .header('Content-Length', Buffer.byteLength(payload))
          .send(payload);
    } catch (e) {
      log.err('Failed to get retainers', { message: e.message, character_id: req.params.id });
      reply.status(500).send({ error: 'Failed to fetch retainers' });
    }
  });
  
  // Retainers are bought with the owner's XP at the Retainers background
  // rate, charged here in the same transaction as the retainer row so the two
  // can't drift apart (the client used to pay through a separate spend call
  // it could simply skip).
  const RETAINER_XP_PER_TIER = 3;
  // `cost` may be a function of the open connection, so it is worked out
  // after the lock is taken (an upgrade must price against the tier as it is
  // now, not as a racing request saw it).
  async function withRetainerCharge(charId, costOrFn, label, write) {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      // Locking the owner first serializes every retainer change for this
      // character, so a burst of identical clicks runs one at a time.
      const [[ch]] = await conn.query('SELECT xp FROM characters WHERE id=? FOR UPDATE', [charId]);
      const cost = typeof costOrFn === 'function' ? await costOrFn(conn) : costOrFn;
      if (cost > 0) {
        if (!ch || Number(ch.xp) < cost) {
          throw Object.assign(new Error(`Not enough XP (need ${cost}, have ${Number(ch?.xp) || 0})`), { status: 400 });
        }
        await conn.query('UPDATE characters SET xp = xp - ? WHERE id=?', [cost, charId]);
        await conn.query(
          'INSERT INTO xp_log (character_id, action, target, cost, payload) VALUES (?,?,?,?,?)',
          [charId, 'advantage', label.slice(0, 120), cost, JSON.stringify({ retainer: true })]
        );
      }
      const result = await write(conn);
      await conn.commit();
      return result;
    } catch (e) {
      await conn.rollback().catch(() => {});
      throw e;
    } finally {
      conn.release();
    }
  }

  // A personal ghoul drinks its owner's blood: their highest-rated Discipline and
  // a level 1 power they own (utils/ghoulBlood.js). Error string or null.
  async function ghoulGiftOf(charId, sheet, oldSheet) {
    if (sheet?.isGhoul !== true) return null;
    const [[owner]] = await pool.query('SELECT sheet FROM characters WHERE id=?', [charId]);
    return checkGhoulGift(parseSheet(owner && owner.sheet) || {}, sheet, oldSheet, 'your character');
  }

  // Create a retainer on a character (owner or admin)
  fastify.post('/api/characters/:id/retainers', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const charId = Number(req.params.id);
      if (!isAdmin(req.user) && !(await userOwnsCharacter(pool, req.user.id, charId))) {
        return reply.status(403).send({ error: 'Unauthorized' });
      }

      const { name } = req.body;
      const admin = isAdmin(req.user);
      // A player's dates are set once from here on (utils/sheetDates.js).
      const sheet = keepTrackers(null, admin ? req.body.sheet : withSetOnceDates({}, req.body.sheet, RETAINER_DATES));
      const tier = Number(req.body.tier || 1);
      if (!Number.isInteger(tier) || tier < 1 || tier > 4) return reply.status(400).send({ error: 'Tier must be 1 to 4.' });
      // A retainer's own XP is the Storyteller's to set.
      const xp = admin ? Number(req.body.xp) || 0 : 0;

      const isGhoul = sheet?.isGhoul === true;
      const validationError = validateRetainerSheet(tier, sheet, isGhoul)
        || (!admin && await ghoulGiftOf(charId, sheet, null));
      if (validationError) {
        return reply.status(400).send({ error: validationError });
      }

      const id = await withRetainerCharge(charId, admin ? 0 : tier * RETAINER_XP_PER_TIER, `Recruit Tier ${tier} Retainer: ${name}`, async (conn) => {
        // One retainer per name: a double-clicked "Confirm & Pay" recruits once.
        const [[dupe]] = await conn.query('SELECT id FROM retainers WHERE character_id=? AND name=?', [charId, name]);
        if (dupe) throw Object.assign(new Error(`You already have a retainer named ${name}.`), { status: 409 });
        const [result] = await conn.query(
          'INSERT INTO retainers (character_id, name, tier, sheet, xp) VALUES (?, ?, ?, ?, ?)',
          [charId, name, tier, JSON.stringify(sheet || {}), xp]
        );
        return result.insertId;
      });
      reply.send({ id, character_id: charId, name, tier, sheet, xp });
    } catch (e) {
      if (e.status) return reply.status(e.status).send({ error: e.message });
      log.err('Failed to create retainer', { message: e.message, character_id: req.params.id });
      reply.status(500).send({ error: 'Failed to create retainer' });
    }
  });

  fastify.put('/api/retainers/:retainerId/favorite', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { is_favorite } = req.body;
      // Check ownership
      const [rows] = await pool.query(
        'SELECT r.id FROM retainers r JOIN characters c ON r.character_id = c.id WHERE r.id = ? AND c.user_id = ?',
        [req.params.retainerId, req.user.id]
      );
      if (rows.length === 0) return reply.status(403).send({ error: 'Not authorized or retainer not found' });
      
      await pool.query('UPDATE retainers SET is_favorite = ? WHERE id = ?', [is_favorite ? 1 : 0, req.params.retainerId]);
      reply.send({ success: true, is_favorite: !!is_favorite });
    } catch (e) {
      log.err('Failed to update favorite status', { message: e.message, retainerId: req.params.retainerId });
      reply.status(500).send({ error: 'Failed to update favorite status' });
    }
  });


  fastify.put('/api/retainers/:retainerId/upgrade', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { name } = req.body;
      let { sheet } = req.body;
      const tier = Number(req.body.tier);
      if (!Number.isInteger(tier) || tier < 1 || tier > 4) return reply.status(400).send({ error: 'Tier must be 1 to 4.' });

      // Check ownership
      const [rows] = await pool.query(
        'SELECT r.* FROM retainers r JOIN characters c ON r.character_id = c.id WHERE r.id = ? AND c.user_id = ?',
        [req.params.retainerId, req.user.id]
      );
      if (rows.length === 0) return reply.status(403).send({ error: 'Not authorized or retainer not found' });
      const oldRetainer = rows[0];
      sheet = keepTrackers(parseSheet(oldRetainer.sheet), withSetOnceDates(parseSheet(oldRetainer.sheet), sheet, RETAINER_DATES));

      // Ensure tier is only going up or staying the same
      if (tier < oldRetainer.tier) {
        return reply.status(400).send({ error: 'Cannot downgrade tier via upgrade route.' });
      }

      // Strict V5 Validation
      const isGhoul = sheet?.isGhoul === true;
      const validationError = validateRetainerSheet(Number(tier), sheet, isGhoul)
        || await ghoulGiftOf(oldRetainer.character_id, sheet, parseSheet(oldRetainer.sheet));
      if (validationError) {
        return reply.status(400).send({ error: validationError });
      }

      const priceNow = async (conn) => {
        const [[current]] = await conn.query('SELECT tier FROM retainers WHERE id=? FOR UPDATE', [req.params.retainerId]);
        if (tier < Number(current.tier)) throw Object.assign(new Error('Cannot downgrade tier via upgrade route.'), { status: 400 });
        return (tier - Number(current.tier)) * RETAINER_XP_PER_TIER;
      };
      await withRetainerCharge(oldRetainer.character_id, priceNow, `Upgrade Retainer ${oldRetainer.name} to Tier ${tier}`, (conn) => conn.query(
        'UPDATE retainers SET name=?, tier=?, sheet=? WHERE id=?',
        [name || oldRetainer.name, tier, JSON.stringify(sheet), req.params.retainerId]
      ));
      
      const [updatedRows] = await pool.query('SELECT * FROM retainers WHERE id=?', [req.params.retainerId]);
      if (updatedRows.length > 0) {
         const ret = updatedRows[0];
         ret.sheet = parseSheet(ret.sheet);
         reply.send(ret);
      } else {
         reply.send({ success: true });
      }
    } catch (e) {
      if (e.status) return reply.status(e.status).send({ error: e.message });
      log.err('Failed to upgrade retainer', { message: e.message, retainer_id: req.params.retainerId });
      reply.status(500).send({ error: 'Failed to upgrade retainer' });
    }
  });

  fastify.put('/api/retainers/:retainerId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { name, tier, xp } = req.body;
      const retainerId = req.params.retainerId;
      // Health/Willpower change only through the tracker routes (services/ghoulTrackers.js).
      const [[stored]] = await pool.query('SELECT sheet FROM retainers WHERE id=?', [retainerId]);
      const sheet = keepTrackers(parseSheet(stored && stored.sheet), req.body.sheet);

      // Strict V5 Validation
      const isGhoul = sheet?.isGhoul === true;
      const validationError = validateRetainerSheet(Number(tier), sheet, isGhoul);
      if (validationError) {
        return reply.status(400).send({ error: validationError });
      }

      await pool.query(
        'UPDATE retainers SET name=?, tier=?, sheet=?, xp=? WHERE id=?',
        [name, tier, JSON.stringify(sheet), xp, retainerId]
      );
      
      const [updatedRows] = await pool.query('SELECT * FROM retainers WHERE id=?', [retainerId]);
      if (updatedRows.length > 0) {
         const ret = updatedRows[0];
         ret.sheet = parseSheet(ret.sheet);
         reply.send(ret);
      } else {
         reply.send({ success: true });
      }
    } catch (e) {
      log.err('Failed to update retainer', { message: e.message, retainer_id: req.params.retainerId });
      reply.status(500).send({ error: 'Failed to update retainer' });
    }
  });

  fastify.delete('/api/retainers/:retainerId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      await pool.query('DELETE FROM retainers WHERE id=?', [req.params.retainerId]);
      reply.send({ success: true });
    } catch (e) {
      log.err('Failed to delete retainer', { message: e.message, retainer_id: req.params.retainerId });
      reply.status(500).send({ error: 'Failed to delete retainer' });
    }
  });

  fastify.put('/api/admin/characters/:id/reset', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const charId = req.params.id;

      // 1. Clear XP logs so math doesn't break for the new sheet
      try { await pool.query('DELETE FROM xp_log WHERE character_id=?', [charId]); } catch (e) { }

      // 2. Reset sheet to NULL and XP to 50
      await pool.query('UPDATE characters SET sheet=NULL, xp=50 WHERE id=?', [charId]);

      const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [charId]);
      log.adm('Character reset by admin', { id: charId, admin_id: req.user.id });
      reply.send({ character: rows[0] });
    } catch (e) {
      log.err('Admin reset character failed', { message: e.message, id: req.params.id });
      reply.status(500).send({ error: 'Failed to reset character' });
    }
  });

  // Rebuild character (overwrites sheet, resets to 50 XP, keeps ID)
  fastify.post('/api/characters/rebuild', { preHandler: [authRequired] }, async (req, reply) => {
    const { name, clan, sheet } = req.body;
    if (!name || !clan) {
      log.warn('Rebuild character missing fields', { user_id: req.user.id });
      return reply.status(400).send({ error: 'Name and clan are required' });
    }

    if (await isClanDisabled(clan)) {
      log.warn('Rebuild character disabled clan', { user_id: req.user.id, clan });
      return reply.status(400).send({ error: `${clan} is not currently available for character creation` });
    }

    try {
      // Find the user's existing character
      const [rows] = await pool.query('SELECT id, sheet FROM characters WHERE user_id=?', [req.user.id]);
      if (!rows.length) {
        return reply.status(404).send({ error: 'No character found to rebuild' });
      }
      // A rebuild wipes XP history and starts over, so only when a
      // Storyteller has granted a re-roll (Admin > Characters > Allow Re-Roll).
      if (parseSheet(rows[0].sheet)?.allow_reset !== true) {
        log.warn('Rebuild refused: no re-roll granted', { user_id: req.user.id });
        return reply.status(403).send({ error: 'Your Storyteller has not allowed a re-roll for this character.' });
      }

      const charId = rows[0].id;

      // Wipe the old XP log so they start totally fresh
      try {
        await pool.query('DELETE FROM xp_log WHERE character_id=?', [charId]);
      } catch (e) { /* ignore if table missing */ }

      let sheetObj = parseSheet(sheet);
      sheetObj.is_active = false;
      delete sheetObj.allow_reset; // one re-roll per grant

      // Overwrite the character data and reset XP to 50
      const rebuildSheetJson = JSON.stringify(sheetObj);
      await pool.query(
        'UPDATE characters SET name=?, clan=?, sheet=?, xp=50 WHERE id=?',
        [name, clan, rebuildSheetJson, charId]
      );
      try {
        await pool.query(
          'INSERT INTO character_sheet_versions (character_id, editor_id, sheet, change_summary) VALUES (?, ?, ?, ?)',
          [charId, req.user?.id || null, rebuildSheetJson, 'Character rebuild']
        );
      } catch (err) {
        // Non-fatal
      }

      // Fetch and return the updated character
      const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [charId]);
      const ch = out[0];
      if (ch) ch.sheet = parseSheet(ch.sheet);

      log.char('Character rebuilt', { id: charId, user_id: req.user.id, name, clan });
      reply.send({ character: ch });
    } catch (e) {
      log.err('Failed to rebuild character', e);
      reply.status(500).send({ error: 'Failed to rebuild character' });
    }
  });


};


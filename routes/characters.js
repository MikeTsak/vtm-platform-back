const { getSetting } = require('../utils/settings');
const { DEFAULT_DISABLED_CLANS } = require('../utils/clans');
const { isAdmin, userOwnsCharacter } = require('../services/guards');
const { parseSheet } = require('../utils/sheet');
const { mergePlayerSheetEdit } = require('../utils/playerSheetEdit');

async function isClanDisabled(clan) {
  const raw = await getSetting('disabled_clans', JSON.stringify(DEFAULT_DISABLED_CLANS));
  let disabledClans;
  try { disabledClans = JSON.parse(raw); } catch { disabledClans = DEFAULT_DISABLED_CLANS; }
  return disabledClans.includes(clan);
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, moderateLimiter, requireAdmin, validateRetainerSheet, getMimeType, sharp, imageClient, broadcastNtfyAlert } = opts;

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
      return reply.status(400).json({ error: 'Name and clan are required' });
    }

    if (await isClanDisabled(clan)) {
      log.warn('Create character disabled clan', { user_id: req.user.id, clan });
      return reply.status(400).json({ error: `${clan} is not currently available for character creation` });
    }

    try {
      const [exists] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
      if (exists.length) {
        log.warn('Create character already exists', { user_id: req.user.id });
        return reply.status(409).json({ error: 'Character already exists' });
      }

      let sheetObj = parseSheet(sheet);
      sheetObj.is_active = false;
      delete sheetObj.allow_reset; // only a Storyteller grants re-rolls

      const [r] = await pool.query(
        'INSERT INTO characters (user_id, name, clan, sheet, xp) VALUES (?,?,?,?,?)',
        [req.user.id, name, clan, JSON.stringify(sheetObj), 50]
      );

      const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [r.insertId]);
      const ch = rows[0];
      if (ch) ch.sheet = parseSheet(ch.sheet);
      log.char('Character created', { id: r.insertId, user_id: req.user.id, name, clan, xp: ch?.xp });
      broadcastNtfyAlert(`**${name}** (Clan: **${clan}**) was created by ${req.user.display_name} (${req.user.id}).`, { title: 'New Character', tags: 'vampire', priority: 'default' });
      reply.send({ character: ch });
    } catch (e) {
      log.err('Failed to create character', e);
      reply.status(500).json({ error: 'Failed to create character' });
    }
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
      reply.status(500).json({ error: 'Failed to fetch character' });
    }
  });

  // PUT update a specific character by ID (For Admins)
  fastify.put('/api/characters/user/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const { name, clan, sheet } = req.body;
    const charId = req.params.id;

    const [rows] = await pool.query('SELECT id FROM characters WHERE id=?', [charId]);
    if (!rows.length) {
      return reply.status(404).json({ error: 'No character found' });
    }

    const fields = [], vals = [];
    if (name) { fields.push('name=?'); vals.push(name); }
    if (clan) { fields.push('clan=?'); vals.push(clan); }
    if (sheet !== undefined) { fields.push('sheet=?'); vals.push(sheet ? JSON.stringify(sheet) : null); }

    if (!fields.length) {
      return reply.status(400).json({ error: 'Nothing to update' });
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

  // ==========================================
  // INVENTORY ROUTES
  // ==========================================

  // Mirrors the enum on inventory_items.item_type. Anything else makes
  // MariaDB raise 'Data truncated for column', which surfaced as a 500;
  // a bad type is the caller's mistake, so answer 400.
  const ITEM_TYPES = ['Relic', 'Artifact', 'Blood Magic', 'Weapon', 'Armor', 'Mundane'];

  // A data: URL is pushed to the image CDN and replaced by its https URL.
  // Anything else (an existing CDN url, or null) is passed through.
  const resolveItemImage = async (image, charId) => {
    if (!image || !String(image).startsWith('data:image')) return image || null;
    try {
      const base64Data = image.split(';base64,').pop();
      const buffer = Buffer.from(base64Data, 'base64');
      const extMatch = image.match(/data:image\/([a-zA-Z0-9]+);/);
      const ext = extMatch ? extMatch[1] : 'jpeg';
      const result = await imageClient.uploadImage(buffer, `inventory_${charId}_${Date.now()}.${ext}`);
      if (result && result.success) return result.url;
      log.warn('Inventory image upload failed, setting to null');
      return null;
    } catch (err) {
      log.err('Error uploading inventory image', { error: err.message });
      return null;
    }
  };

  // quantity is optional, but 0 and negatives are meaningless for an
  // inventory row. `quantity || 1` also turned a deliberate 0 into 1,
  // so be explicit about the floor.
  const normaliseQty = (q) => {
    const n = Number(q);
    return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 1;
  };

  // GET: Fetch a character's inventory (owner or admin — mirrors POST/PUT/DELETE below)
  fastify.get('/api/characters/:id/inventory', { preHandler: [authRequired] }, async (req, reply) => {
    // Prevent ghost caching of items
    reply.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');

    try {
      const charId = Number(req.params.id);
      if (!isAdmin(req.user) && !(await userOwnsCharacter(pool, req.user.id, charId))) {
        return reply.status(403).json({ error: 'Unauthorized' });
      }

      const [items] = await pool.query(
        'SELECT * FROM inventory_items WHERE character_id = ? ORDER BY item_type, name',
        [charId]
      );
      reply.send({ items });
    } catch (e) {
      log.err('Failed to fetch inventory', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch inventory' });
    }
  });

  // POST: Add a new item
  fastify.post('/api/characters/:id/inventory', { preHandler: [authRequired] }, async (req, reply) => {
    const charId = Number(req.params.id);
    const { name, item_type, description, mechanic_notes, quantity, image, researched } = req.body;

    if (!name) return reply.status(400).json({ error: 'Item name is required' });
    if (item_type && !ITEM_TYPES.includes(item_type)) {
      return reply.status(400).json({ error: `Invalid item type. Expected one of: ${ITEM_TYPES.join(', ')}` });
    }

    try {
      if (!isAdmin(req.user) && !(await userOwnsCharacter(pool, req.user.id, charId))) {
        return reply.status(403).json({ error: 'Unauthorized' });
      }

      const finalImage = await resolveItemImage(image, charId);

      const [r] = await pool.query(
        `INSERT INTO inventory_items (character_id, name, item_type, description, mechanic_notes, quantity, image, researched, granted_by) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [charId, name, item_type || 'Mundane', description || null, mechanic_notes || null, normaliseQty(quantity), finalImage, researched ? 1 : 0, req.user?.id || null]
      );

      const [[newItem]] = await pool.query('SELECT * FROM inventory_items WHERE id = ?', [r.insertId]);
      reply.status(201).json({ item: newItem });
    } catch (e) {
      log.err('Failed to add inventory item', { message: e.message });
      reply.status(500).json({ error: 'Failed to add item' });
    }
  });

  // PUT: Edit an existing item
  fastify.put('/api/characters/:id/inventory/:itemId', { preHandler: [authRequired] }, async (req, reply) => {
    const charId = Number(req.params.id);
    const itemId = Number(req.params.itemId);
    const { name, item_type, description, mechanic_notes, quantity, image, researched } = req.body;

    if (!name) return reply.status(400).json({ error: 'Item name is required' });
    if (item_type && !ITEM_TYPES.includes(item_type)) {
      return reply.status(400).json({ error: `Invalid item type. Expected one of: ${ITEM_TYPES.join(', ')}` });
    }

    try {
      if (!isAdmin(req.user) && !(await userOwnsCharacter(pool, req.user.id, charId))) {
        return reply.status(403).json({ error: 'Unauthorized' });
      }

      // An absent `image` key means 'leave the picture alone'; an explicit
      // null clears it. Previously any PUT without the field silently wiped
      // the image, because `image || null` cannot tell the two apart.
      let finalImage;
      if (!Object.prototype.hasOwnProperty.call(req.body || {}, 'image')) {
        const [[current]] = await pool.query('SELECT image FROM inventory_items WHERE id=? AND character_id=?', [itemId, charId]);
        if (!current) return reply.status(404).json({ error: 'Item not found' });
        finalImage = current.image;
      } else {
        finalImage = await resolveItemImage(image, charId);
      }

      const [result] = await pool.query(
        `UPDATE inventory_items 
       SET name=?, item_type=?, description=?, mechanic_notes=?, quantity=?, image=?, researched=? 
       WHERE id=? AND character_id=?`,
        [name, item_type || 'Mundane', description || null, mechanic_notes || null, normaliseQty(quantity), finalImage, researched ? 1 : 0, itemId, charId]
      );

      // affectedRows 0 means the id/character pair matched nothing — a wrong
      // id used to answer 200, so the client believed a lost edit had saved.
      if (!result.affectedRows) return reply.status(404).json({ error: 'Item not found' });

      const [[updated]] = await pool.query('SELECT * FROM inventory_items WHERE id = ?', [itemId]);
      reply.send({ success: true, item: updated });
    } catch (e) {
      log.err('Failed to update inventory item', { message: e.message });
      reply.status(500).json({ error: 'Failed to update item' });
    }
  });

  // DELETE: Remove an item
  fastify.delete('/api/characters/:id/inventory/:itemId', { preHandler: [authRequired] }, async (req, reply) => {
    const charId = Number(req.params.id);
    const itemId = Number(req.params.itemId);

    try {
      if (!isAdmin(req.user) && !(await userOwnsCharacter(pool, req.user.id, charId))) {
        return reply.status(403).json({ error: 'Unauthorized' });
      }

      const [result] = await pool.query('DELETE FROM inventory_items WHERE id=? AND character_id=?', [itemId, charId]);
      if (!result.affectedRows) return reply.status(404).json({ error: 'Item not found' });
      reply.send({ success: true });
    } catch (e) {
      log.err('Failed to delete inventory item', { message: e.message });
      reply.status(500).json({ error: 'Failed to delete item' });
    }
  });

  // --- Character Personal Inventory ---

  // ================== Retainers ==================
  // GET a character's retainers (owner or admin)
  fastify.get('/api/characters/:id/retainers', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const charId = Number(req.params.id);
      if (!isAdmin(req.user) && !(await userOwnsCharacter(pool, req.user.id, charId))) {
        return reply.status(403).json({ error: 'Unauthorized' });
      }

      const [rows] = await pool.query('SELECT id, character_id, name, tier, sheet, xp, created_at, is_favorite FROM retainers WHERE character_id=?', [charId]);
      const results = [];
      for (const row of rows) {
        row.sheet = parseSheet(row.sheet);
        results.push({ ...row }); // Ensure it's a plain object
      }
        const payload = JSON.stringify(results);
        return reply
          .header('Content-Type', 'application/json; charset=utf-8')
          .header('Content-Length', Buffer.byteLength(payload))
          .send(payload);
    } catch (e) {
      log.err('Failed to get retainers', { message: e.message, character_id: req.params.id });
      reply.status(500).json({ error: 'Failed to fetch retainers' });
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

  // Create a retainer on a character (owner or admin)
  fastify.post('/api/characters/:id/retainers', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const charId = Number(req.params.id);
      if (!isAdmin(req.user) && !(await userOwnsCharacter(pool, req.user.id, charId))) {
        return reply.status(403).json({ error: 'Unauthorized' });
      }

      const { name, sheet } = req.body;
      const admin = isAdmin(req.user);
      const tier = Number(req.body.tier || 1);
      if (!Number.isInteger(tier) || tier < 1 || tier > 4) return reply.status(400).json({ error: 'Tier must be 1 to 4.' });
      // A retainer's own XP is the Storyteller's to set.
      const xp = admin ? Number(req.body.xp) || 0 : 0;

      const isGhoul = sheet?.isGhoul === true;
      const validationError = validateRetainerSheet(tier, sheet, isGhoul);
      if (validationError) {
        return reply.status(400).json({ error: validationError });
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
      if (e.status) return reply.status(e.status).json({ error: e.message });
      log.err('Failed to create retainer', { message: e.message, character_id: req.params.id });
      reply.status(500).json({ error: 'Failed to create retainer' });
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
      if (rows.length === 0) return reply.status(403).json({ error: 'Not authorized or retainer not found' });
      
      await pool.query('UPDATE retainers SET is_favorite = ? WHERE id = ?', [is_favorite ? 1 : 0, req.params.retainerId]);
      reply.send({ success: true, is_favorite: !!is_favorite });
    } catch (e) {
      log.err('Failed to update favorite status', { message: e.message, retainerId: req.params.retainerId });
      reply.status(500).json({ error: 'Failed to update favorite status' });
    }
  });


  fastify.put('/api/retainers/:retainerId/upgrade', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const { name, sheet } = req.body;
      const tier = Number(req.body.tier);
      if (!Number.isInteger(tier) || tier < 1 || tier > 4) return reply.status(400).json({ error: 'Tier must be 1 to 4.' });

      // Check ownership
      const [rows] = await pool.query(
        'SELECT r.* FROM retainers r JOIN characters c ON r.character_id = c.id WHERE r.id = ? AND c.user_id = ?',
        [req.params.retainerId, req.user.id]
      );
      if (rows.length === 0) return reply.status(403).json({ error: 'Not authorized or retainer not found' });
      const oldRetainer = rows[0];

      // Ensure tier is only going up or staying the same
      if (tier < oldRetainer.tier) {
        return reply.status(400).json({ error: 'Cannot downgrade tier via upgrade route.' });
      }

      // Strict V5 Validation
      const isGhoul = sheet?.isGhoul === true;
      const validationError = validateRetainerSheet(Number(tier), sheet, isGhoul);
      if (validationError) {
        return reply.status(400).json({ error: validationError });
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
      if (e.status) return reply.status(e.status).json({ error: e.message });
      log.err('Failed to upgrade retainer', { message: e.message, retainer_id: req.params.retainerId });
      reply.status(500).json({ error: 'Failed to upgrade retainer' });
    }
  });

  fastify.put('/api/retainers/:retainerId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { name, tier, sheet, xp } = req.body;
      const retainerId = req.params.retainerId;

      // Strict V5 Validation
      const isGhoul = sheet?.isGhoul === true;
      const validationError = validateRetainerSheet(Number(tier), sheet, isGhoul);
      if (validationError) {
        return reply.status(400).json({ error: validationError });
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
      reply.status(500).json({ error: 'Failed to update retainer' });
    }
  });

  fastify.delete('/api/retainers/:retainerId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      await pool.query('DELETE FROM retainers WHERE id=?', [req.params.retainerId]);
      reply.send({ success: true });
    } catch (e) {
      log.err('Failed to delete retainer', { message: e.message, retainer_id: req.params.retainerId });
      reply.status(500).json({ error: 'Failed to delete retainer' });
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
      reply.status(500).json({ error: 'Failed to reset character' });
    }
  });

  // Rebuild character (overwrites sheet, resets to 50 XP, keeps ID)
  fastify.post('/api/characters/rebuild', { preHandler: [authRequired] }, async (req, reply) => {
    const { name, clan, sheet } = req.body;
    if (!name || !clan) {
      log.warn('Rebuild character missing fields', { user_id: req.user.id });
      return reply.status(400).json({ error: 'Name and clan are required' });
    }

    if (await isClanDisabled(clan)) {
      log.warn('Rebuild character disabled clan', { user_id: req.user.id, clan });
      return reply.status(400).json({ error: `${clan} is not currently available for character creation` });
    }

    try {
      // Find the user's existing character
      const [rows] = await pool.query('SELECT id, sheet FROM characters WHERE user_id=?', [req.user.id]);
      if (!rows.length) {
        return reply.status(404).json({ error: 'No character found to rebuild' });
      }
      // A rebuild wipes XP history and starts over, so only when a
      // Storyteller has granted a re-roll (Admin > Characters > Allow Re-Roll).
      if (parseSheet(rows[0].sheet)?.allow_reset !== true) {
        log.warn('Rebuild refused: no re-roll granted', { user_id: req.user.id });
        return reply.status(403).json({ error: 'Your Storyteller has not allowed a re-roll for this character.' });
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
      reply.status(500).json({ error: 'Failed to rebuild character' });
    }
  });


};


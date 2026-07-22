module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, moderateLimiter, requireAdmin, validateRetainerSheet, getMimeType, sharp, imageClient, broadcastNtfyAlert } = opts;
/* -------------------- Characters -------------------- */
// Get my character (parse sheet if string)
fastify.get('/api/characters/me', { preHandler: [authRequired] }, async (req, reply) => {
  const [rows] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
  const ch = rows[0] || null;
  if (ch && ch.sheet && typeof ch.sheet === 'string') {
    try { ch.sheet = JSON.parse(ch.sheet); } catch { }
  }
  log.char('Fetch my character', { user_id: req.user.id, hasCharacter: !!ch });
  reply.send({ character: ch });
});

// Update my character (optional)
fastify.put('/api/characters/me', { preHandler: [authRequired] }, async (req, reply) => {
  const { name, clan, sheet } = req.body;
  const [rows] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
  if (!rows.length) {
    log.warn('Update character not found', { user_id: req.user.id });
    return reply.status(404).json({ error: 'No character' });
  }

  const fields = [], vals = [];
  if (name) { fields.push('name=?'); vals.push(name); }
  if (clan) { fields.push('clan=?'); vals.push(clan); }
  if (sheet !== undefined) { fields.push('sheet=?'); vals.push(sheet ? JSON.stringify(sheet) : null); }
  if (!fields.length) {
    log.warn('Update character no fields', { user_id: req.user.id });
    return reply.status(400).json({ error: 'Nothing to update' });
  }

  vals.push(rows[0].id);
  await pool.query(`UPDATE characters SET ${fields.join(', ')} WHERE id=?`, vals);

  const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [rows[0].id]);
  const ch = out[0];
  if (ch && ch.sheet && typeof ch.sheet === 'string') { try { ch.sheet = JSON.parse(ch.sheet); } catch { } }
  log.char('Character updated', { id: rows[0].id, user_id: req.user.id, updates: fields });
  reply.send({ character: ch });
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

  try {
    const [exists] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
    if (exists.length) {
      log.warn('Create character already exists', { user_id: req.user.id });
      return reply.status(409).json({ error: 'Character already exists' });
    }

    const [r] = await pool.query(
      'INSERT INTO characters (user_id, name, clan, sheet, xp) VALUES (?,?,?,?,?)',
      [req.user.id, name, clan, sheet ? JSON.stringify(sheet) : null, 50]
    );

    const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [r.insertId]);
    const ch = rows[0];
    if (ch && ch.sheet && typeof ch.sheet === 'string') { try { ch.sheet = JSON.parse(ch.sheet); } catch { } }
    log.char('Character created', { id: r.insertId, user_id: req.user.id, name, clan, xp: ch?.xp });
    broadcastNtfyAlert(`**${name}** (Clan: **${clan}**) was created by User #${req.user.id}.`, { title: 'New Character', tags: 'vampire', priority: 'default' });
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
  const { name, clan, sheet } = req.body;
  const [rows] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
  if (!rows.length) {
    log.warn('Update character not found', { user_id: req.user.id });
    return reply.status(404).json({ error: 'No character' });
  }

  const fields = [], vals = [];
  if (name) { fields.push('name=?'); vals.push(name); }
  if (clan) { fields.push('clan=?'); vals.push(clan); }
  if (sheet !== undefined) { fields.push('sheet=?'); vals.push(sheet ? JSON.stringify(sheet) : null); }
  if (!fields.length) {
    log.warn('Update character no fields', { user_id: req.user.id });
    return reply.status(400).json({ error: 'Nothing to update' });
  }

  vals.push(rows[0].id);
  await pool.query(`UPDATE characters SET ${fields.join(', ')} WHERE id=?`, vals);

  const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [rows[0].id]);
  const ch = out[0];
  if (ch && ch.sheet && typeof ch.sheet === 'string') { try { ch.sheet = JSON.parse(ch.sheet); } catch { } }
  log.char('Character updated', { id: rows[0].id, user_id: req.user.id, updates: fields });
  reply.send({ character: ch });
});

// ==========================================
// INVENTORY ROUTES
// ==========================================

// GET: Fetch a character's inventory
fastify.get('/api/characters/:id/inventory', { preHandler: [authRequired] }, async (req, reply) => {
  try {
    const [items] = await pool.query(
      'SELECT * FROM inventory_items WHERE character_id = ? ORDER BY item_type, name',
      [req.params.id]
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

  try {
    if (req.user.role !== 'admin') {
      const [charRows] = await pool.query('SELECT id FROM characters WHERE id = ? AND user_id = ?', [charId, req.user.id]);
      if (!charRows.length) return reply.status(403).json({ error: 'Unauthorized' });
    }

    const [r] = await pool.query(
      `INSERT INTO inventory_items (character_id, name, item_type, description, mechanic_notes, quantity, image, researched) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [charId, name, item_type || 'Mundane', description || null, mechanic_notes || null, quantity || 1, image || null, researched ? 1 : 0]
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

  try {
    if (req.user.role !== 'admin') {
      const [charRows] = await pool.query('SELECT id FROM characters WHERE id = ? AND user_id = ?', [charId, req.user.id]);
      if (!charRows.length) return reply.status(403).json({ error: 'Unauthorized' });
    }

    await pool.query(
      `UPDATE inventory_items 
       SET name=?, item_type=?, description=?, mechanic_notes=?, quantity=?, image=?, researched=? 
       WHERE id=? AND character_id=?`,
      [name, item_type || 'Mundane', description || null, mechanic_notes || null, quantity || 1, image || null, researched ? 1 : 0, itemId, charId]
    );

    reply.send({ success: true });
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
    if (req.user.role !== 'admin') {
      const [charRows] = await pool.query('SELECT id FROM characters WHERE id = ? AND user_id = ?', [charId, req.user.id]);
      if (!charRows.length) return reply.status(403).json({ error: 'Unauthorized' });
    }

    await pool.query('DELETE FROM inventory_items WHERE id=? AND character_id=?', [itemId, charId]);
    reply.send({ success: true });
  } catch (e) {
    log.err('Failed to delete inventory item', { message: e.message });
    reply.status(500).json({ error: 'Failed to delete item' });
  }
});

// --- Character Personal Inventory ---

// Get a character's inventory (owner or admin)
// DUP: fastify.get('/api/characters/:id/inventory', { preHandler: [authRequired] }, async (req, reply) => {
// DUP:   const charId = Number(req.params.id);
// DUP:   try {
// DUP:     // Check if the requesting user owns the character or is an admin
// DUP:     if (req.user.role !== 'admin') {
// DUP:       const [charRows] = await pool.query(
// DUP:         'SELECT id FROM characters WHERE id = ? AND user_id = ?',
// DUP:         [charId, req.user.id]
// DUP:       );
// DUP:       if (!charRows.length) {
// DUP:         return reply.status(403).json({ error: 'Unauthorized' });
// DUP:       }
// DUP:     }
// DUP:     const [items] = await pool.query(
// DUP:       'SELECT * FROM character_inventory WHERE character_id = ? ORDER BY id',
// DUP:       [charId]
// DUP:     );
// DUP:     reply.send({ items });
// DUP:   } catch (e) {
// DUP:     log.err('Failed to fetch character inventory', { message: e.message, character_id: charId });
// DUP:     reply.status(500).json({ error: 'Failed to fetch inventory' });
// DUP:   }
// DUP: });

// Add an item to a character's inventory (owner or admin)
// DUP: fastify.post('/api/characters/:id/inventory', { preHandler: [authRequired] }, async (req, reply) => {
// DUP:   const charId = Number(req.params.id);
// DUP: 
// DUP:   // Destructure all available payload fields
// DUP:   const {
// DUP:     name,
// DUP:     item_type,
// DUP:     description,
// DUP:     mechanic_notes,
// DUP:     quantity,
// DUP:     image,
// DUP:     researched
// DUP:   } = req.body;
// DUP: 
// DUP:   if (!name) {
// DUP:     return reply.status(400).json({ error: 'Item name is required' });
// DUP:   }
// DUP: 
// DUP:   try {
// DUP:     // Verify user owns the character (unless admin)
// DUP:     if (req.user.role !== 'admin') {
// DUP:       const [charRows] = await pool.query(
// DUP:         'SELECT id FROM characters WHERE id = ? AND user_id = ?',
// DUP:         [charId, req.user.id]
// DUP:       );
// DUP:       if (!charRows.length) {
// DUP:         return reply.status(403).json({ error: 'Unauthorized' });
// DUP:       }
// DUP:     }
// DUP: 
// DUP:     // Insert new item
// DUP:     const [r] = await pool.query(
// DUP:       `INSERT INTO inventory_items 
// DUP:         (character_id, name, item_type, description, mechanic_notes, quantity, image, researched) 
// DUP:        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
// DUP:       [
// DUP:         charId,
// DUP:         name,
// DUP:         item_type || 'Mundane',
// DUP:         description || null,
// DUP:         mechanic_notes || null,
// DUP:         quantity || 1,
// DUP:         image || null,
// DUP:         researched ?? false
// DUP:       ]
// DUP:     );
// DUP: 
// DUP:     const [[newItem]] = await pool.query('SELECT * FROM inventory_items WHERE id = ?', [r.insertId]);
// DUP:     reply.status(201).json({ item: newItem });
// DUP: 
// DUP:   } catch (e) {
// DUP:     log.err('Failed to add inventory item', { message: e.message, character_id: charId });
// DUP:     reply.status(500).json({ error: 'Failed to add item' });
// DUP:   }
// DUP: });

// Update an inventory item (owner or admin)
// DUP: fastify.put('/api/characters/:id/inventory/:itemId', { preHandler: [authRequired] }, async (req, reply) => {
// DUP:   const charId = Number(req.params.id);
// DUP:   const itemId = Number(req.params.itemId);
// DUP:   const { name, description, image, researched } = req.body;
// DUP:   if (!name) {
// DUP:     return reply.status(400).json({ error: 'Item name is required' });
// DUP:   }
// DUP:   try {
// DUP:     // Check ownership or admin
// DUP:     if (req.user.role !== 'admin') {
// DUP:       const [charRows] = await pool.query(
// DUP:         'SELECT c.id FROM character_inventory i JOIN characters c ON i.character_id = c.id WHERE i.id = ? AND c.user_id = ?',
// DUP:         [itemId, req.user.id]
// DUP:       );
// DUP:       if (!charRows.length) {
// DUP:         return reply.status(403).json({ error: 'Unauthorized' });
// DUP:       }
// DUP:     }
// DUP:     await pool.query(
// DUP:       'UPDATE character_inventory SET name=?, description=?, image=?, researched=? WHERE id=? AND character_id=?',
// DUP:       [name, description || null, image || null, researched ?? false, itemId, charId]
// DUP:     );
// DUP:     const [[updatedItem]] = await pool.query('SELECT * FROM character_inventory WHERE id = ?', [itemId]);
// DUP:     reply.send({ item: updatedItem });
// DUP:   } catch (e) {
// DUP:     log.err('Failed to update inventory item', { message: e.message, character_id: charId, item_id: itemId });
// DUP:     reply.status(500).json({ error: 'Failed to update item' });
// DUP:   }
// DUP: });

// Delete an inventory item (owner or admin)
// DUP: fastify.delete('/api/characters/:id/inventory/:itemId', { preHandler: [authRequired] }, async (req, reply) => {
// DUP:   const charId = Number(req.params.id);
// DUP:   const itemId = Number(req.params.itemId);
// DUP:   try {
// DUP:     // Check ownership or admin
// DUP:     if (req.user.role !== 'admin') {
// DUP:       const [charRows] = await pool.query(
// DUP:         'SELECT c.id FROM character_inventory i JOIN characters c ON i.character_id = c.id WHERE i.id = ? AND c.user_id = ?',
// DUP:         [itemId, req.user.id]
// DUP:       );
// DUP:       if (!charRows.length) {
// DUP:         return reply.status(403).json({ error: 'Unauthorized' });
// DUP:       }
// DUP:     }
// DUP:     await pool.query('DELETE FROM character_inventory WHERE id = ? AND character_id = ?', [itemId, charId]);
// DUP:     reply.send({ ok: true });
// DUP:   } catch (e) {
// DUP:     log.err('Failed to delete inventory item', { message: e.message, character_id: charId, item_id: itemId });
// DUP:     reply.status(500).json({ error: 'Failed to delete item' });
// DUP:   }
// DUP: });

// ================== Retainers ==================
fastify.get('/api/characters/:id/retainers', { preHandler: [authRequired] }, async (req, reply) => {
  try {
    const [rows] = await pool.query('SELECT id, character_id, name, tier, sheet, xp, created_at FROM retainers WHERE character_id=?', [req.params.id]);
    reply.send(rows);
  } catch (e) {
    log.err('Failed to get retainers', { message: e.message, character_id: req.params.id });
    reply.status(500).json({ error: 'Failed to fetch retainers' });
  }
});

fastify.post('/api/characters/:id/retainers', { preHandler: [authRequired] }, async (req, reply) => {
  try {
    const { name, tier, sheet, xp } = req.body;
    const [result] = await pool.query(
      'INSERT INTO retainers (character_id, name, tier, sheet, xp) VALUES (?, ?, ?, ?, ?)',
      [req.params.id, name, tier || 1, JSON.stringify(sheet || {}), xp || 0]
    );
    reply.send({ id: result.insertId, character_id: req.params.id, name, tier, sheet, xp });
  } catch (e) {
    log.err('Failed to create retainer', { message: e.message, character_id: req.params.id });
    reply.status(500).json({ error: 'Failed to create retainer' });
  }
});


fastify.put('/api/retainers/:retainerId/upgrade', { preHandler: [authRequired] }, async (req, reply) => {
  try {
    const { name, tier, sheet, xp } = req.body;

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

    await pool.query(
      'UPDATE retainers SET tier=?, sheet=? WHERE id=?',
      [tier, JSON.stringify(sheet), req.params.retainerId]
    );
    reply.send({ success: true });
  } catch (e) {
    log.err('Failed to upgrade retainer', { message: e.message, retainer_id: req.params.retainerId });
    reply.status(500).json({ error: 'Failed to upgrade retainer' });
  }
});

fastify.put('/api/retainers/:retainerId', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
  try {
    const { name, tier, sheet, xp } = req.body;

    // Strict V5 Validation
    const isGhoul = sheet?.isGhoul === true;
    const validationError = validateRetainerSheet(Number(tier), sheet, isGhoul);
    if (validationError) {
      return reply.status(400).json({ error: validationError });
    }

    // 1. Clear XP logs so math doesn't break for the new sheet
    try { await pool.query('DELETE FROM xp_log WHERE character_id=?', [id]); } catch (e) { }

    // 2. Reset sheet to NULL and XP to 50
    await pool.query('UPDATE characters SET sheet=NULL, xp=50 WHERE id=?', [id]);

    const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [id]);
    log.adm('Character reset by admin', { id, admin_id: req.user.id });
    reply.send({ character: rows[0] });
  } catch (e) {
    log.err('Admin reset character failed', { message: e.message, id });
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

  try {
    // Find the user's existing character
    const [rows] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
    if (!rows.length) {
      return reply.status(404).json({ error: 'No character found to rebuild' });
    }

    const charId = rows[0].id;

    // Wipe the old XP log so they start totally fresh
    try {
      await pool.query('DELETE FROM xp_log WHERE character_id=?', [charId]);
    } catch (e) { /* ignore if table missing */ }

    // Overwrite the character data and reset XP to 50
    await pool.query(
      'UPDATE characters SET name=?, clan=?, sheet=?, xp=50 WHERE id=?',
      [name, clan, sheet ? JSON.stringify(sheet) : null, charId]
    );

    // Fetch and return the updated character
    const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [charId]);
    const ch = out[0];
    if (ch && ch.sheet && typeof ch.sheet === 'string') {
      try { ch.sheet = JSON.parse(ch.sheet); } catch { }
    }

    log.char('Character rebuilt', { id: charId, user_id: req.user.id, name, clan });
    reply.send({ character: ch });
  } catch (e) {
    log.err('Failed to rebuild character', e);
    reply.status(500).json({ error: 'Failed to rebuild character' });
  }
});


};


// routes/inventory.js
//
// Storyteller-run inventory. Players never create items: the ST hands them out
// from the admin Inventory tab, or leaves them in the world (character_id NULL)
// with a printable QR (claim_code) that the first scanner claims — or, with
// claim_copies, every scanner gets their own copy.
//
// Players move items between themselves with "Pass item": the holder opens a
// short-lived QR (inventory_transfers.token), the receiver scans it and the
// item (or part of the stack) moves in one transaction.
//
// Research: until an item is `researched`, players see what it is (name,
// description, picture) but not what it does — mechanic_notes is stripped
// server-side. player_notes belongs to the holder.

const crypto = require('crypto');
const { isAdmin, userOwnsCharacter } = require('../services/guards');

// Mirrors the enum on inventory_items.item_type.
const ITEM_TYPES = ['Relic', 'Artifact', 'Blood Magic', 'Weapon', 'Armor', 'Mundane'];
const TRANSFER_MINUTES = 10;
const CONFIRM_MINUTES = 5; // time the giver has to confirm once someone has scanned
const MAX_TEXT = 20000;

const newCode = () => crypto.randomBytes(18).toString('base64url');
const toId = (v) => { const n = Number(v); return Number.isInteger(n) && n > 0 ? n : null; };
const normaliseQty = (q) => {
  const n = Number(q);
  return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 1;
};
const text = (v) => (v == null || v === '' ? null : String(v).slice(0, MAX_TEXT));

// What a player is allowed to see of an item they hold.
function forPlayer(item) {
  const { claim_code, claim_copies, source_item_id, granted_by, ...rest } = item;
  if (!rest.researched) rest.mechanic_notes = null;
  return rest;
}

const httpError = (status, message) => Object.assign(new Error(message), { status });

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, moderateLimiter, imageClient } = opts;
  const limited = moderateLimiter ? [authRequired, moderateLimiter] : [authRequired];
  const adminOnly = [authRequired, requireAdmin];

  // A data: URL is pushed to the image CDN and replaced by its https URL.
  // Anything else (an existing CDN url, or null) is passed through.
  const resolveItemImage = async (image, tag) => {
    if (!image || !String(image).startsWith('data:image')) return image || null;
    try {
      const buffer = Buffer.from(image.split(';base64,').pop(), 'base64');
      const ext = (image.match(/data:image\/([a-zA-Z0-9]+);/) || [])[1] || 'jpeg';
      const result = await imageClient.uploadImage(buffer, `inventory_${tag}_${Date.now()}.${ext}`);
      if (result && result.success) return result.url;
      log.warn('Inventory image upload failed, setting to null');
      return null;
    } catch (err) {
      log.err('Error uploading inventory image', { error: err.message });
      return null;
    }
  };

  const currentCharacter = async (conn, userId) => {
    const [[ch]] = await conn.query('SELECT id, name FROM characters WHERE user_id = ? ORDER BY id LIMIT 1', [userId]);
    return ch || null;
  };

  async function inTransaction(fn) {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const out = await fn(conn);
      await conn.commit();
      return out;
    } catch (e) {
      await conn.rollback().catch(() => {});
      throw e;
    } finally {
      conn.release();
    }
  }

  const fail = (reply, e, what) => {
    if (e.status) return reply.status(e.status).send({ error: e.message });
    log.err(`Inventory: ${what} failed`, { message: e.message });
    return reply.status(500).send({ error: `Failed to ${what}` });
  };

  // Copies an item row (split stack / world copy). The claim code is never
  // copied: a copy a player holds gets none, one sent to the world a fresh one.
  const copyItem = (conn, srcId, { characterId, quantity, playerNotes, sourceItemId, claimCode = null }) => conn.query(
    `INSERT INTO inventory_items
       (character_id, name, item_type, description, mechanic_notes, player_notes, quantity, image, researched, granted_by, source_item_id, claim_code)
     SELECT ?, name, item_type, description, mechanic_notes, ?, ?, image, researched, granted_by, ?, ?
     FROM inventory_items WHERE id = ?`,
    [characterId, playerNotes, quantity, sourceItemId, claimCode, srcId]
  );

  // to_user_id set + to_character_id NULL = the Storyteller is receiving.
  const recipientName = (t) => (t.to_user_id == null ? null : t.to_character_id == null ? 'the Storyteller' : t.to_char || null);

  // ============ PLAYER ============

  // A character's inventory (owner, incl. their retired characters, or admin).
  fastify.get('/api/characters/:id/inventory', { preHandler: [authRequired] }, async (req, reply) => {
    reply.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    try {
      const charId = Number(req.params.id);
      const admin = isAdmin(req.user);
      if (!admin) {
        const [[owned]] = await pool.query(
          'SELECT 1 AS ok FROM characters WHERE id = ? AND ? IN (user_id, retired_user_id)', [charId, req.user.id]
        );
        if (!owned) return reply.status(403).send({ error: 'Unauthorized' });
      }
      const [items] = await pool.query('SELECT * FROM inventory_items WHERE character_id = ? ORDER BY item_type, name', [charId]);
      reply.send({ items: admin ? items : items.map(forPlayer) });
    } catch (e) {
      fail(reply, e, 'fetch inventory');
    }
  });

  // The holder's own notes — the only field a player can edit.
  fastify.put('/api/characters/:id/inventory/:itemId/notes', { preHandler: limited }, async (req, reply) => {
    try {
      const charId = Number(req.params.id);
      if (!isAdmin(req.user) && !(await userOwnsCharacter(pool, req.user.id, charId))) {
        return reply.status(403).send({ error: 'Unauthorized' });
      }
      const [r] = await pool.query(
        'UPDATE inventory_items SET player_notes = ? WHERE id = ? AND character_id = ?',
        [text(req.body?.player_notes), Number(req.params.itemId), charId]
      );
      if (!r.affectedRows) return reply.status(404).send({ error: 'Item not found' });
      reply.send({ success: true });
    } catch (e) {
      fail(reply, e, 'save notes');
    }
  });

  // Pass item: open a QR the receiver scans. One live pass per item —
  // opening a new one cancels the previous (open or mid-handshake).
  fastify.post('/api/inventory/transfers', { preHandler: limited }, async (req, reply) => {
    try {
      const itemId = toId(req.body?.item_id);
      if (!itemId) return reply.status(400).send({ error: 'item_id is required' });
      const out = await inTransaction(async (conn) => {
        const ch = await currentCharacter(conn, req.user.id);
        if (!ch) throw httpError(400, 'You need a character to pass items.');
        const [[item]] = await conn.query('SELECT id, quantity FROM inventory_items WHERE id = ? AND character_id = ? FOR UPDATE', [itemId, ch.id]);
        if (!item) throw httpError(404, 'Item not found in your inventory.');
        const qty = normaliseQty(req.body?.quantity);
        if (qty > (item.quantity || 1)) throw httpError(400, `You only have ${item.quantity || 1}.`);

        await conn.query("UPDATE inventory_transfers SET status = 'cancelled' WHERE item_id = ? AND status IN ('open','pending')", [itemId]);
        const token = newCode();
        await conn.query(
          `INSERT INTO inventory_transfers (token, item_id, from_character_id, quantity, include_notes, created_by, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, NOW() + INTERVAL ${TRANSFER_MINUTES} MINUTE)`,
          [token, itemId, ch.id, qty, req.body?.include_notes ? 1 : 0, req.user.id]
        );
        return { token, quantity: qty, ttl_seconds: TRANSFER_MINUTES * 60 };
      });
      reply.status(201).send(out);
    } catch (e) {
      fail(reply, e, 'start transfer');
    }
  });

  // Both sides poll this: the giver to see who scanned, the receiver to see
  // the giver's answer.
  fastify.get('/api/inventory/transfers/:token', { preHandler: [authRequired] }, async (req, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const [[t]] = await pool.query(
        `SELECT t.*, t.expires_at <= NOW() AS expired, tc.name AS to_char, fc.name AS from_name, i.name AS item_name
         FROM inventory_transfers t
         LEFT JOIN characters tc ON tc.id = t.to_character_id
         LEFT JOIN characters fc ON fc.id = t.from_character_id
         LEFT JOIN inventory_items i ON i.id = t.item_id
         WHERE t.token = ?`,
        [req.params.token]
      );
      const me = Number(req.user.id);
      if (!t || (!isAdmin(req.user) && Number(t.created_by) !== me && Number(t.to_user_id) !== me)) {
        return reply.status(404).send({ error: 'Transfer not found' });
      }
      const live = t.status === 'open' || t.status === 'pending';
      reply.send({
        status: live && t.expired ? 'expired' : t.status,
        quantity: t.quantity,
        to_name: recipientName(t),
        from_name: t.from_name,
        item_name: t.item_name,
      });
    } catch (e) {
      fail(reply, e, 'read transfer');
    }
  });

  // The giver's "Yes, pass it to <name>": only now does the item move.
  fastify.post('/api/inventory/transfers/:token/confirm', { preHandler: limited }, async (req, reply) => {
    try {
      const out = await inTransaction(async (conn) => {
        const [[t]] = await conn.query(
          'SELECT *, expires_at <= NOW() AS expired FROM inventory_transfers WHERE token = ? AND created_by = ? FOR UPDATE',
          [req.params.token, req.user.id]
        );
        if (!t) throw httpError(404, 'Transfer not found');
        if (t.status === 'claimed') throw httpError(409, 'This item has already been handed over.');
        if (t.status !== 'pending') throw httpError(409, t.status === 'open' ? 'Nobody has scanned the code yet.' : 'This hand-over was cancelled.');
        if (t.expired) throw httpError(410, 'This hand-over timed out. Show a new code.');

        // Both sides must still be who they were when the QR went up.
        const [[giver]] = await conn.query('SELECT 1 AS ok FROM characters WHERE id = ? AND user_id = ?', [t.from_character_id, req.user.id]);
        if (!giver) throw httpError(409, 'This character can no longer pass items.');
        if (t.to_character_id != null) {
          const [[taker]] = await conn.query('SELECT 1 AS ok FROM characters WHERE id = ? AND user_id = ?', [t.to_character_id, t.to_user_id]);
          if (!taker) throw httpError(409, 'The receiver can no longer take items.');
        }
        const [[item]] = await conn.query('SELECT * FROM inventory_items WHERE id = ? FOR UPDATE', [t.item_id]);
        if (!item || Number(item.character_id) !== Number(t.from_character_id) || (item.quantity || 1) < t.quantity) {
          throw httpError(409, 'You no longer have this item.');
        }

        const dest = t.to_character_id; // NULL = back to the Storyteller (out in the world)
        const notes = t.include_notes ? item.player_notes : null;
        if (t.quantity >= (item.quantity || 1)) {
          await conn.query(
            'UPDATE inventory_items SET character_id = ?, player_notes = ?, claim_code = COALESCE(claim_code, ?) WHERE id = ?',
            [dest, notes, dest == null ? newCode() : null, item.id]
          );
        } else {
          await conn.query('UPDATE inventory_items SET quantity = quantity - ? WHERE id = ?', [t.quantity, item.id]);
          await copyItem(conn, item.id, {
            characterId: dest, quantity: t.quantity, playerNotes: notes,
            sourceItemId: item.source_item_id, claimCode: dest == null ? newCode() : null,
          });
        }
        await conn.query("UPDATE inventory_transfers SET status = 'claimed', claimed_at = NOW() WHERE id = ?", [t.id]);
        const [[to]] = await conn.query('SELECT name FROM characters WHERE id = ?', [dest]);
        return { status: 'claimed', to_name: recipientName({ ...t, to_char: to?.name }) };
      });
      log.char('Inventory item passed', { user_id: req.user.id, token_tail: req.params.token.slice(-4) });
      reply.send(out);
    } catch (e) {
      fail(reply, e, 'confirm transfer');
    }
  });

  // Cancel: the giver at any point before it lands ("Not them" included), or
  // the receiver backing out while waiting for the giver.
  fastify.delete('/api/inventory/transfers/:token', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      await pool.query(
        `UPDATE inventory_transfers SET status = 'cancelled'
         WHERE token = ? AND (
           (created_by = ? AND status IN ('open','pending')) OR
           (to_user_id = ? AND status = 'pending'))`,
        [req.params.token, req.user.id, req.user.id]
      );
      reply.send({ success: true });
    } catch (e) {
      fail(reply, e, 'cancel transfer');
    }
  });

  // Who is receiving: the scanner's current character, or — from the admin
  // Inventory tab only — the Storyteller taking an item back.
  async function recipientFor(conn, user, asStoryteller) {
    if (asStoryteller) {
      if (!isAdmin(user)) throw httpError(403, 'Only the Storyteller can take items back.');
      return { characterId: null, userId: user.id };
    }
    const ch = await currentCharacter(conn, user.id);
    if (!ch) throw httpError(400, 'You need a character to receive items.');
    return { characterId: ch.id, userId: user.id };
  }

  // Validates a scanned code for this recipient. The same checks back the
  // "are you sure?" preview (lock = false) and the claim itself (lock = true).
  async function inspectCode(conn, code, who, lock) {
    const fu = lock ? ' FOR UPDATE' : '';
    const [[t]] = await conn.query(`SELECT *, expires_at <= NOW() AS expired FROM inventory_transfers WHERE token = ?${fu}`, [code]);
    if (t) {
      if (t.status === 'claimed') throw httpError(409, 'This item has already been handed over.');
      if (t.status === 'cancelled' || t.expired) throw httpError(410, 'This code has expired. Ask for a new one.');
      if (t.status === 'pending' && Number(t.to_user_id) !== Number(who.userId)) throw httpError(409, 'Someone else is already receiving this item.');
      if (Number(t.created_by) === Number(who.userId)) throw httpError(400, 'You cannot pass an item to yourself.');
      const [[item]] = await conn.query(`SELECT * FROM inventory_items WHERE id = ?${fu}`, [t.item_id]);
      if (!item || Number(item.character_id) !== Number(t.from_character_id) || (item.quantity || 1) < t.quantity) {
        throw httpError(409, 'The giver no longer has this item.');
      }
      const [[from]] = await conn.query('SELECT name FROM characters WHERE id = ?', [t.from_character_id]);
      return { kind: 'transfer', transfer: t, item, from_name: from?.name || null, quantity: t.quantity };
    }

    const [[world]] = await conn.query(`SELECT * FROM inventory_items WHERE claim_code = ?${fu}`, [code]);
    if (!world) throw httpError(404, 'That code does not match any item.');
    const [[holder]] = world.character_id != null
      ? await conn.query('SELECT name FROM characters WHERE id = ?', [world.character_id])
      : [[null]];
    if (who.characterId == null) {
      // The Storyteller scanning a prop's printed QR takes it back from whoever has it.
      if (world.character_id == null) throw httpError(409, 'That item is already with the Storyteller.');
      return { kind: 'takeback', item: world, from_name: holder?.name || null, quantity: world.quantity || 1 };
    }
    if (world.character_id == null && world.claim_copies) {
      // ponytail: "one copy each" is checked against what the character holds now;
      // pass your copy away and you could scan again. Add a claims log if that matters.
      const [[dupe]] = await conn.query('SELECT 1 AS x FROM inventory_items WHERE source_item_id = ? AND character_id = ? LIMIT 1', [world.id, who.characterId]);
      if (dupe) throw httpError(409, 'You already have this item.');
      return { kind: 'world', copies: true, item: world, from_name: null, quantity: world.quantity || 1 };
    }
    if (world.character_id != null) {
      throw httpError(409, Number(world.character_id) === Number(who.characterId)
        ? 'You already have this item.'
        : `${holder?.name || 'Someone'} already has this item. Ask them to pass it to you.`);
    }
    return { kind: 'world', item: world, from_name: null, quantity: world.quantity || 1 };
  }

  const readCode = (body) => {
    const code = String(body?.code || '').trim();
    if (!code || code.length > 64) throw httpError(400, 'Invalid code.');
    return code;
  };

  // Scan, step 1: what is this, and from whom? Nothing changes yet.
  fastify.post('/api/inventory/preview', { preHandler: limited }, async (req, reply) => {
    try {
      const code = readCode(req.body);
      const who = await recipientFor(pool, req.user, !!req.body?.as_storyteller);
      const r = await inspectCode(pool, code, who, false);
      reply.send({ kind: r.kind, from_name: r.from_name, item: { ...forPlayer(r.item), quantity: r.quantity } });
    } catch (e) {
      fail(reply, e, 'read code');
    }
  });

  // Scan, step 2 ("Take it"). A world item lands at once; a pass waits for the
  // giver to confirm (kind 'pending'); the Storyteller's take-back of a prop
  // lands at once.
  fastify.post('/api/inventory/claim', { preHandler: limited }, async (req, reply) => {
    try {
      const code = readCode(req.body);
      const out = await inTransaction(async (conn) => {
        const who = await recipientFor(conn, req.user, !!req.body?.as_storyteller);
        const r = await inspectCode(conn, code, who, true);
        const preview = { ...forPlayer(r.item), quantity: r.quantity };

        if (r.kind === 'transfer') {
          if (r.transfer.status === 'open') {
            await conn.query(
              `UPDATE inventory_transfers SET status = 'pending', to_character_id = ?, to_user_id = ?,
                 expires_at = GREATEST(expires_at, NOW() + INTERVAL ${CONFIRM_MINUTES} MINUTE)
               WHERE id = ?`,
              [who.characterId, who.userId, r.transfer.id]
            );
          }
          return { kind: 'pending', token: code, from_name: r.from_name, item: preview };
        }
        if (r.kind === 'takeback') {
          await conn.query('UPDATE inventory_items SET character_id = NULL, player_notes = NULL WHERE id = ?', [r.item.id]);
          await conn.query("UPDATE inventory_transfers SET status = 'cancelled' WHERE item_id = ? AND status IN ('open','pending')", [r.item.id]);
          return { kind: 'takeback', from_name: r.from_name, item: preview };
        }
        let id = r.item.id;
        if (r.copies) {
          const [ins] = await copyItem(conn, r.item.id, { characterId: who.characterId, quantity: r.quantity, playerNotes: r.item.player_notes, sourceItemId: r.item.id });
          id = ins.insertId;
        } else {
          await conn.query('UPDATE inventory_items SET character_id = ? WHERE id = ?', [who.characterId, r.item.id]);
        }
        const [[item]] = await conn.query('SELECT * FROM inventory_items WHERE id = ?', [id]);
        return { kind: 'world', from_name: null, item: forPlayer(item) };
      });
      log.char('Inventory code scanned', { user_id: req.user.id, kind: out.kind });
      reply.send(out);
    } catch (e) {
      fail(reply, e, 'claim item');
    }
  });

  // ============ ADMIN ============

  // ponytail: whole table in one response; page it if the item count gets into the thousands.
  fastify.get('/api/admin/inventory', { preHandler: adminOnly }, async (req, reply) => {
    try {
      const [items] = await pool.query(
        `SELECT i.*, c.name AS character_name,
                (SELECT COUNT(*) FROM inventory_items x WHERE x.source_item_id = i.id AND x.character_id IS NOT NULL) AS copies_claimed
         FROM inventory_items i LEFT JOIN characters c ON c.id = i.character_id
         ORDER BY i.character_id IS NOT NULL, i.updated_at DESC`
      );
      reply.send({ items });
    } catch (e) {
      fail(reply, e, 'fetch items');
    }
  });

  // Partial update: only fields present in the body are written. Sent through
  // one helper so create and edit validate the same way.
  async function readItemBody(body, { creating }) {
    const fields = {};
    const has = (k) => Object.prototype.hasOwnProperty.call(body, k);
    if (creating || has('name')) {
      const name = String(body.name || '').trim();
      if (!name) throw httpError(400, 'Item name is required');
      fields.name = name.slice(0, 255);
    }
    if (has('item_type')) {
      if (!ITEM_TYPES.includes(body.item_type)) throw httpError(400, `Invalid item type. Expected one of: ${ITEM_TYPES.join(', ')}`);
      fields.item_type = body.item_type;
    }
    for (const k of ['description', 'mechanic_notes', 'player_notes']) if (has(k)) fields[k] = text(body[k]);
    if (has('quantity')) fields.quantity = normaliseQty(body.quantity);
    if (has('researched')) fields.researched = body.researched ? 1 : 0;
    if (has('claim_copies')) fields.claim_copies = body.claim_copies ? 1 : 0;
    if (has('character_id')) {
      const cid = body.character_id == null || body.character_id === '' ? null : toId(body.character_id);
      if (body.character_id != null && body.character_id !== '' && !cid) throw httpError(400, 'Invalid character');
      if (cid) {
        const [[c]] = await pool.query('SELECT id FROM characters WHERE id = ?', [cid]);
        if (!c) throw httpError(400, 'Character not found');
      }
      fields.character_id = cid;
    }
    if (has('image')) fields.image = await resolveItemImage(body.image, fields.character_id || 'world');
    return fields;
  }

  fastify.post('/api/admin/inventory', { preHandler: adminOnly }, async (req, reply) => {
    try {
      const fields = await readItemBody(req.body || {}, { creating: true });
      fields.claim_code = newCode(); // every item can be put out in the world later
      fields.granted_by = req.user.id;
      const [r] = await pool.query('INSERT INTO inventory_items SET ?', [fields]);
      const [[item]] = await pool.query('SELECT * FROM inventory_items WHERE id = ?', [r.insertId]);
      log.adm('Inventory item created', { admin_id: req.user.id, item_id: r.insertId, character_id: fields.character_id ?? null });
      reply.status(201).send({ item });
    } catch (e) {
      fail(reply, e, 'create item');
    }
  });

  fastify.put('/api/admin/inventory/:id', { preHandler: adminOnly }, async (req, reply) => {
    try {
      const id = Number(req.params.id);
      const fields = await readItemBody(req.body || {}, { creating: false });
      const [[cur]] = await pool.query('SELECT claim_code FROM inventory_items WHERE id = ?', [id]);
      if (!cur) return reply.status(404).send({ error: 'Item not found' });
      // Items from before world items existed have no code yet.
      if (!cur.claim_code) fields.claim_code = newCode();
      if (Object.keys(fields).length) await pool.query('UPDATE inventory_items SET ? WHERE id = ?', [fields, id]);
      const [[item]] = await pool.query('SELECT * FROM inventory_items WHERE id = ?', [id]);
      reply.send({ item });
    } catch (e) {
      fail(reply, e, 'update item');
    }
  });

  fastify.delete('/api/admin/inventory/:id', { preHandler: adminOnly }, async (req, reply) => {
    try {
      const [r] = await pool.query('DELETE FROM inventory_items WHERE id = ?', [Number(req.params.id)]);
      if (!r.affectedRows) return reply.status(404).send({ error: 'Item not found' });
      reply.send({ success: true });
    } catch (e) {
      fail(reply, e, 'delete item');
    }
  });
};


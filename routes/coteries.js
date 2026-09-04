// routes/coteries.js
//
// Coterie CRUD, membership, and the coterie XP economy. Extracted out of
// server.fastify.js so it can be mounted in isolation for integration tests
// (see tests/setup/testApp.js) and so the rules engine has one call site.
//
// Authorization model for this chronicle:
//   * read     — any member, or admin. `/all` is a public registry for every
//                logged-in player (names and roster only).
//   * write    — any member may edit their own coterie freely, or admin.
//   * xp award — ADMIN ONLY. Previously any member could POST an arbitrary
//                delta to /xp and mint themselves an unlimited bank.
//   * delete   — admin only.
//
// Every mutation is validated server-side by utils/coterieRules; the client's
// pool arithmetic is treated as a display convenience, never as truth.

const rules = require('../utils/coterieRules');

const isAdmin = (user) => user && (user.role === 'admin' || user.permission_level === 'admin');

const safeParse = (val, fallback) => {
  if (val == null) return fallback;
  if (typeof val !== 'string') return val;
  try {
    const out = JSON.parse(val);
    return out == null ? fallback : out;
  } catch {
    return fallback;
  }
};

// Shapes a raw `coteries` row into the object the client consumes, with the
// derived V5 mechanics attached so the sheet does not have to recompute them.
function presentCoterie(row, members = []) {
  if (!row) return null;
  const traits = {
    chasse: Number(row.chasse) || 0,
    lien: Number(row.lien) || 0,
    portillon: Number(row.portillon) || 0,
  };
  const backgrounds = safeParse(row.backgrounds_json, []);
  const merits = safeParse(row.merits_json, []);
  const flaws = safeParse(row.flaws_json, []);

  const budget = rules.computeBudget({
    memberCount: members.length,
    pointsPerMember: Number(row.points_per_member) || 1,
    bonusPoints: Number(row.bonus_points) || 0,
    traits,
    backgrounds,
    merits,
    flaws,
  });

  return {
    id: row.id,
    name: row.name,
    type: row.type,
    concept: row.concept || null,
    domain_id: row.domain_id,
    traits,
    required: safeParse(row.required_json, {}),
    backgrounds,
    merits,
    flaws,
    extras: safeParse(row.extras_json, []),
    points_per_member: Number(row.points_per_member) || 1,
    bonus_points: Number(row.bonus_points) || 0,
    coterie_xp: Number(row.coterie_xp) || 0,
    rules_override: !!row.rules_override,
    created_by: row.created_by,
    created_at: row.created_at,
    updated_at: row.updated_at,
    budget,
    mechanics: {
      huntingDifficulty: rules.huntingDifficulty(traits.chasse),
      chasseSize: rules.CHASSE_SIZE_TABLE[traits.chasse] || null,
      lienBonusDice: rules.lienBonusDice(traits.lien),
      portillonPenaltyDice: rules.portillonPenaltyDice(traits.portillon),
    },
  };
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, broadcastNtfyAlert } = opts;

  /** Resolves the caller's relationship to a coterie. */
  async function access(req, coterieId) {
    if (isAdmin(req.user)) return { allowed: true, admin: true, member: false };
    const [rows] = await pool.query(
      'SELECT 1 FROM coterie_members WHERE coterie_id=? AND user_id=? LIMIT 1',
      [coterieId, req.user.id]
    );
    return { allowed: rows.length > 0, admin: false, member: rows.length > 0 };
  }

  async function loadMembers(conn, coterieId) {
    const [rows] = await (conn || pool).query(
      `SELECT m.user_id, m.character_id, m.display_name,
              COALESCE(ch.name, m.display_name) AS character_name,
              ch.clan
         FROM coterie_members m
         LEFT JOIN characters ch ON ch.id = m.character_id
        WHERE m.coterie_id=?
        ORDER BY m.id ASC`,
      [coterieId]
    );
    return rows;
  }

  // Resolves [{user_id, display_name}] from the client into rows that carry a
  // real character_id, and rejects users who have no character at all — a
  // coterie is a group of characters, not of accounts.
  async function resolveMembers(members) {
    const ids = [...new Set((members || []).map((m) => Number(m.user_id)).filter(Number.isFinite))];
    if (!ids.length) return { rows: [], missing: [] };

    const [chars] = await pool.query(
      `SELECT c.id, c.user_id, c.name
         FROM characters c
         JOIN (SELECT user_id, MIN(id) AS id FROM characters WHERE user_id IN (?) GROUP BY user_id) p
           ON p.id = c.id`,
      [ids]
    );
    const byUser = new Map(chars.map((c) => [Number(c.user_id), c]));

    const rows = [];
    const missing = [];
    for (const id of ids) {
      const ch = byUser.get(id);
      if (!ch) { missing.push(id); continue; }
      const supplied = (members || []).find((m) => Number(m.user_id) === id);
      rows.push([id, ch.id, (supplied && supplied.display_name) || ch.name || null]);
    }
    return { rows, missing };
  }

  /* ================================================================ *
   * Create
   * ================================================================ */

  fastify.post('/api/coteries', { preHandler: [authRequired] }, async (req, reply) => {
    const body = req.body || {};
    const members = Array.isArray(body.members) ? body.members : [];

    if (!isAdmin(req.user) && !members.some((m) => Number(m.user_id) === Number(req.user.id))) {
      return reply.status(403).json({ error: 'You must include yourself in the coterie' });
    }

    // Only an ST may create a coterie that bypasses the point rules.
    const rulesOverride = isAdmin(req.user) ? !!body.rules_override : false;

    const { rows: memberRows, missing } = await resolveMembers(members);
    if (missing.length) {
      return reply.status(400).json({
        error: 'Every member needs a character sheet before joining a coterie.',
        missing_user_ids: missing,
      });
    }

    const check = rules.validateCoterie({
      name: body.name,
      memberCount: memberRows.length,
      pointsPerMember: body.points_per_member,
      bonusPoints: body.bonus_points,
      domainId: body.domain_id,
      traits: body.traits,
      backgrounds: body.backgrounds,
      merits: body.merits,
      flaws: body.flaws,
      rulesOverride,
    });
    if (check.errors.length) {
      return reply.status(400).json({ error: check.errors[0], errors: check.errors });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [ins] = await conn.query(
        `INSERT INTO coteries
          (name, type, concept, domain_id, chasse, lien, portillon,
           required_json, backgrounds_json, merits_json, flaws_json, extras_json,
           points_per_member, bonus_points, coterie_xp, rules_override, created_by)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          String(body.name).trim(),
          body.type || null,
          body.concept ? String(body.concept).slice(0, 500) : null,
          body.domain_id ? Number(body.domain_id) : null,
          check.traits.chasse, check.traits.lien, check.traits.portillon,
          body.required ? JSON.stringify(body.required) : null,
          JSON.stringify(check.backgrounds),
          JSON.stringify(check.merits),
          JSON.stringify(check.flaws),
          JSON.stringify(Array.isArray(body.extras) ? body.extras : []),
          check.pointsPerMember,
          Number(body.bonus_points) || 0,
          // Starting XP is an ST award, not something a player declares.
          isAdmin(req.user) ? Math.max(0, Number(body.coterie_xp) || 0) : 0,
          rulesOverride ? 1 : 0,
          req.user.id,
        ]
      );
      const coterieId = ins.insertId;

      await conn.query(
        'INSERT INTO coterie_members (coterie_id, user_id, character_id, display_name) VALUES ?',
        [memberRows.map((r) => [coterieId, r[0], r[1], r[2]])]
      );

      const startingXp = isAdmin(req.user) ? Math.max(0, Number(body.coterie_xp) || 0) : 0;
      if (startingXp > 0) {
        await conn.query(
          `INSERT INTO coterie_xp_log (coterie_id, user_id, kind, bank_delta, note)
           VALUES (?,?,?,?,?)`,
          [coterieId, req.user.id, 'award', startingXp, 'Starting coterie XP']
        );
      }

      await conn.commit();

      const [[row]] = await pool.query('SELECT * FROM coteries WHERE id=?', [coterieId]);
      const memberList = await loadMembers(null, coterieId);
      log.ok('Coterie created', { id: coterieId, by_user_id: req.user.id });
      if (typeof broadcastNtfyAlert === 'function') {
        broadcastNtfyAlert(`A new Coterie **"${row.name}"** was just formed!`, {
          title: 'New Coterie', tags: 'shield', priority: 'default',
        });
      }
      reply.status(201).json({
        coterie: presentCoterie(row, memberList),
        members: memberList,
        warnings: check.warnings,
      });
    } catch (e) {
      await conn.rollback();
      log.err('Create coterie failed', { message: e.message, stack: e.stack });
      reply.status(500).json({ error: 'Failed to create coterie' });
    } finally {
      conn.release();
    }
  });

  /* ================================================================ *
   * Read
   * ================================================================ */

  // Public registry — every logged-in player sees who is out there.
  // GROUP_CONCAT is capped at 1024 bytes by default, which silently truncated
  // large rosters; members are fetched as rows and grouped in JS instead.
  fastify.get('/api/coteries/all', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(`
        SELECT c.id, c.name, c.type, c.concept, c.domain_id,
               c.chasse, c.lien, c.portillon
          FROM coteries c
         ORDER BY c.name ASC
      `);
      if (!rows.length) return reply.send({ coteries: [] });

      const [memberRows] = await pool.query(
        `SELECT m.coterie_id, COALESCE(ch.name, m.display_name) AS character_name, ch.clan
           FROM coterie_members m
           LEFT JOIN characters ch ON ch.id = m.character_id
          WHERE m.coterie_id IN (?)`,
        [rows.map((r) => r.id)]
      );
      const byCoterie = new Map();
      for (const m of memberRows) {
        if (!byCoterie.has(m.coterie_id)) byCoterie.set(m.coterie_id, []);
        byCoterie.get(m.coterie_id).push({ name: m.character_name, clan: m.clan || null });
      }

      reply.send({
        coteries: rows.map((r) => {
          const roster = byCoterie.get(r.id) || [];
          return {
            ...r,
            member_count: roster.length,
            members: roster,
            mechanics: {
              huntingDifficulty: rules.huntingDifficulty(r.chasse),
              lienBonusDice: rules.lienBonusDice(r.lien),
              portillonPenaltyDice: rules.portillonPenaltyDice(r.portillon),
            },
          };
        }),
      });
    } catch (e) {
      log.err('Load public coteries failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to load public coteries' });
    }
  });

  // List coteries the caller can actually edit (admin → all).
  fastify.get('/api/coteries', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = isAdmin(req.user)
        ? await pool.query('SELECT * FROM coteries ORDER BY updated_at DESC')
        : await pool.query(
            `SELECT c.* FROM coteries c
               JOIN coterie_members m ON m.coterie_id=c.id
              WHERE m.user_id=?
              ORDER BY c.updated_at DESC`,
            [req.user.id]
          );
      if (!rows.length) return reply.send({ coteries: [] });

      const [memberRows] = await pool.query(
        `SELECT m.coterie_id, m.user_id, m.character_id, m.display_name,
                COALESCE(ch.name, m.display_name) AS character_name, ch.clan
           FROM coterie_members m
           LEFT JOIN characters ch ON ch.id = m.character_id
          WHERE m.coterie_id IN (?)`,
        [rows.map((r) => r.id)]
      );
      const byCoterie = new Map();
      for (const m of memberRows) {
        if (!byCoterie.has(m.coterie_id)) byCoterie.set(m.coterie_id, []);
        byCoterie.get(m.coterie_id).push(m);
      }

      reply.send({
        coteries: rows.map((r) => {
          const mem = byCoterie.get(r.id) || [];
          return { ...presentCoterie(r, mem), members: mem };
        }),
      });
    } catch (e) {
      log.err('List coteries failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to load coteries' });
    }
  });

  fastify.get('/api/coteries/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const id = Number(req.params.id);
      const [[row]] = await pool.query('SELECT * FROM coteries WHERE id=?', [id]);
      if (!row) return reply.status(404).json({ error: 'Not found' });

      const { allowed } = await access(req, id);
      if (!allowed) return reply.status(403).json({ error: 'Not allowed' });

      const members = await loadMembers(null, id);
      const [xpLog] = await pool.query(
        `SELECT id, user_id, kind, bank_delta, personal_delta, target_type,
                target_key, target_name, from_dots, to_dots, note, created_at
           FROM coterie_xp_log WHERE coterie_id=? ORDER BY created_at DESC, id DESC LIMIT 100`,
        [id]
      );

      reply.send({ coterie: presentCoterie(row, members), members, xp_log: xpLog });
    } catch (e) {
      log.err('Read coterie failed', { message: e.message, stack: e.stack });
      reply.status(500).json({ error: 'Failed to load coterie' });
    }
  });

  /* ================================================================ *
   * Update
   * ================================================================ */

  fastify.put('/api/coteries/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const id = Number(req.params.id);
      const { allowed, admin } = await access(req, id);
      if (!allowed) return reply.status(403).json({ error: 'Not allowed' });

      const [[existing]] = await pool.query('SELECT * FROM coteries WHERE id=?', [id]);
      if (!existing) return reply.status(404).json({ error: 'Not found' });

      const body = req.body || {};
      const members = await loadMembers(null, id);

      // Only an ST may flip the override; members inherit whatever is set.
      const rulesOverride = admin && body.rules_override !== undefined
        ? !!body.rules_override
        : !!existing.rules_override;

      const merged = {
        name: body.name !== undefined ? body.name : existing.name,
        memberCount: members.length,
        pointsPerMember: body.points_per_member !== undefined
          ? body.points_per_member : existing.points_per_member,
        bonusPoints: body.bonus_points !== undefined
          ? body.bonus_points : existing.bonus_points,
        domainId: body.domain_id !== undefined ? body.domain_id : existing.domain_id,
        traits: body.traits !== undefined ? body.traits : {
          chasse: existing.chasse, lien: existing.lien, portillon: existing.portillon,
        },
        backgrounds: body.backgrounds !== undefined
          ? body.backgrounds : safeParse(existing.backgrounds_json, []),
        merits: body.merits !== undefined
          ? body.merits : safeParse(existing.merits_json, []),
        flaws: body.flaws !== undefined
          ? body.flaws : safeParse(existing.flaws_json, []),
        rulesOverride,
      };

      const check = rules.validateCoterie(merged);
      if (check.errors.length) {
        return reply.status(400).json({ error: check.errors[0], errors: check.errors });
      }

      const fields = [
        'name=?', 'type=?', 'concept=?', 'domain_id=?',
        'chasse=?', 'lien=?', 'portillon=?',
        'required_json=?', 'backgrounds_json=?', 'merits_json=?', 'flaws_json=?', 'extras_json=?',
        'points_per_member=?', 'bonus_points=?', 'rules_override=?',
      ];
      const params = [
        String(merged.name).trim(),
        body.type !== undefined ? (body.type || null) : existing.type,
        body.concept !== undefined
          ? (body.concept ? String(body.concept).slice(0, 500) : null)
          : existing.concept,
        merged.domainId ? Number(merged.domainId) : null,
        check.traits.chasse, check.traits.lien, check.traits.portillon,
        body.required !== undefined
          ? (body.required ? JSON.stringify(body.required) : null)
          : existing.required_json,
        JSON.stringify(check.backgrounds),
        JSON.stringify(check.merits),
        JSON.stringify(check.flaws),
        body.extras !== undefined
          ? JSON.stringify(Array.isArray(body.extras) ? body.extras : [])
          : existing.extras_json,
        check.pointsPerMember,
        Number(merged.bonusPoints) || 0,
        rulesOverride ? 1 : 0,
      ];

      // coterie_xp is never writable here — it moves only through /xp
      // (ST award) and /purchase (member spend), both of which write a ledger
      // row. Letting PUT set it was how members minted unlimited XP.
      if (admin && body.coterie_xp !== undefined
          && Number(body.coterie_xp) !== Number(existing.coterie_xp)) {
        const target = Math.max(0, Number(body.coterie_xp) || 0);
        const delta = target - Number(existing.coterie_xp || 0);
        fields.push('coterie_xp=?');
        params.push(target);
        await pool.query(
          `INSERT INTO coterie_xp_log (coterie_id, user_id, kind, bank_delta, note)
           VALUES (?,?,?,?,?)`,
          [id, req.user.id, 'adjust', delta, 'Set directly by Storyteller']
        );
      }

      await pool.query(`UPDATE coteries SET ${fields.join(', ')} WHERE id=?`, [...params, id]);

      const [[row]] = await pool.query('SELECT * FROM coteries WHERE id=?', [id]);
      reply.send({
        coterie: presentCoterie(row, members),
        members,
        warnings: check.warnings,
      });
    } catch (e) {
      log.err('Update coterie failed', { message: e.message, stack: e.stack });
      reply.status(500).json({ error: 'Failed to update coterie' });
    }
  });

  /* ================================================================ *
   * Membership
   * ================================================================ */

  fastify.post('/api/coteries/:id/members/set', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const id = Number(req.params.id);
      const { allowed, admin } = await access(req, id);
      if (!allowed) return reply.status(403).json({ error: 'Not allowed' });

      const members = Array.isArray((req.body || {}).members) ? req.body.members : [];
      if (!admin && !members.some((m) => Number(m.user_id) === Number(req.user.id))) {
        return reply.status(403).json({ error: 'You must include yourself in the coterie' });
      }

      const { rows, missing } = await resolveMembers(members);
      if (missing.length) {
        return reply.status(400).json({
          error: 'Every member needs a character sheet before joining a coterie.',
          missing_user_ids: missing,
        });
      }
      if (rows.length < rules.MIN_MEMBERS) {
        return reply.status(400).json({ error: `At least ${rules.MIN_MEMBERS} members are required` });
      }

      const before = await loadMembers(null, id);

      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        await conn.query('DELETE FROM coterie_members WHERE coterie_id=?', [id]);
        await conn.query(
          'INSERT INTO coterie_members (coterie_id, user_id, character_id, display_name) VALUES ?',
          [rows.map((r) => [id, r[0], r[1], r[2]])]
        );
        await conn.commit();
      } catch (e) {
        await conn.rollback();
        throw e;
      } finally {
        conn.release();
      }

      // Membership changes shift the coterie pool, so they are worth a trace
      // even though any member is allowed to make them.
      const removed = before
        .filter((b) => !rows.some((r) => r[0] === b.user_id))
        .map((b) => b.character_name || b.user_id);
      if (removed.length) {
        log.adm('Coterie members removed', {
          coterie_id: id, by_user_id: req.user.id, removed,
        });
      }

      const after = await loadMembers(null, id);
      reply.send({ members: after });
    } catch (e) {
      log.err('Set coterie members failed', { message: e.message, stack: e.stack });
      reply.status(500).json({ error: 'Failed to set members' });
    }
  });

  /* ================================================================ *
   * XP — award (ST only)
   * ================================================================ */

  fastify.post('/api/coteries/:id/xp', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const id = Number(req.params.id);
      const delta = Math.trunc(Number((req.body || {}).delta) || 0);
      if (!delta) return reply.status(400).json({ error: 'delta must be a non-zero integer' });

      const [[row]] = await pool.query('SELECT coterie_xp FROM coteries WHERE id=?', [id]);
      if (!row) return reply.status(404).json({ error: 'Not found' });

      const before = Number(row.coterie_xp) || 0;
      const after = Math.max(0, before + delta);
      const applied = after - before;

      await pool.query('UPDATE coteries SET coterie_xp=? WHERE id=?', [after, id]);
      await pool.query(
        `INSERT INTO coterie_xp_log (coterie_id, user_id, kind, bank_delta, note)
         VALUES (?,?,?,?,?)`,
        [id, req.user.id, applied >= 0 ? 'award' : 'adjust', applied,
         ((req.body || {}).note || '').slice(0, 500) || null]
      );

      log.xp('Coterie XP award', { coterie_id: id, by_user_id: req.user.id, delta: applied });
      reply.send({ coterie_xp: after });
    } catch (e) {
      log.err('Adjust coterie XP failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to adjust XP' });
    }
  });

  /* ================================================================ *
   * XP — purchase (members, hybrid bank + personal top-up)
   * ================================================================ */

  /**
   * Raise a Domain trait, Background or Merit after character creation.
   *
   * body: {
   *   target: { kind: 'domain'|'background'|'merit', key: string },
   *   to_dots: number,
   *   from_bank: number,        // XP drawn from the coterie bank
   *   from_personal: number,    // XP drawn from the caller's own character
   *   note?: string
   * }
   *
   * Cost is the V5 Advantage rate: 3 XP per new dot. The two funding sources
   * must add up to exactly the cost — the client proposes the split, the
   * server verifies both sides can cover it and moves them atomically.
   */
  fastify.post('/api/coteries/:id/purchase', { preHandler: [authRequired] }, async (req, reply) => {
    const id = Number(req.params.id);
    const body = req.body || {};
    const target = body.target || {};
    const kind = String(target.kind || '');
    const key = String(target.key || '').trim().toLowerCase();
    const toDots = Math.trunc(Number(body.to_dots));

    const { allowed } = await access(req, id);
    if (!allowed) return reply.status(403).json({ error: 'Not allowed' });

    if (!['domain', 'background', 'merit'].includes(kind)) {
      return reply.status(400).json({ error: 'target.kind must be domain, background or merit' });
    }
    if (!Number.isFinite(toDots) || toDots < 0 || toDots > rules.MAX_DOTS) {
      return reply.status(400).json({ error: `to_dots must be between 0 and ${rules.MAX_DOTS}` });
    }

    const catalog = kind === 'domain' ? null
      : kind === 'background' ? rules.COTERIE_BACKGROUNDS
      : rules.COTERIE_MERITS;
    if (kind === 'domain' && !rules.DOMAIN_TRAITS.includes(key)) {
      return reply.status(400).json({ error: 'Unknown domain trait' });
    }
    if (catalog && !catalog[key]) {
      return reply.status(400).json({ error: `Unknown coterie ${kind}: ${key}` });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [[row]] = await conn.query('SELECT * FROM coteries WHERE id=? FOR UPDATE', [id]);
      if (!row) { await conn.rollback(); return reply.status(404).json({ error: 'Not found' }); }

      const traits = {
        chasse: Number(row.chasse) || 0,
        lien: Number(row.lien) || 0,
        portillon: Number(row.portillon) || 0,
      };
      const backgrounds = safeParse(row.backgrounds_json, []);
      const merits = safeParse(row.merits_json, []);
      const flaws = safeParse(row.flaws_json, []);

      const list = kind === 'background' ? backgrounds : merits;
      const existingEntry = kind === 'domain' ? null : list.find((x) => x.key === key);
      const fromDots = kind === 'domain' ? traits[key] : (existingEntry ? Number(existingEntry.dots) || 0 : 0);

      if (toDots <= fromDots) {
        await conn.rollback();
        return reply.status(400).json({
          error: 'XP buys new dots only. Drop a rating with the builder instead — V5 gives no refund.',
        });
      }

      const cost = rules.xpForDots(fromDots, toDots);

      const fromBank = Math.max(0, Math.trunc(Number(body.from_bank) || 0));
      const fromPersonal = Math.max(0, Math.trunc(Number(body.from_personal) || 0));
      if (fromBank + fromPersonal !== cost) {
        await conn.rollback();
        return reply.status(400).json({
          error: `Funding must total the cost of ${cost} XP (got ${fromBank + fromPersonal}).`,
          cost,
        });
      }

      const bank = Number(row.coterie_xp) || 0;
      if (fromBank > bank) {
        await conn.rollback();
        return reply.status(400).json({
          error: `The coterie bank holds ${bank} XP, cannot draw ${fromBank}.`, cost,
        });
      }

      // Personal top-up comes out of the caller's own character sheet.
      let character = null;
      if (fromPersonal > 0) {
        const [[ch]] = await conn.query(
          'SELECT id, name, xp FROM characters WHERE user_id=? ORDER BY id ASC LIMIT 1 FOR UPDATE',
          [req.user.id]
        );
        if (!ch) {
          await conn.rollback();
          return reply.status(400).json({ error: 'You need a character sheet to contribute personal XP.' });
        }
        if ((Number(ch.xp) || 0) < fromPersonal) {
          await conn.rollback();
          return reply.status(400).json({
            error: `Not enough personal XP (need ${fromPersonal}, have ${ch.xp || 0}).`, cost,
          });
        }
        character = ch;
      }

      // Apply the dot change, then re-validate the whole coterie so a purchase
      // can never push it into an illegal state (e.g. a Domain Merit bought
      // for a trait the coterie no longer holds).
      if (kind === 'domain') {
        traits[key] = toDots;
      } else if (existingEntry) {
        existingEntry.dots = toDots;
        existingEntry.name = catalog[key].name;
      } else {
        list.push({ key, name: catalog[key].name, dots: toDots, note: null });
      }

      const members = await loadMembers(conn, id);
      const check = rules.validateCoterie({
        name: row.name,
        memberCount: members.length,
        pointsPerMember: row.points_per_member,
        bonusPoints: row.bonus_points,
        domainId: row.domain_id,
        traits,
        backgrounds,
        merits,
        flaws,
        // XP purchases legitimately exceed the creation pool — that is the
        // point of advancement — so only the structural rules apply here.
        rulesOverride: true,
      });
      if (check.errors.length) {
        await conn.rollback();
        return reply.status(400).json({ error: check.errors[0], errors: check.errors });
      }

      await conn.query(
        `UPDATE coteries
            SET chasse=?, lien=?, portillon=?, backgrounds_json=?, merits_json=?, coterie_xp=?
          WHERE id=?`,
        [
          check.traits.chasse, check.traits.lien, check.traits.portillon,
          JSON.stringify(check.backgrounds), JSON.stringify(check.merits),
          bank - fromBank, id,
        ]
      );

      if (fromPersonal > 0 && character) {
        await conn.query('UPDATE characters SET xp = xp - ? WHERE id=?', [fromPersonal, character.id]);
        await conn.query(
          `INSERT INTO xp_log (character_id, action, target, from_level, to_level, cost, payload)
           VALUES (?,?,?,?,?,?,?)`,
          [
            character.id, 'coterie_advantage',
            `${row.name}: ${kind === 'domain' ? key : catalog[key].name}`,
            fromDots, toDots, fromPersonal,
            JSON.stringify({ coterie_id: id, kind, key, from_bank: fromBank }),
          ]
        ).catch(() => { /* xp_log is best-effort, as elsewhere */ });
      }

      const targetName = kind === 'domain'
        ? key.charAt(0).toUpperCase() + key.slice(1)
        : catalog[key].name;

      await conn.query(
        `INSERT INTO coterie_xp_log
          (coterie_id, user_id, kind, bank_delta, personal_delta, character_id,
           target_type, target_key, target_name, from_dots, to_dots, note)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          id, req.user.id, 'spend', -fromBank, -fromPersonal,
          character ? character.id : null,
          kind, key, targetName, fromDots, toDots,
          (body.note || '').slice(0, 500) || null,
        ]
      );

      await conn.commit();

      const [[updated]] = await pool.query('SELECT * FROM coteries WHERE id=?', [id]);
      log.xp('Coterie purchase', {
        coterie_id: id, by_user_id: req.user.id, kind, key,
        from: fromDots, to: toDots, cost, from_bank: fromBank, from_personal: fromPersonal,
      });
      reply.send({
        coterie: presentCoterie(updated, members),
        members,
        spent: { cost, from_bank: fromBank, from_personal: fromPersonal },
        warnings: check.warnings,
      });
    } catch (e) {
      await conn.rollback();
      log.err('Coterie purchase failed', { message: e.message, stack: e.stack });
      reply.status(500).json({ error: 'Failed to complete the purchase' });
    } finally {
      conn.release();
    }
  });

  /* ================================================================ *
   * Delete
   * ================================================================ */

  fastify.delete('/api/coteries/:id', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const id = Number(req.params.id);
      await pool.query('DELETE FROM coteries WHERE id=?', [id]);
      log.adm('Coterie deleted', { id, by_user_id: req.user.id });
      reply.send({ ok: true });
    } catch (e) {
      log.err('Delete coterie failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to delete coterie' });
    }
  });
};

module.exports.presentCoterie = presentCoterie;

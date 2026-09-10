// services/domainManagers.js
//
// "Domain Stewards": the users allowed to run the Athens claims map —
// approve/deny claim requests, directly assign or vacate divisions, moderate
// the codex, and read the incident log.
//
// Admins can always do this and are not stored anywhere. Everyone else needs a
// row in `domain_manager_grants`, which only an admin can add/remove (via the
// Claims tab in the admin panel). The `courtuser` role no longer confers any
// of this — that was the whole point of the table.

const pool = require('../db');

/** admin OR an explicit grant. */
async function isDomainManager(userId, role) {
  if (role === 'admin') return true;
  if (!userId) return false;
  const [rows] = await pool.query(
    'SELECT 1 FROM domain_manager_grants WHERE user_id = ? LIMIT 1',
    [userId],
  );
  return rows.length > 0;
}

/** Fastify preHandler — 403s anyone who isn't a Domain Steward. */
async function requireDomainManager(req, reply) {
  if (await isDomainManager(req.user?.id, req.user?.role)) return;
  return reply.status(403).send({ error: 'Forbidden: Domain Steward access required' });
}

/**
 * The roster, for the admin manager UI and the read-only dossier display.
 * Shows the player's active character name when they have one, else the account.
 */
async function listDomainManagers() {
  const [rows] = await pool.query(`
    SELECT g.user_id, u.display_name, u.email, u.role,
           g.granted_by, gb.display_name AS granted_by_name, g.granted_at,
           ch.name AS character_name, ch.clan
    FROM domain_manager_grants g
    JOIN users u ON u.id = g.user_id
    LEFT JOIN users gb ON gb.id = g.granted_by
    LEFT JOIN (
      SELECT user_id, name, clan
      FROM (
        SELECT user_id, name, clan,
               ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY id) AS rn
        FROM characters
        WHERE COALESCE(is_deceased, 0) = 0 AND COALESCE(is_left, 0) = 0
      ) active_chars
      WHERE rn = 1
    ) ch ON ch.user_id = g.user_id
    ORDER BY (character_name IS NULL), character_name, u.display_name, u.email
  `);
  return rows.map(r => ({
    user_id: r.user_id,
    name: r.character_name || r.display_name || r.email,
    account: r.display_name || r.email,
    role: r.role,
    clan: r.clan || null,
    granted_by_name: r.granted_by_name || null,
    granted_at: r.granted_at,
  }));
}

module.exports = { isDomainManager, requireDomainManager, listDomainManagers };

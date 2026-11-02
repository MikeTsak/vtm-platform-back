// services/domainOverlays.js
//
// Domains-map restricted overlays: per-user access.
// Free for everyone: the base map + transit. Locked otherwise: 'catacombs',
// 'necropolis_old', 'necropolis_new'. Admins get all; anything else needs an explicit grant.

const pool = require('../db');

const DOMAIN_OVERLAY_KEYS = ['catacombs', 'necropolis_old', 'necropolis_new'];

async function resolveOverlayAccess(userId, role) {
  if (role === 'admin') return { overlays: [...DOMAIN_OVERLAY_KEYS], admin: true };
  const set = new Set();
  const [grants] = await pool.query('SELECT overlay_key FROM domain_overlay_grants WHERE user_id=?', [userId]);
  for (const g of grants) if (DOMAIN_OVERLAY_KEYS.includes(g.overlay_key)) set.add(g.overlay_key);
  return { overlays: [...set], admin: false };
}

module.exports = { DOMAIN_OVERLAY_KEYS, resolveOverlayAccess };

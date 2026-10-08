// services/courtOffices.js
//
// Court offices come from the character's camarilla_titles (set in the
// Hierarchy editor). Court Actions is gated on the `courtuser` account role,
// and the office then decides which panels that court user gets. Former
// office holders (characters.is_ex) and the dead hold no office.

const pool = require('../db');

// Mirrors mainCourtTitles in front/src/features/court/HierarchyView.jsx: holding
// one of these is what makes an account a court user.
const MAIN_COURT = ['Prince', 'Seneschal', 'Sheriff', 'Keeper', 'Harpy', 'Assistant Harpy', 'Hound', 'Shadow', 'Scourge'];

// Which offices may do what. Admin may do everything.
const CAN = {
  callBloodHunt: ['Prince'],                                  // goes live at once, and ratifies proposals
  proposeBloodHunt: ['Seneschal', 'Sheriff', 'Scourge'],      // needs the Prince to ratify
  security: ['Prince', 'Seneschal', 'Sheriff', 'Scourge', 'Hound'], // the dangerous-domains ranking
  decree: ['Prince', 'Seneschal'],                            // announcement + push to every player
  wanted: ['Sheriff', 'Scourge', 'Hound'],
  harpy: ['Harpy', 'Assistant Harpy'],
  keeper: ['Keeper'],
};

function parseTitles(raw) {
  if (Array.isArray(raw)) return raw.filter(t => typeof t === 'string');
  if (typeof raw !== 'string' || !raw.trim()) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.filter(t => typeof t === 'string');
    if (typeof parsed === 'string') return [parsed];
  } catch { /* legacy comma list */ }
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}

// Offices the caller currently holds, across their living, current characters.
async function getOffices(user) {
  if (!user) return [];
  const [rows] = await pool.query(
    'SELECT camarilla_titles FROM characters WHERE user_id = ? AND COALESCE(is_ex, 0) = 0 AND COALESCE(is_deceased, 0) = 0',
    [user.id]
  );
  return [...new Set(rows.flatMap(r => parseTitles(r.camarilla_titles)))];
}

// The permission map the frontend renders panels from.
async function getCourtContext(user) {
  const isAdmin = user?.role === 'admin';
  const isCourt = isAdmin || user?.role === 'courtuser';
  const offices = isCourt ? await getOffices(user) : [];
  const can = {};
  for (const [k, list] of Object.entries(CAN)) can[k] = isAdmin || (isCourt && offices.some(o => list.includes(o)));
  return { isAdmin, isCourt, offices, can };
}

// preHandler factory: 403 unless the caller is a court user holding one of the
// offices behind `capability` (or is admin).
function requireCapability(capability) {
  return async (req, reply) => {
    const ctx = await getCourtContext(req.user);
    if (!ctx.can[capability]) {
      return reply.status(403).send({ error: 'Your office does not grant this power.' });
    }
    req.court = ctx;
  };
}

// The office to sign an action with: the first of the caller's offices that grants it.
function signingOffice(ctx, capability) {
  if (!ctx) return null;
  return ctx.offices.find(o => CAN[capability].includes(o)) || (ctx.isAdmin ? 'Storyteller' : null);
}

module.exports = { MAIN_COURT, CAN, parseTitles, getOffices, getCourtContext, requireCapability, signingOffice };

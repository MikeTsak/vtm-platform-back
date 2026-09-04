// utils/coterieRules.js
//
// Authoritative V5 coterie rules engine. Pure functions + static catalogs, no
// db/log/req imports, so it is trivially unit-testable and safe to require
// from anywhere (routes, tests, scripts).
//
// The frontend keeps a richer catalog (front/src/data/coterieRules.js) with
// prose descriptions for the UI. THIS file is the one that decides whether a
// coterie is legal — the client is never trusted. Keys must stay in sync; see
// tests/coterieRules.test.js which pins the key lists.
//
// Sources: V:tM 5th ed. Corebook pp. 195-199 (Coterie Creation, Domain,
// Coterie Backgrounds, Types of Coteries) and the V5 Players Guide
// (Coterie Backgrounds and Merits).

/* ------------------------------------------------------------------ *
 * Domain traits
 * ------------------------------------------------------------------ */

const DOMAIN_TRAITS = ['chasse', 'lien', 'portillon'];
const MAX_DOTS = 5;

// Corebook p.196: "One dot in Chasse provides the coterie with a default
// hunting Difficulty of 6 inside their domain. Each additional dot reduces
// that Difficulty by one."
//
// Returns null when the coterie has no Chasse at all — such a coterie has no
// hunting ground of its own and the ST sets the Difficulty (corebook p.308).
function huntingDifficulty(chasse) {
  const c = Number(chasse) || 0;
  if (c < 1) return null;
  return Math.max(1, 7 - Math.min(MAX_DOTS, c));
}

// Corebook p.196: "Each dot in Lien adds one die to a coterie member's pool
// on attempts to [...] interact peacefully with a native mortal; find
// something, someone, or somewhere specific within the domain; find out the
// 'word on the street'; or otherwise investigate something within the
// domain." Lien never modifies coterie member hunting rolls.
function lienBonusDice(lien) {
  return Math.min(MAX_DOTS, Math.max(0, Number(lien) || 0));
}

// Corebook p.196: "Each dot of Portillon subtracts one die from a foe's pool
// when they attempt to [...] enter, investigate, or surveil the domain
// without the coterie's knowledge." Portillon does not apply to Havens.
function portillonPenaltyDice(portillon) {
  return Math.min(MAX_DOTS, Math.max(0, Number(portillon) || 0));
}

// Corebook p.196 Chasse geographical-equivalent table.
const CHASSE_SIZE_TABLE = {
  1: 'One city block, one suburban gated community',
  2: 'Two to four blocks, one park and its entrances, one small site (tourist landmark, hospital, mall)',
  3: 'Eight blocks on both sides of a major street, one medium site (airport, major employer, casino, college)',
  4: 'One neighborhood or defined district, a square kilometer; everything along one highway or major street, one major site (large university, amusement park)',
  5: 'Three neighborhoods, a large group of features ("all parks on the South Side", "all hospitals in Queens", "all highways south of the river")',
};

/* ------------------------------------------------------------------ *
 * Coterie Backgrounds
 * ------------------------------------------------------------------ */

// Corebook p.196: "Coteries can hold certain Backgrounds and Flaws in common:
// Adversary, Ally, Contacts, Enemy, Haven, Herd, Influence, Mask, Mawla,
// Resources, Retainers, and Status."
//
// `flaw: true` entries are the Flaw side of a Background pair — taking them
// GRANTS pool dots rather than costing them (corebook p.195: "The coterie can
// also purchase coterie Flaws to get more dots for the coterie").
const COTERIE_BACKGROUNDS = {
  adversary: { name: 'Adversary', max: 5, flaw: true },
  ally: { name: 'Ally', max: 6 },
  contacts: { name: 'Contacts', max: 5 },
  enemy: { name: 'Enemy', max: 5, flaw: true },
  haven: { name: 'Haven', max: 5 },
  herd: { name: 'Herd', max: 5 },
  influence: { name: 'Influence', max: 5 },
  mask: { name: 'Mask', max: 2 },
  mawla: { name: 'Mawla', max: 5 },
  resources: { name: 'Resources', max: 5 },
  retainers: { name: 'Retainers', max: 5 },
  status: { name: 'Status', max: 5 },

  // Beyond the corebook's list of twelve, but required outright by coterie
  // types printed in the Players Guide (Carnival wants Fame •••, Schism and
  // Excommunicates want Loresheet •••, The Decade Club wants Library •••),
  // so a coterie cannot be built to spec without them. Flagged so the UI can
  // say where they come from.
  fame: { name: 'Fame', max: 5, extended: true },
  loresheet: { name: 'Loresheet', max: 5, extended: true },
  library: { name: 'Library', max: 5, extended: true },
};

const COTERIE_BACKGROUND_KEYS = Object.keys(COTERIE_BACKGROUNDS);

/* ------------------------------------------------------------------ *
 * Coterie Merits (Players Guide) — these cost pool dots / XP
 * ------------------------------------------------------------------ */

// General coterie Merits, available to any coterie.
const COTERIE_MERITS_GENERAL = {
  bolt_holes: { name: 'Bolt Holes', min: 1, max: 3 },
  on_tap: { name: 'On Tap', min: 1, max: 3 },
  privileged: { name: 'Privileged', min: 3, max: 3 },
  transportation: { name: 'Transportation', min: 2, max: 2 },
};

// Domain Merits — each is anchored to one Domain trait and therefore requires
// the coterie to actually hold a Domain with at least one dot in that trait.
const COTERIE_MERITS_DOMAIN = {
  // Chasse
  apartment_towers: { name: 'Apartment Towers', min: 2, max: 2, trait: 'chasse' },
  back_alleys: { name: 'Back Alleys', min: 2, max: 2, trait: 'chasse' },
  funerary: { name: 'Funerary', min: 1, max: 1, trait: 'chasse' },
  gated_community: { name: 'Gated Community', min: 2, max: 2, trait: 'chasse' },
  hospital: { name: 'Hospital', min: 2, max: 2, trait: 'chasse' },
  nightlife: { name: 'Nightlife', min: 3, max: 3, trait: 'chasse' },
  shelter: { name: 'Shelter', min: 2, max: 2, trait: 'chasse' },
  built_in_flock: { name: 'Built-In Flock', min: 1, max: 1, trait: 'chasse' },
  mithraeum: { name: 'Mithraeum', min: 2, max: 2, trait: 'chasse' },
  // Lien
  campus: { name: 'Campus', min: 3, max: 3, trait: 'lien' },
  city_hall: { name: 'City Hall', min: 3, max: 3, trait: 'lien' },
  cultural_landmark: { name: 'Cultural Landmark', min: 2, max: 2, trait: 'lien' },
  marketplace: { name: 'Marketplace', min: 2, max: 2, trait: 'lien' },
  members_only: { name: 'Members Only', min: 2, max: 2, trait: 'lien' },
  transitions: { name: 'Transitions', min: 2, max: 2, trait: 'lien' },
  community_outreach: { name: 'Community Outreach', min: 1, max: 1, trait: 'lien' },
  // Portillon
  abandoned_building: { name: 'Abandoned Building', min: 1, max: 1, trait: 'portillon' },
  firehouse: { name: 'Firehouse', min: 3, max: 3, trait: 'portillon' },
  police_station: { name: 'Police Station', min: 2, max: 2, trait: 'portillon' },
  prison: { name: 'Prison', min: 2, max: 2, trait: 'portillon' },
  transit: { name: 'Transit', min: 2, max: 2, trait: 'portillon' },
  networked: { name: 'Networked', min: 1, max: 1, trait: 'portillon' },
};

// Clan coterie Merits — require at least one member of that clan.
const COTERIE_MERITS_CLAN = {
  call_to_purpose: { name: 'Call to Purpose', min: 2, max: 2, clan: 'Banu Haqim' },
  boot_and_rally: { name: 'Boot and Rally', min: 1, max: 1, clan: 'Brujah' },
  pack_tactics: { name: 'Pack Tactics', min: 3, max: 3, clan: 'Gangrel' },
  ars_moriendi: { name: 'Ars Moriendi', min: 2, max: 2, clan: 'Hecata' },
  at_any_cost: { name: 'At Any Cost', min: 2, max: 2, clan: 'Lasombra' },
  everything_is_connected: { name: 'Everything is Connected', min: 3, max: 3, clan: 'Malkavian' },
  discerning: { name: 'Discerning', min: 1, max: 1, clan: 'The Ministry' },
  contextual_contact: { name: 'Contextual Contact', min: 2, max: 2, clan: 'Nosferatu' },
  cryptolect: { name: 'Cryptolect', min: 3, max: 3, clan: 'Ravnos' },
  restraint: { name: 'Restraint', min: 3, max: 3, clan: 'Salubri' },
  all_access: { name: 'All Access', min: 1, max: 1, clan: 'Toreador' },
  multi_level_lorekeeping: { name: 'Multi-Level Lorekeeping', min: 2, max: 2, clan: 'Tremere' },
  old_world_hospitality: { name: 'Old-World Hospitality', min: 2, max: 2, clan: 'Tzimisce' },
  kindred_legacies: { name: 'Kindred Legacies', min: 2, max: 2, clan: 'Ventrue' },
  versatile_vitae: { name: 'Versatile Vitae', min: 2, max: 2, clan: 'Caitiff' },
  mortal_heart: { name: 'Mortal Heart', min: 2, max: 2, clan: 'Thin-blood' },
};

const COTERIE_MERITS = {
  ...COTERIE_MERITS_GENERAL,
  ...COTERIE_MERITS_DOMAIN,
  ...COTERIE_MERITS_CLAN,
};

const COTERIE_MERIT_KEYS = Object.keys(COTERIE_MERITS);

/* ------------------------------------------------------------------ *
 * Coterie Flaws — taking these GRANTS pool dots
 * ------------------------------------------------------------------ */

const COTERIE_FLAWS = {
  bullies: { name: 'Bullies', min: 1, max: 1 },
  cursed: { name: 'Cursed', min: 1, max: 2 },
  custodians: { name: 'Custodians', min: 2, max: 2 },
  targeted: { name: 'Targeted', min: 1, max: 1 },
  territorial: { name: 'Territorial', min: 1, max: 1 },
  under_siege: { name: 'Under Siege', min: 1, max: 2 },
  disputed_domain: { name: 'Disputed Domain', min: 2, max: 2, trait: 'chasse' },
  visibility: { name: 'Visibility', min: 2, max: 2, trait: 'lien' },
  shared_vulnerabilities: { name: 'Shared Vulnerabilities', min: 1, max: 1, trait: 'portillon' },
  // Background-flaw side, usable as a coterie Flaw (corebook p.196 list).
  adversary: { name: 'Adversary', min: 1, max: 5 },
  enemy: { name: 'Enemy', min: 1, max: 5 },
  suspect: { name: 'Status Flaw: Suspect', min: 1, max: 1 },
  notorious: { name: 'Status Flaw: Notorious', min: 1, max: 1 },
  excommunicated: { name: 'Excommunicated', min: 1, max: 2 },
  infamy: { name: 'Infamy', min: 1, max: 3 },
  despised: { name: 'Despised', min: 2, max: 2 },
  shunned: { name: 'Shunned', min: 3, max: 3 },
  dark_secret: { name: 'Dark Secret', min: 1, max: 2 },
  no_haven: { name: 'No Haven', min: 1, max: 1 },
  destitute: { name: 'Destitute', min: 1, max: 1 },
  haunted: { name: 'Haven Flaw: Haunted', min: 1, max: 1 },
  compromised_haven: { name: 'Compromised Haven', min: 1, max: 2 },
  stalkers: { name: 'Stalkers', min: 1, max: 1 },
};

const COTERIE_FLAW_KEYS = Object.keys(COTERIE_FLAWS);

/* ------------------------------------------------------------------ *
 * XP
 * ------------------------------------------------------------------ */

// V5 advancement: Advantages cost 3 XP per dot. Coterie Domain traits,
// Backgrounds and Merits are all Advantages, so they all use this rate.
// Mirrors utils/xpCost.js `type: 'advantage'`.
const XP_PER_DOT = 3;

function xpForDots(fromDots, toDots) {
  const delta = (Number(toDots) || 0) - (Number(fromDots) || 0);
  return delta > 0 ? delta * XP_PER_DOT : 0;
}

// Dropping dots refunds nothing by default — V5 has no refund rule and
// refunding would let a coterie launder XP by pumping and dumping a trait.
function xpRefundForDots() {
  return 0;
}

/* ------------------------------------------------------------------ *
 * Pool arithmetic
 * ------------------------------------------------------------------ */

const sumDots = (list) =>
  (Array.isArray(list) ? list : []).reduce((n, x) => n + (Number(x && x.dots) || 0), 0);

// Corebook p.195: "The coterie pool begins with one free dot per player
// character. (The Storyteller may allow player groups with three or fewer
// players to begin with a coterie pool of two free dots per character.)
// Players may also contribute their own characters' Advantage dots to the
// coterie pool." Coterie Flaws add further dots.
function computePool({ memberCount, pointsPerMember, bonusPoints, flaws }) {
  const base = (Number(memberCount) || 0) * (Number(pointsPerMember) || 1);
  const bonus = Number(bonusPoints) || 0;
  const fromFlaws = sumDots(flaws);
  return { base, bonus, fromFlaws, total: base + bonus + fromFlaws };
}

// Every dot the coterie holds is paid from the pool — including the Domain
// dots listed by its type. Corebook p.197: "If your coterie matches a given
// type, subtract the listed costs from the coterie pool."
function computeSpend({ traits, backgrounds, merits }) {
  const t = traits || {};
  const domain = DOMAIN_TRAITS.reduce((n, k) => n + (Number(t[k]) || 0), 0);
  const bg = sumDots(backgrounds);
  const mr = sumDots(merits);
  return { domain, backgrounds: bg, merits: mr, total: domain + bg + mr };
}

function computeBudget(input) {
  const pool = computePool(input);
  const spend = computeSpend(input);
  return { pool, spend, remaining: pool.total - spend.total };
}

/* ------------------------------------------------------------------ *
 * Validation
 * ------------------------------------------------------------------ */

const MIN_MEMBERS = 3; // House rule for this chronicle (see COTERIE_DOC).

function normalizeEntries(list, catalog) {
  if (!Array.isArray(list)) return [];
  const seen = new Set();
  const out = [];
  for (const raw of list) {
    if (!raw) continue;
    const key = String(raw.key || '').trim().toLowerCase();
    if (!key || !catalog[key] || seen.has(key)) continue;
    seen.add(key);
    out.push({
      key,
      name: catalog[key].name,
      dots: Math.max(0, Math.min(MAX_DOTS, Number(raw.dots) || 0)),
      note: raw.note ? String(raw.note).slice(0, 240) : null,
    });
  }
  return out;
}

/**
 * Validates a coterie payload against V5 rules.
 *
 * @param {object} input
 * @param {boolean} input.rulesOverride  ST flag; relaxes the budget and
 *   dot-range ceilings but never the structural rules (legal keys, member
 *   count, domain/trait coherence).
 * @returns {{ errors: string[], warnings: string[], budget: object,
 *             backgrounds: object[], merits: object[], flaws: object[] }}
 */
function validateCoterie(input = {}) {
  const errors = [];
  const warnings = [];

  const name = String(input.name || '').trim();
  const memberCount = Number(input.memberCount) || 0;
  const pointsPerMember = Math.min(2, Math.max(1, Number(input.pointsPerMember) || 1));
  const domainId = input.domainId == null || input.domainId === '' ? null : Number(input.domainId);
  const rulesOverride = !!input.rulesOverride;

  const traits = {};
  for (const k of DOMAIN_TRAITS) {
    traits[k] = Math.max(0, Math.min(MAX_DOTS, Number((input.traits || {})[k]) || 0));
  }

  const backgrounds = normalizeEntries(input.backgrounds, COTERIE_BACKGROUNDS);
  const merits = normalizeEntries(input.merits, COTERIE_MERITS);
  const flaws = normalizeEntries(input.flaws, COTERIE_FLAWS);

  const budget = computeBudget({
    memberCount,
    pointsPerMember,
    bonusPoints: Number(input.bonusPoints) || 0,
    traits,
    backgrounds,
    merits,
    flaws,
  });

  /* --- structural rules: always enforced --- */

  if (!name) errors.push('Missing coterie name.');
  if (name.length > 160) errors.push('Coterie name is too long (max 160 characters).');

  if (memberCount < MIN_MEMBERS) {
    errors.push(`At least ${MIN_MEMBERS} members are required (currently ${memberCount}).`);
  }

  // Corebook p.195: the two-dots-per-character option exists for "player
  // groups with three or fewer players".
  if (pointsPerMember === 2 && memberCount > 3) {
    warnings.push(
      'Two pool dots per member is the Storyteller option for groups of three or fewer players; ' +
      `this coterie has ${memberCount}.`
    );
  }

  const hasDomain = domainId != null && Number.isFinite(domainId);
  const anyTrait = DOMAIN_TRAITS.some((k) => traits[k] > 0);

  if (!hasDomain && anyTrait) {
    errors.push(
      'Chasse, Lien and Portillon describe a Domain. Either claim a Domain division or set all three to zero.'
    );
  }
  if (hasDomain && traits.chasse < 1) {
    errors.push('A claimed Domain needs at least Chasse • to function as a hunting ground.');
  }
  if (!hasDomain) {
    warnings.push(
      'Coteries without a Domain must poach (at grave risk from the domain holder) or carry a letter of passage; ' +
      'the Storyteller sets hunting Difficulty.'
    );
  }

  // Domain Merits are anchored to a Domain trait.
  for (const m of merits) {
    const def = COTERIE_MERITS[m.key];
    if (def.trait && traits[def.trait] < 1) {
      errors.push(`${def.name} is a ${def.trait} Merit and needs at least one dot of ${def.trait}.`);
    }
    if (def.clan) {
      warnings.push(`${def.name} requires a ${def.clan} member in the coterie.`);
    }
  }
  for (const f of flaws) {
    const def = COTERIE_FLAWS[f.key];
    if (def.trait && traits[def.trait] < 1) {
      errors.push(`${def.name} is a ${def.trait} Flaw and needs at least one dot of ${def.trait}.`);
    }
  }

  /* --- rating ranges and budget: relaxed by ST override --- */

  const rangeIssues = [];
  for (const [list, catalog, label] of [
    [backgrounds, COTERIE_BACKGROUNDS, 'Background'],
    [merits, COTERIE_MERITS, 'Merit'],
    [flaws, COTERIE_FLAWS, 'Flaw'],
  ]) {
    for (const item of list) {
      const def = catalog[item.key];
      const min = def.min != null ? def.min : 1;
      const max = def.max != null ? def.max : MAX_DOTS;
      if (item.dots < min || item.dots > max) {
        const range = min === max ? `${min}` : `${min}–${max}`;
        rangeIssues.push(`${label} ${def.name} must be rated ${range} (currently ${item.dots}).`);
      }
    }
  }

  const overspend = budget.remaining < 0;

  if (rulesOverride) {
    rangeIssues.forEach((m) => warnings.push(`[ST override] ${m}`));
    if (overspend) {
      warnings.push(
        `[ST override] Overspending the coterie pool by ${Math.abs(budget.remaining)} dot(s).`
      );
    }
  } else {
    rangeIssues.forEach((m) => errors.push(m));
    if (overspend) {
      errors.push(
        `Overspending the coterie pool by ${Math.abs(budget.remaining)} dot(s). ` +
        'Take a coterie Flaw for more dots, contribute personal Advantage dots, or trim a purchase.'
      );
    }
  }

  return { errors, warnings, budget, traits, backgrounds, merits, flaws, pointsPerMember };
}

/**
 * Checks a coterie against the requirements of its declared type. Purely
 * advisory — a troupe may drop a type's Domain dots to buy something else
 * (corebook p.195, the Maréchal example) and the coterie is still that type.
 */
function checkTypeCompliance({ typeRequirements, traits, backgrounds }) {
  const unmet = [];
  const req = typeRequirements || {};

  const held = new Map();
  for (const b of backgrounds || []) held.set(String(b.key).toLowerCase(), Number(b.dots) || 0);

  for (const [rawName, needed] of Object.entries(req.backgrounds || {})) {
    const key = String(rawName).trim().toLowerCase();
    const have = held.get(key) || 0;
    if (have < Number(needed)) {
      unmet.push({ name: rawName, needed: Number(needed), have });
    }
  }
  for (const k of DOMAIN_TRAITS) {
    const needed = Number((req.domain || {})[k]) || 0;
    const have = Number((traits || {})[k]) || 0;
    if (needed && have < needed) unmet.push({ name: k, needed, have });
  }
  return { compliant: unmet.length === 0, unmet };
}

module.exports = {
  // constants
  DOMAIN_TRAITS,
  MAX_DOTS,
  MIN_MEMBERS,
  XP_PER_DOT,
  CHASSE_SIZE_TABLE,
  COTERIE_BACKGROUNDS,
  COTERIE_BACKGROUND_KEYS,
  COTERIE_MERITS,
  COTERIE_MERITS_GENERAL,
  COTERIE_MERITS_DOMAIN,
  COTERIE_MERITS_CLAN,
  COTERIE_MERIT_KEYS,
  COTERIE_FLAWS,
  COTERIE_FLAW_KEYS,
  // derived mechanics
  huntingDifficulty,
  lienBonusDice,
  portillonPenaltyDice,
  // xp
  xpForDots,
  xpRefundForDots,
  // budget
  computePool,
  computeSpend,
  computeBudget,
  // validation
  normalizeEntries,
  validateCoterie,
  checkTypeCompliance,
};

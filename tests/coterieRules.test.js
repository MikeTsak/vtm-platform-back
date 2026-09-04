// tests/coterieRules.test.js — pure unit tests for the V5 coterie rules
// engine. No DB, no server; just utils/coterieRules.js.
//
// The numbers pinned here come from the V:tM 5th ed. Corebook pp. 195-199 and
// the V5 Players Guide. If one of these fails, either the engine drifted or
// somebody house-ruled the book — both are worth a deliberate decision.
const rules = require('../utils/coterieRules');

const baseCoterie = (over = {}) => ({
  name: 'Night Wardens',
  memberCount: 4,
  pointsPerMember: 1,
  bonusPoints: 0,
  domainId: 7,
  traits: { chasse: 1, lien: 0, portillon: 0 },
  backgrounds: [],
  merits: [],
  flaws: [],
  ...over,
});

describe('Domain trait mechanics', () => {
  it('gives Chasse 1 a hunting Difficulty of 6 and reduces it per dot', () => {
    expect(rules.huntingDifficulty(1)).toBe(6);
    expect(rules.huntingDifficulty(2)).toBe(5);
    expect(rules.huntingDifficulty(3)).toBe(4);
    expect(rules.huntingDifficulty(4)).toBe(3);
    expect(rules.huntingDifficulty(5)).toBe(2);
  });

  it('has no default hunting Difficulty without Chasse', () => {
    expect(rules.huntingDifficulty(0)).toBeNull();
  });

  it('adds one die per dot of Lien', () => {
    expect(rules.lienBonusDice(3)).toBe(3);
    expect(rules.lienBonusDice(0)).toBe(0);
  });

  it('subtracts one die from a foe per dot of Portillon', () => {
    expect(rules.portillonPenaltyDice(4)).toBe(4);
  });

  it('describes every Chasse rating on the size table', () => {
    for (let i = 1; i <= 5; i++) {
      expect(typeof rules.CHASSE_SIZE_TABLE[i]).toBe('string');
    }
  });
});

describe('XP costs', () => {
  it('charges the V5 Advantage rate of 3 XP per new dot', () => {
    expect(rules.xpForDots(0, 1)).toBe(3);
    expect(rules.xpForDots(2, 4)).toBe(6);
    expect(rules.xpForDots(1, 5)).toBe(12);
  });

  it('charges nothing for dropping a rating and refunds nothing', () => {
    expect(rules.xpForDots(4, 2)).toBe(0);
    expect(rules.xpRefundForDots(4, 2)).toBe(0);
  });
});

describe('pool arithmetic', () => {
  it('starts the pool at one free dot per member', () => {
    const { pool } = rules.computeBudget(baseCoterie({ memberCount: 5 }));
    expect(pool.total).toBe(5);
  });

  it('honours the Storyteller two-dots-per-member option', () => {
    const { pool } = rules.computeBudget(baseCoterie({ memberCount: 3, pointsPerMember: 2 }));
    expect(pool.total).toBe(6);
  });

  it('adds dots granted by coterie Flaws', () => {
    const { pool } = rules.computeBudget(baseCoterie({
      memberCount: 4,
      flaws: [{ key: 'adversary', dots: 2 }],
    }));
    expect(pool.fromFlaws).toBe(2);
    expect(pool.total).toBe(6);
  });

  // Corebook p.197: "If your coterie matches a given type, subtract the
  // listed costs from the coterie pool." A type's Domain dots are paid for,
  // not granted — the old builder treated them as free.
  it('charges the pool for every Domain dot, including a type baseline', () => {
    const { spend } = rules.computeBudget(baseCoterie({
      traits: { chasse: 2, lien: 0, portillon: 2 }, // Maréchal
    }));
    expect(spend.domain).toBe(4);
    expect(spend.total).toBe(4);
  });

  it('charges for Backgrounds and Merits alongside Domain dots', () => {
    const { spend } = rules.computeBudget(baseCoterie({
      traits: { chasse: 1, lien: 0, portillon: 3 },
      backgrounds: [{ key: 'haven', dots: 2 }],
      merits: [{ key: 'bolt_holes', dots: 1 }],
    }));
    expect(spend.domain).toBe(4);
    expect(spend.backgrounds).toBe(2);
    expect(spend.merits).toBe(1);
    expect(spend.total).toBe(7);
  });

  // The corebook's own worked example (p.195): a Maréchal coterie drops its
  // four Domain dots into Contacts and a Haven, then takes Adversary •• for
  // two more dots which go into Status.
  it('reproduces the corebook Maréchal example', () => {
    const budget = rules.computeBudget({
      memberCount: 4,
      pointsPerMember: 1,
      bonusPoints: 0,
      traits: { chasse: 0, lien: 0, portillon: 0 },
      backgrounds: [
        { key: 'contacts', dots: 3 },
        { key: 'haven', dots: 1 },
        { key: 'status', dots: 2 },
      ],
      merits: [],
      flaws: [{ key: 'adversary', dots: 2 }],
    });
    expect(budget.pool.total).toBe(6);
    expect(budget.spend.total).toBe(6);
    expect(budget.remaining).toBe(0);
  });
});

describe('validateCoterie', () => {
  it('accepts a legal coterie', () => {
    const r = rules.validateCoterie(baseCoterie({
      memberCount: 4,
      traits: { chasse: 2, lien: 1, portillon: 1 },
    }));
    expect(r.errors).toEqual([]);
  });

  it('requires a name', () => {
    const r = rules.validateCoterie(baseCoterie({ name: '   ' }));
    expect(r.errors.join(' ')).toMatch(/name/i);
  });

  it('enforces the three-member house rule', () => {
    const r = rules.validateCoterie(baseCoterie({ memberCount: 2 }));
    expect(r.errors.join(' ')).toMatch(/at least 3 members/i);
  });

  it('rejects Domain traits without a Domain', () => {
    const r = rules.validateCoterie(baseCoterie({
      domainId: null,
      traits: { chasse: 2, lien: 0, portillon: 0 },
    }));
    expect(r.errors.join(' ')).toMatch(/claim a Domain/i);
  });

  it('rejects a claimed Domain with no Chasse', () => {
    const r = rules.validateCoterie(baseCoterie({
      traits: { chasse: 0, lien: 2, portillon: 0 },
    }));
    expect(r.errors.join(' ')).toMatch(/Chasse/i);
  });

  it('warns rather than errors for a domainless coterie', () => {
    const r = rules.validateCoterie(baseCoterie({
      domainId: null,
      traits: { chasse: 0, lien: 0, portillon: 0 },
    }));
    expect(r.errors).toEqual([]);
    expect(r.warnings.join(' ')).toMatch(/poach|letter of passage/i);
  });

  it('blocks overspending the coterie pool', () => {
    const r = rules.validateCoterie(baseCoterie({
      memberCount: 3, // pool 3
      traits: { chasse: 3, lien: 3, portillon: 3 }, // spend 9
    }));
    expect(r.errors.join(' ')).toMatch(/overspending/i);
  });

  it('downgrades overspending to a warning under ST override', () => {
    const r = rules.validateCoterie(baseCoterie({
      memberCount: 3,
      traits: { chasse: 3, lien: 3, portillon: 3 },
      rulesOverride: true,
    }));
    expect(r.errors).toEqual([]);
    expect(r.warnings.join(' ')).toMatch(/ST override.*Overspending/i);
  });

  // Corebook p.196 lists exactly which Backgrounds a coterie may hold in
  // common. Anything else is silently dropped rather than saved as junk.
  it('drops Backgrounds that cannot be held in common', () => {
    const r = rules.validateCoterie(baseCoterie({
      memberCount: 6,
      backgrounds: [
        { key: 'haven', dots: 2 },
        { key: 'linguistics', dots: 2 }, // personal Merit, never shared
        { key: 'auspex', dots: 1 },
      ],
    }));
    expect(r.backgrounds.map((b) => b.key)).toEqual(['haven']);
  });

  // Carnival requires Fame •••, so the catalog has to carry it even though
  // it is outside the corebook's list of twelve.
  it('allows the extended Backgrounds the Players Guide types require', () => {
    const r = rules.validateCoterie(baseCoterie({
      memberCount: 9,
      domainId: null,
      traits: { chasse: 0, lien: 0, portillon: 0 },
      backgrounds: [
        { key: 'fame', dots: 3 },
        { key: 'loresheet', dots: 3 },
        { key: 'library', dots: 3 },
      ],
    }));
    expect(r.errors).toEqual([]);
    expect(r.backgrounds).toHaveLength(3);
  });

  it('de-duplicates repeated entries', () => {
    const r = rules.validateCoterie(baseCoterie({
      memberCount: 6,
      backgrounds: [{ key: 'haven', dots: 2 }, { key: 'haven', dots: 3 }],
    }));
    expect(r.backgrounds).toHaveLength(1);
    expect(r.backgrounds[0].dots).toBe(2);
  });

  it('enforces each Merit\'s fixed rating', () => {
    const r = rules.validateCoterie(baseCoterie({
      memberCount: 8,
      merits: [{ key: 'privileged', dots: 1 }], // Privileged is always •••
    }));
    expect(r.errors.join(' ')).toMatch(/Privileged must be rated 3/i);
  });

  it('requires the anchoring trait for a Domain Merit', () => {
    const r = rules.validateCoterie(baseCoterie({
      memberCount: 8,
      traits: { chasse: 2, lien: 0, portillon: 0 },
      merits: [{ key: 'campus', dots: 3 }], // a Lien Merit
    }));
    expect(r.errors.join(' ')).toMatch(/Campus is a lien Merit/i);
  });

  it('warns that a clan Merit needs a member of that clan', () => {
    const r = rules.validateCoterie(baseCoterie({
      memberCount: 8,
      merits: [{ key: 'pack_tactics', dots: 3 }],
    }));
    expect(r.warnings.join(' ')).toMatch(/Gangrel/);
  });

  it('warns when two pool dots per member is used by a large group', () => {
    const r = rules.validateCoterie(baseCoterie({
      memberCount: 5, pointsPerMember: 2, traits: { chasse: 1, lien: 0, portillon: 0 },
    }));
    expect(r.warnings.join(' ')).toMatch(/three or fewer/i);
  });

  it('clamps dots into the 0-5 range instead of trusting the client', () => {
    const r = rules.validateCoterie(baseCoterie({
      memberCount: 40,
      traits: { chasse: 99, lien: -4, portillon: 0 },
    }));
    expect(r.traits.chasse).toBe(5);
    expect(r.traits.lien).toBe(0);
  });
});

describe('checkTypeCompliance', () => {
  it('passes a coterie that still meets its type', () => {
    const r = rules.checkTypeCompliance({
      typeRequirements: { domain: { chasse: 1, portillon: 3 }, backgrounds: { Haven: 2 } },
      traits: { chasse: 1, lien: 0, portillon: 3 },
      backgrounds: [{ key: 'haven', dots: 2 }],
    });
    expect(r.compliant).toBe(true);
  });

  it('reports what a drifted coterie is missing', () => {
    const r = rules.checkTypeCompliance({
      typeRequirements: { domain: { chasse: 1, portillon: 3 }, backgrounds: { Haven: 2 } },
      traits: { chasse: 1, lien: 0, portillon: 1 },
      backgrounds: [],
    });
    expect(r.compliant).toBe(false);
    expect(r.unmet).toEqual(
      expect.arrayContaining([
        { name: 'Haven', needed: 2, have: 0 },
        { name: 'portillon', needed: 3, have: 1 },
      ])
    );
  });
});

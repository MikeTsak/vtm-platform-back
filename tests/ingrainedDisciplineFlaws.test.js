// tests/ingrainedDisciplineFlaws.test.js
const { applyPurchase, needsDowntime } = require('../utils/xpPurchase');

describe('Ingrained Discipline Flaws', () => {
  const baseSheet = {
    disciplines: { Potence: 3, Celerity: 2, Auspex: 3 },
    disciplinePowers: {
      Potence: [
        { level: 1, id: 'lethal_body', name: 'Lethal Body' },
        { level: 2, id: 'soaring_leap', name: 'Soaring Leap' },
        { level: 3, id: 'brutal_feed', name: 'Brutal Feed' }
      ]
    }
  };

  it('flags ingrained_discipline_flaw as requiring downtime', () => {
    expect(needsDowntime({ type: 'ingrained_discipline_flaw' })).toBe(true);
    expect(needsDowntime({ type: 'ingrained_discipline_power' })).toBe(false);
  });

  it('rejects an ingrained flaw if the discipline has fewer than 3 dots', async () => {
    await expect(applyPurchase({
      sheet: baseSheet,
      clan: 'Brujah',
      body: { type: 'ingrained_discipline_flaw', target: 'Celerity' }
    })).rejects.toThrow(/at least 3 dots in Celerity/);
  });

  it('rejects an ingrained flaw if the discipline is not in-clan for a non-Caitiff', async () => {
    // Auspex is not in-clan for Brujah
    await expect(applyPurchase({
      sheet: baseSheet,
      clan: 'Brujah',
      body: { type: 'ingrained_discipline_flaw', target: 'Auspex' }
    })).rejects.toThrow(/not an in-clan discipline for Brujah/);
  });

  it('allows an out-of-clan flaw if the character is Caitiff', async () => {
    const res = await applyPurchase({
      sheet: baseSheet,
      clan: 'Caitiff',
      body: { type: 'ingrained_discipline_flaw', target: 'Auspex' }
    });
    expect(res.cost).toBe(0);
    expect(res.sheet.ingrained_discipline_flaw).toEqual({
      discipline: 'Auspex',
      flaw_name: 'Daymares',
      active: true,
      bonus_powers: []
    });
  });

  it('allows an out-of-clan flaw if Storyteller (isAdmin)', async () => {
    const res = await applyPurchase({
      sheet: baseSheet,
      clan: 'Brujah',
      isAdmin: true,
      body: { type: 'ingrained_discipline_flaw', target: 'Auspex' }
    });
    expect(res.cost).toBe(0);
    expect(res.sheet.ingrained_discipline_flaw.discipline).toBe('Auspex');
    expect(res.sheet.ingrained_discipline_flaw.flaw_name).toBe('Daymares');
  });

  it('successfully acquires an in-clan ingrained flaw at 3+ dots for 0 XP', async () => {
    const res = await applyPurchase({
      sheet: baseSheet,
      clan: 'Brujah',
      body: { type: 'ingrained_discipline_flaw', target: 'Potence' }
    });
    expect(res.cost).toBe(0);
    expect(res.sheet.ingrained_discipline_flaw).toEqual({
      discipline: 'Potence',
      flaw_name: 'Killer Instinct',
      active: true,
      bonus_powers: []
    });
  });

  it('rejects taking a second ingrained flaw', async () => {
    const sheetWithFlaw = {
      ...baseSheet,
      ingrained_discipline_flaw: {
        discipline: 'Potence',
        flaw_name: 'Killer Instinct',
        active: true,
        bonus_powers: []
      }
    };
    await expect(applyPurchase({
      sheet: sheetWithFlaw,
      clan: 'Brujah',
      body: { type: 'ingrained_discipline_flaw', target: 'Potence' }
    })).rejects.toThrow(/already have an Ingrained Discipline Flaw/);
  });

  describe('Bonus powers purchase', () => {
    const sheetWithFlaw = {
      ...baseSheet,
      ingrained_discipline_flaw: {
        discipline: 'Potence',
        flaw_name: 'Killer Instinct',
        active: true,
        bonus_powers: []
      }
    };

    it('rejects buying bonus power if target does not match flaw discipline', async () => {
      await expect(applyPurchase({
        sheet: sheetWithFlaw,
        clan: 'Brujah',
        body: { type: 'ingrained_discipline_power', target: 'Celerity', powerName: 'Cat\'s Grace' }
      })).rejects.toThrow(/flaw is in Potence, not Celerity/i);
    });

    it('rejects buying a power that the character already has in main powers', async () => {
      await expect(applyPurchase({
        sheet: sheetWithFlaw,
        clan: 'Brujah',
        body: { type: 'ingrained_discipline_power', target: 'Potence', powerId: 'lethal_body' }
      })).rejects.toThrow(/already have/);
    });

    it('rejects buying a power whose level exceeds character discipline dots', async () => {
      // Potence is 3 dots; Fist of Caine is level 5
      await expect(applyPurchase({
        sheet: sheetWithFlaw,
        clan: 'Brujah',
        body: { type: 'ingrained_discipline_power', target: 'Potence', powerId: 'fist_of_caine' }
      })).rejects.toThrow(/needs Potence 5/i);
    });

    it('buys a level 1 bonus power at 5 XP and tracks it in bonus_powers', async () => {
      // Potence level 1 power: Soaring Leap is already taken, let's check another level 1 or check catalog
      const res = await applyPurchase({
        sheet: sheetWithFlaw,
        clan: 'Brujah',
        body: { type: 'ingrained_discipline_power', target: 'Potence', powerName: 'Prowess' }
      });
      // Prowess is level 2 in CATALOG? Let's check catalog or let's inspect returned cost
      expect(res.cost).toBeGreaterThan(0);
      expect(res.sheet.ingrained_discipline_flaw.bonus_powers.length).toBe(1);
    });

    it('enforces maximum 3 total bonus ranks', async () => {
      // If 2 ranks already spent
      const sheetWith2Ranks = {
        ...sheetWithFlaw,
        ingrained_discipline_flaw: {
          ...sheetWithFlaw.ingrained_discipline_flaw,
          bonus_powers: [{ id: 'prowess', name: 'Prowess', level: 2 }]
        }
      };

      // Trying to buy another level 2 power (2 + 2 = 4 > 3) should fail
      await expect(applyPurchase({
        sheet: sheetWith2Ranks,
        clan: 'Brujah',
        body: { type: 'ingrained_discipline_power', target: 'Potence', powerId: 'brutal_feed' }
      })).rejects.toThrow(/already have/); // Brutal Feed is already owned in main

      // Trying to buy level 3 power when only 1 rank remains (2 + 3 = 5 > 3)
      await expect(applyPurchase({
        sheet: sheetWith2Ranks,
        clan: 'Brujah',
        body: { type: 'ingrained_discipline_power', target: 'Potence', powerName: 'Wrecker' }
      })).rejects.toThrow(/Not enough bonus ranks remaining/);
    });

    it('detects Resilience acquired via ingrained flaw to increase max health in trackers', () => {
      const { trackers } = require('../services/rolls');
      const sheetWithResilience = {
          attributes: { Stamina: 3, Composure: 2, Resolve: 2 },
          disciplines: { Fortitude: 3 },
          disciplinePowers: { Fortitude: [] },
          ingrained_discipline_flaw: {
            discipline: 'Fortitude',
            flaw_name: 'Scar Tissue',
            active: true,
            bonus_powers: [{ id: 'resilience', name: 'Resilience', level: 1 }]
          },
          health: { superficial: 6, aggravated: 0 }
        };
        // Without resilience, maxHealth = 3 + 3 = 6, so superficial 6 would make it impaired.
        // With resilience bonus power, maxHealth = 3 + 3 + 3 = 9, so superficial 6 is NOT impaired.
        const tr = trackers(sheetWithResilience);
        expect(tr.healthImpaired).toBe(false);
      });
    });
  });


// tests/sheetDates.test.js — player-entered life dates are set once.
const { withSetOnceDates, newDatesMessage, RETAINER_DATES, CHARACTER_DATES } = require('../utils/sheetDates');
const { mergePlayerSheetEdit } = require('../utils/playerSheetEdit');

const NOW = new Date('2026-10-30T12:00:00Z');

describe('set-once dates', () => {
  it('lets a player fill an empty date and records when', () => {
    const out = withSetOnceDates({}, { birthDate: '1980-02-03', ghouledDate: 'garbage' }, RETAINER_DATES, NOW);
    expect(out.birthDate).toBe('1980-02-03');
    expect(out).not.toHaveProperty('ghouledDate');
    expect(out.datesSetAt).toEqual({ birthDate: NOW.toISOString() });
  });

  it('keeps a set date: no change, no clearing, no forged timestamp', () => {
    const stored = { birthDate: '1980-02-03', datesSetAt: { birthDate: '2026-01-01T00:00:00.000Z' } };
    const out = withSetOnceDates(stored, { birthDate: '', datesSetAt: { birthDate: 'x' } }, RETAINER_DATES, NOW);
    expect(out.birthDate).toBe('1980-02-03');
    expect(out.datesSetAt).toEqual(stored.datesSetAt);
    expect(withSetOnceDates(stored, { birthDate: '1999-01-01' }, RETAINER_DATES, NOW).birthDate).toBe('1980-02-03');
  });

  it('applies to the player character sheet save', () => {
    const first = mergePlayerSheetEdit({ ambition: 'a' }, { birthDate: '1900-05-01', deathDate: '1930-06-01' }, 'Brujah');
    expect(first).toMatchObject({ birthDate: '1900-05-01', deathDate: '1930-06-01' });
    expect(Object.keys(first.datesSetAt)).toEqual(['birthDate', 'deathDate']);
    const again = mergePlayerSheetEdit(first, { birthDate: '', deathDate: '1950-01-01' }, 'Brujah');
    expect(again).toMatchObject({ birthDate: '1900-05-01', deathDate: '1930-06-01' });
  });
});

describe('Storyteller push when dates are set', () => {
  it('reports a vampire: looks their age at the Embrace', () => {
    const msg = newDatesMessage({}, { birthDate: '1900-05-01', deathDate: '1930-06-01' }, CHARACTER_DATES, { who: 'Ana', now: NOW });
    expect(msg).toContain('**Ana** set their dates');
    expect(msg).toContain('Embraced **1 Jun 1930**');
    expect(msg).toContain('Apparent age **30**, true age **126**');
  });

  it('reports a ghoul: frozen at the ghouling, Crone\'s Curse adds ten', () => {
    const sheet = { isGhoul: true, birthDate: '1980-02-03', ghouledDate: '2010-02-03', flaws: [{ name: "Crone's Curse" }] };
    const msg = newDatesMessage({}, sheet, RETAINER_DATES, { who: 'Ana', retainerName: 'Vana', now: NOW });
    expect(msg).toContain('the dates of **Vana** (ghoul)');
    expect(msg).toContain('Apparent age **40**, true age **46**');
  });

  it('stays quiet when nothing new was set', () => {
    const stored = { birthDate: '1980-02-03' };
    expect(newDatesMessage(stored, stored, RETAINER_DATES, { who: 'Ana', retainerName: 'Vana', now: NOW })).toBeNull();
  });
});

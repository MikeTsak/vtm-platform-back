// tests/sheetDates.test.js — player-entered life dates are set once.
const { withSetOnceDates, RETAINER_DATES } = require('../utils/sheetDates');
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

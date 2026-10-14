// tests/commsState.test.js — the comms switch follows the calendar; an
// emergency override holds only until the calendar's next change.
const { resolveCommsState, nextCalendarChange } = require('../services/commsState');

// November 2026: Athens is on winter time (+02:00).
const at = (local) => new Date(`${local}+02:00`);
const schedule = {
  '2026-11-02': false,
  '2026-11-03': true,
  '2026-11-04': true,
  '2026-11-05': '17:00',
  '2026-11-06': false,
  '2026-11-07': 'event',
  '2026-11-08': '17:00',
};
const state = (now, override = null) => resolveCommsState(schedule, override ? JSON.stringify(override) : '', at(now));

test('follows the calendar, including 17:00 days and their carry-over', () => {
  expect(state('2026-11-02T12:00:00').isCommsEnabled).toBe(false);
  expect(state('2026-11-03T00:30:00').isCommsEnabled).toBe(true);
  expect(state('2026-11-05T16:59:00').isCommsEnabled).toBe(false);
  expect(state('2026-11-05T17:00:00').isCommsEnabled).toBe(true);
  // An explicit closed day cuts the 17:00 carry-over short.
  expect(state('2026-11-06T10:00:00').isCommsEnabled).toBe(false);
  // A 17:00 day stays open into the next morning when that day is blank.
  expect(state('2026-11-09T10:00:00').isCommsEnabled).toBe(true);
  expect(state('2026-11-09T17:30:00').isCommsEnabled).toBe(false);
  // Blank days are closed.
  expect(state('2026-12-25T12:00:00').isCommsEnabled).toBe(false);
});

test('next opening / closing come from the calendar, in Athens time', () => {
  const closed = state('2026-11-02T12:00:00');
  expect(closed.nextOpening).toMatchObject({ day: 'Tuesday', time: '00:01', date: '03/11/2026' });
  expect(closed.nextOpening.iso).toBe('2026-11-02T22:01:00.000Z');
  const open = state('2026-11-03T12:00:00');
  expect(open.nextClosing).toMatchObject({ day: 'Thursday', time: '00:01' });
  expect(state('2026-11-05T12:00:00').nextOpening).toMatchObject({ day: 'Thursday', time: '17:00' });
  expect(state('2026-12-25T12:00:00').nextOpening).toBeNull();
});

test('override ends at the calendar\'s next change', () => {
  expect(nextCalendarChange(schedule, at('2026-11-03T12:00:00')).toISOString()).toBe('2026-11-04T22:01:00.000Z');
  expect(nextCalendarChange(schedule, at('2026-11-02T12:00:00')).toISOString()).toBe('2026-11-02T22:01:00.000Z');
});

test('emergency OFF while the calendar is open', () => {
  const override = { state: false, until: '2026-11-04T22:01:00.000Z' };
  const now = state('2026-11-03T12:00:00', override);
  expect(now).toMatchObject({ isCommsEnabled: false, calendarEnabled: true, overrideExpired: false });
  // Still closed when the override ends (the calendar closes then too), so
  // the next opening is the calendar's 17:00 on Thursday.
  expect(now.nextOpening).toMatchObject({ day: 'Thursday', time: '17:00' });
  // After that the calendar is back in charge, even though the stale row is still stored.
  const later = state('2026-11-05T18:00:00', override);
  expect(later).toMatchObject({ isCommsEnabled: true, override: null, overrideExpired: true });
});

test('emergency ON while the calendar is closed', () => {
  const override = { state: true, until: '2026-11-02T22:01:00.000Z' };
  const now = state('2026-11-02T20:00:00', override);
  expect(now).toMatchObject({ isCommsEnabled: true, calendarEnabled: false });
  // The calendar opens as the override ends, so comms stay open until it closes.
  expect(now.nextClosing).toMatchObject({ day: 'Thursday', time: '00:01' });
});

test('an override with no end holds; junk is ignored', () => {
  expect(state('2026-12-25T12:00:00', { state: true, until: null }).isCommsEnabled).toBe(true);
  expect(resolveCommsState(schedule, 'not json', at('2026-11-03T12:00:00')).isCommsEnabled).toBe(true);
  expect(resolveCommsState('not json', '', at('2026-11-03T12:00:00')).isCommsEnabled).toBe(false);
});

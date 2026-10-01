// Data migration: every downtime cycle gets an explicit mass release date, so the Calendar shows
// (and the admin can change) exactly when each cycle's resolutions go out. Cycles that already have
// one are left alone. The live cycle keeps the release date currently set in the Downtimes tab; the
// others start at the morning after they close (10:00), to be adjusted per cycle in the Calendar.
const pad = (n) => String(n).padStart(2, '0');
const dayAfter = (ymd) => {
  const d = new Date(`${ymd}T12:00:00`);
  d.setDate(d.getDate() + 1);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
};

module.exports = {
  name: '0040_downtime_cycle_release_dates',
  async up(pool) {
    const get = async (key) => {
      const [[row]] = await pool.query('SELECT setting_value FROM app_settings WHERE setting_key = ?', [key]);
      return row ? row.setting_value : null;
    };
    const raw = await get('downtime_cycles_schedule');
    if (!raw) return;
    let cycles;
    try { cycles = JSON.parse(raw); } catch (_) { return; }
    if (!Array.isArray(cycles) || cycles.length === 0) return;

    const opening = String((await get('downtime_opening')) || '').slice(0, 10);
    const deadline = String((await get('downtime_deadline')) || '').slice(0, 10);
    const liveRelease = String((await get('downtime_mass_release_date')) || '').slice(0, 16);

    let changed = false;
    const next = cycles.map(c => {
      if (!c || c.release_date || !c.closing_date) return c;
      changed = true;
      const isLive = c.closing_date === deadline && (!opening || c.opening_date === opening);
      return { ...c, release_date: isLive && liveRelease ? liveRelease : `${dayAfter(c.closing_date)}T10:00` };
    });
    if (!changed) return;
    await pool.query('UPDATE app_settings SET setting_value = ? WHERE setting_key = ?', [JSON.stringify(next), 'downtime_cycles_schedule']);
  },
};

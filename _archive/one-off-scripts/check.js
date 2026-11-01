const pool = require('./db');
async function run() {
  const [rows] = await pool.query("SELECT name, sheet FROM characters WHERE JSON_EXTRACT(sheet, '$.predator_type') IS NOT NULL");
  console.log('Found ' + rows.length + ' chars');
  rows.slice(0, 5).forEach(r => {
    const s = typeof r.sheet === 'string' ? JSON.parse(r.sheet) : r.sheet;
    let allSpecs = [];
    if (Array.isArray(s.specialties)) allSpecs.push(...s.specialties);
    if (s.skills) {
      Object.keys(s.skills).forEach(k => {
        if (s.skills[k] && Array.isArray(s.skills[k].specialties)) {
          allSpecs.push(...s.skills[k].specialties.map(spec => k + ': ' + spec));
        }
      });
    }
    console.log(r.name, s.predator_type, allSpecs);
  });
  process.exit(0);
}
run();

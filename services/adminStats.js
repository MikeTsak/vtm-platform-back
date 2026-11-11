// services/adminStats.js
//
// The admin Stats page: every number for a period, computed here in SQL and
// returned as display-ready cards ({ id, kind, title, ... }) grouped in
// sections. The page only draws and exports them, so a new stat is a change in
// this file. Periods are Athens calendar days ('YYYY-MM-DD', both inclusive).
//
// Names: a stat names the character behind an account (the player's current
// character, or the retired one behind an archive account). Hidden characters
// and accounts with no character (Storytellers) are never named. News and
// rumor authors are never named either (author anonymity).
//
// A text value may be { division: n }: the page turns it into the division's
// name (front/src/constants/divisionNames.js is the one list of those names).

const { parseSheet } = require('../utils/sheet');
const { cycleIndexOf } = require('../utils/feedingCycle');
const { readCycles, dateOnly } = require('./downtimeSchedule');

/* ---------------- Athens time ---------------- */

const TZ = 'Europe/Athens';
const DOW = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const PARTS = new Intl.DateTimeFormat('en-GB', {
  timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', weekday: 'short', hourCycle: 'h23',
});

function athens(ms) {
  const p = {};
  for (const x of PARTS.formatToParts(new Date(ms))) p[x.type] = x.value;
  return { day: `${p.year}-${p.month}-${p.day}`, hour: Number(p.hour), dow: DOW.indexOf(p.weekday) };
}

// Epoch ms of 00:00 Athens time on `day` (Athens is UTC+2, or +3 in summer).
function athensMidnight(day) {
  const utc = Date.parse(`${day}T00:00:00Z`);
  for (const h of [2, 3]) {
    const ms = utc - h * 3600e3;
    const a = athens(ms);
    if (a.day === day && a.hour === 0) return ms;
  }
  return utc - 2 * 3600e3;
}

const addDays = (day, n) => new Date(Date.parse(`${day}T12:00:00Z`) + n * 864e5).toISOString().slice(0, 10);
const dayLabel = (day) => new Intl.DateTimeFormat('en-GB', { weekday: 'short', day: 'numeric', month: 'short', timeZone: 'UTC' })
  .format(new Date(`${day}T12:00:00Z`));
const msOf = (v) => (v instanceof Date ? v.getTime() : Date.parse(v));

function period(query) {
  let from = DAY.test(query.from || '') ? query.from : null;
  let to = DAY.test(query.to || '') ? query.to : null;
  if (from && to && from > to) [from, to] = [to, from];
  const today = athens(Date.now()).day;
  // Inlined into SQL below: always integers built from validated dates, never user text.
  const lo = from ? Math.floor(athensMidnight(from) / 1000) : null;
  const hi = to ? Math.floor(athensMidnight(addDays(to, 1)) / 1000) : null;
  const R = (col) => [
    lo != null ? `${col} >= FROM_UNIXTIME(${lo})` : null,
    hi != null ? `${col} < FROM_UNIXTIME(${hi})` : null,
  ].filter(Boolean).join(' AND ') || '1 = 1';
  return { from, to, today, R };
}

// Day -> count, summed into day, week (Monday) or month buckets with the empty
// ones kept, so a line over time is honest about quiet stretches.
function series(byDay, P) {
  const days = [...byDay.keys()].sort();
  if (!days.length) return { bucket: 'day', points: [] };
  const first = P.from || days[0];
  const last = P.to && P.to < P.today ? P.to : P.today;
  const span = Math.round((Date.parse(last) - Date.parse(first)) / 864e5) + 1;
  const bucket = span <= 62 ? 'day' : span <= 400 ? 'week' : 'month';
  const keyOf = (d) => {
    if (bucket === 'day') return d;
    if (bucket === 'month') return d.slice(0, 7);
    return addDays(d, -((new Date(`${d}T12:00:00Z`).getUTCDay() + 6) % 7));
  };
  const sums = new Map();
  for (let d = first; d <= last; d = addDays(d, 1)) {
    const k = keyOf(d);
    sums.set(k, (sums.get(k) || 0) + (byDay.get(d) || 0));
  }
  return { bucket, points: [...sums].map(([t, value]) => ({ t, value })) };
}

/* ---------------- People ---------------- */

const isActive = (c) => !c.is_hidden && !c.is_deceased && !c.is_left && !c.is_exiled && !c.is_missing && !c.is_called;

async function loadPeople(pool) {
  const [chars] = await pool.query(
    `SELECT id, user_id, name, clan, sheet, xp, camarilla_titles, created_at,
            is_deceased, is_hidden, is_left, is_missing, is_exiled, is_called, is_bloodhunted
       FROM characters`
  );
  const [archives] = await pool.query('SELECT id, archived_character_id FROM users WHERE archived_character_id IS NOT NULL');
  const byId = new Map(chars.map((c) => [c.id, { ...c, sheet: parseSheet(c.sheet) }]));
  const byUser = new Map();
  for (const c of byId.values()) if (c.user_id) byUser.set(c.user_id, c);
  for (const u of archives) if (byId.has(u.archived_character_id)) byUser.set(u.id, byId.get(u.archived_character_id));
  const byName = new Map([...byId.values()].map((c) => [String(c.name).trim().toLowerCase(), c]));
  const named = (c) => (c && !c.is_hidden ? c : null);
  return {
    all: [...byId.values()].filter((c) => !c.is_hidden),
    char: (id) => named(byId.get(Number(id))),
    user: (id) => named(byUser.get(Number(id))),
    byName: (name) => named(byName.get(String(name || '').trim().toLowerCase())),
  };
}

// [{ k, n }] keyed by account or character id -> [{ c, n }] per named character, biggest first.
function tally(rows, resolve, field = 'n') {
  const m = new Map();
  for (const r of rows) {
    const c = resolve(r.k);
    if (!c) continue;
    const e = m.get(c.id) || { c, n: 0 };
    e.n += Number(r[field]) || 0;
    m.set(c.id, e);
  }
  return [...m.values()].filter((e) => e.n > 0).sort((a, b) => b.n - a.n);
}

// Map key -> count, as ranked entries with a display name.
const ranked = (map, nameOf = (k) => k) => [...map]
  .filter(([, n]) => n > 0)
  .map(([k, n]) => ({ c: { name: nameOf(k) }, n, k }))
  .sort((a, b) => b.n - a.n);

const bump = (map, key, by = 1) => map.set(key, (map.get(key) || 0) + by);

/* ---------------- Cards ---------------- */

const num = (n) => Number(n || 0).toLocaleString('en-US');
const plural = (n, one, many = `${one}s`) => `${num(n)} ${Number(n) === 1 ? one : many}`;
const nameList = (xs) => (xs.length <= 1 ? xs[0] || ''
  : xs.length <= 3 ? `${xs.slice(0, -1).join(', ')} & ${xs[xs.length - 1]}`
    : `${xs.slice(0, 2).join(', ')} & ${xs.length - 2} more`);

// The first entry of a ranked list wins, with everyone tied with it. More than
// three tied is no award at all ("12 people with 1 division").
function award(id, title, icon, list, value) {
  if (!list.length) return null;
  const best = list.filter((e) => e.n === list[0].n);
  if (best.length > 3) return null;
  return {
    id, kind: 'award', title, icon,
    name: nameList(best.map((e) => e.c.name)),
    clan: best.length === 1 ? best[0].c.clan || null : null,
    value: value(list[0].n, best[0]),
  };
}
const hero = (id, title, value, sub) => ({ id, kind: 'hero', title, value, sub });
const tiles = (id, title, items) => {
  const kept = items.filter(Boolean);
  return kept.length ? { id, kind: 'tiles', title, items: kept } : null;
};
const bars = (id, title, items, unit) => (items.length ? { id, kind: 'bars', title, unit, items } : null);
const columns = (id, title, items, sub) => (items.some((i) => i.value > 0) ? { id, kind: 'columns', title, sub, items } : null);
const split = (id, title, items) => {
  const kept = items.filter((i) => i.value > 0);
  return kept.length > 1 ? { id, kind: 'split', title, items: kept } : null;
};
const timeline = (id, title, s, unit) => (s.points.filter((p) => p.value > 0).length > 1 ? { id, kind: 'timeline', title, unit, ...s } : null);
const list = (id, title, items) => (items.length ? { id, kind: 'list', title, items } : null);
const person = (e, value) => ({ name: e.c.name, clan: e.c.clan || null, value });
const section = (id, title, icon, cards) => ({ id, title, icon, cards: cards.filter(Boolean) });

const parseJson = (v) => {
  if (v && typeof v === 'object') return v;
  try { return JSON.parse(v) || {}; } catch { return {}; }
};
const titlesOf = (c) => {
  const raw = parseJson(c.camarilla_titles);
  return (Array.isArray(raw) ? raw : [])
    .map((t) => (typeof t === 'string' ? t : t?.title || t?.name || ''))
    .filter((t) => t && !/ex-/i.test(t));
};

/* ---------------- The Blood ---------------- */

function population(people, P) {
  const chars = people.all;
  const active = chars.filter(isActive);
  const clans = new Map();
  const predators = new Map();
  const generations = new Map();
  let humanity = 0; let humanityN = 0; let bp = 0; let bpN = 0;
  for (const c of active) {
    bump(clans, c.clan || 'Unknown');
    if (c.sheet.predator_type) bump(predators, c.sheet.predator_type);
    const gen = Number(c.sheet.generation);
    if (gen > 0) bump(generations, gen);
    if (c.sheet.humanity != null && c.sheet.humanity !== '') { humanity += Number(c.sheet.humanity) || 0; humanityN += 1; }
    if (c.sheet.blood_potency != null && c.sheet.blood_potency !== '') { bp += Number(c.sheet.blood_potency) || 0; bpN += 1; }
  }
  const lo = P.from ? athensMidnight(P.from) : 0;
  const hi = P.to ? athensMidnight(addDays(P.to, 1)) : Infinity;
  const arrivals = chars.filter((c) => { const t = msOf(c.created_at); return t >= lo && t < hi; }).length;
  const by = (field, dir = -1) => active
    .filter((c) => Number(c.sheet[field]) > 0)
    .map((c) => ({ c, n: Number(c.sheet[field]) }))
    .sort((a, b) => dir * (a.n - b.n));
  const ord = (n) => `${n}${n % 100 >= 11 && n % 100 <= 13 ? 'th' : ['th', 'st', 'nd', 'rd'][n % 10] || 'th'}`;

  return section('blood', 'The Blood', 'fa-droplet', [
    hero('blood.active', 'Kindred walking the night', num(active.length),
      arrivals && (P.from || P.to) ? `${plural(arrivals, 'new arrival')} this period` : null),
    tiles('blood.fates', 'Fates', [
      { label: 'Met Final Death', value: num(chars.filter((c) => c.is_deceased).length) },
      { label: 'Left or exiled', value: num(chars.filter((c) => !c.is_deceased && (c.is_left || c.is_exiled || c.is_called)).length) },
      { label: 'Missing', value: num(chars.filter((c) => !c.is_deceased && c.is_missing).length) },
      { label: 'Blood-hunted', value: num(chars.filter((c) => !c.is_deceased && c.is_bloodhunted).length) },
    ]),
    bars('blood.clans', 'Clans of Athens', ranked(clans).map((e) => ({ label: e.k, clan: e.k, value: e.n })), 'kindred'),
    bars('blood.predators', 'How they hunt', ranked(predators).map((e) => ({ label: e.k, value: e.n })), 'kindred'),
    columns('blood.generations', 'Generations',
      [...generations].sort((a, b) => a[0] - b[0]).map(([g, n]) => ({ label: ord(g), value: n }))),
    tiles('blood.averages', 'Averages', [
      humanityN ? { label: 'Average Humanity', value: (humanity / humanityN).toFixed(1) } : null,
      bpN ? { label: 'Average Blood Potency', value: (bp / bpN).toFixed(1) } : null,
    ]),
    award('blood.potent', 'Thickest blood', 'fa-droplet', by('blood_potency'), (n) => `Blood Potency ${n}`),
    award('blood.eldest', 'Eldest blood', 'fa-crown', by('generation', 1), (n) => `${ord(n)} Generation`),
    award('blood.humane', 'Most humane', 'fa-star', by('humanity'), (n) => `Humanity ${n}`),
    award('blood.beast', 'Closest to the Beast', 'fa-paw', by('humanity', 1), (n) => `Humanity ${n}`),
  ]);
}

/* ---------------- The Whispers ---------------- */

const NOT_SYSTEM = "(type IS NULL OR type <> 'system')";
const SENT = "(status IS NULL OR status = 'sent')";

async function comms(pool, people, P) {
  const { R } = P;
  const dm = `FROM chat_messages WHERE ${R('created_at')} AND ${NOT_SYSTEM}`;
  const grp = `FROM chat_group_messages WHERE ${R('created_at')} AND ${NOT_SYSTEM}`;
  const npc = `FROM npc_messages WHERE ${R('created_at')} AND ${SENT}`;
  const mail = `FROM email_messages WHERE ${R('created_at')} AND ${SENT}`;

  const [[channels], [hours], [senders], [received], [pairs], [npcPairs], [groups], [night], [favs], [[reacts]]] = await Promise.all([
    pool.query(`SELECT (SELECT COUNT(*) ${dm}) dm, (SELECT COUNT(*) ${grp}) grp, (SELECT COUNT(*) ${npc}) npc, (SELECT COUNT(*) ${mail}) mail`),
    pool.query(`SELECT FLOOR(UNIX_TIMESTAMP(created_at) / 3600) h, COUNT(*) n FROM (
        SELECT created_at ${dm} UNION ALL SELECT created_at ${grp} UNION ALL SELECT created_at ${npc} UNION ALL SELECT created_at ${mail}
      ) x GROUP BY h`),
    pool.query(`SELECT sender_id k, COUNT(*) n, SUM(attachment_id IS NOT NULL) pics ${dm} GROUP BY sender_id
      UNION ALL SELECT sender_id, COUNT(*), SUM(attachment_id IS NOT NULL) ${grp} GROUP BY sender_id
      UNION ALL SELECT user_id, COUNT(*), SUM(attachment_id IS NOT NULL) ${npc} AND from_side = 'user' GROUP BY user_id
      UNION ALL SELECT t.user_id, COUNT(*), 0 FROM email_messages m JOIN email_threads t ON t.id = m.thread_id
        WHERE ${R('m.created_at')} AND m.sender_type = 'user' AND (m.status IS NULL OR m.status = 'sent') GROUP BY t.user_id`),
    pool.query(`SELECT recipient_id k, COUNT(*) n ${dm} GROUP BY recipient_id`),
    pool.query(`SELECT LEAST(sender_id, recipient_id) a, GREATEST(sender_id, recipient_id) b, COUNT(*) n ${dm} GROUP BY a, b ORDER BY n DESC LIMIT 12`),
    pool.query(`SELECT m.user_id, n.name, COUNT(*) c FROM npc_messages m JOIN npcs n ON n.id = m.npc_id
      WHERE ${R('m.created_at')} AND (m.status IS NULL OR m.status = 'sent') GROUP BY m.npc_id, m.user_id, n.name ORDER BY c DESC LIMIT 12`),
    pool.query(`SELECT g.name, COUNT(*) n FROM chat_group_messages m JOIN chat_groups g ON g.id = m.group_id
      WHERE ${R('m.created_at')} AND (m.type IS NULL OR m.type <> 'system') GROUP BY m.group_id, g.name ORDER BY n DESC LIMIT 6`),
    // Night owls: the UTC hours that can be 00:00-04:59 in Athens, checked exactly below.
    pool.query(`SELECT k, FLOOR(UNIX_TIMESTAMP(created_at) / 3600) h, COUNT(*) n FROM (
        SELECT sender_id k, created_at ${dm} UNION ALL SELECT sender_id, created_at ${grp}
        UNION ALL SELECT user_id, created_at ${npc} AND from_side = 'user'
      ) x WHERE MOD(FLOOR(UNIX_TIMESTAMP(created_at) / 3600), 24) IN (21, 22, 23, 0, 1, 2) GROUP BY k, h`),
    pool.query(`SELECT m.sender_id k, COUNT(*) n FROM chat_message_reactions r JOIN chat_messages m ON m.id = r.message_id
        WHERE r.message_table = 'chat_messages' AND ${R('r.created_at')} AND r.user_id <> m.sender_id GROUP BY m.sender_id
      UNION ALL SELECT m.sender_id, COUNT(*) FROM chat_message_reactions r JOIN chat_group_messages m ON m.id = r.message_id
        WHERE r.message_table = 'chat_group_messages' AND ${R('r.created_at')} AND r.user_id <> m.sender_id GROUP BY m.sender_id
      UNION ALL SELECT m.user_id, COUNT(*) FROM chat_message_reactions r JOIN npc_messages m ON m.id = r.message_id
        WHERE r.message_table = 'npc_messages' AND m.from_side = 'user' AND ${R('r.created_at')} AND r.user_id <> m.user_id GROUP BY m.user_id`),
    pool.query(`SELECT COUNT(*) n FROM chat_message_reactions WHERE ${R('created_at')}`),
  ]);

  const c = channels[0];
  const total = Number(c.dm) + Number(c.grp) + Number(c.npc) + Number(c.mail);
  const byDay = new Map();
  const byHour = new Map();
  const grid = Array.from({ length: 7 }, () => Array(24).fill(0));
  for (const r of hours) {
    const a = athens(Number(r.h) * 3600e3);
    const n = Number(r.n);
    bump(byDay, a.day, n);
    bump(byHour, a.hour, n);
    grid[a.dow][a.hour] += n;
  }
  const s = series(byDay, P);
  const spanDays = Math.max(1, s.points.length * ({ day: 1, week: 7, month: 30.4 })[s.bucket]);
  const [busiestDay] = ranked(byDay, dayLabel);
  const [busiestHour] = ranked(byHour, (h) => `${String(h).padStart(2, '0')}:00`);

  const writers = tally(senders, people.user);
  const pics = tally(senders, people.user, 'pics');
  const owls = tally(night.filter((r) => athens(Number(r.h) * 3600e3).hour < 5), people.user);
  const convos = [
    ...pairs.map((p) => ({ a: people.user(p.a), b: people.user(p.b), n: Number(p.n) })).filter((p) => p.a && p.b)
      .map((p) => ({ c: { name: `${p.a.name} & ${p.b.name}` }, n: p.n })),
    ...npcPairs.map((p) => ({ a: people.user(p.user_id), name: p.name, n: Number(p.c) })).filter((p) => p.a)
      .map((p) => ({ c: { name: `${p.a.name} & ${p.name}` }, n: p.n })),
  ].sort((x, y) => y.n - x.n);
  const totalPics = senders.reduce((sum, r) => sum + Number(r.pics || 0), 0);

  return section('comms', 'The Whispers', 'fa-comments', [
    hero('comms.total', 'Messages sent', num(total), total ? `${(total / spanDays).toFixed(1)} a day` : null),
    split('comms.channels', 'Where they talk', [
      { label: 'Direct messages', value: Number(c.dm) },
      { label: 'Groups', value: Number(c.grp) },
      { label: 'NPC chats', value: Number(c.npc) },
      { label: 'Email', value: Number(c.mail) },
    ]),
    timeline('comms.timeline', 'Messages over time', s, 'messages'),
    total ? { id: 'comms.heatmap', kind: 'heatmap', title: 'When Athens whispers', rows: DOW, grid } : null,
    tiles('comms.moments', 'Peak moments', [
      busiestDay && { label: 'Busiest day', value: busiestDay.c.name, sub: plural(busiestDay.n, 'message') },
      busiestHour && { label: 'Busiest hour', value: busiestHour.c.name, sub: plural(busiestHour.n, 'message') },
      totalPics ? { label: 'Pictures shared', value: num(totalPics) } : null,
      Number(reacts.n) ? { label: 'Reactions given', value: num(reacts.n) } : null,
    ]),
    award('comms.writer', 'Most prolific writer', 'fa-comments', writers, (n) => plural(n, 'message')),
    award('comms.sought', 'Most sought-after', 'fa-envelope', tally(received, people.user), (n) => `${plural(n, 'message')} received`),
    award('comms.convo', 'Longest conversation', 'fa-handshake', convos, (n) => `${plural(n, 'message')} exchanged`),
    award('comms.group', 'Loudest circle', 'fa-bullhorn', groups.map((g) => ({ c: { name: g.name }, n: Number(g.n) })), (n) => plural(n, 'message')),
    award('comms.owl', 'Night owl', 'fa-moon', owls, (n) => `${plural(n, 'message')} between midnight and 5 am`),
    award('comms.pics', 'Shutterbug', 'fa-camera', pics, (n) => plural(n, 'picture')),
    award('comms.fav', 'Crowd favorite', 'fa-star', tally(favs, people.user), (n) => `${plural(n, 'reaction')} received`),
    list('comms.writers', 'Top writers', writers.slice(0, 10).map((e) => person(e, num(e.n)))),
    list('comms.pairs', 'Longest conversations', convos.slice(0, 5).map((e) => ({ name: e.c.name, value: num(e.n) }))),
    bars('comms.groups', 'Busiest groups', groups.map((g) => ({ label: g.name, value: Number(g.n) })), 'messages'),
  ]);
}

/* ---------------- Fate & Fortune ---------------- */

// Storyteller rolls never win a player's award.
const ST_ROLLS = new Set(['admin_roll', 'opposed_roll', 'remorse', 'npc_roll']);

async function dice(pool, people, P) {
  const [rows] = await pool.query(
    `SELECT character_id, roll_type, successes, crit_pairs, messy_crit, bestial_failure, results_json, note
       FROM dice_rolls WHERE ${P.R('created_at')}`
  );
  const faces = Array(11).fill(0);
  const disciplines = new Map();
  const luck = new Map();
  const per = { rolls: new Map(), messy: new Map(), bestial: new Map(), rerolls: new Map() };
  let messy = 0; let bestial = 0; let crits = 0; let rerolls = 0; let rouse = 0; let rouseOk = 0;
  let resisted = 0; let frenzied = 0; let best = null; let worst = null;

  for (const r of rows) {
    const res = parseJson(r.results_json);
    const normal = Array.isArray(res.normal) ? res.normal : [];
    const hunger = Array.isArray(res.hunger) ? res.hunger : [];
    const rouseDice = Array.isArray(res.rouse) ? res.rouse : [];
    for (const v of [...normal, ...hunger, ...rouseDice]) if (v >= 1 && v <= 10) faces[v] += 1;
    if (r.messy_crit) messy += 1;
    if (r.bestial_failure) bestial += 1;
    if (r.crit_pairs > 0 && !r.messy_crit) crits += 1;
    if (r.roll_type === 'willpower_reroll') rerolls += 1;
    if (rouseDice.length) { rouse += 1; if (rouseDice.some((v) => v >= 6)) rouseOk += 1; }
    if (r.roll_type === 'frenzy_resistance') { if (/^resisted/i.test(r.note || '')) resisted += 1; else frenzied += 1; }
    if (res.disc && r.roll_type !== 'discipline_deactivation') bump(disciplines, res.disc);

    const c = people.char(r.character_id);
    if (!c || ST_ROLLS.has(r.roll_type) || String(r.roll_type || '').startsWith('ghoul')) continue;
    bump(per.rolls, c.id);
    if (r.messy_crit) bump(per.messy, c.id);
    if (r.bestial_failure) bump(per.bestial, c.id);
    if (r.roll_type === 'willpower_reroll') bump(per.rerolls, c.id);
    const size = normal.length + hunger.length;
    if (!size) continue;
    const roll = { c, normal, hunger, successes: Number(r.successes) || 0, size, note: r.note, bestial: !!r.bestial_failure };
    if (r.roll_type !== 'willpower_reroll') {
      const l = luck.get(c.id) || { c, dice: 0, succ: 0, rolls: 0 };
      l.dice += size; l.succ += roll.successes; l.rolls += 1;
      luck.set(c.id, l);
    }
    if (!best || roll.successes > best.successes || (roll.successes === best.successes && size < best.size)) best = roll;
    const failing = roll.bestial || roll.successes === 0;
    if (failing && (!worst || (roll.bestial && !worst.bestial) || (roll.bestial === worst.bestial && size > worst.size))) worst = roll;
  }

  const perChar = (map) => [...map].map(([id, n]) => ({ c: people.char(id), n })).filter((e) => e.c).sort((a, b) => b.n - a.n);
  const lucky = [...luck.values()].filter((l) => l.rolls >= 10).map((l) => ({ c: l.c, n: Math.round((l.succ / l.dice) * 100) / 100 }));
  const luckiest = [...lucky].sort((a, b) => b.n - a.n);
  const unluckiest = lucky.length > 1 ? [...lucky].sort((a, b) => a.n - b.n) : [];
  const totalDice = faces.reduce((a, b) => a + b, 0);
  const rollCard = (id, title, roll, value) => roll && {
    id, kind: 'roll', title, name: roll.c.name, clan: roll.c.clan || null, value, note: roll.note || null,
    normal: roll.normal, hunger: roll.hunger,
  };

  return section('dice', 'Fate & Fortune', 'fa-dice', [
    hero('dice.total', 'Dice rolls', num(rows.length), totalDice ? `${num(totalDice)} dice thrown` : null),
    tiles('dice.drama', 'Drama', [
      { label: 'Messy Criticals', value: num(messy) },
      { label: 'Bestial Failures', value: num(bestial) },
      { label: 'Clean criticals', value: num(crits) },
      { label: 'Willpower rerolls', value: num(rerolls) },
      rouse ? { label: 'Rouse Checks passed', value: `${Math.round((rouseOk / rouse) * 100)}%`, sub: `of ${num(rouse)}` } : null,
      resisted + frenzied ? { label: 'Frenzies resisted', value: `${num(resisted)} of ${num(resisted + frenzied)}` } : null,
    ]),
    columns('dice.faces', 'Are the dice fair?', faces.slice(1).map((n, i) => ({ label: String(i + 1), value: n })),
      totalDice ? `Every die thrown. Average face ${(faces.reduce((s, n, v) => s + n * v, 0) / totalDice).toFixed(2)} (a fair d10 averages 5.50)` : null),
    bars('dice.disciplines', 'Disciplines in play', ranked(disciplines).slice(0, 8).map((e) => ({ label: e.k, value: e.n })), 'rolls'),
    award('dice.lucky', 'Luckiest', 'fa-star', luckiest, (n) => `${n.toFixed(2)} successes per die`),
    award('dice.unlucky', 'Cursed dice', 'fa-burst', unluckiest, (n) => `${n.toFixed(2)} successes per die`),
    award('dice.messy', "The Beast's favorite", 'fa-paw', perChar(per.messy), (n) => plural(n, 'Messy Critical')),
    award('dice.bestial', 'Bestial', 'fa-triangle-exclamation', perChar(per.bestial), (n) => plural(n, 'Bestial Failure')),
    award('dice.addict', 'Dice addict', 'fa-dice', perChar(per.rolls), (n) => plural(n, 'roll')),
    award('dice.willpower', 'Iron will', 'fa-shield-halved', perChar(per.rerolls), (n) => plural(n, 'Willpower reroll')),
    rollCard('dice.best', 'Greatest triumph', best, best && `${plural(best.successes, 'success', 'successes')} from ${plural(best.size, 'die', 'dice')}`),
    rollCard('dice.worst', 'Darkest failure', worst, worst && (worst.bestial ? `Bestial Failure on ${plural(worst.size, 'die', 'dice')}` : `No successes from ${plural(worst.size, 'die', 'dice')}`)),
  ]);
}

/* ---------------- The Hunt ---------------- */

async function hunt(pool, people, P) {
  const { R } = P;
  const [[feeds], [ghouls], [incidents]] = await Promise.all([
    pool.query(`SELECT character_id, division, predator_type, outcome FROM feedings WHERE status = 'resolved' AND ${R('created_at')}`),
    pool.query(`SELECT status, method FROM ghoul_feedings WHERE ${R('created_at')}`),
    pool.query(`SELECT intruder_character_id k, outcome FROM domain_incidents WHERE ${R('created_at')}`),
  ]);
  const out = new Map();
  const predators = new Map();
  const divisions = new Map();
  const hunters = new Map();
  const apex = new Map();
  const messy = new Map();
  for (const f of feeds) {
    bump(out, f.outcome);
    if (f.predator_type) bump(predators, f.predator_type);
    if (f.division != null && f.outcome !== 'herd' && f.outcome !== 'downtime') bump(divisions, f.division);
    bump(hunters, f.character_id);
    if (f.outcome === 'critical') bump(apex, f.character_id);
    if (f.outcome === 'messy_critical') bump(messy, f.character_id);
  }
  const o = (k) => out.get(k) || 0;
  const clean = o('success') + o('critical');
  const failed = o('failure') + o('bestial_failure');
  const rolled = clean + o('messy_critical') + failed;
  const perChar = (map) => tally([...map].map(([k, n]) => ({ k, n })), people.char);

  return section('hunt', 'The Hunt', 'fa-paw', [
    hero('hunt.total', 'Hunts', num(feeds.length), rolled ? `${Math.round(((clean + o('messy_critical')) / rolled) * 100)}% of rolled hunts fed` : null),
    split('hunt.outcomes', 'How the hunts went', [
      { label: 'Clean kills', value: clean },
      { label: 'Messy', value: o('messy_critical') },
      { label: 'Failed', value: failed },
      { label: 'Herd & downtime', value: o('herd') + o('downtime') },
    ]),
    bars('hunt.predators', 'Predator types at work', ranked(predators).map((e) => ({ label: e.k, value: e.n })), 'hunts'),
    bars('hunt.divisions', 'Favorite hunting grounds', ranked(divisions).slice(0, 8).map((e) => ({ label: { division: Number(e.k) }, value: e.n })), 'hunts'),
    tiles('hunt.tiles', 'In the shadows', [
      o('critical') ? { label: 'Critical hunts', value: num(o('critical')) } : null,
      incidents.length ? { label: 'Domain incidents', value: num(incidents.length), sub: 'hunters caught in a rival domain' } : null,
      ghouls.length ? { label: 'Ghouls fed', value: num(ghouls.filter((g) => g.status === 'fed').length) } : null,
      ghouls.some((g) => g.status === 'starved') ? { label: 'Ghouls starved', value: num(ghouls.filter((g) => g.status === 'starved').length) } : null,
    ]),
    award('hunt.prolific', 'Most prolific hunter', 'fa-paw', perChar(hunters), (n) => plural(n, 'hunt')),
    award('hunt.apex', 'Apex predator', 'fa-crown', perChar(apex), (n) => plural(n, 'critical hunt')),
    award('hunt.messy', 'Messiest feeder', 'fa-droplet', perChar(messy), (n) => plural(n, 'messy hunt')),
    award('hunt.poacher', 'Poacher', 'fa-eye', tally(incidents.map((i) => ({ k: i.k, n: 1 })), people.char), (n) => `caught ${plural(n, 'time')} in a rival domain`),
  ]);
}

/* ---------------- The Domains (as they stand now) ---------------- */

async function domains(pool, people, P) {
  const [[claims], [[guests]], [[incidents]]] = await Promise.all([
    pool.query('SELECT division, owner_character_id, owner_npc_id, owner_name, is_abaton, safety_rating FROM domain_claims'),
    pool.query('SELECT COUNT(*) n FROM domain_guests'),
    pool.query(`SELECT COUNT(*) n FROM domain_incidents WHERE ${P.R('created_at')}`),
  ]);
  const owned = claims.filter((d) => d.owner_character_id || d.owner_npc_id || d.owner_name);
  const clans = new Map();
  const landlords = new Map();
  let players = 0;
  for (const d of owned) {
    const c = people.char(d.owner_character_id);
    if (!c) continue;
    players += 1;
    bump(clans, c.clan || 'Unknown');
    bump(landlords, c.id);
  }
  const rated = owned.filter((d) => d.safety_rating != null);
  const avg = rated.length ? rated.reduce((s, d) => s + Number(d.safety_rating), 0) / rated.length : null;
  const lowest = [...rated].sort((a, b) => a.safety_rating - b.safety_rating)[0];
  const lowestTies = lowest ? rated.filter((d) => d.safety_rating === lowest.safety_rating).length : 0;

  return section('domains', 'The Domains', 'fa-map', [
    hero('domains.claimed', 'Divisions claimed', num(owned.length), `${num(players)} held by players`),
    bars('domains.clans', 'Territory by clan', ranked(clans).map((e) => ({ label: e.k, clan: e.k, value: e.n })), 'divisions'),
    tiles('domains.tiles', 'The state of the city', [
      avg != null ? { label: 'Average safety', value: `${avg.toFixed(1)} / 10` } : null,
      lowest ? { label: 'Most dangerous', value: { division: Number(lowest.division) }, sub: `Safety ${lowest.safety_rating}${lowestTies > 1 ? ` (and ${lowestTies - 1} more)` : ''}` } : null,
      claims.some((d) => d.is_abaton) ? { label: 'Abaton', value: num(claims.filter((d) => d.is_abaton).length), sub: 'sacred ground' } : null,
      Number(guests.n) ? { label: 'Guests hosted', value: num(guests.n) } : null,
      Number(incidents.n) ? { label: 'Incidents this period', value: num(incidents.n) } : null,
    ]),
    award('domains.landlord', 'Greatest landlord', 'fa-chess-rook', tally([...landlords].map(([k, n]) => ({ k, n })), people.char), (n) => plural(n, 'division')),
  ]);
}

/* ---------------- The Court ---------------- */

const BOON_LEVELS = ['trivial', 'minor', 'major', 'life'];

async function court(pool, people, P) {
  const { R } = P;
  const [[boons], [[hunts]], [[wanted]], [[elysiums]]] = await Promise.all([
    pool.query(`SELECT from_name, to_name, level, boon_level, status FROM boons WHERE ${R('created_at')}`),
    pool.query(`SELECT COUNT(*) n FROM blood_hunts WHERE ${R('created_at')}`),
    pool.query(`SELECT COUNT(*) n FROM court_wanted WHERE ${R('created_at')}`),
    pool.query(`SELECT COUNT(*) n FROM elysium_invitations WHERE published_at IS NOT NULL AND ${R('published_at')}`),
  ]);
  const levels = new Map();
  const creditors = new Map();
  const debtors = new Map();
  for (const b of boons) {
    const level = String(b.level || b.boon_level || '').toLowerCase();
    bump(levels, BOON_LEVELS.includes(level) ? level : 'trivial');
    if (b.to_name) bump(creditors, b.to_name.trim());
    if (b.from_name) bump(debtors, b.from_name.trim());
  }
  const withClan = (map) => ranked(map).map((e) => ({ c: { name: e.k, clan: people.byName(e.k)?.clan || null }, n: e.n }));
  const holders = people.all.filter(isActive).map((c) => ({ c, titles: titlesOf(c) })).filter((h) => h.titles.length);
  const titleClans = new Map();
  for (const h of holders) bump(titleClans, h.c.clan || 'Unknown', h.titles.length);

  return section('court', 'The Court', 'fa-crown', [
    hero('court.boons', 'Boons incurred', num(boons.length),
      boons.length ? `${num(boons.filter((b) => /owed/i.test(b.status || '')).length)} still owed` : null),
    columns('court.levels', 'Boons by weight', BOON_LEVELS.map((l) => ({ label: l[0].toUpperCase() + l.slice(1), value: levels.get(l) || 0 }))),
    award('court.broker', 'Power broker', 'fa-handshake', withClan(creditors), (n) => `owed ${plural(n, 'boon')}`),
    award('court.debt', 'Deepest in debt', 'fa-scroll', withClan(debtors), (n) => `owes ${plural(n, 'boon')}`),
    bars('court.titles', 'Titles by clan', ranked(titleClans).map((e) => ({ label: e.k, clan: e.k, value: e.n })), 'titles'),
    list('court.roster', 'The Court of Athens', holders.map((h) => ({ name: h.c.name, clan: h.c.clan || null, value: h.titles.join(', ') }))),
    tiles('court.tiles', 'Courtly affairs', [
      Number(hunts.n) ? { label: 'Blood Hunts called', value: num(hunts.n) } : null,
      Number(wanted.n) ? { label: 'Wanted notices', value: num(wanted.n) } : null,
      Number(elysiums.n) ? { label: 'Elysiums held', value: num(elysiums.n) } : null,
    ]),
  ]);
}

/* ---------------- Coteries & retainers (as they stand now) ---------------- */

async function coteries(pool, people) {
  const [[groups], [retainers]] = await Promise.all([
    pool.query("SELECT c.id, c.name, COUNT(m.id) members FROM coteries c LEFT JOIN coterie_members m ON m.coterie_id = c.id WHERE c.status <> 'dissolved' GROUP BY c.id, c.name"),
    pool.query('SELECT character_id, coterie_id, domitor_character_id, sheet FROM retainers'),
  ]);
  const ghouls = retainers.filter((r) => parseSheet(r.sheet).isGhoul === true);
  const sizes = groups.map((g) => ({ c: { name: g.name }, n: Number(g.members) })).sort((a, b) => b.n - a.n);
  const keepers = new Map();
  for (const r of retainers) if (r.character_id) bump(keepers, r.character_id);
  const domitors = new Map();
  for (const g of ghouls) if (g.domitor_character_id || g.character_id) bump(domitors, g.domitor_character_id || g.character_id);
  const perChar = (map) => tally([...map].map(([k, n]) => ({ k, n })), people.char);

  return section('coteries', 'Coteries & Retainers', 'fa-shield-halved', [
    hero('coteries.count', 'Coteries', num(groups.length),
      groups.length ? `${(groups.reduce((s, g) => s + Number(g.members), 0) / groups.length).toFixed(1)} members on average` : null),
    bars('coteries.sizes', 'Coteries by size', sizes.filter((e) => e.n > 0).slice(0, 8).map((e) => ({ label: e.c.name, value: e.n })), 'members'),
    tiles('coteries.tiles', 'Their servants', [
      { label: 'Retainers', value: num(retainers.length) },
      { label: 'Ghouls', value: num(ghouls.length) },
      { label: 'Mortals', value: num(retainers.length - ghouls.length) },
      { label: 'Owned by coteries', value: num(retainers.filter((r) => r.coterie_id).length) },
    ]),
    award('coteries.largest', 'Largest coterie', 'fa-shield-halved', sizes.filter((e) => e.n > 0), (n) => plural(n, 'member')),
    award('coteries.keeper', 'Most retainers', 'fa-user', perChar(keepers), (n) => plural(n, 'retainer')),
    award('coteries.domitor', 'Most ghouls', 'fa-droplet', perChar(domitors), (n) => plural(n, 'ghoul')),
  ]);
}

/* ---------------- Growth ---------------- */

const XP_KINDS = {
  discipline: 'Disciplines', ingrained_discipline_power: 'Disciplines', skill: 'Skills', specialty: 'Specialties',
  attribute: 'Attributes', advantage: 'Merits & backgrounds', ritual: 'Rituals', ceremony: 'Ceremonies',
  blood_potency: 'Blood Potency',
};

async function growth(pool, people, P) {
  const [rows] = await pool.query(`SELECT character_id, action, target, cost, created_at FROM xp_log WHERE ${P.R('created_at')}`);
  let spent = 0; let granted = 0; let bpRises = 0;
  const kinds = new Map();
  const disciplines = new Map();
  const spenders = new Map();
  const disciplined = new Map();
  const byDay = new Map();
  for (const r of rows) {
    const cost = Number(r.cost) || 0;
    if (cost < 0) { granted -= cost; continue; }
    if (!cost || !XP_KINDS[r.action]) continue;
    spent += cost;
    bump(kinds, XP_KINDS[r.action], cost);
    bump(spenders, r.character_id, cost);
    bump(byDay, athens(msOf(r.created_at)).day, cost);
    if (r.action === 'discipline' && r.target) { bump(disciplines, r.target); bump(disciplined, r.character_id); }
    if (r.action === 'blood_potency') bpRises += 1;
  }
  const unspent = people.all.filter(isActive).reduce((s, c) => s + (Number(c.xp) || 0), 0);
  const perChar = (map) => tally([...map].map(([k, n]) => ({ k, n })), people.char);

  return section('growth', 'Growth', 'fa-star', [
    hero('growth.spent', 'XP spent', num(spent), granted ? `${num(granted)} XP awarded by the Storytellers` : null),
    tiles('growth.tiles', 'The ledger', [
      { label: 'Unspent XP now', value: num(unspent), sub: 'across active characters' },
      bpRises ? { label: 'Blood Potency rises', value: num(bpRises) } : null,
      disciplines.size ? { label: 'Discipline dots bought', value: num([...disciplines.values()].reduce((a, b) => a + b, 0)) } : null,
    ]),
    bars('growth.kinds', 'Where the XP went', ranked(kinds).map((e) => ({ label: e.k, value: e.n })), 'XP'),
    bars('growth.disciplines', 'Favorite Disciplines', ranked(disciplines).slice(0, 8).map((e) => ({ label: e.k, value: e.n })), 'dots'),
    timeline('growth.timeline', 'XP spent over time', series(byDay, P), 'XP'),
    award('growth.spender', 'Biggest spender', 'fa-star', perChar(spenders), (n) => `${num(n)} XP spent`),
    award('growth.disciplined', 'Most disciplined', 'fa-wand-magic-sparkles', perChar(disciplined), (n) => plural(n, 'Discipline dot')),
  ]);
}

/* ---------------- News & rumors (authors are never named) ---------------- */

async function news(pool, P) {
  const { R } = P;
  const [[entries], [[rumors]]] = await Promise.all([
    pool.query(`SELECT e.id, e.type, e.title, (SELECT COUNT(*) FROM news_reads r WHERE r.news_id = e.id) readers,
        (SELECT COUNT(*) FROM announcement_reactions a WHERE a.announcement_id = e.id) reactions
       FROM news_entries e WHERE e.is_private = 0 AND ${R('COALESCE(e.published_at, e.created_at)')}`),
    pool.query(`SELECT COUNT(*) n FROM rumors WHERE ${R('created_at')}`),
  ]);
  const articles = entries.filter((e) => e.type === 'news');
  const decrees = entries.filter((e) => e.type === 'announcement');
  const reads = entries.reduce((s, e) => s + Number(e.readers), 0);
  const byReaders = entries.map((e) => ({ c: { name: e.title || 'Untitled' }, n: Number(e.readers) })).filter((e) => e.n > 0).sort((a, b) => b.n - a.n);
  const byReactions = decrees.map((e) => ({ c: { name: e.title || 'Untitled' }, n: Number(e.reactions) })).filter((e) => e.n > 0).sort((a, b) => b.n - a.n);

  return section('news', 'News & Rumors', 'fa-newspaper', [
    hero('news.reads', 'Times the news was read', num(reads), `${plural(entries.length, 'piece')} published`),
    tiles('news.tiles', 'The presses', [
      { label: 'Articles', value: num(articles.length) },
      { label: 'Decrees', value: num(decrees.length) },
      { label: 'Rumors', value: num(rumors.n) },
    ]),
    award('news.read', 'Most read', 'fa-newspaper', byReaders, (n) => plural(n, 'reader')),
    award('news.reacted', 'Most reacted decree', 'fa-bullhorn', byReactions, (n) => plural(n, 'reaction')),
    bars('news.top', 'Most read pieces', byReaders.slice(0, 5).map((e) => ({ label: e.c.name, value: e.n })), 'readers'),
  ]);
}

/* ---------------- Downtimes & sessions ---------------- */

async function story(pool, people, P) {
  const { R } = P;
  const [[downtimes], [sessions], [seats], [[tableRolls]], [[visions]], [[trades]]] = await Promise.all([
    pool.query(`SELECT character_id, status, created_at, resolved_at FROM downtimes WHERE ${R('created_at')}`),
    pool.query(`SELECT id, duration_seconds FROM live_sessions WHERE ${R('created_at')}`),
    pool.query(`SELECT p.session_id, p.user_id, p.character_id FROM live_session_participants p
        JOIN live_sessions s ON s.id = p.session_id WHERE ${R('s.created_at')}`),
    pool.query(`SELECT COUNT(*) n FROM dice_rolls WHERE session_id IS NOT NULL AND ${R('created_at')}`),
    pool.query(`SELECT COUNT(*) n FROM premonitions WHERE ${R('created_at')}`),
    pool.query(`SELECT COUNT(*) n FROM inventory_transfers WHERE claimed_at IS NOT NULL AND ${R('claimed_at')}`),
  ]);
  const done = downtimes.filter((d) => /^(resolved|approved)/i.test(d.status || ''));
  const inScene = downtimes.filter((d) => /in scene/i.test(d.status || '')).length;
  const timed = done.filter((d) => d.resolved_at && d.created_at);
  const avgDays = timed.length ? timed.reduce((s, d) => s + (msOf(d.resolved_at) - msOf(d.created_at)), 0) / timed.length / 864e5 : null;
  const schemers = new Map();
  for (const d of downtimes) bump(schemers, d.character_id);
  const attended = new Map();
  for (const s of seats) {
    const c = people.char(s.character_id) || people.user(s.user_id);
    if (c) attended.set(`${c.id}:${s.session_id}`, c);
  }
  const regulars = new Map();
  for (const c of attended.values()) bump(regulars, c.id);
  // A session nobody ended closes itself after 24 h (services/liveSession.js): not a real night.
  const longest = Math.max(0, ...sessions.map((s) => Number(s.duration_seconds) || 0).filter((sec) => sec < 20 * 3600));
  const hours = (sec) => `${(sec / 3600).toFixed(1)} h`;
  const perChar = (map) => tally([...map].map(([k, n]) => ({ k, n })), people.char);

  return section('story', 'Downtimes & Sessions', 'fa-scroll', [
    hero('story.downtimes', 'Downtimes filed', num(downtimes.length), done.length ? `${num(done.length)} resolved` : null),
    tiles('story.dt', 'Between the nights', [
      inScene ? { label: 'Resolved in a scene', value: num(inScene) } : null,
      avgDays != null ? { label: 'Average time to resolve', value: `${avgDays.toFixed(1)} days` } : null,
      Number(visions.n) ? { label: 'Premonitions sent', value: num(visions.n) } : null,
      Number(trades.n) ? { label: 'Items traded', value: num(trades.n) } : null,
    ]),
    tiles('story.sessions', 'At the table', sessions.length ? [
      { label: 'Live sessions', value: num(sessions.length) },
      { label: 'Average table', value: (attended.size / sessions.length).toFixed(1), sub: 'players per session' },
      longest ? { label: 'Longest session', value: hours(longest) } : null,
      Number(tableRolls.n) ? { label: 'Rolls at the table', value: num(tableRolls.n) } : null,
    ] : []),
    award('story.schemer', 'Master schemer', 'fa-scroll', perChar(schemers), (n) => plural(n, 'downtime')),
    award('story.regular', 'Always at the table', 'fa-calendar-days', perChar(regulars), (n) => plural(n, 'session')),
  ]);
}

/* ---------------- Entry point ---------------- */

async function periodsFromCalendar() {
  const today = athens(Date.now()).day;
  return (await readCycles())
    .map((c, i) => ({ label: `Cycle ${cycleIndexOf(c, i)}`, from: dateOnly(c.opening_date), to: dateOnly(c.closing_date) || null }))
    .filter((c) => c.from && c.from <= today)
    .sort((a, b) => b.from.localeCompare(a.from));
}

/**
 * GET /api/admin/stats?from=YYYY-MM-DD&to=YYYY-MM-DD (either may be empty: no bound).
 * @returns {Promise<{ period, cycles, sections: Array<{ id, title, icon, cards: object[] }> }>}
 */
async function buildStats(pool, query = {}) {
  const P = period(query);
  const people = await loadPeople(pool);
  const sections = await Promise.all([
    population(people, P),
    comms(pool, people, P),
    dice(pool, people, P),
    hunt(pool, people, P),
    domains(pool, people, P),
    court(pool, people, P),
    coteries(pool, people),
    growth(pool, people, P),
    news(pool, P),
    story(pool, people, P),
  ]);
  return { period: { from: P.from, to: P.to }, cycles: await periodsFromCalendar(), sections };
}

module.exports = { buildStats, athens, athensMidnight, series };

// scripts/build-rules-catalog.mjs
//
// Generates data/rulesCatalog.json from the front end's rules data, so the
// server can price and validate XP purchases itself without trusting the
// client. front/src/data stays the single source of truth; re-run after
// editing disciplines, rituals or merits:   npm run catalog
// tests/rulesCatalog.test.js fails when the JSON is out of date.
import { writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const FRONT_DATA = path.resolve(here, '../../front/src/data');
export const OUT = path.resolve(here, '../data/rulesCatalog.json');

export async function buildCatalog() {
  const load = (f) => import(pathToFileURL(path.join(FRONT_DATA, f)).href);
  const { DISCIPLINES } = await load('disciplines.js');
  const { RITUALS } = await load('rituals.js');
  const { listAllItems } = await load('merits_flaws.js');
  const { POWER_MECHANICS } = await load('disciplineMechanics.js');

  const disciplines = {};
  for (const [name, d] of Object.entries(DISCIPLINES)) {
    const powers = {};
    for (const [lvl, list] of Object.entries(d.levels || {})) {
      for (const p of list || []) {
        if (!p?.id) continue;
        powers[p.id] = { level: Number(lvl), name: p.name };
        if (p.clan) powers[p.id].clan = p.clan;
        if (p.amalgam) powers[p.id].amalgam = p.amalgam;
        if (p.dice_pool) powers[p.id].dicePool = p.dice_pool;
        const mod = POWER_MECHANICS[p.id]?.dicePoolMod;
        if (mod) powers[p.id].dicePoolMod = mod.amount; // a number, or "@Discipline" / "@Discipline/2"
      }
    }
    disciplines[name] = { clanAffinity: d.clan_affinity || [], powers };
  }

  const rituals = {};
  for (const kind of ['blood_sorcery', 'oblivion']) {
    rituals[kind] = {};
    for (const [lvl, list] of Object.entries(RITUALS[kind]?.levels || {})) {
      for (const r of list || []) if (r?.id) rituals[kind][r.id] = { level: Number(lvl), name: r.name };
    }
  }

  const advantages = {};
  for (const i of listAllItems()) advantages[i.id] = { type: i.type, name: i.name, dots: i.dots };

  return { disciplines, rituals, advantages };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  writeFileSync(OUT, JSON.stringify(await buildCatalog()) + '\n');
  console.log('Wrote', OUT);
}

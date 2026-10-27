// scripts/build-rules-catalog.mjs
//
// Generates data/rulesCatalog.json from the front ends rules data, so the
// server can price and validate XP purchases itself without trusting the
// client. front/src/data stays the single source of truth: re run after
// editing disciplines, rituals, merits, or systems:   npm run catalog
// tests/rulesCatalog.test.js fails when the JSON is out of date.
import { writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const FRONT_DATA = path.resolve(here, '../../front/src/data');
export const OUT = path.resolve(here, '../data/rulesCatalog.json');
export const OUT_INDEX = path.resolve(here, '../data/corebookSubjectIndex.json');

const BOOK_FILES = {
  'Corebook': 'Vampire-the-Masquerade-1.pdf',
  'Players Guide': 'Vampire-The-Masquerade-V5-Players-Guide.pdf',
  'Cults of the Blood Gods': 'Cults-of-the-Blood-Gods-Vampire-the-Masquerade-5th-Edition.pdf',
  'Camarilla': 'Vampire-the-Masquerade-V5-Camarilla-2018.pdf',
  'Anarch': 'Anarch-Vampire-the-Masquerade-5th-Edition.pdf',
  'Sabbat': 'Vampire-The-Masquerade-V5-Sabbat-The-Black-Hand-Definitive-Edition.pdf'
};

export async function buildSubjectIndex() {
  const load = (f) => import(pathToFileURL(path.join(FRONT_DATA, f)).href);
  const { SOURCEBOOKS_SUBJECT_INDEX } = await load('sourcebooksIndex.js');
  return SOURCEBOOKS_SUBJECT_INDEX.map((item) => ({
    ...item,
    file: item.file || BOOK_FILES[item.book] || 'Vampire-the-Masquerade-1.pdf'
  }));
}

export async function buildCatalog() {
  const load = (f) => import(pathToFileURL(path.join(FRONT_DATA, f)).href);
  const { DISCIPLINES } = await load('disciplines.js');
  const { RITUALS } = await load('rituals.js');
  const { listAllItems } = await load('merits_flaws.js');
  const { POWER_MECHANICS } = await load('disciplineMechanics.js');
  const { PREDATOR_TYPES } = await load('predator_types.js');
  const { COTERIES } = await load('cotteries.js');
  const { ALTERNATIVE_CLAN_BANES } = await load('clanReference.js');

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
        if (mod) powers[p.id].dicePoolMod = mod.amount;
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
  for (const i of listAllItems()) {
    if (!i?.id) continue;
    advantages[i.id] = {
      type: i.type,
      name: i.name,
      dots: i.dots,
      category: i.category,
      description: i.description || null,
      source: i.source || null,
      book: i.book || null,
      page: i.page || null,
      pdfPage: i.pdfPage || null
    };
  }

  const predatorTypes = {};
  for (const [key, pt] of Object.entries(PREDATOR_TYPES)) {
    const isPlayersGuide = ['Grim Reaper', 'Montero', 'Pursuer', 'Trapdoor'].includes(pt.name);
    const isCults = ['Extortionist', 'Graverobber'].includes(pt.name);
    const isAnarch = pt.name === 'Roadside Killer';
    const isMemoriam = pt.name === 'Tithe Collector';
    const book = isPlayersGuide ? 'Players Guide' : isCults ? 'Cults of the Blood Gods' : isAnarch ? 'Anarch' : isMemoriam ? 'In Memoriam' : 'Corebook';
    const page = isPlayersGuide ? (pt.name === 'Grim Reaper' ? 138 : pt.name === 'Montero' ? 140 : pt.name === 'Pursuer' ? 142 : 144)
      : isCults ? (pt.name === 'Extortionist' ? 98 : 99)
      : isAnarch ? 182
      : isMemoriam ? 42
      : (pt.name === 'Alleycat' ? 175 : pt.name === 'Bagger' ? 175 : pt.name === 'Blood Leech' ? 176 : pt.name === 'Cleaver' ? 176 : pt.name === 'Consensualist' ? 177 : pt.name === 'Farmer' ? 177 : pt.name === 'Osiris' ? 177 : pt.name === 'Sandman' ? 177 : pt.name === 'Scene Queen' ? 178 : 178);
    const pdfPage = page + (book === 'Corebook' || book === 'Players Guide' ? 2 : 1);

    predatorTypes[key] = {
      name: pt.name,
      rolls: pt.rolls,
      huntingPools: pt.huntingPools || [],
      huntingAttributes: pt.huntingAttributes || [],
      huntingSkills: pt.huntingSkills || [],
      specialties: pt.picks?.specialty || [],
      disciplines: typeof pt.picks?.discipline === 'function' ? pt.picks.discipline() : [],
      desc: pt.desc,
      book,
      page,
      pdfPage
    };
  }

  const coteries = {};
  for (const [key, cData] of Object.entries(COTERIES)) {
    coteries[key] = {
      name: key,
      domain: cData.domain || null,
      required: cData.required || null,
      flaws: cData.flaws || null,
      extras: cData.extras || [],
      notes: cData.notes || null,
      book: 'Corebook',
      page: 197,
      pdfPage: 199
    };
  }

  const alternativeClanBanes = ALTERNATIVE_CLAN_BANES;

  return { disciplines, rituals, advantages, predatorTypes, coteries, alternativeClanBanes };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  writeFileSync(OUT, JSON.stringify(await buildCatalog(), null, 2) + '\n');
  console.log('Wrote', OUT);
  writeFileSync(OUT_INDEX, JSON.stringify(await buildSubjectIndex(), null, 2) + '\n');
  console.log('Wrote', OUT_INDEX);
}

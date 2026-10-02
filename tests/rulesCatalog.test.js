// tests/rulesCatalog.test.js — data/rulesCatalog.json is generated from the
// front end's rules data (scripts/build-rules-catalog.mjs). If this fails, a
// discipline, ritual or merit changed in front/src/data: run `npm run catalog`.
const fs = require('fs');
const path = require('path');

const frontData = path.resolve(__dirname, '../../front/src/data/disciplines.js');

describe('rules catalog', () => {
  it.skipIf(!fs.existsSync(frontData))('matches front/src/data', async () => {
    const { buildCatalog } = await import('../scripts/build-rules-catalog.mjs');
    expect(require('../data/rulesCatalog.json')).toEqual(JSON.parse(JSON.stringify(await buildCatalog())));
  });
});

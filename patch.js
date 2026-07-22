const fs = require('fs');
const content = fs.readFileSync('../node_modules/fastify/lib/route.js', 'utf8');
const patched = content.replace('const request = new this.Request(req.id, params, req, res, store.log, this)', 'if (req.url.includes("banner")) { console.log("CONTEXT KEYS:", Object.keys(this)); console.log("preParsing value:", this.preParsing); } const request = new this.Request(req.id, params, req, res, store.log, this)');
fs.writeFileSync('../node_modules/fastify/lib/route.js', patched);

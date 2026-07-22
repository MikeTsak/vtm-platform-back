const fs = require('fs');
const content = fs.readFileSync('../node_modules/fastify/lib/route.js', 'utf8');
const patched = content.replace("avvio.once('preReady', () => {", "avvio.once('preReady', () => { console.log('preReady executing for route', opts.url);");
fs.writeFileSync('../node_modules/fastify/lib/route.js', patched);

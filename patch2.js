const fs = require('fs');
const content = fs.readFileSync('../node_modules/fastify/lib/route.js', 'utf8');
const patched = content.replace('const request = new context.Request(id, params, req, query, childLogger, context)', 'console.log("PREPARING VALUE IS:", context.preParsing); const request = new context.Request(id, params, req, query, childLogger, context)');
fs.writeFileSync('../node_modules/fastify/lib/route.js', patched);

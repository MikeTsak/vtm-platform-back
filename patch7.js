const fs = require('fs');
let content = fs.readFileSync('server.fastify.js', 'utf8');

// Fix SSE usages
content = content.replace(/res\.flushHeaders\(\)/g, 'reply.raw.flushHeaders()');
content = content.replace(/res\.write\(/g, 'reply.raw.write(');
content = content.replace(/res\.flush\(\)/g, 'reply.raw.flush()');

// Fix res.writeHead inside routes
content = content.replace(/res\.writeHead\(/g, 'reply.raw.writeHead(');

fs.writeFileSync('server.fastify.js', content);
console.log('Patched res references.');

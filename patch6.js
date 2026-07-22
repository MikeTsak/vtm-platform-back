const fs = require('fs');
let content = fs.readFileSync('server.fastify.js', 'utf8');
content = content.replace(/server\.listen\s*\(\s*PORT\s*,/g, "fastify.listen({ port: PORT, host: '0.0.0.0' },");
fs.writeFileSync('server.fastify.js', content);

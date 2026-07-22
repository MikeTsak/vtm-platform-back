const fs = require('fs');
const content = fs.readFileSync('../node_modules/fastify/lib/route.js', 'utf8');
const patched = content.replace("this.after((notHandledErr, done) => {", "this.after((notHandledErr, done) => { console.log('this.after executed for route', opts.url);");
fs.writeFileSync('../node_modules/fastify/lib/route.js', patched);

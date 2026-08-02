const fs = require('fs');
let code = fs.readFileSync('server.fastify.js', 'utf8');
let counter = 0;
// First remove the old trace
code = code.replace(/console\.log\("Registering plugin " \+ \([^)]+\)\); /g, '');
// Now add the new trace WITH .after()
code = code.replace(/fastify\.register\([^;]+;/g, (match) => {
  counter++;
  return match + ' fastify.after(() => console.log("Finished loading plugin ' + counter + '"));';
});
fs.writeFileSync('server.fastify.js', code);

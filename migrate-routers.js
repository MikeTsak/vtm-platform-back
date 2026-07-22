const fs = require('fs');
const path = require('path');

const routeFiles = ['routes/dashboard.js', 'routes/index.js', 'routes/users.js'];

for (const file of routeFiles) {
  if (!fs.existsSync(file)) continue;
  let content = fs.readFileSync(file, 'utf8');

  // Replace standard route signatures
  content = content.replace(/router\.(get|post|put|delete|patch)\(([^,]+),\s*(.*?)(\(?_?req,\s*_?res\)?)\s*=>\s*\{/g, (match, method, urlPath, middlewares, reqRes) => {
    let mw = middlewares.trim();
    if (mw.endsWith(',')) mw = mw.slice(0, -1);

    let isAsync = false;
    if (mw === 'async') {
      isAsync = true;
      mw = '';
    } else if (mw.endsWith(' async')) {
      isAsync = true;
      mw = mw.slice(0, -6).trim();
      if (mw.endsWith(',')) mw = mw.slice(0, -1);
    }

    if (mw.length > 0) {
      if (isAsync) return `fastify.${method}(${urlPath}, { preHandler: [${mw}] }, async (req, reply) => {`;
      return `fastify.${method}(${urlPath}, { preHandler: [${mw}] }, (req, reply) => {`;
    } else {
      if (isAsync) return `fastify.${method}(${urlPath}, async (req, reply) => {`;
      return `fastify.${method}(${urlPath}, (req, reply) => {`;
    }
  });

  // Rename res to reply
  content = content.replace(/res\.status\(/g, 'reply.status(');
  content = content.replace(/res\.json\(/g, 'reply.send(');
  content = content.replace(/res\.send\(/g, 'reply.send(');
  content = content.replace(/res\.redirect\(/g, 'reply.redirect(');
  content = content.replace(/res\.set\(/g, 'reply.header(');
  content = content.replace(/res\.setHeader\(/g, 'reply.header(');
  content = content.replace(/res\.end\(/g, 'reply.send(');
  content = content.replace(/_?req\.body/g, 'req.body');
  content = content.replace(/_?req\.params/g, 'req.params');
  content = content.replace(/_?req\.query/g, 'req.query');
  content = content.replace(/_?req\.user/g, 'req.user');

  // Remove express router stuff
  content = content.replace(/const express = require\('express'\);\s*const router = express\.Router\(\);/, "module.exports = async function (fastify, opts) {");
  content = content.replace(/module\.exports = router;/, "};");
  
  // Auth Middleware
  content = content.replace(/require\('\.\.\/authMiddleware'\)/g, "require('../authMiddleware.fastify')");

  // Multer removal
  content = content.replace(/const multer = require\('multer'\);/g, "/* multer removed from router */");
  content = content.replace(/const upload = multer\(\{[\s\S]*?\}\);/g, "/* multer upload removed */");
  content = content.replace(/upload\.single\([^)]+\)/g, "async (req, reply) => { /* TODO: Implement multipart parsing here */ }");
  content = content.replace(/upload\.array\([^)]+\)/g, "async (req, reply) => { /* TODO: Implement multipart parsing here */ }");

  const newFileName = file.replace('.js', '.fastify.js');
  fs.writeFileSync(newFileName, content, 'utf8');
  console.log(`Migrated ${file} -> ${newFileName}`);
}

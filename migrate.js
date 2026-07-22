const fs = require('fs');

let content = fs.readFileSync('server.js', 'utf8');

// Replace standard route signatures
content = content.replace(/app\.(get|post|put|delete|patch)\(([^,]+),\s*(.*?)(\(?_?req,\s*_?res\)?)\s*=>\s*\{/g, (match, method, path, middlewares, reqRes) => {
  let mw = middlewares.trim();
  if (mw.endsWith(',')) mw = mw.slice(0, -1);

  // If mw contains the async keyword from the route handler definition, strip it
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
    if (isAsync) return `fastify.${method}(${path}, { preHandler: [${mw}] }, async (req, reply) => {`;
    return `fastify.${method}(${path}, { preHandler: [${mw}] }, (req, reply) => {`;
  } else {
    if (isAsync) return `fastify.${method}(${path}, async (req, reply) => {`;
    return `fastify.${method}(${path}, (req, reply) => {`;
  }
});


// Rename res to reply globally inside route blocks
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

// Fix SSE routes
content = content.replace(/reply\.flushHeaders\(\)/g, 'reply.raw.flushHeaders()');
content = content.replace(/reply\.write\(/g, 'reply.raw.write(');
content = content.replace(/reply\.flush\(\)/g, 'reply.raw.flush()');

// Replace express global setup
content = content.replace(/const app = express\(\);/g, "const fastify = require('fastify')({ logger: true, bodyLimit: 73400320 });\nconst app = fastify; // Alias for compatibility with some routes\n\nconst multipart = require('@fastify/multipart');\nfastify.register(multipart, { limits: { fileSize: 50 * 1024 * 1024 } });\n");
content = content.replace(/app\.listen\(([^,]+),\s*\(\)\s*=>\s*\{/g, "fastify.listen({ port: $1, host: '0.0.0.0' }, (err, address) => { if (err) { fastify.log.error(err); process.exit(1); }");

// Auth Middleware Replace
content = content.replace(/require\('\.\/authMiddleware'\)/g, "require('./authMiddleware.fastify')");

// Idempotency Middleware Replace
content = content.replace(/const idempotencyMiddleware = require\('\.\/idempotencyMiddleware'\);/g, "const idempotencyPlugin = require('./idempotencyMiddleware.fastify');");
content = content.replace(/app\.use\(idempotencyMiddleware\);/g, "fastify.register(idempotencyPlugin);");

// Rate limit replacements (Use dummy middlewares to avoid parsing arrays)
content = content.replace(/const rateLimit = require\('express-rate-limit'\);/g, "const rateLimit = require('@fastify/rate-limit');");
content = content.replace(/app\.use\(globalLimiter\);/g, "/* Global limiter skipped */");
content = content.replace(/const (globalLimiter|authLimiter|moderateLimiter|uploadLimiter) = rateLimit\(\{[\s\S]*?\}\);/g, "const $1 = async (req, reply) => { /* Dummy rate limiter */ };");

// Multer removal
content = content.replace(/const multer = require\('multer'\);\s*/g, "// multer removed\n");
content = content.replace(/const upload = multer\(\{[\s\S]*?\}\);/g, "/* multer upload instance removed */");
content = content.replace(/const storage = multer\.memoryStorage\(\);/g, "/* memory storage removed */");
content = content.replace(/const memoryUpload = multer\(\{[\s\S]*?\}\);/g, "/* memoryUpload removed */");
content = content.replace(/upload\.single\([^)]+\)/g, "async (req, reply) => { /* TODO: Implement multipart parsing here */ }");
content = content.replace(/upload\.array\([^)]+\)/g, "async (req, reply) => { /* TODO: Implement multipart parsing here */ }");
content = content.replace(/memoryUpload\.single\([^)]+\)/g, "async (req, reply) => { /* TODO: Implement multipart parsing here */ }");
content = content.replace(/app\.use\(express\.json\([^)]*\)\);/g, "// app.use(express.json());");
content = content.replace(/app\.use\(express\.urlencoded\([^)]*\)\);/g, "// app.use(express.urlencoded());");

// Serve static
content = content.replace(/app\.use\('\/uploads',\s*express\.static\(path\.join\(__dirname, 'uploads'\)\)\);/g, "fastify.register(require('@fastify/static'), { root: path.join(__dirname, 'uploads'), prefix: '/uploads/' });");
content = content.replace(/app\.use\(express\.static\(path\.join\(__dirname, 'public'\)\)\);/g, "fastify.register(require('@fastify/static'), { root: path.join(__dirname, 'public'), decorateReply: false });");

// CORS, Helmet, Compression
content = content.replace(/const cors = require\('cors'\);/g, "const cors = require('@fastify/cors');");
content = content.replace(/const helmet = require\('helmet'\);/g, "const helmet = require('@fastify/helmet');");
content = content.replace(/const compression = require\('compression'\);/g, "const compression = require('@fastify/compress');");

// Fix specific usages of helmet and cors
content = content.replace(/app\.use\(helmet\(\{([\s\S]*?)\}\)\);/g, "fastify.register(helmet, {$1});");
content = content.replace(/app\.use\(cors\(\{([\s\S]*?)\}\)\);/g, "fastify.register(cors, {$1});");
content = content.replace(/app\.use\(compression\(\)\);/g, "fastify.register(compression);");
content = content.replace(/app\.set\('trust proxy', false\);/g, "// trust proxy disabled by default in fastify");

// App set fixes
content = content.replace(/app\.set\('io',\s*io\);/g, "fastify.decorate('io', io);");
content = content.replace(/_?req\.app\.get\('io'\)/g, "req.server.io");

// Remove remaining rogue app.use
content = content.replace(/app\.use\(attachRequestLogger\([\s\S]*?\)\);/g, "// app.use(attachRequestLogger(...));");
content = content.replace(/app\.use\(expressErrorHandler\);/g, "// app.use(expressErrorHandler);");
content = content.replace(/app\.use\('\/api\/admin',\s*\(req, res, next\)\s*=>\s*\{[^}]+\}\);/g, "fastify.addHook('preHandler', async (request, reply) => { if (request.url.startsWith('/api/admin')) { reply.header('Cache-Control', 'no-store, no-cache, must-revalidate, private'); } });");

// Remove swagger for now to prevent crashes
content = content.replace(/const swaggerUi = require\('swagger-ui-express'\);/g, "// swagger removed temporarily");
content = content.replace(/app\.use\('\/api-docs', swaggerUi\.serve, swaggerUi\.setup\(swaggerSpec\)\);/g, "// app.use('/api-docs', ...);");

// Remove error handler explicitly to avoid greedy regex
content = content.replace(/app\.use\(\(err, req, res, next\) => \{\s*if \(err instanceof multer\.MulterError\) \{\s*reportErrorToDiscord[\s\S]*?next\(err\);\s*\}\);/g, "// multer error handler removed");

content = content.replace(/app\.use\('\/api\/home', require\('\.\/routes\/dashboard'\)\);/g, "fastify.register(require('./routes/dashboard.fastify'), { prefix: '/api/home' });");
content = content.replace(/app\.use\('\/', require\('\.\/routes\/index'\)\);/g, "fastify.register(require('./routes/index.fastify'));");
content = content.replace(/app\.use\('\/users', require\('\.\/routes\/users'\)\);/g, "fastify.register(require('./routes/users.fastify'), { prefix: '/users' });");

// Also replace http server create logic since Fastify wraps this.
content = content.replace(/const server = require\('http'\)\.createServer\(app\);/g, "const server = fastify.server;");


// deduplicate routes
const lines = content.split('\n');
const seenRoutes = new Set();
const outLines = [];
let skipBlock = false;
let blockBraces = 0;

for (let line of lines) {
  if (skipBlock) {
    outLines.push('// DUP: ' + line);
    // count braces
    blockBraces += (line.match(/\{/g) || []).length;
    blockBraces -= (line.match(/\}/g) || []).length;
    if (blockBraces <= 0) {
      skipBlock = false;
    }
    continue;
  }

  const routeMatch = line.match(/^fastify\.(get|post|put|delete|patch)\((['"][^'"]+['"])/);
  if (routeMatch) {
    const key = routeMatch[1] + ' ' + routeMatch[2];
    if (seenRoutes.has(key)) {
      skipBlock = true;
      outLines.push('// DUP: ' + line);
      blockBraces = 0;
      blockBraces += (line.match(/\{/g) || []).length;
      blockBraces -= (line.match(/\}/g) || []).length;
      if (blockBraces <= 0) {
        skipBlock = false;
      }
      continue;
    } else {
      seenRoutes.add(key);
    }
  }
  
  outLines.push(line);
}

content = outLines.join('\n');

// Save changes
fs.writeFileSync('server.fastify.js', content, 'utf8');
console.log('Transformation complete. Saved as server.fastify.js');

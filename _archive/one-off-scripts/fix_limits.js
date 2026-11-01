const fs = require('fs');
let content = fs.readFileSync('server.fastify.js', 'utf8');

// 1. Remove dummy limiters
content = content.replace(/const globalLimiter.*?\n/g, '');
content = content.replace(/const authLimiter.*?\n/g, '');
content = content.replace(/const moderateLimiter.*?\n/g, '');
content = content.replace(/const uploadLimiter.*?\n/g, '');
content = content.replace(/\/\* Global limiter skipped \*\//g, '');

// 2. Add the fastify.register statement
// Find where fastify is required and initialized.
// "const fastify = require('fastify')" or "const rateLimit = require('@fastify/rate-limit');"
content = content.replace(
  "const rateLimit = require('@fastify/rate-limit');",
  "const rateLimit = require('@fastify/rate-limit');\nfastify.register(rateLimit, {\n  max: 3000,\n  timeWindow: 15 * 60 * 1000\n});"
);

// 3. Process routes
const limiters = [
  { name: 'authLimiter', max: 5 },
  { name: 'moderateLimiter', max: 30 },
  { name: 'uploadLimiter', max: 10 }
];

limiters.forEach(limiter => {
  const regex = new RegExp(`(\\{.*?preHandler:\\s*\\[)(.*?)(\\].*?)\\}`, 'g');
  
  content = content.replace(regex, (match, p1, p2, p3) => {
    if (!p2.includes(limiter.name)) return match;
    
    // Remove the limiter from the array
    let newArray = p2.split(',').map(s => s.trim()).filter(s => s && s !== limiter.name).join(', ');
    
    // Check if config already exists in p3 (very unlikely based on our inspection, but to be safe)
    if (p3.includes('config:')) {
      // Just append it
      return `${p1}${newArray}${p3}`.replace('config: {', `config: { rateLimit: { max: ${limiter.max}, timeWindow: 15 * 60 * 1000 }, `);
    } else {
      return `${p1}${newArray}${p3}, config: { rateLimit: { max: ${limiter.max}, timeWindow: 15 * 60 * 1000 } } }`;
    }
  });
});

fs.writeFileSync('server.fastify.js', content);
console.log('Rate limiters configured');

const { z } = require('zod');
const { log } = require('../logger');

const envSchema = z.object({
  // Server Config
  PORT: z.string().optional().default('5000'),
  CORS_ORIGIN: z.string().optional(),

  // Database
  DB_HOST: z.string(),
  DB_PORT: z.string(),
  DB_USER: z.string(),
  DB_PASS: z.string(),
  DB_NAME: z.string(),

  // JWT
  JWT_SECRET: z.string(),
  JWT_REFRESH_SECRET: z.string().optional(),

  // VAPID keys
  VAPID_PUBLIC_KEY: z.string(),
  VAPID_PRIVATE_KEY: z.string(),

  // Add more keys here as you refactor and find them.
  // We can make some optional if they aren't strictly required for boot.
});

function validateEnv() {
  try {
    envSchema.parse(process.env);
    log.ok('Environment variables validated successfully.');
  } catch (error) {
    log.err('❌ Environment Variable Validation Failed:');
    if (error && error.issues) {
      error.issues.forEach((err) => {
        console.error(`  - ${err.path.join('.')}: ${err.message}`);
      });
    } else {
      console.error(error);
    }
    process.exit(1);
  }
}

module.exports = { validateEnv };

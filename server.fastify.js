// server.fastify.js
//
// Process entry point. Everything this file does is *boot sequencing*:
//
//   1. load + validate the environment (must happen before anything touches
//      process.env or opens the DB pool)
//   2. install crash handlers
//   3. build the app          -> app.js
//   4. attach socket.io       -> realtime.js
//   5. start background jobs  -> jobs/index.js
//   6. listen
//
// Routes live in routes/ (see routes/index.js for the manifest), shared
// helpers in services/, Fastify infrastructure in plugins/.

require('dotenv').config();
const { validateEnv } = require('./utils/envValidator');
validateEnv();

// Nothing above this line may require a module that reads process.env at load
// time — notably ./db, which builds its pool from DB_* the moment it is first
// required. Everything below is safe.
const { log, installProcessHandlers } = require('./logger');
const { initDatabase } = require('./migrations/schema');
const { printReadyBanner } = require('./utils/bootBanner');
const { buildApp } = require('./app');
const { attachRealtime } = require('./realtime');
const { startJobs } = require('./jobs');

const bootStartedAt = Date.now();
const PORT = Number(process.env.PORT) || 3001;

const asciiArt = `
         %@@@@@@@@@@@@@@@
         #*@@@%##*##%@@@=
      .@@@-@%        %@@#@@=
    -@@@@@-@*        %@@-@@@@%
   @@*@%@@@@@@@@@@@@@@@@@%#@+@@.
  @@+#@+%+%@@@@@@@@@@@@@+@#%@+%@:
 @@++@#+@*#@+#@#@@@%@+@@+@++@++@@
 @@++@%+@@@@#%@@#%@@%#@@@@+%@*+%@#
=@.  ==  @-@ *# :* %%:@@#   #   #%
-*        -@*-  :#   %@@        .%
          -@* @@@@@@-*@@
          -@@@@@@@@@@@@@
         %@@%@@@@@@@@@@@@
         +@@@@@@@@@@@@@@%
`;
console.log(asciiArt);
console.log('🦇 Erebus Portal API');

// Catch crashes and unhandled promise rejections before anything else runs.
installProcessHandlers();

log.start('API booting…');

// The Discord bot runs decoupled, in its own module.
require('./discordWorker');

// Schema creation is idempotent and deliberately not awaited — the API comes
// up straight away and the first request that needs a missing table would fail
// loudly rather than the whole boot hanging on DDL.
initDatabase();

const fastify = buildApp();

// Must run before listen(): it decorates the instance with `io`, which route
// modules reach through `fastify.io` / `req.server.io`.
attachRealtime(fastify);

fastify
  .listen({ port: PORT, host: '0.0.0.0' })
  .then(async (address) => {
    log.start(`API server started on ${address}`, { port: PORT, env: process.env.NODE_ENV || 'stable' });
    printReadyBanner({
      address,
      env: process.env.NODE_ENV || 'stable',
      nodeVersion: process.version,
      bootMs: Date.now() - bootStartedAt,
    });

    startJobs();

    // Track server start
    try {
      await fastify.db.query(
        "INSERT INTO app_settings (setting_key, setting_value) VALUES ('daily_server_starts', '1') ON DUPLICATE KEY UPDATE setting_value = CAST(CAST(setting_value AS UNSIGNED) + 1 AS CHAR)"
      );
    } catch (e) {
      log.err('Failed to track server start', { error: e.message });
    }
  })
  .catch((err) => {
    log.err(`API server failed to start`, { error: err.message });
    console.error(err);
    process.exit(1);
  });

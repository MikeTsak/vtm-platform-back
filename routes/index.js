// routes/index.js
//
// The route manifest: every route plugin in the API, and the shared dependency
// bundle they are registered with.
//
// Each module is a standard Fastify plugin —
//   module.exports = async function (fastify, opts) { ... }
// — and destructures only what it needs out of `opts`. Nothing here is
// encapsulation-breaking, so a module can add its own hooks or decorators
// without leaking them into its siblings.
//
// Anything stateless (pure helpers, config, settings access) is require()d
// directly by the module that needs it rather than threaded through `opts`;
// `opts` is reserved for things a test harness may want to substitute —
// chiefly the database pool, the logger, and the auth guards.
// See tests/setup/testApp.js.

const { pluginLoaded } = require('../utils/bootBanner');

// name        — label shown in the boot progress bar
// path        — module to require
// prefix      — optional route prefix (modules without one declare full paths)
// extra       — extra opts merged on top of the shared bundle
const ROUTE_MODULES = [
  { name: 'dashboard', path: './dashboard.fastify', prefix: '/api/home' },
  { name: 'auth', path: './auth', prefix: '/api/auth' },
  { name: 'users', path: './users', prefix: '/api/users' },
  { name: 'characters', path: './characters' },
  { name: 'character-xp', path: './characterXp' },
  { name: 'discipline-access', path: './disciplineAccess' },
  { name: 'wiki', path: './wiki' },

  { name: 'system', path: './system' },
  { name: 'banner', path: './banner' },
  { name: 'maintenance', path: './maintenance' },
  { name: 'clans', path: './clans' },
  { name: 'ntfy', path: './ntfy' },

  { name: 'xp', path: './xp' },
  { name: 'admin-characters', path: './adminCharacters' },
  { name: 'npcs', path: './npcs' },
  { name: 'npc-chat', path: './npcChat' },
  { name: 'comms', path: './comms' },
  { name: 'chat', path: './chat' },
  { name: 'emails', path: './emails' },
  { name: 'camarilla', path: './camarilla' },
  { name: 'avatars', path: './avatars' },
  { name: 'downtimes', path: './downtimes' },
  { name: 'feeding', path: './feeding' },
  { name: 'domains', path: './domains' },
  { name: 'domain-claims', path: './domainClaims' },
  { name: 'domain-overlays', path: './domainOverlays' },
  { name: 'boons', path: './boons' },
  { name: 'coteries', path: './coteries' },
  { name: 'discord-admin', path: './discordAdmin' },
  { name: 'admin-users', path: './adminUsers' },
  { name: 'admin-logs', path: './adminLogs' },
  { name: 'push', path: './push' },
  { name: 'premonitions', path: './premonitions' },
  { name: 'live-sessions', path: './liveSessions' },
  { name: 'dice', path: './dice' },
  { name: 'news', path: './news' },
  { name: 'rumors', path: './rumors' },
  { name: 'hunts', path: './hunts' },
  { name: 'admin-misc', path: './adminMisc' },
  { name: 'mechanics', path: './mechanics' },
  { name: 'activity', path: './activity', prefix: '/api/activity' },
];

function registerRoutes(fastify, deps) {
  for (const { name, path: modulePath, prefix, extra } of ROUTE_MODULES) {
    const opts = { ...deps, ...extra };
    if (prefix) opts.prefix = prefix;
    fastify.register(require(modulePath), opts);
    fastify.after(() => pluginLoaded(name));
  }
}

module.exports = { ROUTE_MODULES, registerRoutes };

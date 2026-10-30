<div align="center">

# Erebus Portal: API

**The server behind the Athens Through Time *Vampire: The Masquerade* V5 LARP platform.**

Characters, XP, domains, Court politics, in-fiction comms, live sessions, dice, feeding, and the Discord bot: one Fastify process, one MariaDB database.

[![Node.js](https://img.shields.io/badge/Node.js-20%2B-339933?style=flat-square&logo=nodedotjs&logoColor=white)](https://nodejs.org)
[![Fastify](https://img.shields.io/badge/Fastify-5-000000?style=flat-square&logo=fastify&logoColor=white)](https://fastify.dev)
[![MariaDB](https://img.shields.io/badge/MariaDB-10.5%2B-003545?style=flat-square&logo=mariadb&logoColor=white)](https://mariadb.org)
[![Socket.IO](https://img.shields.io/badge/Socket.IO-4-010101?style=flat-square&logo=socketdotio&logoColor=white)](https://socket.io)
[![Vitest](https://img.shields.io/badge/tested_with-Vitest-6E9F18?style=flat-square&logo=vitest&logoColor=white)](https://vitest.dev)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue?style=flat-square)](LICENSE.txt)

[Live API](https://api.attlarp.gr/api/health) · [API docs](https://api.attlarp.gr/api-docs) · [Portal](https://portal.attlarp.gr)

</div>

---

## Contents

- [Highlights](#highlights)
- [Quick start](#quick-start)
- [Scripts](#scripts)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Authentication and roles](#authentication-and-roles)
- [API map](#api-map)
- [Realtime](#realtime)
- [Background jobs](#background-jobs)
- [Database and migrations](#database-and-migrations)
- [Testing](#testing)
- [Backups](#backups)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [The Erebus ecosystem](#the-erebus-ecosystem)

## Highlights

- **Server-authoritative game rules.** XP purchases, sheet edits, Rouse checks, Willpower, damage, feeding hunts, and every dice roll are computed on the server. The client never sends a price or a result. Rules data is compiled from the frontend into `data/rulesCatalog.json` so both sides share one source of truth.
- **About 50 route modules** covering characters, coteries, retainers, domains, boons, Court offices and actions, news and rumours, SchreckNet chat, Surface Web email, anonymous notes, premonitions, hunts, live sessions, inventory with QR trading, the wiki, and admin tooling.
- **Realtime** chat, presence, and live-session sync over Socket.IO, using the same cookie auth as HTTP.
- **Calendar-driven world.** Downtime cycles, comms open/close, ghoul upkeep, Willpower resets, and Elysium invitations all run off the admin calendar through scheduled jobs.
- **Safe by default.** httpOnly cookie sessions with instant revocation, per-tier rate limiting, Zod-validated env and payloads, Helmet, an origin allowlist, and idempotency keys on spend and send endpoints.
- **Self-migrating.** Numbered migrations apply on boot, so a deploy updates the schema with no manual step.
- **Integrations.** Discord bot (`discord.js`), Web Push (VAPID), ntfy alerts, EmailJS password resets, an image CDN, and a Gemini-backed rules assistant.

## Quick start

**Requirements:** Node.js 20+ (Fastify 5 does not support Node 18) and MariaDB 10.5+ (tested on 10.6).

```bash
npm install
# create .env (see Configuration below); the server refuses to boot without the required keys
npm run dev
```

The API listens on `http://localhost:3001/api`. Interactive docs are at `http://localhost:3001/api-docs`.

`initDatabase()` runs on every boot. It creates missing tables and applies pending migrations, so a fresh database needs no manual step.

> **Tip:** To work against real data, `npm run db:staging` replaces your local database with the newest production backup. It refuses to run unless `DB_HOST` is local.

## Scripts

| Script | What it does |
| --- | --- |
| `npm run dev` | Regenerate the Swagger spec, then run under nodemon |
| `npm start` | Regenerate the Swagger spec, then run once |
| `npm test` / `npm run test:watch` | Vitest integration and unit tests |
| `npm run catalog` | Rebuild `data/rulesCatalog.json` from `front/src/data` after rules data changes |
| `npm run migrate` | Apply pending migrations locally |
| `npm run migrate:status` | Show applied, pending and orphaned migrations |
| `npm run migrations` | Apply pending migrations on production |
| `npm run migrations:status` | Inspect production migration state without changing it |
| `npm run backup` | Gzipped SQL dump (add `-- --no-media` to skip image BLOBs) |
| `npm run backup:list` | List local backups with size and date |
| `npm run db:staging` | Mirror the newest production backup into the local database |
| `npm run deploy` | Back up production, upload changed files, restart, verify health |
| `npm run deploy:dry` | Preview a deploy without uploading or restarting |
| `npm run deploy:force` | Re-upload every file regardless of cached hash |
| `npm run deploy:restart` | Restart the live app only and verify health |
| `npm run deploy:backup` / `deploy:backup:full` | Run a production backup on demand (full includes media) |

## Configuration

Create `back/.env`. The schema lives in `utils/envValidator.js`. If a required key is missing, the process names it and exits.

```env
# Required
DB_HOST=localhost
DB_PORT=3306
DB_USER=vtm
DB_PASS=secret                 # DB_PASS, not DB_PASSWORD
DB_NAME=vtm
JWT_SECRET=long-random-string  # changing it logs every user out
VAPID_PUBLIC_KEY=...           # npx web-push generate-vapid-keys
VAPID_PRIVATE_KEY=...

# Optional
PORT=3001
NODE_ENV=development
APP_BASE_URL=https://portal.attlarp.gr      # links in emails and pushes
CORS_ORIGIN=https://portal.attlarp.gr,http://localhost:3002
COOKIE_SECURE=true                          # force cookie flags behind a proxy
VAPID_SUBJECT=mailto:admin@attlarp.gr
```

<details>
<summary><b>All optional integrations</b></summary>

| Variable | Purpose |
| --- | --- |
| `DISCORD_BOT_TOKEN` | Enables the Discord bot. Without it every Discord path is a no-op. |
| `LOG_CHANNEL_ID` | Discord channel for error reports |
| `NTFY_TOPIC` | ntfy.sh topic for admin alerts and daily summaries |
| `IMAGE_API_KEY` | Upload key for the image CDN |
| `GOOGLE_API_KEY` or `GEMINI_API_KEY` | Gemini rules assistant (wiki and Discord bot) |
| `EMAILJS_SERVICE_ID`, `EMAILJS_TEMPLATE_ID`, `EMAILJS_PUBLIC_KEY`, `EMAILJS_PRIVATE_KEY` | Password-reset mail. Without them `/auth/forgot` fails. |
| `EMAILJS_VAR_TO`, `_NAME`, `_APP`, `_LINK`, `_EXPIRES` | Only if your EmailJS template uses non-default variable names |
| `RESET_COOLDOWN_MIN` | Minimum minutes between password-reset requests |
| `LOG_LEVEL`, `LOG_FILE`, `LOG_JSON`, `LOG_SILENCE_PATHS` | Logging. `LOG_FILE` is required for the admin log viewer. |
| `BACKUP_SCHEDULE_ENABLED`, `BACKUP_SCHEDULE_CRON`, `BACKUP_SCHEDULE_FULL`, `BACKUP_DIR`, `BACKUP_RETENTION_DAYS`, `BACKUP_MEDIA_TABLES` | Nightly backup job (see [Backups](#backups)) |
| `TEST_DB_NAME` | Isolated database used by the test suite |
| `DISABLE_LOGIN_LIMITS` | `true` turns off login throttling. For debugging only; remove it afterwards. |

</details>

## Architecture

The API is a Fastify app assembled from plugins. `server.fastify.js` only sequences the boot. It contains no routes.

```text
server.fastify.js          entry: env check -> app -> socket.io -> jobs -> listen
app.js                     builds the Fastify instance (no listen, no side effects)
realtime.js                socket.io auth, rooms, chat relay; decorates fastify.io
discordWorker.js           Discord bot
db.js                      mysql2 promise pool
authMiddleware.fastify.js  authRequired / optionalAuth / requireAdmin

config/      cors.js: origin allowlist shared by HTTP, SSE and socket.io
plugins/     observability, security (helmet, cors, cookie, multipart, static), docs
routes/      one plugin per feature; index.js is the manifest
services/    shared domain logic: dice, rolls, feeding, ghoul upkeep, comms state,
             downtime schedule, court offices, blood hunts, push, discord, media ...
utils/       pure helpers: xpCost, xpPurchase, playerSheetEdit, sheetLock,
             idempotency, envValidator, authCookie, athensTime ...
jobs/        every cron and interval, started once by startJobs()
migrations/  numbered migrations (list/) and hand-runnable SQL equivalents (sql/)
scripts/     migrate, backup, deploy, db:staging, rules catalog
tests/       vitest suites against a real Fastify instance
```

### Adding a route

1. Create `routes/<feature>.js`:

   ```js
   module.exports = async function (fastify, opts) {
     const { pool, authRequired } = opts;

     fastify.get('/api/thing', { preHandler: [authRequired] }, async (req) => {
       return { thing: null };
     });
   };
   ```

2. Add it to `ROUTE_MODULES` in `routes/index.js`.

That is all the wiring. Swagger picks the module up from the same manifest. `opts` carries only what a test may want to substitute (pool, logger, guards, limiters, external clients). `require()` stateless helpers directly.

## Authentication and roles

- The session JWT lives in an **httpOnly cookie** named `token`, so client JavaScript, including an XSS payload, cannot read it. Browsers just send `withCredentials: true`.
- `Authorization: Bearer <token>` is also accepted, for the mobile app, scripts and cURL.
- There is deliberately **no `?token=` fallback**, because URLs leak into logs and history.
- **Instant revocation:** each token embeds the user's `token_version`. Bumping it (password reset, "log out everywhere") invalidates every issued token on the next request.
- **Role is live:** the role is read from the database on each request, not trusted from the JWT, so a demotion takes effect immediately.
- **Cookie flags** (`Secure` and `SameSite`) are decided together in `utils/authCookie.js`. `COOKIE_SECURE` overrides them.

| Role | Access |
| --- | --- |
| `user` | Player |
| `courtuser` | Court officer. Passes `requireCourt`. Specific powers are narrowed further by held offices (`services/courtOffices.js`). |
| `admin` | Storyteller. Passes everything. |

Admin routes answer **403** for a non-admin session and **401** for no session. Use `optionalAuth` for public endpoints that reveal more to signed-in callers. Don't wrap `authRequired` in try/catch: it sends the 401 rather than throwing.

**Rate limiting** is enforced per tier in `services/guards.js`. Signed-in callers are keyed by user ID, so a venue's shared wifi doesn't lock out a table of players. Anonymous callers are keyed by IP.

| Tier | Limit |
| --- | --- |
| `auth` | 30 requests per 15 minutes |
| `moderate` | 120 requests per minute |
| `upload` | 30 requests per minute |

## API map

All routes live under `/api`. **`/api-docs` is the generated, always-current reference.** This table is a map, not an exhaustive list.

| Area | Modules |
| --- | --- |
| Auth and users | `auth`, `users`, `adminUsers`, `debugLogin` |
| Characters and sheets | `characters`, `characterXp`, `xp`, `mechanics`, `disciplineAccess`, `wishlist`, `inventory` |
| Coteries and retainers | `coteries` |
| Domains | `domains`, `domainClaims`, `domainOverlays`, `domainResidents` |
| Court | `camarilla`, `courtActions`, `boons`, `clans` |
| Feeding and downtimes | `feeding`, `downtimes` |
| Comms | `chat`, `npcChat`, `emails`, `comms`, `drafts`, `anonymousNotes` |
| Press | `news`, `rumors`, `banner` |
| Sessions and dice | `liveSessions`, `dice`, `elysium` |
| World content | `premonitions`, `hunts`, `wiki`, `npcs`, `avatars` |
| Ops | `system`, `push`, `ntfy`, `discordAdmin`, `activity`, `adminCharacters`, `adminLogs`, `adminMisc`, `maintenance`, `dashboard` |

**Conventions**

- Success bodies are JSON objects, never bare arrays: `{ character }`, `{ articles: [...] }`, `{ ok: true }`.
- Errors are `{ error }`. Schema failures add `details`.
- Everything under `/api/admin` is sent `Cache-Control: no-store`.
- Long-running admin jobs stream Server-Sent Events instead of blocking.
- XP spends and chat sends honour an `Idempotency-Key` header, so a retry cannot double-charge or double-post.

## Realtime

`realtime.js` attaches Socket.IO to the same HTTP server. Route modules publish through `fastify.io`.

- **Handshake auth** mirrors `authRequired`: cookie first, then `auth.token`, with `token_version` checked.
- **Rooms:** `user_<id>`, `admin_chat`, `group_<id>` (membership-checked), and `session_<code>`.
- The sender identity on relayed messages is overwritten from the verified socket, so it cannot be spoofed.

## Background jobs

Every schedule is registered in `jobs/index.js` and started once, after the server is listening.

| Schedule | Job |
| --- | --- |
| Every minute | Comms switch follows the calendar; flushes the Send Later queue when comms open |
| Every minute | Downtime mass-release ntfy ping (latched, fires once) |
| Every 60 s | Daily Discord mail digest at the admin-set time |
| Every 5 min | Closes live sessions left open for over 24 hours |
| Every 10 min | Ghoul upkeep once the cycle's feeding date passes |
| Every 10 min | Ends expired Blood Hunts |
| Every 15 min | Auto-posts Elysium invitations to Discord on the Monday before the event |
| 00:02 daily | Advances the active downtime cycle |
| 00:05 daily | Feeding-cycle Masquerade decay |
| 00:08 daily | Willpower reset after a Modern Day event |
| 00:20 daily | Purges expired idempotency keys |
| 03:30 daily | Nightly backup, with pruning and a failure alert |
| 12:00 daily | Discord DMs to players who still owe downtime actions |
| 23:59 daily | ntfy daily summary, then counter reset |

## Database and migrations

Migrations are numbered files in `migrations/list/`. Applied ones are recorded in `schema_migrations` and pending ones run on every boot.

```text
  applied   0070_feeding_safety_before    2026-10-27T...
  applied   0071_news_edited_at           2026-10-29T...
  PENDING   0072_something_new
```

To write one, create `migrations/list/00NN_short_name.js`:

```js
module.exports = {
  name: '00NN_short_name', // must match the filename and never change once applied
  async up(pool) {
    await pool.query('ALTER TABLE ...');
  },
};
```

- The runner **silently skips** a file without both `name` and `up`, so check `npm run migrate:status` after adding one.
- **Never renumber an applied migration.** The name is the key, so a rename runs it twice.
- **Make `up()` idempotent** (check `information_schema` first). A migration that throws partway is not recorded and is retried from the top.
- Where it helps, `migrations/sql/` holds a hand-runnable phpMyAdmin equivalent.

Major tables are system-versioned (MariaDB `WITH SYSTEM VERSIONING`), so row history is queryable after the fact.

## Testing

```bash
npm test
```

Integration tests build a real Fastify instance from the production route plugins (`tests/setup/testApp.js`) against an isolated database (`TEST_DB_NAME`). Auth, authorization and SQL are the real code. Only outbound side effects (ntfy, EmailJS, image uploads) are stubbed.

The suite covers XP pricing and purchase, sheet edits, IDOR protection, rate limits, idempotency, comms switching and drafts, feeding cycles, ghoul upkeep, coterie rules, retainers, Court actions, news publishing and edit windows, live-session privacy, inventory, dice, and the rules catalog. `rulesCatalog.test.js` fails when `npm run catalog` needs re-running.

## Backups

`scripts/backup-db.js` writes a gzipped SQL dump using mysql2 rather than `mysqldump`, so it works on hosts without that binary. It imports directly in phpMyAdmin or through a client:

```bash
gunzip -c backups/vtm-20261030-033000.sql.gz | mysql -u USER -p vtm
```

`--no-media` skips the `premonition_media` and `news_media` image BLOBs. Those make up nearly all of the database's size, while the chronicle data itself is a few MB. A partial dump is never disguised as a full one: the filename carries `-nomedia`, the header says `PARTIAL BACKUP`, and each skipped table is marked in place.

The nightly job runs `--no-media` at 03:30, prunes past `BACKUP_RETENTION_DAYS` (default 14), and alerts through ntfy on failure. **Take a full backup before anything risky**, and copy backups off the box if losing the box matters.

## Deployment

Production runs on Plesk under Phusion Passenger. `npm run deploy` does the whole job:

1. Triggers a production database backup (`--no-backup` to skip).
2. Blocks the deploy if `package.json` adds dependencies the server doesn't have yet (`--skip-deps-check` to bypass).
3. Bumps the version in `package.json` and `version.json` (`--bump minor`, or `--no-bump`).
4. Regenerates the Swagger spec.
5. Uploads only changed files over FTPS, tracked by hash in `.deploy-manifest.json`.
6. Touches `tmp/restart.txt` to reload Passenger.
7. Polls `https://api.attlarp.gr/api/health` until the new version reports in with a live database connection.

Configuration lives in `deploy.config.json`, which is gitignored. Start from `deploy.config.example.json`. Migrations apply themselves on the restarted boot.

**Production notes**

- Terminate TLS at the reverse proxy and forward `X-Forwarded-Proto` (or set `COOKIE_SECURE=true`).
- Pass WebSocket upgrades through, or chat silently falls back to polling.
- `sharp` is pinned to low memory use for the 2 GB host. Check headroom before changing that.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Boot exits naming a variable | A required key is missing from `.env`. Note that it is `DB_PASS`. |
| `EADDRINUSE :3001` | Another instance is running. `PORT=0` is treated as unset. |
| 401 everywhere after a deploy | `JWT_SECRET` changed, or the user's `token_version` was bumped. |
| Login fails only on Safari, iOS or Incognito | Cookie flags. Set `COOKIE_SECURE=true` if the proxy hides HTTPS. |
| CORS errors | Add the origin to `CORS_ORIGIN`. There is no allow-all fallback, because auth is a cookie. |
| 403 on an admin route | The role isn't `admin`. Court officers pass `requireCourt` only. |
| 429 Too Many Requests | A rate-limit tier was hit. Wait out `Retry-After`. |
| Empty admin log viewer | `LOG_FILE` is unset. |
| Discord features do nothing | `DISCORD_BOT_TOKEN` is unset (no-op by design). |
| A new migration never runs | It is missing `name` or `up`. Check `npm run migrate:status`. |

## The Erebus ecosystem

| Repository | Role |
| --- | --- |
| **back** (this repo) | API, realtime, jobs, Discord bot |
| [front](https://github.com/MikeTsak/vtm-platform-front) | Player and Storyteller portal at [portal.attlarp.gr](https://portal.attlarp.gr) |
| [wiki-vtm](https://github.com/MikeTsak/wiki-vtm) | Erebus Wiki at [wiki.attlarp.gr](https://wiki.attlarp.gr) |
| [attlarp.gr](https://github.com/MikeTsak/attlarp.gr) | Public chronicle website |
| [erebus-mobile](https://github.com/MikeTsak/erebus-mobile) | Expo mobile app for SchreckNet and Surface Web |
| [harpy-kindle](https://github.com/MikeTsak/harpy-kindle) | E-ink Harpy terminal for live events |
| [vampire-treasure-hunt](https://github.com/MikeTsak/vampire-treasure-hunt) | Hunt Tracker for location-based challenges |
| [badge-for-larp](https://github.com/MikeTsak/badge-for-larp) | Printable character badge generator |

## License

[GNU GPL v3.0](LICENSE.txt). Copyright (C) 2025 Michail Tsakiroglou.

*Vampire: The Masquerade* is a trademark of Paradox Interactive AB. This is an unofficial fan project for the Athens Through Time chronicle.

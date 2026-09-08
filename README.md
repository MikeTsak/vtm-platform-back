# VTM Platform (V5 LARP) — Backend

Fastify + MariaDB backend API for the **Vampire: The Masquerade V5 LARP** platform.

It provides authentication, character management, XP economy (including discipline power assignment), downtimes, domains/claims, and admin tooling (users, XP tools, and NPCs).

- Frontend: Located in the `front/` directory of this repository
- API base (local default): `http://localhost:3001/api`
- Swagger UI (if enabled): `http://localhost:3001/api-docs`

## Project Ecosystem

This backend is part of the Vampire Platform monorepo, which includes:

- `front/` - React single-page application for player and Storyteller/admin interfaces
- `hunt/` - Hunt tracker application for managing hunting chronicles
- `erebus-mobile/` - Mobile companion app for in-character (SchreckNet) and out-of-character (Surface Web) communication
- `larp-badges/` - Tool for generating printable character badges
- `attlarp.gr/` - Athens Through Time chronicle website (lore, setting, gallery)
- `db/` - Database schemas and sample data

All components communicate with this backend API to provide a full-featured LARP management platform.

---

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Environment variables](#environment-variables)
- [Database schema (SQL)](#database-schema-sql)
- [Project layout](#project-layout)
- [Authentication & roles](#authentication--roles)
- [API overview](#api-overview)
- [XP spend rules](#xp-spend-rules)
- [Realtime (socket.io)](#realtime-socketio)
- [Background jobs](#background-jobs)
- [Tests](#tests)
- [Backups](#backups)
- [Schema versions (migrations)](#schema-versions-migrations)
- [Swagger / OpenAPI](#swagger--openapi)
- [Troubleshooting / gotchas](#troubleshooting--gotchas)
- [cURL examples](#curl-examples)
- [Production notes](#production-notes)

---

## Requirements

- **Node.js 20+** — Fastify 5 does not support Node 18.
- MariaDB 10.5+ (tested on 10.6)
- A database + user with privileges to create tables (InnoDB)
- `sharp` needs prebuilt binaries for your platform (installed automatically).

---

## Quick start

```bash
# 1) Install deps
npm install

# 2) Create .env  (see "Environment variables" below — the server refuses to
#    boot if a required key is missing, and tells you which one)
cp .env.example .env

# 3) Run migrations (creates/updates tables)
npm run migrate

# 4) Run the server
npm run dev      # nodemon + regenerates the Swagger spec
# or
npm start        # plain node + regenerates the Swagger spec
```

The API listens on `http://localhost:3001/api` by default.

`initDatabase()` also runs on every boot and is idempotent, so a fresh database
comes up without a manual migration step. `npm run migrate` is for applying the
numbered migrations in `migrations/list/`.

### npm scripts

| Script | What it does |
| --- | --- |
| `dev` | Regenerate the Swagger spec, then run under nodemon |
| `start` | Regenerate the Swagger spec, then run once |
| `test` / `test:watch` | vitest integration + unit tests |
| `migrate` | Apply pending migrations from `migrations/list/` |
| `migrate:status` | Show which migrations are applied and which are pending |
| `migrate:legacy` | The old ad-hoc `run-migrations.js`; superseded, kept for reference |
| `backup` | Full gzipped SQL dump (add `-- --no-media` to skip image BLOBs) |
| `backup:list` | List existing backups with size and date |
| `migrate-avatar-thumbs` | Backfill the 160px avatar thumbnails |
| `migrate-avatars-to-cdn` | One-off: move BLOB avatars to the image CDN |
| `migrate-news-urls` | One-off: rewrite legacy news media URLs |

Both `dev` and `start` run `swagger-autogen.js` first. It reads the route
manifest in `routes/index.js`, so a new route module is documented
automatically — you never edit the scanned-file list by hand.

---

## Environment variables

Create a `.env` file in `back/`. Startup validation lives in
`utils/envValidator.js` (Zod): if a **required** key is missing the process
logs which one and exits immediately.

```env
# --- Required ---------------------------------------------------------
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_db_user
DB_PASS=your_db_password          # note: DB_PASS, not DB_PASSWORD
DB_NAME=vtm

JWT_SECRET=replace_me_with_strong_random

# Web Push. Generate once with: npx web-push generate-vapid-keys
VAPID_PUBLIC_KEY=...
VAPID_PRIVATE_KEY=...

# --- Optional ---------------------------------------------------------
PORT=3001                          # default 3001
NODE_ENV=development
VAPID_SUBJECT=mailto:admin@attlarp.gr

# Comma-separated allowlist. Falls back to the known app origins
# (config/cors.js) — never to "*", because auth is a cookie.
CORS_ORIGIN=https://portal.attlarp.gr,http://localhost:5173

# Forces the session cookie's Secure/SameSite pair instead of inferring it
# from the request. Set to "false" only for non-TLS local setups that the
# hostname sniffing in utils/authCookie.js can't detect.
COOKIE_SECURE=true

APP_BASE_URL=https://portal.attlarp.gr   # used to build links in emails/pushes
IMAGE_API_KEY=...                        # img.miketsak.gr upload key
DISCORD_BOT_TOKEN=...                    # omit to run without the bot
LOG_CHANNEL_ID=...                       # Discord channel for error reports
NTFY_TOPIC=...                           # ntfy.sh broadcast topic

# Password-reset mail (EmailJS). Without these, /auth/forgot throws.
EMAILJS_SERVICE_ID=...
EMAILJS_TEMPLATE_ID=...
EMAILJS_PUBLIC_KEY=...
EMAILJS_PRIVATE_KEY=...
# Only if your EmailJS template uses non-default variable names:
EMAILJS_VAR_TO=to_email
EMAILJS_VAR_NAME=to_name
EMAILJS_VAR_APP=app_name
EMAILJS_VAR_LINK=reset_link
EMAILJS_VAR_EXPIRES=expires_minutes

# Logging (see logger.js)
LOG_LEVEL=debug
LOG_FILE=./logs/api.log            # required by the admin log viewer
LOG_JSON=0
```

Notes:

- Don't commit secrets — `.env` is in `.gitignore`.
- Changing `JWT_SECRET` invalidates every existing session (all users re-login).
- Tests use a separate database via `TEST_DB_NAME`; see `tests/setup/env.js`.

---

## Database schema (SQL)

Run these statements in your MariaDB database (InnoDB + `utf8mb4`).

> If you ever hit `errno: 150` on foreign keys: it’s usually type mismatch (signed vs unsigned) or different engines/collations. The schema below uses `INT UNSIGNED` consistently for IDs.

```sql
-- USERS
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email         VARCHAR(190) NOT NULL UNIQUE,
  display_name  VARCHAR(190) NOT NULL,
  role          ENUM('user','admin') NOT NULL DEFAULT 'user',
  password_hash VARCHAR(255) NOT NULL,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- CHARACTERS
-- user_id is nullable so NPCs can exist (NPC = character with user_id NULL)
CREATE TABLE IF NOT EXISTS characters (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id    INT UNSIGNED NULL,
  name       VARCHAR(190) NOT NULL,
  clan       VARCHAR(64)  NOT NULL,
  sheet      JSON NULL,
  xp         INT NOT NULL DEFAULT 50,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_char_user
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- XP LOG (optional but recommended)
CREATE TABLE IF NOT EXISTS xp_log (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  character_id  INT UNSIGNED NOT NULL,
  action        VARCHAR(64) NOT NULL,
  target        VARCHAR(190) NULL,
  from_level    INT NULL,
  to_level      INT NULL,
  cost          INT NOT NULL DEFAULT 0,
  payload       JSON NULL,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_xp_char (character_id),
  CONSTRAINT fk_xp_char
    FOREIGN KEY (character_id) REFERENCES characters(id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DOWNTIMES
CREATE TABLE IF NOT EXISTS downtimes (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  character_id  INT UNSIGNED NOT NULL,
  title         VARCHAR(255) NOT NULL,
  feeding_type  VARCHAR(128) NULL,
  body          TEXT NOT NULL,
  status        ENUM('submitted','approved','rejected','resolved') NOT NULL DEFAULT 'submitted',
  gm_notes      TEXT NULL,
  gm_resolution TEXT NULL,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at   TIMESTAMP NULL DEFAULT NULL,
  INDEX idx_dt_char (character_id),
  CONSTRAINT fk_dt_char
    FOREIGN KEY (character_id) REFERENCES characters(id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DOMAINS (optional catalog)
CREATE TABLE IF NOT EXISTS domains (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(190) NOT NULL,
  description TEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DOMAIN CLAIMS (map division -> owner/color/character)
CREATE TABLE IF NOT EXISTS domain_claims (
  division             INT UNSIGNED NOT NULL PRIMARY KEY,
  owner_name           VARCHAR(190) NULL,
  color                CHAR(7) NOT NULL DEFAULT '#454545',
  owner_character_id   INT UNSIGNED NULL,
  updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_claim_char (owner_character_id),
  CONSTRAINT fk_claim_char
    FOREIGN KEY (owner_character_id) REFERENCES characters(id)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

---

## Project layout

The API is a Fastify app assembled from plugins. `server.fastify.js` only
sequences the boot; it contains no routes.

```
server.fastify.js          # entry point: env -> app -> socket.io -> jobs -> listen
app.js                     # builds the Fastify instance (no listen, no side effects)
realtime.js                # socket.io: auth, rooms, chat relay; decorates fastify.io
db.js                      # mysql2 pool (promise)
authMiddleware.fastify.js  # authRequired / requireAdmin

config/                # environment-derived configuration
  cors.js              #   origin allowlist, shared by HTTP + SSE + socket.io

plugins/               # Fastify infrastructure (fastify-plugin wrapped, root scope)
  observability.js     #   request logging, admin no-store, error handler, onClose
  security.js          #   multipart, helmet, cors, cookie, static, compression
  docs.js              #   swagger + /api-docs

routes/                # one plugin per feature
  index.js             #   the route manifest + shared dependency bundle
  chat.js  news.js  hunts.js  domainClaims.js  liveSessions.js  ...  (38 modules)

services/              # shared, route-agnostic logic
  push.js  discord.js  email.js  media.js  dice.js  guards.js
  format.js  news.js  sse.js  banner.js  logTail.js  token.js
  liveSession.js  domainOverlays.js

jobs/                  # every cron/interval in the process, started by startJobs()
utils/                 # small pure helpers (settings, sanitize, xpCost, clans, ...)
migrations/            # schema creation + migration runner
tests/                 # vitest integration tests (see tests/setup/testApp.js)
```

### Adding a route

1. Create `routes/<feature>.js`:

   ```js
   module.exports = async function (fastify, opts) {
     const { pool, log, authRequired } = opts;

     fastify.get('/api/thing', { preHandler: [authRequired] }, async (req, reply) => {
       // ...
     });
   };
   ```

2. Add it to `ROUTE_MODULES` in `routes/index.js`.

That is the whole wiring — Swagger picks the module up from the same manifest.

`opts` carries only what a test may want to substitute: the pool, the logger,
the auth guards, the rate limiters, and the external clients. Anything
stateless (pure helpers, config, settings access) should be `require()`d
directly by the module that uses it rather than threaded through `opts`.

---

## Authentication & roles

The session JWT travels in an **httpOnly cookie** named `token`, not in
`localStorage`. Client-side JS — including an injected XSS payload — cannot
read it. The frontend never handles a token; it just sends
`withCredentials: true` (see `front/src/core/api.js`).

- `POST /api/auth/login` sets the cookie; `POST /api/auth/logout` clears it.
- An `Authorization: Bearer <token>` header is still accepted, for non-browser
  clients (the mobile app, scripts, cURL) that can't rely on cookies.
- There is deliberately **no** `?token=` query fallback — a token in a URL leaks
  into access logs, proxy logs and browser history. SSE streams, `<img>` avatar
  requests and the socket.io handshake all authenticate via the cookie.

**Revocation.** Each token embeds `tv`, the user's `token_version`. Bumping that
column (password reset, "log out everywhere") invalidates every token already
issued to them — `authRequired` re-checks it on each request, so revocation is
immediate rather than waiting out the 7-day expiry.

**Cookie flags.** `Secure` and `SameSite` are decided together from one signal
(`utils/authCookie.js`): a request that is HTTPS, or forwarded as HTTPS, or
addressed to a non-local host, gets `SameSite=None; Secure`; local dev over
`http://127.0.0.1` gets `SameSite=Lax`. `COOKIE_SECURE` overrides both. Getting
this wrong is what previously broke login on Safari, iOS and Chrome Incognito.

### Roles

| Role | Meaning |
| --- | --- |
| `user` | Ordinary player. |
| `courtuser` | Court officer. Passes `requireCourt` — boons, domain assignment, the Court NPC-chat views. |
| `admin` | Storyteller. Passes both `requireCourt` and `requireAdmin`. |

Guards live in `authMiddleware.fastify.js` (`authRequired`, `optionalAuth`,
`requireAdmin`) and `services/guards.js` (`requireCourt`). Admin routes answer
**403** for a non-admin session and **401** for no session at all.

`optionalAuth` is for endpoints that are public but reveal more to a signed-in
caller (e.g. the wiki feed showing private articles to admins). Do **not** wrap
`authRequired` in a try/catch for that — it *sends* a 401 rather than throwing,
so the reply is already committed by the time your catch would run.

> **Rate limiting is currently a no-op.** The four limiters in
> `services/guards.js` are stubs, and `@fastify/rate-limit` — although
> installed — is not registered. Every call site already declares which tier it
> wants, so switching real limiting on is a change to that one file.

---

## API overview

Base path: `/api`. There are ~220 endpoints; **`/api-docs` is the generated,
always-current reference**. This section is a map of where things live, not an
exhaustive list — for the authoritative route table read `routes/index.js` and
the module it points at.

| Area | Module | Notable endpoints |
| --- | --- | --- |
| Health & status | `routes/system.js` | `GET /health`, `GET /` (HTML status page) |
| Auth | `routes/auth.js` | `/auth/register`, `/auth/login`, `/auth/me`, `/auth/forgot`, `/auth/reset`, `/auth/logout`, `/auth/logout-all` |
| Users | `routes/users.js`, `routes/adminUsers.js` | `/users/search`, `/admin/users`, `PATCH /admin/users/:id`, `/auth/refresh` |
| Characters | `routes/characters.js` | `/characters/me`, `/characters/user/:id` (admin; `:id` is a **character** id), inventory, retainers |
| XP | `routes/characterXp.js`, `routes/xp.js` | `POST /characters/xp/spend` (self, idempotent), `/admin/characters/:id/xp/spend`, `/admin/characters/:id/xp`, `/admin/xp-logs` |
| Mechanics | `routes/mechanics.js` | `/characters/:id/rouse`, `/spend-wp`, `/apply-damage` — server-authoritative |
| Downtimes | `routes/downtimes.js` | `/downtimes/mine`, `/downtimes/quota`, `POST /downtimes`, `/admin/downtimes`, `/downtimes/config` |
| Domains | `routes/domains.js`, `routes/domainClaims.js`, `routes/domainOverlays.js` | claims, requests, Court assignment, safety, codex, restricted map overlays |
| Coteries | `routes/coteries.js` | CRUD, `/coteries/:id/members/set`, `/coteries/:id/purchase`, `/coteries/:id/xp` (admin) |
| Boons | `routes/boons.js` | `/boons`, `/boons/entities` — Court writes, everyone reads |
| Court | `routes/camarilla.js` | `/camarilla/roster` (public), `/admin/camarilla/update` |
| Chat | `routes/chat.js`, `routes/npcChat.js` | DMs, groups, reactions, media, 4h edit/delete window, NPC threads |
| Email (in-fiction) | `routes/emails.js` | `/emails/my-inbox`, `/emails/send`, `/admin/emails/*` |
| News & rumours | `routes/news.js`, `routes/rumors.js` | public feed, sitemap, authoring, per-theme permissions, broadcast |
| Premonitions | `routes/premonitions.js` | Malkavian visions: authoring, delivery, media |
| Hunts | `routes/hunts.js` | hunt/step authoring, review, group join, submission |
| Live sessions | `routes/liveSessions.js` | lifecycle, participants, rolls, ST broadcast |
| Dice | `routes/dice.js` | `POST /dice/rolls`, `/admin/dice/rolls` |
| Wiki | `routes/wiki.js` | articles, search, graph, timeline, Elysium boards |
| Push | `routes/push.js` | subscribe/unsubscribe, per-category settings, test send |
| NPCs | `routes/npcs.js` | admin CRUD + NPC XP |
| Avatars | `routes/avatars.js` | `GET/PUT /{users,npcs,retainers,identities}/:id/avatar` |
| Admin tooling | `routes/adminMisc.js`, `routes/adminLogs.js`, `routes/maintenance.js`, `routes/discordAdmin.js`, `routes/ntfy.js`, `routes/clans.js`, `routes/banner.js` | events, broadcasts, timelines, blood web, audit logs, log tail, SSE migration runners, Discord/ntfy config, clan availability, global banner |

### Conventions

- Success bodies are JSON objects, never bare arrays: `{ character }`,
  `{ articles: [...] }`, `{ ok: true }`.
- Errors are `{ error: "..." }`, with `{ error: "Validation Error", details }`
  for schema failures.
- Everything under `/api/admin` is sent `Cache-Control: no-store` by a global
  hook, so the admin panel never reads a stale 304.
- Long-running admin jobs stream **SSE** rather than blocking a request — see
  `routes/maintenance.js`.
- `POST /api/characters/xp/spend` honours an `Idempotency-Key` header, so a
  retried request cannot double-spend. It is the only endpoint that does.

---

## XP spend rules

Endpoint:

- `POST /api/characters/xp/spend`

Body (varies by purchase type):

```jsonc
{
  "type": "attribute" | "skill" | "specialty" |
          "discipline" | "ritual" | "ceremony" |
          "thin_blood_formula" | "advantage" |
          "blood_potency",
  "target": "Presence",
  "currentLevel": 1,
  "newLevel": 2,
  "disciplineKind": "clan" | "other" | "caitiff" | "select",
  "ritualLevel": 2,
  "formulaLevel": 1,
  "dots": 1,
  "patchSheet": { /* optional updated sheet JSON */ }
}
```

Costs:

- Attribute: `new × 5`
- Skill: `new × 3`
- Specialty: `3`
- Discipline:
  - clan: `new × 5`
  - other: `new × 7`
  - caitiff: `new × 6`
- Discipline power assignment **only** (no dot increase): **free**
- Ritual: `level × 3`
- Ceremony: `level × 3`
- Thin-blood formula: `level × 3`
- Advantage: `3 × dots`
- Blood potency: `new × 10`

Response:

```json
{ "character": { /* updated */ }, "spent": 15 }
```

---

## Realtime (socket.io)

`realtime.js` attaches socket.io to the same HTTP server and decorates the
Fastify instance, so route modules publish through `fastify.io` (or
`req.server.io` inside a handler).

- **Handshake auth** mirrors `authRequired`: the JWT is read from the handshake
  `Cookie` header (falling back to `auth.token`), verified, and checked against
  the user's current `token_version`. Unauthenticated sockets are rejected.
- **Rooms**: `user_<id>` (joined automatically), `admin_chat` (admins and Court),
  `group_<id>` (membership-checked on join), `session_<code>` (participants and
  STs).
- **Events**: the server emits `chat:refresh` and `chat:reactions` to nudge
  clients to refetch, and `refresh_session` for live sessions. `chat_message` is
  relayed for live sessions with the sender identity overwritten from the
  verified socket — a client cannot spoof who sent a message.
- The socket.io CORS allowlist is the same `config/cors.js` list the HTTP layer
  uses.

---

## Background jobs

Every cron and interval in the process is registered in `jobs/index.js` and
started once, by `startJobs()`, after the server is listening. Nothing schedules
itself as a side effect of being `require()`d.

| Schedule | Job |
| --- | --- |
| `0 12 * * *` | Downtime deadline pings — DMs players who still owe actions when the deadline is 24–48h out. No-ops without a Discord client. |
| `* * * * *` | Mass-release ping — one ntfy broadcast the moment the countdown expires, latched by `downtime_mass_release_notified`. |
| every 60s | Daily Discord mail digest — compares the clock to the admin-set `discord_schedule_time`; sends at most once per day. |
| `59 23 * * *` | End-of-day ntfy summary, then resets the counters. |

---

## Tests

```bash
npm test          # vitest run
npm run test:watch
```

Integration tests build a real Fastify instance from the production route
plugins (`tests/setup/testApp.js`) against an isolated test database
(`TEST_DB_NAME`, see `tests/setup/env.js`). Auth, authorization and DB access
are the real code — only outbound side effects (ntfy, EmailJS, image uploads)
are stubbed.

Because route modules take their pool/logger/guards from `opts`, mounting one in
isolation is a single `app.register(require('../../routes/x'), { pool, ... })`.

---

## Backups

`scripts/backup-db.js` writes a gzipped SQL dump using mysql2 — deliberately
**not** `mysqldump`, which isn't installed everywhere this runs and whose absence
would silently stop the job. The output is a plain SQL script, so you can import
it straight into **phpMyAdmin** (Import ▸ choose file — it accepts `.sql.gz`), or
pipe it to a mysql client:

```bash
gunzip -c backups/vtm-20260909-033000.sql.gz | mysql -u USER -p vtm
```

```bash
npm run backup                  # full dump           -> vtm-<stamp>.sql.gz
npm run backup -- --no-media    # game data only      -> vtm-<stamp>-nomedia.sql.gz
npm run backup:list             # what's on disk
```

### Why `--no-media` exists

`premonition_media` and `news_media` store full-resolution images as BLOBs:

| table | rows | size |
| --- | ---: | ---: |
| premonition_media | 38 | 349.5 MB |
| news_media | 36 | 21.5 MB |
| **everything else combined** | ~12,600 | **~12 MB** |

So a full dump is ~400 MB and a `--no-media` dump is ~2.4 MB, for the same
chronicle data. A nightly 400 MB backup would fill the Plesk box in days, and
those 74 images barely change.

A partial backup is never disguised as a full one: the filename carries
`-nomedia`, the file header says `*** PARTIAL BACKUP ***` and names the omitted
tables, and each skipped table is marked in place with
`-- row data intentionally omitted (N rows)`. **Take a full `npm run backup`
before anything risky.**

### Nightly job

`jobs/index.js` schedules one at 03:30 with `--no-media`, prunes anything past
the retention window, and fires an ntfy alert if it fails.

```env
BACKUP_SCHEDULE_ENABLED=true      # set false to turn it off
BACKUP_SCHEDULE_CRON=30 3 * * *
BACKUP_SCHEDULE_FULL=false        # true = include media every night (~400 MB)
BACKUP_DIR=./backups              # gitignored
BACKUP_RETENTION_DAYS=14          # 0 disables pruning
BACKUP_MEDIA_TABLES=premonition_media,news_media
```

Backups are written to disk on the same machine as the database, which protects
against a bad migration or a mistaken `DELETE` — **not** against losing the box.
Copy them off-site if that matters.

---

## Schema versions (migrations)

Migrations are numbered files in `migrations/list/`, and applied ones are
recorded in the `schema_migrations` table. `initDatabase()` runs pending ones on
every boot, so a deploy is self-applying; `npm run migrate` does the same by
hand, and `npm run migrate:status` shows where you stand:

```
  applied   0011_avatar_thumb_urls             2026-09-05T00:47:41.000Z
  applied   0012_performance_indexes           2026-09-08T22:55:01.000Z
  PENDING   0013_something_new
  orphaned  0008_chat_message_reactions        (recorded, but no file on disk)
```

### Applying to another server (production)

Deploying the code and restarting is enough — `initDatabase()` applies anything
pending on boot. If you'd rather run a change by hand in phpMyAdmin first,
`migrations/sql/` holds a hand-runnable equivalent for migrations where that is
useful (e.g. `0012_performance_indexes.sql`). Those files are idempotent, run
STEP 0 as a read-only inspection before changing anything, and do not replace the
`.js` migration — the app still records itself in `schema_migrations` afterwards.

### Writing one

Create `migrations/list/00NN_short_name.js` exporting **exactly this shape**:

```js
module.exports = {
  name: '00NN_short_name',      // must match, and must never change once applied
  async up(pool) {
    await pool.query('ALTER TABLE ...');
  },
};
```

The runner skips anything that doesn't have both `name` and `up`, and it does so
**silently** — `0010_downtime_read.js` exported a bare function for weeks and was
skipped on every single boot without ever being recorded. Check
`npm run migrate:status` after adding one.

Two more rules the schema_migrations table can't enforce for you:

- **Never renumber an applied migration.** `name` is the key. Renaming a file
  that has already run makes the runner treat it as new and apply it a second
  time — that is what the `orphaned 0008_chat_message_reactions` row above is.
- **Make `up()` idempotent** where you can (check `information_schema` or
  `SHOW COLUMNS` first). If a migration throws partway it is *not* recorded, so
  the next boot retries it from the top.

---
## Swagger / OpenAPI

- Local: `http://localhost:3001/api-docs`
- Production: `https://api.attlarp.gr/api-docs`

The spec (`swagger_output.json`) is regenerated by `swagger-autogen.js` on every
`npm run dev` / `npm start`. Its scanned-file list is derived from
`ROUTE_MODULES` in `routes/index.js`, so adding a route module documents it
automatically.

Swagger UI runs in the browser and shares its cookies with the API, so if you
are already logged in to the portal on the same site, authenticated calls just
work. For a Bearer token instead, click **Authorize** and paste
`Bearer <token>`.

---

## Troubleshooting / gotchas

- **Boot exits immediately with a variable name** — a required key is missing
  from `.env`. Note it is `DB_PASS`, not `DB_PASSWORD`.
- **`EADDRINUSE :3001`** — another instance is already running. `PORT=0` does
  *not* pick a random port; `Number(process.env.PORT) || 3001` treats 0 as unset.
- **401 everywhere after a deploy** — `JWT_SECRET` changed, or the user's
  `token_version` was bumped. Both force a re-login, by design.
- **Login works locally but not in production (Safari / iOS / Incognito)** — a
  cookie-flag problem, not a credentials problem. See
  `utils/authCookie.js`; set `COOKIE_SECURE=true` explicitly if the reverse
  proxy does not forward `X-Forwarded-Proto`.
- **CORS failures** — add the origin to `CORS_ORIGIN`. `config/cors.js` is the
  single source of truth and is shared by HTTP, SSE and the socket.io
  handshake; there is no "allow all" fallback because auth is a cookie.
- **403 on admin routes** — the session's role is not `admin`. Court officers
  (`courtuser`) pass `requireCourt` but not `requireAdmin`.
- **Admin log viewer is empty** — `LOG_FILE` is unset.
- **Discord features silently do nothing** — the bot runs in
  `discordWorker.js`; without `DISCORD_BOT_TOKEN` every Discord path no-ops by
  design (`services/discord.js` exports a null client).
- **FK create errors (`errno:150`)** — check signed vs unsigned ID types and
  make sure the engine is InnoDB.

---

## cURL examples

Auth is a cookie, so use a cookie jar (`-c` to save, `-b` to send). The
`Authorization: Bearer` header works too, if you prefer.

### Register

```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","display_name":"Admin","password":"changeme"}'
```

### Login (stores the session cookie in cookies.txt)

```bash
curl -c cookies.txt -X POST http://localhost:3001/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"changeme"}'
```

### Who am I

```bash
curl -b cookies.txt http://localhost:3001/api/auth/me
```

### Spend XP (discipline dot increase)

`Idempotency-Key` makes a retry safe — replaying the same key returns the first
response instead of charging twice.

```bash
curl -b cookies.txt -X POST http://localhost:3001/api/characters/xp/spend \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: 3f1c1f5e-1f0e-4a3f-9b47-1a2b3c4d5e6f' \
  -d '{
    "type":"discipline",
    "disciplineKind":"clan",
    "target":"Auspex",
    "currentLevel":1,
    "newLevel":2,
    "patchSheet":{ "disciplines": {"Auspex":2} }
  }'
```

### Admin: resolve a downtime

```bash
curl -b cookies.txt -X PATCH http://localhost:3001/api/admin/downtimes/12 \
  -H 'Content-Type: application/json' \
  -d '{"status":"resolved","gm_resolution":"You tracked the ghoul and reclaimed the book."}'
```

### Upload an avatar (multipart)

```bash
curl -b cookies.txt -X PUT http://localhost:3001/api/users/1/avatar \
  -F 'avatar=@portrait.png'
```

---

## Production notes

- Run behind a reverse proxy (Apache/nginx) terminating TLS. Make sure it
  forwards `X-Forwarded-Proto`, or set `COOKIE_SECURE=true` explicitly —
  otherwise the session cookie's flags are guessed from the hostname.
- The proxy must pass WebSocket upgrades through for socket.io, or realtime
  chat silently falls back to polling.
- Use a process manager (PM2/systemd). `npm start` regenerates the Swagger spec
  first, so the process needs write access to `swagger_output.json`.
- `sharp` is pinned to low memory use (`cache(false)`, `concurrency(1)`) for the
  2GB Plesk box — don't remove that without checking headroom.
- Keep DB backups. `initDatabase()` creates missing tables but never drops or
  alters existing data.
- Rotate `JWT_SECRET` deliberately: it logs every user out.
- The Discord bot is a separate module in the same process
  (`discordWorker.js`); it reconnects on its own and never blocks API boot.
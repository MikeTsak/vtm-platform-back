# Vampire V5 LARP — Backend (Express + MariaDB)

Express API + MariaDB for your Vampire: The Masquerade V5 LARP platform. It powers auth, characters (with XP economy and discipline power assignment), downtimes, domains/claims, and admin/NPC tools.

> Pairs with the React frontend README you already have.

---

## Requirements

* Node.js 18+ and npm 9+
* MariaDB 10.5+ (tested on 10.6)
* A database and user with privileges to create tables (InnoDB)

---

## Quick Start

```bash
# 1) Install deps
npm install

# 2) Create the .env (see below)
cp .env.example .env
# edit it with your DB info and JWT secret

# 3) Initialize DB tables
#   Option A: paste the SQL from "Schema (SQL)" into your MariaDB
#   Option B: run each statement manually in phpMyAdmin

# 4) Run the server
npm start      # or: npm run dev (if using nodemon)
# API will print: API on http://localhost:3001
```

---

## Environment (.env)

```env
# HTTP
PORT=3001
NODE_ENV=development

# MariaDB
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=vtm

# JWT
JWT_SECRET=replace_me_with_strong_random

# (optional) logging verbosity
LOG_LEVEL=debug
```

> Do **not** commit real credentials. Keep `.env` out of version control (use `.gitignore`).

---

## Schema (SQL)

Run these in your `vtm` database (InnoDB, utf8mb4). Types and unsignedness are aligned to avoid FK errors.

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

-- CHARACTERS (user_id nullable so NPCs can exist)
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

-- XP LOG (optional but useful)
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
  gm_notes      TEXT NULL,        -- visible to player
  gm_resolution TEXT NULL,        -- private gm write-up (or swap meanings to taste)
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at   TIMESTAMP NULL DEFAULT NULL,
  INDEX idx_dt_char (character_id),
  CONSTRAINT fk_dt_char
    FOREIGN KEY (character_id) REFERENCES characters(id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DOMAINS (optional catalog; you can skip if using claims-only)
CREATE TABLE IF NOT EXISTS domains (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(190) NOT NULL,
  description TEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DOMAIN CLAIMS (map division → owner/color/character)
CREATE TABLE IF NOT EXISTS domain_claims (
  division             INT UNSIGNED NOT NULL PRIMARY KEY,
  owner_name           VARCHAR(190) NULL,
  color                CHAR(7) NOT NULL DEFAULT '#454545', -- '#RRGGBB'
  owner_character_id   INT UNSIGNED NULL,
  updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_claim_char (owner_character_id),
  CONSTRAINT fk_claim_char
    FOREIGN KEY (owner_character_id) REFERENCES characters(id)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

> Got `errno: 150` earlier? That’s almost always **mismatched types/unsigned** between FK and PK. The definitions above fix that (all IDs are `INT UNSIGNED`).

---

## Scripts

```jsonc
// package.json (relevant)
{
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  }
}
```

---

## Files (high level)

```
back/
  server.js            # all routes (auth, characters, xp, downtimes, admin, claims, NPCs)
  db.js                # mysql2 pool with .promise()
  authMiddleware.js    # authRequired + requireAdmin (JWT)
  .env                 # your secrets
  .gitignore           # ignore node_modules, .env, logs, etc.
```

**db.js** (example):

```js
// db.js
const mysql = require('mysql2');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});

module.exports = pool.promise();
```

**authMiddleware.js** (example):

```js
const jwt = require('jsonwebtoken');

function authRequired(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}

module.exports = { authRequired, requireAdmin };
```

---

## API Documentation (Swagger)

This backend includes interactive API documentation powered by Swagger/OpenAPI. Once the server is running, you can:

* **View API Documentation**: Navigate to `http://localhost:3001/api-docs` in your browser
* **Try API Endpoints**: Use the Swagger UI to test endpoints directly from the browser
* **Explore Schemas**: See detailed request/response models and authentication requirements

### Accessing Swagger UI

1. Start the server: `npm start` or `npm run dev`
2. Open your browser and go to: `http://localhost:3001/api-docs`
3. For production, access via: `https://vtm.back.miketsak.gr/api-docs`

### Authentication in Swagger

For endpoints that require authentication:

1. First, use the `/api/auth/register` or `/api/auth/login` endpoint to get a JWT token
2. Click the "Authorize" button at the top of the Swagger UI
3. Enter your token in the format: `Bearer <your-token-here>`
4. Click "Authorize" to apply the token to all protected endpoints

### Swagger Configuration

The Swagger configuration is located in `swagger.config.js` and includes:

* API metadata (title, version, description)
* Server URLs (development and production)
* Security schemes (JWT Bearer authentication)
* Schema definitions for common models (User, Character, Error)
* Endpoint documentation with request/response examples

To add documentation for new endpoints, use JSDoc-style comments with `@swagger` tags in `server.js`.

---

## API Overview

Base URL defaults to: `http://localhost:3001/api`

### Auth

* `POST /auth/register` → `{ token }`
* `POST /auth/login` → `{ token }`
* `GET /auth/me` → `{ user }` (requires Bearer token)

### Characters (player)

* `GET /characters/me` → `{ character }` (sheet auto-parsed)
* `POST /characters` body: `{ name, clan, sheet }` → `{ character }` (starts at 50 XP)
* `PUT /characters` body: any of `{ name, clan, sheet }` → `{ character }`
* `POST /characters/xp/spend` (see XP Spend below) → `{ character, spent }`

### Downtimes (player)

* `GET /downtimes/quota` → `{ used, limit: 3 }` (per calendar month)
* `GET /downtimes/mine` → `{ downtimes: [...] }`
* `POST /downtimes` body: `{ title, body, feeding_type? }` → `{ downtime }`

### Domains / Claims

* `GET /domain-claims` → `{ claims: [{ division, owner_name, color, owner_character_id, updated_at }, ...] }`

### Admin

* `GET /admin/users` → joined list (users + their character summary)
* `PATCH /admin/users/:id` (optional) body: `{ display_name, email, role }`
* `PATCH /admin/characters/:id` body: `{ name?, clan?, sheet? }`
* `PATCH /admin/characters/:id/xp` body: `{ delta }`
* `GET /admin/downtimes` → `{ downtimes: [...] }` (joined with users & characters)
* `PATCH /admin/downtimes/:id` body: `{ status?, gm_notes?, gm_resolution? }`
* Domain Claims:

  * `PATCH /admin/domain-claims/:division` body: `{ owner_name?, color?, owner_character_id? }` (upsert)
  * `DELETE /admin/domain-claims/:division`
* NPCs:

  * `GET /admin/npcs` → `{ npcs:[...] }` (characters with `user_id IS NULL`)
  * `POST /admin/npcs` body: `{ name, clan, sheet? }` → `{ npc }` (starts with 10,000 XP)
  * `GET /admin/npcs/:id` → `{ npc }`
  * `PATCH /admin/npcs/:id` body: `{ name?, clan?, sheet? }`
  * `DELETE /admin/npcs/:id` → `{ ok:true }`
  * `POST /admin/npcs/:id/xp/spend` → same as player XP spend path but for that NPC

---

## XP Spend (Rules & Endpoint)

**Endpoint:** `POST /api/characters/xp/spend`

**Body** (depending on what you’re buying):

```jsonc
{
  "type": "attribute" | "skill" | "specialty" |
          "discipline" | "ritual" | "ceremony" |
          "thin_blood_formula" | "advantage" |
          "blood_potency",
  "target": "Presence",           // optional (e.g., discipline name)
  "currentLevel": 1,              // for level ups
  "newLevel": 2,                  // for level ups
  "disciplineKind": "clan" | "other" | "caitiff" | "select",
  "ritualLevel": 2,               // for rituals/ceremonies
  "formulaLevel": 1,              // for thin-blood formula
  "dots": 1,                      // for advantages
  "patchSheet": { /* updated sheet JSON */ }  // optional: atomically patch character sheet server-side
}
```

**Costs**:

* Attribute: `new × 5`
* Skill: `new × 3`
* Specialty: `3`
* Discipline: `new × 5` (clan), `new × 7` (other), `new × 6` (Caitiff)
* **Discipline Power Assignment** (no level change): **FREE** (`disciplineKind: "select"` or `newLevel === currentLevel`)
* Blood Sorcery **Ritual**: `level × 3`
* Oblivion **Ceremony**: `level × 3`
* Thin-blood **Formula**: `level × 3`
* Advantage (merit/background): `3 × dots`
* Blood Potency: `new × 10`

**Response**:

```json
{ "character": { /* updated */ }, "spent": 15 }
```

**Notes**:

* If `patchSheet` is present, the server replaces the `sheet` column with that JSON **after** deducting XP.
* Every spend attempts to write an `xp_log` row (ignored if the table is missing).
* If `type` is `discipline` and you’re only **assigning** a power for an already-owned dot, pass `disciplineKind: "select"` and set `newLevel === currentLevel` → cost is 0.

---

## Downtimes

* Players have **3 per calendar month** (server checks `created_at` between first-of-month and first-of-next-month).
* `feeding_type` auto-fills from the character’s predatorType if omitted.

**Admin editing**:

* `PATCH /admin/downtimes/:id` body can set:

  * `status` among `submitted|approved|rejected|resolved`
  * `gm_notes` (visible to player)
  * `gm_resolution` (private)
* When status becomes `resolved`, server sets `resolved_at = NOW()`.

---

## Domains & Claims

* Player endpoint: `GET /domain-claims` (used by `Domains.jsx` to color a GeoJSON map).
* Admin endpoints:

  * `PATCH /admin/domain-claims/:division` upserts a record with `{ owner_name, color "#RRGGBB", owner_character_id? }`
  * `DELETE /admin/domain-claims/:division`

> The map’s polygons come from the **frontend** `Domains.json` (GeoJSON). On the backend we only store **who owns which division** and the hex color.

---

## NPCs (Admin)

* Implemented as `characters` with `user_id = NULL`.
* Creation defaults to **10,000 XP** (as requested).
* Full XP economy and sheet patching works the same as for players.
* Endpoints under `/admin/npcs` (see API above).

---

## Logging (with emojis)

The server prints structured, human-friendly logs. Typical categories:

* `log.ok('✅ something good')`
* `log.warn('⚠️ something to warn')`
* `log.err('🛑 something failed')`
* `log.xp('🩸 XP event')`
* `log.dom('🏙️ domain/claim event')`

You’ll see messages like:

```
🩸 XP spend request { user_id: 3, type: 'discipline', target: 'Presence', currentLevel: 1, newLevel: 2, cost: 10 }
✅ XP spend complete { user_id: 3, remaining_xp: 40 }
```

If you don’t have a custom logger, a minimal inline helper in `server.js` is fine:

```js
const log = {
  ok:  (...a) => console.log('✅', ...a),
  warn:(...a) => console.warn('⚠️', ...a),
  err: (...a) => console.error('🛑', ...a),
  xp:  (...a) => console.log('🩸', ...a),
  dom: (...a) => console.log('🏙️', ...a),
};
```

---

## Common Gotchas

* **“Cannot find module 'mysql2/promise'”** → install `mysql2` and import the pool from `db.js` using `pool.promise()` (as shown). Use `await pool.query(...)`.
* **Tried to await query that isn’t a promise** → you used the callback version. Make sure you export `pool.promise()` from `db.js`.
* **FK error (errno:150) creating `domain_claims`** → ensure both `domain_claims.owner_character_id` and `characters.id` are **INT UNSIGNED** with the same engine/collation. Use the schema above.
* **403 on admin routes** → your token’s `role` isn’t `admin`. Update the user row or re-login with an admin account.
* **CORS** → keep `app.use(cors({ origin: true, credentials: true }))` in `server.js` for local dev.
* **JWT invalid after server restart** → you changed `JWT_SECRET`. Log out/in to refresh tokens.

---

## Minimal Route Examples

**Register**

```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","display_name":"Admin","password":"changeme"}'
```

**Login**

```bash
curl -X POST http://localhost:3001/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"changeme"}'
# => { "token": "..." }
```

**Create character**

```bash
curl -X POST http://localhost:3001/api/characters \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Alexios","clan":"Tremere","sheet":{"predatorType":"Siren","disciplines":{"Auspex":2,"Dominate":1}}}'
```

**Spend XP (discipline, clan)**
(also patches the sheet to record a chosen power at the new level)

```bash
curl -X POST http://localhost:3001/api/characters/xp/spend \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "type":"discipline",
    "disciplineKind":"clan",
    "target":"Auspex",
    "currentLevel":1,
    "newLevel":2,
    "patchSheet":{"disciplines":{"Auspex":2},"disciplinePowers":{"Auspex":[{"level":2,"id":"premonition","name":"Premonition"}]}}
  }'
```

**Assign power for an existing dot (FREE)**

```bash
curl -X POST http://localhost:3001/api/characters/xp/spend \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "type":"discipline",
    "disciplineKind":"select",
    "target":"Auspex",
    "currentLevel":2,
    "newLevel":2,
    "patchSheet":{"disciplinePowers":{"Auspex":[{"level":1,"id":"heightened_senses","name":"Heightened Senses"}]}}
  }'
```

**Admin: resolve downtime**

```bash
curl -X PATCH http://localhost:3001/api/admin/downtimes/12 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"status":"resolved","gm_resolution":"You tracked the ghoul and reclaimed the book."}'
```

**Admin: upsert domain claim #3**

```bash
curl -X PATCH http://localhost:3001/api/admin/domain-claims/3 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"owner_name":"FirstName LastName","color":"#2563eb","owner_character_id":42}'
```

---

## Production Notes

* Use a process manager (PM2/systemd) and set `NODE_ENV=production`.
* Serve behind a reverse proxy (nginx) with TLS.
* Apply DB backups; restrict DB user to DB-level privileges.
* Rotate `JWT_SECRET` carefully (forces re-login).